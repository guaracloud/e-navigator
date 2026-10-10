//! Bounded CRI polling; retained files are drained independently of live pod discovery.
use async_trait::async_trait;
use e_navigator_core::{
    CoreError, CoreResult, CriLogsConfig, LogInitialRead, ModuleKind, ModuleMetadata, Source,
};
use e_navigator_signals::{
    ApplicationLogObservation, LogCollectionOutcome as Outcome, LogCollectionWarning, LogStream,
    SignalEnvelope,
};
use rustix::fs::{AtFlags, Mode, OFlags, mkdirat, openat, renameat, unlinkat};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs::File,
    io::{self, Read, Seek, SeekFrom},
    path::{Component, Path},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

const MAX_BATCH_RECORDS: usize = 1024;
const SOURCE: &str = "source.cri_logs";

#[derive(Debug, Clone)]
pub struct CriLogSource {
    config: CriLogsConfig,
    host: Option<String>,
}
impl CriLogSource {
    pub fn new(config: CriLogsConfig, host: Option<String>) -> Self {
        Self { config, host }
    }
}

#[async_trait]
impl Source<SignalEnvelope> for CriLogSource {
    fn metadata(&self) -> ModuleMetadata {
        ModuleMetadata::new(SOURCE, ModuleKind::Source)
    }
    async fn run(self: Box<Self>, tx: tokio::sync::mpsc::Sender<SignalEnvelope>) -> CoreResult<()> {
        #[cfg(not(unix))]
        {
            let _ = tx;
            return Err(module_error("CRI logs require Unix"));
        }
        let config = self.config.clone();
        let mut collector = tokio::task::spawn_blocking(move || Collector::new(config))
            .await
            .map_err(|_| module_error("collector task failed"))?
            .map_err(|_| {
                module_error("cannot open log/checkpoint roots or acquire checkpoint lock")
            })?;
        loop {
            let (next, batch) = tokio::task::spawn_blocking(move || {
                let result = collector.poll(now_millis());
                (collector, result)
            })
            .await
            .map_err(|_| module_error("collector task failed"))?;
            collector = next;
            let batch = batch.map_err(|_| module_error("log read failed"))?;
            for payload in batch {
                let signal = match payload {
                    Collected::Log(log) => {
                        SignalEnvelope::application_log(SOURCE, self.host.clone(), log)
                    }
                    Collected::Warning(outcome, count) => SignalEnvelope::log_collection_warning(
                        SOURCE,
                        self.host.clone(),
                        LogCollectionWarning { outcome, count },
                    ),
                };
                tx.send(signal)
                    .await
                    .map_err(|_| CoreError::PipelineClosed)?;
            }
            // Admission to this bounded channel is NOT downstream acknowledgement.
            collector = tokio::task::spawn_blocking(move || {
                collector.commit()?;
                Ok::<_, io::Error>(collector)
            })
            .await
            .map_err(|_| module_error("checkpoint task failed"))?
            .map_err(|_| module_error("checkpoint persistence failed"))?;
            tokio::time::sleep(Duration::from_millis(self.config.poll_interval_millis)).await;
        }
    }
}
fn module_error(message: &str) -> CoreError {
    CoreError::ModuleFailed {
        module: SOURCE.into(),
        message: message.into(),
    }
}
fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

#[derive(Debug)]
enum Collected {
    Log(ApplicationLogObservation),
    Warning(Outcome, u64),
}
#[derive(Debug, Clone)]
struct Identity {
    namespace: String,
    pod: String,
    uid: String,
    container: String,
    restart: u32,
}
#[derive(Debug)]
struct Partial {
    body: Vec<u8>,
    bytes: u64,
    timestamp: String,
    start: u64,
    since: u64,
    truncated: bool,
}
#[derive(Debug)]
struct Tracked {
    file: File,
    path: std::path::PathBuf,
    identity: Identity,
    offset: u64,
    line_start: u64,
    line: Vec<u8>,
    oversized: bool,
    line_since: Option<u64>,
    partials: [Option<Partial>; 2],
    last_seen: u64,
    prefix: Anchor,
    tail: Anchor,
}
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Anchor {
    start: u64,
    len: u64,
    hash: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Checkpoint {
    key: String,
    offset: u64,
    prefix: Anchor,
    tail: Anchor,
    last_seen: u64,
}
#[derive(Debug, Serialize, Deserialize)]
struct Checkpoints {
    version: u16,
    entries: Vec<Checkpoint>,
}
#[derive(Debug)]
struct Collector {
    config: CriLogsConfig,
    directory: File,
    _lock: File,
    files: BTreeMap<String, Tracked>,
    saved: BTreeMap<String, Checkpoint>,
    rejected: bool,
    initial_scan: bool,
    scan: Vec<(std::path::PathBuf, std::fs::ReadDir, usize)>,
    read_cursor: usize,
    startup_time: Option<u64>,
}

/// Walk each component through directory descriptors, refusing symlinks even during replacement.
fn directory(path: &Path, create: bool) -> io::Result<File> {
    if !path.is_absolute() {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let mut dir = File::open("/")?;
    for component in path.components() {
        let Component::Normal(name) = component else {
            if component == Component::RootDir {
                continue;
            }
            return Err(io::ErrorKind::InvalidInput.into());
        };
        if create {
            match mkdirat(&dir, name, Mode::from_raw_mode(0o700)) {
                Ok(()) => {
                    dir.sync_all()?;
                }
                Err(rustix::io::Errno::EXIST) => {}
                Err(e) => return Err(e.into()),
            }
        }
        dir = openat(
            &dir,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?
        .into();
    }
    Ok(dir)
}
fn regular(dir: &File, name: &std::ffi::OsStr, flags: OFlags) -> io::Result<File> {
    let file: File = openat(
        dir,
        name,
        flags | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600),
    )?
    .into();
    if !file.metadata()?.is_file() {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    Ok(file)
}
fn anchor(file: &mut File, start: u64, len: u64) -> io::Result<Anchor> {
    file.seek(SeekFrom::Start(start))?;
    let mut bytes = vec![0; len as usize];
    file.read_exact(&mut bytes)?;
    // ponytail: bounded 64-byte identity anchors, not cryptographic integrity or deduplication.
    let hash = bytes.iter().fold(0xcbf29ce484222325u64, |h, b| {
        (h ^ u64::from(*b)).wrapping_mul(0x100000001b3)
    });
    Ok(Anchor { start, len, hash })
}
fn matches_anchor(file: &mut File, expected: &Anchor) -> io::Result<bool> {
    Ok(expected.len == 0
        || (expected.len <= 64
            && anchor(file, expected.start, expected.len)?.hash == expected.hash))
}

impl Collector {
    fn new(config: CriLogsConfig) -> io::Result<Self> {
        config
            .validate()
            .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        directory(&config.root, false)?;
        let dir = directory(&config.checkpoint_dir, true)?;
        let lock = regular(
            &dir,
            std::ffi::OsStr::new("lock"),
            OFlags::RDWR | OFlags::CREATE,
        )?;
        lock.try_lock()
            .map_err(|_| io::Error::from(io::ErrorKind::WouldBlock))?;
        let mut saved = BTreeMap::new();
        let mut rejected = false;
        match regular(
            &dir,
            std::ffi::OsStr::new("checkpoints.json"),
            OFlags::RDONLY,
        ) {
            Ok(file) => {
                let mut bytes = Vec::new();
                file.take((config.max_files * 2048 + 1) as u64)
                    .read_to_end(&mut bytes)?;
                match serde_json::from_slice::<Checkpoints>(&bytes) {
                    Ok(snapshot)
                        if snapshot.version == 1
                            && snapshot.entries.len() <= config.max_files
                            && bytes.len() <= config.max_files * 2048 =>
                    {
                        for c in snapshot.entries {
                            if c.key.len() > 1280
                                || c.key.is_empty()
                                || c.prefix.len != c.offset.min(64)
                                || c.tail.len != c.offset.min(64)
                                || c.prefix.start != 0
                                || c.tail.start != c.offset.saturating_sub(64)
                                || saved.contains_key(&c.key)
                            {
                                rejected = true;
                                break;
                            }
                            saved.insert(c.key.clone(), c);
                        }
                    }
                    _ => rejected = true,
                }
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(_) => rejected = true,
        }
        if rejected {
            saved.clear();
        }
        Ok(Self {
            config,
            directory: dir,
            _lock: lock,
            files: BTreeMap::new(),
            saved,
            rejected,
            initial_scan: !rejected,
            scan: Vec::new(),
            read_cursor: 0,
            startup_time: None,
        })
    }

    fn poll(&mut self, now: u64) -> io::Result<Vec<Collected>> {
        let mut out = Vec::new();
        let startup = *self.startup_time.get_or_insert(now);
        // Recovery eligibility is measured at startup, not at the eventual discovery poll.
        let checkpoint_now = if self.initial_scan { startup } else { now };
        if self.rejected {
            out.push(Collected::Warning(Outcome::CheckpointRejected, 1));
            self.rejected = false;
        }
        // Presence is independent of the incremental discovery work budget.
        use std::os::unix::fs::MetadataExt;
        for file in self.files.values_mut() {
            if let Some(parent) = file.path.parent()
                && let Ok(dir) = directory(parent, false)
                && let Some(name) = file.path.file_name()
                && let Ok(current) = regular(&dir, name, OFlags::RDONLY)
                && let (Ok(current), Ok(held)) = (current.metadata(), file.file.metadata())
                && current.dev() == held.dev()
                && current.ino() == held.ino()
            {
                file.last_seen = now;
            }
        }
        let expired_saved = self
            .saved
            .iter()
            .filter(|(k, c)| {
                !self.files.contains_key(*k)
                    && checkpoint_now.saturating_sub(c.last_seen) > self.config.retained_file_millis
            })
            .count();
        if expired_saved > 0 {
            out.push(Collected::Warning(
                Outcome::RetentionExpired,
                expired_saved as u64,
            ));
        }
        self.saved.retain(|_, c| {
            checkpoint_now.saturating_sub(c.last_seen) <= self.config.retained_file_millis
        });
        // Expire idle files before discovery, so churn cannot permanently fill the table.
        let expired: Vec<_> = self
            .files
            .iter()
            .filter(|(_, f)| now.saturating_sub(f.last_seen) > self.config.retained_file_millis)
            .map(|(k, _)| k.clone())
            .collect();
        for key in expired {
            if let Some(mut file) = self.files.remove(&key) {
                file.flush_expired(now, &self.config, &mut out, true);
                out.push(Collected::Warning(Outcome::RetentionExpired, 1));
            }
            self.saved.remove(&key);
        }
        self.discover(now, &mut out)?;
        let keys: Vec<_> = self.files.keys().cloned().collect();
        for i in 0..keys.len() {
            if out.len() >= MAX_BATCH_RECORDS - 4 {
                break;
            }
            let index = (self.read_cursor + i) % keys.len();
            if let Some(file) = self.files.get_mut(&keys[index]) {
                file.read(now, &self.config, &mut out)?;
            }
        }
        self.read_cursor = self.read_cursor.wrapping_add(1);
        Ok(out)
    }

    fn discover(&mut self, now: u64, out: &mut Vec<Collected>) -> io::Result<()> {
        use std::os::unix::fs::MetadataExt;
        let mut budget = self.config.max_discovery_entries;
        let mut file_limit = 0;
        let mut unsafe_paths = 0;
        // A resumable depth-first walk keeps discovery work bounded and prevents starvation.
        if self.scan.is_empty() {
            directory(&self.config.root, false)?;
            self.scan.push((
                self.config.root.clone(),
                std::fs::read_dir(&self.config.root)?,
                0,
            ));
        }
        while budget > 0 {
            let Some((path, entries, depth)) = self.scan.last_mut() else {
                self.initial_scan = false;
                break;
            };
            let path = path.clone();
            let depth = *depth;
            let Some(entry) = entries.next() else {
                self.scan.pop();
                continue;
            };
            budget -= 1;
            let entry = match entry {
                Ok(e) => e,
                Err(_) => {
                    unsafe_paths += 1;
                    continue;
                }
            };
            let kind = match entry.file_type() {
                Ok(k) => k,
                Err(_) => {
                    unsafe_paths += 1;
                    continue;
                }
            };
            if kind.is_symlink() {
                unsafe_paths += 1;
                continue;
            }
            if kind.is_dir() && depth < 2 {
                match std::fs::read_dir(entry.path()) {
                    Ok(entries) => self.scan.push((entry.path(), entries, depth + 1)),
                    Err(_) => unsafe_paths += 1,
                }
                continue;
            }
            if depth != 2 || !kind.is_file() {
                continue;
            }
            let Some(identity) = identity(&entry.path()) else {
                continue;
            };
            let parent = match directory(&path, false) {
                Ok(p) => p,
                Err(_) => {
                    unsafe_paths += 1;
                    continue;
                }
            };
            let mut file = match regular(&parent, &entry.file_name(), OFlags::RDONLY) {
                Ok(f) => f,
                Err(_) => {
                    unsafe_paths += 1;
                    continue;
                }
            };
            let metadata = file.metadata()?;
            let key = format!(
                "{}/{}/{}/{}/{}:{}:{}",
                identity.namespace,
                identity.pod,
                identity.uid,
                identity.container,
                identity.restart,
                metadata.dev(),
                metadata.ino()
            );
            if let Some(tracked) = self.files.get_mut(&key) {
                tracked.last_seen = now;
                tracked.path = entry.path();
                continue;
            }
            if self.files.len() >= self.config.max_files
                || (!self.saved.contains_key(&key)
                    && self.files.len()
                        + self
                            .saved
                            .keys()
                            .filter(|k| !self.files.contains_key(*k))
                            .count()
                        >= self.config.max_files)
            {
                file_limit += 1;
                continue;
            }
            let mut offset = if self.initial_scan && self.config.initial_read == LogInitialRead::End
            {
                metadata.len()
            } else {
                0
            };
            if let Some(saved) = self.saved.get(&key) {
                let checkpoint_now = if self.initial_scan {
                    self.startup_time.unwrap_or(now)
                } else {
                    now
                };
                if checkpoint_now.saturating_sub(saved.last_seen)
                    <= self.config.retained_file_millis
                    && metadata.len() >= saved.offset
                    && matches_anchor(&mut file, &saved.prefix).unwrap_or(false)
                    && matches_anchor(&mut file, &saved.tail).unwrap_or(false)
                {
                    offset = saved.offset;
                } else {
                    offset = 0;
                    out.push(Collected::Warning(Outcome::FileReset, 1));
                }
            }
            let prefix = anchor(&mut file, 0, offset.min(64))?;
            let tail = anchor(&mut file, offset.saturating_sub(64), offset.min(64))?;
            self.files.insert(
                key,
                Tracked {
                    file,
                    path: entry.path(),
                    identity,
                    offset,
                    line_start: offset,
                    line: Vec::new(),
                    oversized: false,
                    line_since: None,
                    partials: [None, None],
                    last_seen: now,
                    prefix,
                    tail,
                },
            );
        }
        if budget == 0 && !self.scan.is_empty() {
            out.push(Collected::Warning(Outcome::DiscoveryLimit, 1));
        }
        if file_limit > 0 {
            out.push(Collected::Warning(Outcome::FileLimit, file_limit));
        }
        if unsafe_paths > 0 {
            out.push(Collected::Warning(Outcome::UnsafePath, unsafe_paths));
        }
        Ok(())
    }

    fn commit(&mut self) -> io::Result<()> {
        let mut checkpoints = self.saved.clone();
        for (key, file) in &mut self.files {
            if !matches_anchor(&mut file.file, &file.prefix)?
                || !matches_anchor(&mut file.file, &file.tail)?
            {
                return Err(io::ErrorKind::InvalidData.into());
            }
            let offset = file.committed_offset();
            let c = Checkpoint {
                key: key.clone(),
                offset,
                prefix: anchor(&mut file.file, 0, offset.min(64))?,
                tail: anchor(&mut file.file, offset.saturating_sub(64), offset.min(64))?,
                last_seen: file.last_seen,
            };
            checkpoints.insert(key.clone(), c);
        }
        let entries: Vec<_> = checkpoints.into_values().collect();
        let bytes = serde_json::to_vec(&Checkpoints {
            version: 1,
            entries: entries.clone(),
        })?;
        // A crashed writer's temp file is never recovery input.
        match unlinkat(&self.directory, "checkpoints.tmp", AtFlags::empty()) {
            Ok(()) | Err(rustix::io::Errno::NOENT) => {}
            Err(e) => return Err(e.into()),
        }
        let mut temp = regular(
            &self.directory,
            std::ffi::OsStr::new("checkpoints.tmp"),
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL,
        )?;
        use std::io::Write;
        temp.write_all(&bytes)?;
        temp.sync_all()?;
        renameat(
            &self.directory,
            "checkpoints.tmp",
            &self.directory,
            "checkpoints.json",
        )?;
        self.directory.sync_all()?;
        self.saved = entries.into_iter().map(|c| (c.key.clone(), c)).collect();
        Ok(())
    }
}

fn identity(path: &Path) -> Option<Identity> {
    let name = path.file_name()?.to_str()?;
    let (restart, suffix) = name.split_once(".log")?;
    if !suffix.is_empty() && !suffix.starts_with('.') {
        return None;
    }
    // Compressed archives need a separate decoder; never claim to ingest them.
    let parent = path.parent()?;
    let container = parent.file_name()?.to_str()?;
    let mut pod = parent.parent()?.file_name()?.to_str()?.splitn(3, '_');
    let namespace = pod.next()?;
    let name = pod.next()?;
    let uid = pod.next()?;
    if [namespace, name, uid, container]
        .iter()
        .any(|s| s.is_empty() || s.len() > 256 || s.bytes().any(|b| b.is_ascii_control()))
    {
        return None;
    }
    Some(Identity {
        namespace: namespace.into(),
        pod: name.into(),
        uid: uid.into(),
        container: container.into(),
        restart: restart.parse().ok()?,
    })
}

impl Tracked {
    fn committed_offset(&self) -> u64 {
        self.partials
            .iter()
            .flatten()
            .map(|p| p.start)
            .fold(self.line_start, u64::min)
    }
    fn read(
        &mut self,
        now: u64,
        config: &CriLogsConfig,
        out: &mut Vec<Collected>,
    ) -> io::Result<()> {
        if self.file.metadata()?.len() < self.offset
            || !matches_anchor(&mut self.file, &self.prefix).unwrap_or(false)
            || !matches_anchor(&mut self.file, &self.tail).unwrap_or(false)
        {
            self.flush_expired(now, config, out, true);
            self.offset = 0;
            self.line_start = 0;
            self.line.clear();
            self.line_since = None;
            self.oversized = false;
            self.partials = [None, None];
            out.push(Collected::Warning(Outcome::FileReset, 1));
        }
        self.file.seek(SeekFrom::Start(self.offset))?;
        let mut bytes = Vec::new();
        (&mut self.file)
            .take(config.max_read_bytes_per_file as u64)
            .read_to_end(&mut bytes)?;
        for byte in bytes {
            if out.len() >= MAX_BATCH_RECORDS - 4 {
                break;
            }
            self.line_since.get_or_insert(now);
            self.offset += 1;
            if byte == b'\n' {
                if self.oversized {
                    self.flush_partials(now, config, out);
                    out.push(Collected::Warning(Outcome::RecordTooLarge, 1));
                } else {
                    self.consume(now, config, out);
                }
                self.line.clear();
                self.line_start = self.offset;
                self.line_since = None;
                self.oversized = false;
            } else if self.line.len() < config.max_record_bytes {
                self.line.push(byte);
            } else {
                self.oversized = true;
            }
        }
        self.flush_expired(now, config, out, false);
        // Anchors cover consumed bytes, not bytes appended after this poll.
        self.prefix = anchor(&mut self.file, 0, self.offset.min(64))?;
        self.tail = anchor(
            &mut self.file,
            self.offset.saturating_sub(64),
            self.offset.min(64),
        )?;
        Ok(())
    }
    fn consume(&mut self, now: u64, config: &CriLogsConfig, out: &mut Vec<Collected>) {
        let mut fields = self.line.splitn(4, |b| *b == b' ');
        let parsed = (|| {
            let timestamp = std::str::from_utf8(fields.next()?).ok()?;
            if !valid_timestamp(timestamp) {
                return None;
            }
            let stream = match fields.next()? {
                b"stdout" => LogStream::Stdout,
                b"stderr" => LogStream::Stderr,
                _ => return None,
            };
            let full = match fields.next()? {
                b"F" => true,
                b"P" => false,
                _ => return None,
            };
            Some((timestamp.to_string(), stream, full, fields.next()?.to_vec()))
        })();
        let Some((timestamp, stream, full, body)) = parsed else {
            self.flush_partials(now, config, out);
            out.push(Collected::Warning(Outcome::UnsupportedFormat, 1));
            return;
        };
        let index = if stream == LogStream::Stdout { 0 } else { 1 };
        let partial = self.partials[index].get_or_insert_with(|| Partial {
            body: Vec::new(),
            bytes: 0,
            timestamp,
            start: self.line_start,
            since: now,
            truncated: false,
        });
        partial.bytes = partial.bytes.saturating_add(body.len() as u64);
        let available = config.max_record_bytes.saturating_sub(partial.body.len());
        partial.truncated |= body.len() > available;
        partial
            .body
            .extend_from_slice(&body[..body.len().min(available)]);
        if full && let Some(partial) = self.partials[index].take() {
            out.push(Collected::Log(
                self.log(partial, stream, now, config, false),
            ));
        }
    }
    fn log(
        &self,
        p: Partial,
        stream: LogStream,
        now: u64,
        config: &CriLogsConfig,
        incomplete: bool,
    ) -> ApplicationLogObservation {
        let invalid_utf8 = std::str::from_utf8(&p.body).is_err();
        let mut truncated = p.truncated;
        let body = config.include_body.then(|| {
            let mut body = String::from_utf8_lossy(&p.body).into_owned();
            if body.len() > config.max_record_bytes {
                let mut end = config.max_record_bytes;
                while !body.is_char_boundary(end) {
                    end -= 1;
                }
                body.truncate(end);
                truncated = true;
            }
            body
        });
        ApplicationLogObservation {
            namespace: self.identity.namespace.clone(),
            pod_name: self.identity.pod.clone(),
            pod_uid: self.identity.uid.clone(),
            container_name: self.identity.container.clone(),
            restart_count: self.identity.restart,
            stream,
            timestamp: p.timestamp,
            observed_at_unix_nanos: now.saturating_mul(1_000_000),
            body,
            body_bytes: p.bytes,
            truncated,
            incomplete,
            invalid_utf8,
        }
    }
    fn flush_partials(&mut self, now: u64, config: &CriLogsConfig, out: &mut Vec<Collected>) {
        for (index, stream) in [LogStream::Stdout, LogStream::Stderr]
            .into_iter()
            .enumerate()
        {
            if let Some(p) = self.partials[index].take() {
                out.push(Collected::Log(self.log(p, stream, now, config, true)));
            }
        }
    }
    fn flush_expired(
        &mut self,
        now: u64,
        config: &CriLogsConfig,
        out: &mut Vec<Collected>,
        force: bool,
    ) {
        for (index, stream) in [LogStream::Stdout, LogStream::Stderr]
            .into_iter()
            .enumerate()
        {
            if self.partials[index].as_ref().is_some_and(|p| {
                force || now.saturating_sub(p.since) >= config.assembly_timeout_millis
            }) && let Some(p) = self.partials[index].take()
            {
                out.push(Collected::Log(self.log(p, stream, now, config, true)));
            }
        }
        if self.line_since.is_some_and(|since| {
            force || now.saturating_sub(since) >= config.assembly_timeout_millis
        }) {
            // CRI normally ends each physical record in LF. Surface an exit-final fragment.
            if self.oversized {
                out.push(Collected::Warning(Outcome::RecordTooLarge, 1));
            } else {
                let before = out.len();
                self.consume(now, config, out);
                for item in &mut out[before..] {
                    if let Collected::Log(log) = item {
                        log.incomplete = true;
                    }
                }
                for (index, stream) in [LogStream::Stdout, LogStream::Stderr]
                    .into_iter()
                    .enumerate()
                {
                    if let Some(p) = self.partials[index].take() {
                        out.push(Collected::Log(self.log(p, stream, now, config, true)));
                    }
                }
            }
            self.line.clear();
            self.line_start = self.offset;
            self.line_since = None;
            self.oversized = false;
        }
    }
}

/// CRI uses RFC3339 UTC, with optional fractional seconds through nanoseconds.
fn valid_timestamp(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() < 20
        || b.len() > 30
        || b[4] != b'-'
        || b[7] != b'-'
        || b[10] != b'T'
        || b[13] != b':'
        || b[16] != b':'
        || b.last() != Some(&b'Z')
    {
        return false;
    }
    let number = |range: std::ops::Range<usize>| -> Option<u32> {
        let bytes = b.get(range)?;
        if !bytes.iter().all(u8::is_ascii_digit) {
            return None;
        }
        bytes
            .iter()
            .try_fold(0u32, |v, c| Some(v * 10 + u32::from(c - b'0')))
    };
    let (Some(year), Some(month), Some(day), Some(hour), Some(minute), Some(second)) = (
        number(0..4),
        number(5..7),
        number(8..10),
        number(11..13),
        number(14..16),
        number(17..19),
    ) else {
        return false;
    };
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) => 29,
        2 => 28,
        _ => 0,
    };
    year > 0
        && day > 0
        && day <= days
        && hour < 24
        && minute < 60
        && second < 60
        && (b.len() == 20
            || (b.len() >= 22
                && b[19] == b'.'
                && b[20..b.len() - 1].iter().all(u8::is_ascii_digit)))
}

#[cfg(test)]
mod tests;
