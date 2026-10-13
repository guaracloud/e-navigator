//! One crash-consistent, checksummed OTLP request per segment. No payload Debug.
use flate2::Crc;
use rustix::fs::{AtFlags, Dir, Mode, OFlags, mkdirat, openat, renameat, unlinkat};
use std::{
    collections::BTreeMap,
    fs::File,
    io::{self, Read, Write},
    path::{Component, Path},
};

const HEADER: usize = 36;
pub(crate) const MAX_SEGMENT_BYTES: usize = 4 * 1024 * 1024;
// ponytail: one request per segment; add multi-record journaling only if measured append throughput requires it.
const MAGIC: &[u8; 8] = b"ENSP0001";

pub(crate) struct Entry {
    pub id: u64,
    pub count: u64,
    pub body: Vec<u8>,
}

#[derive(Debug)]
pub(crate) struct Spool {
    directory: File,
    _lock: File,
    entries: BTreeMap<u64, u64>,
    next_id: u64,
    pub bytes: u64,
    max_bytes: u64,
    max_entries: usize,
    max_age_millis: u64,
    pub expired: u64,
    #[cfg(test)]
    pub(crate) fail_at: u8,
}

impl Spool {
    pub(crate) fn open(
        path: &Path,
        max_bytes: u64,
        max_entries: usize,
        max_age_millis: u64,
    ) -> io::Result<Self> {
        let directory = directory(path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if directory.metadata()?.permissions().mode() & 0o077 != 0 {
                return Err(io::ErrorKind::PermissionDenied.into());
            }
        }
        let lock = regular(&directory, "lock", OFlags::RDWR | OFlags::CREATE)?;
        lock.try_lock()
            .map_err(|_| io::Error::from(io::ErrorKind::WouldBlock))?;
        let mut spool = Self {
            directory,
            _lock: lock,
            entries: BTreeMap::new(),
            next_id: 0,
            bytes: 0,
            max_bytes,
            max_entries,
            max_age_millis,
            expired: 0,
            #[cfg(test)]
            fail_at: 0,
        };
        for item in Dir::read_from(&spool.directory)? {
            let item = item?;
            let name = item.file_name().to_str().map_err(|_| invalid())?;
            if matches!(name, "." | ".." | "lock") {
                continue;
            }
            if name == "pending.tmp" {
                regular(&spool.directory, name, OFlags::RDONLY)?;
                unlinkat(&spool.directory, name, AtFlags::empty())?;
                spool.directory.sync_all()?;
                continue;
            }
            let id = name
                .strip_suffix(".spool")
                .filter(|s| s.len() == 16)
                .and_then(|s| u64::from_str_radix(s, 16).ok())
                .ok_or_else(invalid)?;
            if name != filename(id) {
                return Err(invalid());
            }
            if spool.entries.len() >= max_entries {
                return Err(invalid());
            }
            let file = regular(&spool.directory, name, OFlags::RDONLY)?;
            let size = file.metadata()?.len();
            if size > MAX_SEGMENT_BYTES as u64
                || size < HEADER as u64
                || spool.bytes.saturating_add(size) > max_bytes
            {
                return Err(invalid());
            }
            let _ = read_entry(file, id)?;
            spool.entries.insert(id, size);
            spool.bytes += size;
            spool.next_id = spool.next_id.max(id.checked_add(1).ok_or_else(invalid)?);
        }
        Ok(spool)
    }

    pub(crate) fn append(&mut self, body: &[u8], count: u64, now: u64) -> io::Result<()> {
        let size = HEADER as u64 + body.len() as u64;
        if count == 0
            || body.is_empty()
            || size > MAX_SEGMENT_BYTES as u64
            || self.bytes.saturating_add(size) > self.max_bytes
            || self.entries.len() >= self.max_entries
        {
            return Err(io::ErrorKind::StorageFull.into());
        }
        let id = self.next_id;
        let next = id.checked_add(1).ok_or_else(invalid)?;
        let mut bytes = Vec::with_capacity(size as usize);
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&now.to_le_bytes());
        bytes.extend_from_slice(&count.to_le_bytes());
        bytes.extend_from_slice(&(body.len() as u64).to_le_bytes());
        let mut crc = Crc::new();
        crc.update(&bytes);
        crc.update(body);
        bytes.extend_from_slice(&crc.sum().to_le_bytes());
        bytes.extend_from_slice(body);
        // Failed writes leave an unaccepted temp file, never a replayable segment.
        match unlinkat(&self.directory, "pending.tmp", AtFlags::empty()) {
            Ok(()) => {}
            Err(e) if e == rustix::io::Errno::NOENT => {}
            Err(e) => return Err(e.into()),
        }
        let mut file = regular(
            &self.directory,
            "pending.tmp",
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL,
        )?;
        #[cfg(test)]
        self.fault(1)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        #[cfg(test)]
        self.fault(2)?;
        renameat(
            &self.directory,
            "pending.tmp",
            &self.directory,
            filename(id),
        )?;
        // Track an uncertain append so later admissions cannot overwrite its segment.
        self.entries.insert(id, size);
        self.bytes += size;
        self.next_id = next;
        #[cfg(test)]
        self.fault(3)?;
        self.directory.sync_all()
    }

    pub(crate) fn front(&mut self, now: u64) -> io::Result<Option<Entry>> {
        while let Some((&id, _)) = self.entries.first_key_value() {
            let file = regular(&self.directory, &filename(id), OFlags::RDONLY)?;
            let (created, entry) = read_entry(file, id)?;
            if now.saturating_sub(created) <= self.max_age_millis {
                return Ok(Some(entry));
            }
            self.ack(id)?;
            self.expired = self.expired.saturating_add(entry.count);
        }
        Ok(None)
    }

    pub(crate) fn ack(&mut self, id: u64) -> io::Result<()> {
        #[cfg(test)]
        self.fault(4)?;
        unlinkat(&self.directory, filename(id), AtFlags::empty())?;
        #[cfg(test)]
        self.fault(5)?;
        self.directory.sync_all()?;
        if let Some(size) = self.entries.remove(&id) {
            self.bytes -= size;
        }
        Ok(())
    }

    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }
}

fn filename(id: u64) -> String {
    format!("{id:016x}.spool")
}
fn invalid() -> io::Error {
    io::ErrorKind::InvalidData.into()
}
fn read_entry(file: File, id: u64) -> io::Result<(u64, Entry)> {
    let mut bytes = Vec::new();
    file.take(MAX_SEGMENT_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() < HEADER || bytes.len() > MAX_SEGMENT_BYTES || &bytes[..8] != MAGIC {
        return Err(invalid());
    }
    let number = |start| -> io::Result<u64> {
        Ok(u64::from_le_bytes(
            bytes[start..start + 8].try_into().map_err(|_| invalid())?,
        ))
    };
    let created = number(8)?;
    let count = number(16)?;
    let size = number(24)?;
    let expected = u32::from_le_bytes(bytes[32..36].try_into().map_err(|_| invalid())?);
    let mut crc = Crc::new();
    crc.update(&bytes[..32]);
    crc.update(&bytes[HEADER..]);
    if size != (bytes.len() - HEADER) as u64
        || size == 0
        || count == 0
        || count > 4096
        || expected != crc.sum()
    {
        return Err(invalid());
    }
    Ok((
        created,
        Entry {
            id,
            count,
            body: bytes.split_off(HEADER),
        },
    ))
}

fn directory(path: &Path) -> io::Result<File> {
    if !path.is_absolute() {
        return Err(invalid());
    }
    let mut dir = File::open("/")?;
    for component in path.components() {
        let Component::Normal(name) = component else {
            if component == Component::RootDir {
                continue;
            }
            return Err(invalid());
        };
        match mkdirat(&dir, name, Mode::from_raw_mode(0o700)) {
            Ok(()) => dir.sync_all()?,
            Err(e) if e == rustix::io::Errno::EXIST => {}
            Err(e) => return Err(e.into()),
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
fn regular(dir: &File, name: &str, flags: OFlags) -> io::Result<File> {
    let file: File = openat(
        dir,
        name,
        flags | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600),
    )?
    .into();
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let metadata = file.metadata()?;
        if metadata.nlink() != 1 || metadata.permissions().mode() & 0o077 != 0 {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
    }
    if !file.metadata()?.is_file() {
        return Err(invalid());
    }
    Ok(file)
}

#[cfg(test)]
impl Spool {
    fn fault(&mut self, point: u8) -> io::Result<()> {
        if self.fail_at == point {
            self.fail_at = 0;
            Err(io::Error::from_raw_os_error(
                rustix::io::Errno::NOSPC.raw_os_error(),
            ))
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
pub(crate) mod tests {
    use super::*;
    use std::{
        fs,
        sync::atomic::{AtomicU64, Ordering},
    };

    pub(crate) struct Fixture(pub(crate) std::path::PathBuf);
    impl Fixture {
        pub(crate) fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let path = fs::canonicalize(std::env::temp_dir())
                .unwrap()
                .join(format!(
                    "e-navigator-spool-{}-{}",
                    std::process::id(),
                    NEXT.fetch_add(1, Ordering::Relaxed)
                ));
            {
                use std::os::unix::fs::DirBuilderExt;
                fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
            }
            Self(path)
        }
        fn spool(&self) -> Spool {
            Spool::open(&self.0, 1024, 4, 1000).unwrap()
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    #[test]
    fn append_is_replayed_until_synced_ack() {
        let f = Fixture::new();
        let mut spool = f.spool();
        spool.append(b"redacted request", 1, 10).unwrap();
        drop(spool); // crash after append, before send
        let mut spool = f.spool();
        let entry = spool.front(20).unwrap().unwrap();
        assert_eq!(entry.body, b"redacted request");
        assert_eq!(entry.count, 1);
        drop(spool); // backend accepted, crash before local ack
        let mut spool = f.spool();
        assert_eq!(spool.front(30).unwrap().unwrap().body, entry.body);
        spool.ack(entry.id).unwrap();
        drop(spool);
        assert!(f.spool().front(40).unwrap().is_none());
    }

    #[test]
    fn corrupt_truncated_and_unknown_versions_fail_closed() {
        for kind in 0..3 {
            let f = Fixture::new();
            let mut spool = f.spool();
            spool.append(b"payload", 1, 10).unwrap();
            drop(spool);
            let path = fs::read_dir(&f.0)
                .unwrap()
                .map(|e| e.unwrap().path())
                .find(|p| p.extension().is_some_and(|v| v == "spool"))
                .unwrap();
            let mut bytes = fs::read(&path).unwrap();
            match kind {
                0 => {
                    bytes.pop();
                }
                1 => {
                    *bytes.last_mut().unwrap() ^= 1;
                }
                _ => {
                    bytes[7] = b'9';
                }
            }
            fs::write(path, bytes).unwrap();
            assert!(Spool::open(&f.0, 1024, 4, 1000).is_err());
        }
    }

    #[test]
    fn bounds_expiry_lock_and_failed_append_are_visible() {
        let f = Fixture::new();
        let mut spool = Spool::open(&f.0, 80, 1, 1000).unwrap();
        assert!(Spool::open(&f.0, 80, 1, 1000).is_err());
        assert!(spool.append(&[0; 81], 1, 10).is_err());
        spool.append(b"first", 1, 10).unwrap();
        assert!(spool.append(b"second", 1, 10).is_err());
        assert!(spool.front(1011).unwrap().is_none());
        assert_eq!(spool.expired, 1);
        // An actual filesystem write failure must not become durable acceptance.
        fs::create_dir(f.0.join("pending.tmp")).unwrap();
        assert!(spool.append(b"disk write fails", 1, 1012).is_err());
        assert_eq!(spool.bytes, 0);
        assert!(spool.front(1012).unwrap().is_none());
    }

    #[test]
    fn injected_disk_full_and_crashes_preserve_only_committed_segments() {
        for point in [1, 2, 3, 4, 5] {
            let f = Fixture::new();
            let mut spool = f.spool();
            if point >= 4 {
                spool.append(b"accepted", 1, 10).unwrap();
                let id = spool.front(10).unwrap().unwrap().id;
                spool.fail_at = point;
                assert_eq!(
                    spool.ack(id).unwrap_err().kind(),
                    io::ErrorKind::StorageFull
                );
            } else {
                spool.fail_at = point;
                assert_eq!(
                    spool.append(b"accepted", 1, 10).unwrap_err().kind(),
                    io::ErrorKind::StorageFull
                );
            }
            drop(spool);
            let recovered = f.spool().front(10).unwrap();
            assert_eq!(recovered.is_some(), point == 3 || point == 4);
        }
    }

    #[cfg(unix)]
    #[test]
    fn private_files_and_symlink_roots() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let f = Fixture::new();
        let mut spool = f.spool();
        spool.append(b"processed", 1, 0).unwrap();
        for path in fs::read_dir(&f.0)
            .unwrap()
            .map(|v| v.unwrap().path())
            .filter(|p| p.is_file())
        {
            assert_eq!(
                fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        symlink(&f.0, f.0.join("alias")).unwrap();
        assert!(Spool::open(&f.0.join("alias"), 1024, 4, 1000).is_err());
    }
}
