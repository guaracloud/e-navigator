use async_trait::async_trait;
use e_navigator_core::{CoreError, CoreResult, ModuleKind, ModuleMetadata, Source};
use e_navigator_signals::{
    CgroupCpuObservation, CgroupFileDescriptorObservation, CgroupMemoryObservation,
    CgroupPidsObservation, CgroupResourceContext, MetricAggregationWindow, NodeCpuObservation,
    NodeDiskIoObservation, NodeLoadObservation, NodeMemoryObservation, ProcessResourceContext,
    ProcessResourceObservation, SignalEnvelope,
};
use std::{
    collections::VecDeque,
    fs::{self, File},
    io::Read,
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::mpsc;
use tracing::warn;

const MAX_FILE_BYTES: u64 = 128 * 1024;
const DISK_SECTOR_BYTES: u64 = 512;
const DEFAULT_MAX_PROCESSES: usize = 128;
const DEFAULT_MAX_CGROUPS: usize = 128;
const DEFAULT_MAX_FDS_PER_PROCESS: usize = 1024;
const DEFAULT_SAMPLE_INTERVAL_MILLIS: u64 = 15_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostResourceConfig {
    pub procfs_root: PathBuf,
    pub sysfs_root: PathBuf,
    pub cgroup_root: PathBuf,
    pub sample_interval_millis: u64,
    pub max_processes: usize,
    pub max_cgroups: usize,
    pub max_fds_per_process: usize,
    pub max_file_bytes: u64,
}

impl Default for HostResourceConfig {
    fn default() -> Self {
        Self {
            procfs_root: PathBuf::from("/proc"),
            sysfs_root: PathBuf::from("/sys"),
            cgroup_root: PathBuf::from("/sys/fs/cgroup"),
            sample_interval_millis: DEFAULT_SAMPLE_INTERVAL_MILLIS,
            max_processes: DEFAULT_MAX_PROCESSES,
            max_cgroups: DEFAULT_MAX_CGROUPS,
            max_fds_per_process: DEFAULT_MAX_FDS_PER_PROCESS,
            max_file_bytes: MAX_FILE_BYTES,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct HostResourceSnapshot {
    pub signals: Vec<SignalEnvelope>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct HostResourceSource {
    config: HostResourceConfig,
    host: Option<String>,
}

impl HostResourceSource {
    pub fn new(config: HostResourceConfig) -> Self {
        Self { config, host: None }
    }

    pub fn with_host(config: HostResourceConfig, host: Option<String>) -> Self {
        Self { config, host }
    }

    pub fn config(&self) -> &HostResourceConfig {
        &self.config
    }

    pub fn sample_once(&self) -> HostResourceSnapshot {
        sample_host_resources(&self.config, self.host.clone())
    }
}

#[async_trait]
impl Source<SignalEnvelope> for HostResourceSource {
    fn metadata(&self) -> ModuleMetadata {
        ModuleMetadata::new("source.host_resource", ModuleKind::Source)
    }

    async fn run(self: Box<Self>, tx: mpsc::Sender<SignalEnvelope>) -> CoreResult<()> {
        let source = *self;
        loop {
            let config = source.config.clone();
            let host = source.host.clone();
            let snapshot =
                tokio::task::spawn_blocking(move || sample_host_resources(&config, host))
                    .await
                    .map_err(|err| CoreError::ModuleFailed {
                        module: "source.host_resource".to_string(),
                        message: err.to_string(),
                    })?;

            for warning in snapshot.warnings {
                warn!(warning, "host resource observation warning");
            }

            for signal in snapshot.signals {
                tx.send(signal)
                    .await
                    .map_err(|_| CoreError::PipelineClosed)?;
            }

            if source.config.sample_interval_millis == 0 {
                return Ok(());
            }

            tokio::time::sleep(Duration::from_millis(source.config.sample_interval_millis)).await;
        }
    }
}

fn sample_host_resources(
    config: &HostResourceConfig,
    host: Option<String>,
) -> HostResourceSnapshot {
    let started = now_unix_nanos();
    let ended = started;
    let mut snapshot = HostResourceSnapshot::default();
    let clock_ticks_per_second = clock_ticks_per_second();

    push_file_observation(
        &mut snapshot,
        &config.procfs_root.join("stat"),
        |contents| {
            parse_cpu_stat(&contents, clock_ticks_per_second, started, ended).map(|observation| {
                SignalEnvelope::node_cpu_observation(
                    "source.host_resource",
                    host.clone(),
                    observation,
                )
            })
        },
        config.max_file_bytes,
    );
    push_file_observation(
        &mut snapshot,
        &config.procfs_root.join("loadavg"),
        |contents| {
            parse_loadavg(&contents, started, ended).map(|observation| {
                SignalEnvelope::node_load_observation(
                    "source.host_resource",
                    host.clone(),
                    observation,
                )
            })
        },
        config.max_file_bytes,
    );
    push_file_observation(
        &mut snapshot,
        &config.procfs_root.join("meminfo"),
        |contents| {
            parse_meminfo(&contents, started, ended).map(|observation| {
                SignalEnvelope::node_memory_observation(
                    "source.host_resource",
                    host.clone(),
                    observation,
                )
            })
        },
        config.max_file_bytes,
    );

    match read_bounded_to_string(&config.procfs_root.join("diskstats"), config.max_file_bytes)
        .and_then(|contents| parse_diskstats(&contents, started, ended))
    {
        Ok(disks) => snapshot
            .signals
            .extend(disks.into_iter().map(|observation| {
                SignalEnvelope::node_disk_io_observation(
                    "source.host_resource",
                    host.clone(),
                    observation,
                )
            })),
        Err(err) => snapshot.warnings.push(format!("diskstats: {err}")),
    }

    snapshot.signals.extend(
        sample_processes(config, started, ended, &mut snapshot.warnings)
            .into_iter()
            .map(|observation| {
                SignalEnvelope::process_resource_observation(
                    "source.host_resource",
                    host.clone(),
                    observation,
                )
            }),
    );
    for sample in sample_cgroups(config, &mut snapshot.warnings) {
        snapshot
            .signals
            .extend(sample.into_observations(host.clone(), started, ended));
    }

    snapshot
}

fn push_file_observation(
    snapshot: &mut HostResourceSnapshot,
    path: &Path,
    parser: impl FnOnce(String) -> Result<SignalEnvelope, String>,
    max_bytes: u64,
) {
    match read_bounded_to_string(path, max_bytes).and_then(parser) {
        Ok(signal) => snapshot.signals.push(signal),
        Err(err) => snapshot.warnings.push(format!("{}: {err}", path.display())),
    }
}

pub fn parse_cpu_stat(
    contents: &str,
    clock_ticks_per_second: u64,
    start_unix_nanos: u64,
    end_unix_nanos: u64,
) -> Result<NodeCpuObservation, String> {
    let mut cpu_fields = None;
    let mut runnable_tasks = None;
    let mut blocked_tasks = None;

    for line in contents.lines() {
        if let Some(rest) = line.strip_prefix("cpu ") {
            cpu_fields = Some(rest.split_whitespace().collect::<Vec<_>>());
        } else if let Some(value) = line.strip_prefix("procs_running ") {
            runnable_tasks = parse_u64(value).ok();
        } else if let Some(value) = line.strip_prefix("procs_blocked ") {
            blocked_tasks = parse_u64(value).ok();
        }
    }

    let fields = cpu_fields.ok_or_else(|| "missing aggregate cpu line".to_string())?;
    if fields.len() < 8 {
        return Err("aggregate cpu line has too few fields".to_string());
    }

    Ok(NodeCpuObservation {
        metric_name: "system.cpu.time".to_string(),
        unit: "ns".to_string(),
        timestamp_unix_nanos: end_unix_nanos,
        window: MetricAggregationWindow {
            start_unix_nanos,
            end_unix_nanos,
        },
        user_nanos: ticks_to_nanos(
            parse_u64(fields[0])? + parse_u64(fields[1])?,
            clock_ticks_per_second,
        ),
        system_nanos: ticks_to_nanos(parse_u64(fields[2])?, clock_ticks_per_second),
        idle_nanos: ticks_to_nanos(parse_u64(fields[3])?, clock_ticks_per_second),
        iowait_nanos: ticks_to_nanos(parse_u64(fields[4])?, clock_ticks_per_second),
        steal_nanos: ticks_to_nanos(parse_u64(fields[7])?, clock_ticks_per_second),
        runnable_tasks,
        blocked_tasks,
    })
}

pub fn parse_loadavg(
    contents: &str,
    start_unix_nanos: u64,
    end_unix_nanos: u64,
) -> Result<NodeLoadObservation, String> {
    let fields = contents.split_whitespace().collect::<Vec<_>>();
    if fields.len() < 4 {
        return Err("loadavg has too few fields".to_string());
    }
    let (runnable_tasks, total_tasks) = fields[3]
        .split_once('/')
        .map(|(running, total)| (parse_u64(running).ok(), parse_u64(total).ok()))
        .unwrap_or((None, None));

    Ok(NodeLoadObservation {
        metric_name: "system.cpu.load_average.1m".to_string(),
        unit: "1".to_string(),
        timestamp_unix_nanos: end_unix_nanos,
        window: MetricAggregationWindow {
            start_unix_nanos,
            end_unix_nanos,
        },
        load1: parse_f64(fields[0])?,
        load5: parse_f64(fields[1])?,
        load15: parse_f64(fields[2])?,
        runnable_tasks,
        total_tasks,
    })
}

pub fn parse_meminfo(
    contents: &str,
    start_unix_nanos: u64,
    end_unix_nanos: u64,
) -> Result<NodeMemoryObservation, String> {
    let mem_total = meminfo_kib(contents, "MemTotal")?;

    Ok(NodeMemoryObservation {
        metric_name: "system.memory.usage".to_string(),
        unit: "By".to_string(),
        timestamp_unix_nanos: end_unix_nanos,
        window: MetricAggregationWindow {
            start_unix_nanos,
            end_unix_nanos,
        },
        mem_total_bytes: kib_to_bytes(mem_total),
        mem_available_bytes: meminfo_kib(contents, "MemAvailable").ok().map(kib_to_bytes),
        mem_free_bytes: meminfo_kib(contents, "MemFree").ok().map(kib_to_bytes),
        swap_total_bytes: meminfo_kib(contents, "SwapTotal").ok().map(kib_to_bytes),
        swap_free_bytes: meminfo_kib(contents, "SwapFree").ok().map(kib_to_bytes),
    })
}

pub fn parse_diskstats(
    contents: &str,
    start_unix_nanos: u64,
    end_unix_nanos: u64,
) -> Result<Vec<NodeDiskIoObservation>, String> {
    let mut observations = Vec::new();
    for line in contents.lines() {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        if fields.len() < 10 {
            continue;
        }
        let reads_completed = parse_u64(fields[3])?;
        let sectors_read = parse_u64(fields[5])?;
        let writes_completed = parse_u64(fields[7])?;
        let sectors_written = parse_u64(fields[9])?;
        observations.push(NodeDiskIoObservation {
            metric_name: "system.disk.io".to_string(),
            unit: "By".to_string(),
            timestamp_unix_nanos: end_unix_nanos,
            window: MetricAggregationWindow {
                start_unix_nanos,
                end_unix_nanos,
            },
            device: fields[2].to_string(),
            reads_completed,
            writes_completed,
            read_bytes: sectors_read.saturating_mul(DISK_SECTOR_BYTES),
            written_bytes: sectors_written.saturating_mul(DISK_SECTOR_BYTES),
        });
    }
    Ok(observations)
}

#[allow(clippy::too_many_arguments)]
pub fn parse_process_stat(
    pid: u32,
    stat: &str,
    status: Option<&str>,
    clock_ticks_per_second: u64,
    page_size_bytes: u64,
    fd_count: u64,
    socket_count: u64,
    start_unix_nanos: u64,
    end_unix_nanos: u64,
) -> Result<ProcessResourceObservation, String> {
    let close = stat
        .rfind(')')
        .ok_or_else(|| "process stat missing command terminator".to_string())?;
    let rest = stat
        .get(close + 2..)
        .ok_or_else(|| "process stat missing fields".to_string())?;
    let fields = rest.split_whitespace().collect::<Vec<_>>();
    if fields.len() < 22 {
        return Err("process stat has too few fields".to_string());
    }
    let command = status
        .and_then(status_name)
        .unwrap_or_else(|| stat[stat.find('(').unwrap_or(0) + 1..close].to_string());
    let uid = status.and_then(status_uid);
    let threads = status
        .and_then(status_threads)
        .or_else(|| parse_u64(fields[17]).ok());
    let utime = parse_u64(fields[11])?;
    let stime = parse_u64(fields[12])?;
    let vsize = parse_u64(fields[20]).ok();
    let rss_pages = parse_i64(fields[21]).unwrap_or(0).max(0) as u64;

    Ok(ProcessResourceObservation {
        metric_name: "process.resource".to_string(),
        unit: "1".to_string(),
        timestamp_unix_nanos: end_unix_nanos,
        window: MetricAggregationWindow {
            start_unix_nanos,
            end_unix_nanos,
        },
        process: ProcessResourceContext {
            pid,
            ppid: parse_u64(fields[1])
                .ok()
                .and_then(|value| u32::try_from(value).ok()),
            uid,
            command,
            executable: None,
            container: None,
            kubernetes: None,
        },
        cpu_time_nanos: Some(ticks_to_nanos(
            utime.saturating_add(stime),
            clock_ticks_per_second,
        )),
        memory_rss_bytes: Some(rss_pages.saturating_mul(page_size_bytes)),
        virtual_memory_bytes: vsize,
        open_fds: Some(fd_count),
        socket_count: Some(socket_count),
        thread_count: threads,
    })
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CgroupSample {
    pub path: String,
    pub cpu_stat: Option<String>,
    pub memory_current: Option<String>,
    pub memory_peak: Option<String>,
    pub memory_max: Option<String>,
    pub pids_current: Option<String>,
    pub pids_max: Option<String>,
    pub fd_count: Option<u64>,
    pub socket_count: Option<u64>,
}

impl CgroupSample {
    pub fn into_observations(
        self,
        host: Option<String>,
        start_unix_nanos: u64,
        end_unix_nanos: u64,
    ) -> Vec<SignalEnvelope> {
        let cgroup = CgroupResourceContext {
            cgroup_path: self.path,
            container: None,
            kubernetes: None,
        };
        let window = MetricAggregationWindow {
            start_unix_nanos,
            end_unix_nanos,
        };
        let mut signals = Vec::new();

        if let Some(cpu_stat) = self.cpu_stat {
            signals.push(SignalEnvelope::cgroup_cpu_observation(
                "source.host_resource",
                host.clone(),
                CgroupCpuObservation {
                    metric_name: "container.cpu.time".to_string(),
                    unit: "ns".to_string(),
                    timestamp_unix_nanos: end_unix_nanos,
                    window: window.clone(),
                    cgroup: cgroup.clone(),
                    usage_nanos: cpu_stat_value(&cpu_stat, "usage_usec").map(micros_to_nanos),
                    user_nanos: cpu_stat_value(&cpu_stat, "user_usec").map(micros_to_nanos),
                    system_nanos: cpu_stat_value(&cpu_stat, "system_usec").map(micros_to_nanos),
                    throttled_periods: cpu_stat_value(&cpu_stat, "nr_throttled"),
                    throttled_nanos: cpu_stat_value(&cpu_stat, "throttled_usec")
                        .map(micros_to_nanos),
                },
            ));
        }

        if self.memory_current.is_some() || self.memory_peak.is_some() || self.memory_max.is_some()
        {
            signals.push(SignalEnvelope::cgroup_memory_observation(
                "source.host_resource",
                host.clone(),
                CgroupMemoryObservation {
                    metric_name: "container.memory.usage".to_string(),
                    unit: "By".to_string(),
                    timestamp_unix_nanos: end_unix_nanos,
                    window: window.clone(),
                    cgroup: cgroup.clone(),
                    current_bytes: self.memory_current.as_deref().and_then(parse_cgroup_limit),
                    peak_bytes: self.memory_peak.as_deref().and_then(parse_cgroup_limit),
                    max_bytes: self.memory_max.as_deref().and_then(parse_cgroup_limit),
                },
            ));
        }

        if self.pids_current.is_some() || self.pids_max.is_some() {
            signals.push(SignalEnvelope::cgroup_pids_observation(
                "source.host_resource",
                host.clone(),
                CgroupPidsObservation {
                    metric_name: "container.process.count".to_string(),
                    unit: "{process}".to_string(),
                    timestamp_unix_nanos: end_unix_nanos,
                    window: window.clone(),
                    cgroup: cgroup.clone(),
                    process_count: self.pids_current.as_deref().and_then(parse_cgroup_limit),
                    thread_count: None,
                    max_processes: self.pids_max.as_deref().and_then(parse_cgroup_limit),
                },
            ));
        }

        if self.fd_count.is_some() || self.socket_count.is_some() {
            signals.push(SignalEnvelope::cgroup_file_descriptor_observation(
                "source.host_resource",
                host,
                CgroupFileDescriptorObservation {
                    metric_name: "container.file_descriptor.count".to_string(),
                    unit: "{file_descriptor}".to_string(),
                    timestamp_unix_nanos: end_unix_nanos,
                    window,
                    cgroup,
                    open_fds: self.fd_count,
                    socket_count: self.socket_count,
                },
            ));
        }

        signals
    }
}

fn sample_processes(
    config: &HostResourceConfig,
    started: u64,
    ended: u64,
    warnings: &mut Vec<String>,
) -> Vec<ProcessResourceObservation> {
    let clock_ticks_per_second = clock_ticks_per_second();
    let page_size_bytes = page_size_bytes();
    let mut entries = match bounded_numeric_dirs(
        &config.procfs_root,
        config.max_processes,
        "process",
        warnings,
    ) {
        Ok(entries) => entries,
        Err(err) => {
            warnings.push(format!("{}: {err}", config.procfs_root.display()));
            return Vec::new();
        }
    };
    entries.sort_by_key(|(pid, _)| *pid);

    let mut observations = Vec::new();
    for (pid, path) in entries.into_iter().take(config.max_processes) {
        let stat = match read_bounded_to_string(&path.join("stat"), config.max_file_bytes) {
            Ok(stat) => stat,
            Err(err) => {
                warnings.push(format!("{}/stat: {err}", path.display()));
                continue;
            }
        };
        let status = read_bounded_to_string(&path.join("status"), config.max_file_bytes).ok();
        let fd_count = count_dir_entries(&path.join("fd"), config.max_fds_per_process).unwrap_or(0);
        let socket_count =
            count_socket_fds(&path.join("fd"), config.max_fds_per_process).unwrap_or(0);
        match parse_process_stat(
            pid,
            &stat,
            status.as_deref(),
            clock_ticks_per_second,
            page_size_bytes,
            fd_count,
            socket_count,
            started,
            ended,
        ) {
            Ok(observation) => observations.push(observation),
            Err(err) => warnings.push(format!("process {pid}: {err}")),
        }
    }
    observations
}

fn sample_cgroups(config: &HostResourceConfig, warnings: &mut Vec<String>) -> Vec<CgroupSample> {
    let mut samples = Vec::new();
    let mut queue = VecDeque::from([config.cgroup_root.clone()]);
    while let Some(path) = queue.pop_front() {
        if samples.len() >= config.max_cgroups {
            break;
        }
        if path.join("cgroup.procs").exists()
            || path.join("cpu.stat").exists()
            || path.join("memory.current").exists()
        {
            samples.push(CgroupSample {
                path: normalize_cgroup_path(&config.cgroup_root, &path),
                cpu_stat: read_bounded_to_string(&path.join("cpu.stat"), config.max_file_bytes)
                    .ok(),
                memory_current: read_bounded_to_string(
                    &path.join("memory.current"),
                    config.max_file_bytes,
                )
                .ok(),
                memory_peak: read_bounded_to_string(
                    &path.join("memory.peak"),
                    config.max_file_bytes,
                )
                .ok(),
                memory_max: read_bounded_to_string(&path.join("memory.max"), config.max_file_bytes)
                    .ok(),
                pids_current: read_bounded_to_string(
                    &path.join("pids.current"),
                    config.max_file_bytes,
                )
                .ok(),
                pids_max: read_bounded_to_string(&path.join("pids.max"), config.max_file_bytes)
                    .ok(),
                fd_count: None,
                socket_count: None,
            });
        }
        match fs::read_dir(&path) {
            Ok(entries) => {
                let mut children = bounded_child_dirs(
                    entries,
                    config.max_cgroups.saturating_sub(samples.len()),
                    &path,
                    warnings,
                );
                children.sort();
                for child in children {
                    if queue.len().saturating_add(samples.len()) >= config.max_cgroups {
                        warnings.push(format!(
                            "{}: cgroup traversal truncated at {} entries",
                            path.display(),
                            config.max_cgroups
                        ));
                        break;
                    }
                    queue.push_back(child);
                }
            }
            Err(err) => warnings.push(format!("{}: {err}", path.display())),
        }
    }
    samples
}

fn bounded_numeric_dirs(
    root: &Path,
    limit: usize,
    label: &str,
    warnings: &mut Vec<String>,
) -> Result<Vec<(u32, PathBuf)>, String> {
    let mut entries = Vec::new();
    let mut truncated = false;
    for entry in fs::read_dir(root).map_err(|err| err.to_string())? {
        let Ok(entry) = entry else {
            continue;
        };
        let Some(pid) = entry.file_name().to_string_lossy().parse::<u32>().ok() else {
            continue;
        };
        if entries.len() >= limit {
            truncated = true;
            break;
        }
        entries.push((pid, entry.path()));
    }
    if truncated {
        warnings.push(format!(
            "{}: {label} scan truncated at {limit} entries",
            root.display()
        ));
    }
    Ok(entries)
}

fn bounded_child_dirs(
    entries: fs::ReadDir,
    limit: usize,
    path: &Path,
    warnings: &mut Vec<String>,
) -> Vec<PathBuf> {
    let mut children = Vec::new();
    let mut truncated = false;
    for entry in entries {
        let Ok(entry) = entry else {
            continue;
        };
        if !entry.file_type().is_ok_and(|file_type| file_type.is_dir()) {
            continue;
        }
        if children.len() >= limit {
            truncated = true;
            break;
        }
        children.push(entry.path());
    }
    if truncated {
        warnings.push(format!(
            "{}: child cgroup scan truncated at {limit} entries",
            path.display()
        ));
    }
    children
}

fn normalize_cgroup_path(root: &Path, path: &Path) -> String {
    let relative = path.strip_prefix(root).unwrap_or(path);
    let text = relative.to_string_lossy();
    if text.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", text.trim_start_matches('/'))
    }
}

fn read_bounded_to_string(path: &Path, max_bytes: u64) -> Result<String, String> {
    let mut file = File::open(path).map_err(|err| err.to_string())?;
    let mut buffer = String::new();
    file.by_ref()
        .take(max_bytes)
        .read_to_string(&mut buffer)
        .map_err(|err| err.to_string())?;
    Ok(buffer)
}

fn count_dir_entries(path: &Path, max_entries: usize) -> Result<u64, String> {
    Ok(fs::read_dir(path)
        .map_err(|err| err.to_string())?
        .take(max_entries)
        .filter_map(Result::ok)
        .count() as u64)
}

fn count_socket_fds(path: &Path, max_entries: usize) -> Result<u64, String> {
    let mut count = 0;
    for entry in fs::read_dir(path)
        .map_err(|err| err.to_string())?
        .take(max_entries)
    {
        let Ok(entry) = entry else {
            continue;
        };
        if fs::read_link(entry.path())
            .map(|target| target.to_string_lossy().starts_with("socket:"))
            .unwrap_or(false)
        {
            count += 1;
        }
    }
    Ok(count)
}

fn meminfo_kib(contents: &str, key: &str) -> Result<u64, String> {
    for line in contents.lines() {
        if let Some(rest) = line
            .strip_prefix(key)
            .and_then(|rest| rest.strip_prefix(':'))
        {
            let value = rest
                .split_whitespace()
                .next()
                .ok_or_else(|| format!("{key} missing value"))?;
            return parse_u64(value);
        }
    }
    Err(format!("missing {key}"))
}

fn status_name(contents: &str) -> Option<String> {
    status_value(contents, "Name").map(ToOwned::to_owned)
}

fn status_uid(contents: &str) -> Option<u32> {
    status_value(contents, "Uid")
        .and_then(|value| value.split_whitespace().next())
        .and_then(|value| value.parse::<u32>().ok())
}

fn status_threads(contents: &str) -> Option<u64> {
    status_value(contents, "Threads").and_then(|value| value.parse::<u64>().ok())
}

fn status_value<'a>(contents: &'a str, key: &str) -> Option<&'a str> {
    contents.lines().find_map(|line| {
        line.strip_prefix(key)
            .and_then(|rest| rest.strip_prefix(':'))
            .map(str::trim)
    })
}

fn cpu_stat_value(contents: &str, key: &str) -> Option<u64> {
    contents.lines().find_map(|line| {
        let mut fields = line.split_whitespace();
        match (fields.next(), fields.next()) {
            (Some(found), Some(value)) if found == key => parse_u64(value).ok(),
            _ => None,
        }
    })
}

fn parse_cgroup_limit(contents: &str) -> Option<u64> {
    let value = contents.trim();
    if value == "max" {
        None
    } else {
        value.parse::<u64>().ok()
    }
}

fn parse_u64(value: &str) -> Result<u64, String> {
    value
        .parse::<u64>()
        .map_err(|err| format!("invalid unsigned integer {value:?}: {err}"))
}

fn parse_i64(value: &str) -> Result<i64, String> {
    value
        .parse::<i64>()
        .map_err(|err| format!("invalid signed integer {value:?}: {err}"))
}

fn parse_f64(value: &str) -> Result<f64, String> {
    value
        .parse::<f64>()
        .map_err(|err| format!("invalid float {value:?}: {err}"))
}

fn ticks_to_nanos(ticks: u64, clock_ticks_per_second: u64) -> u64 {
    ticks
        .saturating_mul(1_000_000_000)
        .checked_div(clock_ticks_per_second.max(1))
        .unwrap_or(0)
}

fn micros_to_nanos(micros: u64) -> u64 {
    micros.saturating_mul(1_000)
}

fn kib_to_bytes(kib: u64) -> u64 {
    kib.saturating_mul(1024)
}

fn now_unix_nanos() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(0)
}

fn clock_ticks_per_second() -> u64 {
    sysconf_positive(libc::_SC_CLK_TCK).unwrap_or(100)
}

fn page_size_bytes() -> u64 {
    sysconf_positive(libc::_SC_PAGESIZE).unwrap_or(4096)
}

fn sysconf_positive(name: libc::c_int) -> Option<u64> {
    let value = unsafe { libc::sysconf(name) };
    (value > 0).then_some(value as u64)
}

#[cfg(test)]
mod tests {
    use e_navigator_core::Source;
    use e_navigator_signals::SignalPayload;

    use crate::{
        CgroupSample, HostResourceConfig, HostResourceSource, normalize_cgroup_path,
        parse_cpu_stat, parse_diskstats, parse_loadavg, parse_meminfo, parse_process_stat,
        sample_cgroups, sample_processes,
    };

    #[test]
    fn parses_proc_stat_cpu_and_saturation_without_unbounded_labels() {
        let cpu = parse_cpu_stat(
            "cpu  100 0 50 500 10 0 0 2 0 0\nprocs_running 3\nprocs_blocked 1\n",
            100,
            1_000,
            2_000,
        )
        .expect("cpu stat parses");

        assert_eq!(cpu.metric_name, "system.cpu.time");
        assert_eq!(cpu.unit, "ns");
        assert_eq!(cpu.user_nanos, 1_000_000_000);
        assert_eq!(cpu.system_nanos, 500_000_000);
        assert_eq!(cpu.idle_nanos, 5_000_000_000);
        assert_eq!(cpu.iowait_nanos, 100_000_000);
        assert_eq!(cpu.steal_nanos, 20_000_000);
        assert_eq!(cpu.runnable_tasks, Some(3));
        assert_eq!(cpu.blocked_tasks, Some(1));
    }

    #[test]
    fn parses_load_and_memory_fixtures() {
        let load =
            parse_loadavg("0.25 0.50 0.75 2/200 12345\n", 1_000, 2_000).expect("load parses");
        assert_eq!(load.metric_name, "system.cpu.load_average.1m");
        assert_eq!(load.load1, 0.25);
        assert_eq!(load.runnable_tasks, Some(2));
        assert_eq!(load.total_tasks, Some(200));

        let memory = parse_meminfo(
            "MemTotal:        8192 kB\nMemFree:         2048 kB\nMemAvailable:    4096 kB\nSwapTotal:       1024 kB\nSwapFree:         512 kB\n",
            1_000,
            2_000,
        )
        .expect("meminfo parses");
        assert_eq!(memory.metric_name, "system.memory.usage");
        assert_eq!(memory.mem_total_bytes, 8_388_608);
        assert_eq!(memory.mem_available_bytes, Some(4_194_304));
        assert_eq!(memory.swap_free_bytes, Some(524_288));
    }

    #[test]
    fn parses_diskstats_with_block_byte_units() {
        let disks = parse_diskstats(
            "259 0 nvme0n1 10 0 8 0 20 0 16 0 0 0 0 0 0 0 0\n",
            1_000,
            2_000,
        )
        .expect("diskstats parses");

        assert_eq!(disks.len(), 1);
        assert_eq!(disks[0].device, "nvme0n1");
        assert_eq!(disks[0].read_bytes, 4_096);
        assert_eq!(disks[0].written_bytes, 8_192);
    }

    #[test]
    fn parses_process_resource_stat_without_command_cardinality_in_keys() {
        let process = parse_process_stat(
            42,
            "42 (api worker) S 1 1 1 0 -1 0 0 0 0 0 12 6 0 0 20 0 4 0 100 8192 8\n",
            Some("Name:\tapi\nUid:\t1000\t1000\t1000\t1000\nThreads:\t4\n"),
            100,
            4096,
            2,
            1,
            1_000,
            2_000,
        )
        .expect("process stat parses");

        assert_eq!(process.process.pid, 42);
        assert_eq!(process.process.command, "api");
        assert_eq!(process.process.ppid, Some(1));
        assert_eq!(process.process.uid, Some(1000));
        assert_eq!(process.cpu_time_nanos, Some(180_000_000));
        assert_eq!(process.memory_rss_bytes, Some(32_768));
        assert_eq!(process.open_fds, Some(2));
        assert_eq!(process.socket_count, Some(1));
        assert_eq!(process.thread_count, Some(4));
    }

    #[test]
    fn decodes_cgroup_v2_resource_files() {
        let sample = CgroupSample {
            path: "/kubepods.slice/pod123/container.scope".to_string(),
            cpu_stat: Some(
                "usage_usec 100\nuser_usec 60\nsystem_usec 40\nnr_throttled 2\nthrottled_usec 5\n"
                    .to_string(),
            ),
            memory_current: Some("8192\n".to_string()),
            memory_peak: Some("16384\n".to_string()),
            memory_max: Some("max\n".to_string()),
            pids_current: Some("3\n".to_string()),
            pids_max: Some("512\n".to_string()),
            fd_count: Some(42),
            socket_count: Some(7),
        };

        let observations = sample.into_observations(Some("node-a".to_string()), 1_000, 2_000);

        assert_eq!(observations.len(), 4);
        assert!(
            observations
                .iter()
                .all(|signal| signal.host.as_deref() == Some("node-a"))
        );
        assert!(matches!(
            observations[0].payload,
            SignalPayload::CgroupCpuObservation(_)
        ));
        assert!(matches!(
            observations[1].payload,
            SignalPayload::CgroupMemoryObservation(_)
        ));
        assert!(matches!(
            observations[2].payload,
            SignalPayload::CgroupPidsObservation(_)
        ));
        assert!(matches!(
            observations[3].payload,
            SignalPayload::CgroupFileDescriptorObservation(_)
        ));
    }

    #[test]
    fn malformed_missing_and_partial_files_are_non_fatal_warnings() {
        assert!(parse_cpu_stat("intr 1\n", 100, 1_000, 2_000).is_err());
        assert!(parse_meminfo("MemFree: 1 kB\n", 1_000, 2_000).is_err());
        assert!(parse_loadavg("0.1 0.2\n", 1_000, 2_000).is_err());
        assert!(
            parse_diskstats("not enough\n", 1_000, 2_000)
                .expect("partial line skipped")
                .is_empty()
        );
    }

    #[test]
    fn sample_once_reports_missing_and_malformed_procfs_warnings() {
        let root = std::env::temp_dir().join(format!(
            "e-navigator-host-source-warning-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let proc_root = root.join("proc");
        let cgroup_root = root.join("cgroup");
        std::fs::create_dir_all(&proc_root).expect("proc root");
        std::fs::create_dir_all(&cgroup_root).expect("cgroup root");
        std::fs::write(proc_root.join("stat"), "intr 1\n").expect("stat");
        std::fs::write(
            proc_root.join("meminfo"),
            "MemTotal: 8192 kB\nMemAvailable: 4096 kB\n",
        )
        .expect("meminfo");
        std::fs::write(proc_root.join("diskstats"), "partial\n").expect("diskstats");
        std::fs::write(cgroup_root.join("cgroup.procs"), "").expect("cgroup procs");

        let source = HostResourceSource::new(HostResourceConfig {
            procfs_root: proc_root,
            cgroup_root,
            sample_interval_millis: 0,
            max_processes: 1,
            max_cgroups: 1,
            ..HostResourceConfig::default()
        });
        let snapshot = source.sample_once();

        assert!(
            snapshot
                .warnings
                .iter()
                .any(|warning| warning.contains("aggregate cpu line"))
        );
        assert!(
            snapshot
                .warnings
                .iter()
                .any(|warning| warning.contains("loadavg"))
        );
        assert!(
            snapshot
                .signals
                .iter()
                .any(|signal| matches!(signal.payload, SignalPayload::NodeMemoryObservation(_)))
        );

        std::fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn normalizes_cgroup_paths_to_linux_cgroup_form() {
        let root = std::path::Path::new("/sys/fs/cgroup");
        assert_eq!(normalize_cgroup_path(root, root), "/");
        assert_eq!(
            normalize_cgroup_path(root, &root.join("kubepods.slice/pod123")),
            "/kubepods.slice/pod123"
        );
    }

    #[test]
    fn process_scan_is_bounded_before_collection() {
        let root = std::env::temp_dir().join(format!(
            "e-navigator-host-source-process-cap-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        for pid in [100, 101, 102] {
            std::fs::create_dir_all(root.join(pid.to_string())).expect("pid dir");
            std::fs::write(
                root.join(pid.to_string()).join("stat"),
                format!("{pid} (api) S 1 1 1 0 -1 0 0 0 0 0 1 1 0 0 20 0 1 0 100 8192 1\n"),
            )
            .expect("stat");
        }

        let config = HostResourceConfig {
            procfs_root: root.clone(),
            max_processes: 1,
            ..HostResourceConfig::default()
        };
        let mut warnings = Vec::new();
        let observations = sample_processes(&config, 1_000, 2_000, &mut warnings);

        assert_eq!(observations.len(), 1);
        assert!(
            warnings
                .iter()
                .any(|warning| warning.contains("process scan truncated"))
        );

        std::fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn cgroup_child_scan_is_bounded_before_collection() {
        let root = std::env::temp_dir().join(format!(
            "e-navigator-host-source-cgroup-cap-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("a")).expect("cgroup dir");
        std::fs::create_dir_all(root.join("b")).expect("cgroup dir");
        std::fs::create_dir_all(root.join("c")).expect("cgroup dir");
        std::fs::write(root.join("cgroup.procs"), "").expect("root cgroup procs");
        std::fs::write(root.join("a/cgroup.procs"), "").expect("child cgroup procs");

        let config = HostResourceConfig {
            cgroup_root: root.clone(),
            max_cgroups: 2,
            ..HostResourceConfig::default()
        };
        let mut warnings = Vec::new();
        let samples = sample_cgroups(&config, &mut warnings);

        assert!(samples.len() <= 2);
        assert!(
            warnings
                .iter()
                .any(|warning| warning.contains("cgroup scan truncated"))
        );

        std::fs::remove_dir_all(root).expect("cleanup");
    }

    #[tokio::test]
    async fn host_resource_source_emits_bounded_snapshot_from_configured_roots() {
        let source = HostResourceSource::new(HostResourceConfig {
            max_processes: 2,
            ..HostResourceConfig::default()
        });

        assert_eq!(source.metadata().name, "source.host_resource");
        assert_eq!(source.config().max_processes, 2);
    }
}
