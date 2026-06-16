use std::path::PathBuf;

const MAX_FILE_BYTES: u64 = 128 * 1024;
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
