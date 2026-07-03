use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use super::{ConfigError, ConfigResult};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceSourceConfig {
    #[serde(default = "default_procfs_root")]
    pub procfs_root: PathBuf,
    #[serde(default = "default_sysfs_root")]
    pub sysfs_root: PathBuf,
    #[serde(default = "default_cgroup_root")]
    pub cgroup_root: PathBuf,
    #[serde(default = "default_resource_sample_interval_millis")]
    pub sample_interval_millis: u64,
    #[serde(default = "default_resource_max_processes")]
    pub max_processes: usize,
    #[serde(default = "default_resource_max_cgroups")]
    pub max_cgroups: usize,
    #[serde(default = "default_resource_max_fds_per_process")]
    pub max_fds_per_process: usize,
    #[serde(default = "default_resource_max_file_bytes")]
    pub max_file_bytes: u64,
}

impl Default for ResourceSourceConfig {
    fn default() -> Self {
        Self {
            procfs_root: default_procfs_root(),
            sysfs_root: default_sysfs_root(),
            cgroup_root: default_cgroup_root(),
            sample_interval_millis: default_resource_sample_interval_millis(),
            max_processes: default_resource_max_processes(),
            max_cgroups: default_resource_max_cgroups(),
            max_fds_per_process: default_resource_max_fds_per_process(),
            max_file_bytes: default_resource_max_file_bytes(),
        }
    }
}

impl ResourceSourceConfig {
    pub const MAX_SAMPLE_INTERVAL_MILLIS_LIMIT: u64 = 3_600_000;
    pub const MAX_PROCESSES_LIMIT: usize = 65_536;
    pub const MAX_CGROUPS_LIMIT: usize = 65_536;
    pub const MAX_FDS_PER_PROCESS_LIMIT: usize = 1_048_576;
    pub const MAX_FILE_BYTES_LIMIT: u64 = 1024 * 1024;

    pub(super) fn validate(&self) -> ConfigResult<()> {
        if self.procfs_root.as_os_str().is_empty() {
            return Err(ConfigError::invalid_value(
                "resource_source.procfs_root",
                "resource_source.procfs_root must not be empty",
            ));
        }
        if self.sysfs_root.as_os_str().is_empty() {
            return Err(ConfigError::invalid_value(
                "resource_source.sysfs_root",
                "resource_source.sysfs_root must not be empty",
            ));
        }
        if self.cgroup_root.as_os_str().is_empty() {
            return Err(ConfigError::invalid_value(
                "resource_source.cgroup_root",
                "resource_source.cgroup_root must not be empty",
            ));
        }
        if self.sample_interval_millis == 0 {
            return Err(ConfigError::invalid_value(
                "resource_source.sample_interval_millis",
                "resource_source.sample_interval_millis must be greater than zero",
            ));
        }
        if self.sample_interval_millis > Self::MAX_SAMPLE_INTERVAL_MILLIS_LIMIT {
            return Err(ConfigError::invalid_value(
                "resource_source.sample_interval_millis",
                format!(
                    "resource_source.sample_interval_millis must be less than or equal to {}",
                    Self::MAX_SAMPLE_INTERVAL_MILLIS_LIMIT
                ),
            ));
        }
        if self.max_processes == 0 {
            return Err(ConfigError::invalid_value(
                "resource_source.max_processes",
                "resource_source.max_processes must be greater than zero",
            ));
        }
        if self.max_processes > Self::MAX_PROCESSES_LIMIT {
            return Err(ConfigError::invalid_value(
                "resource_source.max_processes",
                format!(
                    "resource_source.max_processes must be less than or equal to {}",
                    Self::MAX_PROCESSES_LIMIT
                ),
            ));
        }
        if self.max_cgroups == 0 {
            return Err(ConfigError::invalid_value(
                "resource_source.max_cgroups",
                "resource_source.max_cgroups must be greater than zero",
            ));
        }
        if self.max_cgroups > Self::MAX_CGROUPS_LIMIT {
            return Err(ConfigError::invalid_value(
                "resource_source.max_cgroups",
                format!(
                    "resource_source.max_cgroups must be less than or equal to {}",
                    Self::MAX_CGROUPS_LIMIT
                ),
            ));
        }
        if self.max_fds_per_process == 0 {
            return Err(ConfigError::invalid_value(
                "resource_source.max_fds_per_process",
                "resource_source.max_fds_per_process must be greater than zero",
            ));
        }
        if self.max_fds_per_process > Self::MAX_FDS_PER_PROCESS_LIMIT {
            return Err(ConfigError::invalid_value(
                "resource_source.max_fds_per_process",
                format!(
                    "resource_source.max_fds_per_process must be less than or equal to {}",
                    Self::MAX_FDS_PER_PROCESS_LIMIT
                ),
            ));
        }
        if self.max_file_bytes == 0 {
            return Err(ConfigError::invalid_value(
                "resource_source.max_file_bytes",
                "resource_source.max_file_bytes must be greater than zero",
            ));
        }
        if self.max_file_bytes > Self::MAX_FILE_BYTES_LIMIT {
            return Err(ConfigError::invalid_value(
                "resource_source.max_file_bytes",
                format!(
                    "resource_source.max_file_bytes must be less than or equal to {}",
                    Self::MAX_FILE_BYTES_LIMIT
                ),
            ));
        }
        Ok(())
    }
}

fn default_procfs_root() -> PathBuf {
    PathBuf::from("/proc")
}

fn default_sysfs_root() -> PathBuf {
    PathBuf::from("/sys")
}

fn default_cgroup_root() -> PathBuf {
    PathBuf::from("/sys/fs/cgroup")
}

fn default_resource_sample_interval_millis() -> u64 {
    15_000
}

fn default_resource_max_processes() -> usize {
    128
}

fn default_resource_max_cgroups() -> usize {
    128
}

fn default_resource_max_fds_per_process() -> usize {
    1024
}

fn default_resource_max_file_bytes() -> u64 {
    128 * 1024
}
