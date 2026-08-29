use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use super::{ConfigError, ConfigResult, bounds::validate_nonzero_bounded, filesystem_paths};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceSourceConfig {
    #[serde(default = "filesystem_paths::procfs_root")]
    pub procfs_root: PathBuf,
    #[serde(default = "filesystem_paths::sysfs_root")]
    pub sysfs_root: PathBuf,
    #[serde(default = "filesystem_paths::cgroup_root")]
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
            procfs_root: filesystem_paths::procfs_root(),
            sysfs_root: filesystem_paths::sysfs_root(),
            cgroup_root: filesystem_paths::cgroup_root(),
            sample_interval_millis: default_resource_sample_interval_millis(),
            max_processes: default_resource_max_processes(),
            max_cgroups: default_resource_max_cgroups(),
            max_fds_per_process: default_resource_max_fds_per_process(),
            max_file_bytes: default_resource_max_file_bytes(),
        }
    }
}

impl ResourceSourceConfig {
    pub const MAX_PATH_BYTES_LIMIT: usize = filesystem_paths::MAX_PATH_BYTES;
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
        filesystem_paths::validate_len("resource_source.procfs_root", &self.procfs_root)?;
        if self.sysfs_root.as_os_str().is_empty() {
            return Err(ConfigError::invalid_value(
                "resource_source.sysfs_root",
                "resource_source.sysfs_root must not be empty",
            ));
        }
        filesystem_paths::validate_len("resource_source.sysfs_root", &self.sysfs_root)?;
        if self.cgroup_root.as_os_str().is_empty() {
            return Err(ConfigError::invalid_value(
                "resource_source.cgroup_root",
                "resource_source.cgroup_root must not be empty",
            ));
        }
        filesystem_paths::validate_len("resource_source.cgroup_root", &self.cgroup_root)?;
        validate_nonzero_bounded(
            "resource_source.sample_interval_millis",
            self.sample_interval_millis,
            Self::MAX_SAMPLE_INTERVAL_MILLIS_LIMIT,
        )?;
        validate_nonzero_bounded(
            "resource_source.max_processes",
            self.max_processes,
            Self::MAX_PROCESSES_LIMIT,
        )?;
        validate_nonzero_bounded(
            "resource_source.max_cgroups",
            self.max_cgroups,
            Self::MAX_CGROUPS_LIMIT,
        )?;
        validate_nonzero_bounded(
            "resource_source.max_fds_per_process",
            self.max_fds_per_process,
            Self::MAX_FDS_PER_PROCESS_LIMIT,
        )?;
        validate_nonzero_bounded(
            "resource_source.max_file_bytes",
            self.max_file_bytes,
            Self::MAX_FILE_BYTES_LIMIT,
        )?;
        Ok(())
    }
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
