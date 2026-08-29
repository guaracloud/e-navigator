use std::path::{Path, PathBuf};

use super::{ConfigError, ConfigResult};

pub(super) const MAX_PATH_BYTES: usize = 4096;

pub(super) fn procfs_root() -> PathBuf {
    PathBuf::from("/proc")
}

pub(super) fn sysfs_root() -> PathBuf {
    PathBuf::from("/sys")
}

pub(super) fn cgroup_root() -> PathBuf {
    PathBuf::from("/sys/fs/cgroup")
}

pub(super) fn validate_len(path: &'static str, value: &Path) -> ConfigResult<()> {
    if value.to_string_lossy().len() > MAX_PATH_BYTES {
        return Err(ConfigError::invalid_value(
            path,
            format!("{path} must be at most {MAX_PATH_BYTES} bytes"),
        ));
    }
    Ok(())
}
