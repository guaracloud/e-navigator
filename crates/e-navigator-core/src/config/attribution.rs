use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use super::{ConfigError, ConfigResult, KubernetesAttributionConfig};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttributionConfig {
    #[serde(default = "default_procfs_root")]
    pub procfs_root: PathBuf,
    #[serde(default = "default_cgroup_root")]
    pub cgroup_root: PathBuf,
    #[serde(default)]
    pub kubernetes: KubernetesAttributionConfig,
}

impl Default for AttributionConfig {
    fn default() -> Self {
        Self {
            procfs_root: default_procfs_root(),
            cgroup_root: default_cgroup_root(),
            kubernetes: KubernetesAttributionConfig::default(),
        }
    }
}

impl AttributionConfig {
    pub const MAX_PATH_BYTES_LIMIT: usize = 4096;

    pub(super) fn validate(&self) -> ConfigResult<()> {
        if self.procfs_root.as_os_str().is_empty() {
            return Err(ConfigError::invalid_value(
                "attribution.procfs_root",
                "attribution.procfs_root must not be empty",
            ));
        }
        validate_path_len("attribution.procfs_root", &self.procfs_root)?;
        if self.cgroup_root.as_os_str().is_empty() {
            return Err(ConfigError::invalid_value(
                "attribution.cgroup_root",
                "attribution.cgroup_root must not be empty",
            ));
        }
        validate_path_len("attribution.cgroup_root", &self.cgroup_root)?;

        self.kubernetes.validate()
    }
}

fn validate_path_len(path: &'static str, value: &Path) -> ConfigResult<()> {
    if value.to_string_lossy().len() > AttributionConfig::MAX_PATH_BYTES_LIMIT {
        return Err(ConfigError::invalid_value(
            path,
            format!(
                "{path} must be at most {} bytes",
                AttributionConfig::MAX_PATH_BYTES_LIMIT
            ),
        ));
    }
    Ok(())
}

fn default_procfs_root() -> PathBuf {
    PathBuf::from("/proc")
}

fn default_cgroup_root() -> PathBuf {
    PathBuf::from("/sys/fs/cgroup")
}
