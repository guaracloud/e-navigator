use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use super::{ConfigError, ConfigResult, KubernetesAttributionConfig, filesystem_paths};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttributionConfig {
    #[serde(default = "filesystem_paths::procfs_root")]
    pub procfs_root: PathBuf,
    #[serde(default = "filesystem_paths::cgroup_root")]
    pub cgroup_root: PathBuf,
    #[serde(default)]
    pub kubernetes: KubernetesAttributionConfig,
}

impl Default for AttributionConfig {
    fn default() -> Self {
        Self {
            procfs_root: filesystem_paths::procfs_root(),
            cgroup_root: filesystem_paths::cgroup_root(),
            kubernetes: KubernetesAttributionConfig::default(),
        }
    }
}

impl AttributionConfig {
    pub const MAX_PATH_BYTES_LIMIT: usize = filesystem_paths::MAX_PATH_BYTES;

    pub(super) fn validate(&self) -> ConfigResult<()> {
        if self.procfs_root.as_os_str().is_empty() {
            return Err(ConfigError::invalid_value(
                "attribution.procfs_root",
                "attribution.procfs_root must not be empty",
            ));
        }
        filesystem_paths::validate_len("attribution.procfs_root", &self.procfs_root)?;
        if self.cgroup_root.as_os_str().is_empty() {
            return Err(ConfigError::invalid_value(
                "attribution.cgroup_root",
                "attribution.cgroup_root must not be empty",
            ));
        }
        filesystem_paths::validate_len("attribution.cgroup_root", &self.cgroup_root)?;

        self.kubernetes.validate()
    }
}
