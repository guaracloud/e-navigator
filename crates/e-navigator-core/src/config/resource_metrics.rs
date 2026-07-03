use serde::{Deserialize, Serialize};

use super::{ConfigError, ConfigResult};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceMetricsConfig {
    #[serde(default = "default_resource_metrics_max_keys")]
    pub max_keys: usize,
}

impl Default for ResourceMetricsConfig {
    fn default() -> Self {
        Self {
            max_keys: default_resource_metrics_max_keys(),
        }
    }
}

impl ResourceMetricsConfig {
    pub const MAX_KEYS_LIMIT: usize = 262_144;

    pub(super) fn validate(&self) -> ConfigResult<()> {
        if self.max_keys == 0 {
            return Err(ConfigError::invalid_value(
                "resource_metrics.max_keys",
                "resource_metrics.max_keys must be greater than zero",
            ));
        }
        if self.max_keys > Self::MAX_KEYS_LIMIT {
            return Err(ConfigError::invalid_value(
                "resource_metrics.max_keys",
                format!(
                    "resource_metrics.max_keys must be less than or equal to {}",
                    Self::MAX_KEYS_LIMIT
                ),
            ));
        }
        Ok(())
    }
}

fn default_resource_metrics_max_keys() -> usize {
    4096
}
