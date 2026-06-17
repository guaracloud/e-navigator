use serde::{Deserialize, Serialize};

use super::{ConfigError, ConfigResult};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    pub(super) fn validate(&self) -> ConfigResult<()> {
        if self.max_keys == 0 {
            return Err(ConfigError::invalid_value(
                "resource_metrics.max_keys",
                "resource_metrics.max_keys must be greater than zero",
            ));
        }
        Ok(())
    }
}

fn default_resource_metrics_max_keys() -> usize {
    4096
}
