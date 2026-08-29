use serde::{Deserialize, Serialize};

use super::{ConfigResult, bounds::validate_nonzero_bounded};

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
        validate_nonzero_bounded(
            "resource_metrics.max_keys",
            self.max_keys,
            Self::MAX_KEYS_LIMIT,
        )?;
        Ok(())
    }
}

fn default_resource_metrics_max_keys() -> usize {
    4096
}
