use serde::{Deserialize, Serialize};

use super::{ConfigError, ConfigResult};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsMetricsConfig {
    #[serde(default = "default_dns_metrics_max_domains")]
    pub max_domains: usize,
}

impl Default for DnsMetricsConfig {
    fn default() -> Self {
        Self {
            max_domains: default_dns_metrics_max_domains(),
        }
    }
}

impl DnsMetricsConfig {
    pub(super) fn validate(&self) -> ConfigResult<()> {
        if self.max_domains == 0 {
            return Err(ConfigError::invalid_value(
                "dns_metrics.max_domains",
                "dns_metrics.max_domains must be greater than zero",
            ));
        }

        Ok(())
    }
}

fn default_dns_metrics_max_domains() -> usize {
    1024
}
