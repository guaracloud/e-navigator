use serde::{Deserialize, Serialize};

use super::{ConfigError, ConfigResult};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsMetricsConfig {
    #[serde(default = "default_dns_metrics_max_domains")]
    pub max_domains: usize,
    #[serde(default = "default_dns_metrics_max_counters")]
    pub max_counters: usize,
    #[serde(default = "default_dns_metrics_max_latencies")]
    pub max_latencies: usize,
    #[serde(default = "default_dns_metrics_max_edges")]
    pub max_edges: usize,
}

impl Default for DnsMetricsConfig {
    fn default() -> Self {
        Self {
            max_domains: default_dns_metrics_max_domains(),
            max_counters: default_dns_metrics_max_counters(),
            max_latencies: default_dns_metrics_max_latencies(),
            max_edges: default_dns_metrics_max_edges(),
        }
    }
}

impl DnsMetricsConfig {
    pub const MAX_DOMAINS_LIMIT: usize = 65_536;
    pub const MAX_COUNTERS_LIMIT: usize = 262_144;
    pub const MAX_LATENCIES_LIMIT: usize = 262_144;
    pub const MAX_EDGES_LIMIT: usize = 262_144;

    pub(super) fn validate(&self) -> ConfigResult<()> {
        if self.max_domains == 0 {
            return Err(ConfigError::invalid_value(
                "dns_metrics.max_domains",
                "dns_metrics.max_domains must be greater than zero",
            ));
        }
        if self.max_domains > Self::MAX_DOMAINS_LIMIT {
            return Err(ConfigError::invalid_value(
                "dns_metrics.max_domains",
                format!(
                    "dns_metrics.max_domains must be less than or equal to {}",
                    Self::MAX_DOMAINS_LIMIT
                ),
            ));
        }

        if self.max_counters == 0 {
            return Err(ConfigError::invalid_value(
                "dns_metrics.max_counters",
                "dns_metrics.max_counters must be greater than zero",
            ));
        }
        if self.max_counters > Self::MAX_COUNTERS_LIMIT {
            return Err(ConfigError::invalid_value(
                "dns_metrics.max_counters",
                format!(
                    "dns_metrics.max_counters must be less than or equal to {}",
                    Self::MAX_COUNTERS_LIMIT
                ),
            ));
        }

        if self.max_latencies == 0 {
            return Err(ConfigError::invalid_value(
                "dns_metrics.max_latencies",
                "dns_metrics.max_latencies must be greater than zero",
            ));
        }
        if self.max_latencies > Self::MAX_LATENCIES_LIMIT {
            return Err(ConfigError::invalid_value(
                "dns_metrics.max_latencies",
                format!(
                    "dns_metrics.max_latencies must be less than or equal to {}",
                    Self::MAX_LATENCIES_LIMIT
                ),
            ));
        }

        if self.max_edges == 0 {
            return Err(ConfigError::invalid_value(
                "dns_metrics.max_edges",
                "dns_metrics.max_edges must be greater than zero",
            ));
        }
        if self.max_edges > Self::MAX_EDGES_LIMIT {
            return Err(ConfigError::invalid_value(
                "dns_metrics.max_edges",
                format!(
                    "dns_metrics.max_edges must be less than or equal to {}",
                    Self::MAX_EDGES_LIMIT
                ),
            ));
        }

        Ok(())
    }
}

fn default_dns_metrics_max_domains() -> usize {
    1024
}

fn default_dns_metrics_max_counters() -> usize {
    4096
}

fn default_dns_metrics_max_latencies() -> usize {
    4096
}

fn default_dns_metrics_max_edges() -> usize {
    4096
}
