use serde::{Deserialize, Serialize};

use super::{ConfigResult, bounds::validate_nonzero_bounded};

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
        validate_nonzero_bounded(
            "dns_metrics.max_domains",
            self.max_domains,
            Self::MAX_DOMAINS_LIMIT,
        )?;
        validate_nonzero_bounded(
            "dns_metrics.max_counters",
            self.max_counters,
            Self::MAX_COUNTERS_LIMIT,
        )?;
        validate_nonzero_bounded(
            "dns_metrics.max_latencies",
            self.max_latencies,
            Self::MAX_LATENCIES_LIMIT,
        )?;
        validate_nonzero_bounded(
            "dns_metrics.max_edges",
            self.max_edges,
            Self::MAX_EDGES_LIMIT,
        )?;
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
