use serde::{Deserialize, Serialize};
use std::net::IpAddr;

use super::{ConfigError, ConfigResult, bounds::validate_nonzero_bounded};

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeSecurityConfig {
    #[serde(default)]
    pub kubernetes_api_endpoints: Vec<NetworkEndpointConfig>,
}

impl RuntimeSecurityConfig {
    pub const MAX_KUBERNETES_API_ENDPOINTS_LIMIT: usize = 32;

    pub(super) fn validate(&self) -> ConfigResult<()> {
        if self.kubernetes_api_endpoints.len() > Self::MAX_KUBERNETES_API_ENDPOINTS_LIMIT {
            return Err(ConfigError::invalid_value(
                "runtime_security.kubernetes_api_endpoints",
                format!(
                    "runtime_security.kubernetes_api_endpoints must contain at most {} entries",
                    Self::MAX_KUBERNETES_API_ENDPOINTS_LIMIT
                ),
            ));
        }

        for endpoint in &self.kubernetes_api_endpoints {
            endpoint.validate()?;
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkEndpointConfig {
    pub address: String,
    pub port: u16,
}

impl NetworkEndpointConfig {
    pub(super) fn validate(&self) -> ConfigResult<()> {
        self.address.parse::<IpAddr>().map_err(|_| {
            ConfigError::invalid_value(
                "runtime_security.kubernetes_api_endpoints.address",
                "runtime_security.kubernetes_api_endpoints.address must be an IP address",
            )
        })?;

        if self.port == 0 {
            return Err(ConfigError::invalid_value(
                "runtime_security.kubernetes_api_endpoints.port",
                "runtime_security.kubernetes_api_endpoints.port must be greater than zero",
            ));
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkMetricsConfig {
    #[serde(default = "default_network_metrics_max_metric_keys")]
    pub max_metric_keys: usize,
    #[serde(default = "default_network_metrics_max_active_connections")]
    pub max_active_connections: usize,
    #[serde(default = "default_active_flow_snapshot_interval_millis")]
    pub active_flow_snapshot_interval_millis: u64,
    #[serde(default = "default_peer_series_idle_timeout_millis")]
    pub peer_series_idle_timeout_millis: u64,
}

impl Default for NetworkMetricsConfig {
    fn default() -> Self {
        Self {
            max_metric_keys: default_network_metrics_max_metric_keys(),
            max_active_connections: default_network_metrics_max_active_connections(),
            active_flow_snapshot_interval_millis: default_active_flow_snapshot_interval_millis(),
            peer_series_idle_timeout_millis: default_peer_series_idle_timeout_millis(),
        }
    }
}

impl NetworkMetricsConfig {
    pub const MAX_METRIC_KEYS_LIMIT: usize = 262_144;
    pub const MAX_ACTIVE_CONNECTIONS_LIMIT: usize = 1_048_576;
    pub const MAX_ACTIVE_FLOW_SNAPSHOT_INTERVAL_MILLIS: u64 = 5 * 60 * 1_000;
    pub const MAX_PEER_SERIES_IDLE_TIMEOUT_MILLIS: u64 = 24 * 60 * 60 * 1_000;

    pub(super) fn validate(&self) -> ConfigResult<()> {
        validate_nonzero_bounded(
            "network_metrics.max_metric_keys",
            self.max_metric_keys,
            Self::MAX_METRIC_KEYS_LIMIT,
        )?;
        validate_nonzero_bounded(
            "network_metrics.max_active_connections",
            self.max_active_connections,
            Self::MAX_ACTIVE_CONNECTIONS_LIMIT,
        )?;
        validate_nonzero_bounded(
            "network_metrics.active_flow_snapshot_interval_millis",
            self.active_flow_snapshot_interval_millis,
            Self::MAX_ACTIVE_FLOW_SNAPSHOT_INTERVAL_MILLIS,
        )?;
        if self.peer_series_idle_timeout_millis < self.active_flow_snapshot_interval_millis {
            return Err(ConfigError::invalid_value(
                "network_metrics.peer_series_idle_timeout_millis",
                "network_metrics.peer_series_idle_timeout_millis must be greater than or equal to network_metrics.active_flow_snapshot_interval_millis",
            ));
        }
        if self.peer_series_idle_timeout_millis > Self::MAX_PEER_SERIES_IDLE_TIMEOUT_MILLIS {
            return Err(ConfigError::invalid_value(
                "network_metrics.peer_series_idle_timeout_millis",
                format!(
                    "network_metrics.peer_series_idle_timeout_millis must be less than or equal to {}",
                    Self::MAX_PEER_SERIES_IDLE_TIMEOUT_MILLIS
                ),
            ));
        }

        Ok(())
    }
}

fn default_network_metrics_max_metric_keys() -> usize {
    4096
}

fn default_network_metrics_max_active_connections() -> usize {
    8192
}

const fn default_active_flow_snapshot_interval_millis() -> u64 {
    3_000
}

const fn default_peer_series_idle_timeout_millis() -> u64 {
    15 * 60 * 1_000
}
