use serde::{Deserialize, Serialize};
use std::net::IpAddr;

use super::{ConfigError, ConfigResult};

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeSecurityConfig {
    #[serde(default)]
    pub kubernetes_api_endpoints: Vec<NetworkEndpointConfig>,
}

impl RuntimeSecurityConfig {
    pub(super) fn validate(&self) -> ConfigResult<()> {
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
}

impl Default for NetworkMetricsConfig {
    fn default() -> Self {
        Self {
            max_metric_keys: default_network_metrics_max_metric_keys(),
            max_active_connections: default_network_metrics_max_active_connections(),
        }
    }
}

impl NetworkMetricsConfig {
    pub const MAX_METRIC_KEYS_LIMIT: usize = 262_144;
    pub const MAX_ACTIVE_CONNECTIONS_LIMIT: usize = 1_048_576;

    pub(super) fn validate(&self) -> ConfigResult<()> {
        if self.max_metric_keys == 0 {
            return Err(ConfigError::invalid_value(
                "network_metrics.max_metric_keys",
                "network_metrics.max_metric_keys must be greater than zero",
            ));
        }
        if self.max_metric_keys > Self::MAX_METRIC_KEYS_LIMIT {
            return Err(ConfigError::invalid_value(
                "network_metrics.max_metric_keys",
                format!(
                    "network_metrics.max_metric_keys must be less than or equal to {}",
                    Self::MAX_METRIC_KEYS_LIMIT
                ),
            ));
        }

        if self.max_active_connections == 0 {
            return Err(ConfigError::invalid_value(
                "network_metrics.max_active_connections",
                "network_metrics.max_active_connections must be greater than zero",
            ));
        }
        if self.max_active_connections > Self::MAX_ACTIVE_CONNECTIONS_LIMIT {
            return Err(ConfigError::invalid_value(
                "network_metrics.max_active_connections",
                format!(
                    "network_metrics.max_active_connections must be less than or equal to {}",
                    Self::MAX_ACTIVE_CONNECTIONS_LIMIT
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
