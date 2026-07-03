use serde::{Deserialize, Serialize};

use super::{ConfigError, ConfigResult};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrometheusHttpConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_bind_address")]
    pub bind_address: String,
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default = "default_max_metric_lines")]
    pub max_metric_lines: usize,
}

impl Default for PrometheusHttpConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bind_address: default_bind_address(),
            port: default_port(),
            max_metric_lines: default_max_metric_lines(),
        }
    }
}

impl PrometheusHttpConfig {
    pub(super) fn validate(&self, module_enabled: bool) -> ConfigResult<()> {
        if !self.enabled {
            return Ok(());
        }
        if !module_enabled {
            return Err(ConfigError::invalid_value(
                "prometheus_http.enabled",
                "prometheus_http.enabled requires enabled sink.prometheus_http module",
            ));
        }
        if self.bind_address.is_empty() {
            return Err(ConfigError::invalid_value(
                "prometheus_http.bind_address",
                "prometheus_http.bind_address must not be empty when sink.prometheus_http is enabled",
            ));
        }
        if self.port == 0 {
            return Err(ConfigError::invalid_value(
                "prometheus_http.port",
                "prometheus_http.port must be greater than zero when sink.prometheus_http is enabled",
            ));
        }
        if self.max_metric_lines == 0 {
            return Err(ConfigError::invalid_value(
                "prometheus_http.max_metric_lines",
                "prometheus_http.max_metric_lines must be greater than zero when sink.prometheus_http is enabled",
            ));
        }
        Ok(())
    }
}

fn default_bind_address() -> String {
    "0.0.0.0".to_string()
}

fn default_port() -> u16 {
    9090
}

fn default_max_metric_lines() -> usize {
    4096
}
