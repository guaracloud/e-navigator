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
    #[serde(default = "default_signal_family_enabled")]
    pub metrics_enabled: bool,
    #[serde(default = "default_signal_family_enabled")]
    pub profiles_enabled: bool,
}

impl Default for PrometheusHttpConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bind_address: default_bind_address(),
            port: default_port(),
            max_metric_lines: default_max_metric_lines(),
            metrics_enabled: default_signal_family_enabled(),
            profiles_enabled: default_signal_family_enabled(),
        }
    }
}

impl PrometheusHttpConfig {
    pub const MAX_METRIC_LINES_LIMIT: usize = 262_144;
    pub const MAX_BIND_ADDRESS_BYTES_LIMIT: usize = 253;

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
        if self.bind_address.trim() != self.bind_address {
            return Err(ConfigError::invalid_value(
                "prometheus_http.bind_address",
                "prometheus_http.bind_address must not have leading or trailing whitespace when sink.prometheus_http is enabled",
            ));
        }
        if self.bind_address.chars().any(char::is_whitespace) {
            return Err(ConfigError::invalid_value(
                "prometheus_http.bind_address",
                "prometheus_http.bind_address must not contain whitespace when sink.prometheus_http is enabled",
            ));
        }
        if self
            .bind_address
            .bytes()
            .any(|byte| byte.is_ascii_control())
        {
            return Err(ConfigError::invalid_value(
                "prometheus_http.bind_address",
                "prometheus_http.bind_address must not contain control characters when sink.prometheus_http is enabled",
            ));
        }
        if self.bind_address.len() > Self::MAX_BIND_ADDRESS_BYTES_LIMIT {
            return Err(ConfigError::invalid_value(
                "prometheus_http.bind_address",
                format!(
                    "prometheus_http.bind_address must be at most {} bytes when sink.prometheus_http is enabled",
                    Self::MAX_BIND_ADDRESS_BYTES_LIMIT
                ),
            ));
        }
        if bind_address_has_inline_port(&self.bind_address) {
            return Err(ConfigError::invalid_value(
                "prometheus_http.bind_address",
                "prometheus_http.bind_address must not include a port because prometheus_http.port is configured separately",
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
        if self.max_metric_lines > Self::MAX_METRIC_LINES_LIMIT {
            return Err(ConfigError::invalid_value(
                "prometheus_http.max_metric_lines",
                format!(
                    "prometheus_http.max_metric_lines must be less than or equal to {} when sink.prometheus_http is enabled",
                    Self::MAX_METRIC_LINES_LIMIT
                ),
            ));
        }
        if !(self.metrics_enabled || self.profiles_enabled) {
            return Err(ConfigError::invalid_value(
                "prometheus_http",
                "prometheus_http must enable at least one signal family when sink.prometheus_http is enabled",
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

fn default_signal_family_enabled() -> bool {
    true
}

fn bind_address_has_inline_port(value: &str) -> bool {
    value.contains(':') && !(value.starts_with('[') && value.ends_with(']'))
}
