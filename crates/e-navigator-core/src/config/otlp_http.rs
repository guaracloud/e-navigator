use serde::{Deserialize, Serialize};

use super::{ConfigError, ConfigResult};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OtlpHttpConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub endpoint: String,
    #[serde(default = "default_signal_family_enabled")]
    pub metrics_enabled: bool,
    #[serde(default = "default_signal_family_enabled")]
    pub traces_enabled: bool,
    #[serde(default = "default_signal_family_enabled")]
    pub profiles_enabled: bool,
    #[serde(default = "default_queue_capacity")]
    pub queue_capacity: usize,
    #[serde(default = "default_batch_size")]
    pub batch_size: usize,
    #[serde(default = "default_timeout_millis")]
    pub timeout_millis: u64,
    #[serde(default = "default_max_retries")]
    pub max_retries: usize,
    #[serde(default)]
    pub tls_insecure_skip_verify: bool,
}

impl Default for OtlpHttpConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            endpoint: String::new(),
            metrics_enabled: default_signal_family_enabled(),
            traces_enabled: default_signal_family_enabled(),
            profiles_enabled: default_signal_family_enabled(),
            queue_capacity: default_queue_capacity(),
            batch_size: default_batch_size(),
            timeout_millis: default_timeout_millis(),
            max_retries: default_max_retries(),
            tls_insecure_skip_verify: false,
        }
    }
}

impl OtlpHttpConfig {
    pub(super) fn validate(&self, module_enabled: bool) -> ConfigResult<()> {
        if !self.enabled {
            return Ok(());
        }
        if !module_enabled {
            return Err(ConfigError::invalid_value(
                "otlp_http.enabled",
                "otlp_http.enabled requires enabled sink.otlp_http module",
            ));
        }
        if self.endpoint.is_empty() {
            return Err(ConfigError::invalid_value(
                "otlp_http.endpoint",
                "otlp_http.endpoint is required when sink.otlp_http is enabled",
            ));
        }
        if self.queue_capacity == 0 {
            return Err(ConfigError::invalid_value(
                "otlp_http.queue_capacity",
                "otlp_http.queue_capacity must be greater than zero when sink.otlp_http is enabled",
            ));
        }
        if self.batch_size == 0 {
            return Err(ConfigError::invalid_value(
                "otlp_http.batch_size",
                "otlp_http.batch_size must be greater than zero when sink.otlp_http is enabled",
            ));
        }
        if self.timeout_millis == 0 {
            return Err(ConfigError::invalid_value(
                "otlp_http.timeout_millis",
                "otlp_http.timeout_millis must be greater than zero when sink.otlp_http is enabled",
            ));
        }
        if !(self.metrics_enabled || self.traces_enabled || self.profiles_enabled) {
            return Err(ConfigError::invalid_value(
                "otlp_http",
                "otlp_http must enable at least one signal family when sink.otlp_http is enabled",
            ));
        }
        Ok(())
    }
}

fn default_signal_family_enabled() -> bool {
    true
}

fn default_queue_capacity() -> usize {
    1024
}

fn default_batch_size() -> usize {
    64
}

fn default_timeout_millis() -> u64 {
    3000
}

fn default_max_retries() -> usize {
    2
}
