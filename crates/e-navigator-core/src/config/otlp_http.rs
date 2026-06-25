use serde::{Deserialize, Serialize};

use super::{ConfigError, ConfigResult};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OtlpHttpConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub endpoint: String,
    #[serde(default)]
    pub metrics_endpoint: String,
    #[serde(default)]
    pub traces_endpoint: String,
    #[serde(default)]
    pub profiles_endpoint: String,
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
            metrics_endpoint: String::new(),
            traces_endpoint: String::new(),
            profiles_endpoint: String::new(),
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
    pub fn effective_metrics_endpoint(&self) -> Option<&str> {
        self.effective_endpoint(&self.metrics_endpoint)
    }

    pub fn effective_traces_endpoint(&self) -> Option<&str> {
        self.effective_endpoint(&self.traces_endpoint)
    }

    pub fn effective_profiles_endpoint(&self) -> Option<&str> {
        self.effective_endpoint(&self.profiles_endpoint)
    }

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
        if self.metrics_enabled && self.effective_metrics_endpoint().is_none() {
            return Err(ConfigError::invalid_value(
                "otlp_http.metrics_endpoint",
                "otlp_http.metrics_endpoint or otlp_http.endpoint is required when OTLP metrics are enabled",
            ));
        }
        if self.traces_enabled && self.effective_traces_endpoint().is_none() {
            return Err(ConfigError::invalid_value(
                "otlp_http.traces_endpoint",
                "otlp_http.traces_endpoint or otlp_http.endpoint is required when OTLP traces are enabled",
            ));
        }
        if self.profiles_enabled && self.effective_profiles_endpoint().is_none() {
            return Err(ConfigError::invalid_value(
                "otlp_http.profiles_endpoint",
                "otlp_http.profiles_endpoint or otlp_http.endpoint is required when OTLP profiles are enabled",
            ));
        }
        Ok(())
    }

    fn effective_endpoint<'a>(&'a self, family_endpoint: &'a str) -> Option<&'a str> {
        if !family_endpoint.is_empty() {
            Some(family_endpoint)
        } else if !self.endpoint.is_empty() {
            Some(&self.endpoint)
        } else {
            None
        }
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
