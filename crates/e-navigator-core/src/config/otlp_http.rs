use serde::{Deserialize, Serialize};

use super::{ConfigError, ConfigResult};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
    #[serde(default = "default_flush_interval_millis")]
    pub flush_interval_millis: u64,
    #[serde(default = "default_timeout_millis")]
    pub timeout_millis: u64,
    #[serde(default = "default_max_retries")]
    pub max_retries: usize,
    #[serde(default = "default_retry_initial_backoff_millis")]
    pub retry_initial_backoff_millis: u64,
    #[serde(default = "default_retry_max_backoff_millis")]
    pub retry_max_backoff_millis: u64,
    #[serde(default = "default_circuit_breaker_failure_threshold")]
    pub circuit_breaker_failure_threshold: usize,
    #[serde(default = "default_circuit_breaker_cooldown_millis")]
    pub circuit_breaker_cooldown_millis: u64,
    #[serde(default = "default_shutdown_timeout_millis")]
    pub shutdown_timeout_millis: u64,
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
            flush_interval_millis: default_flush_interval_millis(),
            timeout_millis: default_timeout_millis(),
            max_retries: default_max_retries(),
            retry_initial_backoff_millis: default_retry_initial_backoff_millis(),
            retry_max_backoff_millis: default_retry_max_backoff_millis(),
            circuit_breaker_failure_threshold: default_circuit_breaker_failure_threshold(),
            circuit_breaker_cooldown_millis: default_circuit_breaker_cooldown_millis(),
            shutdown_timeout_millis: default_shutdown_timeout_millis(),
            tls_insecure_skip_verify: false,
        }
    }
}

impl OtlpHttpConfig {
    pub const MAX_QUEUE_CAPACITY_LIMIT: usize = 65_536;
    pub const MAX_BATCH_SIZE_LIMIT: usize = 4096;
    pub const MAX_TIMEOUT_MILLIS_LIMIT: u64 = 300_000;
    pub const MAX_FLUSH_INTERVAL_MILLIS_LIMIT: u64 = 60_000;
    pub const MAX_RETRY_BACKOFF_MILLIS_LIMIT: u64 = 300_000;
    pub const MAX_RETRIES_LIMIT: usize = 16;
    pub const MAX_CIRCUIT_BREAKER_FAILURE_THRESHOLD_LIMIT: usize = 1024;
    pub const MAX_CIRCUIT_BREAKER_COOLDOWN_MILLIS_LIMIT: u64 = 300_000;
    pub const MAX_SHUTDOWN_TIMEOUT_MILLIS_LIMIT: u64 = 300_000;
    pub const MAX_ENDPOINT_BYTES_LIMIT: usize = 2048;

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
        if self.queue_capacity > Self::MAX_QUEUE_CAPACITY_LIMIT {
            return Err(ConfigError::invalid_value(
                "otlp_http.queue_capacity",
                format!(
                    "otlp_http.queue_capacity must be less than or equal to {} when sink.otlp_http is enabled",
                    Self::MAX_QUEUE_CAPACITY_LIMIT
                ),
            ));
        }
        if self.batch_size == 0 {
            return Err(ConfigError::invalid_value(
                "otlp_http.batch_size",
                "otlp_http.batch_size must be greater than zero when sink.otlp_http is enabled",
            ));
        }
        if self.batch_size > Self::MAX_BATCH_SIZE_LIMIT {
            return Err(ConfigError::invalid_value(
                "otlp_http.batch_size",
                format!(
                    "otlp_http.batch_size must be less than or equal to {} when sink.otlp_http is enabled",
                    Self::MAX_BATCH_SIZE_LIMIT
                ),
            ));
        }
        if self.batch_size > self.queue_capacity {
            return Err(ConfigError::invalid_value(
                "otlp_http.batch_size",
                "otlp_http.batch_size must be less than or equal to otlp_http.queue_capacity",
            ));
        }
        validate_nonzero_millis(
            "otlp_http.flush_interval_millis",
            self.flush_interval_millis,
            Self::MAX_FLUSH_INTERVAL_MILLIS_LIMIT,
        )?;
        if self.timeout_millis == 0 {
            return Err(ConfigError::invalid_value(
                "otlp_http.timeout_millis",
                "otlp_http.timeout_millis must be greater than zero when sink.otlp_http is enabled",
            ));
        }
        if self.timeout_millis > Self::MAX_TIMEOUT_MILLIS_LIMIT {
            return Err(ConfigError::invalid_value(
                "otlp_http.timeout_millis",
                format!(
                    "otlp_http.timeout_millis must be less than or equal to {} when sink.otlp_http is enabled",
                    Self::MAX_TIMEOUT_MILLIS_LIMIT
                ),
            ));
        }
        if self.max_retries > Self::MAX_RETRIES_LIMIT {
            return Err(ConfigError::invalid_value(
                "otlp_http.max_retries",
                format!(
                    "otlp_http.max_retries must be less than or equal to {} when sink.otlp_http is enabled",
                    Self::MAX_RETRIES_LIMIT
                ),
            ));
        }
        validate_nonzero_millis(
            "otlp_http.retry_initial_backoff_millis",
            self.retry_initial_backoff_millis,
            Self::MAX_RETRY_BACKOFF_MILLIS_LIMIT,
        )?;
        validate_nonzero_millis(
            "otlp_http.retry_max_backoff_millis",
            self.retry_max_backoff_millis,
            Self::MAX_RETRY_BACKOFF_MILLIS_LIMIT,
        )?;
        if self.retry_initial_backoff_millis > self.retry_max_backoff_millis {
            return Err(ConfigError::invalid_value(
                "otlp_http.retry_initial_backoff_millis",
                "otlp_http.retry_initial_backoff_millis must be less than or equal to otlp_http.retry_max_backoff_millis",
            ));
        }
        if self.circuit_breaker_failure_threshold == 0 {
            return Err(ConfigError::invalid_value(
                "otlp_http.circuit_breaker_failure_threshold",
                "otlp_http.circuit_breaker_failure_threshold must be greater than zero when sink.otlp_http is enabled",
            ));
        }
        if self.circuit_breaker_failure_threshold
            > Self::MAX_CIRCUIT_BREAKER_FAILURE_THRESHOLD_LIMIT
        {
            return Err(ConfigError::invalid_value(
                "otlp_http.circuit_breaker_failure_threshold",
                format!(
                    "otlp_http.circuit_breaker_failure_threshold must be less than or equal to {} when sink.otlp_http is enabled",
                    Self::MAX_CIRCUIT_BREAKER_FAILURE_THRESHOLD_LIMIT
                ),
            ));
        }
        validate_nonzero_millis(
            "otlp_http.circuit_breaker_cooldown_millis",
            self.circuit_breaker_cooldown_millis,
            Self::MAX_CIRCUIT_BREAKER_COOLDOWN_MILLIS_LIMIT,
        )?;
        validate_nonzero_millis(
            "otlp_http.shutdown_timeout_millis",
            self.shutdown_timeout_millis,
            Self::MAX_SHUTDOWN_TIMEOUT_MILLIS_LIMIT,
        )?;
        if !(self.metrics_enabled || self.traces_enabled || self.profiles_enabled) {
            return Err(ConfigError::invalid_value(
                "otlp_http",
                "otlp_http must enable at least one signal family when sink.otlp_http is enabled",
            ));
        }
        validate_endpoint("otlp_http.endpoint", &self.endpoint)?;
        validate_endpoint("otlp_http.metrics_endpoint", &self.metrics_endpoint)?;
        validate_endpoint("otlp_http.traces_endpoint", &self.traces_endpoint)?;
        validate_endpoint("otlp_http.profiles_endpoint", &self.profiles_endpoint)?;
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

fn validate_nonzero_millis(path: &'static str, value: u64, maximum: u64) -> ConfigResult<()> {
    if value == 0 {
        return Err(ConfigError::invalid_value(
            path,
            format!("{path} must be greater than zero when sink.otlp_http is enabled"),
        ));
    }
    if value > maximum {
        return Err(ConfigError::invalid_value(
            path,
            format!(
                "{path} must be less than or equal to {maximum} when sink.otlp_http is enabled"
            ),
        ));
    }
    Ok(())
}

fn validate_endpoint(path: &'static str, endpoint: &str) -> ConfigResult<()> {
    if endpoint.is_empty() {
        return Ok(());
    }
    if endpoint.len() > OtlpHttpConfig::MAX_ENDPOINT_BYTES_LIMIT {
        return Err(ConfigError::invalid_value(
            path,
            format!(
                "{path} must be at most {} bytes",
                OtlpHttpConfig::MAX_ENDPOINT_BYTES_LIMIT
            ),
        ));
    }
    if endpoint.trim() != endpoint || endpoint.chars().any(char::is_whitespace) {
        return Err(ConfigError::invalid_value(
            path,
            format!("{path} must not contain whitespace"),
        ));
    }
    if endpoint.bytes().any(|byte| byte.is_ascii_control()) {
        return Err(ConfigError::invalid_value(
            path,
            format!("{path} must not contain control characters"),
        ));
    }
    let Some(rest) = endpoint
        .strip_prefix("http://")
        .or_else(|| endpoint.strip_prefix("https://"))
    else {
        return Err(ConfigError::invalid_value(
            path,
            format!("{path} must start with http:// or https://"),
        ));
    };
    let authority = rest
        .split(['/', '?', '#'])
        .next()
        .expect("split always returns at least one segment");
    if !authority_has_host(authority) {
        return Err(ConfigError::invalid_value(
            path,
            format!("{path} must include a host after the scheme"),
        ));
    }
    Ok(())
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

fn default_flush_interval_millis() -> u64 {
    1_000
}

fn default_timeout_millis() -> u64 {
    3000
}

fn default_max_retries() -> usize {
    2
}

fn default_retry_initial_backoff_millis() -> u64 {
    100
}

fn default_retry_max_backoff_millis() -> u64 {
    5_000
}

fn default_circuit_breaker_failure_threshold() -> usize {
    5
}

fn default_circuit_breaker_cooldown_millis() -> u64 {
    30_000
}

fn default_shutdown_timeout_millis() -> u64 {
    10_000
}

fn authority_has_host(authority: &str) -> bool {
    if authority.is_empty() || authority.starts_with(':') {
        return false;
    }
    if let Some(rest) = authority.strip_prefix('[') {
        let Some(end) = rest.find(']') else {
            return false;
        };
        if end == 0 {
            return false;
        }
        let after = &rest[end + 1..];
        return after.is_empty() || after.starts_with(':');
    }
    true
}
