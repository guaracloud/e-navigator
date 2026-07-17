use serde::{Deserialize, Serialize};

use super::{ConfigError, ConfigResult};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestCorrelationConfig {
    #[serde(default = "default_generate_trace_ids")]
    pub generate_trace_ids: bool,
    #[serde(default = "default_request_correlation_max_seen_requests")]
    pub max_seen_requests: usize,
    #[serde(default = "default_request_correlation_max_warnings")]
    pub max_warnings: usize,
}

impl Default for RequestCorrelationConfig {
    fn default() -> Self {
        Self {
            generate_trace_ids: default_generate_trace_ids(),
            max_seen_requests: default_request_correlation_max_seen_requests(),
            max_warnings: default_request_correlation_max_warnings(),
        }
    }
}

fn default_generate_trace_ids() -> bool {
    true
}

impl RequestCorrelationConfig {
    pub const MAX_SEEN_REQUESTS_LIMIT: usize = 131_072;
    pub const MAX_WARNINGS_LIMIT: usize = 16_384;

    pub(super) fn validate(&self) -> ConfigResult<()> {
        if !(1..=Self::MAX_SEEN_REQUESTS_LIMIT).contains(&self.max_seen_requests) {
            return Err(ConfigError::invalid_value(
                "request_correlation.max_seen_requests",
                format!(
                    "request_correlation.max_seen_requests must be between 1 and {}",
                    Self::MAX_SEEN_REQUESTS_LIMIT
                ),
            ));
        }
        if !(1..=Self::MAX_WARNINGS_LIMIT).contains(&self.max_warnings) {
            return Err(ConfigError::invalid_value(
                "request_correlation.max_warnings",
                format!(
                    "request_correlation.max_warnings must be between 1 and {}",
                    Self::MAX_WARNINGS_LIMIT
                ),
            ));
        }
        Ok(())
    }
}

fn default_request_correlation_max_seen_requests() -> usize {
    8192
}

fn default_request_correlation_max_warnings() -> usize {
    1024
}
