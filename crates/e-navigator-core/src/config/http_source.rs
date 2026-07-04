use serde::{Deserialize, Serialize};

use super::{ConfigError, ConfigResult};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpSourceConfig {
    #[serde(default = "default_http_source_max_header_bytes")]
    pub max_header_bytes: usize,
    #[serde(default = "default_http_source_max_request_line_bytes")]
    pub max_request_line_bytes: usize,
    #[serde(default = "default_http_source_max_attributes")]
    pub max_attributes: usize,
    #[serde(default = "default_http_source_max_tracestate_bytes")]
    pub max_tracestate_bytes: usize,
    /// Enables server-side (inbound) HTTP request capture through accept
    /// tracking and read-side payload capture.
    #[serde(default)]
    pub inbound_enabled: bool,
}

impl Default for HttpSourceConfig {
    fn default() -> Self {
        Self {
            max_header_bytes: default_http_source_max_header_bytes(),
            max_request_line_bytes: default_http_source_max_request_line_bytes(),
            max_attributes: default_http_source_max_attributes(),
            max_tracestate_bytes: default_http_source_max_tracestate_bytes(),
            inbound_enabled: false,
        }
    }
}

impl HttpSourceConfig {
    pub const MAX_HEADER_BYTES_LIMIT: usize = 8 * 1024;
    pub const MAX_REQUEST_LINE_BYTES_LIMIT: usize = 1024;
    pub const MAX_ATTRIBUTES_LIMIT: usize = 32;
    pub const MAX_TRACESTATE_BYTES_LIMIT: usize = 4096;

    pub(super) fn validate(&self) -> ConfigResult<()> {
        if !(1..=Self::MAX_HEADER_BYTES_LIMIT).contains(&self.max_header_bytes) {
            return Err(ConfigError::invalid_value(
                "http_source.max_header_bytes",
                format!(
                    "http_source.max_header_bytes must be between 1 and {}",
                    Self::MAX_HEADER_BYTES_LIMIT
                ),
            ));
        }
        if !(1..=Self::MAX_REQUEST_LINE_BYTES_LIMIT).contains(&self.max_request_line_bytes) {
            return Err(ConfigError::invalid_value(
                "http_source.max_request_line_bytes",
                format!(
                    "http_source.max_request_line_bytes must be between 1 and {}",
                    Self::MAX_REQUEST_LINE_BYTES_LIMIT
                ),
            ));
        }
        if !(1..=Self::MAX_ATTRIBUTES_LIMIT).contains(&self.max_attributes) {
            return Err(ConfigError::invalid_value(
                "http_source.max_attributes",
                format!(
                    "http_source.max_attributes must be between 1 and {}",
                    Self::MAX_ATTRIBUTES_LIMIT
                ),
            ));
        }
        if !(1..=Self::MAX_TRACESTATE_BYTES_LIMIT).contains(&self.max_tracestate_bytes) {
            return Err(ConfigError::invalid_value(
                "http_source.max_tracestate_bytes",
                format!(
                    "http_source.max_tracestate_bytes must be between 1 and {}",
                    Self::MAX_TRACESTATE_BYTES_LIMIT
                ),
            ));
        }
        if self.max_request_line_bytes > self.max_header_bytes {
            return Err(ConfigError::invalid_value(
                "http_source.max_request_line_bytes",
                "http_source.max_request_line_bytes must be less than or equal to http_source.max_header_bytes",
            ));
        }
        if self.max_tracestate_bytes > self.max_header_bytes {
            return Err(ConfigError::invalid_value(
                "http_source.max_tracestate_bytes",
                "http_source.max_tracestate_bytes must be less than or equal to http_source.max_header_bytes",
            ));
        }
        Ok(())
    }
}

fn default_http_source_max_header_bytes() -> usize {
    8 * 1024
}

fn default_http_source_max_request_line_bytes() -> usize {
    1024
}

fn default_http_source_max_attributes() -> usize {
    8
}

fn default_http_source_max_tracestate_bytes() -> usize {
    512
}
