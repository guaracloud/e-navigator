use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

use super::{ConfigError, ConfigResult, bounds::validate_inclusive};

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
    /// Narrow, opt-in cleartext HTTP/1 W3C propagation. This contract does
    /// not cover TLS or multiplexed HTTP versions.
    #[serde(default)]
    pub context_propagation: HttpContextPropagationConfig,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpContextPropagationConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_plaintext_ports")]
    pub plaintext_ports: Vec<u16>,
    #[serde(default = "default_max_tracked_sockets")]
    pub max_tracked_sockets: u32,
    #[serde(default = "default_context_pool_capacity")]
    pub context_pool_capacity: u32,
    #[serde(default = "default_same_thread_context_ttl_millis")]
    pub same_thread_context_ttl_millis: u64,
}

impl Default for HttpContextPropagationConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            plaintext_ports: default_plaintext_ports(),
            max_tracked_sockets: default_max_tracked_sockets(),
            context_pool_capacity: default_context_pool_capacity(),
            same_thread_context_ttl_millis: default_same_thread_context_ttl_millis(),
        }
    }
}

impl Default for HttpSourceConfig {
    fn default() -> Self {
        Self {
            max_header_bytes: default_http_source_max_header_bytes(),
            max_request_line_bytes: default_http_source_max_request_line_bytes(),
            max_attributes: default_http_source_max_attributes(),
            max_tracestate_bytes: default_http_source_max_tracestate_bytes(),
            inbound_enabled: false,
            context_propagation: HttpContextPropagationConfig::default(),
        }
    }
}

impl HttpSourceConfig {
    pub const MAX_HEADER_BYTES_LIMIT: usize = 8 * 1024;
    pub const MAX_REQUEST_LINE_BYTES_LIMIT: usize = 1024;
    pub const MAX_ATTRIBUTES_LIMIT: usize = 32;
    pub const MAX_TRACESTATE_BYTES_LIMIT: usize = 4096;

    pub(super) fn validate(&self) -> ConfigResult<()> {
        validate_inclusive(
            "http_source.max_header_bytes",
            self.max_header_bytes,
            1,
            Self::MAX_HEADER_BYTES_LIMIT,
        )?;
        validate_inclusive(
            "http_source.max_request_line_bytes",
            self.max_request_line_bytes,
            1,
            Self::MAX_REQUEST_LINE_BYTES_LIMIT,
        )?;
        validate_inclusive(
            "http_source.max_attributes",
            self.max_attributes,
            1,
            Self::MAX_ATTRIBUTES_LIMIT,
        )?;
        validate_inclusive(
            "http_source.max_tracestate_bytes",
            self.max_tracestate_bytes,
            1,
            Self::MAX_TRACESTATE_BYTES_LIMIT,
        )?;
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
        if self.context_propagation.enabled && !self.inbound_enabled {
            return Err(ConfigError::invalid_value(
                "http_source.context_propagation.enabled",
                "http_source.context_propagation.enabled requires http_source.inbound_enabled = true so propagated server context can be continued",
            ));
        }
        self.context_propagation.validate()?;
        Ok(())
    }
}

impl HttpContextPropagationConfig {
    pub const MAX_PLAINTEXT_PORTS: usize = 32;
    pub const MAX_TRACKED_SOCKETS_LIMIT: u32 = 65_536;
    pub const MIN_CONTEXT_POOL_CAPACITY: u32 = 128;
    pub const MAX_CONTEXT_POOL_CAPACITY: u32 = 65_536;
    pub const MAX_SAME_THREAD_CONTEXT_TTL_MILLIS: u64 = 300_000;

    fn validate(&self) -> ConfigResult<()> {
        if self.plaintext_ports.is_empty() || self.plaintext_ports.len() > Self::MAX_PLAINTEXT_PORTS
        {
            return Err(ConfigError::invalid_value(
                "http_source.context_propagation.plaintext_ports",
                format!(
                    "http_source.context_propagation.plaintext_ports must contain between 1 and {} ports",
                    Self::MAX_PLAINTEXT_PORTS
                ),
            ));
        }
        if self.plaintext_ports.contains(&0) {
            return Err(ConfigError::invalid_value(
                "http_source.context_propagation.plaintext_ports",
                "http_source.context_propagation.plaintext_ports must not contain port 0",
            ));
        }
        if self.plaintext_ports.iter().collect::<BTreeSet<_>>().len() != self.plaintext_ports.len()
        {
            return Err(ConfigError::invalid_value(
                "http_source.context_propagation.plaintext_ports",
                "http_source.context_propagation.plaintext_ports must not contain duplicates",
            ));
        }
        validate_inclusive(
            "http_source.context_propagation.max_tracked_sockets",
            self.max_tracked_sockets,
            1,
            Self::MAX_TRACKED_SOCKETS_LIMIT,
        )?;
        validate_inclusive(
            "http_source.context_propagation.context_pool_capacity",
            self.context_pool_capacity,
            Self::MIN_CONTEXT_POOL_CAPACITY,
            Self::MAX_CONTEXT_POOL_CAPACITY,
        )?;
        validate_inclusive(
            "http_source.context_propagation.same_thread_context_ttl_millis",
            self.same_thread_context_ttl_millis,
            1,
            Self::MAX_SAME_THREAD_CONTEXT_TTL_MILLIS,
        )?;
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

fn default_plaintext_ports() -> Vec<u16> {
    vec![80, 8080]
}

const fn default_max_tracked_sockets() -> u32 {
    8192
}

const fn default_context_pool_capacity() -> u32 {
    4096
}

const fn default_same_thread_context_ttl_millis() -> u64 {
    30_000
}
