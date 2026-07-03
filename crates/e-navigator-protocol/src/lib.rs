#![forbid(unsafe_code)]
#![warn(missing_debug_implementations, rust_2018_idioms, unreachable_pub)]

pub mod http;
pub mod mysql;
pub mod postgres;
pub mod redis;
pub mod trace_context;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProtocolExtractionConfig {
    pub max_header_bytes: usize,
    pub max_request_line_bytes: usize,
    pub max_attributes: usize,
    pub max_tracestate_bytes: usize,
}

impl Default for ProtocolExtractionConfig {
    fn default() -> Self {
        Self {
            max_header_bytes: 8 * 1024,
            max_request_line_bytes: 1024,
            max_attributes: 8,
            max_tracestate_bytes: 512,
        }
    }
}
