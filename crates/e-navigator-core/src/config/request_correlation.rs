use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use super::{
    ConfigResult,
    bounds::validate_inclusive,
    capture_filter::{CaptureFilterConfig, validate_label_selector},
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestCorrelationConfig {
    #[serde(default = "default_generate_trace_ids")]
    pub generate_trace_ids: bool,
    /// Suppress request spans only when bounded procfs evidence identifies a
    /// supported OpenTelemetry zero-code agent in the observed process.
    #[serde(default)]
    pub suppress_otel_sdk_spans: bool,
    /// Exact Kubernetes labels whose complete match declares that application
    /// instrumentation owns request spans for the observed pod.
    #[serde(default)]
    pub application_span_ownership_labels: BTreeMap<String, String>,
    #[serde(default = "default_request_correlation_max_seen_requests")]
    pub max_seen_requests: usize,
    #[serde(default = "default_request_correlation_max_warnings")]
    pub max_warnings: usize,
}

impl Default for RequestCorrelationConfig {
    fn default() -> Self {
        Self {
            generate_trace_ids: default_generate_trace_ids(),
            suppress_otel_sdk_spans: false,
            application_span_ownership_labels: BTreeMap::new(),
            max_seen_requests: default_request_correlation_max_seen_requests(),
            max_warnings: default_request_correlation_max_warnings(),
        }
    }
}

fn default_generate_trace_ids() -> bool {
    true
}

impl RequestCorrelationConfig {
    pub const MAX_APPLICATION_SPAN_OWNERSHIP_LABELS: usize =
        CaptureFilterConfig::MAX_LABEL_SELECTOR_ENTRIES;
    pub const MAX_SEEN_REQUESTS_LIMIT: usize = 131_072;
    pub const MAX_WARNINGS_LIMIT: usize = 16_384;

    pub(super) fn validate(&self) -> ConfigResult<()> {
        validate_label_selector(
            "request_correlation.application_span_ownership_labels",
            &self.application_span_ownership_labels,
        )?;
        validate_inclusive(
            "request_correlation.max_seen_requests",
            self.max_seen_requests,
            1,
            Self::MAX_SEEN_REQUESTS_LIMIT,
        )?;
        validate_inclusive(
            "request_correlation.max_warnings",
            self.max_warnings,
            1,
            Self::MAX_WARNINGS_LIMIT,
        )?;
        Ok(())
    }
}

fn default_request_correlation_max_seen_requests() -> usize {
    8192
}

fn default_request_correlation_max_warnings() -> usize {
    1024
}
