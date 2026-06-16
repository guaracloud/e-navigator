#![forbid(unsafe_code)]
#![warn(missing_debug_implementations, rust_2018_idioms, unreachable_pub)]

pub mod json_stdout;
pub mod otel_metric;
pub mod otel_trace;
pub mod profile_format;

pub use json_stdout::JsonStdoutSink;
pub use otel_metric::{
    OtelMetricKind, OtelMetricRecord, OtelMetricValue, format_otel_metric_record,
};
pub use otel_trace::{OtelTraceRecord, OtelTraceRecordKind, format_otel_trace_record};
pub use profile_format::{ProfileRecord, format_profile_record};
