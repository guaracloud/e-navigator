#![forbid(unsafe_code)]
#![warn(missing_debug_implementations, rust_2018_idioms, unreachable_pub)]

pub mod exporter;
pub mod json_stdout;
pub mod otel_metric;
pub mod otel_trace;
pub mod otlp_http;
mod otlp_trace_proto;
pub mod profile_format;
pub mod prometheus;

pub use exporter::{
    ExporterCounters, ExporterError, HttpExporterConfig, HttpJsonExporter, HttpProtobufExporter,
};
pub use json_stdout::JsonStdoutSink;
pub use otel_metric::{
    OtelMetricKind, OtelMetricRecord, OtelMetricValue, format_otel_metric_record,
};
pub use otel_trace::{OtelTraceRecord, OtelTraceRecordKind, format_otel_trace_record};
pub use otlp_http::OtlpHttpSink;
pub use profile_format::{PYROSCOPE_CPU_PROFILE_IDENTITY, ProfileRecord, format_profile_record};
pub use prometheus::{
    PrometheusHttpSink, PrometheusMetricLine, format_prometheus_compatibility_metric,
    render_prometheus_text,
};
