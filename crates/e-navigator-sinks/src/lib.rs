#![forbid(unsafe_code)]
#![warn(missing_debug_implementations, rust_2018_idioms, unreachable_pub)]

pub mod exporter;
pub mod json_stdout;
mod native_telemetry;
pub mod otel_metric;
pub mod otel_profile;
pub mod otel_trace;
mod otlp_common;
pub mod otlp_http;
mod otlp_metric_proto;
mod otlp_profile_proto;
mod otlp_trace_proto;
pub mod pprof_profile;
pub mod profile_format;
pub mod prometheus;

pub use exporter::{
    ExporterCounters, ExporterError, HttpExporterConfig, HttpJsonExporter, HttpProtobufExporter,
};
pub use json_stdout::{JsonStdoutSink, serialize_signal_line};
pub use native_telemetry::NativeTelemetryRegistry;
pub use otel_metric::{
    OtelMetricKind, OtelMetricRecord, OtelMetricValue, format_otel_metric_record,
};
pub use otel_profile::{OtelProfileFrame, OtelProfileRecord, format_otel_profile_record};
pub use otel_trace::{
    OtelSpanStatus, OtelTraceRecord, OtelTraceRecordKind, format_otel_trace_record,
};
pub use otlp_http::{ExportWorkerTelemetry, OtlpHttpSink, OtlpHttpTelemetry};
pub use pprof_profile::{format_pprof_profile, format_pprof_profile_batch};
pub use profile_format::{
    E_NAVIGATOR_CPU_PROFILE_METRIC_NAME, ProfileRecord, format_profile_record,
};
pub use prometheus::{PrometheusHttpSink, PrometheusMetricLine, render_prometheus_text};
