mod argv;
mod attribution;
mod capture_filter;
mod cpu_profile;
mod dns_metrics;
mod dns_source;
mod ebpf;
mod error;
mod http_source;
mod json_stdout;
mod kubernetes;
mod modules;
mod network_metrics;
mod otlp_http;
mod profiling;
mod prometheus_http;
mod protocol_source;
mod request_correlation;
mod resource_metrics;
mod resource_source;
mod runtime;
mod source_supervisor;
mod tls_source;
mod trace_correlation;

pub use argv::ArgvCaptureConfig;
pub use attribution::AttributionConfig;
pub use capture_filter::{
    CaptureFilterConfig, CapturePosture, CgroupDiscoveryMode, WorkloadSelectorConfig,
};
pub use cpu_profile::{CpuProfileBackpressure, CpuProfileSourceConfig};
pub use dns_metrics::DnsMetricsConfig;
pub use dns_source::DnsSourceConfig;
pub use ebpf::{EbpfConfig, EbpfEventTransport, EbpfNetworkIoHook};
pub use error::{ConfigError, ConfigErrorKind, ConfigResult};
pub use http_source::HttpSourceConfig;
pub use json_stdout::{JsonStdoutConfig, JsonStdoutMode};
pub use kubernetes::KubernetesAttributionConfig;
pub use modules::{
    KNOWN_MODULES, KnownModule, ModuleConfig, is_known_module_name, known_module_names,
};
pub use network_metrics::{NetworkEndpointConfig, NetworkMetricsConfig, RuntimeSecurityConfig};
pub use otlp_http::{OtlpHttpCompression, OtlpHttpConfig};
pub use profiling::ProfilingConfig;
pub use prometheus_http::PrometheusHttpConfig;
pub use protocol_source::ProtocolSourceConfig;
pub use request_correlation::RequestCorrelationConfig;
pub use resource_metrics::ResourceMetricsConfig;
pub use resource_source::ResourceSourceConfig;
pub use runtime::RuntimeConfig;
pub use source_supervisor::{SourceFailurePolicy, SourceSupervisorConfig};
pub use tls_source::TlsSourceConfig;
pub use trace_correlation::TraceCorrelationConfig;

#[cfg(test)]
mod tests;
