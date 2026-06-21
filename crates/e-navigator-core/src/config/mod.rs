mod argv;
mod attribution;
mod cpu_profile;
mod dns_metrics;
mod error;
mod kubernetes;
mod modules;
mod network_metrics;
mod otlp_http;
mod profiling;
mod prometheus_http;
mod request_correlation;
mod resource_metrics;
mod resource_source;
mod runtime;
mod trace_correlation;

pub use argv::ArgvCaptureConfig;
pub use attribution::AttributionConfig;
pub use cpu_profile::{CpuProfileBackpressure, CpuProfileSourceConfig};
pub use dns_metrics::DnsMetricsConfig;
pub use error::{ConfigError, ConfigErrorKind, ConfigResult};
pub use kubernetes::KubernetesAttributionConfig;
pub use modules::{
    KNOWN_MODULES, KnownModule, ModuleConfig, is_known_module_name, known_module_names,
};
pub use network_metrics::{NetworkEndpointConfig, NetworkMetricsConfig, RuntimeSecurityConfig};
pub use otlp_http::OtlpHttpConfig;
pub use profiling::ProfilingConfig;
pub use prometheus_http::PrometheusHttpConfig;
pub use request_correlation::RequestCorrelationConfig;
pub use resource_metrics::ResourceMetricsConfig;
pub use resource_source::ResourceSourceConfig;
pub use runtime::RuntimeConfig;
pub use trace_correlation::TraceCorrelationConfig;

#[cfg(test)]
mod tests;
