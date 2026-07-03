#![forbid(unsafe_code)]
#![warn(missing_debug_implementations, rust_2018_idioms, unreachable_pub)]

pub mod config;
pub mod error;
pub mod module;
pub mod pipeline;

pub use config::{
    ArgvCaptureConfig, AttributionConfig, ConfigError, ConfigErrorKind, ConfigResult,
    CpuProfileBackpressure, CpuProfileSourceConfig, DnsMetricsConfig, DnsSourceConfig,
    HttpSourceConfig, KNOWN_MODULES, KnownModule, KubernetesAttributionConfig, ModuleConfig,
    NetworkEndpointConfig, NetworkMetricsConfig, OtlpHttpConfig, ProfilingConfig,
    PrometheusHttpConfig, RequestCorrelationConfig, ResourceMetricsConfig, ResourceSourceConfig,
    RuntimeConfig, RuntimeSecurityConfig, TraceCorrelationConfig, is_known_module_name,
    known_module_names,
};
pub use error::{CoreError, CoreResult};
pub use module::{ModuleKind, ModuleMetadata};
pub use pipeline::{Generator, Processor, Signal, Sink, Source};
