#![forbid(unsafe_code)]
#![warn(missing_debug_implementations, rust_2018_idioms, unreachable_pub)]

pub mod config;
pub mod error;
pub mod module;
pub mod pipeline;

pub use config::{
    ArgvCaptureConfig, AttributionConfig, ConfigError, ConfigErrorKind, ConfigResult,
    CpuProfileBackpressure, CpuProfileSourceConfig, DnsMetricsConfig, KubernetesAttributionConfig,
    ModuleConfig, NetworkEndpointConfig, NetworkMetricsConfig, ProfilingConfig,
    RequestCorrelationConfig, ResourceMetricsConfig, ResourceSourceConfig, RuntimeConfig,
    RuntimeSecurityConfig, TraceCorrelationConfig,
};
pub use error::{CoreError, CoreResult};
pub use module::{ModuleKind, ModuleMetadata};
pub use pipeline::{Generator, Processor, Signal, Sink, Source};
