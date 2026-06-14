pub mod config;
pub mod error;
pub mod module;
pub mod pipeline;

pub use config::{
    ArgvCaptureConfig, AttributionConfig, KubernetesAttributionConfig, ModuleConfig, RuntimeConfig,
};
pub use error::{CoreError, CoreResult};
pub use module::{ModuleKind, ModuleMetadata};
pub use pipeline::{Generator, Processor, Signal, Sink, Source};
