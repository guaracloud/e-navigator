#![forbid(unsafe_code)]
#![warn(missing_debug_implementations, rust_2018_idioms, unreachable_pub)]
//! Signal processors for workload filtering and evidence-backed attribution.

pub mod container_attribution;
mod log_processing;
mod workload_resource_filter;
pub use log_processing::LogProcessingProcessor;

pub use container_attribution::{
    ContainerAttributionProcessor, KubernetesMetadataCache, KubernetesMetadataProvider,
};
pub use workload_resource_filter::WorkloadResourceFilterProcessor;
