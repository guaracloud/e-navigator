#![forbid(unsafe_code)]
#![warn(missing_debug_implementations, rust_2018_idioms, unreachable_pub)]

pub mod container_attribution;

pub use container_attribution::{
    ContainerAttributionProcessor, KubernetesMetadataCache, KubernetesMetadataProvider,
};
