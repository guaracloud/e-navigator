#![forbid(unsafe_code)]
#![warn(missing_debug_implementations, rust_2018_idioms, unreachable_pub)]
//! Static module registry, source supervision, and bounded signal dispatch.

pub mod registry;
pub mod runtime;
mod source_health;

pub use registry::ModuleRegistry;
pub use runtime::Runner;
pub use source_health::{SourceHealthRegistry, SourceHealthSnapshot};
