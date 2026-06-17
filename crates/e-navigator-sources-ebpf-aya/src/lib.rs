#![warn(missing_debug_implementations, rust_2018_idioms, unreachable_pub)]

pub mod cpu_profile;
#[cfg(any(target_os = "linux", test))]
mod diagnostics;
pub mod exec;
pub mod network;
#[cfg(any(target_os = "linux", test))]
mod perf_sample;
#[cfg(any(target_os = "linux", test))]
mod procfs;
#[cfg(any(target_os = "linux", test))]
mod source_telemetry;

pub use cpu_profile::AyaCpuProfileSource;
pub use exec::AyaExecSource;
pub use network::AyaNetworkSource;
