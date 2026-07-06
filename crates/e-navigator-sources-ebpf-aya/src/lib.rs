#![warn(missing_debug_implementations, rust_2018_idioms, unreachable_pub)]

pub mod cpu_profile;
#[cfg(any(target_os = "linux", test))]
mod cpu_unwind;
#[cfg(any(target_os = "linux", test))]
mod diagnostics;
pub mod dns;
pub mod exec;
pub mod http;
pub mod network;
#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
mod perf_sample;
#[cfg(feature = "fuzzing")]
pub use perf_sample::{bench_inline_sample, bench_perf_sample_into_owned};
#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
mod procfs;
pub mod protocol;
#[cfg(any(target_os = "linux", test))]
mod source_telemetry;
pub mod tls;

pub use cpu_profile::AyaCpuProfileSource;
pub use dns::AyaDnsSource;
pub use exec::AyaExecSource;
pub use http::AyaHttpSource;
pub use network::AyaNetworkSource;
pub use protocol::AyaProtocolSource;
pub use tls::AyaTlsSource;
