#![warn(missing_debug_implementations, rust_2018_idioms, unreachable_pub)]
//! Aya-based Linux sources, raw-event decoding, and privileged attachment logic.

pub mod capture_filter;
pub mod cpu_profile;
#[cfg(any(target_os = "linux", test))]
mod cpu_unwind;
#[cfg(any(target_os = "linux", test))]
mod diagnostics;
pub mod dns;
#[cfg(test)]
#[path = "../../e-navigator-ebpf-programs/src/capture_policy.rs"]
mod ebpf_capture_policy;
#[cfg(target_os = "linux")]
mod ebpf_maps;
mod event_transport;
pub mod exec;
#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
mod go_tls;
pub mod http;
mod kernel_hook;
pub mod network;
#[cfg(target_os = "linux")]
mod perf_reader;
#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
mod perf_sample;
#[cfg(feature = "fuzzing")]
pub use event_transport::bench_ring_sample_handoff;
#[cfg(feature = "fuzzing")]
pub use perf_sample::{bench_inline_sample, bench_perf_sample_into_owned};
#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
mod procfs;
pub mod protocol;
#[cfg(any(target_os = "linux", test))]
mod reader_shutdown;
#[cfg(target_os = "linux")]
mod shutdown;
mod source_telemetry;
#[cfg(feature = "fuzzing")]
pub use source_telemetry::bench_source_telemetry_summary_checks;
pub use source_telemetry::{SourceTelemetrySnapshot, source_telemetry_snapshots};
pub mod tls;

#[cfg(feature = "fuzzing")]
pub use go_tls::{fuzz_decode_go_amd64_returns, fuzz_parse_go_build_info};

pub use cpu_profile::AyaCpuProfileSource;
pub use dns::AyaDnsSource;
pub use exec::AyaExecSource;
pub use http::AyaHttpSource;
pub use network::AyaNetworkSource;
pub use protocol::AyaProtocolSource;
pub use tls::AyaTlsSource;
