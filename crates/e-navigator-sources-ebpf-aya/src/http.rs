#![allow(dead_code)]

#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
use e_navigator_protocol::{
    ProtocolExtractionConfig,
    http::{HttpExtraction, parse_http_request},
};
#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
use e_navigator_signals::{
    NetworkProcessIdentity, ProtocolRequestObservation, SignalEnvelope, TraceConfidence,
    TraceCorrelationKind, TracePeerContext,
};

#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
const RAW_HTTP_MAX_IOVECS: usize = 3;
#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
const RAW_HTTP_IOVEC_CHUNK_BYTES: usize = 96;
#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
pub(crate) const RAW_HTTP_REQUEST_BYTES: usize = RAW_HTTP_IOVEC_CHUNK_BYTES * RAW_HTTP_MAX_IOVECS;
#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
pub(crate) const RAW_HTTP_AF_INET: u32 = 2;
#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
pub(crate) const RAW_HTTP_AF_INET6: u32 = 10;
#[cfg(any(target_os = "linux", test))]
const PERF_BUFFER_PAGE_COUNT: usize = 64;
#[cfg(any(target_os = "linux", test))]
const PERF_READER_POLL_INTERVAL_MS: u64 = 25;
#[cfg(any(target_os = "linux", test))]
const HTTP_DIAGNOSTIC_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_secs(10);
#[cfg(any(target_os = "linux", test))]
const HTTP_DIAGNOSTIC_COUNTERS_LEN: usize = 15;
#[cfg(any(target_os = "linux", test))]
const HTTP_DIAGNOSTIC_COUNTER_NAMES: [&str; HTTP_DIAGNOSTIC_COUNTERS_LEN] = [
    "connect_enter",
    "connect_active",
    "write_enter",
    "writev_enter",
    "sendto_enter",
    "sendmsg_enter",
    "null_or_empty",
    "active_connection_miss",
    "non_tcp_connection",
    "copy_success",
    "copy_empty",
    "output_attempt",
    "fallback_candidate",
    "fallback_non_http_start",
    "fallback_output_attempt",
];

#[cfg(any(target_os = "linux", test))]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct HttpDiagnosticCounterSnapshot {
    counters: [u64; HTTP_DIAGNOSTIC_COUNTERS_LEN],
}

#[cfg(any(target_os = "linux", test))]
impl HttpDiagnosticCounterSnapshot {
    fn from_counters(counters: [u64; HTTP_DIAGNOSTIC_COUNTERS_LEN]) -> Self {
        Self { counters }
    }

    fn delta_since(&self, previous: &Self) -> Self {
        let mut counters = [0_u64; HTTP_DIAGNOSTIC_COUNTERS_LEN];
        for (index, counter) in counters.iter_mut().enumerate() {
            *counter = self.counters[index].saturating_sub(previous.counters[index]);
        }
        Self { counters }
    }

    fn is_empty(&self) -> bool {
        self.counters.iter().all(|counter| *counter == 0)
    }

    fn get(&self, index: usize) -> u64 {
        self.counters[index]
    }

    #[cfg(test)]
    fn nonzero_stage_names(&self) -> Vec<&'static str> {
        self.counters
            .iter()
            .enumerate()
            .filter_map(|(index, counter)| {
                if *counter > 0 {
                    Some(HTTP_DIAGNOSTIC_COUNTER_NAMES[index])
                } else {
                    None
                }
            })
            .collect()
    }
}

#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct RawHttpRequestEvent {
    pub pid: u32,
    pub uid: u32,
    pub cgroup_id: u64,
    pub fd: i32,
    pub family: u32,
    pub remote_port_be: u16,
    pub local_port_be: u16,
    pub remote_addr_v4: u32,
    pub local_addr_v4: u32,
    pub remote_addr_v6: [u8; 16],
    pub local_addr_v6: [u8; 16],
    pub timestamp_unix_nanos: u64,
    pub request_len: u32,
    pub request_iovec_lens: [u16; RAW_HTTP_MAX_IOVECS],
    pub command: [u8; 16],
    pub request: [u8; RAW_HTTP_REQUEST_BYTES],
}

#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RawHttpDecodeError {
    RawSampleTooShort,
    HttpExtraction(HttpExtraction),
}

#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
impl RawHttpDecodeError {
    fn reason_name(self) -> &'static str {
        match self {
            Self::RawSampleTooShort => "raw_sample_too_short",
            Self::HttpExtraction(HttpExtraction::HeadersTooLong) => "headers_too_long",
            Self::HttpExtraction(HttpExtraction::InvalidUtf8) => "invalid_utf8",
            Self::HttpExtraction(HttpExtraction::RequestLineTooLong) => "request_line_too_long",
            Self::HttpExtraction(HttpExtraction::MalformedRequestLine) => "malformed_request_line",
        }
    }
}

#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
fn raw_http_request_to_signal_with_clock_and_procfs(
    bytes: &[u8],
    host: Option<String>,
    observed_unix_nanos: u64,
    procfs_root: &std::path::Path,
) -> Option<SignalEnvelope> {
    raw_http_request_to_signal_result(bytes, host, observed_unix_nanos, procfs_root).ok()
}

#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
fn raw_http_request_to_signal_result(
    bytes: &[u8],
    host: Option<String>,
    observed_unix_nanos: u64,
    procfs_root: &std::path::Path,
) -> Result<SignalEnvelope, RawHttpDecodeError> {
    if bytes.len() < core::mem::size_of::<RawHttpRequestEvent>() {
        return Err(RawHttpDecodeError::RawSampleTooShort);
    }

    let raw = unsafe { core::ptr::read_unaligned(bytes.as_ptr().cast::<RawHttpRequestEvent>()) };
    let request = compact_raw_http_request(&raw);
    let parsed = parse_http_request(&request, &ProtocolExtractionConfig::default())
        .map_err(RawHttpDecodeError::HttpExtraction)?;
    let trace_context = parsed.trace_context.as_ref();
    let peer = peer_context(&raw, &parsed.attributes);
    let container = crate::procfs::container_from_pid_cgroup(procfs_root, raw.pid);
    let process = NetworkProcessIdentity {
        pid: raw.pid,
        ppid: None,
        uid: Some(raw.uid),
        command: bytes_to_string(&raw.command),
        executable: None,
        cgroup_id: (raw.cgroup_id != 0).then_some(raw.cgroup_id),
    };

    Ok(SignalEnvelope::protocol_request_observation(
        "source.aya_http",
        host,
        ProtocolRequestObservation {
            protocol: parsed.protocol,
            start_unix_nanos: observed_unix_nanos,
            end_unix_nanos: None,
            duration_nanos: None,
            trace_id: trace_context.map(|context| context.trace_id.clone()),
            span_id: trace_context.map(|context| context.span_id.clone()),
            parent_span_id: None,
            traceparent: parsed.traceparent,
            tracestate: parsed.tracestate,
            correlation_kind: TraceCorrelationKind::ProtocolObserved,
            confidence: if parsed.warning.is_none() {
                TraceConfidence::High
            } else {
                TraceConfidence::Low
            },
            service_name: Some(process.command.clone()),
            method: parsed.method,
            status_code: None,
            process: Some(process),
            container,
            kubernetes: None,
            peer,
            attributes: parsed.attributes,
        },
    ))
}

#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
fn compact_raw_http_request(raw: &RawHttpRequestEvent) -> Vec<u8> {
    let request_len = (raw.request_len as usize).min(RAW_HTTP_REQUEST_BYTES);
    if raw.request_iovec_lens.iter().all(|len| *len == 0) {
        return raw.request[..request_len].to_vec();
    }

    let mut request = Vec::with_capacity(request_len);
    for (index, len) in raw.request_iovec_lens.iter().enumerate() {
        let start = index * RAW_HTTP_IOVEC_CHUNK_BYTES;
        let end = (start + usize::from(*len)).min(RAW_HTTP_REQUEST_BYTES);
        if start >= end || request.len() >= request_len {
            continue;
        }

        let remaining = request_len - request.len();
        let segment = &raw.request[start..end];
        request.extend_from_slice(&segment[..segment.len().min(remaining)]);
    }
    request
}

#[cfg(feature = "fuzzing")]
pub fn fuzz_decode_raw_http_request_event(bytes: &[u8]) -> bool {
    const MAX_FUZZ_BYTES: usize = 1024;

    let bytes = &bytes[..bytes.len().min(MAX_FUZZ_BYTES)];
    raw_http_request_to_signal_with_clock_and_procfs(
        bytes,
        None,
        1_000,
        std::path::Path::new("__e_navigator_fuzz_no_procfs__"),
    )
    .is_some()
}

#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
fn peer_context(
    raw: &RawHttpRequestEvent,
    attributes: &[e_navigator_signals::TraceAttribute],
) -> Option<TracePeerContext> {
    let address = match raw.family {
        RAW_HTTP_AF_INET => Some(ipv4_to_string(raw.remote_addr_v4)),
        RAW_HTTP_AF_INET6 => Some(ipv6_to_string(raw.remote_addr_v6)),
        _ => None,
    };
    let domain = attribute_value(attributes, "server.address").map(ToString::to_string);
    let port = u16::from_be(raw.remote_port_be);
    let port = if port != 0 {
        Some(port)
    } else {
        attribute_value(attributes, "server.port").and_then(|value| value.parse::<u16>().ok())
    };
    if address.is_none() && domain.is_none() && port.is_none() {
        return None;
    }

    Some(TracePeerContext {
        address,
        port,
        domain,
        workload: None,
        container: None,
    })
}

#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
fn attribute_value<'a>(
    attributes: &'a [e_navigator_signals::TraceAttribute],
    key: &str,
) -> Option<&'a str> {
    attributes
        .iter()
        .find(|attribute| attribute.key == key)
        .map(|attribute| attribute.value.as_str())
}

#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
fn ipv4_to_string(value: u32) -> String {
    let octets = value.to_ne_bytes();
    format!("{}.{}.{}.{}", octets[0], octets[1], octets[2], octets[3])
}

#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
fn ipv6_to_string(value: [u8; 16]) -> String {
    std::net::Ipv6Addr::from(value).to_string()
}

#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
fn bytes_to_string(bytes: &[u8]) -> String {
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).to_string()
}

#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn now_unix_nanos() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(0)
}

#[cfg(target_os = "linux")]
mod platform {
    use crate::diagnostics::{DiagnosticSampleDecision, SourceDiagnostics};
    use crate::perf_sample::perf_sample_bytes;
    use crate::source_telemetry::SourceTelemetry;
    use async_trait::async_trait;
    use aya::{
        Ebpf, include_bytes_aligned,
        maps::{
            MapData, PerCpuArray,
            perf::{PerfEvent, PerfEventArray},
        },
        programs::TracePoint,
        util::online_cpus,
    };
    use e_navigator_core::{CoreError, CoreResult, ModuleKind, ModuleMetadata, Source};
    use e_navigator_signals::{SignalEnvelope, SignalPayload};
    use std::{
        path::PathBuf,
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
    };
    use tokio::{sync::mpsc, task::JoinHandle};
    use tracing::{debug, info, warn};

    #[derive(Debug, Default)]
    pub struct AyaHttpSource {
        host: Option<String>,
        procfs_root: PathBuf,
    }

    impl AyaHttpSource {
        pub fn new(host: Option<String>, procfs_root: PathBuf) -> Self {
            Self { host, procfs_root }
        }
    }

    #[async_trait]
    impl Source<SignalEnvelope> for AyaHttpSource {
        fn metadata(&self) -> ModuleMetadata {
            ModuleMetadata::new("source.aya_http", ModuleKind::Source)
        }

        async fn run(self: Box<Self>, tx: mpsc::Sender<SignalEnvelope>) -> CoreResult<()> {
            bump_memlock_rlimit();
            let shutdown = ReaderShutdown::new();
            let mut reader_handles = Vec::new();
            let diagnostics = SourceDiagnostics::from_env();
            let telemetry = Arc::new(SourceTelemetry::new("source.aya_http"));
            let mut ebpf = Ebpf::load(include_bytes_aligned!(concat!(
                env!("OUT_DIR"),
                "/e-navigator-ebpf-programs"
            )))
            .map_err(module_error)?;

            attach_tracepoint(
                &mut ebpf,
                "tracepoint_http_connect_enter",
                "syscalls",
                "sys_enter_connect",
            )?;
            attach_tracepoint(
                &mut ebpf,
                "tracepoint_http_connect_exit",
                "syscalls",
                "sys_exit_connect",
            )?;
            attach_tracepoint(
                &mut ebpf,
                "tracepoint_http_close_enter",
                "syscalls",
                "sys_enter_close",
            )?;
            attach_tracepoint(
                &mut ebpf,
                "tracepoint_http_write_enter",
                "syscalls",
                "sys_enter_write",
            )?;
            attach_tracepoint(
                &mut ebpf,
                "tracepoint_http_writev_enter",
                "syscalls",
                "sys_enter_writev",
            )?;
            attach_tracepoint(
                &mut ebpf,
                "tracepoint_http_sendto_enter",
                "syscalls",
                "sys_enter_sendto",
            )?;
            attach_tracepoint(
                &mut ebpf,
                "tracepoint_http_sendmsg_enter",
                "syscalls",
                "sys_enter_sendmsg",
            )?;

            if diagnostics.enabled() {
                let diagnostic_counters =
                    PerCpuArray::try_from(ebpf.take_map("HTTP_DIAGNOSTIC_COUNTERS").ok_or_else(
                        || CoreError::ModuleFailed {
                            module: "source.aya_http".to_string(),
                            message: "missing HTTP_DIAGNOSTIC_COUNTERS map".to_string(),
                        },
                    )?)
                    .map_err(module_error)?;
                reader_handles.push(spawn_http_diagnostic_counter_logger(
                    diagnostic_counters,
                    shutdown.clone(),
                ));
            }

            let mut perf_array = PerfEventArray::try_from(
                ebpf.take_map("HTTP_REQUEST_EVENTS")
                    .ok_or_else(|| CoreError::ModuleFailed {
                        module: "source.aya_http".to_string(),
                        message: "missing HTTP_REQUEST_EVENTS map".to_string(),
                    })?,
            )
            .map_err(module_error)?;

            let cpus = online_cpus().map_err(|(_, err)| module_error(err))?;
            for cpu_id in cpus {
                let mut buffer = perf_array
                    .open(cpu_id, Some(super::PERF_BUFFER_PAGE_COUNT))
                    .map_err(module_error)?;
                let cpu_tx = tx.clone();
                let host = self.host.clone();
                let procfs_root = self.procfs_root.clone();
                let reader_shutdown = shutdown.clone();
                let diagnostics = diagnostics.clone();
                let telemetry = telemetry.clone();

                reader_handles.push(tokio::task::spawn_blocking(move || {
                    let mut closed = false;

                    while !reader_shutdown.is_stopped() {
                        buffer.for_each(|event| {
                            if closed {
                                return;
                            }

                            match event {
                                PerfEvent::Sample { head, tail } => {
                                    let bytes = perf_sample_bytes(head, tail);
                                    match super::raw_http_request_to_signal_result(
                                        bytes.as_ref(),
                                        host.clone(),
                                        super::now_unix_nanos(),
                                        &procfs_root,
                                    ) {
                                        Ok(signal) => {
                                            telemetry.record_decoded_sample();
                                            let diagnostic_decision =
                                                log_signal_diagnostic(&diagnostics, &signal);
                                            telemetry
                                                .record_diagnostic_decision(diagnostic_decision);
                                            if cpu_tx.blocking_send(signal).is_err() {
                                                telemetry.record_send_failure();
                                                closed = true;
                                            } else {
                                                telemetry.record_sent_signal();
                                            }
                                        }
                                        Err(err) => {
                                            telemetry.record_invalid_sample();
                                            let diagnostic_decision =
                                                log_invalid_http_sample_diagnostic(
                                                    &diagnostics,
                                                    err,
                                                );
                                            telemetry
                                                .record_diagnostic_decision(diagnostic_decision);
                                        }
                                    }
                                }
                                PerfEvent::Lost { count } => {
                                    telemetry.record_lost_perf_events(count);
                                    warn!(count, "lost http request perf events");
                                }
                            }
                            telemetry.maybe_log_summary();
                        });

                        if closed {
                            return;
                        }

                        std::thread::sleep(std::time::Duration::from_millis(
                            super::PERF_READER_POLL_INTERVAL_MS,
                        ));
                    }
                }));
            }

            if diagnostics.enabled() {
                info!(
                    source = "source.aya_http",
                    remaining_samples = diagnostics.remaining_samples(),
                    filtered_preview_remaining_samples =
                        diagnostics.remaining_filtered_preview_samples(),
                    "source diagnostics enabled"
                );
            }
            debug!("aya http source attached");
            tokio::signal::ctrl_c().await.map_err(module_error)?;
            shutdown.stop();
            join_reader_handles(reader_handles).await
        }
    }

    fn log_signal_diagnostic(
        diagnostics: &SourceDiagnostics,
        signal: &SignalEnvelope,
    ) -> DiagnosticSampleDecision {
        let SignalPayload::ProtocolRequestObservation(event) = &signal.payload else {
            return DiagnosticSampleDecision::Disabled;
        };
        let method = event.method.as_deref().unwrap_or("");
        let peer_address = event
            .peer
            .as_ref()
            .and_then(|peer| peer.address.as_deref())
            .unwrap_or("");
        let filter_values = [method, peer_address];
        let decision = diagnostics.sample_decision_for(&filter_values);
        if decision != DiagnosticSampleDecision::Matched {
            return decision;
        }

        info!(
            target: "e_navigator_sources_ebpf_aya::source_diagnostics",
            source = "source.aya_http",
            raw_event = "protocol_request_observation",
            method = ?event.method,
            trace_id = ?event.trace_id,
            peer_address = ?event.peer.as_ref().and_then(|peer| peer.address.as_deref()),
            peer_port = ?event.peer.as_ref().and_then(|peer| peer.port),
            "source diagnostic raw event decoded"
        );
        DiagnosticSampleDecision::Matched
    }

    fn log_invalid_http_sample_diagnostic(
        diagnostics: &SourceDiagnostics,
        err: super::RawHttpDecodeError,
    ) -> DiagnosticSampleDecision {
        let reason = err.reason_name();
        let decision = diagnostics.sample_decision_for(&[reason]);
        if decision != DiagnosticSampleDecision::Matched {
            return decision;
        }

        info!(
            target: "e_navigator_sources_ebpf_aya::source_diagnostics",
            source = "source.aya_http",
            raw_event = "invalid_http_request_sample",
            invalid_reason = reason,
            "source diagnostic raw event invalid"
        );
        DiagnosticSampleDecision::Matched
    }

    fn spawn_http_diagnostic_counter_logger(
        counters: PerCpuArray<MapData, u64>,
        shutdown: ReaderShutdown,
    ) -> JoinHandle<()> {
        tokio::task::spawn_blocking(move || {
            let mut previous = super::HttpDiagnosticCounterSnapshot::default();

            while !shutdown.is_stopped() {
                std::thread::sleep(super::HTTP_DIAGNOSTIC_POLL_INTERVAL);
                if shutdown.is_stopped() {
                    break;
                }

                match read_http_diagnostic_counters(&counters) {
                    Ok(snapshot) => {
                        let delta = snapshot.delta_since(&previous);
                        previous = snapshot;
                        if delta.is_empty() {
                            continue;
                        }

                        info!(
                            target: "e_navigator_sources_ebpf_aya::source_diagnostics",
                            source = "source.aya_http",
                            connect_enter = delta.get(0),
                            connect_active = delta.get(1),
                            write_enter = delta.get(2),
                            writev_enter = delta.get(3),
                            sendto_enter = delta.get(4),
                            sendmsg_enter = delta.get(5),
                            null_or_empty = delta.get(6),
                            active_connection_miss = delta.get(7),
                            non_tcp_connection = delta.get(8),
                            copy_success = delta.get(9),
                            copy_empty = delta.get(10),
                            output_attempt = delta.get(11),
                            fallback_candidate = delta.get(12),
                            fallback_non_http_start = delta.get(13),
                            fallback_output_attempt = delta.get(14),
                            stage_names = ?super::HTTP_DIAGNOSTIC_COUNTER_NAMES,
                            "source diagnostic http stage counters"
                        );
                    }
                    Err(err) => {
                        warn!(error = %err, "failed to read http diagnostic counters");
                    }
                }
            }
        })
    }

    fn read_http_diagnostic_counters(
        counters: &PerCpuArray<MapData, u64>,
    ) -> Result<super::HttpDiagnosticCounterSnapshot, aya::maps::MapError> {
        let mut totals = [0_u64; super::HTTP_DIAGNOSTIC_COUNTERS_LEN];
        for (index, total) in totals.iter_mut().enumerate() {
            let per_cpu = counters.get(&(index as u32), 0)?;
            *total = per_cpu
                .iter()
                .fold(0_u64, |sum, value| sum.saturating_add(*value));
        }

        Ok(super::HttpDiagnosticCounterSnapshot::from_counters(totals))
    }

    fn attach_tracepoint(
        ebpf: &mut Ebpf,
        program_name: &'static str,
        category: &'static str,
        name: &'static str,
    ) -> CoreResult<()> {
        let program: &mut TracePoint = ebpf
            .program_mut(program_name)
            .ok_or_else(|| CoreError::ModuleFailed {
                module: "source.aya_http".to_string(),
                message: format!("missing {program_name} program"),
            })?
            .try_into()
            .map_err(module_error)?;
        program.load().map_err(module_error)?;
        program.attach(category, name).map_err(module_error)?;
        Ok(())
    }

    #[derive(Clone)]
    struct ReaderShutdown {
        stopped: Arc<AtomicBool>,
    }

    impl ReaderShutdown {
        fn new() -> Self {
            Self {
                stopped: Arc::new(AtomicBool::new(false)),
            }
        }

        fn stop(&self) {
            self.stopped.store(true, Ordering::SeqCst);
        }

        fn is_stopped(&self) -> bool {
            self.stopped.load(Ordering::SeqCst)
        }
    }

    impl Drop for ReaderShutdown {
        fn drop(&mut self) {
            self.stop();
        }
    }

    async fn join_reader_handles(handles: Vec<JoinHandle<()>>) -> CoreResult<()> {
        for handle in handles {
            handle.await.map_err(module_error)?;
        }

        Ok(())
    }

    fn bump_memlock_rlimit() {
        let rlimit = libc::rlimit {
            rlim_cur: libc::RLIM_INFINITY,
            rlim_max: libc::RLIM_INFINITY,
        };
        let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlimit) };
        if ret != 0 {
            debug!("failed to raise RLIMIT_MEMLOCK");
        }
    }

    fn module_error(err: impl ToString) -> CoreError {
        CoreError::ModuleFailed {
            module: "source.aya_http".to_string(),
            message: err.to_string(),
        }
    }
}

#[cfg(not(target_os = "linux"))]
mod platform {
    use async_trait::async_trait;
    use e_navigator_core::{CoreError, CoreResult, ModuleKind, ModuleMetadata, Source};
    use e_navigator_signals::SignalEnvelope;
    use tokio::sync::mpsc;

    #[derive(Debug, Default)]
    pub struct AyaHttpSource {
        host: Option<String>,
        _procfs_root: std::path::PathBuf,
    }

    impl AyaHttpSource {
        pub fn new(host: Option<String>, procfs_root: std::path::PathBuf) -> Self {
            Self {
                host,
                _procfs_root: procfs_root,
            }
        }
    }

    #[async_trait]
    impl Source<SignalEnvelope> for AyaHttpSource {
        fn metadata(&self) -> ModuleMetadata {
            ModuleMetadata::new("source.aya_http", ModuleKind::Source)
        }

        async fn run(self: Box<Self>, _tx: mpsc::Sender<SignalEnvelope>) -> CoreResult<()> {
            Err(CoreError::ModuleFailed {
                module: "source.aya_http".to_string(),
                message: format!(
                    "Aya HTTP source requires Linux and eBPF support; host={}",
                    self.host.as_deref().unwrap_or("unknown")
                ),
            })
        }
    }
}

pub use platform::AyaHttpSource;

#[cfg(test)]
mod tests {
    use super::*;
    use e_navigator_signals::{ProtocolKind, SignalPayload, TraceConfidence, TraceCorrelationKind};

    #[test]
    fn raw_http_request_event_decodes_to_protocol_observation() {
        let request = concat!(
            "GET /orders/42?token=secret HTTP/1.1\r\n",
            "Host: api.example.test:8080\r\n",
            "Traceparent: 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01\r\n",
            "X-Request-Id: req-123\r\n",
            "\r\n"
        );
        let mut raw = RawHttpRequestEvent {
            pid: 42,
            uid: 1000,
            cgroup_id: 7,
            fd: 9,
            family: RAW_HTTP_AF_INET,
            remote_port_be: 8080_u16.to_be(),
            local_port_be: 39000_u16.to_be(),
            remote_addr_v4: u32::from_ne_bytes([10, 43, 0, 77]),
            local_addr_v4: u32::from_ne_bytes([10, 42, 1, 23]),
            remote_addr_v6: [0; 16],
            local_addr_v6: [0; 16],
            timestamp_unix_nanos: 0,
            request_len: request.len() as u32,
            request_iovec_lens: [0; RAW_HTTP_MAX_IOVECS],
            command: fixed_command("curl"),
            request: [0; RAW_HTTP_REQUEST_BYTES],
        };
        raw.request[..request.len()].copy_from_slice(request.as_bytes());

        let signal = raw_http_request_to_signal_with_clock_and_procfs(
            raw_as_bytes(&raw),
            Some("node-a".to_string()),
            1_000,
            std::path::Path::new("/proc"),
        )
        .expect("raw event decodes");

        assert_eq!(signal.source, "source.aya_http");
        let SignalPayload::ProtocolRequestObservation(event) = signal.payload else {
            panic!("expected protocol request observation");
        };
        assert_eq!(event.protocol, ProtocolKind::Http);
        assert_eq!(event.start_unix_nanos, 1_000);
        assert_eq!(event.method.as_deref(), Some("GET"));
        assert_eq!(
            event.trace_id.as_deref(),
            Some("4bf92f3577b34da6a3ce929d0e0e4736")
        );
        assert_eq!(event.span_id.as_deref(), Some("00f067aa0ba902b7"));
        assert_eq!(
            event.correlation_kind,
            TraceCorrelationKind::ProtocolObserved
        );
        assert_eq!(event.confidence, TraceConfidence::High);
        let peer = event.peer.expect("peer context");
        assert_eq!(peer.address.as_deref(), Some("10.43.0.77"));
        assert_eq!(peer.port, Some(8080));
        assert_eq!(peer.domain.as_deref(), Some("api.example.test"));
        let process = event.process.expect("process identity");
        assert_eq!(process.pid, 42);
        assert_eq!(process.command, "curl");
        assert!(
            event
                .attributes
                .iter()
                .any(|attribute| attribute.key == "url.path" && attribute.value == "/orders/42")
        );
        assert!(
            event
                .attributes
                .iter()
                .any(|attribute| attribute.key == "server.port" && attribute.value == "8080")
        );
    }

    #[test]
    fn split_iovec_raw_http_request_compacts_before_decode() {
        let part1 = b"GET /split-iovec";
        let part2 = concat!(
            " HTTP/1.1\r\n",
            "Host: split.example.test\r\n",
            "X-Request-Id: req-split\r\n",
            "\r\n"
        )
        .as_bytes();
        let mut raw = RawHttpRequestEvent {
            pid: 42,
            uid: 1000,
            cgroup_id: 7,
            fd: 9,
            family: RAW_HTTP_AF_INET,
            remote_port_be: 8080_u16.to_be(),
            local_port_be: 39000_u16.to_be(),
            remote_addr_v4: u32::from_ne_bytes([10, 43, 0, 77]),
            local_addr_v4: u32::from_ne_bytes([10, 42, 1, 23]),
            remote_addr_v6: [0; 16],
            local_addr_v6: [0; 16],
            timestamp_unix_nanos: 0,
            request_len: (part1.len() + part2.len()) as u32,
            request_iovec_lens: [part1.len() as u16, part2.len() as u16, 0],
            command: fixed_command("curl"),
            request: [0; RAW_HTTP_REQUEST_BYTES],
        };
        raw.request[..part1.len()].copy_from_slice(part1);
        let second_offset = RAW_HTTP_REQUEST_BYTES / raw.request_iovec_lens.len();
        raw.request[second_offset..second_offset + part2.len()].copy_from_slice(part2);

        let signal = raw_http_request_to_signal_with_clock_and_procfs(
            raw_as_bytes(&raw),
            Some("node-a".to_string()),
            1_000,
            std::path::Path::new("/proc"),
        )
        .expect("split raw event decodes");

        let SignalPayload::ProtocolRequestObservation(event) = signal.payload else {
            panic!("expected protocol request observation");
        };
        assert_eq!(event.method.as_deref(), Some("GET"));
        assert!(
            event
                .attributes
                .iter()
                .any(|attribute| attribute.key == "url.path" && attribute.value == "/split-iovec")
        );
        assert!(
            event
                .attributes
                .iter()
                .any(|attribute| attribute.key == "http.request.id"
                    && attribute.value == "req-split")
        );
    }

    #[test]
    fn three_iovec_raw_http_request_compacts_before_decode() {
        let part1 = b"GET /three";
        let part2 = b"-iovec HTTP/1.1\r\nHost: three.example.test\r\n";
        let part3 = b"X-Request-Id: req-three\r\n\r\n";
        let mut raw = RawHttpRequestEvent {
            pid: 42,
            uid: 1000,
            cgroup_id: 7,
            fd: 9,
            family: RAW_HTTP_AF_INET,
            remote_port_be: 8080_u16.to_be(),
            local_port_be: 39000_u16.to_be(),
            remote_addr_v4: u32::from_ne_bytes([10, 43, 0, 77]),
            local_addr_v4: u32::from_ne_bytes([10, 42, 1, 23]),
            remote_addr_v6: [0; 16],
            local_addr_v6: [0; 16],
            timestamp_unix_nanos: 0,
            request_len: (part1.len() + part2.len() + part3.len()) as u32,
            request_iovec_lens: [part1.len() as u16, part2.len() as u16, part3.len() as u16],
            command: fixed_command("curl"),
            request: [0; RAW_HTTP_REQUEST_BYTES],
        };
        raw.request[..part1.len()].copy_from_slice(part1);
        let slot_len = RAW_HTTP_REQUEST_BYTES / raw.request_iovec_lens.len();
        assert_eq!(slot_len, RAW_HTTP_IOVEC_CHUNK_BYTES);
        assert!(part1.len() <= RAW_HTTP_IOVEC_CHUNK_BYTES);
        assert!(part2.len() <= RAW_HTTP_IOVEC_CHUNK_BYTES);
        assert!(part3.len() <= RAW_HTTP_IOVEC_CHUNK_BYTES);
        raw.request[slot_len..slot_len + part2.len()].copy_from_slice(part2);
        raw.request[(slot_len * 2)..(slot_len * 2) + part3.len()].copy_from_slice(part3);

        let signal = raw_http_request_to_signal_with_clock_and_procfs(
            raw_as_bytes(&raw),
            Some("node-a".to_string()),
            1_000,
            std::path::Path::new("/proc"),
        )
        .expect("three-slot split raw event decodes");

        let SignalPayload::ProtocolRequestObservation(event) = signal.payload else {
            panic!("expected protocol request observation");
        };
        assert_eq!(event.method.as_deref(), Some("GET"));
        assert!(
            event
                .attributes
                .iter()
                .any(|attribute| attribute.key == "url.path" && attribute.value == "/three-iovec")
        );
        assert!(
            event
                .attributes
                .iter()
                .any(|attribute| attribute.key == "server.address"
                    && attribute.value == "three.example.test")
        );
        assert!(
            event
                .attributes
                .iter()
                .any(|attribute| attribute.key == "http.request.id"
                    && attribute.value == "req-three")
        );
    }

    #[test]
    fn non_http_payload_is_ignored() {
        let payload = b"not an http request";
        let mut raw = RawHttpRequestEvent {
            pid: 42,
            uid: 1000,
            cgroup_id: 7,
            fd: 9,
            family: RAW_HTTP_AF_INET,
            remote_port_be: 8080_u16.to_be(),
            local_port_be: 39000_u16.to_be(),
            remote_addr_v4: u32::from_ne_bytes([10, 43, 0, 77]),
            local_addr_v4: u32::from_ne_bytes([10, 42, 1, 23]),
            remote_addr_v6: [0; 16],
            local_addr_v6: [0; 16],
            timestamp_unix_nanos: 0,
            request_len: payload.len() as u32,
            request_iovec_lens: [0; RAW_HTTP_MAX_IOVECS],
            command: fixed_command("curl"),
            request: [0; RAW_HTTP_REQUEST_BYTES],
        };
        raw.request[..payload.len()].copy_from_slice(payload);

        assert!(
            raw_http_request_to_signal_with_clock_and_procfs(
                raw_as_bytes(&raw),
                None,
                1_000,
                std::path::Path::new("/proc")
            )
            .is_none()
        );
    }

    #[test]
    fn raw_http_decode_result_classifies_short_samples() {
        let err =
            raw_http_request_to_signal_result(&[], None, 1_000, std::path::Path::new("/proc"))
                .expect_err("short raw samples are invalid");

        assert_eq!(err, RawHttpDecodeError::RawSampleTooShort);
        assert_eq!(err.reason_name(), "raw_sample_too_short");
    }

    #[test]
    fn raw_http_decode_result_classifies_non_http_payloads() {
        let payload = b"not an http request";
        let mut raw = RawHttpRequestEvent {
            pid: 42,
            uid: 1000,
            cgroup_id: 7,
            fd: 9,
            family: RAW_HTTP_AF_INET,
            remote_port_be: 8080_u16.to_be(),
            local_port_be: 39000_u16.to_be(),
            remote_addr_v4: u32::from_ne_bytes([10, 43, 0, 77]),
            local_addr_v4: u32::from_ne_bytes([10, 42, 1, 23]),
            remote_addr_v6: [0; 16],
            local_addr_v6: [0; 16],
            timestamp_unix_nanos: 0,
            request_len: payload.len() as u32,
            request_iovec_lens: [0; RAW_HTTP_MAX_IOVECS],
            command: fixed_command("curl"),
            request: [0; RAW_HTTP_REQUEST_BYTES],
        };
        raw.request[..payload.len()].copy_from_slice(payload);

        let err = raw_http_request_to_signal_result(
            raw_as_bytes(&raw),
            None,
            1_000,
            std::path::Path::new("/proc"),
        )
        .expect_err("non-http payloads are invalid");

        assert_eq!(
            err,
            RawHttpDecodeError::HttpExtraction(HttpExtraction::HeadersTooLong)
        );
        assert_eq!(err.reason_name(), "headers_too_long");
    }

    #[test]
    fn unknown_socket_peer_uses_host_authority_for_peer_context() {
        let request = concat!(
            "GET /fallback-peer HTTP/1.1\r\n",
            "Host: fallback.example.test:18083\r\n",
            "\r\n"
        );
        let mut raw = RawHttpRequestEvent {
            pid: 42,
            uid: 1000,
            cgroup_id: 7,
            fd: 9,
            family: 0,
            remote_port_be: 0,
            local_port_be: 0,
            remote_addr_v4: 0,
            local_addr_v4: 0,
            remote_addr_v6: [0; 16],
            local_addr_v6: [0; 16],
            timestamp_unix_nanos: 0,
            request_len: request.len() as u32,
            request_iovec_lens: [0; RAW_HTTP_MAX_IOVECS],
            command: fixed_command("curl"),
            request: [0; RAW_HTTP_REQUEST_BYTES],
        };
        raw.request[..request.len()].copy_from_slice(request.as_bytes());

        let signal = raw_http_request_to_signal_with_clock_and_procfs(
            raw_as_bytes(&raw),
            Some("node-a".to_string()),
            1_000,
            std::path::Path::new("/proc"),
        )
        .expect("raw event decodes without socket peer metadata");

        let SignalPayload::ProtocolRequestObservation(event) = signal.payload else {
            panic!("expected protocol request observation");
        };
        assert_eq!(event.method.as_deref(), Some("GET"));
        let peer = event.peer.expect("host authority peer context");
        assert_eq!(peer.address, None);
        assert_eq!(peer.domain.as_deref(), Some("fallback.example.test"));
        assert_eq!(peer.port, Some(18083));
    }

    #[test]
    fn http_diagnostic_counter_snapshot_returns_stage_deltas() {
        let previous = HttpDiagnosticCounterSnapshot::from_counters([
            10, 5, 100, 30, 1, 0, 2, 7, 0, 20, 3, 20, 4, 3, 1,
        ]);
        let current = HttpDiagnosticCounterSnapshot::from_counters([
            12, 8, 100, 45, 1, 4, 2, 11, 0, 35, 3, 35, 10, 8, 2,
        ]);

        let delta = current.delta_since(&previous);

        assert_eq!(delta.get(0), 2);
        assert_eq!(delta.get(1), 3);
        assert_eq!(delta.get(2), 0);
        assert_eq!(delta.get(3), 15);
        assert_eq!(delta.get(5), 4);
        assert_eq!(delta.get(7), 4);
        assert_eq!(delta.get(9), 15);
        assert_eq!(delta.get(11), 15);
        assert_eq!(delta.get(12), 6);
        assert_eq!(delta.get(13), 5);
        assert_eq!(delta.get(14), 1);
        assert_eq!(
            delta.nonzero_stage_names(),
            vec![
                "connect_enter",
                "connect_active",
                "writev_enter",
                "sendmsg_enter",
                "active_connection_miss",
                "copy_success",
                "output_attempt",
                "fallback_candidate",
                "fallback_non_http_start",
                "fallback_output_attempt",
            ]
        );
    }

    #[test]
    fn http_diagnostic_counter_snapshot_ignores_empty_delta() {
        let snapshot =
            HttpDiagnosticCounterSnapshot::from_counters([0; HTTP_DIAGNOSTIC_COUNTERS_LEN]);

        assert!(snapshot.delta_since(&snapshot).is_empty());
    }

    fn fixed_command(value: &str) -> [u8; 16] {
        let mut command = [0_u8; 16];
        let bytes = value.as_bytes();
        let len = bytes.len().min(command.len().saturating_sub(1));
        command[..len].copy_from_slice(&bytes[..len]);
        command
    }

    fn raw_as_bytes(raw: &RawHttpRequestEvent) -> &[u8] {
        unsafe {
            core::slice::from_raw_parts(
                core::ptr::from_ref(raw).cast::<u8>(),
                core::mem::size_of::<RawHttpRequestEvent>(),
            )
        }
    }
}
