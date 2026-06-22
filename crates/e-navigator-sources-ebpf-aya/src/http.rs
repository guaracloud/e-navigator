#![allow(dead_code)]

#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
use e_navigator_protocol::{ProtocolExtractionConfig, http::parse_http_request};
#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
use e_navigator_signals::{
    NetworkProcessIdentity, ProtocolRequestObservation, SignalEnvelope, TraceConfidence,
    TraceCorrelationKind, TracePeerContext,
};

#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
pub(crate) const RAW_HTTP_REQUEST_BYTES: usize = 512;
#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
pub(crate) const RAW_HTTP_AF_INET: u32 = 2;
#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
pub(crate) const RAW_HTTP_AF_INET6: u32 = 10;
#[cfg(any(target_os = "linux", test))]
const PERF_BUFFER_PAGE_COUNT: usize = 64;
#[cfg(any(target_os = "linux", test))]
const PERF_READER_POLL_INTERVAL_MS: u64 = 25;

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
    pub command: [u8; 16],
    pub request: [u8; RAW_HTTP_REQUEST_BYTES],
}

#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
fn raw_http_request_to_signal_with_clock_and_procfs(
    bytes: &[u8],
    host: Option<String>,
    observed_unix_nanos: u64,
    procfs_root: &std::path::Path,
) -> Option<SignalEnvelope> {
    if bytes.len() < core::mem::size_of::<RawHttpRequestEvent>() {
        return None;
    }

    let raw = unsafe { core::ptr::read_unaligned(bytes.as_ptr().cast::<RawHttpRequestEvent>()) };
    let request_len = (raw.request_len as usize).min(RAW_HTTP_REQUEST_BYTES);
    let parsed = parse_http_request(
        &raw.request[..request_len],
        &ProtocolExtractionConfig::default(),
    )
    .ok()?;
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

    Some(SignalEnvelope::protocol_request_observation(
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
    let port = u16::from_be(raw.remote_port_be);
    if address.is_none() && port == 0 {
        return None;
    }

    Some(TracePeerContext {
        address,
        port: (port != 0).then_some(port),
        domain: attribute_value(attributes, "server.address").map(ToString::to_string),
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
        maps::perf::{PerfEvent, PerfEventArray},
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
                                    if let Some(signal) =
                                        super::raw_http_request_to_signal_with_clock_and_procfs(
                                            bytes.as_ref(),
                                            host.clone(),
                                            super::now_unix_nanos(),
                                            &procfs_root,
                                        )
                                    {
                                        telemetry.record_decoded_sample();
                                        let diagnostic_decision =
                                            log_signal_diagnostic(&diagnostics, &signal);
                                        telemetry.record_diagnostic_decision(diagnostic_decision);
                                        if cpu_tx.blocking_send(signal).is_err() {
                                            telemetry.record_send_failure();
                                            closed = true;
                                        } else {
                                            telemetry.record_sent_signal();
                                        }
                                    } else {
                                        telemetry.record_invalid_sample();
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
