#![allow(dead_code)]

#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
use e_navigator_signals::{
    DnsQueryEvent, DnsQueryType, DnsResponseCode, DnsResponseEvent, NetworkProcessIdentity,
    NetworkProtocol, SignalEnvelope,
};

#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
pub(crate) const RAW_DNS_PACKET_BYTES: usize = 512;
#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
pub(crate) const RAW_DNS_PROTOCOL_UDP: u32 = 17;
#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
pub(crate) const RAW_DNS_PROTOCOL_TCP: u32 = 6;
#[cfg(any(target_os = "linux", test))]
const PERF_BUFFER_PAGE_COUNT: usize = 64;
#[cfg(any(target_os = "linux", test))]
const PERF_READER_POLL_INTERVAL_MS: u64 = 25;

#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct RawDnsEvent {
    pub pid: u32,
    pub uid: u32,
    pub cgroup_id: u64,
    pub protocol: u32,
    pub server_port_be: u16,
    pub server_addr_v4: u32,
    pub timestamp_unix_nanos: u64,
    pub latency_nanos: u64,
    pub packet_len: u32,
    pub command: [u8; 16],
    pub packet: [u8; RAW_DNS_PACKET_BYTES],
}

#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedDnsPacket {
    query_name: String,
    query_type: DnsQueryType,
    is_response: bool,
    response_code: Option<DnsResponseCode>,
}

#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
fn parse_dns_packet(packet: &[u8]) -> Option<ParsedDnsPacket> {
    if packet.len() < 12 || packet.len() > RAW_DNS_PACKET_BYTES {
        return None;
    }
    let flags = u16::from_be_bytes([packet[2], packet[3]]);
    let qdcount = u16::from_be_bytes([packet[4], packet[5]]);
    if qdcount == 0 {
        return None;
    }
    let (query_name, next) = parse_dns_name(packet, 12)?;
    if packet.len().saturating_sub(next) < 4 {
        return None;
    }
    let query_type = u16::from_be_bytes([packet[next], packet[next + 1]]);
    let is_response = flags & 0x8000 != 0;
    Some(ParsedDnsPacket {
        query_name,
        query_type: map_query_type(query_type),
        is_response,
        response_code: is_response.then(|| map_response_code((flags & 0x000f) as u8)),
    })
}

#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
fn raw_dns_to_signal(bytes: &[u8], host: Option<String>) -> Option<SignalEnvelope> {
    raw_dns_to_signal_with_clock_and_procfs(
        bytes,
        host,
        now_unix_nanos(),
        std::path::Path::new("/proc"),
    )
}

#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
fn raw_dns_to_signal_with_clock_and_procfs(
    bytes: &[u8],
    host: Option<String>,
    observed_unix_nanos: u64,
    procfs_root: &std::path::Path,
) -> Option<SignalEnvelope> {
    if bytes.len() < core::mem::size_of::<RawDnsEvent>() {
        return None;
    }
    let raw = unsafe { core::ptr::read_unaligned(bytes.as_ptr().cast::<RawDnsEvent>()) };
    let packet_len = (raw.packet_len as usize).min(RAW_DNS_PACKET_BYTES);
    let parsed = parse_dns_packet(&raw.packet[..packet_len])?;
    let process = NetworkProcessIdentity {
        pid: raw.pid,
        ppid: None,
        uid: Some(raw.uid),
        command: bytes_to_string(&raw.command),
        executable: None,
        cgroup_id: (raw.cgroup_id != 0).then_some(raw.cgroup_id),
    };
    let transport_protocol = match raw.protocol {
        RAW_DNS_PROTOCOL_UDP => NetworkProtocol::Udp,
        RAW_DNS_PROTOCOL_TCP => NetworkProtocol::Tcp,
        _ => return None,
    };
    let server_address = (raw.server_addr_v4 != 0).then(|| ipv4_to_string(raw.server_addr_v4));
    let server_port = {
        let port = u16::from_be(raw.server_port_be);
        (port != 0).then_some(port)
    };
    let container = crate::procfs::container_from_pid_cgroup(procfs_root, raw.pid);
    if parsed.is_response {
        Some(SignalEnvelope::dns_response(
            "source.aya_dns",
            host,
            DnsResponseEvent {
                process,
                query_name: parsed.query_name,
                query_type: parsed.query_type,
                response_code: parsed.response_code.unwrap_or(DnsResponseCode::Other),
                latency_nanos: (raw.latency_nanos != 0).then_some(raw.latency_nanos),
                transport_protocol,
                server_address,
                server_port,
                timestamp_unix_nanos: observed_unix_nanos,
                container,
                kubernetes: None,
            },
        ))
    } else {
        Some(SignalEnvelope::dns_query(
            "source.aya_dns",
            host,
            DnsQueryEvent {
                process,
                query_name: parsed.query_name,
                query_type: parsed.query_type,
                transport_protocol,
                server_address,
                server_port,
                timestamp_unix_nanos: observed_unix_nanos,
                container,
                kubernetes: None,
            },
        ))
    }
}

#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn now_unix_nanos() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(0)
}

#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
fn parse_dns_name(packet: &[u8], mut offset: usize) -> Option<(String, usize)> {
    let mut labels = Vec::new();
    let mut total_len = 0_usize;
    loop {
        let len = *packet.get(offset)? as usize;
        offset = offset.checked_add(1)?;
        if len == 0 {
            break;
        }
        if len & 0xc0 != 0 || len > 63 {
            return None;
        }
        let end = offset.checked_add(len)?;
        let label = packet.get(offset..end)?;
        if label.is_empty()
            || !label
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
        {
            return None;
        }
        total_len = total_len
            .saturating_add(len)
            .saturating_add(usize::from(!labels.is_empty()));
        if total_len > 253 {
            return None;
        }
        labels.push(String::from_utf8_lossy(label).to_ascii_lowercase());
        offset = end;
    }
    (!labels.is_empty()).then(|| (labels.join("."), offset))
}

#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
fn map_query_type(value: u16) -> DnsQueryType {
    match value {
        1 => DnsQueryType::A,
        28 => DnsQueryType::Aaaa,
        5 => DnsQueryType::Cname,
        _ => DnsQueryType::Other,
    }
}

#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
fn map_response_code(value: u8) -> DnsResponseCode {
    match value {
        0 => DnsResponseCode::NoError,
        2 => DnsResponseCode::ServFail,
        3 => DnsResponseCode::NxDomain,
        5 => DnsResponseCode::Refused,
        _ => DnsResponseCode::Other,
    }
}

#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
fn ipv4_to_string(value: u32) -> String {
    let octets = value.to_ne_bytes();
    format!("{}.{}.{}.{}", octets[0], octets[1], octets[2], octets[3])
}

#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
fn bytes_to_string(bytes: &[u8]) -> String {
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).to_string()
}

#[cfg(target_os = "linux")]
mod platform {
    use crate::diagnostics::SourceDiagnostics;
    use crate::perf_sample::perf_sample_bytes;
    use crate::source_telemetry::SourceTelemetry;
    use async_trait::async_trait;
    use aya::{
        Ebpf, include_bytes_aligned,
        maps::perf::{PerfEvent, PerfEventArray},
        programs::TracePoint,
        util::online_cpus,
    };
    use e_navigator_core::{CoreError, CoreResult, ModuleKind, ModuleMetadata, Signal, Source};
    use e_navigator_signals::SignalEnvelope;
    use std::{
        path::PathBuf,
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
    };
    use tokio::sync::mpsc;
    use tokio::task::JoinHandle;
    use tracing::{debug, info, warn};

    #[derive(Debug, Default)]
    pub struct AyaDnsSource {
        host: Option<String>,
        procfs_root: PathBuf,
    }

    impl AyaDnsSource {
        pub fn new(host: Option<String>, procfs_root: PathBuf) -> Self {
            Self { host, procfs_root }
        }
    }

    #[async_trait]
    impl Source<SignalEnvelope> for AyaDnsSource {
        fn metadata(&self) -> ModuleMetadata {
            ModuleMetadata::new("source.aya_dns", ModuleKind::Source)
        }

        async fn run(self: Box<Self>, tx: mpsc::Sender<SignalEnvelope>) -> CoreResult<()> {
            bump_memlock_rlimit();
            let shutdown = ReaderShutdown::new();
            let mut reader_handles = Vec::new();
            let diagnostics = SourceDiagnostics::from_env();
            let telemetry = Arc::new(SourceTelemetry::new("source.aya_dns"));
            let mut ebpf = Ebpf::load(include_bytes_aligned!(concat!(
                env!("OUT_DIR"),
                "/e-navigator-ebpf-programs"
            )))
            .map_err(module_error)?;

            attach_tracepoint(
                &mut ebpf,
                "tracepoint_sendto_enter",
                "syscalls",
                "sys_enter_sendto",
            )?;
            attach_tracepoint(
                &mut ebpf,
                "tracepoint_recvfrom_enter",
                "syscalls",
                "sys_enter_recvfrom",
            )?;
            attach_tracepoint(
                &mut ebpf,
                "tracepoint_recvfrom_exit",
                "syscalls",
                "sys_exit_recvfrom",
            )?;
            attach_tracepoint(
                &mut ebpf,
                "tracepoint_sendmsg_enter",
                "syscalls",
                "sys_enter_sendmsg",
            )?;
            attach_tracepoint(
                &mut ebpf,
                "tracepoint_recvmsg_enter",
                "syscalls",
                "sys_enter_recvmsg",
            )?;
            attach_tracepoint(
                &mut ebpf,
                "tracepoint_recvmsg_exit",
                "syscalls",
                "sys_exit_recvmsg",
            )?;
            attach_tracepoint(
                &mut ebpf,
                "tracepoint_write_enter",
                "syscalls",
                "sys_enter_write",
            )?;
            attach_tracepoint(
                &mut ebpf,
                "tracepoint_write_exit",
                "syscalls",
                "sys_exit_write",
            )?;
            attach_tracepoint(
                &mut ebpf,
                "tracepoint_read_enter",
                "syscalls",
                "sys_enter_read",
            )?;
            attach_tracepoint(
                &mut ebpf,
                "tracepoint_read_exit",
                "syscalls",
                "sys_exit_read",
            )?;

            let mut perf_array =
                PerfEventArray::try_from(ebpf.take_map("DNS_EVENTS").ok_or_else(|| {
                    CoreError::ModuleFailed {
                        module: "source.aya_dns".to_string(),
                        message: "missing DNS_EVENTS map".to_string(),
                    }
                })?)
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
                                        super::raw_dns_to_signal_with_clock_and_procfs(
                                            bytes.as_ref(),
                                            host.clone(),
                                            super::now_unix_nanos(),
                                            &procfs_root,
                                        )
                                    {
                                        telemetry.record_decoded_sample();
                                        if diagnostics.enabled()
                                            && diagnostics.sample_decision_for(&[signal.kind()])
                                                == crate::diagnostics::DiagnosticSampleDecision::Matched
                                        {
                                            info!(
                                                target: "e_navigator_sources_ebpf_aya::source_diagnostics",
                                                source = "source.aya_dns",
                                                raw_event = signal.kind(),
                                                "source diagnostic raw event decoded"
                                            );
                                        }
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
                                    warn!(count, "lost dns perf events");
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
                    source = "source.aya_dns",
                    remaining_samples = diagnostics.remaining_samples(),
                    filtered_preview_remaining_samples =
                        diagnostics.remaining_filtered_preview_samples(),
                    "source diagnostics enabled"
                );
            }
            debug!("aya dns source attached");
            tokio::signal::ctrl_c().await.map_err(module_error)?;
            shutdown.stop();
            join_reader_handles(reader_handles).await
        }
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
                module: "source.aya_dns".to_string(),
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
            module: "source.aya_dns".to_string(),
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
    pub struct AyaDnsSource {
        host: Option<String>,
        _procfs_root: std::path::PathBuf,
    }

    impl AyaDnsSource {
        pub fn new(host: Option<String>, procfs_root: std::path::PathBuf) -> Self {
            Self {
                host,
                _procfs_root: procfs_root,
            }
        }
    }

    #[async_trait]
    impl Source<SignalEnvelope> for AyaDnsSource {
        fn metadata(&self) -> ModuleMetadata {
            ModuleMetadata::new("source.aya_dns", ModuleKind::Source)
        }

        async fn run(self: Box<Self>, _tx: mpsc::Sender<SignalEnvelope>) -> CoreResult<()> {
            Err(CoreError::ModuleFailed {
                module: "source.aya_dns".to_string(),
                message: format!(
                    "Aya DNS source requires Linux and eBPF support; host={}",
                    self.host.as_deref().unwrap_or("unknown")
                ),
            })
        }
    }
}

pub use platform::AyaDnsSource;

#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
mod tests {
    use super::*;

    #[test]
    fn parses_valid_dns_query_packet() {
        let packet = dns_query_packet(0x1234, "api.example.com", 1);

        let parsed = parse_dns_packet(&packet).expect("query parses");

        assert_eq!(parsed.query_name, "api.example.com");
        assert_eq!(parsed.query_type, DnsQueryType::A);
        assert!(!parsed.is_response);
        assert_eq!(parsed.response_code, None);
    }

    #[test]
    fn parses_valid_dns_response_packet() {
        let mut packet = dns_query_packet(0x1234, "api.example.com", 28);
        packet[2] = 0x81;
        packet[3] = 0x83;

        let parsed = parse_dns_packet(&packet).expect("response parses");

        assert_eq!(parsed.query_name, "api.example.com");
        assert_eq!(parsed.query_type, DnsQueryType::Aaaa);
        assert!(parsed.is_response);
        assert_eq!(parsed.response_code, Some(DnsResponseCode::NxDomain));
    }

    #[test]
    fn malformed_dns_packets_are_rejected_without_panic() {
        assert!(parse_dns_packet(&[]).is_none());
        assert!(parse_dns_packet(&[0; 11]).is_none());

        let mut truncated_name = dns_query_packet(0x1234, "api.example.com", 1);
        truncated_name.truncate(16);
        assert!(parse_dns_packet(&truncated_name).is_none());
    }

    #[test]
    fn dns_name_bounds_are_enforced() {
        let mut bad_label = vec![0_u8; 12];
        bad_label.extend_from_slice(&[64]);
        bad_label.extend(std::iter::repeat_n(b'a', 64));
        bad_label.extend_from_slice(&[0, 0, 1, 0, 1]);
        assert!(parse_dns_packet(&bad_label).is_none());

        let long_name = (0..128).map(|_| "a").collect::<Vec<_>>().join(".");
        let packet = dns_query_packet(0x1234, &long_name, 1);
        assert!(parse_dns_packet(&packet).is_none());
    }

    #[test]
    fn raw_dns_event_decodes_to_existing_signal_envelopes() {
        let packet = dns_query_packet(0x1234, "api.example.com", 5);
        let mut raw = RawDnsEvent {
            pid: 42,
            uid: 1000,
            cgroup_id: 7,
            protocol: RAW_DNS_PROTOCOL_UDP,
            server_port_be: 53_u16.to_be(),
            server_addr_v4: u32::from_ne_bytes([10, 96, 0, 10]),
            timestamp_unix_nanos: 1_000,
            latency_nanos: 0,
            packet_len: packet.len() as u32,
            command: fixed_command("api"),
            packet: [0; RAW_DNS_PACKET_BYTES],
        };
        raw.packet[..packet.len()].copy_from_slice(&packet);

        let signal = raw_dns_to_signal(raw_as_bytes(&raw), Some("node-a".to_string()))
            .expect("raw event decodes");

        assert_eq!(signal.source, "source.aya_dns");
        let e_navigator_signals::SignalPayload::DnsQuery(event) = signal.payload else {
            panic!("expected dns query payload");
        };
        assert_eq!(event.query_name, "api.example.com");
        assert_eq!(event.query_type, DnsQueryType::Cname);
        assert_eq!(event.process.pid, 42);
        assert_eq!(event.process.cgroup_id, Some(7));
        assert_eq!(event.server_address.as_deref(), Some("10.96.0.10"));
        assert_eq!(event.server_port, Some(53));
    }

    #[test]
    fn raw_dns_event_preserves_source_time_container_attribution() {
        const CONTAINER_ID: &str =
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

        let temp = test_temp_dir("dns-source-time-cgroup");
        let cgroup = temp.join("42/cgroup");
        std::fs::create_dir_all(cgroup.parent().expect("parent")).expect("mkdir");
        std::fs::write(
            &cgroup,
            format!("0::/kubepods.slice/cri-containerd-{CONTAINER_ID}.scope\n"),
        )
        .expect("write cgroup");

        let packet = dns_query_packet(0x1234, "api.example.com", 1);
        let mut raw = RawDnsEvent {
            pid: 42,
            uid: 1000,
            cgroup_id: 7,
            protocol: RAW_DNS_PROTOCOL_UDP,
            server_port_be: 53_u16.to_be(),
            server_addr_v4: u32::from_ne_bytes([10, 96, 0, 10]),
            timestamp_unix_nanos: 1_000,
            latency_nanos: 0,
            packet_len: packet.len() as u32,
            command: fixed_command("api"),
            packet: [0; RAW_DNS_PACKET_BYTES],
        };
        raw.packet[..packet.len()].copy_from_slice(&packet);

        let signal = raw_dns_to_signal_with_clock_and_procfs(
            raw_as_bytes(&raw),
            Some("node-a".to_string()),
            1_000,
            &temp,
        )
        .expect("raw event decodes");

        let e_navigator_signals::SignalPayload::DnsQuery(event) = signal.payload else {
            panic!("expected dns query payload");
        };
        let container = event.container.expect("container attribution");
        assert_eq!(container.container_id, CONTAINER_ID);
        assert_eq!(container.runtime.as_deref(), Some("containerd"));

        let _ = std::fs::remove_dir_all(temp);
    }

    fn dns_query_packet(id: u16, name: &str, query_type: u16) -> Vec<u8> {
        let mut packet = vec![
            (id >> 8) as u8,
            id as u8,
            0x01,
            0x00,
            0x00,
            0x01,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
        ];
        for label in name.split('.') {
            packet.push(label.len() as u8);
            packet.extend_from_slice(label.as_bytes());
        }
        packet.push(0);
        packet.extend_from_slice(&query_type.to_be_bytes());
        packet.extend_from_slice(&1_u16.to_be_bytes());
        packet
    }

    fn fixed_command(value: &str) -> [u8; 16] {
        let mut command = [0_u8; 16];
        let bytes = value.as_bytes();
        let len = bytes.len().min(command.len().saturating_sub(1));
        command[..len].copy_from_slice(&bytes[..len]);
        command
    }

    fn raw_as_bytes(raw: &RawDnsEvent) -> &[u8] {
        unsafe {
            core::slice::from_raw_parts(
                core::ptr::from_ref(raw).cast::<u8>(),
                core::mem::size_of::<RawDnsEvent>(),
            )
        }
    }

    fn test_temp_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("e-navigator-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }
}
