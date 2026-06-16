#[cfg(any(target_os = "linux", test))]
use e_navigator_signals::{
    NetworkAddressFamily, NetworkConnectionCloseEvent, NetworkConnectionFailureEvent,
    NetworkConnectionOpenEvent, NetworkProcessIdentity, NetworkProtocol, SignalEnvelope,
};

#[cfg(any(target_os = "linux", test))]
pub(crate) const RAW_NETWORK_EVENT_OPEN: u32 = 1;
#[cfg(any(target_os = "linux", test))]
pub(crate) const RAW_NETWORK_EVENT_CLOSE: u32 = 2;
#[cfg(any(target_os = "linux", test))]
pub(crate) const RAW_NETWORK_EVENT_FAILURE: u32 = 3;
#[cfg(any(target_os = "linux", test))]
pub(crate) const RAW_AF_INET: u32 = 2;
#[cfg(any(target_os = "linux", test))]
pub(crate) const RAW_AF_INET6: u32 = 10;
#[cfg(any(target_os = "linux", test))]
pub(crate) const RAW_PROTO_TCP: u32 = 6;

#[cfg(any(target_os = "linux", test))]
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct RawNetworkEvent {
    pub event_type: u32,
    pub pid: u32,
    pub uid: u32,
    pub fd: i32,
    pub errno: i32,
    pub family: u32,
    pub protocol: u32,
    pub remote_port_be: u16,
    pub local_port_be: u16,
    pub remote_addr_v4: u32,
    pub local_addr_v4: u32,
    pub remote_addr_v6: [u8; 16],
    pub local_addr_v6: [u8; 16],
    pub timestamp_unix_nanos: u64,
    pub duration_nanos: u64,
    pub command: [u8; 16],
}

#[cfg(any(target_os = "linux", test))]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn raw_network_to_signal(bytes: &[u8], host: Option<String>) -> Option<SignalEnvelope> {
    raw_network_to_signal_with_clock(bytes, host, now_unix_nanos())
}

#[cfg(any(target_os = "linux", test))]
fn raw_network_to_signal_with_clock(
    bytes: &[u8],
    host: Option<String>,
    observed_unix_nanos: u64,
) -> Option<SignalEnvelope> {
    if bytes.len() < core::mem::size_of::<RawNetworkEvent>() {
        return None;
    }

    let raw = unsafe { core::ptr::read_unaligned(bytes.as_ptr().cast::<RawNetworkEvent>()) };
    let process = NetworkProcessIdentity {
        pid: raw.pid,
        ppid: None,
        uid: Some(raw.uid),
        command: bytes_to_string(&raw.command),
        executable: None,
    };
    let protocol = protocol(raw.protocol)?;
    let address_family = address_family(raw.family)?;
    let remote_address = remote_address(&raw, address_family);
    let local_address = local_address(&raw, address_family);
    let remote_port = u16::from_be(raw.remote_port_be);
    let local_port = u16::from_be(raw.local_port_be);
    let fd = (raw.fd >= 0).then_some(raw.fd);

    match raw.event_type {
        RAW_NETWORK_EVENT_OPEN => Some(SignalEnvelope::network_connection_open(
            "source.aya_network",
            host,
            NetworkConnectionOpenEvent {
                process,
                protocol,
                address_family,
                local_address,
                local_port: (local_port != 0).then_some(local_port),
                remote_address,
                remote_port,
                fd,
                timestamp_unix_nanos: observed_unix_nanos,
                container: None,
                kubernetes: None,
            },
        )),
        RAW_NETWORK_EVENT_CLOSE => Some(SignalEnvelope::network_connection_close(
            "source.aya_network",
            host,
            NetworkConnectionCloseEvent {
                process,
                protocol,
                address_family,
                local_address,
                local_port: (local_port != 0).then_some(local_port),
                remote_address,
                remote_port,
                fd,
                opened_at_unix_nanos: observed_unix_nanos
                    .checked_sub(raw.duration_nanos)
                    .filter(|_| raw.duration_nanos != 0),
                closed_at_unix_nanos: observed_unix_nanos,
                duration_nanos: (raw.duration_nanos != 0).then_some(raw.duration_nanos),
                container: None,
                kubernetes: None,
            },
        )),
        RAW_NETWORK_EVENT_FAILURE => Some(SignalEnvelope::network_connection_failure(
            "source.aya_network",
            host,
            NetworkConnectionFailureEvent {
                process,
                protocol,
                address_family,
                remote_address,
                remote_port,
                fd,
                errno: raw.errno,
                timestamp_unix_nanos: observed_unix_nanos,
                container: None,
                kubernetes: None,
            },
        )),
        _ => None,
    }
}

#[cfg(any(target_os = "linux", test))]
fn protocol(value: u32) -> Option<NetworkProtocol> {
    match value {
        RAW_PROTO_TCP => Some(NetworkProtocol::Tcp),
        _ => None,
    }
}

#[cfg(any(target_os = "linux", test))]
fn address_family(value: u32) -> Option<NetworkAddressFamily> {
    match value {
        RAW_AF_INET => Some(NetworkAddressFamily::Ipv4),
        RAW_AF_INET6 => Some(NetworkAddressFamily::Ipv6),
        _ => None,
    }
}

#[cfg(any(target_os = "linux", test))]
fn remote_address(raw: &RawNetworkEvent, family: NetworkAddressFamily) -> String {
    match family {
        NetworkAddressFamily::Ipv4 => ipv4_to_string(raw.remote_addr_v4),
        NetworkAddressFamily::Ipv6 => ipv6_to_string(raw.remote_addr_v6),
        _ => String::new(),
    }
}

#[cfg(any(target_os = "linux", test))]
fn local_address(raw: &RawNetworkEvent, family: NetworkAddressFamily) -> Option<String> {
    match family {
        NetworkAddressFamily::Ipv4 if raw.local_addr_v4 != 0 => {
            Some(ipv4_to_string(raw.local_addr_v4))
        }
        NetworkAddressFamily::Ipv6 if raw.local_addr_v6.iter().any(|byte| *byte != 0) => {
            Some(ipv6_to_string(raw.local_addr_v6))
        }
        _ => None,
    }
}

#[cfg(any(target_os = "linux", test))]
fn ipv4_to_string(value: u32) -> String {
    let octets = value.to_ne_bytes();
    format!("{}.{}.{}.{}", octets[0], octets[1], octets[2], octets[3])
}

#[cfg(any(target_os = "linux", test))]
fn ipv6_to_string(value: [u8; 16]) -> String {
    std::net::Ipv6Addr::from(value).to_string()
}

#[cfg(any(target_os = "linux", test))]
fn bytes_to_string(bytes: &[u8]) -> String {
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).to_string()
}

#[cfg(any(target_os = "linux", test))]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn now_unix_nanos() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(0)
}

#[cfg(target_os = "linux")]
mod platform {
    use async_trait::async_trait;
    use aya::{
        Ebpf, include_bytes_aligned,
        maps::perf::{PerfEvent, PerfEventArray},
        programs::TracePoint,
        util::online_cpus,
    };
    use e_navigator_core::{CoreError, CoreResult, ModuleKind, ModuleMetadata, Source};
    use e_navigator_signals::SignalEnvelope;
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
    use tokio::{sync::mpsc, task::JoinHandle};
    use tracing::{debug, warn};

    #[derive(Debug, Default)]
    pub struct AyaNetworkSource {
        host: Option<String>,
    }

    impl AyaNetworkSource {
        pub fn new(host: Option<String>) -> Self {
            Self { host }
        }
    }

    #[async_trait]
    impl Source<SignalEnvelope> for AyaNetworkSource {
        fn metadata(&self) -> ModuleMetadata {
            ModuleMetadata::new("source.aya_network", ModuleKind::Source)
        }

        async fn run(self: Box<Self>, tx: mpsc::Sender<SignalEnvelope>) -> CoreResult<()> {
            bump_memlock_rlimit();
            let shutdown = ReaderShutdown::new();
            let mut reader_handles = Vec::new();
            let mut ebpf = Ebpf::load(include_bytes_aligned!(concat!(
                env!("OUT_DIR"),
                "/e-navigator-ebpf-programs"
            )))
            .map_err(module_error)?;

            attach_tracepoint(
                &mut ebpf,
                "tracepoint_connect_enter",
                "syscalls",
                "sys_enter_connect",
            )?;
            attach_tracepoint(
                &mut ebpf,
                "tracepoint_connect_exit",
                "syscalls",
                "sys_exit_connect",
            )?;
            attach_tracepoint(
                &mut ebpf,
                "tracepoint_close_enter",
                "syscalls",
                "sys_enter_close",
            )?;

            let mut perf_array =
                PerfEventArray::try_from(ebpf.take_map("NETWORK_EVENTS").ok_or_else(|| {
                    CoreError::ModuleFailed {
                        module: "source.aya_network".to_string(),
                        message: "missing NETWORK_EVENTS map".to_string(),
                    }
                })?)
                .map_err(module_error)?;

            let cpus = online_cpus().map_err(|(_, err)| module_error(err))?;
            for cpu_id in cpus {
                let mut buffer = perf_array.open(cpu_id, None).map_err(module_error)?;
                let cpu_tx = tx.clone();
                let host = self.host.clone();
                let reader_shutdown = shutdown.clone();

                reader_handles.push(tokio::task::spawn_blocking(move || {
                    let mut closed = false;

                    while !reader_shutdown.is_stopped() {
                        buffer.for_each(|event| {
                            if closed {
                                return;
                            }

                            match event {
                                PerfEvent::Sample { head, tail } => {
                                    if !tail.is_empty() {
                                        warn!("dropped wrapped network perf event sample");
                                        return;
                                    }

                                    if let Some(signal) =
                                        super::raw_network_to_signal(head, host.clone())
                                    {
                                        if cpu_tx.blocking_send(signal).is_err() {
                                            closed = true;
                                        }
                                    }
                                }
                                PerfEvent::Lost { count } => {
                                    warn!(count, "lost network perf events");
                                }
                            }
                        });

                        if closed {
                            return;
                        }

                        std::thread::sleep(std::time::Duration::from_millis(100));
                    }
                }));
            }

            debug!("aya network source attached");
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
                module: "source.aya_network".to_string(),
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
            module: "source.aya_network".to_string(),
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
    pub struct AyaNetworkSource {
        host: Option<String>,
    }

    impl AyaNetworkSource {
        pub fn new(host: Option<String>) -> Self {
            Self { host }
        }
    }

    #[async_trait]
    impl Source<SignalEnvelope> for AyaNetworkSource {
        fn metadata(&self) -> ModuleMetadata {
            ModuleMetadata::new("source.aya_network", ModuleKind::Source)
        }

        async fn run(self: Box<Self>, _tx: mpsc::Sender<SignalEnvelope>) -> CoreResult<()> {
            Err(CoreError::ModuleFailed {
                module: "source.aya_network".to_string(),
                message: format!(
                    "Aya network source requires Linux and eBPF support; host={}",
                    self.host.as_deref().unwrap_or("unknown")
                ),
            })
        }
    }
}

pub use platform::AyaNetworkSource;

#[cfg(test)]
mod tests {
    use super::*;
    use e_navigator_core::Signal;
    use e_navigator_signals::{NetworkAddressFamily, NetworkProtocol, SignalPayload};

    #[test]
    fn decodes_raw_tcp_connect_to_open_signal() {
        let raw = RawNetworkEvent {
            event_type: RAW_NETWORK_EVENT_OPEN,
            pid: 42,
            uid: 1000,
            fd: 7,
            errno: 0,
            family: RAW_AF_INET,
            protocol: RAW_PROTO_TCP,
            remote_port_be: 443_u16.to_be(),
            local_port_be: 43512_u16.to_be(),
            remote_addr_v4: u32::from_ne_bytes([203, 0, 113, 10]),
            local_addr_v4: u32::from_ne_bytes([10, 0, 0, 5]),
            remote_addr_v6: [0; 16],
            local_addr_v6: [0; 16],
            timestamp_unix_nanos: 1_000,
            duration_nanos: 0,
            command: fixed_command("api"),
        };

        let signal =
            raw_network_to_signal_with_clock(raw_as_bytes(&raw), Some("node-a".to_string()), 1_000)
                .expect("raw event decodes");

        assert_eq!(signal.kind(), "network_connection_open");
        let SignalPayload::NetworkConnectionOpen(event) = signal.payload else {
            panic!("expected network open payload");
        };
        assert_eq!(event.process.pid, 42);
        assert_eq!(event.process.uid, Some(1000));
        assert_eq!(event.process.command, "api");
        assert_eq!(event.protocol, NetworkProtocol::Tcp);
        assert_eq!(event.address_family, NetworkAddressFamily::Ipv4);
        assert_eq!(event.remote_address, "203.0.113.10");
        assert_eq!(event.remote_port, 443);
        assert_eq!(event.local_address.as_deref(), Some("10.0.0.5"));
        assert_eq!(event.local_port, Some(43512));
        assert_eq!(event.fd, Some(7));
        assert_eq!(event.timestamp_unix_nanos, 1_000);
    }

    #[test]
    fn decodes_linux_little_endian_ipv4_bytes_in_network_order() {
        let raw = RawNetworkEvent {
            event_type: RAW_NETWORK_EVENT_OPEN,
            pid: 42,
            uid: 1000,
            fd: 7,
            errno: 0,
            family: RAW_AF_INET,
            protocol: RAW_PROTO_TCP,
            remote_port_be: 443_u16.to_be(),
            local_port_be: 43512_u16.to_be(),
            remote_addr_v4: u32::from_ne_bytes([203, 0, 113, 10]),
            local_addr_v4: u32::from_ne_bytes([10, 0, 0, 5]),
            remote_addr_v6: [0; 16],
            local_addr_v6: [0; 16],
            timestamp_unix_nanos: 1_000,
            duration_nanos: 0,
            command: fixed_command("api"),
        };

        let signal =
            raw_network_to_signal_with_clock(raw_as_bytes(&raw), Some("node-a".to_string()), 2_000)
                .expect("raw event decodes");

        let SignalPayload::NetworkConnectionOpen(event) = signal.payload else {
            panic!("expected network open payload");
        };
        assert_eq!(event.remote_address, "203.0.113.10");
        assert_eq!(event.local_address.as_deref(), Some("10.0.0.5"));
    }

    #[test]
    fn converts_raw_monotonic_time_to_unix_time_during_decode() {
        let raw = RawNetworkEvent {
            event_type: RAW_NETWORK_EVENT_CLOSE,
            pid: 42,
            uid: 1000,
            fd: 7,
            errno: 0,
            family: RAW_AF_INET,
            protocol: RAW_PROTO_TCP,
            remote_port_be: 443_u16.to_be(),
            local_port_be: 43512_u16.to_be(),
            remote_addr_v4: u32::from_ne_bytes([203, 0, 113, 10]),
            local_addr_v4: u32::from_ne_bytes([10, 0, 0, 5]),
            remote_addr_v6: [0; 16],
            local_addr_v6: [0; 16],
            timestamp_unix_nanos: 1_000,
            duration_nanos: 200,
            command: fixed_command("api"),
        };

        let signal = raw_network_to_signal_with_clock(
            raw_as_bytes(&raw),
            Some("node-a".to_string()),
            10_000,
        )
        .expect("raw event decodes");

        let SignalPayload::NetworkConnectionClose(event) = signal.payload else {
            panic!("expected network close payload");
        };
        assert_eq!(event.closed_at_unix_nanos, 10_000);
        assert_eq!(event.opened_at_unix_nanos, Some(9_800));
        assert_eq!(event.duration_nanos, Some(200));
    }

    #[test]
    fn decodes_raw_failed_connect_to_failure_signal() {
        let raw = RawNetworkEvent {
            event_type: RAW_NETWORK_EVENT_FAILURE,
            pid: 42,
            uid: 1000,
            fd: 7,
            errno: 111,
            family: RAW_AF_INET,
            protocol: RAW_PROTO_TCP,
            remote_port_be: 5432_u16.to_be(),
            local_port_be: 0,
            remote_addr_v4: u32::from_ne_bytes([10, 0, 0, 20]),
            local_addr_v4: 0,
            remote_addr_v6: [0; 16],
            local_addr_v6: [0; 16],
            timestamp_unix_nanos: 2_000,
            duration_nanos: 0,
            command: fixed_command("worker"),
        };

        let signal =
            raw_network_to_signal_with_clock(raw_as_bytes(&raw), Some("node-a".to_string()), 2_000)
                .expect("raw event decodes");

        assert_eq!(signal.kind(), "network_connection_failure");
        let SignalPayload::NetworkConnectionFailure(event) = signal.payload else {
            panic!("expected network failure payload");
        };
        assert_eq!(event.remote_address, "10.0.0.20");
        assert_eq!(event.remote_port, 5432);
        assert_eq!(event.errno, 111);
        assert_eq!(event.timestamp_unix_nanos, 2_000);
    }

    #[test]
    fn decodes_raw_close_to_duration_signal() {
        let raw = RawNetworkEvent {
            event_type: RAW_NETWORK_EVENT_CLOSE,
            pid: 42,
            uid: 1000,
            fd: 7,
            errno: 0,
            family: RAW_AF_INET,
            protocol: RAW_PROTO_TCP,
            remote_port_be: 5432_u16.to_be(),
            local_port_be: 43512_u16.to_be(),
            remote_addr_v4: u32::from_ne_bytes([10, 0, 0, 20]),
            local_addr_v4: u32::from_ne_bytes([10, 0, 0, 5]),
            remote_addr_v6: [0; 16],
            local_addr_v6: [0; 16],
            timestamp_unix_nanos: 3_000,
            duration_nanos: 2_000,
            command: fixed_command("api"),
        };

        let signal =
            raw_network_to_signal_with_clock(raw_as_bytes(&raw), Some("node-a".to_string()), 3_000)
                .expect("raw event decodes");

        assert_eq!(signal.kind(), "network_connection_close");
        let SignalPayload::NetworkConnectionClose(event) = signal.payload else {
            panic!("expected network close payload");
        };
        assert_eq!(event.remote_address, "10.0.0.20");
        assert_eq!(event.duration_nanos, Some(2_000));
        assert_eq!(event.closed_at_unix_nanos, 3_000);
        assert_eq!(event.opened_at_unix_nanos, Some(1_000));
    }

    #[test]
    fn rejects_short_unknown_family_and_protocol_raw_network_events() {
        assert!(raw_network_to_signal_with_clock(&[0, 1, 2], None, 1_000).is_none());

        let mut raw = RawNetworkEvent {
            event_type: RAW_NETWORK_EVENT_OPEN,
            pid: 42,
            uid: 1000,
            fd: 7,
            errno: 0,
            family: RAW_AF_INET,
            protocol: RAW_PROTO_TCP,
            remote_port_be: 443_u16.to_be(),
            local_port_be: 43512_u16.to_be(),
            remote_addr_v4: u32::from_ne_bytes([203, 0, 113, 10]),
            local_addr_v4: u32::from_ne_bytes([10, 0, 0, 5]),
            remote_addr_v6: [0; 16],
            local_addr_v6: [0; 16],
            timestamp_unix_nanos: 1_000,
            duration_nanos: 0,
            command: fixed_command("api"),
        };

        raw.event_type = 99;
        assert!(raw_network_to_signal_with_clock(raw_as_bytes(&raw), None, 1_000).is_none());
        raw.event_type = RAW_NETWORK_EVENT_OPEN;
        raw.family = 99;
        assert!(raw_network_to_signal_with_clock(raw_as_bytes(&raw), None, 1_000).is_none());
        raw.family = RAW_AF_INET;
        raw.protocol = 17;
        assert!(raw_network_to_signal_with_clock(raw_as_bytes(&raw), None, 1_000).is_none());
    }

    #[test]
    fn raw_network_event_layout_size_matches_ebpf_abi() {
        assert_eq!(std::mem::size_of::<RawNetworkEvent>(), 104);
    }

    fn fixed_command(value: &str) -> [u8; 16] {
        let mut command = [0_u8; 16];
        let bytes = value.as_bytes();
        command[..bytes.len()].copy_from_slice(bytes);
        command
    }

    fn raw_as_bytes(raw: &RawNetworkEvent) -> &[u8] {
        unsafe {
            std::slice::from_raw_parts(
                std::ptr::from_ref(raw).cast::<u8>(),
                std::mem::size_of::<RawNetworkEvent>(),
            )
        }
    }
}
