#![allow(dead_code)]

#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
use e_navigator_core::ProtocolSourceConfig;
#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
use e_navigator_protocol::{
    ProtocolExtractionConfig,
    kafka::parse_kafka_request,
    mongodb::parse_mongodb_message,
    mysql::parse_mysql_command,
    nats::parse_nats_command,
    postgres::parse_postgres_message,
    redis::parse_redis_command,
    stream::{RequestStreamDecoder, StreamDecodeLimits, StreamFrame, StreamProtocol},
};
#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
use e_navigator_signals::{
    NetworkProcessIdentity, ProtocolKind, ProtocolRequestObservation, SignalEnvelope,
    TraceAttribute, TraceConfidence, TraceCorrelationKind, TracePeerContext,
};

#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
pub(crate) const RAW_PROTOCOL_DATA_BYTES: usize = 256;
#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
pub(crate) const RAW_PROTOCOL_DIRECTION_READ: u32 = 1;
#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
pub(crate) const RAW_PROTOCOL_DIRECTION_WRITE: u32 = 2;
#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
pub(crate) const RAW_PROTOCOL_AF_INET: u32 = 2;
#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
pub(crate) const RAW_PROTOCOL_AF_INET6: u32 = 10;
#[cfg(any(target_os = "linux", test))]
const PERF_BUFFER_PAGE_COUNT: usize = 64;
#[cfg(any(target_os = "linux", test))]
const PERF_READER_POLL_INTERVAL_MS: u64 = 25;
#[cfg(any(target_os = "linux", test))]
const RAW_SAMPLE_CHANNEL_CAPACITY: usize = 1024;
#[cfg(any(target_os = "linux", test))]
const PROTOCOL_DIAGNOSTIC_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_secs(10);
#[cfg(any(target_os = "linux", test))]
const PROTOCOL_DIAGNOSTIC_COUNTERS_LEN: usize = 9;
#[cfg(any(target_os = "linux", test))]
const PROTOCOL_DIAGNOSTIC_COUNTER_NAMES: [&str; PROTOCOL_DIAGNOSTIC_COUNTERS_LEN] = [
    "write_enter",
    "read_enter",
    "read_exit",
    "connection_miss",
    "port_filtered",
    "non_tcp_connection",
    "null_or_empty",
    "copy_empty",
    "output_attempt",
];

/// Raw payload capture event; must stay byte-identical to the eBPF-side
/// `RawProtocolDataEvent` in `e-navigator-ebpf-programs`.
#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct RawProtocolDataEvent {
    pub pid: u32,
    pub uid: u32,
    pub cgroup_id: u64,
    pub fd: i32,
    pub direction: u32,
    pub family: u32,
    pub remote_port_be: u16,
    pub local_port_be: u16,
    pub remote_addr_v4: u32,
    pub local_addr_v4: u32,
    pub remote_addr_v6: [u8; 16],
    pub local_addr_v6: [u8; 16],
    pub timestamp_unix_nanos: u64,
    pub payload_len: u32,
    pub payload_total_len: u32,
    pub command: [u8; 16],
    pub payload: [u8; RAW_PROTOCOL_DATA_BYTES],
}

#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RawProtocolInvalidSampleMetadata {
    pid: u32,
    uid: u32,
    cgroup_id: u64,
    fd: i32,
    direction: u32,
    family: u32,
    remote_port_be: u16,
    local_port_be: u16,
    payload_len: u32,
    payload_total_len: u32,
    command: [u8; 16],
}

#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
impl RawProtocolInvalidSampleMetadata {
    fn from_raw(raw: &RawProtocolDataEvent) -> Self {
        Self {
            pid: raw.pid,
            uid: raw.uid,
            cgroup_id: raw.cgroup_id,
            fd: raw.fd,
            direction: raw.direction,
            family: raw.family,
            remote_port_be: raw.remote_port_be,
            local_port_be: raw.local_port_be,
            payload_len: raw.payload_len,
            payload_total_len: raw.payload_total_len,
            command: raw.command,
        }
    }
}

#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RawProtocolDecodeError {
    RawSampleTooShort,
    InvalidPayloadLength {
        sample: RawProtocolInvalidSampleMetadata,
    },
    UnmappedPort {
        sample: RawProtocolInvalidSampleMetadata,
    },
}

#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
impl RawProtocolDecodeError {
    fn reason_name(self) -> &'static str {
        match self {
            Self::RawSampleTooShort => "raw_sample_too_short",
            Self::InvalidPayloadLength { .. } => "invalid_payload_length",
            Self::UnmappedPort { .. } => "unmapped_port",
        }
    }

    fn sample_metadata(self) -> Option<RawProtocolInvalidSampleMetadata> {
        match self {
            Self::RawSampleTooShort => None,
            Self::InvalidPayloadLength { sample } => Some(sample),
            Self::UnmappedPort { sample } => Some(sample),
        }
    }
}

/// Maps configured remote ports to their protocol.
#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
#[derive(Debug, Clone, Default)]
pub(crate) struct ProtocolPortMap {
    entries: Vec<(u16, StreamProtocol)>,
}

#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
impl ProtocolPortMap {
    pub(crate) fn from_config(config: &ProtocolSourceConfig) -> Self {
        let mut entries = Vec::new();
        let protocols = [
            (StreamProtocol::Kafka, &config.kafka_ports),
            (StreamProtocol::Mongodb, &config.mongodb_ports),
            (StreamProtocol::Mysql, &config.mysql_ports),
            (StreamProtocol::Nats, &config.nats_ports),
            (StreamProtocol::Postgresql, &config.postgresql_ports),
            (StreamProtocol::Redis, &config.redis_ports),
        ];
        for (protocol, ports) in protocols {
            for port in ports {
                if *port != 0 && !entries.iter().any(|(existing, _)| existing == port) {
                    entries.push((*port, protocol));
                }
            }
        }
        Self { entries }
    }

    pub(crate) fn lookup(&self, port: u16) -> Option<StreamProtocol> {
        self.entries
            .iter()
            .find(|(candidate, _)| *candidate == port)
            .map(|(_, protocol)| *protocol)
    }

    pub(crate) fn ports(&self) -> impl Iterator<Item = u16> + '_ {
        self.entries.iter().map(|(port, _)| *port)
    }
}

/// Counters for everything the registry chose not to turn into a signal.
#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct ProtocolRegistryCounters {
    pub ignored_read_events: u64,
    pub truncated_frames: u64,
    pub unparsed_frames: u64,
    pub evicted_connections: u64,
}

#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct ConnectionId {
    pid: u32,
    fd: i32,
}

#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
#[derive(Debug)]
struct ConnectionStream {
    decoder: RequestStreamDecoder,
    last_seen_unix_nanos: u64,
}

/// Per-connection reassembly and parsing state for the protocol source.
#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
#[derive(Debug)]
pub(crate) struct ProtocolStreamRegistry {
    host: Option<String>,
    procfs_root: std::path::PathBuf,
    ports: ProtocolPortMap,
    extraction: ProtocolExtractionConfig,
    limits: StreamDecodeLimits,
    max_tracked_connections: usize,
    connections: std::collections::HashMap<ConnectionId, ConnectionStream>,
    frames: Vec<StreamFrame>,
    counters: ProtocolRegistryCounters,
}

#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
impl ProtocolStreamRegistry {
    pub(crate) fn new(
        host: Option<String>,
        procfs_root: std::path::PathBuf,
        config: &ProtocolSourceConfig,
    ) -> Self {
        Self {
            host,
            procfs_root,
            ports: ProtocolPortMap::from_config(config),
            extraction: ProtocolExtractionConfig {
                max_header_bytes: config.max_buffered_bytes_per_connection,
                max_attributes: config.max_attributes,
                ..ProtocolExtractionConfig::default()
            },
            limits: StreamDecodeLimits {
                max_buffered_bytes: config.max_buffered_bytes_per_connection,
                ..StreamDecodeLimits::default()
            },
            max_tracked_connections: config.max_tracked_connections.max(1),
            connections: std::collections::HashMap::new(),
            frames: Vec::new(),
            counters: ProtocolRegistryCounters::default(),
        }
    }

    pub(crate) fn counters(&self) -> ProtocolRegistryCounters {
        self.counters
    }

    pub(crate) fn tracked_connections(&self) -> usize {
        self.connections.len()
    }

    /// Decodes one raw perf sample and appends any resulting protocol
    /// request observations to `signals`.
    pub(crate) fn handle_event(
        &mut self,
        bytes: &[u8],
        observed_unix_nanos: u64,
        signals: &mut Vec<SignalEnvelope>,
    ) -> Result<(), RawProtocolDecodeError> {
        if bytes.len() < core::mem::size_of::<RawProtocolDataEvent>() {
            return Err(RawProtocolDecodeError::RawSampleTooShort);
        }

        let raw =
            unsafe { core::ptr::read_unaligned(bytes.as_ptr().cast::<RawProtocolDataEvent>()) };
        if raw.payload_len as usize > RAW_PROTOCOL_DATA_BYTES
            || raw.payload_len > raw.payload_total_len
        {
            return Err(RawProtocolDecodeError::InvalidPayloadLength {
                sample: RawProtocolInvalidSampleMetadata::from_raw(&raw),
            });
        }
        if raw.direction != RAW_PROTOCOL_DIRECTION_WRITE {
            // Response-direction capture is decoded once request/response
            // matching lands; until then it is counted, not guessed at.
            self.counters.ignored_read_events += 1;
            return Ok(());
        }

        let remote_port = u16::from_be(raw.remote_port_be);
        let Some(protocol) = self.ports.lookup(remote_port) else {
            return Err(RawProtocolDecodeError::UnmappedPort {
                sample: RawProtocolInvalidSampleMetadata::from_raw(&raw),
            });
        };

        let connection_id = ConnectionId {
            pid: raw.pid,
            fd: raw.fd,
        };
        self.evict_if_needed(connection_id);
        let limits = self.limits;
        let stream = self
            .connections
            .entry(connection_id)
            .or_insert_with(|| ConnectionStream {
                decoder: RequestStreamDecoder::new(protocol, limits),
                last_seen_unix_nanos: observed_unix_nanos,
            });
        stream.last_seen_unix_nanos = observed_unix_nanos;

        let payload = &raw.payload[..raw.payload_len as usize];
        self.frames.clear();
        stream
            .decoder
            .push_chunk(payload, u64::from(raw.payload_total_len), &mut self.frames);

        let frames = std::mem::take(&mut self.frames);
        for frame in &frames {
            match frame {
                StreamFrame::Complete(frame_bytes) => {
                    match parse_request_frame(protocol, frame_bytes, &self.extraction) {
                        Ok(parsed) => {
                            signals.push(self.build_observation(&raw, parsed, observed_unix_nanos));
                        }
                        Err(_) => {
                            self.counters.unparsed_frames += 1;
                        }
                    }
                }
                StreamFrame::Truncated { .. } => {
                    self.counters.truncated_frames += 1;
                }
            }
        }
        self.frames = frames;
        self.frames.clear();
        Ok(())
    }

    fn evict_if_needed(&mut self, incoming: ConnectionId) {
        if self.connections.contains_key(&incoming)
            || self.connections.len() < self.max_tracked_connections
        {
            return;
        }
        let oldest = self
            .connections
            .iter()
            .min_by_key(|(_, stream)| stream.last_seen_unix_nanos)
            .map(|(id, _)| *id);
        if let Some(id) = oldest {
            self.connections.remove(&id);
            self.counters.evicted_connections += 1;
        }
    }

    fn build_observation(
        &self,
        raw: &RawProtocolDataEvent,
        parsed: ParsedRequestFrame,
        observed_unix_nanos: u64,
    ) -> SignalEnvelope {
        let peer = peer_context(raw);
        let container = crate::procfs::container_from_pid_cgroup(&self.procfs_root, raw.pid);
        let process = NetworkProcessIdentity {
            pid: raw.pid,
            ppid: None,
            uid: Some(raw.uid),
            command: bytes_to_string(&raw.command),
            executable: None,
            cgroup_id: (raw.cgroup_id != 0).then_some(raw.cgroup_id),
        };

        SignalEnvelope::protocol_request_observation(
            "source.aya_protocol",
            self.host.clone(),
            ProtocolRequestObservation {
                protocol: parsed.protocol,
                start_unix_nanos: observed_unix_nanos,
                end_unix_nanos: None,
                duration_nanos: None,
                trace_id: None,
                span_id: None,
                parent_span_id: None,
                traceparent: None,
                tracestate: None,
                correlation_kind: TraceCorrelationKind::ProtocolObserved,
                confidence: if parsed.warning.is_none() {
                    TraceConfidence::High
                } else {
                    TraceConfidence::Low
                },
                service_name: Some(process.command.clone()),
                method: parsed.operation,
                status_code: None,
                process: Some(process),
                container,
                kubernetes: None,
                peer,
                attributes: parsed.attributes,
            },
        )
    }
}

#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ParsedRequestFrame {
    protocol: ProtocolKind,
    operation: Option<String>,
    warning: Option<String>,
    attributes: Vec<TraceAttribute>,
}

#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
fn parse_request_frame(
    protocol: StreamProtocol,
    frame: &[u8],
    config: &ProtocolExtractionConfig,
) -> Result<ParsedRequestFrame, &'static str> {
    match protocol {
        StreamProtocol::Kafka => parse_kafka_request(frame, config)
            .map(|parsed| ParsedRequestFrame {
                protocol: parsed.protocol,
                operation: parsed.operation,
                warning: parsed.warning,
                attributes: parsed.attributes,
            })
            .map_err(|_| "kafka_request"),
        StreamProtocol::Mongodb => parse_mongodb_message(frame, config)
            .map(|parsed| ParsedRequestFrame {
                protocol: parsed.protocol,
                operation: parsed.operation,
                warning: parsed.warning,
                attributes: parsed.attributes,
            })
            .map_err(|_| "mongodb_message"),
        StreamProtocol::Mysql => parse_mysql_command(frame, config)
            .map(|parsed| ParsedRequestFrame {
                protocol: parsed.protocol,
                operation: parsed.operation,
                warning: parsed.warning,
                attributes: parsed.attributes,
            })
            .map_err(|_| "mysql_command"),
        StreamProtocol::Nats => parse_nats_command(frame, config)
            .map(|parsed| ParsedRequestFrame {
                protocol: parsed.protocol,
                operation: parsed.operation,
                warning: parsed.warning,
                attributes: parsed.attributes,
            })
            .map_err(|_| "nats_command"),
        StreamProtocol::Postgresql => parse_postgres_message(frame, config)
            .map(|parsed| ParsedRequestFrame {
                protocol: parsed.protocol,
                operation: parsed.operation,
                warning: parsed.warning,
                attributes: parsed.attributes,
            })
            .map_err(|_| "postgres_message"),
        StreamProtocol::Redis => parse_redis_command(frame, config)
            .map(|parsed| ParsedRequestFrame {
                protocol: parsed.protocol,
                operation: parsed.command,
                warning: parsed.warning,
                attributes: parsed.attributes,
            })
            .map_err(|_| "redis_command"),
    }
}

#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
fn peer_context(raw: &RawProtocolDataEvent) -> Option<TracePeerContext> {
    let address = match raw.family {
        RAW_PROTOCOL_AF_INET => Some(ipv4_to_string(raw.remote_addr_v4)),
        RAW_PROTOCOL_AF_INET6 => Some(ipv6_to_string(raw.remote_addr_v6)),
        _ => None,
    };
    let port = u16::from_be(raw.remote_port_be);
    let port = (port != 0).then_some(port);
    if address.is_none() && port.is_none() {
        return None;
    }

    Some(TracePeerContext {
        address,
        port,
        domain: None,
        workload: None,
        container: None,
    })
}

#[cfg(feature = "fuzzing")]
pub fn fuzz_decode_raw_protocol_data_event(bytes: &[u8]) -> bool {
    const MAX_FUZZ_BYTES: usize = 1024;

    let bytes = &bytes[..bytes.len().min(MAX_FUZZ_BYTES)];
    let config = ProtocolSourceConfig::default();
    let mut registry = ProtocolStreamRegistry::new(
        None,
        std::path::PathBuf::from("__e_navigator_fuzz_no_procfs__"),
        &config,
    );
    let mut signals = Vec::new();
    registry.handle_event(bytes, 1_000, &mut signals).is_ok()
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
            HashMap as AyaHashMap, MapData, PerCpuArray,
            perf::{PerfEvent, PerfEventArray},
        },
        programs::TracePoint,
        util::online_cpus,
    };
    use e_navigator_core::{
        CoreError, CoreResult, ModuleKind, ModuleMetadata, ProtocolSourceConfig, Source,
    };
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
    pub struct AyaProtocolSource {
        host: Option<String>,
        procfs_root: PathBuf,
        config: ProtocolSourceConfig,
    }

    impl AyaProtocolSource {
        pub fn new(
            host: Option<String>,
            procfs_root: PathBuf,
            config: ProtocolSourceConfig,
        ) -> Self {
            Self {
                host,
                procfs_root,
                config,
            }
        }
    }

    #[async_trait]
    impl Source<SignalEnvelope> for AyaProtocolSource {
        fn metadata(&self) -> ModuleMetadata {
            ModuleMetadata::new("source.aya_protocol", ModuleKind::Source)
        }

        async fn run(self: Box<Self>, tx: mpsc::Sender<SignalEnvelope>) -> CoreResult<()> {
            bump_memlock_rlimit();
            let shutdown = ReaderShutdown::new();
            let mut reader_handles = Vec::new();
            let diagnostics = SourceDiagnostics::from_env();
            let telemetry = Arc::new(SourceTelemetry::new("source.aya_protocol"));
            let mut ebpf = Ebpf::load(include_bytes_aligned!(concat!(
                env!("OUT_DIR"),
                "/e-navigator-ebpf-programs"
            )))
            .map_err(module_error)?;

            populate_capture_ports(&mut ebpf, &self.config)?;

            attach_tracepoint(
                &mut ebpf,
                "tracepoint_protocol_connect_enter",
                "syscalls",
                "sys_enter_connect",
            )?;
            attach_tracepoint(
                &mut ebpf,
                "tracepoint_protocol_connect_exit",
                "syscalls",
                "sys_exit_connect",
            )?;
            attach_tracepoint(
                &mut ebpf,
                "tracepoint_protocol_close_enter",
                "syscalls",
                "sys_enter_close",
            )?;
            attach_tracepoint(
                &mut ebpf,
                "tracepoint_protocol_write_enter",
                "syscalls",
                "sys_enter_write",
            )?;
            attach_tracepoint(
                &mut ebpf,
                "tracepoint_protocol_sendto_enter",
                "syscalls",
                "sys_enter_sendto",
            )?;

            if diagnostics.enabled() {
                let diagnostic_counters = PerCpuArray::try_from(
                    ebpf.take_map("PROTOCOL_DIAGNOSTIC_COUNTERS")
                        .ok_or_else(|| CoreError::ModuleFailed {
                            module: "source.aya_protocol".to_string(),
                            message: "missing PROTOCOL_DIAGNOSTIC_COUNTERS map".to_string(),
                        })?,
                )
                .map_err(module_error)?;
                reader_handles.push(spawn_protocol_diagnostic_counter_logger(
                    diagnostic_counters,
                    shutdown.clone(),
                ));
            }

            let mut perf_array = PerfEventArray::try_from(
                ebpf.take_map("PROTOCOL_DATA_EVENTS")
                    .ok_or_else(|| CoreError::ModuleFailed {
                        module: "source.aya_protocol".to_string(),
                        message: "missing PROTOCOL_DATA_EVENTS map".to_string(),
                    })?,
            )
            .map_err(module_error)?;

            // Reassembly is stateful per connection while perf samples arrive
            // per CPU, so all readers feed a single decoder task.
            let (sample_tx, mut sample_rx) =
                mpsc::channel::<Vec<u8>>(super::RAW_SAMPLE_CHANNEL_CAPACITY);

            let cpus = online_cpus().map_err(|(_, err)| module_error(err))?;
            for cpu_id in cpus {
                let mut buffer = perf_array
                    .open(cpu_id, Some(super::PERF_BUFFER_PAGE_COUNT))
                    .map_err(module_error)?;
                let reader_shutdown = shutdown.clone();
                let telemetry = telemetry.clone();
                let sample_tx = sample_tx.clone();

                reader_handles.push(tokio::task::spawn_blocking(move || {
                    let mut closed = false;

                    while !reader_shutdown.is_stopped() {
                        buffer.for_each(|event| {
                            if closed {
                                return;
                            }

                            match event {
                                PerfEvent::Sample { head, tail } => {
                                    let bytes = perf_sample_bytes(head, tail).into_owned();
                                    if sample_tx.blocking_send(bytes).is_err() {
                                        closed = true;
                                    }
                                }
                                PerfEvent::Lost { count } => {
                                    telemetry.record_lost_perf_events(count);
                                    warn!(count, "lost protocol data perf events");
                                }
                            }
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
            drop(sample_tx);

            let decoder_host = self.host.clone();
            let decoder_procfs_root = self.procfs_root.clone();
            let decoder_config = self.config.clone();
            let decoder_shutdown = shutdown.clone();
            let decoder_diagnostics = diagnostics.clone();
            let decoder_telemetry = telemetry.clone();
            reader_handles.push(tokio::task::spawn_blocking(move || {
                let mut registry = super::ProtocolStreamRegistry::new(
                    decoder_host,
                    decoder_procfs_root,
                    &decoder_config,
                );
                let mut signals = Vec::new();

                while let Some(bytes) = sample_rx.blocking_recv() {
                    if decoder_shutdown.is_stopped() {
                        return;
                    }

                    signals.clear();
                    match registry.handle_event(&bytes, super::now_unix_nanos(), &mut signals) {
                        Ok(()) => {
                            decoder_telemetry.record_decoded_sample();
                            for signal in signals.drain(..) {
                                let diagnostic_decision =
                                    log_signal_diagnostic(&decoder_diagnostics, &signal);
                                decoder_telemetry.record_diagnostic_decision(diagnostic_decision);
                                if tx.blocking_send(signal).is_err() {
                                    decoder_telemetry.record_send_failure();
                                    return;
                                }
                                decoder_telemetry.record_sent_signal();
                            }
                        }
                        Err(err) => {
                            decoder_telemetry.record_invalid_sample();
                            let diagnostic_decision =
                                log_invalid_protocol_sample_diagnostic(&decoder_diagnostics, err);
                            decoder_telemetry.record_diagnostic_decision(diagnostic_decision);
                        }
                    }
                    decoder_telemetry.maybe_log_summary();
                }
            }));

            if diagnostics.enabled() {
                info!(
                    source = "source.aya_protocol",
                    remaining_samples = diagnostics.remaining_samples(),
                    filtered_preview_remaining_samples =
                        diagnostics.remaining_filtered_preview_samples(),
                    "source diagnostics enabled"
                );
            }
            debug!("aya protocol source attached");
            tokio::signal::ctrl_c().await.map_err(module_error)?;
            shutdown.stop();
            join_reader_handles(reader_handles).await
        }
    }

    fn populate_capture_ports(ebpf: &mut Ebpf, config: &ProtocolSourceConfig) -> CoreResult<()> {
        let map =
            ebpf.map_mut("PROTOCOL_CAPTURE_PORTS")
                .ok_or_else(|| CoreError::ModuleFailed {
                    module: "source.aya_protocol".to_string(),
                    message: "missing PROTOCOL_CAPTURE_PORTS map".to_string(),
                })?;
        let mut ports: AyaHashMap<&mut MapData, u16, u32> =
            AyaHashMap::try_from(map).map_err(module_error)?;
        let port_map = super::ProtocolPortMap::from_config(config);
        for port in port_map.ports() {
            ports.insert(port, 1, 0).map_err(module_error)?;
        }
        Ok(())
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
            source = "source.aya_protocol",
            raw_event = "protocol_request_observation",
            protocol = ?event.protocol,
            method = ?event.method,
            peer_address = ?event.peer.as_ref().and_then(|peer| peer.address.as_deref()),
            peer_port = ?event.peer.as_ref().and_then(|peer| peer.port),
            "source diagnostic raw event decoded"
        );
        DiagnosticSampleDecision::Matched
    }

    fn log_invalid_protocol_sample_diagnostic(
        diagnostics: &SourceDiagnostics,
        err: super::RawProtocolDecodeError,
    ) -> DiagnosticSampleDecision {
        let reason = err.reason_name();
        let sample = err.sample_metadata();
        let command = sample
            .map(|sample| super::bytes_to_string(&sample.command))
            .unwrap_or_default();
        let decision = diagnostics.sample_decision_for(&[reason, command.as_str()]);
        if decision != DiagnosticSampleDecision::Matched {
            return decision;
        }

        let redacted_command = sample.map(|sample| {
            let command = super::bytes_to_string(&sample.command);
            diagnostics.redact_value(&command)
        });
        let cgroup_id =
            sample.and_then(|sample| (sample.cgroup_id != 0).then_some(sample.cgroup_id));
        info!(
            target: "e_navigator_sources_ebpf_aya::source_diagnostics",
            source = "source.aya_protocol",
            raw_event = "invalid_protocol_data_sample",
            invalid_reason = reason,
            pid = ?sample.map(|sample| sample.pid),
            uid = ?sample.map(|sample| sample.uid),
            command = ?redacted_command,
            cgroup_id = ?diagnostics.redact_optional_u64(cgroup_id),
            fd = ?sample.map(|sample| sample.fd),
            direction = ?sample.map(|sample| sample.direction),
            family = ?sample.map(|sample| sample.family),
            remote_port = ?sample.map(|sample| u16::from_be(sample.remote_port_be)),
            local_port = ?sample.map(|sample| u16::from_be(sample.local_port_be)),
            payload_len = ?sample.map(|sample| sample.payload_len),
            payload_total_len = ?sample.map(|sample| sample.payload_total_len),
            "source diagnostic raw event invalid"
        );
        DiagnosticSampleDecision::Matched
    }

    #[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
    struct ProtocolDiagnosticCounterSnapshot {
        counters: [u64; super::PROTOCOL_DIAGNOSTIC_COUNTERS_LEN],
    }

    impl ProtocolDiagnosticCounterSnapshot {
        fn delta_since(&self, previous: &Self) -> Self {
            let mut counters = [0_u64; super::PROTOCOL_DIAGNOSTIC_COUNTERS_LEN];
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
    }

    fn spawn_protocol_diagnostic_counter_logger(
        counters: PerCpuArray<MapData, u64>,
        shutdown: ReaderShutdown,
    ) -> JoinHandle<()> {
        tokio::task::spawn_blocking(move || {
            let mut previous = ProtocolDiagnosticCounterSnapshot::default();

            while !shutdown.is_stopped() {
                std::thread::sleep(super::PROTOCOL_DIAGNOSTIC_POLL_INTERVAL);
                if shutdown.is_stopped() {
                    break;
                }

                match read_protocol_diagnostic_counters(&counters) {
                    Ok(snapshot) => {
                        let delta = snapshot.delta_since(&previous);
                        previous = snapshot;
                        if delta.is_empty() {
                            continue;
                        }

                        info!(
                            target: "e_navigator_sources_ebpf_aya::source_diagnostics",
                            source = "source.aya_protocol",
                            write_enter = delta.get(0),
                            read_enter = delta.get(1),
                            read_exit = delta.get(2),
                            connection_miss = delta.get(3),
                            port_filtered = delta.get(4),
                            non_tcp_connection = delta.get(5),
                            null_or_empty = delta.get(6),
                            copy_empty = delta.get(7),
                            output_attempt = delta.get(8),
                            stage_names = ?super::PROTOCOL_DIAGNOSTIC_COUNTER_NAMES,
                            "source diagnostic protocol stage counters"
                        );
                    }
                    Err(err) => {
                        warn!(error = %err, "failed to read protocol diagnostic counters");
                    }
                }
            }
        })
    }

    fn read_protocol_diagnostic_counters(
        counters: &PerCpuArray<MapData, u64>,
    ) -> Result<ProtocolDiagnosticCounterSnapshot, aya::maps::MapError> {
        let mut totals = [0_u64; super::PROTOCOL_DIAGNOSTIC_COUNTERS_LEN];
        for (index, total) in totals.iter_mut().enumerate() {
            let per_cpu = counters.get(&(index as u32), 0)?;
            *total = per_cpu
                .iter()
                .fold(0_u64, |sum, value| sum.saturating_add(*value));
        }

        Ok(ProtocolDiagnosticCounterSnapshot { counters: totals })
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
                module: "source.aya_protocol".to_string(),
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
            module: "source.aya_protocol".to_string(),
            message: err.to_string(),
        }
    }
}

#[cfg(not(target_os = "linux"))]
mod platform {
    use async_trait::async_trait;
    use e_navigator_core::{
        CoreError, CoreResult, ModuleKind, ModuleMetadata, ProtocolSourceConfig, Source,
    };
    use e_navigator_signals::SignalEnvelope;
    use tokio::sync::mpsc;

    #[derive(Debug, Default)]
    pub struct AyaProtocolSource {
        host: Option<String>,
        _procfs_root: std::path::PathBuf,
        _config: ProtocolSourceConfig,
    }

    impl AyaProtocolSource {
        pub fn new(
            host: Option<String>,
            procfs_root: std::path::PathBuf,
            config: ProtocolSourceConfig,
        ) -> Self {
            Self {
                host,
                _procfs_root: procfs_root,
                _config: config,
            }
        }
    }

    #[async_trait]
    impl Source<SignalEnvelope> for AyaProtocolSource {
        fn metadata(&self) -> ModuleMetadata {
            ModuleMetadata::new("source.aya_protocol", ModuleKind::Source)
        }

        async fn run(self: Box<Self>, _tx: mpsc::Sender<SignalEnvelope>) -> CoreResult<()> {
            Err(CoreError::ModuleFailed {
                module: "source.aya_protocol".to_string(),
                message: format!(
                    "Aya protocol source requires Linux and eBPF support; host={}",
                    self.host.as_deref().unwrap_or("unknown")
                ),
            })
        }
    }
}

pub use platform::AyaProtocolSource;

#[cfg(test)]
mod tests {
    use super::*;
    use e_navigator_signals::SignalPayload;

    fn fixed_command(name: &str) -> [u8; 16] {
        let mut command = [0_u8; 16];
        let bytes = name.as_bytes();
        command[..bytes.len().min(16)].copy_from_slice(&bytes[..bytes.len().min(16)]);
        command
    }

    fn raw_event(remote_port: u16, payload: &[u8], total_len: u32) -> RawProtocolDataEvent {
        let mut event = RawProtocolDataEvent {
            pid: 4242,
            uid: 1000,
            cgroup_id: 77,
            fd: 9,
            direction: RAW_PROTOCOL_DIRECTION_WRITE,
            family: RAW_PROTOCOL_AF_INET,
            remote_port_be: remote_port.to_be(),
            local_port_be: 43210_u16.to_be(),
            remote_addr_v4: u32::from_ne_bytes([10, 0, 0, 5]),
            local_addr_v4: u32::from_ne_bytes([10, 0, 0, 9]),
            remote_addr_v6: [0; 16],
            local_addr_v6: [0; 16],
            timestamp_unix_nanos: 1_000,
            payload_len: payload.len() as u32,
            payload_total_len: total_len,
            command: fixed_command("client"),
            payload: [0; RAW_PROTOCOL_DATA_BYTES],
        };
        event.payload[..payload.len()].copy_from_slice(payload);
        event
    }

    fn raw_as_bytes(event: &RawProtocolDataEvent) -> &[u8] {
        unsafe {
            core::slice::from_raw_parts(
                (event as *const RawProtocolDataEvent).cast::<u8>(),
                core::mem::size_of::<RawProtocolDataEvent>(),
            )
        }
    }

    fn registry() -> ProtocolStreamRegistry {
        ProtocolStreamRegistry::new(
            Some("test-host".to_string()),
            std::path::PathBuf::from("__e_navigator_test_no_procfs__"),
            &ProtocolSourceConfig::default(),
        )
    }

    fn handle(
        registry: &mut ProtocolStreamRegistry,
        event: &RawProtocolDataEvent,
    ) -> Vec<SignalEnvelope> {
        let mut signals = Vec::new();
        registry
            .handle_event(raw_as_bytes(event), 5_000, &mut signals)
            .expect("valid event decodes");
        signals
    }

    fn observation(signal: &SignalEnvelope) -> &ProtocolRequestObservation {
        match &signal.payload {
            SignalPayload::ProtocolRequestObservation(observation) => observation,
            other => panic!("expected protocol request observation, got {other:?}"),
        }
    }

    #[test]
    fn redis_command_produces_observation() {
        let mut registry = registry();
        let payload = b"*2\r\n$3\r\nGET\r\n$10\r\nsecret-key\r\n";
        let event = raw_event(6379, payload, payload.len() as u32);
        let signals = handle(&mut registry, &event);

        assert_eq!(signals.len(), 1);
        let observation = observation(&signals[0]);
        assert_eq!(observation.protocol, ProtocolKind::Redis);
        assert_eq!(observation.method.as_deref(), Some("GET"));
        assert_eq!(observation.confidence, TraceConfidence::High);
        let process = observation.process.as_ref().expect("process identity");
        assert_eq!(process.pid, 4242);
        assert_eq!(process.command, "client");
        let peer = observation.peer.as_ref().expect("peer context");
        assert_eq!(peer.address.as_deref(), Some("10.0.0.5"));
        assert_eq!(peer.port, Some(6379));

        // The key must never appear anywhere in the serialized signal.
        let serialized = serde_json::to_string(&signals[0]).expect("signal serializes");
        assert!(!serialized.contains("secret-key"));
    }

    #[test]
    fn kafka_request_reassembles_across_chunks() {
        let mut registry = registry();
        // api_key=3 (metadata), api_version=9, correlation_id=7, client_id len=-1.
        let body = [0, 3, 0, 9, 0, 0, 0, 7, 0xff, 0xff];
        let mut frame = (body.len() as i32).to_be_bytes().to_vec();
        frame.extend_from_slice(&body);

        let first = raw_event(9092, &frame[..6], 6);
        assert!(handle(&mut registry, &first).is_empty());

        let second = raw_event(9092, &frame[6..], (frame.len() - 6) as u32);
        let signals = handle(&mut registry, &second);
        assert_eq!(signals.len(), 1);
        let observation = observation(&signals[0]);
        assert_eq!(observation.protocol, ProtocolKind::Kafka);
        assert_eq!(observation.method.as_deref(), Some("metadata"));
    }

    #[test]
    fn truncated_frame_is_counted_not_emitted() {
        let mut registry = registry();
        let mut frame = 4096_i32.to_be_bytes().to_vec();
        frame.extend_from_slice(&[0; 64]);
        let event = raw_event(9092, &frame, 4100);
        let signals = handle(&mut registry, &event);

        assert!(signals.is_empty());
        assert_eq!(registry.counters().truncated_frames, 1);
    }

    #[test]
    fn read_direction_events_are_ignored() {
        let mut registry = registry();
        let payload = b"+OK\r\n";
        let mut event = raw_event(6379, payload, payload.len() as u32);
        event.direction = RAW_PROTOCOL_DIRECTION_READ;
        let signals = handle(&mut registry, &event);

        assert!(signals.is_empty());
        assert_eq!(registry.counters().ignored_read_events, 1);
    }

    #[test]
    fn unmapped_port_is_an_error() {
        let mut registry = registry();
        let payload = b"PING\r\n";
        let event = raw_event(8080, payload, payload.len() as u32);
        let mut signals = Vec::new();
        let err = registry
            .handle_event(raw_as_bytes(&event), 5_000, &mut signals)
            .expect_err("unmapped port is rejected");
        assert_eq!(err.reason_name(), "unmapped_port");
    }

    #[test]
    fn short_sample_is_rejected() {
        let mut registry = registry();
        let mut signals = Vec::new();
        let err = registry
            .handle_event(&[0_u8; 16], 5_000, &mut signals)
            .expect_err("short sample is rejected");
        assert_eq!(err.reason_name(), "raw_sample_too_short");
    }

    #[test]
    fn invalid_payload_length_is_rejected() {
        let mut registry = registry();
        let payload = b"PING\r\n";
        let mut event = raw_event(6379, payload, payload.len() as u32);
        event.payload_len = (RAW_PROTOCOL_DATA_BYTES + 1) as u32;
        let mut signals = Vec::new();
        let err = registry
            .handle_event(raw_as_bytes(&event), 5_000, &mut signals)
            .expect_err("oversized payload length is rejected");
        assert_eq!(err.reason_name(), "invalid_payload_length");
    }

    #[test]
    fn unparsed_frames_are_counted() {
        let mut registry = registry();
        // A valid MySQL packet header carrying an unknown command byte.
        let packet = [1, 0, 0, 0, 0xfb];
        let event = raw_event(3306, &packet, packet.len() as u32);
        let signals = handle(&mut registry, &event);

        assert!(signals.is_empty());
        assert_eq!(registry.counters().unparsed_frames, 1);
    }

    #[test]
    fn connection_cap_evicts_oldest_stream() {
        let config = ProtocolSourceConfig {
            max_tracked_connections: 2,
            ..ProtocolSourceConfig::default()
        };
        let mut registry = ProtocolStreamRegistry::new(
            None,
            std::path::PathBuf::from("__e_navigator_test_no_procfs__"),
            &config,
        );

        let payload = b"PING\r\n";
        for fd in 0..3 {
            let mut event = raw_event(6379, payload, payload.len() as u32);
            event.fd = fd;
            let mut signals = Vec::new();
            registry
                .handle_event(raw_as_bytes(&event), 5_000 + fd as u64, &mut signals)
                .expect("valid event decodes");
        }

        assert_eq!(registry.tracked_connections(), 2);
        assert_eq!(registry.counters().evicted_connections, 1);
    }

    #[test]
    fn postgres_query_produces_observation() {
        let mut registry = registry();
        let statement = b"SELECT 1\0";
        let mut frame = vec![b'Q'];
        frame.extend_from_slice(&((statement.len() + 4) as u32).to_be_bytes());
        frame.extend_from_slice(statement);
        let event = raw_event(5432, &frame, frame.len() as u32);
        let signals = handle(&mut registry, &event);

        assert_eq!(signals.len(), 1);
        let observation = observation(&signals[0]);
        assert_eq!(observation.protocol, ProtocolKind::Postgresql);
        assert_eq!(observation.method.as_deref(), Some("SELECT"));
        let serialized = serde_json::to_string(&signals[0]).expect("signal serializes");
        assert!(!serialized.contains("SELECT 1"));
    }

    #[test]
    fn nats_publish_produces_observation() {
        let mut registry = registry();
        let payload = b"PUB orders.created 5\r\nhello\r\n";
        let event = raw_event(4222, payload, payload.len() as u32);
        let signals = handle(&mut registry, &event);

        assert_eq!(signals.len(), 1);
        let observation = observation(&signals[0]);
        assert_eq!(observation.protocol, ProtocolKind::Nats);
        assert_eq!(observation.method.as_deref(), Some("pub"));
        let serialized = serde_json::to_string(&signals[0]).expect("signal serializes");
        assert!(!serialized.contains("orders.created"));
    }

    #[test]
    fn pipelined_commands_emit_multiple_observations() {
        let mut registry = registry();
        let payload = b"*1\r\n$4\r\nPING\r\n*1\r\n$4\r\nPING\r\n";
        let event = raw_event(6379, payload, payload.len() as u32);
        let signals = handle(&mut registry, &event);

        assert_eq!(signals.len(), 2);
    }
}
