#![allow(dead_code)]

#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
use e_navigator_core::ProtocolSourceConfig;
#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
use e_navigator_protocol::{
    ProtocolExtractionConfig,
    http::{parse_http_request, parse_http_response},
    http2::{
        HTTP2_FLAG_END_STREAM, HTTP2_FRAME_TYPE_HEADERS, HpackDecoder, parse_http2_frame_header,
        parse_http2_request_headers_frame, parse_http2_response_headers_frame,
    },
    kafka::{parse_kafka_request, parse_kafka_response_for_api_key},
    mongodb::{parse_mongodb_message, parse_mongodb_response},
    mysql::{parse_mysql_command, parse_mysql_response},
    nats::parse_nats_command,
    postgres::{parse_postgres_message, parse_postgres_response},
    redis::{parse_redis_command, parse_redis_response},
    stream::{
        ProtocolStreamDecoder, StreamDecodeLimits, StreamDirection, StreamFrame, StreamProtocol,
    },
};
#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
use e_navigator_signals::{
    ContainerContext, NetworkProcessIdentity, ProtocolCaptureRole, ProtocolKind,
    ProtocolRequestObservation, SignalEnvelope, TraceAttribute, TraceConfidence,
    TraceCorrelationKind, TracePeerContext,
};

#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
pub(crate) const RAW_PROTOCOL_DATA_BYTES: usize = 256;
/// Matches the eBPF per-syscall capture bound (16 segments of 256 bytes).
#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
pub(crate) const RAW_PROTOCOL_MAX_CAPTURE_BYTES: u32 = 16 * RAW_PROTOCOL_DATA_BYTES as u32;
#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
pub(crate) const RAW_PROTOCOL_DIRECTION_READ: u32 = 1;
#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
pub(crate) const RAW_PROTOCOL_DIRECTION_WRITE: u32 = 2;
#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
pub(crate) const RAW_PROTOCOL_AF_INET: u32 = 2;
#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
pub(crate) const RAW_PROTOCOL_AF_INET6: u32 = 10;
#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
pub(crate) const MAX_IN_FLIGHT_REQUESTS: usize = 32;
#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
pub(crate) const REQUEST_MATCH_TIMEOUT_NANOS: u64 = 30_000_000_000;
#[cfg(any(target_os = "linux", test))]
const PERF_BUFFER_PAGE_COUNT: usize = 64;
#[cfg(any(target_os = "linux", test))]
const PERF_READER_POLL_INTERVAL_MS: u64 = 25;
#[cfg(any(target_os = "linux", test))]
const RAW_SAMPLE_CHANNEL_CAPACITY: usize = 1024;
#[cfg(any(target_os = "linux", test))]
const PROTOCOL_DIAGNOSTIC_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_secs(10);
#[cfg(any(target_os = "linux", test))]
const PROTOCOL_DIAGNOSTIC_COUNTERS_LEN: usize = 11;
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
    "writev_enter",
    "sendmsg_enter",
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
    pub payload_offset: u32,
    pub payload_captured_len: u32,
    pub command: [u8; 16],
    pub payload: [u8; RAW_PROTOCOL_DATA_BYTES],
}

#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawProtocolInvalidSampleMetadata {
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
    payload_offset: u32,
    payload_captured_len: u32,
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
            payload_offset: raw.payload_offset,
            payload_captured_len: raw.payload_captured_len,
            command: raw.command,
        }
    }
}

#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RawProtocolDecodeError {
    RawSampleTooShort,
    InvalidPayloadLength {
        sample: RawProtocolInvalidSampleMetadata,
    },
    InvalidDirection {
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
            Self::InvalidDirection { .. } => "invalid_direction",
            Self::UnmappedPort { .. } => "unmapped_port",
        }
    }

    fn sample_metadata(self) -> Option<RawProtocolInvalidSampleMetadata> {
        match self {
            Self::RawSampleTooShort => None,
            Self::InvalidPayloadLength { sample } => Some(sample),
            Self::InvalidDirection { sample } => Some(sample),
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
            (StreamProtocol::Http1, &config.http1_ports),
            (StreamProtocol::Http2, &config.http2_ports),
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
    pub matched_responses: u64,
    pub orphan_responses: u64,
    pub unparsed_responses: u64,
    pub response_continuations: u64,
    pub unmatched_overflow: u64,
    pub unmatched_expired: u64,
    pub unmatched_evicted: u64,
    pub segment_gaps: u64,
}

#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct ConnectionId {
    pid: u32,
    fd: i32,
}

/// Connection identity fields retained for deferred emission.
#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
#[derive(Debug, Clone)]
struct ObservationContext {
    pid: u32,
    uid: u32,
    cgroup_id: u64,
    family: u32,
    remote_port_be: u16,
    local_port_be: u16,
    remote_addr_v4: u32,
    local_addr_v4: u32,
    remote_addr_v6: [u8; 16],
    local_addr_v6: [u8; 16],
    command: [u8; 16],
    container: Option<ContainerContext>,
}

#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
impl ObservationContext {
    fn from_raw(raw: &RawProtocolDataEvent, procfs_root: &std::path::Path) -> Self {
        Self {
            pid: raw.pid,
            uid: raw.uid,
            cgroup_id: raw.cgroup_id,
            family: raw.family,
            remote_port_be: raw.remote_port_be,
            local_port_be: raw.local_port_be,
            remote_addr_v4: raw.remote_addr_v4,
            local_addr_v4: raw.local_addr_v4,
            remote_addr_v6: raw.remote_addr_v6,
            local_addr_v6: raw.local_addr_v6,
            command: raw.command,
            container: crate::procfs::container_from_pid_cgroup(procfs_root, raw.pid),
        }
    }

    fn matches_connection(&self, raw: &RawProtocolDataEvent) -> bool {
        self.pid == raw.pid
            && self.uid == raw.uid
            && self.cgroup_id == raw.cgroup_id
            && self.family == raw.family
            && self.remote_port_be == raw.remote_port_be
            && self.local_port_be == raw.local_port_be
            && self.remote_addr_v4 == raw.remote_addr_v4
            && self.local_addr_v4 == raw.local_addr_v4
            && self.remote_addr_v6 == raw.remote_addr_v6
            && self.local_addr_v6 == raw.local_addr_v6
    }
}

#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
#[derive(Debug)]
struct InFlightRequest {
    parsed: ParsedRequestFrame,
    started_unix_nanos: u64,
    kafka_api_key: i16,
    kafka_api_version: i16,
}

#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
#[derive(Debug)]
struct Http2ConnectionState {
    request_hpack: HpackDecoder,
    response_hpack: HpackDecoder,
    streams: std::collections::BTreeMap<u32, InFlightRequest>,
}

/// Splicing position inside a multi-segment syscall capture whose final
/// segment has not arrived yet.
#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SegmentProgress {
    timestamp_unix_nanos: u64,
    next_offset: u32,
    captured_len: u32,
    total_len: u32,
}

#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
#[derive(Debug)]
struct ConnectionStream {
    protocol: StreamProtocol,
    request_decoder: ProtocolStreamDecoder,
    response_decoder: ProtocolStreamDecoder,
    request_segments: Option<SegmentProgress>,
    response_segments: Option<SegmentProgress>,
    in_flight: std::collections::VecDeque<InFlightRequest>,
    http2: Option<Http2ConnectionState>,
    context: ObservationContext,
    last_seen_unix_nanos: u64,
}

/// Per-connection reassembly and parsing state for the protocol source.
#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
#[derive(Debug)]
pub struct ProtocolStreamRegistry {
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
    pub fn new(
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
    pub fn handle_event(
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
            || raw.payload_captured_len > RAW_PROTOCOL_MAX_CAPTURE_BYTES
            || u64::from(raw.payload_offset) + u64::from(raw.payload_len)
                > u64::from(raw.payload_captured_len)
            || raw.payload_captured_len > raw.payload_total_len
        {
            return Err(RawProtocolDecodeError::InvalidPayloadLength {
                sample: RawProtocolInvalidSampleMetadata::from_raw(&raw),
            });
        }
        if raw.direction != RAW_PROTOCOL_DIRECTION_WRITE
            && raw.direction != RAW_PROTOCOL_DIRECTION_READ
        {
            return Err(RawProtocolDecodeError::InvalidDirection {
                sample: RawProtocolInvalidSampleMetadata::from_raw(&raw),
            });
        }

        let remote_port = u16::from_be(raw.remote_port_be);
        let Some(protocol) = self.ports.lookup(remote_port) else {
            return Err(RawProtocolDecodeError::UnmappedPort {
                sample: RawProtocolInvalidSampleMetadata::from_raw(&raw),
            });
        };

        // NATS commands are fire-and-forget; server-to-client traffic is
        // asynchronous message delivery, not per-request responses.
        if raw.direction == RAW_PROTOCOL_DIRECTION_READ && protocol == StreamProtocol::Nats {
            self.counters.ignored_read_events += 1;
            return Ok(());
        }

        let connection_id = ConnectionId {
            pid: raw.pid,
            fd: raw.fd,
        };
        if self
            .connections
            .get(&connection_id)
            .is_some_and(|stream| !stream.context.matches_connection(&raw))
        {
            self.evict_connection(connection_id, signals);
        }
        self.evict_if_needed(connection_id, signals);
        let limits = self.limits;
        let stream = self
            .connections
            .entry(connection_id)
            .or_insert_with(|| ConnectionStream {
                protocol,
                request_decoder: ProtocolStreamDecoder::new(
                    protocol,
                    StreamDirection::Request,
                    limits,
                ),
                response_decoder: ProtocolStreamDecoder::new(
                    protocol,
                    StreamDirection::Response,
                    limits,
                ),
                request_segments: None,
                response_segments: None,
                in_flight: std::collections::VecDeque::new(),
                http2: (protocol == StreamProtocol::Http2).then(|| Http2ConnectionState {
                    request_hpack: HpackDecoder::new(),
                    response_hpack: HpackDecoder::new(),
                    streams: std::collections::BTreeMap::new(),
                }),
                context: ObservationContext::from_raw(&raw, &self.procfs_root),
                last_seen_unix_nanos: observed_unix_nanos,
            });
        stream.last_seen_unix_nanos = observed_unix_nanos;

        let payload = &raw.payload[..raw.payload_len as usize];
        let mut frames = std::mem::take(&mut self.frames);
        frames.clear();
        let (decoder, pending_segments) = if raw.direction == RAW_PROTOCOL_DIRECTION_WRITE {
            (&mut stream.request_decoder, &mut stream.request_segments)
        } else {
            (&mut stream.response_decoder, &mut stream.response_segments)
        };
        feed_segment(
            decoder,
            pending_segments,
            &raw,
            payload,
            &mut self.counters,
            &mut frames,
        );

        if stream.protocol == StreamProtocol::Http2 {
            handle_http2_frames(
                stream,
                &frames,
                raw.direction == RAW_PROTOCOL_DIRECTION_WRITE,
                &self.extraction,
                &self.host,
                &mut self.counters,
                observed_unix_nanos,
                signals,
            );
        } else if raw.direction == RAW_PROTOCOL_DIRECTION_WRITE {
            handle_request_frames(
                stream,
                &frames,
                &self.extraction,
                &self.host,
                &mut self.counters,
                observed_unix_nanos,
                signals,
            );
        } else {
            handle_response_frames(
                stream,
                &frames,
                &self.extraction,
                &self.host,
                &mut self.counters,
                observed_unix_nanos,
                signals,
            );
        }
        frames.clear();
        self.frames = frames;
        Ok(())
    }

    fn evict_if_needed(&mut self, incoming: ConnectionId, signals: &mut Vec<SignalEnvelope>) {
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
            self.evict_connection(id, signals);
        }
    }

    fn evict_connection(&mut self, id: ConnectionId, signals: &mut Vec<SignalEnvelope>) {
        let Some(mut stream) = self.connections.remove(&id) else {
            return;
        };
        self.counters.evicted_connections += 1;
        if let Some(http2) = stream.http2.as_mut() {
            while let Some((_, entry)) = http2.streams.pop_first() {
                self.counters.unmatched_evicted += 1;
                signals.push(build_observation(
                    self.host.clone(),
                    &stream.context,
                    entry.parsed,
                    entry.started_unix_nanos,
                    None,
                ));
            }
        }
        for entry in stream.in_flight.drain(..) {
            self.counters.unmatched_evicted += 1;
            signals.push(build_observation(
                self.host.clone(),
                &stream.context,
                entry.parsed,
                entry.started_unix_nanos,
                None,
            ));
        }
    }
}

/// Feeds one captured segment into the stream decoder, splicing contiguous
/// segments of a multi-segment syscall and converting every lost or
/// mis-ordered segment into an explicit uncaptured gap. Non-adjacent bytes
/// are never spliced together.
#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
fn feed_segment(
    decoder: &mut ProtocolStreamDecoder,
    pending: &mut Option<SegmentProgress>,
    raw: &RawProtocolDataEvent,
    payload: &[u8],
    counters: &mut ProtocolRegistryCounters,
    frames: &mut Vec<StreamFrame>,
) {
    let continues = pending.is_some_and(|progress| {
        raw.timestamp_unix_nanos == progress.timestamp_unix_nanos
            && raw.payload_offset == progress.next_offset
            && raw.payload_captured_len == progress.captured_len
            && raw.payload_total_len == progress.total_len
    });
    if !continues {
        if let Some(progress) = pending.take() {
            // The rest of the previous syscall's segments never arrived.
            counters.segment_gaps += 1;
            decoder.push_chunk(
                &[],
                u64::from(progress.total_len.saturating_sub(progress.next_offset)),
                frames,
            );
        }
        if raw.payload_offset > 0 {
            // Segments before this one were lost.
            counters.segment_gaps += 1;
            decoder.push_chunk(&[], u64::from(raw.payload_offset), frames);
        }
    }

    let segment_end = raw.payload_offset + raw.payload_len;
    let is_final = segment_end >= raw.payload_captured_len;
    let chunk_total_len = if is_final {
        // The final segment carries the uncaptured syscall tail as its gap.
        payload.len() as u64
            + u64::from(
                raw.payload_total_len
                    .saturating_sub(raw.payload_captured_len),
            )
    } else {
        payload.len() as u64
    };
    decoder.push_chunk(payload, chunk_total_len, frames);
    *pending = (!is_final).then_some(SegmentProgress {
        timestamp_unix_nanos: raw.timestamp_unix_nanos,
        next_offset: segment_end,
        captured_len: raw.payload_captured_len,
        total_len: raw.payload_total_len,
    });
}

/// Processes reassembled request frames: parsed requests join the bounded
/// in-flight queue (NATS emits immediately); overflow and expiry emit
/// unmatched observations rather than growing state.
#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
#[allow(clippy::too_many_arguments)]
fn handle_request_frames(
    stream: &mut ConnectionStream,
    frames: &[StreamFrame],
    extraction: &ProtocolExtractionConfig,
    host: &Option<String>,
    counters: &mut ProtocolRegistryCounters,
    observed_unix_nanos: u64,
    signals: &mut Vec<SignalEnvelope>,
) {
    for frame in frames {
        let (parsed, frame_bytes) = match frame {
            StreamFrame::Complete(frame_bytes) => {
                match parse_request_frame(stream.protocol, frame_bytes, extraction) {
                    Ok(parsed) => (parsed, Some(frame_bytes.as_slice())),
                    Err(_) => {
                        counters.unparsed_frames += 1;
                        (
                            placeholder_request(stream.protocol, "unparsed_request_frame"),
                            Some(frame_bytes.as_slice()),
                        )
                    }
                }
            }
            StreamFrame::Truncated { prefix, .. } => {
                counters.truncated_frames += 1;
                (
                    placeholder_request(stream.protocol, "truncated_request_frame"),
                    Some(prefix.as_slice()),
                )
            }
        };

        if stream.protocol == StreamProtocol::Nats {
            signals.push(build_observation(
                host.clone(),
                &stream.context,
                parsed,
                observed_unix_nanos,
                None,
            ));
            continue;
        }

        let (kafka_api_key, kafka_api_version) = frame_bytes
            .filter(|_| stream.protocol == StreamProtocol::Kafka)
            .and_then(kafka_request_header_prefix)
            .unwrap_or((-1, -1));

        expire_in_flight(stream, host, counters, observed_unix_nanos, signals);
        if stream.in_flight.len() >= MAX_IN_FLIGHT_REQUESTS
            && let Some(entry) = stream.in_flight.pop_front()
        {
            counters.unmatched_overflow += 1;
            signals.push(build_observation(
                host.clone(),
                &stream.context,
                entry.parsed,
                entry.started_unix_nanos,
                None,
            ));
        }
        stream.in_flight.push_back(InFlightRequest {
            parsed,
            started_unix_nanos: observed_unix_nanos,
            kafka_api_key,
            kafka_api_version,
        });
    }
}

/// How a response frame interacts with the in-flight request queue.
#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ResponseAction {
    /// The frame completes exactly the oldest in-flight request.
    PopOne,
    /// The frame completes every queued request (PostgreSQL ReadyForQuery
    /// ends a pipelined batch).
    PopAll,
    /// The frame continues an already-completed or in-progress response and
    /// must not consume a queued request.
    Ignore,
}

/// Multi-frame response protocols need per-frame queue policies so latency
/// is never attributed to the wrong request.
#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
fn response_action(protocol: StreamProtocol, frame: &[u8]) -> ResponseAction {
    match protocol {
        // HTTP/2 uses stream-id matching, never the FIFO queue.
        StreamProtocol::Http2 => ResponseAction::Ignore,
        // HTTP/1 is strict request/response over one connection; each framed
        // response completes exactly the oldest in-flight request.
        StreamProtocol::Http1
        | StreamProtocol::Kafka
        | StreamProtocol::Mongodb
        | StreamProtocol::Redis => ResponseAction::PopOne,
        // MySQL response packets to one command increment the sequence id;
        // only the first packet (sequence 1) marks the response start.
        StreamProtocol::Mysql => {
            if frame.len() >= 4 && frame[3] == 1 {
                ResponseAction::PopOne
            } else {
                ResponseAction::Ignore
            }
        }
        // PostgreSQL answers one frontend batch with many backend messages;
        // ErrorResponse completes the current request, ReadyForQuery closes
        // the batch, everything else is response payload.
        StreamProtocol::Postgresql => match frame.first() {
            Some(b'E') => ResponseAction::PopOne,
            Some(b'Z') => ResponseAction::PopAll,
            _ => ResponseAction::Ignore,
        },
        StreamProtocol::Nats => ResponseAction::Ignore,
    }
}

/// Processes reassembled response frames by completing in-flight requests
/// with latency and response status semantics.
#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
#[allow(clippy::too_many_arguments)]
fn handle_response_frames(
    stream: &mut ConnectionStream,
    frames: &[StreamFrame],
    extraction: &ProtocolExtractionConfig,
    host: &Option<String>,
    counters: &mut ProtocolRegistryCounters,
    observed_unix_nanos: u64,
    signals: &mut Vec<SignalEnvelope>,
) {
    for frame in frames {
        let (frame_bytes, truncated) = match frame {
            StreamFrame::Complete(frame_bytes) => (frame_bytes.as_slice(), false),
            StreamFrame::Truncated { prefix, .. } => {
                counters.truncated_frames += 1;
                (prefix.as_slice(), true)
            }
        };

        let action = response_action(stream.protocol, frame_bytes);
        if action == ResponseAction::Ignore {
            counters.response_continuations += 1;
            continue;
        }
        if stream.in_flight.is_empty() {
            counters.orphan_responses += 1;
            continue;
        }

        let response = if truncated {
            Err("truncated_response_frame")
        } else {
            let front = stream
                .in_flight
                .front()
                .expect("in-flight queue checked non-empty");
            parse_response_frame(
                stream.protocol,
                frame_bytes,
                front.kafka_api_key,
                front.kafka_api_version,
                extraction,
            )
        };

        let pop_count = match action {
            ResponseAction::PopOne => 1,
            ResponseAction::PopAll => stream.in_flight.len(),
            ResponseAction::Ignore => 0,
        };
        for _ in 0..pop_count {
            let Some(entry) = stream.in_flight.pop_front() else {
                break;
            };
            let mut parsed = entry.parsed;
            match &response {
                Ok(response) => {
                    counters.matched_responses += 1;
                    for attribute in &response.attributes {
                        if parsed.attributes.len() >= extraction.max_attributes {
                            break;
                        }
                        if !parsed
                            .attributes
                            .iter()
                            .any(|existing| existing.key == attribute.key)
                        {
                            parsed.attributes.push(attribute.clone());
                        }
                    }
                }
                Err(reason) => {
                    counters.unparsed_responses += 1;
                    parsed.warning.get_or_insert_with(|| (*reason).to_string());
                }
            }
            signals.push(build_observation(
                host.clone(),
                &stream.context,
                parsed,
                entry.started_unix_nanos,
                Some(observed_unix_nanos),
            ));
        }
    }
}

/// Processes reassembled HTTP/2 frames for one direction. Requests are
/// keyed by stream id; responses merge status semantics into the stream
/// entry and emit when the stream ends.
#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
#[allow(clippy::too_many_arguments)]
fn handle_http2_frames(
    stream: &mut ConnectionStream,
    frames: &[StreamFrame],
    is_request_direction: bool,
    extraction: &ProtocolExtractionConfig,
    host: &Option<String>,
    counters: &mut ProtocolRegistryCounters,
    observed_unix_nanos: u64,
    signals: &mut Vec<SignalEnvelope>,
) {
    for frame in frames {
        let (frame_bytes, truncated) = match frame {
            StreamFrame::Complete(frame_bytes) => (frame_bytes.as_slice(), false),
            StreamFrame::Truncated { prefix, .. } => {
                counters.truncated_frames += 1;
                (prefix.as_slice(), true)
            }
        };
        // The client connection preface is not a frame.
        if is_request_direction && frame_bytes.starts_with(b"PRI * HTTP/2.0") {
            continue;
        }
        let Ok(header) = parse_http2_frame_header(frame_bytes) else {
            counters.unparsed_frames += 1;
            continue;
        };
        let payload = &frame_bytes[frame_bytes.len().min(9)..];
        let Some(http2) = stream.http2.as_mut() else {
            return;
        };

        if is_request_direction {
            if header.frame_type != HTTP2_FRAME_TYPE_HEADERS || header.stream_id == 0 {
                counters.response_continuations += 1;
                continue;
            }
            let parsed = if truncated {
                counters.unparsed_frames += 1;
                ParsedRequestFrame {
                    protocol: ProtocolKind::Http,
                    operation: None,
                    warning: Some("truncated_request_frame".to_string()),
                    attributes: Vec::new(),
                }
            } else {
                match parse_http2_request_headers_frame(
                    &mut http2.request_hpack,
                    &header,
                    payload,
                    extraction,
                ) {
                    Ok(parsed) => ParsedRequestFrame {
                        protocol: parsed.protocol,
                        operation: parsed.method,
                        warning: parsed.warning,
                        attributes: parsed.attributes,
                    },
                    Err(_) => {
                        counters.unparsed_frames += 1;
                        ParsedRequestFrame {
                            protocol: ProtocolKind::Http,
                            operation: None,
                            warning: Some("unparsed_request_frame".to_string()),
                            attributes: Vec::new(),
                        }
                    }
                }
            };
            if http2.streams.len() >= MAX_IN_FLIGHT_REQUESTS
                && let Some((_, entry)) = http2.streams.pop_first()
            {
                counters.unmatched_overflow += 1;
                signals.push(build_observation(
                    host.clone(),
                    &stream.context,
                    entry.parsed,
                    entry.started_unix_nanos,
                    None,
                ));
            }
            http2.streams.insert(
                header.stream_id,
                InFlightRequest {
                    parsed,
                    started_unix_nanos: observed_unix_nanos,
                    kafka_api_key: -1,
                    kafka_api_version: -1,
                },
            );
            continue;
        }

        // Response direction.
        if header.stream_id == 0 {
            counters.response_continuations += 1;
            continue;
        }
        let Some(mut entry) = http2.streams.remove(&header.stream_id) else {
            if header.frame_type == HTTP2_FRAME_TYPE_HEADERS {
                counters.orphan_responses += 1;
            }
            continue;
        };

        if header.frame_type == HTTP2_FRAME_TYPE_HEADERS {
            if truncated {
                counters.unparsed_responses += 1;
                entry
                    .parsed
                    .warning
                    .get_or_insert_with(|| "truncated_response_frame".to_string());
            } else {
                match parse_http2_response_headers_frame(
                    &mut http2.response_hpack,
                    &header,
                    payload,
                    extraction,
                ) {
                    Ok(response) => {
                        counters.matched_responses += 1;
                        if response.protocol == ProtocolKind::Grpc {
                            entry.parsed.protocol = ProtocolKind::Grpc;
                        }
                        for attribute in response.attributes {
                            if entry.parsed.attributes.len() >= extraction.max_attributes {
                                break;
                            }
                            if !entry
                                .parsed
                                .attributes
                                .iter()
                                .any(|existing| existing.key == attribute.key)
                            {
                                entry.parsed.attributes.push(attribute);
                            }
                        }
                    }
                    Err(_) => {
                        counters.unparsed_responses += 1;
                        entry
                            .parsed
                            .warning
                            .get_or_insert_with(|| "unparsed_response_frame".to_string());
                    }
                }
            }
        }

        if header.flags & HTTP2_FLAG_END_STREAM != 0 {
            signals.push(build_observation(
                host.clone(),
                &stream.context,
                entry.parsed,
                entry.started_unix_nanos,
                Some(observed_unix_nanos),
            ));
        } else {
            // Stream continues (for example gRPC trailers still pending).
            http2.streams.insert(header.stream_id, entry);
        }
    }
}

/// Emits and drops in-flight requests older than the match timeout.
#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
fn expire_in_flight(
    stream: &mut ConnectionStream,
    host: &Option<String>,
    counters: &mut ProtocolRegistryCounters,
    observed_unix_nanos: u64,
    signals: &mut Vec<SignalEnvelope>,
) {
    while let Some(entry) = stream.in_flight.front() {
        if observed_unix_nanos.saturating_sub(entry.started_unix_nanos)
            < REQUEST_MATCH_TIMEOUT_NANOS
        {
            return;
        }
        let entry = stream
            .in_flight
            .pop_front()
            .expect("front entry exists while expiring");
        counters.unmatched_expired += 1;
        signals.push(build_observation(
            host.clone(),
            &stream.context,
            entry.parsed,
            entry.started_unix_nanos,
            None,
        ));
    }
}

#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
fn placeholder_request(protocol: StreamProtocol, warning: &str) -> ParsedRequestFrame {
    ParsedRequestFrame {
        protocol: protocol_kind(protocol),
        operation: None,
        warning: Some(warning.to_string()),
        attributes: Vec::new(),
    }
}

#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
fn protocol_kind(protocol: StreamProtocol) -> ProtocolKind {
    match protocol {
        StreamProtocol::Http1 => ProtocolKind::Http,
        StreamProtocol::Http2 => ProtocolKind::Http,
        StreamProtocol::Kafka => ProtocolKind::Kafka,
        StreamProtocol::Mongodb => ProtocolKind::Mongodb,
        StreamProtocol::Mysql => ProtocolKind::Mysql,
        StreamProtocol::Nats => ProtocolKind::Nats,
        StreamProtocol::Postgresql => ProtocolKind::Postgresql,
        StreamProtocol::Redis => ProtocolKind::Redis,
    }
}

/// Reads the API key and version from a Kafka request frame prefix.
#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
fn kafka_request_header_prefix(frame: &[u8]) -> Option<(i16, i16)> {
    if frame.len() < 8 {
        return None;
    }
    let api_key = i16::from_be_bytes([frame[4], frame[5]]);
    let api_version = i16::from_be_bytes([frame[6], frame[7]]);
    Some((api_key, api_version))
}

#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
fn build_observation(
    host: Option<String>,
    context: &ObservationContext,
    parsed: ParsedRequestFrame,
    start_unix_nanos: u64,
    end_unix_nanos: Option<u64>,
) -> SignalEnvelope {
    let peer = context_peer(context);
    let container = context.container.clone();
    let process = NetworkProcessIdentity {
        pid: context.pid,
        ppid: None,
        uid: Some(context.uid),
        command: bytes_to_string(&context.command),
        executable: None,
        cgroup_id: (context.cgroup_id != 0).then_some(context.cgroup_id),
    };

    SignalEnvelope::protocol_request_observation(
        "source.aya_protocol",
        host,
        ProtocolRequestObservation {
            protocol: parsed.protocol,
            role: Some(ProtocolCaptureRole::Client),
            start_unix_nanos,
            end_unix_nanos,
            duration_nanos: end_unix_nanos
                .map(|end_nanos| end_nanos.saturating_sub(start_unix_nanos)),
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
        StreamProtocol::Http1 => parse_http_request(frame, config)
            .map(|parsed| ParsedRequestFrame {
                protocol: parsed.protocol,
                operation: parsed.method,
                warning: parsed.warning,
                attributes: parsed.attributes,
            })
            .map_err(|_| "http1_request"),
        StreamProtocol::Http2 => Err("http2_handled_separately"),
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

/// Uniform response summary derived from the per-protocol response parsers.
#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedResponseFrame {
    status_code: Option<String>,
    error_type: Option<String>,
    attributes: Vec<TraceAttribute>,
}

#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
fn parse_response_frame(
    protocol: StreamProtocol,
    frame: &[u8],
    kafka_api_key: i16,
    kafka_api_version: i16,
    config: &ProtocolExtractionConfig,
) -> Result<ParsedResponseFrame, &'static str> {
    match protocol {
        StreamProtocol::Http1 => parse_http_response(frame, config)
            .map(|parsed| ParsedResponseFrame {
                status_code: Some(parsed.status_code.to_string()),
                error_type: None,
                attributes: parsed.attributes,
            })
            .map_err(|_| "http1_response"),
        StreamProtocol::Http2 => Err("http2_handled_separately"),
        StreamProtocol::Kafka => {
            parse_kafka_response_for_api_key(kafka_api_key, kafka_api_version, frame, config)
                .map(|parsed| ParsedResponseFrame {
                    status_code: Some(parsed.status_code),
                    error_type: parsed.error_type,
                    attributes: parsed.attributes,
                })
                .map_err(|_| "kafka_response")
        }
        StreamProtocol::Mongodb => parse_mongodb_response(frame, config)
            .map(|parsed| ParsedResponseFrame {
                status_code: Some(parsed.status_code),
                error_type: parsed.error_type,
                attributes: parsed.attributes,
            })
            .map_err(|_| "mongodb_response"),
        StreamProtocol::Mysql => parse_mysql_response(frame, config)
            .map(|parsed| ParsedResponseFrame {
                status_code: Some(parsed.status_code),
                error_type: parsed.error_type,
                attributes: parsed.attributes,
            })
            .map_err(|_| "mysql_response"),
        StreamProtocol::Nats => Err("nats_response_unmatched"),
        StreamProtocol::Postgresql => parse_postgres_response(frame, config)
            .map(|parsed| ParsedResponseFrame {
                status_code: Some(parsed.status_code),
                error_type: parsed.error_type,
                attributes: parsed.attributes,
            })
            .map_err(|_| "postgres_response"),
        StreamProtocol::Redis => parse_redis_response(frame, config)
            .map(|parsed| ParsedResponseFrame {
                status_code: parsed.status_code,
                error_type: parsed.error_type,
                attributes: parsed.attributes,
            })
            .map_err(|_| "redis_response"),
    }
}

#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
fn context_peer(context: &ObservationContext) -> Option<TracePeerContext> {
    let address = match context.family {
        RAW_PROTOCOL_AF_INET => Some(ipv4_to_string(context.remote_addr_v4)),
        RAW_PROTOCOL_AF_INET6 => Some(ipv6_to_string(context.remote_addr_v6)),
        _ => None,
    };
    let port = u16::from_be(context.remote_port_be);
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
    use crate::perf_sample::InlineSample;
    use crate::reader_shutdown::ReaderShutdown;
    use crate::source_telemetry::SourceTelemetry;
    use async_trait::async_trait;
    use aya::{
        Ebpf, include_bytes_aligned,
        maps::{
            Array as AyaArray, HashMap as AyaHashMap, MapData, PerCpuArray,
            perf::{PerfEvent, PerfEventArray},
        },
        programs::TracePoint,
        util::online_cpus,
    };
    use e_navigator_core::{
        CoreError, CoreResult, ModuleKind, ModuleMetadata, ProtocolSourceConfig, Source,
    };
    use e_navigator_signals::{SignalEnvelope, SignalPayload};
    use std::{path::PathBuf, sync::Arc};
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
            populate_capture_limit(&mut ebpf, &self.config)?;

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
            attach_tracepoint(
                &mut ebpf,
                "tracepoint_protocol_writev_enter",
                "syscalls",
                "sys_enter_writev",
            )?;
            attach_tracepoint(
                &mut ebpf,
                "tracepoint_protocol_sendmsg_enter",
                "syscalls",
                "sys_enter_sendmsg",
            )?;
            attach_tracepoint(
                &mut ebpf,
                "tracepoint_protocol_read_enter",
                "syscalls",
                "sys_enter_read",
            )?;
            attach_tracepoint(
                &mut ebpf,
                "tracepoint_protocol_read_exit",
                "syscalls",
                "sys_exit_read",
            )?;
            attach_tracepoint(
                &mut ebpf,
                "tracepoint_protocol_recvfrom_enter",
                "syscalls",
                "sys_enter_recvfrom",
            )?;
            attach_tracepoint(
                &mut ebpf,
                "tracepoint_protocol_recvfrom_exit",
                "syscalls",
                "sys_exit_recvfrom",
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

            if let Some(handle) =
                crate::capture_filter::attach_capture_filter(&mut ebpf, "source.aya_protocol", {
                    let shutdown = shutdown.clone();
                    move || shutdown.is_stopped()
                })?
            {
                reader_handles.push(handle);
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
                mpsc::channel::<InlineSample>(super::RAW_SAMPLE_CHANNEL_CAPACITY);

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
                                    // Copy into a fixed inline buffer so the
                                    // hand-off to the decoder needs no
                                    // per-event heap allocation. Oversized
                                    // samples are dropped with accounting.
                                    let Some(sample) = InlineSample::from_perf(head, tail) else {
                                        telemetry.record_lost_perf_events(1);
                                        return;
                                    };
                                    if sample_tx.blocking_send(sample).is_err() {
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

                while let Some(sample) = sample_rx.blocking_recv() {
                    if decoder_shutdown.is_stopped() {
                        return;
                    }

                    signals.clear();
                    match registry.handle_event(
                        sample.as_bytes(),
                        super::now_unix_nanos(),
                        &mut signals,
                    ) {
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
            telemetry.mark_initialized();
            debug!("aya protocol source attached");
            crate::shutdown::signal().await.map_err(module_error)?;
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

    fn populate_capture_limit(ebpf: &mut Ebpf, config: &ProtocolSourceConfig) -> CoreResult<()> {
        let map =
            ebpf.map_mut("PROTOCOL_CAPTURE_LIMIT")
                .ok_or_else(|| CoreError::ModuleFailed {
                    module: "source.aya_protocol".to_string(),
                    message: "missing PROTOCOL_CAPTURE_LIMIT map".to_string(),
                })?;
        let mut limit: AyaArray<&mut MapData, u32> =
            AyaArray::try_from(map).map_err(module_error)?;
        let capture_bytes = config.capture_bytes_per_syscall.clamp(
            ProtocolSourceConfig::MIN_CAPTURE_BYTES_PER_SYSCALL,
            ProtocolSourceConfig::MAX_CAPTURE_BYTES_PER_SYSCALL,
        ) as u32;
        limit.set(0, capture_bytes, 0).map_err(module_error)?;
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
            payload_offset = ?sample.map(|sample| sample.payload_offset),
            payload_captured_len = ?sample.map(|sample| sample.payload_captured_len),
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
                            writev_enter = delta.get(9),
                            sendmsg_enter = delta.get(10),
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
            payload_offset: 0,
            payload_captured_len: payload.len() as u32,
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
        handle_at(registry, event, 5_000)
    }

    fn handle_at(
        registry: &mut ProtocolStreamRegistry,
        event: &RawProtocolDataEvent,
        observed_unix_nanos: u64,
    ) -> Vec<SignalEnvelope> {
        let mut signals = Vec::new();
        registry
            .handle_event(raw_as_bytes(event), observed_unix_nanos, &mut signals)
            .expect("valid event decodes");
        signals
    }

    fn response_event(remote_port: u16, payload: &[u8]) -> RawProtocolDataEvent {
        let mut event = raw_event(remote_port, payload, payload.len() as u32);
        event.direction = RAW_PROTOCOL_DIRECTION_READ;
        event
    }

    fn observation(signal: &SignalEnvelope) -> &ProtocolRequestObservation {
        match &signal.payload {
            SignalPayload::ProtocolRequestObservation(observation) => observation,
            other => panic!("expected protocol request observation, got {other:?}"),
        }
    }

    #[test]
    fn redis_command_matches_response_with_latency() {
        let mut registry = registry();
        let payload = b"*2\r\n$3\r\nGET\r\n$10\r\nsecret-key\r\n";
        let event = raw_event(6379, payload, payload.len() as u32);
        assert!(handle_at(&mut registry, &event, 5_000).is_empty());

        let response = response_event(6379, b"$5\r\nhello\r\n");
        let signals = handle_at(&mut registry, &response, 7_500);

        assert_eq!(signals.len(), 1);
        let observation = observation(&signals[0]);
        assert_eq!(observation.protocol, ProtocolKind::Redis);
        assert_eq!(observation.method.as_deref(), Some("GET"));
        assert_eq!(observation.confidence, TraceConfidence::High);
        assert_eq!(observation.start_unix_nanos, 5_000);
        assert_eq!(observation.end_unix_nanos, Some(7_500));
        assert_eq!(observation.duration_nanos, Some(2_500));
        let process = observation.process.as_ref().expect("process identity");
        assert_eq!(process.pid, 4242);
        assert_eq!(process.command, "client");
        let peer = observation.peer.as_ref().expect("peer context");
        assert_eq!(peer.address.as_deref(), Some("10.0.0.5"));
        assert_eq!(peer.port, Some(6379));
        assert_eq!(registry.counters().matched_responses, 1);

        // Neither the key nor the response value may appear in the signal.
        let serialized = serde_json::to_string(&signals[0]).expect("signal serializes");
        assert!(!serialized.contains("secret-key"));
        assert!(!serialized.contains("hello"));
    }

    #[test]
    fn connection_reuses_source_time_container_attribution() {
        const CONTAINER_ID: &str =
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let procfs_root = std::env::temp_dir().join(format!(
            "e-navigator-protocol-container-cache-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&procfs_root);
        let cgroup_path = procfs_root.join("4242/cgroup");
        std::fs::create_dir_all(cgroup_path.parent().expect("cgroup parent"))
            .expect("create procfs fixture");
        std::fs::write(
            &cgroup_path,
            format!("0::/kubepods.slice/cri-containerd-{CONTAINER_ID}.scope\n"),
        )
        .expect("write cgroup fixture");
        let mut registry = ProtocolStreamRegistry::new(
            Some("test-host".to_string()),
            procfs_root.clone(),
            &ProtocolSourceConfig::default(),
        );

        let request = raw_event(6379, b"*1\r\n$4\r\nPING\r\n", 14);
        assert!(handle_at(&mut registry, &request, 5_000).is_empty());
        std::fs::remove_file(&cgroup_path).expect("remove cgroup fixture after connection start");

        let response = response_event(6379, b"+PONG\r\n");
        let signals = handle_at(&mut registry, &response, 6_000);

        let container = observation(&signals[0])
            .container
            .as_ref()
            .expect("connection keeps its source-time container");
        assert_eq!(container.container_id, CONTAINER_ID);
        assert_eq!(container.runtime.as_deref(), Some("containerd"));
        std::fs::remove_dir_all(procfs_root).expect("cleanup procfs fixture");
    }

    #[test]
    fn reused_fd_with_a_new_socket_tuple_resets_stream_state() {
        let mut registry = registry();
        let first = raw_event(6379, b"*2\r\n$3\r\nGET\r\n$3\r\nkey\r\n", 22);
        assert!(handle_at(&mut registry, &first, 5_000).is_empty());

        let mut reused = raw_event(6379, b"*1\r\n$4\r\nPING\r\n", 14);
        reused.local_port_be = 43211_u16.to_be();
        let evicted = handle_at(&mut registry, &reused, 6_000);

        assert_eq!(evicted.len(), 1);
        assert_eq!(observation(&evicted[0]).method.as_deref(), Some("GET"));
        assert_eq!(observation(&evicted[0]).end_unix_nanos, None);
        assert_eq!(registry.counters().evicted_connections, 1);
        assert_eq!(registry.counters().unmatched_evicted, 1);

        let mut response = response_event(6379, b"+PONG\r\n");
        response.local_port_be = 43211_u16.to_be();
        let matched = handle_at(&mut registry, &response, 7_000);

        assert_eq!(matched.len(), 1);
        assert_eq!(observation(&matched[0]).method.as_deref(), Some("PING"));
        assert_eq!(observation(&matched[0]).duration_nanos, Some(1_000));
    }

    #[test]
    fn redis_error_response_attaches_error_attributes() {
        let mut registry = registry();
        let request = raw_event(6379, b"*1\r\n$4\r\nPING\r\n", 14);
        assert!(handle_at(&mut registry, &request, 5_000).is_empty());

        let response = response_event(6379, b"-ERR unknown command\r\n");
        let signals = handle_at(&mut registry, &response, 6_000);

        assert_eq!(signals.len(), 1);
        let observation = observation(&signals[0]);
        assert_eq!(observation.duration_nanos, Some(1_000));
        assert!(
            observation
                .attributes
                .iter()
                .any(|attribute| attribute.key == "error.type" || attribute.key.contains("status")),
            "expected response status attributes, got {:?}",
            observation.attributes,
        );
    }

    #[test]
    fn kafka_request_reassembles_and_matches_response() {
        let mut registry = registry();
        // api_key=18 (api_versions), api_version=0, correlation_id=7,
        // client_id len=-1.
        let body = [0, 18, 0, 0, 0, 0, 0, 7, 0xff, 0xff];
        let mut frame = (body.len() as i32).to_be_bytes().to_vec();
        frame.extend_from_slice(&body);

        let first = raw_event(9092, &frame[..6], 6);
        assert!(handle_at(&mut registry, &first, 5_000).is_empty());
        let second = raw_event(9092, &frame[6..], (frame.len() - 6) as u32);
        assert!(handle_at(&mut registry, &second, 5_100).is_empty());

        // ApiVersions v0 response: correlation id + error code 0.
        let response_body = [0, 0, 0, 7, 0, 0];
        let mut response_frame = (response_body.len() as i32).to_be_bytes().to_vec();
        response_frame.extend_from_slice(&response_body);
        let response = response_event(9092, &response_frame);
        let signals = handle_at(&mut registry, &response, 9_100);

        assert_eq!(signals.len(), 1);
        let observation = observation(&signals[0]);
        assert_eq!(observation.protocol, ProtocolKind::Kafka);
        assert_eq!(observation.method.as_deref(), Some("api_versions"));
        assert_eq!(observation.duration_nanos, Some(4_000));
        assert_eq!(registry.counters().matched_responses, 1);
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
    fn nats_read_direction_is_ignored() {
        let mut registry = registry();
        let event = response_event(4222, b"MSG updates 1 5\r\nhello\r\n");
        let signals = handle(&mut registry, &event);

        assert!(signals.is_empty());
        assert_eq!(registry.counters().ignored_read_events, 1);
    }

    #[test]
    fn orphan_responses_are_counted_not_matched() {
        let mut registry = registry();
        let event = response_event(6379, b"+OK\r\n");
        let signals = handle(&mut registry, &event);

        assert!(signals.is_empty());
        assert_eq!(registry.counters().orphan_responses, 1);
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

    /// Splits one syscall payload into eBPF-shaped segment events.
    fn segmented_events(remote_port: u16, payload: &[u8]) -> Vec<RawProtocolDataEvent> {
        payload
            .chunks(RAW_PROTOCOL_DATA_BYTES)
            .enumerate()
            .map(|(index, chunk)| {
                let mut event = raw_event(remote_port, chunk, payload.len() as u32);
                event.payload_offset = (index * RAW_PROTOCOL_DATA_BYTES) as u32;
                event.payload_captured_len = payload.len() as u32;
                event
            })
            .collect()
    }

    #[test]
    fn multi_segment_syscall_reassembles_complete_frame() {
        let mut registry = registry();
        let value = "x".repeat(560);
        let mut command = format!(
            "*3\r\n$3\r\nSET\r\n$10\r\nsecret-key\r\n${}\r\n",
            value.len()
        )
        .into_bytes();
        command.extend_from_slice(value.as_bytes());
        command.extend_from_slice(b"\r\n");
        assert!(command.len() > 2 * RAW_PROTOCOL_DATA_BYTES);

        for event in segmented_events(6379, &command) {
            assert!(handle_at(&mut registry, &event, 5_000).is_empty());
        }

        let response = response_event(6379, b"+OK\r\n");
        let signals = handle_at(&mut registry, &response, 6_000);
        assert_eq!(signals.len(), 1);
        let observation = observation(&signals[0]);
        assert_eq!(observation.method.as_deref(), Some("SET"));
        assert_eq!(observation.confidence, TraceConfidence::High);
        assert_eq!(registry.counters().segment_gaps, 0);
        assert_eq!(registry.counters().truncated_frames, 0);

        let serialized = serde_json::to_string(&signals[0]).expect("signal serializes");
        assert!(!serialized.contains("xxxx"));
        assert!(!serialized.contains("secret-key"));
    }

    #[test]
    fn lost_final_segment_becomes_accounted_gap() {
        let mut registry = registry();
        let value = "x".repeat(560);
        let mut command = format!(
            "*3\r\n$3\r\nSET\r\n$10\r\nsecret-key\r\n${}\r\n",
            value.len()
        )
        .into_bytes();
        command.extend_from_slice(value.as_bytes());
        command.extend_from_slice(b"\r\n");

        let segments = segmented_events(6379, &command);
        assert!(segments.len() >= 2);
        // Only the first segment arrives; the rest are lost.
        assert!(handle_at(&mut registry, &segments[0], 5_000).is_empty());

        // The next syscall flushes the missing tail as a gap; its own
        // command still parses cleanly at the next frame boundary.
        let ping = raw_event(6379, b"*1\r\n$4\r\nPING\r\n", 14);
        assert!(handle_at(&mut registry, &ping, 5_100).is_empty());
        assert_eq!(registry.counters().segment_gaps, 1);
        assert_eq!(registry.counters().truncated_frames, 1);

        let response = response_event(6379, b"+PONG\r\n+PONG\r\n");
        let signals = handle_at(&mut registry, &response, 6_000);
        assert_eq!(signals.len(), 2);
        assert_eq!(observation(&signals[1]).method.as_deref(), Some("PING"));
    }

    #[test]
    fn lost_leading_segments_become_accounted_gap() {
        let mut registry = registry();
        // A mid-syscall segment arrives with no preceding offset-0 segment.
        // Its bytes cannot start a valid frame, so the decoder resyncs.
        let mut orphan = raw_event(6379, &[b'*'; 200], 456);
        orphan.payload_offset = 256;
        orphan.payload_captured_len = 456;
        assert!(handle_at(&mut registry, &orphan, 5_000).is_empty());
        assert_eq!(registry.counters().segment_gaps, 1);

        // The stream recovers at the next clean frame boundary.
        let ping = raw_event(6379, b"*1\r\n$4\r\nPING\r\n", 14);
        assert!(handle_at(&mut registry, &ping, 5_100).is_empty());
        let response = response_event(6379, b"+PONG\r\n");
        let signals = handle_at(&mut registry, &response, 6_000);
        assert_eq!(signals.len(), 1);
        assert_eq!(observation(&signals[0]).method.as_deref(), Some("PING"));
    }

    #[test]
    fn segment_exceeding_captured_len_is_rejected() {
        let mut registry = registry();
        let payload = b"PING\r\n";
        let mut event = raw_event(6379, payload, payload.len() as u32);
        event.payload_offset = 8;
        let mut signals = Vec::new();
        let err = registry
            .handle_event(raw_as_bytes(&event), 5_000, &mut signals)
            .expect_err("segment past captured length is rejected");
        assert_eq!(err.reason_name(), "invalid_payload_length");
    }

    #[test]
    fn captured_len_exceeding_total_len_is_rejected() {
        let mut registry = registry();
        let payload = b"PING\r\n";
        let mut event = raw_event(6379, payload, payload.len() as u32);
        event.payload_captured_len = event.payload_total_len + 1;
        let mut signals = Vec::new();
        let err = registry
            .handle_event(raw_as_bytes(&event), 5_000, &mut signals)
            .expect_err("captured length past total length is rejected");
        assert_eq!(err.reason_name(), "invalid_payload_length");
    }

    #[test]
    fn unparsed_request_frames_hold_queue_position() {
        let mut registry = registry();
        // A valid MySQL packet header carrying an unknown command byte: it
        // cannot be parsed, but its response slot must stay aligned.
        let packet = [1, 0, 0, 0, 0xfb];
        let event = raw_event(3306, &packet, packet.len() as u32);
        assert!(handle_at(&mut registry, &event, 5_000).is_empty());
        assert_eq!(registry.counters().unparsed_frames, 1);

        let response = response_event(3306, &[5, 0, 0, 1, 0, 0, 0, 2, 0]);
        let signals = handle_at(&mut registry, &response, 6_000);
        assert_eq!(signals.len(), 1);
        let observation = observation(&signals[0]);
        assert_eq!(observation.method, None);
        assert_eq!(observation.confidence, TraceConfidence::Low);
        assert_eq!(observation.duration_nanos, Some(1_000));
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

    fn http2_frame(frame_type: u8, flags: u8, stream_id: u32, payload: &[u8]) -> Vec<u8> {
        let mut frame = Vec::new();
        frame.extend_from_slice(&(payload.len() as u32).to_be_bytes()[1..]);
        frame.push(frame_type);
        frame.push(flags);
        frame.extend_from_slice(&stream_id.to_be_bytes());
        frame.extend_from_slice(payload);
        frame
    }

    #[test]
    fn http2_request_matches_stream_response() {
        let config = ProtocolSourceConfig {
            http2_ports: vec![50051],
            ..ProtocolSourceConfig::default()
        };
        let mut registry = ProtocolStreamRegistry::new(
            None,
            std::path::PathBuf::from("__e_navigator_test_no_procfs__"),
            &config,
        );

        // Preface, then HEADERS for stream 1: :method GET (0x82), :path / (0x84).
        let mut request_payload = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
        request_payload.extend_from_slice(&http2_frame(1, 0x4, 1, &[0x82, 0x84]));
        let request = raw_event(50051, &request_payload, request_payload.len() as u32);
        assert!(handle_at(&mut registry, &request, 5_000).is_empty());

        // Response HEADERS with :status 200 (0x88) and END_STREAM|END_HEADERS.
        let response_payload = http2_frame(1, 0x4 | 0x1, 1, &[0x88]);
        let mut response = raw_event(50051, &response_payload, response_payload.len() as u32);
        response.direction = RAW_PROTOCOL_DIRECTION_READ;
        let signals = handle_at(&mut registry, &response, 6_200);

        assert_eq!(signals.len(), 1);
        let observation = observation(&signals[0]);
        assert_eq!(observation.protocol, ProtocolKind::Http);
        assert_eq!(observation.method.as_deref(), Some("GET"));
        assert_eq!(observation.duration_nanos, Some(1_200));
        assert!(
            observation
                .attributes
                .iter()
                .any(|attribute| attribute.key == "http.response.status_code"
                    && attribute.value == "200"),
        );
    }

    #[test]
    fn http2_multiplexed_streams_match_out_of_order() {
        let config = ProtocolSourceConfig {
            http2_ports: vec![50051],
            ..ProtocolSourceConfig::default()
        };
        let mut registry = ProtocolStreamRegistry::new(
            None,
            std::path::PathBuf::from("__e_navigator_test_no_procfs__"),
            &config,
        );

        let mut request_payload = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
        request_payload.extend_from_slice(&http2_frame(1, 0x4, 1, &[0x82, 0x84]));
        request_payload.extend_from_slice(&http2_frame(1, 0x4, 3, &[0x83, 0x84]));
        let request = raw_event(50051, &request_payload, request_payload.len() as u32);
        assert!(handle_at(&mut registry, &request, 5_000).is_empty());

        // Stream 3 responds before stream 1.
        let mut response_payload = http2_frame(1, 0x4 | 0x1, 3, &[0x88]);
        response_payload.extend_from_slice(&http2_frame(1, 0x4 | 0x1, 1, &[0x88]));
        let mut response = raw_event(50051, &response_payload, response_payload.len() as u32);
        response.direction = RAW_PROTOCOL_DIRECTION_READ;
        let signals = handle_at(&mut registry, &response, 6_000);

        assert_eq!(signals.len(), 2);
        assert_eq!(observation(&signals[0]).method.as_deref(), Some("POST"));
        assert_eq!(observation(&signals[1]).method.as_deref(), Some("GET"));
    }

    #[test]
    fn http2_grpc_trailers_complete_the_stream() {
        let config = ProtocolSourceConfig {
            http2_ports: vec![50051],
            ..ProtocolSourceConfig::default()
        };
        let mut registry = ProtocolStreamRegistry::new(
            None,
            std::path::PathBuf::from("__e_navigator_test_no_procfs__"),
            &config,
        );

        // gRPC request: :method POST, :path /pkg.Svc/Do, content-type
        // application/grpc (all literal without indexing where needed).
        let mut block = vec![0x83, 0x04];
        let path = b"/pkg.Svc/Do";
        block.push(path.len() as u8);
        block.extend_from_slice(path);
        block.push(0x0f);
        block.push(31 - 15);
        let content_type = b"application/grpc";
        block.push(content_type.len() as u8);
        block.extend_from_slice(content_type);
        let mut request_payload = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
        request_payload.extend_from_slice(&http2_frame(1, 0x4, 1, &block));
        let request = raw_event(50051, &request_payload, request_payload.len() as u32);
        assert!(handle_at(&mut registry, &request, 5_000).is_empty());

        // Response headers without END_STREAM, then trailers with grpc-status.
        let headers = http2_frame(1, 0x4, 1, &[0x88]);
        let mut response = raw_event(50051, &headers, headers.len() as u32);
        response.direction = RAW_PROTOCOL_DIRECTION_READ;
        assert!(handle_at(&mut registry, &response, 5_500).is_empty());

        let mut trailer_block = vec![0x00];
        let name = b"grpc-status";
        trailer_block.push(name.len() as u8);
        trailer_block.extend_from_slice(name);
        trailer_block.push(1);
        trailer_block.push(b'0');
        let trailers = http2_frame(1, 0x4 | 0x1, 1, &trailer_block);
        let mut response = raw_event(50051, &trailers, trailers.len() as u32);
        response.direction = RAW_PROTOCOL_DIRECTION_READ;
        let signals = handle_at(&mut registry, &response, 6_000);

        assert_eq!(signals.len(), 1);
        let observation = observation(&signals[0]);
        assert_eq!(observation.protocol, ProtocolKind::Grpc);
        assert_eq!(observation.duration_nanos, Some(1_000));
        assert!(
            observation
                .attributes
                .iter()
                .any(|attribute| attribute.key == "rpc.service" && attribute.value == "pkg.Svc"),
        );
        assert!(
            observation
                .attributes
                .iter()
                .any(|attribute| attribute.key == "rpc.grpc.status_code" && attribute.value == "0"),
        );
    }

    #[test]
    fn http1_request_matches_response_with_status() {
        let config = ProtocolSourceConfig {
            http1_ports: vec![8443],
            ..ProtocolSourceConfig::default()
        };
        let mut registry = ProtocolStreamRegistry::new(
            None,
            std::path::PathBuf::from("__e_navigator_test_no_procfs__"),
            &config,
        );

        let request = b"GET /orders/42 HTTP/1.1\r\nHost: api.test\r\n\r\n";
        let event = raw_event(8443, request, request.len() as u32);
        assert!(handle_at(&mut registry, &event, 5_000).is_empty());

        let response = response_event(
            8443,
            b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n",
        );
        let signals = handle_at(&mut registry, &response, 6_000);

        assert_eq!(signals.len(), 1);
        let observation = observation(&signals[0]);
        assert_eq!(observation.protocol, ProtocolKind::Http);
        assert_eq!(observation.method.as_deref(), Some("GET"));
        assert_eq!(observation.duration_nanos, Some(1_000));
        assert!(
            observation
                .attributes
                .iter()
                .any(|attribute| attribute.key == "http.response.status_code"
                    && attribute.value == "503"),
        );
        // The request target path must not leak as a high-cardinality value.
        let serialized = serde_json::to_string(&signals[0]).expect("signal serializes");
        assert!(serialized.contains("url.path"));
    }

    #[test]
    fn postgres_query_matches_ready_for_query() {
        let mut registry = registry();
        let statement = b"SELECT 1\0";
        let mut frame = vec![b'Q'];
        frame.extend_from_slice(&((statement.len() + 4) as u32).to_be_bytes());
        frame.extend_from_slice(statement);
        let event = raw_event(5432, &frame, frame.len() as u32);
        assert!(handle_at(&mut registry, &event, 5_000).is_empty());

        // CommandComplete is response payload; ReadyForQuery closes the batch.
        let mut response_payload = Vec::new();
        response_payload.push(b'C');
        response_payload.extend_from_slice(&13_u32.to_be_bytes());
        response_payload.extend_from_slice(b"SELECT 1\0");
        response_payload.push(b'Z');
        response_payload.extend_from_slice(&5_u32.to_be_bytes());
        response_payload.push(b'I');
        let response = response_event(5432, &response_payload);
        let signals = handle_at(&mut registry, &response, 8_000);

        assert_eq!(signals.len(), 1);
        let observation = observation(&signals[0]);
        assert_eq!(observation.protocol, ProtocolKind::Postgresql);
        assert_eq!(observation.method.as_deref(), Some("SELECT"));
        assert_eq!(observation.duration_nanos, Some(3_000));
        assert_eq!(registry.counters().response_continuations, 1);
        let serialized = serde_json::to_string(&signals[0]).expect("signal serializes");
        assert!(!serialized.contains("SELECT 1"));
    }

    #[test]
    fn mysql_response_pops_only_on_first_sequence_packet() {
        let mut registry = registry();
        // COM_QUERY packet, then a two-packet response: sequence 1 (OK-ish
        // header) pops the request, sequence 2 must be ignored.
        let request = [6, 0, 0, 0, 3, b's', b'e', b'l', b'e', b'c'];
        let event = raw_event(3306, &request, request.len() as u32);
        assert!(handle_at(&mut registry, &event, 5_000).is_empty());

        let mut response_payload = Vec::new();
        response_payload.extend_from_slice(&[5, 0, 0, 1, 0, 0, 0, 2, 0]);
        response_payload.extend_from_slice(&[1, 0, 0, 2, 0xfe]);
        let response = response_event(3306, &response_payload);
        let signals = handle_at(&mut registry, &response, 6_000);

        assert_eq!(signals.len(), 1);
        assert_eq!(registry.counters().response_continuations, 1);
        assert_eq!(registry.counters().orphan_responses, 0);
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
    fn pipelined_commands_match_pipelined_responses() {
        let mut registry = registry();
        let payload = b"*1\r\n$4\r\nPING\r\n*1\r\n$4\r\nPING\r\n";
        let event = raw_event(6379, payload, payload.len() as u32);
        assert!(handle_at(&mut registry, &event, 5_000).is_empty());

        let response = response_event(6379, b"+PONG\r\n+PONG\r\n");
        let signals = handle_at(&mut registry, &response, 5_400);

        assert_eq!(signals.len(), 2);
        for signal in &signals {
            assert_eq!(observation(signal).duration_nanos, Some(400));
        }
    }

    #[test]
    fn in_flight_overflow_emits_unmatched_observation() {
        let mut registry = registry();
        let payload = b"*1\r\n$4\r\nPING\r\n";
        let mut emitted = Vec::new();
        for index in 0..(MAX_IN_FLIGHT_REQUESTS + 1) {
            let event = raw_event(6379, payload, payload.len() as u32);
            emitted.extend(handle_at(&mut registry, &event, 5_000 + index as u64));
        }

        assert_eq!(emitted.len(), 1);
        let observation = observation(&emitted[0]);
        assert_eq!(observation.end_unix_nanos, None);
        assert_eq!(observation.duration_nanos, None);
        assert_eq!(registry.counters().unmatched_overflow, 1);
    }

    #[test]
    fn stale_in_flight_requests_expire_unmatched() {
        let mut registry = registry();
        let payload = b"*1\r\n$4\r\nPING\r\n";
        let event = raw_event(6379, payload, payload.len() as u32);
        assert!(handle_at(&mut registry, &event, 5_000).is_empty());

        let later = 5_000 + REQUEST_MATCH_TIMEOUT_NANOS + 1;
        let signals = handle_at(&mut registry, &event, later);

        assert_eq!(signals.len(), 1);
        assert_eq!(observation(&signals[0]).duration_nanos, None);
        assert_eq!(registry.counters().unmatched_expired, 1);
    }
}
