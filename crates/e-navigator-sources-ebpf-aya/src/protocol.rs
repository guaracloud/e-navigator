#![allow(dead_code)]

#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
mod database_response;
#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
mod mysql_transport;
#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
mod postgres_negotiation;
mod telemetry;

#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
use database_response::{DatabaseResponseContext, handle_database_response};
#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
use mysql_transport::{
    MysqlConnectionState, decode_mysql_compressed_transport_frames,
    handle_mysql_connection_request_frame, handle_mysql_connection_response_frame,
};
#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
use postgres_negotiation::{
    PostgresNegotiation, begin_postgres_negotiation, handle_postgres_negotiation_response,
};
pub(crate) use telemetry::ProtocolSurfaceCounters;

#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
use e_navigator_core::ProtocolSourceConfig;
#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
use e_navigator_protocol::{
    ProtocolExtractionConfig,
    discovery::classify_protocol_prefix,
    grpc_web::{parse_grpc_web_request, parse_grpc_web_response},
    http::{parse_http_request, parse_http_response},
    http2::{
        HTTP2_FLAG_END_STREAM, HTTP2_FRAME_TYPE_CONTINUATION, HTTP2_FRAME_TYPE_HEADERS,
        HpackDecoder, Http2HeaderBlockAssembler, parse_http2_frame_header,
        parse_http2_request_headers_frame, parse_http2_response_headers_frame,
    },
    kafka::{
        parse_kafka_request, parse_kafka_request_correlation_id,
        parse_kafka_response_correlation_id, parse_kafka_response_for_api_key,
    },
    mongodb::{
        MongodbResponseLifecycle, MongodbResponseProgress, parse_mongodb_message,
        parse_mongodb_response,
    },
    mysql::{
        MysqlClientHandshakeResponse, MysqlClientPacketProgress, MysqlCompressionAlgorithm,
        MysqlLogicalPacketProgress, MysqlResponseLifecycle, MysqlResponseProgress,
        MysqlServerGreeting, decode_mysql_compressed_packet, mysql_requested_compression,
        negotiate_mysql_compression, parse_mysql_client_handshake_response, parse_mysql_command,
        parse_mysql_command_prefix, parse_mysql_packet_metadata, parse_mysql_response,
        parse_mysql_server_greeting,
    },
    nats::parse_nats_command,
    postgres::{
        PostgresRequestLifecycle, PostgresRequestProgress, PostgresSimpleQueryLifecycle,
        PostgresSimpleQueryProgress, PostgresStartupKind, PostgresStartupLifecycle,
        PostgresStartupProgress, parse_postgres_message, parse_postgres_response,
        parse_postgres_startup_message,
    },
    redis::{
        RedisResponseLifecycle, RedisResponseProgress, RedisResponseRole, RedisSubscriptionState,
        parse_redis_command, parse_redis_response, redis_connection_response_role,
        redis_response_role,
    },
    stream::{
        ProtocolStreamDecoder, StreamDecodeLimits, StreamDirection, StreamFrame, StreamProtocol,
    },
    websocket::{WebSocketDirection, is_websocket_upgrade_request, parse_websocket_frame},
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
pub(crate) const RAW_PROTOCOL_ROLE_CLIENT: u32 = 0;
#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
pub(crate) const RAW_PROTOCOL_ROLE_SERVER: u32 = 1;
#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
pub(crate) const RAW_PROTOCOL_AF_INET: u32 = 2;
#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
pub(crate) const RAW_PROTOCOL_AF_INET6: u32 = 10;
#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
pub(crate) const MAX_IN_FLIGHT_REQUESTS: usize = 32;
#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
pub(crate) const REQUEST_MATCH_TIMEOUT_NANOS: u64 = 30_000_000_000;
#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
const POSTGRES_SKIPPED_AFTER_ERROR_WARNING: &str = "postgres_skipped_after_error";
#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
const REDIS_AMBIGUOUS_SUBSCRIPTION_WARNING: &str = "redis_ambiguous_subscription_state";
#[cfg(any(target_os = "linux", test))]
const PERF_BUFFER_PAGE_COUNT: usize = 64;
#[cfg(any(target_os = "linux", test))]
const RAW_SAMPLE_CHANNEL_CAPACITY: usize = 1024;
/// Bounds the cross-CPU merge queue. Reaching the bound flushes the oldest
/// sample instead of dropping it; under normal operation per-CPU poll
/// watermarks keep the queue near one poll interval of traffic.
#[cfg(any(target_os = "linux", test))]
pub(crate) const PROTOCOL_REORDER_MAX_PENDING_SAMPLES: usize = RAW_SAMPLE_CHANNEL_CAPACITY * 8;
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
#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
const MAX_PROC_NET_BYTES: u64 = 2 * 1024 * 1024;
#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
const MAX_PROC_NET_LINES: usize = 65_536;
#[cfg(any(target_os = "linux", test))]
const MAX_EXISTING_LISTENER_PROCESSES: usize = 4_096;
#[cfg(any(target_os = "linux", test))]
const MAX_EXISTING_LISTENER_FDS_PER_PROCESS: usize = 1_024;
#[cfg(any(target_os = "linux", test))]
const MAX_EXISTING_LISTENERS: usize = 4_096;

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
    pub role: u32,
    pub family: u32,
    pub remote_port_be: u16,
    pub local_port_be: u16,
    pub remote_addr_v4: u32,
    pub local_addr_v4: u32,
    pub remote_addr_v6: [u8; 16],
    pub local_addr_v6: [u8; 16],
    pub timestamp_unix_nanos: u64,
    pub connection_started_at_nanos: u64,
    pub payload_len: u32,
    pub payload_total_len: u32,
    pub payload_offset: u32,
    pub payload_captured_len: u32,
    pub command: [u8; 16],
    pub payload: [u8; RAW_PROTOCOL_DATA_BYTES],
}

/// Message sent by each per-CPU perf reader to the single stream decoder.
/// A poll watermark means that the reader has drained every event that was
/// visible before `timestamp_monotonic_nanos`.
#[cfg(any(target_os = "linux", test))]
#[derive(Clone, Copy)]
// Boxing the sample variant would restore one heap allocation per captured
// event, defeating InlineSample's allocation-free reader handoff.
#[allow(clippy::large_enum_variant)]
pub(crate) enum ProtocolPerfMessage {
    Sample(crate::perf_sample::InlineSample),
    Watermark {
        reader_index: usize,
        timestamp_monotonic_nanos: u64,
    },
}

#[cfg(any(target_os = "linux", test))]
#[derive(Clone, Copy)]
struct PendingProtocolSample {
    timestamp_monotonic_nanos: u64,
    sequence: u64,
    sample: crate::perf_sample::InlineSample,
}

#[cfg(any(target_os = "linux", test))]
impl PartialEq for PendingProtocolSample {
    fn eq(&self, other: &Self) -> bool {
        (self.timestamp_monotonic_nanos, self.sequence)
            == (other.timestamp_monotonic_nanos, other.sequence)
    }
}

#[cfg(any(target_os = "linux", test))]
impl Eq for PendingProtocolSample {}

#[cfg(any(target_os = "linux", test))]
impl PartialOrd for PendingProtocolSample {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

#[cfg(any(target_os = "linux", test))]
impl Ord for PendingProtocolSample {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        // BinaryHeap is a max-heap. Reverse both keys so pop() returns the
        // earliest kernel timestamp while preserving same-syscall segment
        // arrival order for equal timestamps.
        other
            .timestamp_monotonic_nanos
            .cmp(&self.timestamp_monotonic_nanos)
            .then_with(|| other.sequence.cmp(&self.sequence))
    }
}

/// Bounded k-way merge for samples read from independent per-CPU perf rings.
#[cfg(any(target_os = "linux", test))]
pub(crate) struct ProtocolSampleOrder {
    reader_watermarks: Vec<Option<u64>>,
    pending: std::collections::BinaryHeap<PendingProtocolSample>,
    next_sequence: u64,
    max_pending_samples: usize,
}

#[cfg(any(target_os = "linux", test))]
impl ProtocolSampleOrder {
    pub(crate) fn new(reader_count: usize, max_pending_samples: usize) -> Self {
        Self {
            reader_watermarks: vec![None; reader_count],
            pending: std::collections::BinaryHeap::new(),
            next_sequence: 0,
            max_pending_samples: max_pending_samples.max(1),
        }
    }

    /// Queues a sample and returns the oldest one only when the hard bound
    /// requires an early flush. No captured sample is discarded.
    pub(crate) fn push_sample(
        &mut self,
        sample: crate::perf_sample::InlineSample,
    ) -> Option<crate::perf_sample::InlineSample> {
        let timestamp_monotonic_nanos = protocol_sample_timestamp(&sample).unwrap_or(0);
        let sequence = self.next_sequence;
        self.next_sequence = self.next_sequence.wrapping_add(1);
        self.pending.push(PendingProtocolSample {
            timestamp_monotonic_nanos,
            sequence,
            sample,
        });
        (self.pending.len() > self.max_pending_samples)
            .then(|| self.pending.pop().map(|pending| pending.sample))
            .flatten()
    }

    pub(crate) fn update_watermark(&mut self, reader_index: usize, timestamp_monotonic_nanos: u64) {
        if let Some(watermark) = self.reader_watermarks.get_mut(reader_index) {
            *watermark = Some(watermark.map_or(timestamp_monotonic_nanos, |current| {
                current.max(timestamp_monotonic_nanos)
            }));
        }
    }

    pub(crate) fn pop_ready(&mut self) -> Option<crate::perf_sample::InlineSample> {
        // `None` sorts before `Some`, so no sample is ready until every
        // reader has completed at least one poll.
        let global_watermark = self.reader_watermarks.iter().copied().min()??;
        self.pending
            .peek()
            .is_some_and(|pending| pending.timestamp_monotonic_nanos <= global_watermark)
            .then(|| self.pending.pop().map(|pending| pending.sample))
            .flatten()
    }

    pub(crate) fn pop_oldest(&mut self) -> Option<crate::perf_sample::InlineSample> {
        self.pending.pop().map(|pending| pending.sample)
    }
}

#[cfg(any(target_os = "linux", test))]
pub(crate) fn protocol_sample_timestamp(sample: &crate::perf_sample::InlineSample) -> Option<u64> {
    let bytes = sample.as_bytes();
    (bytes.len() >= core::mem::size_of::<RawProtocolDataEvent>()).then(|| {
        let raw =
            unsafe { core::ptr::read_unaligned(bytes.as_ptr().cast::<RawProtocolDataEvent>()) };
        raw.timestamp_unix_nanos
    })
}

#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawProtocolInvalidSampleMetadata {
    pid: u32,
    uid: u32,
    cgroup_id: u64,
    fd: i32,
    direction: u32,
    role: u32,
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
            role: raw.role,
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
    InvalidRole {
        sample: RawProtocolInvalidSampleMetadata,
    },
    UnresolvedServerPort {
        sample: RawProtocolInvalidSampleMetadata,
    },
    UnmappedPort {
        sample: RawProtocolInvalidSampleMetadata,
    },
}

#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
impl RawProtocolDecodeError {
    pub(crate) fn reason_name(self) -> &'static str {
        match self {
            Self::RawSampleTooShort => "raw_sample_too_short",
            Self::InvalidPayloadLength { .. } => "invalid_payload_length",
            Self::InvalidDirection { .. } => "invalid_direction",
            Self::InvalidRole { .. } => "invalid_role",
            Self::UnresolvedServerPort { .. } => "unresolved_server_port",
            Self::UnmappedPort { .. } => "unmapped_port",
        }
    }

    pub(crate) fn is_filtered_sample(self) -> bool {
        matches!(self, Self::UnmappedPort { .. })
    }

    fn sample_metadata(self) -> Option<RawProtocolInvalidSampleMetadata> {
        match self {
            Self::RawSampleTooShort => None,
            Self::InvalidPayloadLength { sample } => Some(sample),
            Self::InvalidDirection { sample } => Some(sample),
            Self::InvalidRole { sample } => Some(sample),
            Self::UnresolvedServerPort { sample } => Some(sample),
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
    pub kafka_correlation_mismatches: u64,
    pub mongodb_correlation_mismatches: u64,
    pub discovered_connections: u64,
    pub discovery_unclassified_events: u64,
    pub discovery_candidate_evictions: u64,
    pub response_continuations: u64,
    pub unmatched_overflow: u64,
    pub unmatched_expired: u64,
    pub unmatched_evicted: u64,
    pub segment_gaps: u64,
    pub websocket_upgrades: u64,
    pub websocket_frames: u64,
    pub websocket_transition_rejections: u64,
    pub grpc_web_requests: u64,
    pub redis_ambiguous_state_transitions: u64,
    pub postgres_skipped_requests: u64,
    pub postgres_startup_auth_messages: u64,
    pub postgres_encryption_negotiation_accepted: u64,
    pub postgres_encryption_negotiation_rejected: u64,
    pub postgres_negotiation_failures: u64,
    pub postgres_encrypted_transport_events: u64,
    pub postgres_copy_ignored_controls: u64,
    pub mysql_local_infile_packets: u64,
    pub mysql_local_infile_bytes: u64,
    pub mysql_logical_request_continuations: u64,
    pub mysql_logical_response_continuations: u64,
    pub mysql_logical_sequence_failures: u64,
    pub mysql_server_greetings: u64,
    pub mysql_client_handshakes: u64,
    pub mysql_auth_packets: u64,
    pub mysql_compression_zlib_connections: u64,
    pub mysql_compression_zstd_rejections: u64,
    pub mysql_compression_unverified_rejections: u64,
    pub mysql_compressed_packets: u64,
    pub mysql_compression_failures: u64,
    pub mysql_compression_opaque_events: u64,
    pub mysql_handshake_failures: u64,
    pub mongodb_fire_and_forget_requests: u64,
    pub mongodb_response_continuations: u64,
    pub mongodb_lifecycle_failures: u64,
}

#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
impl ProtocolRegistryCounters {
    pub(crate) fn protocol_surface_counts(self) -> ProtocolSurfaceCounters {
        self.into()
    }
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
    source: &'static str,
    pid: u32,
    uid: u32,
    cgroup_id: u64,
    role: u32,
    family: u32,
    remote_port_be: u16,
    local_port_be: u16,
    remote_addr_v4: u32,
    local_addr_v4: u32,
    remote_addr_v6: [u8; 16],
    local_addr_v6: [u8; 16],
    connection_started_at_nanos: u64,
    command: [u8; 16],
    container: Option<ContainerContext>,
}

#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
impl ObservationContext {
    fn from_raw(
        raw: &RawProtocolDataEvent,
        procfs_root: &std::path::Path,
        source: &'static str,
    ) -> Self {
        Self {
            source,
            pid: raw.pid,
            uid: raw.uid,
            cgroup_id: raw.cgroup_id,
            role: raw.role,
            family: raw.family,
            remote_port_be: raw.remote_port_be,
            local_port_be: raw.local_port_be,
            remote_addr_v4: raw.remote_addr_v4,
            local_addr_v4: raw.local_addr_v4,
            remote_addr_v6: raw.remote_addr_v6,
            local_addr_v6: raw.local_addr_v6,
            connection_started_at_nanos: raw.connection_started_at_nanos,
            command: raw.command,
            container: crate::procfs::container_from_pid_cgroup(procfs_root, raw.pid),
        }
    }

    fn matches_connection(&self, raw: &RawProtocolDataEvent) -> bool {
        self.pid == raw.pid
            && self.uid == raw.uid
            && self.cgroup_id == raw.cgroup_id
            && self.role == raw.role
            && self.family == raw.family
            && self.remote_port_be == raw.remote_port_be
            && self.local_port_be == raw.local_port_be
            && self.remote_addr_v4 == raw.remote_addr_v4
            && self.local_addr_v4 == raw.local_addr_v4
            && self.remote_addr_v6 == raw.remote_addr_v6
            && self.local_addr_v6 == raw.local_addr_v6
            && self.connection_started_at_nanos == raw.connection_started_at_nanos
    }
}

#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
#[derive(Debug)]
struct InFlightRequest {
    parsed: ParsedRequestFrame,
    started_unix_nanos: u64,
    kafka_api_key: i16,
    kafka_api_version: i16,
    kafka_correlation_id: Option<i32>,
    mongodb_response: Option<MongodbResponseLifecycle>,
    mysql_response: Option<MysqlResponseLifecycle>,
    redis_response: Option<RedisResponseLifecycle>,
    postgres_simple_response: Option<PostgresSimpleQueryLifecycle>,
    postgres_request_response: Option<PostgresRequestLifecycle>,
    postgres_startup_response: Option<PostgresStartupLifecycle>,
}

#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
#[derive(Debug)]
struct Http2InFlightRequests {
    entries: Vec<(u32, InFlightRequest)>,
}

#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
impl Default for Http2InFlightRequests {
    fn default() -> Self {
        Self {
            entries: Vec::with_capacity(MAX_IN_FLIGHT_REQUESTS),
        }
    }
}

#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
impl Http2InFlightRequests {
    fn len(&self) -> usize {
        self.entries.len()
    }

    fn insert(&mut self, stream_id: u32, request: InFlightRequest) {
        match self
            .entries
            .binary_search_by_key(&stream_id, |(entry_stream_id, _)| *entry_stream_id)
        {
            Ok(index) => self.entries[index].1 = request,
            Err(index) => self.entries.insert(index, (stream_id, request)),
        }
    }

    fn remove(&mut self, stream_id: u32) -> Option<InFlightRequest> {
        self.entries
            .binary_search_by_key(&stream_id, |(entry_stream_id, _)| *entry_stream_id)
            .ok()
            .map(|index| self.entries.remove(index).1)
    }

    fn pop_first(&mut self) -> Option<InFlightRequest> {
        (!self.entries.is_empty()).then(|| self.entries.remove(0).1)
    }
}

#[cfg(feature = "fuzzing")]
pub fn bench_http2_in_flight_index_cycle() -> u64 {
    fn request(stream_id: u32) -> InFlightRequest {
        InFlightRequest {
            parsed: ParsedRequestFrame {
                protocol: ProtocolKind::Grpc,
                operation: None,
                status_code: None,
                trace_id: None,
                span_id: None,
                warning: None,
                attributes: Vec::new(),
                websocket_upgrade: false,
            },
            started_unix_nanos: u64::from(stream_id),
            kafka_api_key: -1,
            kafka_api_version: -1,
            kafka_correlation_id: None,
            mongodb_response: None,
            mysql_response: None,
            redis_response: None,
            postgres_simple_response: None,
            postgres_request_response: None,
            postgres_startup_response: None,
        }
    }

    let mut streams = Http2InFlightRequests::default();
    for stream_id in (1..=63).step_by(2) {
        streams.insert(stream_id, request(stream_id));
    }
    let mut checksum = 0_u64;
    for stream_id in (1..=63).step_by(2) {
        if let Some(entry) = streams.remove(stream_id) {
            checksum = checksum.wrapping_add(entry.started_unix_nanos);
        }
        let replacement = stream_id + 64;
        streams.insert(replacement, request(replacement));
    }
    while let Some(entry) = streams.pop_first() {
        checksum = checksum.wrapping_add(entry.started_unix_nanos);
    }
    checksum
}

#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
#[derive(Debug)]
struct Http2ConnectionState {
    request_hpack: HpackDecoder,
    response_hpack: HpackDecoder,
    request_headers: Http2HeaderBlockAssembler,
    response_headers: Http2HeaderBlockAssembler,
    request_headers_started_unix_nanos: Option<u64>,
    streams: Http2InFlightRequests,
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
struct ProtocolDiscoveryCandidate {
    context: ObservationContext,
    direction: StreamDirection,
    bytes: Vec<u8>,
    started_unix_nanos: u64,
    last_seen_unix_nanos: u64,
    segments: Option<SegmentProgress>,
}

#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
#[derive(Debug)]
struct ProtocolDiscoveryMatch {
    protocol: StreamProtocol,
    direction: StreamDirection,
    bytes: Vec<u8>,
    started_unix_nanos: u64,
    context: ObservationContext,
}

#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
#[derive(Debug)]
struct ConnectionStream {
    protocol: StreamProtocol,
    request_decoder: ProtocolStreamDecoder,
    response_decoder: ProtocolStreamDecoder,
    request_segments: Option<SegmentProgress>,
    response_segments: Option<SegmentProgress>,
    request_frame_started_unix_nanos: Option<u64>,
    response_frame_started_unix_nanos: Option<u64>,
    in_flight: std::collections::VecDeque<InFlightRequest>,
    http2: Option<Http2ConnectionState>,
    postgres_discarding_until_sync: bool,
    postgres_negotiation: Option<PostgresNegotiation>,
    postgres_transport_opaque: bool,
    postgres_copy_in: bool,
    redis_subscription: RedisSubscriptionState,
    redis_transport_opaque: bool,
    mysql: Option<MysqlConnectionState>,
    context: ObservationContext,
    last_seen_unix_nanos: u64,
}

/// Per-connection reassembly and parsing state for the protocol source.
#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
#[derive(Debug)]
pub struct ProtocolStreamRegistry {
    source: &'static str,
    host: Option<String>,
    procfs_root: std::path::PathBuf,
    ports: ProtocolPortMap,
    discovery_enabled: bool,
    extraction: ProtocolExtractionConfig,
    limits: StreamDecodeLimits,
    max_tracked_connections: usize,
    connections: std::collections::HashMap<ConnectionId, ConnectionStream>,
    discovery_candidates: std::collections::HashMap<ConnectionId, ProtocolDiscoveryCandidate>,
    frames: Vec<StreamFrame>,
    mysql_frames: Vec<StreamFrame>,
    counters: ProtocolRegistryCounters,
}

#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
impl ProtocolStreamRegistry {
    pub fn new(
        host: Option<String>,
        procfs_root: std::path::PathBuf,
        config: &ProtocolSourceConfig,
    ) -> Self {
        Self::new_with_source(host, procfs_root, config, "source.aya_protocol")
    }

    pub(crate) fn new_with_source(
        host: Option<String>,
        procfs_root: std::path::PathBuf,
        config: &ProtocolSourceConfig,
        source: &'static str,
    ) -> Self {
        Self {
            source,
            host,
            procfs_root,
            ports: ProtocolPortMap::from_config(config),
            discovery_enabled: config.discovery_enabled,
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
            discovery_candidates: std::collections::HashMap::new(),
            frames: Vec::new(),
            mysql_frames: Vec::new(),
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

        let mut raw =
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

        if raw.role != RAW_PROTOCOL_ROLE_CLIENT && raw.role != RAW_PROTOCOL_ROLE_SERVER {
            return Err(RawProtocolDecodeError::InvalidRole {
                sample: RawProtocolInvalidSampleMetadata::from_raw(&raw),
            });
        }

        let connection_id = ConnectionId {
            pid: raw.pid,
            fd: raw.fd,
        };
        if raw.role == RAW_PROTOCOL_ROLE_SERVER && raw.local_port_be == 0 {
            let local_port_be = self
                .connections
                .get(&connection_id)
                .map(|stream| stream.context.local_port_be)
                .filter(|port| *port != 0)
                .or_else(|| {
                    resolve_server_local_port(&self.procfs_root, raw.pid, raw.fd).map(u16::to_be)
                });
            let Some(local_port_be) = local_port_be else {
                return Err(RawProtocolDecodeError::UnresolvedServerPort {
                    sample: RawProtocolInvalidSampleMetadata::from_raw(&raw),
                });
            };
            raw.local_port_be = local_port_be;
        }

        if self
            .connections
            .get(&connection_id)
            .is_some_and(|stream| !stream.context.matches_connection(&raw))
        {
            self.evict_connection(connection_id, signals);
        }

        let capture_port = if raw.role == RAW_PROTOCOL_ROLE_SERVER {
            u16::from_be(raw.local_port_be)
        } else {
            u16::from_be(raw.remote_port_be)
        };

        // NATS commands are fire-and-forget; server-to-client traffic is
        // asynchronous message delivery, not per-request responses.
        let is_request_direction = (raw.role == RAW_PROTOCOL_ROLE_CLIENT
            && raw.direction == RAW_PROTOCOL_DIRECTION_WRITE)
            || (raw.role == RAW_PROTOCOL_ROLE_SERVER
                && raw.direction == RAW_PROTOCOL_DIRECTION_READ);

        let direction = if is_request_direction {
            StreamDirection::Request
        } else {
            StreamDirection::Response
        };
        let configured_protocol = self.ports.lookup(capture_port);
        let existing_protocol = self
            .connections
            .get(&connection_id)
            .map(|stream| stream.protocol);
        let mut discovery_match = None;
        let protocol = if let Some(protocol) = existing_protocol.or(configured_protocol) {
            protocol
        } else if self.discovery_enabled {
            let payload = &raw.payload[..raw.payload_len as usize];
            let Some(discovered) = self.discover_protocol(
                connection_id,
                &raw,
                payload,
                direction,
                observed_unix_nanos,
            ) else {
                self.counters.discovery_unclassified_events += 1;
                return Ok(());
            };
            let protocol = discovered.protocol;
            discovery_match = Some(discovered);
            protocol
        } else {
            return Err(RawProtocolDecodeError::UnmappedPort {
                sample: RawProtocolInvalidSampleMetadata::from_raw(&raw),
            });
        };

        if !is_request_direction && protocol == StreamProtocol::Nats {
            self.counters.ignored_read_events += 1;
            return Ok(());
        }

        self.evict_if_needed(connection_id, signals);
        let limits = self.limits;
        let stream = self.connections.entry(connection_id).or_insert_with(|| {
            let context = discovery_match.as_ref().map_or_else(
                || ObservationContext::from_raw(&raw, &self.procfs_root, self.source),
                |discovered| discovered.context.clone(),
            );
            ConnectionStream {
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
                request_frame_started_unix_nanos: None,
                response_frame_started_unix_nanos: None,
                in_flight: std::collections::VecDeque::new(),
                http2: (protocol == StreamProtocol::Http2).then(|| Http2ConnectionState {
                    request_hpack: HpackDecoder::new(),
                    response_hpack: HpackDecoder::new(),
                    request_headers: Http2HeaderBlockAssembler::new(),
                    response_headers: Http2HeaderBlockAssembler::new(),
                    request_headers_started_unix_nanos: None,
                    streams: Http2InFlightRequests::default(),
                }),
                postgres_discarding_until_sync: false,
                postgres_negotiation: None,
                postgres_transport_opaque: false,
                postgres_copy_in: false,
                redis_subscription: RedisSubscriptionState::None,
                redis_transport_opaque: false,
                mysql: (protocol == StreamProtocol::Mysql)
                    .then(|| MysqlConnectionState::new(limits)),
                context,
                last_seen_unix_nanos: observed_unix_nanos,
            }
        });
        if discovery_match.is_some() {
            self.counters.discovered_connections += 1;
        }
        stream.last_seen_unix_nanos = observed_unix_nanos;

        let payload = &raw.payload[..raw.payload_len as usize];
        if stream.protocol == StreamProtocol::Mysql
            && stream
                .mysql
                .as_ref()
                .is_some_and(MysqlConnectionState::is_opaque)
        {
            self.counters.mysql_compression_opaque_events += 1;
            return Ok(());
        }
        if stream.protocol == StreamProtocol::Postgresql && stream.postgres_transport_opaque {
            self.counters.postgres_encrypted_transport_events += 1;
            return Ok(());
        }
        if stream.protocol == StreamProtocol::Postgresql
            && !is_request_direction
            && let Some(negotiation) = stream.postgres_negotiation
        {
            let invalid_offset = raw.payload_offset != 0;
            let missing_payload = payload.is_empty() && raw.payload_total_len > 0;
            let invalid_prefix = payload.first().is_some_and(|response| {
                !negotiation.accepts(*response) && *response != b'N' && *response != b'E'
            });
            let invalid_single_byte_length = payload
                .first()
                .is_some_and(|response| negotiation.accepts(*response) || *response == b'N')
                && raw.payload_total_len != 1;
            if invalid_offset || missing_payload || invalid_prefix || invalid_single_byte_length {
                // PostgreSQL requires an exact one-byte negotiation response.
                // Treat missing, displaced, unexpected, or buffer-stuffed
                // bytes as ambiguous and stop parsing the raw socket.
                stream.postgres_negotiation = None;
                stream.postgres_transport_opaque = true;
                self.counters.postgres_negotiation_failures += 1;
                return Ok(());
            }
        }
        let mut frames = std::mem::take(&mut self.frames);
        frames.clear();
        let (decoder, pending_segments, pending_frame_started) = if is_request_direction {
            (
                &mut stream.request_decoder,
                &mut stream.request_segments,
                &mut stream.request_frame_started_unix_nanos,
            )
        } else {
            (
                &mut stream.response_decoder,
                &mut stream.response_segments,
                &mut stream.response_frame_started_unix_nanos,
            )
        };
        let input_started_unix_nanos = discovery_match
            .as_ref()
            .map_or(observed_unix_nanos, |discovered| {
                discovered.started_unix_nanos
            });
        let frame_started_unix_nanos = pending_frame_started.unwrap_or(input_started_unix_nanos);
        let complete_frames_before = decoder.stats().complete_frames;
        if let Some(discovered) = discovery_match {
            debug_assert_eq!(discovered.direction, direction);
            decoder.push_chunk(
                &discovered.bytes,
                discovered.bytes.len() as u64,
                &mut frames,
            );
        } else {
            feed_segment(
                decoder,
                pending_segments,
                &raw,
                payload,
                &mut self.counters,
                &mut frames,
            );
        }
        *pending_frame_started = if decoder.buffered_bytes() == 0 {
            None
        } else if decoder.stats().complete_frames > complete_frames_before {
            Some(input_started_unix_nanos)
        } else {
            Some(frame_started_unix_nanos)
        };

        let mut mysql_frames = std::mem::take(&mut self.mysql_frames);
        mysql_frames.clear();
        let compressed_transport_active = stream.protocol == StreamProtocol::Mysql
            && stream
                .mysql
                .as_ref()
                .is_some_and(MysqlConnectionState::is_compressed);
        let mut mysql_frame_started_unix_nanos = None;
        let decoded_transport = !compressed_transport_active
            || decode_mysql_compressed_transport_frames(
                stream,
                &frames,
                is_request_direction,
                frame_started_unix_nanos,
                &mut mysql_frames,
                &mut mysql_frame_started_unix_nanos,
                &mut self.counters,
            );
        let handled_frames = if compressed_transport_active {
            &mysql_frames
        } else {
            &frames
        };

        if !decoded_transport {
            frames.clear();
            self.frames = frames;
            mysql_frames.clear();
            self.mysql_frames = mysql_frames;
            return Ok(());
        }

        let handled_frame_started_unix_nanos = if compressed_transport_active {
            mysql_frame_started_unix_nanos.unwrap_or(frame_started_unix_nanos)
        } else {
            frame_started_unix_nanos
        };

        if stream.protocol == StreamProtocol::Http2 {
            handle_http2_frames(
                stream,
                handled_frames,
                is_request_direction,
                &self.extraction,
                &self.host,
                &mut self.counters,
                handled_frame_started_unix_nanos,
                signals,
            );
        } else if is_request_direction {
            handle_request_frames(
                stream,
                handled_frames,
                &self.extraction,
                &self.host,
                &mut self.counters,
                handled_frame_started_unix_nanos,
                signals,
            );
        } else {
            handle_response_frames(
                stream,
                handled_frames,
                &self.extraction,
                &self.host,
                &mut self.counters,
                handled_frame_started_unix_nanos,
                signals,
            );
        }
        frames.clear();
        self.frames = frames;
        mysql_frames.clear();
        self.mysql_frames = mysql_frames;
        Ok(())
    }

    fn discover_protocol(
        &mut self,
        connection_id: ConnectionId,
        raw: &RawProtocolDataEvent,
        payload: &[u8],
        direction: StreamDirection,
        observed_unix_nanos: u64,
    ) -> Option<ProtocolDiscoveryMatch> {
        if self
            .discovery_candidates
            .get(&connection_id)
            .is_some_and(|candidate| !candidate.context.matches_connection(raw))
        {
            self.discovery_candidates.remove(&connection_id);
        }
        if !self.discovery_candidates.contains_key(&connection_id)
            && self.discovery_candidates.len() >= self.max_tracked_connections
            && let Some(oldest) = self
                .discovery_candidates
                .iter()
                .min_by_key(|(_, candidate)| candidate.last_seen_unix_nanos)
                .map(|(id, _)| *id)
        {
            self.discovery_candidates.remove(&oldest);
            self.counters.discovery_candidate_evictions += 1;
        }

        let max_bytes = self
            .extraction
            .max_header_bytes
            .min(RAW_PROTOCOL_MAX_CAPTURE_BYTES as usize);
        let candidate = self
            .discovery_candidates
            .entry(connection_id)
            .or_insert_with(|| ProtocolDiscoveryCandidate {
                context: ObservationContext::from_raw(raw, &self.procfs_root, self.source),
                direction,
                bytes: Vec::new(),
                started_unix_nanos: observed_unix_nanos,
                last_seen_unix_nanos: observed_unix_nanos,
                segments: None,
            });
        candidate.last_seen_unix_nanos = observed_unix_nanos;
        if !append_discovery_payload(
            candidate,
            raw,
            payload,
            direction,
            observed_unix_nanos,
            max_bytes,
        ) {
            self.discovery_candidates.remove(&connection_id);
            return None;
        }

        let protocol = classify_protocol_prefix(&candidate.bytes, direction, &self.extraction)?;
        let candidate = self.discovery_candidates.remove(&connection_id)?;
        Some(ProtocolDiscoveryMatch {
            protocol,
            direction,
            bytes: candidate.bytes,
            started_unix_nanos: candidate.started_unix_nanos,
            context: candidate.context,
        })
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
        self.discovery_candidates.remove(&id);
        let Some(mut stream) = self.connections.remove(&id) else {
            return;
        };
        self.counters.evicted_connections += 1;
        if let Some(http2) = stream.http2.as_mut() {
            while let Some(entry) = http2.streams.pop_first() {
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

#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
fn append_discovery_payload(
    candidate: &mut ProtocolDiscoveryCandidate,
    raw: &RawProtocolDataEvent,
    payload: &[u8],
    direction: StreamDirection,
    observed_unix_nanos: u64,
    max_bytes: usize,
) -> bool {
    if candidate.direction != direction {
        candidate.direction = direction;
        candidate.bytes.clear();
        candidate.started_unix_nanos = observed_unix_nanos;
        candidate.segments = None;
    }
    if raw.payload_captured_len != raw.payload_total_len {
        return false;
    }

    let continues = candidate.segments.is_some_and(|progress| {
        raw.timestamp_unix_nanos == progress.timestamp_unix_nanos
            && raw.payload_offset == progress.next_offset
            && raw.payload_captured_len == progress.captured_len
            && raw.payload_total_len == progress.total_len
    });
    if raw.payload_offset == 0 {
        if candidate.segments.take().is_some() {
            candidate.bytes.clear();
            candidate.started_unix_nanos = observed_unix_nanos;
        }
    } else if !continues {
        return false;
    }

    let Some(new_len) = candidate.bytes.len().checked_add(payload.len()) else {
        return false;
    };
    if new_len > max_bytes {
        return false;
    }
    candidate.bytes.extend_from_slice(payload);

    let segment_end = raw.payload_offset.saturating_add(raw.payload_len);
    candidate.segments = (segment_end < raw.payload_captured_len).then_some(SegmentProgress {
        timestamp_unix_nanos: raw.timestamp_unix_nanos,
        next_offset: segment_end,
        captured_len: raw.payload_captured_len,
        total_len: raw.payload_total_len,
    });
    true
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
        if stream.protocol == StreamProtocol::Mysql
            && handle_mysql_connection_request_frame(stream, frame, extraction, counters)
        {
            continue;
        }
        if stream.protocol == StreamProtocol::WebSocket {
            emit_websocket_observation(
                frame,
                WebSocketDirection::ClientToServer,
                stream,
                extraction,
                host,
                counters,
                observed_unix_nanos,
                signals,
            );
            continue;
        }
        if stream.protocol == StreamProtocol::Mysql
            && stream.in_flight.back().is_some_and(|entry| {
                entry
                    .mysql_response
                    .as_ref()
                    .is_some_and(MysqlResponseLifecycle::owns_request_continuation)
            })
        {
            let (prefix, declared_len) = match frame {
                StreamFrame::Complete(bytes) => (bytes.as_slice(), bytes.len() as u64),
                StreamFrame::Truncated {
                    prefix,
                    declared_len,
                } => {
                    counters.truncated_frames += 1;
                    (prefix.as_slice(), *declared_len)
                }
                StreamFrame::ProtocolSwitch { .. } => {
                    counters.unparsed_frames += 1;
                    continue;
                }
            };
            let progress = stream
                .in_flight
                .back_mut()
                .and_then(|entry| entry.mysql_response.as_mut())
                .map(|lifecycle| lifecycle.observe_request_continuation(prefix, declared_len));
            match progress {
                Some(Ok(
                    MysqlLogicalPacketProgress::Continue | MysqlLogicalPacketProgress::Complete,
                )) => counters.mysql_logical_request_continuations += 1,
                Some(Err(_)) | None => {
                    counters.mysql_logical_sequence_failures += 1;
                    continue;
                }
            }

            let no_response_complete = stream.in_flight.back().is_some_and(|entry| {
                entry.mysql_response.as_ref().is_some_and(|lifecycle| {
                    !lifecycle.owns_request_continuation() && !lifecycle.expects_response()
                })
            });
            if no_response_complete && let Some(entry) = stream.in_flight.pop_back() {
                signals.push(build_observation(
                    host.clone(),
                    &stream.context,
                    entry.parsed,
                    entry.started_unix_nanos,
                    None,
                ));
            }
            continue;
        }
        if stream.protocol == StreamProtocol::Mysql
            && stream.in_flight.front().is_some_and(|entry| {
                entry
                    .mysql_response
                    .as_ref()
                    .is_some_and(MysqlResponseLifecycle::owns_local_infile_client_packets)
            })
        {
            let (prefix, declared_len) = match frame {
                StreamFrame::Complete(bytes) => (bytes.as_slice(), bytes.len() as u64),
                StreamFrame::Truncated {
                    prefix,
                    declared_len,
                } => {
                    counters.truncated_frames += 1;
                    (prefix.as_slice(), *declared_len)
                }
                StreamFrame::ProtocolSwitch { .. } => {
                    counters.unparsed_frames += 1;
                    continue;
                }
            };
            let Some(lifecycle) = stream
                .in_flight
                .front_mut()
                .and_then(|entry| entry.mysql_response.as_mut())
            else {
                counters.unparsed_frames += 1;
                continue;
            };
            let progress = lifecycle.observe_client_packet(prefix, declared_len);
            match progress {
                Ok(
                    MysqlClientPacketProgress::Continue | MysqlClientPacketProgress::UploadComplete,
                ) => {
                    counters.mysql_local_infile_packets += 1;
                    counters.mysql_local_infile_bytes += declared_len.saturating_sub(4);
                }
                Err(_) => counters.unparsed_frames += 1,
            }
            continue;
        }
        if stream.protocol == StreamProtocol::Mysql
            && matches!(frame, StreamFrame::Complete(bytes) if bytes == &[0, 0, 0, 0])
        {
            counters.unparsed_frames += 1;
            continue;
        }
        if stream.protocol == StreamProtocol::Postgresql
            && let StreamFrame::Complete(frame_bytes) = frame
        {
            if frame_bytes.first() == Some(&0)
                && let Ok(startup) = parse_postgres_startup_message(frame_bytes, extraction)
            {
                match startup.kind {
                    PostgresStartupKind::SslRequest => {
                        begin_postgres_negotiation(stream, PostgresNegotiation::Ssl, counters);
                        continue;
                    }
                    PostgresStartupKind::GssEncryptionRequest => {
                        begin_postgres_negotiation(
                            stream,
                            PostgresNegotiation::GssEncryption,
                            counters,
                        );
                        continue;
                    }
                    PostgresStartupKind::CancelRequest => {
                        let parsed = postgres_startup_request_frame(startup);
                        signals.push(build_observation(
                            host.clone(),
                            &stream.context,
                            parsed,
                            observed_unix_nanos,
                            None,
                        ));
                        continue;
                    }
                    PostgresStartupKind::Startup => {}
                }
            }

            if stream
                .in_flight
                .front()
                .is_some_and(|entry| entry.postgres_startup_response.is_some())
                && frame_bytes.first() == Some(&b'p')
            {
                // Password, SASL, GSS, and SSPI responses all use `p`; their
                // bodies are authentication secrets and belong to CONNECT.
                counters.postgres_startup_auth_messages += 1;
                continue;
            }

            if stream.postgres_copy_in {
                match frame_bytes.first() {
                    Some(b'S' | b'H') => {
                        counters.postgres_copy_ignored_controls += 1;
                        continue;
                    }
                    Some(b'c' | b'f') => stream.postgres_copy_in = false,
                    _ => {}
                }
            }
        }
        let (mut parsed, frame_bytes) = match frame {
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
            StreamFrame::Truncated {
                prefix,
                declared_len,
            } if stream.protocol == StreamProtocol::Mysql => {
                counters.truncated_frames += 1;
                match parse_mysql_command_prefix(prefix, *declared_len, extraction) {
                    Ok(parsed) => (
                        ParsedRequestFrame {
                            protocol: parsed.protocol,
                            operation: parsed.operation,
                            status_code: None,
                            trace_id: None,
                            span_id: None,
                            warning: parsed.warning,
                            attributes: parsed.attributes,
                            websocket_upgrade: false,
                        },
                        Some(prefix.as_slice()),
                    ),
                    Err(_) => {
                        counters.unparsed_frames += 1;
                        (
                            placeholder_request(stream.protocol, "truncated_request_frame"),
                            Some(prefix.as_slice()),
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
            StreamFrame::ProtocolSwitch { .. } => {
                counters.unparsed_frames += 1;
                continue;
            }
        };

        if parsed.protocol == ProtocolKind::Grpc
            && parsed.attributes.iter().any(|attribute| {
                attribute.key == "rpc.grpc.transport" && attribute.value == "grpc_web"
            })
        {
            counters.grpc_web_requests += 1;
        }

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
        if stream.protocol == StreamProtocol::Redis && stream.redis_transport_opaque {
            parsed
                .warning
                .get_or_insert_with(|| REDIS_AMBIGUOUS_SUBSCRIPTION_WARNING.to_string());
            signals.push(build_observation(
                host.clone(),
                &stream.context,
                parsed,
                observed_unix_nanos,
                None,
            ));
            continue;
        }

        let (kafka_api_key, kafka_api_version, kafka_correlation_id) = frame_bytes
            .filter(|_| stream.protocol == StreamProtocol::Kafka)
            .and_then(|frame| kafka_request_header_prefix(frame, extraction))
            .map_or((-1, -1, None), |(api_key, api_version, correlation_id)| {
                (api_key, api_version, Some(correlation_id))
            });
        let mongodb_response = frame_bytes
            .filter(|_| stream.protocol == StreamProtocol::Mongodb)
            .and_then(|frame| MongodbResponseLifecycle::from_request(frame, extraction).ok());
        let mysql_response = if stream.protocol == StreamProtocol::Mysql {
            match frame {
                StreamFrame::Complete(frame) => {
                    MysqlResponseLifecycle::from_request(frame, extraction).ok()
                }
                StreamFrame::Truncated {
                    prefix,
                    declared_len,
                } => MysqlResponseLifecycle::from_request_prefix(prefix, *declared_len, extraction)
                    .ok(),
                StreamFrame::ProtocolSwitch { .. } => None,
            }
        } else {
            None
        };
        let redis_response = frame_bytes
            .filter(|_| stream.protocol == StreamProtocol::Redis)
            .and_then(|frame| RedisResponseLifecycle::from_request(frame, extraction).ok());
        let postgres_simple_response = frame_bytes
            .filter(|_| stream.protocol == StreamProtocol::Postgresql)
            .and_then(|frame| PostgresSimpleQueryLifecycle::from_request(frame, extraction).ok());
        let postgres_request_response = frame_bytes
            .filter(|_| stream.protocol == StreamProtocol::Postgresql)
            .and_then(|frame| PostgresRequestLifecycle::from_request(frame, extraction).ok());
        let postgres_startup_response = frame_bytes
            .filter(|_| stream.protocol == StreamProtocol::Postgresql)
            .and_then(|frame| PostgresStartupLifecycle::from_request(frame, extraction).ok());
        let postgres_is_sync = postgres_request_response
            .as_ref()
            .is_some_and(PostgresRequestLifecycle::is_sync);
        if stream.protocol == StreamProtocol::Postgresql
            && stream.postgres_discarding_until_sync
            && !postgres_is_sync
        {
            parsed
                .warning
                .get_or_insert_with(|| POSTGRES_SKIPPED_AFTER_ERROR_WARNING.to_string());
            counters.postgres_skipped_requests += 1;
            signals.push(build_observation(
                host.clone(),
                &stream.context,
                parsed,
                observed_unix_nanos,
                None,
            ));
            continue;
        }
        if stream.protocol == StreamProtocol::Postgresql
            && postgres_simple_response.is_none()
            && postgres_request_response.is_none()
            && postgres_startup_response.is_none()
        {
            signals.push(build_observation(
                host.clone(),
                &stream.context,
                parsed,
                observed_unix_nanos,
                None,
            ));
            continue;
        }
        let mongodb_fire_and_forget = mongodb_response
            .as_ref()
            .is_some_and(|lifecycle| !lifecycle.expects_response());
        let redis_without_correlated_response = redis_response
            .as_ref()
            .is_some_and(|lifecycle| !lifecycle.expects_response());
        if mysql_response.as_ref().is_some_and(|lifecycle| {
            !lifecycle.expects_response() && !lifecycle.owns_request_continuation()
        }) || redis_response
            .as_ref()
            .is_some_and(|lifecycle| !lifecycle.expects_response())
            || postgres_request_response
                .as_ref()
                .is_some_and(|lifecycle| !lifecycle.expects_response())
            || mongodb_fire_and_forget
        {
            if mongodb_fire_and_forget {
                counters.mongodb_fire_and_forget_requests += 1;
            }
            if redis_without_correlated_response {
                stream.redis_transport_opaque = true;
                counters.redis_ambiguous_state_transitions += 1;
                while let Some(mut entry) = stream.in_flight.pop_front() {
                    entry
                        .parsed
                        .warning
                        .get_or_insert_with(|| REDIS_AMBIGUOUS_SUBSCRIPTION_WARNING.to_string());
                    signals.push(build_observation(
                        host.clone(),
                        &stream.context,
                        entry.parsed,
                        entry.started_unix_nanos,
                        None,
                    ));
                }
                parsed
                    .warning
                    .get_or_insert_with(|| REDIS_AMBIGUOUS_SUBSCRIPTION_WARNING.to_string());
            }
            signals.push(build_observation(
                host.clone(),
                &stream.context,
                parsed,
                observed_unix_nanos,
                None,
            ));
            continue;
        }

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
            kafka_correlation_id,
            mongodb_response,
            mysql_response,
            redis_response,
            postgres_simple_response,
            postgres_request_response,
            postgres_startup_response,
        });
        if postgres_is_sync {
            stream.postgres_discarding_until_sync = false;
        }
    }
}

/// How a response frame interacts with the in-flight request queue.
#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ResponseAction {
    /// The frame completes exactly the oldest in-flight request.
    PopOne,
    /// The frame continues an already-completed or in-progress response and
    /// must not consume a queued request.
    Ignore,
}

/// Multi-frame response protocols need per-frame queue policies so latency
/// is never attributed to the wrong request.
#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
fn response_action(protocol: StreamProtocol, frame: &[u8]) -> ResponseAction {
    match protocol {
        // HTTP/2, Kafka, MongoDB, and MySQL use dedicated matching/lifecycle
        // paths, never this generic FIFO policy.
        StreamProtocol::Http2
        | StreamProtocol::Kafka
        | StreamProtocol::Mongodb
        | StreamProtocol::Mysql
        | StreamProtocol::MysqlCompressed
        | StreamProtocol::WebSocket => ResponseAction::Ignore,
        // HTTP/1 is strict request/response over one connection; each framed
        // response completes exactly the oldest in-flight request.
        StreamProtocol::Http1 => ResponseAction::PopOne,
        StreamProtocol::Redis => match redis_response_role(frame) {
            Ok(RedisResponseRole::Reply) => ResponseAction::PopOne,
            Ok(RedisResponseRole::Push | RedisResponseRole::Attribute) | Err(_) => {
                ResponseAction::Ignore
            }
        },
        // Every parsed PostgreSQL request uses a dedicated lifecycle. These
        // asynchronous frames are not responses to the queue front; any
        // other frame without lifecycle state is an orphan candidate.
        StreamProtocol::Postgresql => match frame.first() {
            Some(b'A' | b'K' | b'N' | b'R' | b'S' | b'v') => ResponseAction::Ignore,
            _ => ResponseAction::PopOne,
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
        if let StreamFrame::ProtocolSwitch {
            frame: transition_frame,
            protocol: StreamProtocol::WebSocket,
        } = frame
        {
            let valid_upgrade = stream
                .in_flight
                .front()
                .is_some_and(|entry| entry.parsed.websocket_upgrade);
            if !valid_upgrade || stream.protocol != StreamProtocol::Http1 {
                counters.websocket_transition_rejections += 1;
                stream
                    .response_decoder
                    .switch_protocol(StreamProtocol::Http1);
                continue;
            }

            let Some(entry) = stream.in_flight.pop_front() else {
                counters.websocket_transition_rejections += 1;
                stream
                    .response_decoder
                    .switch_protocol(StreamProtocol::Http1);
                continue;
            };
            let mut parsed = entry.parsed;
            match parse_http1_response_frame(transition_frame, extraction) {
                Ok(response) => {
                    counters.matched_responses += 1;
                    parsed.status_code = response.signal_status_code;
                    merge_response_attributes(&mut parsed, &response, extraction.max_attributes);
                }
                Err(reason) => {
                    counters.unparsed_responses += 1;
                    parsed.warning.get_or_insert_with(|| reason.to_string());
                }
            }
            signals.push(build_observation(
                host.clone(),
                &stream.context,
                parsed,
                entry.started_unix_nanos,
                Some(observed_unix_nanos),
            ));
            stream.protocol = StreamProtocol::WebSocket;
            stream
                .request_decoder
                .switch_protocol(StreamProtocol::WebSocket);
            counters.websocket_upgrades += 1;
            continue;
        }
        if matches!(frame, StreamFrame::ProtocolSwitch { .. }) {
            counters.websocket_transition_rejections += 1;
            continue;
        }
        if stream.protocol == StreamProtocol::Mysql
            && handle_mysql_connection_response_frame(stream, frame, extraction, counters)
        {
            continue;
        }
        if stream.protocol == StreamProtocol::WebSocket {
            emit_websocket_observation(
                frame,
                WebSocketDirection::ServerToClient,
                stream,
                extraction,
                host,
                counters,
                observed_unix_nanos,
                signals,
            );
            continue;
        }
        let (frame_bytes, truncated, declared_len) = match frame {
            StreamFrame::Complete(frame_bytes) => {
                (frame_bytes.as_slice(), false, frame_bytes.len() as u64)
            }
            StreamFrame::Truncated {
                prefix,
                declared_len,
            } => {
                counters.truncated_frames += 1;
                (prefix.as_slice(), true, *declared_len)
            }
            StreamFrame::ProtocolSwitch { .. } => continue,
        };

        if stream.protocol == StreamProtocol::Postgresql
            && handle_postgres_negotiation_response(stream, frame_bytes, truncated, counters)
        {
            continue;
        }

        if stream.protocol == StreamProtocol::Kafka {
            handle_kafka_response_frame(
                stream,
                frame_bytes,
                truncated,
                extraction,
                host,
                counters,
                observed_unix_nanos,
                signals,
            );
            continue;
        }
        if stream.protocol == StreamProtocol::Mongodb {
            handle_mongodb_response_frame(
                stream,
                frame_bytes,
                truncated,
                extraction,
                host,
                counters,
                observed_unix_nanos,
                signals,
            );
            continue;
        }
        if handle_database_response(
            stream,
            frame_bytes,
            truncated,
            declared_len,
            &mut DatabaseResponseContext {
                extraction,
                host,
                counters,
                observed_unix_nanos,
                signals,
            },
        ) {
            continue;
        }

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
            let Some(front) = stream.in_flight.front() else {
                counters.orphan_responses += 1;
                continue;
            };
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
                    if let Some(protocol) = response.protocol {
                        parsed.protocol = protocol;
                    }
                    parsed.status_code = response.signal_status_code;
                    merge_response_attributes(&mut parsed, response, extraction.max_attributes);
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

/// Completes the Kafka request identified by the response correlation id.
/// A missing or ambiguous match is deliberately non-destructive: retaining
/// the queue is safer than attributing the response to the wrong request.
#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
#[allow(clippy::too_many_arguments)]
fn handle_kafka_response_frame(
    stream: &mut ConnectionStream,
    frame: &[u8],
    truncated: bool,
    extraction: &ProtocolExtractionConfig,
    host: &Option<String>,
    counters: &mut ProtocolRegistryCounters,
    observed_unix_nanos: u64,
    signals: &mut Vec<SignalEnvelope>,
) {
    if truncated {
        counters.unparsed_responses += 1;
        return;
    }
    let Ok(correlation_id) = parse_kafka_response_correlation_id(frame, extraction) else {
        counters.unparsed_responses += 1;
        return;
    };

    let mut matching_positions =
        stream
            .in_flight
            .iter()
            .enumerate()
            .filter_map(|(position, entry)| {
                (entry.kafka_correlation_id == Some(correlation_id)).then_some(position)
            });
    let Some(position) = matching_positions.next() else {
        if stream.in_flight.is_empty() {
            counters.orphan_responses += 1;
        } else {
            counters.kafka_correlation_mismatches += 1;
        }
        return;
    };
    if matching_positions.next().is_some() {
        counters.kafka_correlation_mismatches += 1;
        return;
    }

    let Some(entry) = stream.in_flight.remove(position) else {
        counters.kafka_correlation_mismatches += 1;
        return;
    };
    let response = parse_response_frame(
        StreamProtocol::Kafka,
        frame,
        entry.kafka_api_key,
        entry.kafka_api_version,
        extraction,
    );
    let mut parsed = entry.parsed;
    match response {
        Ok(response) => {
            counters.matched_responses += 1;
            parsed.status_code = response.signal_status_code;
            merge_response_attributes(&mut parsed, &response, extraction.max_attributes);
        }
        Err(reason) => {
            counters.unparsed_responses += 1;
            parsed.warning.get_or_insert_with(|| reason.to_string());
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

/// Completes the MongoDB request identified by the wire-level `responseTo`
/// field. A missing or ambiguous match retains the queue so a later valid
/// response can still be attributed to the correct request.
#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
#[allow(clippy::too_many_arguments)]
fn handle_mongodb_response_frame(
    stream: &mut ConnectionStream,
    frame: &[u8],
    truncated: bool,
    extraction: &ProtocolExtractionConfig,
    host: &Option<String>,
    counters: &mut ProtocolRegistryCounters,
    observed_unix_nanos: u64,
    signals: &mut Vec<SignalEnvelope>,
) {
    if truncated {
        counters.unparsed_responses += 1;
        return;
    }
    let Ok(response) = parse_mongodb_response(frame, extraction) else {
        counters.unparsed_responses += 1;
        return;
    };

    let mut matching_positions =
        stream
            .in_flight
            .iter()
            .enumerate()
            .filter_map(|(position, entry)| {
                entry
                    .mongodb_response
                    .as_ref()
                    .is_some_and(|lifecycle| lifecycle.request_id() == response.response_to)
                    .then_some(position)
            });
    let Some(position) = matching_positions.next() else {
        if stream.in_flight.is_empty() {
            counters.orphan_responses += 1;
        } else {
            counters.mongodb_correlation_mismatches += 1;
        }
        return;
    };
    if matching_positions.next().is_some() {
        counters.mongodb_correlation_mismatches += 1;
        return;
    }

    let progress = {
        let Some(lifecycle) = stream
            .in_flight
            .get_mut(position)
            .and_then(|entry| entry.mongodb_response.as_mut())
        else {
            counters.mongodb_correlation_mismatches += 1;
            return;
        };
        lifecycle.observe_response(response)
    };
    let response = match progress {
        Ok(MongodbResponseProgress::Continue) => {
            counters.mongodb_response_continuations += 1;
            return;
        }
        Ok(MongodbResponseProgress::Complete(response)) => response,
        Err(_) => {
            counters.mongodb_lifecycle_failures += 1;
            return;
        }
    };
    let Some(entry) = stream.in_flight.remove(position) else {
        counters.mongodb_correlation_mismatches += 1;
        return;
    };
    let mut parsed = entry.parsed;
    counters.matched_responses += 1;
    let response = ParsedResponseFrame {
        protocol: None,
        signal_status_code: None,
        status_code: Some(response.status_code),
        error_type: response.error_type,
        attributes: response.attributes,
    };
    merge_response_attributes(&mut parsed, &response, extraction.max_attributes);
    signals.push(build_observation(
        host.clone(),
        &stream.context,
        parsed,
        entry.started_unix_nanos,
        Some(observed_unix_nanos),
    ));
}

#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
fn merge_response_attributes(
    parsed: &mut ParsedRequestFrame,
    response: &ParsedResponseFrame,
    max_attributes: usize,
) {
    for attribute in &response.attributes {
        if parsed.attributes.len() >= max_attributes {
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

#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
#[allow(clippy::too_many_arguments)]
fn emit_websocket_observation(
    frame: &StreamFrame,
    direction: WebSocketDirection,
    stream: &ConnectionStream,
    extraction: &ProtocolExtractionConfig,
    host: &Option<String>,
    counters: &mut ProtocolRegistryCounters,
    observed_unix_nanos: u64,
    signals: &mut Vec<SignalEnvelope>,
) {
    let (bytes, capture_complete) = match frame {
        StreamFrame::Complete(bytes) => (bytes.as_slice(), true),
        StreamFrame::Truncated { prefix, .. } => {
            counters.truncated_frames += 1;
            (prefix.as_slice(), false)
        }
        StreamFrame::ProtocolSwitch { .. } => return,
    };
    let metadata = match parse_websocket_frame(
        bytes,
        direction,
        StreamDecodeLimits::default().max_frame_bytes,
        capture_complete,
    ) {
        Ok(metadata) => metadata,
        Err(_) => {
            counters.unparsed_frames += 1;
            let warning = if capture_complete {
                "unparsed_websocket_frame"
            } else {
                "truncated_websocket_frame_header"
            };
            signals.push(build_observation(
                host.clone(),
                &stream.context,
                ParsedRequestFrame {
                    protocol: ProtocolKind::Websocket,
                    operation: None,
                    status_code: None,
                    trace_id: None,
                    span_id: None,
                    warning: Some(warning.to_string()),
                    attributes: Vec::new(),
                    websocket_upgrade: false,
                },
                observed_unix_nanos,
                None,
            ));
            return;
        }
    };

    let mut attributes = Vec::new();
    push_unique_attribute(
        &mut attributes,
        extraction.max_attributes,
        "network.protocol.name",
        "websocket",
    );
    push_unique_attribute(
        &mut attributes,
        extraction.max_attributes,
        "websocket.frame.direction",
        match direction {
            WebSocketDirection::ClientToServer => "client_to_server",
            WebSocketDirection::ServerToClient => "server_to_client",
        },
    );
    push_unique_attribute(
        &mut attributes,
        extraction.max_attributes,
        "websocket.frame.opcode",
        metadata.opcode.name(),
    );
    push_unique_attribute(
        &mut attributes,
        extraction.max_attributes,
        "websocket.frame.fin",
        if metadata.fin { "true" } else { "false" },
    );
    push_unique_attribute(
        &mut attributes,
        extraction.max_attributes,
        "websocket.frame.masked",
        if metadata.masked { "true" } else { "false" },
    );
    push_unique_attribute(
        &mut attributes,
        extraction.max_attributes,
        "websocket.frame.payload_length",
        &metadata.payload_len.to_string(),
    );
    push_unique_attribute(
        &mut attributes,
        extraction.max_attributes,
        "websocket.frame.capture_complete",
        if metadata.capture_complete {
            "true"
        } else {
            "false"
        },
    );
    counters.websocket_frames += 1;
    signals.push(build_observation(
        host.clone(),
        &stream.context,
        ParsedRequestFrame {
            protocol: ProtocolKind::Websocket,
            operation: Some(metadata.opcode.name().to_string()),
            status_code: None,
            trace_id: None,
            span_id: None,
            warning: (!capture_complete).then(|| "truncated_websocket_frame".to_string()),
            attributes,
            websocket_upgrade: false,
        },
        observed_unix_nanos,
        None,
    ));
}

#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
fn push_unique_attribute(
    attributes: &mut Vec<TraceAttribute>,
    max_attributes: usize,
    key: &str,
    value: &str,
) {
    if attributes.len() >= max_attributes || attributes.iter().any(|attribute| attribute.key == key)
    {
        return;
    }
    attributes.push(TraceAttribute {
        key: key.to_string(),
        value: value.to_string(),
    });
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
            StreamFrame::ProtocolSwitch { .. } => {
                counters.unparsed_frames += 1;
                continue;
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
            let is_header_frame = matches!(
                header.frame_type,
                HTTP2_FRAME_TYPE_HEADERS | HTTP2_FRAME_TYPE_CONTINUATION
            );
            if header.stream_id == 0 {
                counters.response_continuations += 1;
                continue;
            }

            let (request_header, header_block, started_unix_nanos) = if truncated {
                http2.request_headers.reset();
                http2.request_headers_started_unix_nanos = None;
                if header.frame_type != HTTP2_FRAME_TYPE_HEADERS {
                    counters.unparsed_frames += 1;
                    continue;
                }
                counters.unparsed_frames += 1;
                (header, None, observed_unix_nanos)
            } else {
                if !is_header_frame && !http2.request_headers.is_pending() {
                    counters.response_continuations += 1;
                    continue;
                }

                let starts_header_block = header.frame_type == HTTP2_FRAME_TYPE_HEADERS;
                match http2.request_headers.push_frame(
                    &header,
                    payload,
                    extraction.max_header_bytes,
                ) {
                    Ok(Some(assembled)) => {
                        let started_unix_nanos = http2
                            .request_headers_started_unix_nanos
                            .take()
                            .unwrap_or(observed_unix_nanos);
                        (assembled.header, Some(assembled.block), started_unix_nanos)
                    }
                    Ok(None) => {
                        if starts_header_block {
                            http2.request_headers_started_unix_nanos = Some(observed_unix_nanos);
                        }
                        continue;
                    }
                    Err(_) => {
                        http2.request_headers_started_unix_nanos = None;
                        counters.unparsed_frames += 1;
                        if header.frame_type != HTTP2_FRAME_TYPE_HEADERS {
                            continue;
                        }
                        (header, None, observed_unix_nanos)
                    }
                }
            };

            let parsed = if let Some(header_block) = header_block {
                match parse_http2_request_headers_frame(
                    &mut http2.request_hpack,
                    &request_header,
                    &header_block,
                    extraction,
                ) {
                    Ok(parsed) => ParsedRequestFrame {
                        protocol: parsed.protocol,
                        operation: parsed.method,
                        status_code: None,
                        trace_id: parsed
                            .trace_context
                            .as_ref()
                            .map(|context| context.trace_id.clone()),
                        span_id: parsed
                            .trace_context
                            .as_ref()
                            .map(|context| context.span_id.clone()),
                        warning: parsed.warning,
                        attributes: parsed.attributes,
                        websocket_upgrade: false,
                    },
                    Err(_) => {
                        counters.unparsed_frames += 1;
                        ParsedRequestFrame {
                            protocol: ProtocolKind::Http,
                            operation: None,
                            status_code: None,
                            trace_id: None,
                            span_id: None,
                            warning: Some("unparsed_request_frame".to_string()),
                            attributes: Vec::new(),
                            websocket_upgrade: false,
                        }
                    }
                }
            } else {
                ParsedRequestFrame {
                    protocol: ProtocolKind::Http,
                    operation: None,
                    status_code: None,
                    trace_id: None,
                    span_id: None,
                    warning: Some(
                        if truncated {
                            "truncated_request_frame"
                        } else {
                            "unparsed_request_frame"
                        }
                        .to_string(),
                    ),
                    attributes: Vec::new(),
                    websocket_upgrade: false,
                }
            };
            if http2.streams.len() >= MAX_IN_FLIGHT_REQUESTS
                && let Some(entry) = http2.streams.pop_first()
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
                request_header.stream_id,
                InFlightRequest {
                    parsed,
                    started_unix_nanos,
                    kafka_api_key: -1,
                    kafka_api_version: -1,
                    kafka_correlation_id: None,
                    mongodb_response: None,
                    mysql_response: None,
                    redis_response: None,
                    postgres_simple_response: None,
                    postgres_request_response: None,
                    postgres_startup_response: None,
                },
            );
            continue;
        }

        // Response direction.
        if header.stream_id == 0 {
            counters.response_continuations += 1;
            continue;
        }

        let is_header_frame = matches!(
            header.frame_type,
            HTTP2_FRAME_TYPE_HEADERS | HTTP2_FRAME_TYPE_CONTINUATION
        );
        let (response_header, header_block) = if truncated {
            http2.response_headers.reset();
            counters.unparsed_responses += 1;
            if header.frame_type != HTTP2_FRAME_TYPE_HEADERS {
                continue;
            }
            (header, None)
        } else if is_header_frame || http2.response_headers.is_pending() {
            match http2
                .response_headers
                .push_frame(&header, payload, extraction.max_header_bytes)
            {
                Ok(Some(assembled)) => (assembled.header, Some(assembled.block)),
                Ok(None) => continue,
                Err(_) => {
                    counters.unparsed_responses += 1;
                    if header.frame_type != HTTP2_FRAME_TYPE_HEADERS {
                        continue;
                    }
                    (header, None)
                }
            }
        } else {
            (header, None)
        };

        let Some(mut entry) = http2.streams.remove(response_header.stream_id) else {
            if response_header.frame_type == HTTP2_FRAME_TYPE_HEADERS {
                counters.orphan_responses += 1;
            }
            continue;
        };

        if response_header.frame_type == HTTP2_FRAME_TYPE_HEADERS {
            if let Some(header_block) = header_block {
                match parse_http2_response_headers_frame(
                    &mut http2.response_hpack,
                    &response_header,
                    &header_block,
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
            } else {
                entry.parsed.warning.get_or_insert_with(|| {
                    if truncated {
                        "truncated_response_frame"
                    } else {
                        "unparsed_response_frame"
                    }
                    .to_string()
                });
            }
        }

        if response_header.flags & HTTP2_FLAG_END_STREAM != 0 {
            signals.push(build_observation(
                host.clone(),
                &stream.context,
                entry.parsed,
                entry.started_unix_nanos,
                Some(observed_unix_nanos),
            ));
        } else {
            // Stream continues (for example gRPC trailers still pending).
            http2.streams.insert(response_header.stream_id, entry);
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
        let Some(entry) = stream.in_flight.pop_front() else {
            return;
        };
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
        status_code: None,
        trace_id: None,
        span_id: None,
        warning: Some(warning.to_string()),
        attributes: Vec::new(),
        websocket_upgrade: false,
    }
}

#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
fn protocol_kind(protocol: StreamProtocol) -> ProtocolKind {
    match protocol {
        StreamProtocol::Http1 => ProtocolKind::Http,
        StreamProtocol::Http2 => ProtocolKind::Http,
        StreamProtocol::WebSocket => ProtocolKind::Websocket,
        StreamProtocol::Kafka => ProtocolKind::Kafka,
        StreamProtocol::Mongodb => ProtocolKind::Mongodb,
        StreamProtocol::Mysql | StreamProtocol::MysqlCompressed => ProtocolKind::Mysql,
        StreamProtocol::Nats => ProtocolKind::Nats,
        StreamProtocol::Postgresql => ProtocolKind::Postgresql,
        StreamProtocol::Redis => ProtocolKind::Redis,
    }
}

/// Reads the API key, version, and internal correlation id from a Kafka
/// request frame prefix.
#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
fn kafka_request_header_prefix(
    frame: &[u8],
    config: &ProtocolExtractionConfig,
) -> Option<(i16, i16, i32)> {
    if frame.len() < 8 {
        return None;
    }
    let api_key = i16::from_be_bytes([frame[4], frame[5]]);
    let api_version = i16::from_be_bytes([frame[6], frame[7]]);
    let correlation_id = parse_kafka_request_correlation_id(frame, config).ok()?;
    Some((api_key, api_version, correlation_id))
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
        context.source,
        host,
        ProtocolRequestObservation {
            protocol: parsed.protocol,
            role: Some(if context.role == RAW_PROTOCOL_ROLE_SERVER {
                ProtocolCaptureRole::Server
            } else {
                ProtocolCaptureRole::Client
            }),
            start_unix_nanos,
            end_unix_nanos,
            duration_nanos: end_unix_nanos
                .map(|end_nanos| end_nanos.saturating_sub(start_unix_nanos)),
            trace_id: parsed.trace_id,
            span_id: parsed.span_id,
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
            status_code: parsed.status_code,
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
    status_code: Option<u16>,
    trace_id: Option<String>,
    span_id: Option<String>,
    warning: Option<String>,
    attributes: Vec<TraceAttribute>,
    websocket_upgrade: bool,
}

#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
fn parse_request_frame(
    protocol: StreamProtocol,
    frame: &[u8],
    config: &ProtocolExtractionConfig,
) -> Result<ParsedRequestFrame, &'static str> {
    match protocol {
        StreamProtocol::Http1 => parse_http1_request_frame(frame, config),
        StreamProtocol::Http2 => Err("http2_handled_separately"),
        StreamProtocol::WebSocket => Err("websocket_handled_separately"),
        StreamProtocol::Kafka => parse_kafka_request(frame, config)
            .map(|parsed| ParsedRequestFrame {
                protocol: parsed.protocol,
                operation: parsed.operation,
                status_code: None,
                trace_id: None,
                span_id: None,
                warning: parsed.warning,
                attributes: parsed.attributes,
                websocket_upgrade: false,
            })
            .map_err(|_| "kafka_request"),
        StreamProtocol::Mongodb => parse_mongodb_message(frame, config)
            .map(|parsed| ParsedRequestFrame {
                protocol: parsed.protocol,
                operation: parsed.operation,
                status_code: None,
                trace_id: None,
                span_id: None,
                warning: parsed.warning,
                attributes: parsed.attributes,
                websocket_upgrade: false,
            })
            .map_err(|_| "mongodb_message"),
        StreamProtocol::Mysql => parse_mysql_command(frame, config)
            .map(|parsed| ParsedRequestFrame {
                protocol: parsed.protocol,
                operation: parsed.operation,
                status_code: None,
                trace_id: None,
                span_id: None,
                warning: parsed.warning,
                attributes: parsed.attributes,
                websocket_upgrade: false,
            })
            .map_err(|_| "mysql_command"),
        StreamProtocol::MysqlCompressed => Err("mysql_compression_handled_separately"),
        StreamProtocol::Nats => parse_nats_command(frame, config)
            .map(|parsed| ParsedRequestFrame {
                protocol: parsed.protocol,
                operation: parsed.operation,
                status_code: None,
                trace_id: None,
                span_id: None,
                warning: parsed.warning,
                attributes: parsed.attributes,
                websocket_upgrade: false,
            })
            .map_err(|_| "nats_command"),
        StreamProtocol::Postgresql if frame.first() == Some(&0) => {
            parse_postgres_startup_message(frame, config)
                .map(postgres_startup_request_frame)
                .map_err(|_| "postgres_startup_message")
        }
        StreamProtocol::Postgresql => parse_postgres_message(frame, config)
            .map(|parsed| ParsedRequestFrame {
                protocol: parsed.protocol,
                operation: parsed.operation,
                status_code: None,
                trace_id: None,
                span_id: None,
                warning: parsed.warning,
                attributes: parsed.attributes,
                websocket_upgrade: false,
            })
            .map_err(|_| "postgres_message"),
        StreamProtocol::Redis => parse_redis_command(frame, config)
            .map(|parsed| ParsedRequestFrame {
                protocol: parsed.protocol,
                operation: parsed.command,
                status_code: None,
                trace_id: None,
                span_id: None,
                warning: parsed.warning,
                attributes: parsed.attributes,
                websocket_upgrade: false,
            })
            .map_err(|_| "redis_command"),
    }
}

#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
fn postgres_startup_request_frame(
    parsed: e_navigator_protocol::postgres::ParsedPostgresStartup,
) -> ParsedRequestFrame {
    ParsedRequestFrame {
        protocol: parsed.protocol,
        operation: parsed.operation,
        status_code: None,
        trace_id: None,
        span_id: None,
        warning: None,
        attributes: parsed.attributes,
        websocket_upgrade: false,
    }
}

#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
fn parse_http1_request_frame(
    frame: &[u8],
    config: &ProtocolExtractionConfig,
) -> Result<ParsedRequestFrame, &'static str> {
    match parse_grpc_web_request(frame, config) {
        Ok(Some(parsed)) => {
            return Ok(ParsedRequestFrame {
                protocol: parsed.protocol,
                operation: parsed.method,
                status_code: None,
                trace_id: parsed
                    .trace_context
                    .as_ref()
                    .map(|context| context.trace_id.clone()),
                span_id: parsed
                    .trace_context
                    .as_ref()
                    .map(|context| context.span_id.clone()),
                warning: parsed.warning,
                attributes: parsed.attributes,
                websocket_upgrade: false,
            });
        }
        Ok(None) => {}
        Err(_) => return Err("grpc_web_request"),
    }

    let websocket_upgrade = is_websocket_upgrade_request(frame, config.max_header_bytes)
        .map_err(|_| "websocket_upgrade_request")?;
    let parsed = parse_http_request(frame, config).map_err(|_| "http1_request")?;
    let mut attributes = parsed.attributes;
    if websocket_upgrade {
        push_unique_attribute(
            &mut attributes,
            config.max_attributes,
            "network.protocol.name",
            "websocket",
        );
        push_unique_attribute(
            &mut attributes,
            config.max_attributes,
            "websocket.version",
            "13",
        );
    }
    Ok(ParsedRequestFrame {
        protocol: if websocket_upgrade {
            ProtocolKind::Websocket
        } else {
            parsed.protocol
        },
        operation: if websocket_upgrade {
            Some("handshake".to_string())
        } else {
            parsed.method
        },
        status_code: None,
        trace_id: parsed
            .trace_context
            .as_ref()
            .map(|context| context.trace_id.clone()),
        span_id: parsed
            .trace_context
            .as_ref()
            .map(|context| context.span_id.clone()),
        warning: parsed.warning,
        attributes,
        websocket_upgrade,
    })
}

/// Uniform response summary derived from the per-protocol response parsers.
#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedResponseFrame {
    protocol: Option<ProtocolKind>,
    signal_status_code: Option<u16>,
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
        StreamProtocol::Http1 => parse_http1_response_frame(frame, config),
        StreamProtocol::Http2 => Err("http2_handled_separately"),
        StreamProtocol::WebSocket => Err("websocket_handled_separately"),
        StreamProtocol::Kafka => {
            parse_kafka_response_for_api_key(kafka_api_key, kafka_api_version, frame, config)
                .map(|parsed| ParsedResponseFrame {
                    protocol: None,
                    signal_status_code: None,
                    status_code: Some(parsed.status_code),
                    error_type: parsed.error_type,
                    attributes: parsed.attributes,
                })
                .map_err(|_| "kafka_response")
        }
        StreamProtocol::Mongodb => parse_mongodb_response(frame, config)
            .map(|parsed| ParsedResponseFrame {
                protocol: None,
                signal_status_code: None,
                status_code: Some(parsed.status_code),
                error_type: parsed.error_type,
                attributes: parsed.attributes,
            })
            .map_err(|_| "mongodb_response"),
        StreamProtocol::Mysql => parse_mysql_response(frame, config)
            .map(|parsed| ParsedResponseFrame {
                protocol: None,
                signal_status_code: None,
                status_code: Some(parsed.status_code),
                error_type: parsed.error_type,
                attributes: parsed.attributes,
            })
            .map_err(|_| "mysql_response"),
        StreamProtocol::MysqlCompressed => Err("mysql_compression_handled_separately"),
        StreamProtocol::Nats => Err("nats_response_unmatched"),
        StreamProtocol::Postgresql => parse_postgres_response(frame, config)
            .map(|parsed| ParsedResponseFrame {
                protocol: None,
                signal_status_code: None,
                status_code: Some(parsed.status_code),
                error_type: parsed.error_type,
                attributes: parsed.attributes,
            })
            .map_err(|_| "postgres_response"),
        StreamProtocol::Redis => parse_redis_response(frame, config)
            .map(|parsed| ParsedResponseFrame {
                protocol: None,
                signal_status_code: None,
                status_code: parsed.status_code,
                error_type: parsed.error_type,
                attributes: parsed.attributes,
            })
            .map_err(|_| "redis_response"),
    }
}

#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
fn parse_http1_response_frame(
    frame: &[u8],
    config: &ProtocolExtractionConfig,
) -> Result<ParsedResponseFrame, &'static str> {
    match parse_grpc_web_response(frame, config) {
        Ok(Some(parsed)) => {
            return Ok(ParsedResponseFrame {
                protocol: Some(parsed.protocol),
                signal_status_code: Some(parsed.status_code),
                status_code: Some(parsed.status_code.to_string()),
                error_type: None,
                attributes: parsed.attributes,
            });
        }
        Ok(None) => {}
        Err(_) => return Err("grpc_web_response"),
    }
    parse_http_response(frame, config)
        .map(|parsed| ParsedResponseFrame {
            protocol: None,
            signal_status_code: Some(parsed.status_code),
            status_code: Some(parsed.status_code.to_string()),
            error_type: None,
            attributes: parsed.attributes,
        })
        .map_err(|_| "http1_response")
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

/// Resolves an accepted socket's bound port when the bind happened before
/// the eBPF source attached or in a prefork parent that cannot be matched
/// safely in-kernel. Reads are bounded and scoped to the observed process's
/// network namespace.
#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
fn resolve_server_local_port(procfs_root: &std::path::Path, pid: u32, fd: i32) -> Option<u16> {
    if pid == 0 || fd < 0 {
        return None;
    }
    let fd_path = procfs_root
        .join(pid.to_string())
        .join("fd")
        .join(fd.to_string());
    let target = std::fs::read_link(fd_path).ok()?;
    let target = target.to_str()?;
    let inode = target.strip_prefix("socket:[")?.strip_suffix(']')?;
    if inode.is_empty() || !inode.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }

    for table in ["tcp", "tcp6"] {
        let path = procfs_root.join(pid.to_string()).join("net").join(table);
        let Ok(file) = std::fs::File::open(path) else {
            continue;
        };
        let mut contents = String::new();
        let mut bounded = std::io::Read::take(file, MAX_PROC_NET_BYTES);
        if std::io::Read::read_to_string(&mut bounded, &mut contents).is_err() {
            continue;
        }
        for line in contents.lines().skip(1).take(MAX_PROC_NET_LINES) {
            if let Some(port) = proc_net_line_port(line, inode) {
                return Some(port);
            }
        }
    }
    None
}

#[cfg(any(target_os = "linux", test))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ExistingListenerEndpoint {
    pid: u32,
    fd: i32,
    family: u32,
    local_port_be: u16,
    local_addr_v4: u32,
    local_addr_v6: [u8; 16],
}

#[cfg(any(target_os = "linux", test))]
fn discover_existing_listener_endpoints(
    procfs_root: &std::path::Path,
) -> Vec<ExistingListenerEndpoint> {
    use std::collections::BTreeMap;

    let Ok(processes) = std::fs::read_dir(procfs_root) else {
        return Vec::new();
    };
    let mut listeners = Vec::new();
    for process in processes.flatten().take(MAX_EXISTING_LISTENER_PROCESSES) {
        if listeners.len() >= MAX_EXISTING_LISTENERS {
            break;
        }
        let Some(pid) = process
            .file_name()
            .to_str()
            .and_then(|value| value.parse::<u32>().ok())
        else {
            continue;
        };
        let process_root = process.path();
        let Ok(fds) = std::fs::read_dir(process_root.join("fd")) else {
            continue;
        };
        let mut socket_fds = BTreeMap::new();
        for fd in fds.flatten().take(MAX_EXISTING_LISTENER_FDS_PER_PROCESS) {
            let Some(fd_number) = fd
                .file_name()
                .to_str()
                .and_then(|value| value.parse::<i32>().ok())
            else {
                continue;
            };
            let Ok(target) = std::fs::read_link(fd.path()) else {
                continue;
            };
            let Some(target) = target.to_str() else {
                continue;
            };
            let Some(inode) = target
                .strip_prefix("socket:[")
                .and_then(|value| value.strip_suffix(']'))
                .filter(|value| {
                    !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit())
                })
            else {
                continue;
            };
            socket_fds.insert(inode.to_string(), fd_number);
        }
        if socket_fds.is_empty() {
            continue;
        }

        for (table, family) in [
            ("tcp", RAW_PROTOCOL_AF_INET),
            ("tcp6", RAW_PROTOCOL_AF_INET6),
        ] {
            let Ok(file) = std::fs::File::open(process_root.join("net").join(table)) else {
                continue;
            };
            let mut contents = String::new();
            let mut bounded = std::io::Read::take(file, MAX_PROC_NET_BYTES);
            if std::io::Read::read_to_string(&mut bounded, &mut contents).is_err() {
                continue;
            }
            for line in contents.lines().skip(1).take(MAX_PROC_NET_LINES) {
                let Some((inode, local_port_be, local_addr_v4, local_addr_v6)) =
                    parse_proc_net_listener(line, family)
                else {
                    continue;
                };
                let Some(fd) = socket_fds.get(inode).copied() else {
                    continue;
                };
                listeners.push(ExistingListenerEndpoint {
                    pid,
                    fd,
                    family,
                    local_port_be,
                    local_addr_v4,
                    local_addr_v6,
                });
                if listeners.len() >= MAX_EXISTING_LISTENERS {
                    return listeners;
                }
            }
        }
    }
    listeners
}

#[cfg(any(target_os = "linux", test))]
fn parse_proc_net_listener(line: &str, family: u32) -> Option<(&str, u16, u32, [u8; 16])> {
    let fields: Vec<&str> = line.split_ascii_whitespace().collect();
    if fields.len() < 10 || fields[3] != "0A" {
        return None;
    }
    let (address, port) = fields[1].rsplit_once(':')?;
    let port = u16::from_str_radix(port, 16).ok()?;
    if port == 0 {
        return None;
    }
    let local_addr_v4 = if family == RAW_PROTOCOL_AF_INET {
        u32::from_str_radix(address, 16).ok()?
    } else {
        0
    };
    Some((fields[9], port.to_be(), local_addr_v4, [0; 16]))
}

#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
fn proc_net_line_port(line: &str, expected_inode: &str) -> Option<u16> {
    let mut fields = line.split_ascii_whitespace();
    let local_address = fields.nth(1)?;
    let inode = fields.nth(7)?;
    if inode != expected_inode {
        return None;
    }
    let (_, port) = local_address.rsplit_once(':')?;
    let port = u16::from_str_radix(port, 16).ok()?;
    (port != 0).then_some(port)
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
        Ebpf,
        maps::{
            Array as AyaArray, HashMap as AyaHashMap, MapData, PerCpuArray,
            ProgramArray as AyaProgramArray, perf::PerfEvent,
        },
        programs::TracePoint,
        util::online_cpus,
    };
    use e_navigator_core::{
        CoreError, CoreResult, EbpfConfig, ModuleKind, ModuleMetadata, ProtocolSourceConfig, Source,
    };
    use e_navigator_signals::{SignalEnvelope, SignalPayload};
    use std::{path::PathBuf, sync::Arc};
    use tokio::{sync::mpsc, task::JoinHandle};
    use tracing::{debug, info, warn};

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct ListenerConnectionKey {
        tgid: u32,
        fd: i32,
    }

    unsafe impl aya::Pod for ListenerConnectionKey {}

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct ListenerEndpoint {
        family: u32,
        local_port_be: u16,
        reserved: u16,
        local_addr_v4: u32,
        local_addr_v6: [u8; 16],
    }

    unsafe impl aya::Pod for ListenerEndpoint {}

    #[derive(Debug, Default)]
    pub struct AyaProtocolSource {
        host: Option<String>,
        procfs_root: PathBuf,
        config: ProtocolSourceConfig,
        ebpf: EbpfConfig,
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
                ebpf: EbpfConfig::default(),
            }
        }

        pub fn with_ebpf_config(mut self, ebpf: EbpfConfig) -> Self {
            self.ebpf = ebpf;
            self
        }
    }

    fn monotonic_nanos() -> u64 {
        let mut timestamp = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut timestamp) } != 0 {
            // A failed clock read must not stall the merge queue forever.
            return u64::MAX;
        }
        u64::try_from(timestamp.tv_sec)
            .unwrap_or(0)
            .saturating_mul(1_000_000_000)
            .saturating_add(u64::try_from(timestamp.tv_nsec).unwrap_or(0))
    }

    #[async_trait]
    impl Source<SignalEnvelope> for AyaProtocolSource {
        fn metadata(&self) -> ModuleMetadata {
            ModuleMetadata::new("source.aya_protocol", ModuleKind::Source)
        }

        async fn run(self: Box<Self>, tx: mpsc::Sender<SignalEnvelope>) -> CoreResult<()> {
            crate::memlock::bump_memlock_rlimit();
            let shutdown = ReaderShutdown::new();
            let mut reader_handles = Vec::new();
            let diagnostics = SourceDiagnostics::from_env();
            let diagnostics_enabled: &'static u8 = if diagnostics.enabled() { &1 } else { &0 };
            let (mut ebpf, transport) = crate::event_transport::load_ebpf_with(
                &self.ebpf,
                crate::ebpf_maps::SourceMapProfile::Protocol,
                "source.aya_protocol",
                |loader| {
                    loader.override_global("SOURCE_DIAGNOSTICS_ENABLED", diagnostics_enabled, true);
                },
            )?;
            let telemetry = Arc::new(SourceTelemetry::new_with_transport(
                "source.aya_protocol",
                transport.kind.as_str(),
            ));

            populate_capture_ports(&mut ebpf, &self.config)?;
            populate_capture_all(&mut ebpf, &self.config)?;
            populate_capture_limit(&mut ebpf, &self.config)?;
            populate_capture_inbound(&mut ebpf, &self.config)?;
            setup_protocol_iovec_emitter(&mut ebpf)?;
            if self.config.inbound_enabled {
                let listeners = prepopulate_existing_listeners(&mut ebpf, &self.procfs_root)?;
                info!(
                    source = "source.aya_protocol",
                    listeners, "prepopulated existing TCP listeners"
                );
            }

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
            if self.config.inbound_enabled {
                attach_tracepoint(
                    &mut ebpf,
                    "tracepoint_socket_bind_enter",
                    "syscalls",
                    "sys_enter_bind",
                )?;
                attach_tracepoint(
                    &mut ebpf,
                    "tracepoint_socket_bind_exit",
                    "syscalls",
                    "sys_exit_bind",
                )?;
                attach_tracepoint(
                    &mut ebpf,
                    "tracepoint_http_accept_enter",
                    "syscalls",
                    "sys_enter_accept",
                )?;
                attach_tracepoint(
                    &mut ebpf,
                    "tracepoint_http_accept_exit",
                    "syscalls",
                    "sys_exit_accept",
                )?;
                attach_tracepoint(
                    &mut ebpf,
                    "tracepoint_http_accept4_enter",
                    "syscalls",
                    "sys_enter_accept4",
                )?;
                attach_tracepoint(
                    &mut ebpf,
                    "tracepoint_http_accept4_exit",
                    "syscalls",
                    "sys_exit_accept4",
                )?;
            }
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
            attach_tracepoint(
                &mut ebpf,
                "tracepoint_protocol_readv_enter",
                "syscalls",
                "sys_enter_readv",
            )?;
            attach_tracepoint(
                &mut ebpf,
                "tracepoint_protocol_readv_exit",
                "syscalls",
                "sys_exit_readv",
            )?;
            attach_tracepoint(
                &mut ebpf,
                "tracepoint_protocol_recvmsg_enter",
                "syscalls",
                "sys_enter_recvmsg",
            )?;
            attach_tracepoint(
                &mut ebpf,
                "tracepoint_protocol_recvmsg_exit",
                "syscalls",
                "sys_exit_recvmsg",
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

            let protocol_events = crate::event_transport::take_event_map(
                &mut ebpf,
                "PROTOCOL_DATA_EVENTS",
                transport,
                "source.aya_protocol",
            )?;
            if let Some(handle) = crate::event_transport::spawn_transport_loss_reader(
                &mut ebpf,
                crate::ebpf_maps::SourceMapProfile::Protocol,
                transport,
                "source.aya_protocol",
                shutdown.clone(),
                telemetry.clone(),
            )? {
                reader_handles.push(handle);
            }

            // Reassembly is stateful per connection while perf samples arrive
            // per CPU, so all readers feed a single decoder task.
            let (sample_tx, mut sample_rx) =
                mpsc::channel::<super::ProtocolPerfMessage>(super::RAW_SAMPLE_CHANNEL_CAPACITY);
            let reader_count = match protocol_events {
                crate::event_transport::EventMap::Perf(mut perf_array) => {
                    let cpus = online_cpus().map_err(|(_, err)| module_error(err))?;
                    let reader_count = cpus.len();
                    for (reader_index, cpu_id) in cpus.into_iter().enumerate() {
                        let mut buffer = perf_array
                            .open(cpu_id, Some(super::PERF_BUFFER_PAGE_COUNT))
                            .map_err(module_error)?;
                        let reader_shutdown = shutdown.clone();
                        let telemetry = telemetry.clone();
                        let sample_tx = sample_tx.clone();

                        reader_handles.push(tokio::task::spawn_blocking(move || {
                            let mut closed = false;
                            while !reader_shutdown.is_stopped() {
                                let Some(readable) = crate::perf_reader::wait_for_events(
                                    &buffer,
                                    "source.aya_protocol",
                                    cpu_id,
                                ) else {
                                    continue;
                                };
                                let poll_started_monotonic_nanos = monotonic_nanos();
                                if readable {
                                    buffer.for_each(|event| {
                                        if closed {
                                            return;
                                        }
                                        match event {
                                            PerfEvent::Sample { head, tail } => {
                                                let Some(sample) =
                                                    InlineSample::from_perf(head, tail)
                                                else {
                                                    telemetry.record_lost_perf_events(1);
                                                    return;
                                                };
                                                if sample_tx
                                                    .blocking_send(
                                                        super::ProtocolPerfMessage::Sample(sample),
                                                    )
                                                    .is_err()
                                                {
                                                    closed = true;
                                                }
                                            }
                                            PerfEvent::Lost { count } => {
                                                telemetry.record_lost_perf_events(count);
                                                warn!(count, "lost protocol data perf events");
                                            }
                                        }
                                    });
                                }
                                if closed {
                                    return;
                                }
                                if sample_tx
                                    .blocking_send(super::ProtocolPerfMessage::Watermark {
                                        reader_index,
                                        timestamp_monotonic_nanos: poll_started_monotonic_nanos,
                                    })
                                    .is_err()
                                {
                                    return;
                                }
                            }
                        }));
                    }
                    reader_count
                }
                crate::event_transport::EventMap::Ring(mut ring) => {
                    let reader_shutdown = shutdown.clone();
                    let telemetry = telemetry.clone();
                    let sample_tx = sample_tx.clone();
                    reader_handles.push(tokio::task::spawn_blocking(move || {
                        while !reader_shutdown.is_stopped() {
                            let Some(readable) = crate::perf_reader::wait_for_ring_events(
                                &ring,
                                "source.aya_protocol",
                            ) else {
                                continue;
                            };
                            let poll_started_monotonic_nanos = monotonic_nanos();
                            if readable {
                                while let Some(item) = ring.next() {
                                    let Some(sample) = InlineSample::from_bytes(&item) else {
                                        telemetry.record_invalid_sample();
                                        warn!(
                                            size = item.len(),
                                            "oversized protocol ring-buffer event"
                                        );
                                        continue;
                                    };
                                    if sample_tx
                                        .blocking_send(super::ProtocolPerfMessage::Sample(sample))
                                        .is_err()
                                    {
                                        return;
                                    }
                                }
                            }
                            if sample_tx
                                .blocking_send(super::ProtocolPerfMessage::Watermark {
                                    reader_index: 0,
                                    timestamp_monotonic_nanos: poll_started_monotonic_nanos,
                                })
                                .is_err()
                            {
                                return;
                            }
                        }
                    }));
                    1
                }
            };
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
                let mut order = super::ProtocolSampleOrder::new(
                    reader_count,
                    super::PROTOCOL_REORDER_MAX_PENDING_SAMPLES,
                );
                let mut last_protocol_surface_counts = super::ProtocolSurfaceCounters::default();

                let mut decode_sample = |sample: InlineSample| -> bool {
                    if decoder_shutdown.is_stopped() {
                        return false;
                    }

                    signals.clear();
                    let result = registry.handle_event(
                        sample.as_bytes(),
                        super::now_unix_nanos(),
                        &mut signals,
                    );
                    let protocol_surface_counts = registry.counters().protocol_surface_counts();
                    let protocol_surface_deltas =
                        protocol_surface_counts.delta_since(last_protocol_surface_counts);
                    last_protocol_surface_counts = protocol_surface_counts;
                    decoder_telemetry
                        .record_protocol_surface_counter_deltas(protocol_surface_deltas);
                    match result {
                        Ok(()) => {
                            decoder_telemetry.record_decoded_sample();
                            for signal in signals.drain(..) {
                                let diagnostic_decision =
                                    log_signal_diagnostic(&decoder_diagnostics, &signal);
                                decoder_telemetry.record_diagnostic_decision(diagnostic_decision);
                                if tx.blocking_send(signal).is_err() {
                                    decoder_telemetry.record_send_failure();
                                    return false;
                                }
                                decoder_telemetry.record_sent_signal();
                            }
                        }
                        Err(err) => {
                            if err.is_filtered_sample() {
                                decoder_telemetry.record_filtered_sample();
                            } else {
                                decoder_telemetry.record_invalid_sample();
                            }
                            let diagnostic_decision =
                                log_protocol_decode_error_diagnostic(&decoder_diagnostics, err);
                            decoder_telemetry.record_diagnostic_decision(diagnostic_decision);
                        }
                    }
                    decoder_telemetry.maybe_log_summary();
                    true
                };

                while let Some(message) = sample_rx.blocking_recv() {
                    let forced = match message {
                        super::ProtocolPerfMessage::Sample(sample) => order.push_sample(sample),
                        super::ProtocolPerfMessage::Watermark {
                            reader_index,
                            timestamp_monotonic_nanos,
                        } => {
                            order.update_watermark(reader_index, timestamp_monotonic_nanos);
                            None
                        }
                    };
                    if let Some(sample) = forced {
                        warn!(
                            max_pending_samples = super::PROTOCOL_REORDER_MAX_PENDING_SAMPLES,
                            "protocol perf reorder queue reached its bound; flushing oldest sample"
                        );
                        if !decode_sample(sample) {
                            return;
                        }
                    }
                    while let Some(sample) = order.pop_ready() {
                        if !decode_sample(sample) {
                            return;
                        }
                    }
                }
                while let Some(sample) = order.pop_oldest() {
                    if !decode_sample(sample) {
                        return;
                    }
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
            shutdown
                .stop_and_join("source.aya_protocol", reader_handles)
                .await
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

    fn populate_capture_all(ebpf: &mut Ebpf, config: &ProtocolSourceConfig) -> CoreResult<()> {
        let map = ebpf
            .map_mut("PROTOCOL_CAPTURE_ALL")
            .ok_or_else(|| module_error("missing PROTOCOL_CAPTURE_ALL map"))?;
        let mut capture_all: AyaArray<&mut MapData, u32> =
            AyaArray::try_from(map).map_err(module_error)?;
        capture_all
            .set(0, u32::from(config.discovery_enabled), 0)
            .map_err(module_error)?;
        Ok(())
    }

    fn populate_capture_inbound(ebpf: &mut Ebpf, config: &ProtocolSourceConfig) -> CoreResult<()> {
        let map =
            ebpf.map_mut("PROTOCOL_CAPTURE_INBOUND")
                .ok_or_else(|| CoreError::ModuleFailed {
                    module: "source.aya_protocol".to_string(),
                    message: "missing PROTOCOL_CAPTURE_INBOUND map".to_string(),
                })?;
        let mut inbound: AyaArray<&mut MapData, u32> =
            AyaArray::try_from(map).map_err(module_error)?;
        inbound
            .set(0, u32::from(config.inbound_enabled), 0)
            .map_err(module_error)?;
        Ok(())
    }

    pub(crate) fn prepopulate_existing_listeners(
        ebpf: &mut Ebpf,
        procfs_root: &std::path::Path,
    ) -> CoreResult<usize> {
        let listeners = super::discover_existing_listener_endpoints(procfs_root);
        let map = ebpf
            .map_mut("PROCESS_LISTENER_ENDPOINTS")
            .ok_or_else(|| module_error("missing PROCESS_LISTENER_ENDPOINTS map"))?;
        let mut endpoints: AyaHashMap<&mut MapData, ListenerConnectionKey, ListenerEndpoint> =
            AyaHashMap::try_from(map).map_err(module_error)?;
        for listener in &listeners {
            endpoints
                .insert(
                    ListenerConnectionKey {
                        tgid: listener.pid,
                        fd: listener.fd,
                    },
                    ListenerEndpoint {
                        family: listener.family,
                        local_port_be: listener.local_port_be,
                        reserved: 0,
                        local_addr_v4: listener.local_addr_v4,
                        local_addr_v6: listener.local_addr_v6,
                    },
                    0,
                )
                .map_err(module_error)?;
        }
        Ok(listeners.len())
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

    fn log_protocol_decode_error_diagnostic(
        diagnostics: &SourceDiagnostics,
        err: super::RawProtocolDecodeError,
    ) -> DiagnosticSampleDecision {
        let reason = err.reason_name();
        let classification = if err.is_filtered_sample() {
            "filtered"
        } else {
            "invalid"
        };
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
            raw_event = "rejected_protocol_data_sample",
            classification,
            decode_reason = reason,
            pid = ?sample.map(|sample| sample.pid),
            uid = ?sample.map(|sample| sample.uid),
            command = ?redacted_command,
            cgroup_id = ?diagnostics.redact_optional_u64(cgroup_id),
            fd = ?sample.map(|sample| sample.fd),
            direction = ?sample.map(|sample| sample.direction),
            role = ?sample.map(|sample| sample.role),
            family = ?sample.map(|sample| sample.family),
            remote_port = ?sample.map(|sample| u16::from_be(sample.remote_port_be)),
            local_port = ?sample.map(|sample| u16::from_be(sample.local_port_be)),
            payload_len = ?sample.map(|sample| sample.payload_len),
            payload_total_len = ?sample.map(|sample| sample.payload_total_len),
            payload_offset = ?sample.map(|sample| sample.payload_offset),
            payload_captured_len = ?sample.map(|sample| sample.payload_captured_len),
            "source diagnostic raw event rejected"
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

    fn setup_protocol_iovec_emitter(ebpf: &mut Ebpf) -> CoreResult<()> {
        for (index, name) in [
            (0u32, "tracepoint_protocol_iovec_compute"),
            (1u32, "tracepoint_protocol_iovec_emit"),
        ] {
            let program: &mut TracePoint = ebpf
                .program_mut(name)
                .ok_or_else(|| CoreError::ModuleFailed {
                    module: "source.aya_protocol".to_string(),
                    message: format!("missing {name} program"),
                })?
                .try_into()
                .map_err(module_error)?;
            program.load().map_err(module_error)?;
            let program_fd = program
                .fd()
                .map_err(module_error)?
                .try_clone()
                .map_err(module_error)?;
            let map =
                ebpf.map_mut("PROTOCOL_IOVEC_PROGS")
                    .ok_or_else(|| CoreError::ModuleFailed {
                        module: "source.aya_protocol".to_string(),
                        message: "missing PROTOCOL_IOVEC_PROGS map".to_string(),
                    })?;
            let mut programs: AyaProgramArray<&mut MapData> =
                AyaProgramArray::try_from(map).map_err(module_error)?;
            programs.set(index, &program_fd, 0).map_err(module_error)?;
        }
        Ok(())
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
        CoreError, CoreResult, EbpfConfig, ModuleKind, ModuleMetadata, ProtocolSourceConfig, Source,
    };
    use e_navigator_signals::SignalEnvelope;
    use tokio::sync::mpsc;

    #[derive(Debug, Default)]
    pub struct AyaProtocolSource {
        host: Option<String>,
        _procfs_root: std::path::PathBuf,
        _config: ProtocolSourceConfig,
        _ebpf: EbpfConfig,
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
                _ebpf: EbpfConfig::default(),
            }
        }

        pub fn with_ebpf_config(mut self, ebpf: EbpfConfig) -> Self {
            self._ebpf = ebpf;
            self
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
#[cfg(target_os = "linux")]
pub(crate) use platform::prepopulate_existing_listeners;

#[cfg(test)]
mod tests;
