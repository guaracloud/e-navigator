#![allow(dead_code)]

#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
mod database_response;

#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
use database_response::{DatabaseResponseContext, handle_database_response};

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
        RedisResponseLifecycle, RedisResponseProgress, RedisResponseRole, parse_redis_command,
        parse_redis_response, redis_response_role,
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
    pub mysql_compression_unverified_connections: u64,
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
    pub(crate) fn protocol_surface_counts(self) -> [u64; 31] {
        [
            self.websocket_upgrades,
            self.websocket_frames,
            self.websocket_transition_rejections,
            self.grpc_web_requests,
            self.discovered_connections,
            self.discovery_unclassified_events,
            self.discovery_candidate_evictions,
            self.postgres_startup_auth_messages,
            self.postgres_encryption_negotiation_accepted,
            self.postgres_encryption_negotiation_rejected,
            self.postgres_negotiation_failures,
            self.postgres_encrypted_transport_events,
            self.postgres_copy_ignored_controls,
            self.mysql_local_infile_packets,
            self.mysql_local_infile_bytes,
            self.mysql_logical_request_continuations,
            self.mysql_logical_response_continuations,
            self.mysql_logical_sequence_failures,
            self.mysql_server_greetings,
            self.mysql_client_handshakes,
            self.mysql_auth_packets,
            self.mysql_compression_zlib_connections,
            self.mysql_compression_zstd_rejections,
            self.mysql_compression_unverified_connections,
            self.mysql_compressed_packets,
            self.mysql_compression_failures,
            self.mysql_compression_opaque_events,
            self.mysql_handshake_failures,
            self.mongodb_fire_and_forget_requests,
            self.mongodb_response_continuations,
            self.mongodb_lifecycle_failures,
        ]
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
    mysql: Option<MysqlConnectionState>,
    context: ObservationContext,
    last_seen_unix_nanos: u64,
}

#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
#[derive(Debug)]
struct MysqlConnectionState {
    phase: MysqlConnectionPhase,
    compression: Option<MysqlCompressedTransport>,
    limits: StreamDecodeLimits,
}

#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
impl MysqlConnectionState {
    fn new(limits: StreamDecodeLimits) -> Self {
        Self {
            phase: MysqlConnectionPhase::Unknown,
            compression: None,
            limits,
        }
    }

    fn is_opaque(&self) -> bool {
        self.phase == MysqlConnectionPhase::Opaque
    }
}

#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MysqlConnectionPhase {
    Unknown,
    AwaitClientHandshake {
        server: MysqlServerGreeting,
    },
    Authenticating {
        algorithm: MysqlCompressionAlgorithm,
        next_sequence: u8,
        server_verified: bool,
    },
    Command,
    Opaque,
}

#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
#[derive(Debug)]
struct MysqlCompressedTransport {
    request_decoder: ProtocolStreamDecoder,
    response_decoder: ProtocolStreamDecoder,
    request_frame_started_unix_nanos: Option<u64>,
    response_frame_started_unix_nanos: Option<u64>,
    next_sequence: u8,
}

#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
impl MysqlCompressedTransport {
    fn new(limits: StreamDecodeLimits) -> Self {
        Self {
            request_decoder: ProtocolStreamDecoder::new(
                StreamProtocol::Mysql,
                StreamDirection::Request,
                limits,
            ),
            response_decoder: ProtocolStreamDecoder::new(
                StreamProtocol::Mysql,
                StreamDirection::Response,
                limits,
            ),
            request_frame_started_unix_nanos: None,
            response_frame_started_unix_nanos: None,
            next_sequence: 0,
        }
    }
}

#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PostgresNegotiation {
    Ssl,
    GssEncryption,
}

#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
impl PostgresNegotiation {
    fn accepts(self, response: u8) -> bool {
        matches!(
            (self, response),
            (Self::Ssl, b'S') | (Self::GssEncryption, b'G')
        )
    }
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
                .is_some_and(|mysql| mysql.compression.is_some());
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

/// Decodes the negotiated MySQL compression layer into the existing bounded
/// ordinary-packet reassembler. Any missing bytes, decompression mismatch, or
/// compressed sequence ambiguity makes the connection opaque; a later frame
/// is never guessed back into alignment.
#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
fn decode_mysql_compressed_transport_frames(
    stream: &mut ConnectionStream,
    frames: &[StreamFrame],
    is_request_direction: bool,
    input_started_unix_nanos: u64,
    decoded_frames: &mut Vec<StreamFrame>,
    decoded_frame_started_unix_nanos: &mut Option<u64>,
    counters: &mut ProtocolRegistryCounters,
) -> bool {
    for frame in frames {
        let bytes = match frame {
            StreamFrame::Complete(bytes) => bytes,
            StreamFrame::Truncated { .. } => {
                counters.truncated_frames += 1;
                mark_mysql_transport_opaque(stream, counters);
                return false;
            }
            StreamFrame::ProtocolSwitch { .. } => {
                counters.unparsed_frames += 1;
                mark_mysql_transport_opaque(stream, counters);
                return false;
            }
        };

        let max_payload_bytes = stream
            .mysql
            .as_ref()
            .map_or(0, |mysql| mysql.limits.max_buffered_bytes);
        let packet = match decode_mysql_compressed_packet(bytes, max_payload_bytes) {
            Ok(packet) => packet,
            Err(_) => {
                mark_mysql_transport_opaque(stream, counters);
                return false;
            }
        };

        let exchange_idle = stream.in_flight.is_empty()
            && stream.mysql.as_ref().is_some_and(|mysql| {
                mysql.compression.as_ref().is_some_and(|transport| {
                    transport.request_decoder.buffered_bytes() == 0
                        && transport.response_decoder.buffered_bytes() == 0
                })
            });
        let Some(transport) = stream
            .mysql
            .as_mut()
            .and_then(|mysql| mysql.compression.as_mut())
        else {
            mark_mysql_transport_opaque(stream, counters);
            return false;
        };
        let reset_for_new_command =
            is_request_direction && exchange_idle && packet.sequence_id == 0;
        if packet.sequence_id != transport.next_sequence && !reset_for_new_command {
            mark_mysql_transport_opaque(stream, counters);
            return false;
        }
        transport.next_sequence = packet.sequence_id.wrapping_add(1);
        let (decoder, pending_frame_started) = if is_request_direction {
            (
                &mut transport.request_decoder,
                &mut transport.request_frame_started_unix_nanos,
            )
        } else {
            (
                &mut transport.response_decoder,
                &mut transport.response_frame_started_unix_nanos,
            )
        };
        let frame_started_unix_nanos = pending_frame_started.unwrap_or(input_started_unix_nanos);
        let complete_frames_before = decoder.stats().complete_frames;
        let decoded_frames_before = decoded_frames.len();
        decoder.push_chunk(&packet.payload, packet.payload.len() as u64, decoded_frames);
        if decoded_frames.len() > decoded_frames_before
            && decoded_frame_started_unix_nanos.is_none()
        {
            *decoded_frame_started_unix_nanos = Some(frame_started_unix_nanos);
        }
        *pending_frame_started = if decoder.buffered_bytes() == 0 {
            None
        } else if decoder.stats().complete_frames > complete_frames_before {
            Some(input_started_unix_nanos)
        } else {
            Some(frame_started_unix_nanos)
        };
        counters.mysql_compressed_packets += 1;
    }
    true
}

#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
fn mark_mysql_transport_opaque(
    stream: &mut ConnectionStream,
    counters: &mut ProtocolRegistryCounters,
) {
    mark_mysql_connection_opaque(stream);
    counters.mysql_compression_failures += 1;
}

#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
fn mark_mysql_handshake_opaque(
    stream: &mut ConnectionStream,
    counters: &mut ProtocolRegistryCounters,
) {
    mark_mysql_connection_opaque(stream);
    counters.mysql_handshake_failures += 1;
}

#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
fn mark_mysql_connection_opaque(stream: &mut ConnectionStream) {
    if let Some(mysql) = stream.mysql.as_mut() {
        mysql.phase = MysqlConnectionPhase::Opaque;
        mysql.compression = None;
    }
}

#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
fn handle_mysql_connection_request_frame(
    stream: &mut ConnectionStream,
    frame: &StreamFrame,
    extraction: &ProtocolExtractionConfig,
    counters: &mut ProtocolRegistryCounters,
) -> bool {
    let Some(phase) = stream.mysql.as_ref().map(|mysql| mysql.phase) else {
        return false;
    };
    match phase {
        MysqlConnectionPhase::Command => false,
        MysqlConnectionPhase::Opaque => true,
        MysqlConnectionPhase::Unknown => {
            let StreamFrame::Complete(bytes) = frame else {
                if matches!(frame, StreamFrame::Truncated { .. }) {
                    if let Some(mysql) = stream.mysql.as_mut() {
                        mysql.phase = MysqlConnectionPhase::Command;
                    }
                    return false;
                }
                mark_mysql_handshake_opaque(stream, counters);
                return true;
            };
            match parse_mysql_client_handshake_response(bytes, extraction.max_header_bytes) {
                Ok(client) => {
                    begin_mysql_authentication(stream, client, None, counters);
                    true
                }
                Err(_) => {
                    if parse_mysql_packet_metadata(bytes, extraction.max_header_bytes)
                        .is_ok_and(|metadata| metadata.sequence_id == 0)
                        && let Some(mysql) = stream.mysql.as_mut()
                    {
                        mysql.phase = MysqlConnectionPhase::Command;
                    }
                    false
                }
            }
        }
        MysqlConnectionPhase::AwaitClientHandshake { server } => {
            let StreamFrame::Complete(bytes) = frame else {
                mark_mysql_handshake_opaque(stream, counters);
                return true;
            };
            match parse_mysql_client_handshake_response(bytes, extraction.max_header_bytes) {
                Ok(client) => begin_mysql_authentication(stream, client, Some(server), counters),
                Err(_) => mark_mysql_handshake_opaque(stream, counters),
            }
            true
        }
        MysqlConnectionPhase::Authenticating { next_sequence, .. } => {
            let StreamFrame::Complete(bytes) = frame else {
                mark_mysql_handshake_opaque(stream, counters);
                return true;
            };
            let Ok(metadata) = parse_mysql_packet_metadata(bytes, extraction.max_header_bytes)
            else {
                mark_mysql_handshake_opaque(stream, counters);
                return true;
            };
            if metadata.sequence_id != next_sequence {
                mark_mysql_handshake_opaque(stream, counters);
                return true;
            }
            if let Some(mysql) = stream.mysql.as_mut()
                && let MysqlConnectionPhase::Authenticating { next_sequence, .. } = &mut mysql.phase
            {
                *next_sequence = next_sequence.wrapping_add(1);
            }
            counters.mysql_auth_packets += 1;
            true
        }
    }
}

#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
fn handle_mysql_connection_response_frame(
    stream: &mut ConnectionStream,
    frame: &StreamFrame,
    extraction: &ProtocolExtractionConfig,
    counters: &mut ProtocolRegistryCounters,
) -> bool {
    let Some(phase) = stream.mysql.as_ref().map(|mysql| mysql.phase) else {
        return false;
    };
    match phase {
        MysqlConnectionPhase::Command => false,
        MysqlConnectionPhase::Opaque => true,
        MysqlConnectionPhase::Unknown => {
            let StreamFrame::Complete(bytes) = frame else {
                return false;
            };
            let Ok(server) = parse_mysql_server_greeting(bytes, extraction.max_header_bytes) else {
                return false;
            };
            if let Some(mysql) = stream.mysql.as_mut() {
                mysql.phase = MysqlConnectionPhase::AwaitClientHandshake { server };
            }
            counters.mysql_server_greetings += 1;
            true
        }
        MysqlConnectionPhase::AwaitClientHandshake { .. } => {
            mark_mysql_handshake_opaque(stream, counters);
            true
        }
        MysqlConnectionPhase::Authenticating {
            next_sequence,
            algorithm,
            server_verified,
        } => {
            let StreamFrame::Complete(bytes) = frame else {
                mark_mysql_handshake_opaque(stream, counters);
                return true;
            };
            let Ok(metadata) = parse_mysql_packet_metadata(bytes, extraction.max_header_bytes)
            else {
                mark_mysql_handshake_opaque(stream, counters);
                return true;
            };
            if metadata.sequence_id != next_sequence {
                mark_mysql_handshake_opaque(stream, counters);
                return true;
            }
            counters.mysql_auth_packets += 1;
            match metadata.first_payload_byte {
                Some(0x00)
                    if parse_mysql_response(bytes, extraction)
                        .is_ok_and(|response| response.error_type.is_none()) =>
                {
                    activate_mysql_compression(stream, algorithm, server_verified, counters);
                }
                Some(0xff)
                    if parse_mysql_response(bytes, extraction)
                        .is_ok_and(|response| response.error_type.is_some()) =>
                {
                    mark_mysql_connection_opaque(stream);
                }
                Some(0x01 | 0xfe) => {
                    if let Some(mysql) = stream.mysql.as_mut()
                        && let MysqlConnectionPhase::Authenticating { next_sequence, .. } =
                            &mut mysql.phase
                    {
                        *next_sequence = next_sequence.wrapping_add(1);
                    }
                }
                _ => mark_mysql_handshake_opaque(stream, counters),
            }
            true
        }
    }
}

#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
fn begin_mysql_authentication(
    stream: &mut ConnectionStream,
    client: MysqlClientHandshakeResponse,
    server: Option<MysqlServerGreeting>,
    counters: &mut ProtocolRegistryCounters,
) {
    let (algorithm, server_verified) = server.map_or_else(
        || (mysql_requested_compression(client), false),
        |server| (negotiate_mysql_compression(server, client), true),
    );
    if let Some(mysql) = stream.mysql.as_mut() {
        mysql.phase = MysqlConnectionPhase::Authenticating {
            algorithm,
            next_sequence: client.sequence_id.wrapping_add(1),
            server_verified,
        };
    }
    counters.mysql_client_handshakes += 1;
}

#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
fn activate_mysql_compression(
    stream: &mut ConnectionStream,
    algorithm: MysqlCompressionAlgorithm,
    server_verified: bool,
    counters: &mut ProtocolRegistryCounters,
) {
    let Some(mysql) = stream.mysql.as_mut() else {
        return;
    };
    match algorithm {
        MysqlCompressionAlgorithm::Disabled => {
            mysql.phase = MysqlConnectionPhase::Command;
        }
        MysqlCompressionAlgorithm::Zlib => {
            mysql.phase = MysqlConnectionPhase::Command;
            mysql.compression = Some(MysqlCompressedTransport::new(mysql.limits));
            stream
                .request_decoder
                .switch_protocol(StreamProtocol::MysqlCompressed);
            stream
                .response_decoder
                .switch_protocol(StreamProtocol::MysqlCompressed);
            stream.request_segments = None;
            stream.response_segments = None;
            stream.request_frame_started_unix_nanos = None;
            stream.response_frame_started_unix_nanos = None;
            counters.mysql_compression_zlib_connections += 1;
            if !server_verified {
                counters.mysql_compression_unverified_connections += 1;
            }
        }
        MysqlCompressionAlgorithm::Zstd => {
            mysql.phase = MysqlConnectionPhase::Opaque;
            counters.mysql_compression_zstd_rejections += 1;
        }
    }
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

#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
fn begin_postgres_negotiation(
    stream: &mut ConnectionStream,
    negotiation: PostgresNegotiation,
    counters: &mut ProtocolRegistryCounters,
) {
    if stream.postgres_negotiation.is_some() || !stream.in_flight.is_empty() {
        counters.postgres_negotiation_failures += 1;
        stream.postgres_transport_opaque = true;
        return;
    }
    stream.postgres_negotiation = Some(negotiation);
    stream
        .response_decoder
        .expect_postgres_negotiation_response();
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

#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
fn handle_postgres_negotiation_response(
    stream: &mut ConnectionStream,
    frame: &[u8],
    truncated: bool,
    counters: &mut ProtocolRegistryCounters,
) -> bool {
    let Some(negotiation) = stream.postgres_negotiation else {
        return false;
    };
    if truncated {
        stream.postgres_negotiation = None;
        stream.postgres_transport_opaque = true;
        counters.postgres_negotiation_failures += 1;
        return true;
    }

    match frame {
        [b'N'] => {
            stream.postgres_negotiation = None;
            counters.postgres_encryption_negotiation_rejected += 1;
        }
        [response] if negotiation.accepts(*response) => {
            stream.postgres_negotiation = None;
            stream.postgres_transport_opaque = true;
            counters.postgres_encryption_negotiation_accepted += 1;
        }
        bytes if bytes.first() == Some(&b'E') => {
            stream.postgres_negotiation = None;
            stream.postgres_transport_opaque = true;
            counters.postgres_negotiation_failures += 1;
        }
        _ => {
            stream.postgres_negotiation = None;
            stream.postgres_transport_opaque = true;
            counters.postgres_negotiation_failures += 1;
        }
    }
    true
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
            bump_memlock_rlimit();
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
                let mut last_protocol_surface_counts = [0_u64; 31];

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
                    let protocol_surface_deltas = std::array::from_fn(|index| {
                        protocol_surface_counts[index]
                            .saturating_sub(last_protocol_surface_counts[index])
                    });
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
mod tests {
    use super::*;
    use crate::perf_sample::InlineSample;
    use e_navigator_signals::SignalPayload;
    use flate2::{Compression, write::ZlibEncoder};
    use std::io::Write as _;

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
            role: RAW_PROTOCOL_ROLE_CLIENT,
            family: RAW_PROTOCOL_AF_INET,
            remote_port_be: remote_port.to_be(),
            local_port_be: 43210_u16.to_be(),
            remote_addr_v4: u32::from_ne_bytes([10, 0, 0, 5]),
            local_addr_v4: u32::from_ne_bytes([10, 0, 0, 9]),
            remote_addr_v6: [0; 16],
            local_addr_v6: [0; 16],
            timestamp_unix_nanos: 1_000,
            connection_started_at_nanos: 100,
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

    fn inline_sample(event: &RawProtocolDataEvent) -> InlineSample {
        InlineSample::from_perf(raw_as_bytes(event), &[]).expect("raw protocol event fits inline")
    }

    fn registry() -> ProtocolStreamRegistry {
        ProtocolStreamRegistry::new(
            Some("test-host".to_string()),
            std::path::PathBuf::from("__e_navigator_test_no_procfs__"),
            &ProtocolSourceConfig::default(),
        )
    }

    fn http_registry(port: u16) -> ProtocolStreamRegistry {
        let config = ProtocolSourceConfig {
            http1_ports: vec![port],
            ..ProtocolSourceConfig::default()
        };
        ProtocolStreamRegistry::new(
            Some("test-host".to_string()),
            std::path::PathBuf::from("__e_navigator_test_no_procfs__"),
            &config,
        )
    }

    fn discovery_registry() -> ProtocolStreamRegistry {
        let config = ProtocolSourceConfig {
            discovery_enabled: true,
            ..ProtocolSourceConfig::default()
        };
        ProtocolStreamRegistry::new(
            Some("test-host".to_string()),
            std::path::PathBuf::from("__e_navigator_test_no_procfs__"),
            &config,
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

    fn response_event_with_total(
        remote_port: u16,
        payload: &[u8],
        total_len: u32,
    ) -> RawProtocolDataEvent {
        let mut event = raw_event(remote_port, payload, total_len);
        event.direction = RAW_PROTOCOL_DIRECTION_READ;
        event
    }

    fn postgres_frame(message_type: u8, body: &[u8]) -> Vec<u8> {
        let mut frame = Vec::with_capacity(body.len() + 5);
        frame.push(message_type);
        frame.extend_from_slice(&((body.len() + 4) as u32).to_be_bytes());
        frame.extend_from_slice(body);
        frame
    }

    fn postgres_startup(parameters: &[u8]) -> Vec<u8> {
        let mut body = 196_608_u32.to_be_bytes().to_vec();
        body.extend_from_slice(parameters);
        let mut frame = ((body.len() + 4) as u32).to_be_bytes().to_vec();
        frame.extend_from_slice(&body);
        frame
    }

    fn postgres_error(sqlstate: &[u8], message: &[u8]) -> Vec<u8> {
        let mut body = b"SERROR\0C".to_vec();
        body.extend_from_slice(sqlstate);
        body.push(0);
        body.push(b'M');
        body.extend_from_slice(message);
        body.extend_from_slice(&[0, 0]);
        postgres_frame(b'E', &body)
    }

    fn mysql_column_definition_packet(sequence: u8) -> Vec<u8> {
        let mut payload = Vec::new();
        for value in [b"def".as_slice(), b"", b"", b"", b"value", b""] {
            payload.push(value.len() as u8);
            payload.extend_from_slice(value);
        }
        payload.push(0x0c);
        payload.extend_from_slice(&0x0021_u16.to_le_bytes());
        payload.extend_from_slice(&11_u32.to_le_bytes());
        payload.push(0x03);
        payload.extend_from_slice(&0_u16.to_le_bytes());
        payload.push(0);
        payload.extend_from_slice(&[0, 0]);

        let mut packet = Vec::with_capacity(payload.len() + 4);
        packet.push((payload.len() & 0xff) as u8);
        packet.push(((payload.len() >> 8) & 0xff) as u8);
        packet.push(((payload.len() >> 16) & 0xff) as u8);
        packet.push(sequence);
        packet.extend_from_slice(&payload);
        packet
    }

    fn mysql_wire_packet(sequence: u8, payload: &[u8]) -> Vec<u8> {
        let payload_len = payload.len();
        let mut packet = Vec::with_capacity(payload_len + 4);
        packet.push((payload_len & 0xff) as u8);
        packet.push(((payload_len >> 8) & 0xff) as u8);
        packet.push(((payload_len >> 16) & 0xff) as u8);
        packet.push(sequence);
        packet.extend_from_slice(payload);
        packet
    }

    fn mysql_server_greeting(capabilities: u32) -> Vec<u8> {
        let mut payload = vec![0x0a];
        payload.extend_from_slice(b"8.0.36\0");
        payload.extend_from_slice(&42_u32.to_le_bytes());
        payload.extend_from_slice(b"12345678");
        payload.push(0);
        payload.extend_from_slice(&(capabilities as u16).to_le_bytes());
        payload.push(0x21);
        payload.extend_from_slice(&2_u16.to_le_bytes());
        payload.extend_from_slice(&((capabilities >> 16) as u16).to_le_bytes());
        payload.push(21);
        payload.extend_from_slice(&[0; 10]);
        payload.extend_from_slice(b"abcdefghijkl\0");
        mysql_wire_packet(0, &payload)
    }

    fn mysql_client_handshake_response(sequence: u8, capabilities: u32) -> Vec<u8> {
        let mut payload = capabilities.to_le_bytes().to_vec();
        payload.extend_from_slice(&16_777_216_u32.to_le_bytes());
        payload.push(0x21);
        payload.extend_from_slice(&[0; 23]);
        payload.extend_from_slice(b"fixture-user\0");
        payload.push(0);
        mysql_wire_packet(sequence, &payload)
    }

    fn mysql_compressed_packet(sequence: u8, payload: &[u8], compress: bool) -> Vec<u8> {
        let (body, uncompressed_len) = if compress {
            let mut encoder = ZlibEncoder::new(Vec::new(), Compression::fast());
            encoder
                .write_all(payload)
                .expect("fixture zlib write succeeds");
            let body = encoder.finish().expect("fixture zlib finish succeeds");
            (body, payload.len())
        } else {
            (payload.to_vec(), 0)
        };
        let body_len = u32::try_from(body.len()).expect("fixture length fits u32");
        let uncompressed_len = u32::try_from(uncompressed_len).expect("fixture length fits u32");
        let mut packet = Vec::with_capacity(body.len() + 7);
        packet.extend_from_slice(&body_len.to_le_bytes()[..3]);
        packet.push(sequence);
        packet.extend_from_slice(&uncompressed_len.to_le_bytes()[..3]);
        packet.extend_from_slice(&body);
        packet
    }

    fn kafka_api_versions_request(correlation_id: i32) -> Vec<u8> {
        let mut body = vec![0, 18, 0, 0];
        body.extend_from_slice(&correlation_id.to_be_bytes());
        body.extend_from_slice(&[0xff, 0xff]);
        let mut frame = (body.len() as i32).to_be_bytes().to_vec();
        frame.extend_from_slice(&body);
        frame
    }

    fn kafka_api_versions_response(correlation_id: i32) -> Vec<u8> {
        let mut body = correlation_id.to_be_bytes().to_vec();
        body.extend_from_slice(&[0, 0]);
        let mut frame = (body.len() as i32).to_be_bytes().to_vec();
        frame.extend_from_slice(&body);
        frame
    }

    fn mongodb_op_msg(request_id: i32, response_to: i32, document: &[u8]) -> Vec<u8> {
        mongodb_op_msg_with_flags(request_id, response_to, 0, document)
    }

    fn mongodb_op_msg_with_flags(
        request_id: i32,
        response_to: i32,
        flags: u32,
        document: &[u8],
    ) -> Vec<u8> {
        let message_len = 16 + 4 + 1 + document.len();
        let mut frame = Vec::with_capacity(message_len);
        frame.extend_from_slice(&(message_len as i32).to_le_bytes());
        frame.extend_from_slice(&request_id.to_le_bytes());
        frame.extend_from_slice(&response_to.to_le_bytes());
        frame.extend_from_slice(&2013_i32.to_le_bytes());
        frame.extend_from_slice(&flags.to_le_bytes());
        frame.push(0);
        frame.extend_from_slice(document);
        frame
    }

    fn mongodb_find_document(collection: &str) -> Vec<u8> {
        let value_len = collection.len() + 1;
        let document_len = 4 + 1 + 5 + 4 + value_len + 1;
        let mut document = Vec::with_capacity(document_len);
        document.extend_from_slice(&(document_len as i32).to_le_bytes());
        document.push(0x02);
        document.extend_from_slice(b"find\0");
        document.extend_from_slice(&(value_len as i32).to_le_bytes());
        document.extend_from_slice(collection.as_bytes());
        document.push(0);
        document.push(0);
        document
    }

    fn mongodb_ok_document() -> Vec<u8> {
        let mut document = 10_i32.to_le_bytes().to_vec();
        document.extend_from_slice(&[0x08, b'o', b'k', 0, 1, 0]);
        document
    }

    #[test]
    fn protocol_perf_watermarks_merge_cross_cpu_samples_by_kernel_time() {
        let mut later = raw_event(6379, b"later", 5);
        later.timestamp_unix_nanos = 300;
        let mut earlier = raw_event(6379, b"earlier", 7);
        earlier.timestamp_unix_nanos = 100;
        let mut order = ProtocolSampleOrder::new(2, 8);

        // Reader 1 delivers first, but reader 0 has not completed its poll,
        // so the later event must remain buffered.
        assert!(order.push_sample(inline_sample(&later)).is_none());
        order.update_watermark(1, 400);
        assert!(order.pop_ready().is_none());

        assert!(order.push_sample(inline_sample(&earlier)).is_none());
        order.update_watermark(0, 400);
        assert_eq!(
            protocol_sample_timestamp(&order.pop_ready().expect("earlier sample")),
            Some(100)
        );
        assert_eq!(
            protocol_sample_timestamp(&order.pop_ready().expect("later sample")),
            Some(300)
        );
        assert!(order.pop_ready().is_none());
    }

    #[test]
    fn protocol_perf_merge_bound_flushes_without_dropping() {
        let mut later = raw_event(6379, b"later", 5);
        later.timestamp_unix_nanos = 300;
        let mut earlier = raw_event(6379, b"earlier", 7);
        earlier.timestamp_unix_nanos = 100;
        let mut order = ProtocolSampleOrder::new(2, 1);

        assert!(order.push_sample(inline_sample(&later)).is_none());
        let forced = order
            .push_sample(inline_sample(&earlier))
            .expect("bound flushes oldest sample");
        assert_eq!(protocol_sample_timestamp(&forced), Some(100));
        assert_eq!(
            protocol_sample_timestamp(&order.pop_oldest().expect("remaining sample")),
            Some(300)
        );
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
    fn fragmented_request_latency_starts_at_the_first_observed_byte() {
        let mut registry = registry();
        let first = b"*2\r\n$3\r\nGET\r\n";
        let second = b"$10\r\nsecret-key\r\n";
        assert!(
            handle_at(
                &mut registry,
                &raw_event(6379, first, first.len() as u32),
                5_000,
            )
            .is_empty()
        );
        assert!(
            handle_at(
                &mut registry,
                &raw_event(6379, second, second.len() as u32),
                5_500,
            )
            .is_empty()
        );

        let signals = handle_at(
            &mut registry,
            &response_event(6379, b"$5\r\nhello\r\n"),
            9_000,
        );
        assert_eq!(signals.len(), 1);
        let observation = observation(&signals[0]);
        assert_eq!(observation.start_unix_nanos, 5_000);
        assert_eq!(observation.duration_nanos, Some(4_000));
    }

    #[test]
    fn redis_resp3_push_does_not_consume_the_command_reply() {
        let mut registry = registry();
        let request = b"*2\r\n$3\r\nGET\r\n$10\r\nsecret-key\r\n";
        assert!(
            handle_at(
                &mut registry,
                &raw_event(6379, request, request.len() as u32),
                5_000,
            )
            .is_empty()
        );

        let response = b">2\r\n+invalidate\r\n$10\r\nsecret-key\r\n$5\r\nhello\r\n";
        let signals = handle_at(&mut registry, &response_event(6379, response), 7_500);

        assert_eq!(signals.len(), 1);
        let observation = observation(&signals[0]);
        assert_eq!(observation.method.as_deref(), Some("GET"));
        assert_eq!(observation.duration_nanos, Some(2_500));
        assert_eq!(registry.counters().matched_responses, 1);
        assert_eq!(registry.counters().response_continuations, 1);
        assert_eq!(registry.counters().orphan_responses, 0);
        let serialized = serde_json::to_string(&signals).expect("signals serialize");
        assert!(!serialized.contains("secret-key"));
        assert!(!serialized.contains("hello"));
    }

    #[test]
    fn redis_resp3_subscription_pushes_complete_only_the_subscribe_command() {
        let mut registry = registry();
        let requests = b"*3\r\n$9\r\nSUBSCRIBE\r\n$10\r\nsecret-one\r\n$10\r\nsecret-two\r\n*1\r\n$4\r\nPING\r\n";
        assert!(
            handle_at(
                &mut registry,
                &raw_event(6379, requests, requests.len() as u32),
                5_000,
            )
            .is_empty()
        );

        let first_confirmation = b">3\r\n$9\r\nsubscribe\r\n$10\r\nsecret-one\r\n:1\r\n";
        assert!(
            handle_at(
                &mut registry,
                &response_event(6379, first_confirmation),
                7_000,
            )
            .is_empty(),
            "one confirmation must not complete a two-channel subscription"
        );

        let second_confirmation = b">3\r\n$9\r\nsubscribe\r\n$10\r\nsecret-two\r\n:2\r\n";
        let signals = handle_at(
            &mut registry,
            &response_event(6379, second_confirmation),
            8_000,
        );
        assert_eq!(signals.len(), 1);
        assert_eq!(
            observation(&signals[0]).method.as_deref(),
            Some("SUBSCRIBE")
        );
        assert_eq!(observation(&signals[0]).duration_nanos, Some(3_000));

        let signals = handle_at(&mut registry, &response_event(6379, b"+PONG\r\n"), 9_000);
        assert_eq!(signals.len(), 1);
        assert_eq!(observation(&signals[0]).method.as_deref(), Some("PING"));
        assert_eq!(registry.counters().matched_responses, 2);
        let serialized = serde_json::to_string(&signals).expect("signals serialize");
        assert!(!serialized.contains("secret-one"));
        assert!(!serialized.contains("secret-two"));
    }

    #[test]
    fn redis_resp2_pubsub_delivery_does_not_consume_an_interleaved_reply() {
        let mut registry = registry();
        let requests = b"*2\r\n$9\r\nSUBSCRIBE\r\n$7\r\nchannel\r\n*1\r\n$4\r\nPING\r\n";
        assert!(
            handle_at(
                &mut registry,
                &raw_event(6379, requests, requests.len() as u32),
                5_000,
            )
            .is_empty()
        );

        let confirmation = b"*3\r\n$9\r\nsubscribe\r\n$7\r\nchannel\r\n:1\r\n";
        let signals = handle_at(&mut registry, &response_event(6379, confirmation), 6_000);
        assert_eq!(signals.len(), 1);
        assert_eq!(
            observation(&signals[0]).method.as_deref(),
            Some("SUBSCRIBE")
        );

        let delivery = b"*3\r\n$7\r\nmessage\r\n$7\r\nchannel\r\n$14\r\nsecret-payload\r\n";
        assert!(
            handle_at(&mut registry, &response_event(6379, delivery), 7_000,).is_empty(),
            "an out-of-band delivery must not complete PING"
        );

        let signals = handle_at(&mut registry, &response_event(6379, b"+PONG\r\n"), 8_000);
        assert_eq!(signals.len(), 1);
        assert_eq!(observation(&signals[0]).method.as_deref(), Some("PING"));
        assert_eq!(observation(&signals[0]).duration_nanos, Some(3_000));
        assert_eq!(registry.counters().matched_responses, 2);
        assert_eq!(registry.counters().response_continuations, 1);
        let serialized = serde_json::to_string(&signals).expect("signals serialize");
        assert!(!serialized.contains("secret-payload"));
        assert!(!serialized.contains("channel"));
    }

    #[test]
    fn redis_resp3_attributes_do_not_consume_the_decorated_reply() {
        let mut registry = registry();
        let request = b"*2\r\n$3\r\nGET\r\n$10\r\nsecret-key\r\n";
        assert!(
            handle_at(
                &mut registry,
                &raw_event(6379, request, request.len() as u32),
                5_000,
            )
            .is_empty()
        );

        let response = b"|1\r\n+ttl\r\n:10\r\n$5\r\nhello\r\n";
        let signals = handle_at(&mut registry, &response_event(6379, response), 7_500);

        assert_eq!(signals.len(), 1);
        let observation = observation(&signals[0]);
        assert_eq!(observation.method.as_deref(), Some("GET"));
        assert_eq!(observation.duration_nanos, Some(2_500));
        assert_eq!(registry.counters().matched_responses, 1);
        assert_eq!(registry.counters().response_continuations, 1);
        assert_eq!(registry.counters().orphan_responses, 0);
        let serialized = serde_json::to_string(&signals).expect("signals serialize");
        assert!(!serialized.contains("secret-key"));
        assert!(!serialized.contains("hello"));
        assert!(!serialized.contains("ttl"));
    }

    #[test]
    fn websocket_upgrade_and_coalesced_frames_emit_metadata_only() {
        let mut registry = http_registry(8080);
        let request = b"GET /chat HTTP/1.1\r\nHost: example.test\r\nUpgrade: websocket\r\nConnection: keep-alive, Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
        assert!(
            handle_at(
                &mut registry,
                &raw_event(8080, request, request.len() as u32),
                5_000,
            )
            .is_empty()
        );

        let response = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n";
        let server_frame = [0x81, 0x06, b's', b'e', b'c', b'r', b'e', b't'];
        let mut response_and_frame = response.to_vec();
        response_and_frame.extend_from_slice(&server_frame);
        let signals = handle_at(
            &mut registry,
            &response_event(8080, &response_and_frame),
            7_000,
        );

        assert_eq!(signals.len(), 2);
        let handshake = observation(&signals[0]);
        assert_eq!(handshake.protocol, ProtocolKind::Websocket);
        assert_eq!(handshake.method.as_deref(), Some("handshake"));
        assert_eq!(handshake.status_code, Some(101));
        let frame = observation(&signals[1]);
        assert_eq!(frame.protocol, ProtocolKind::Websocket);
        assert_eq!(frame.method.as_deref(), Some("text"));
        assert!(frame.attributes.iter().any(|attribute| {
            attribute.key == "websocket.frame.payload_length" && attribute.value == "6"
        }));
        let serialized = serde_json::to_string(&signals).expect("signals serialize");
        assert!(!serialized.contains("secret"));
        assert_eq!(registry.counters().websocket_upgrades, 1);
        assert_eq!(registry.counters().websocket_frames, 1);

        let masked_client_frame = [0x89, 0x80, 1, 2, 3, 4];
        let client_signals = handle_at(
            &mut registry,
            &raw_event(8080, &masked_client_frame, masked_client_frame.len() as u32),
            8_000,
        );
        assert_eq!(client_signals.len(), 1);
        assert_eq!(
            observation(&client_signals[0]).method.as_deref(),
            Some("ping")
        );
        assert_eq!(registry.counters().websocket_frames, 2);
    }

    #[test]
    fn grpc_web_binary_request_matches_text_response_status() {
        use base64::{Engine as _, engine::general_purpose::STANDARD};

        let mut registry = http_registry(8081);
        let message = [
            0, 0, 0, 0, 11, b's', b'e', b'c', b'r', b'e', b't', b'-', b'b', b'o', b'd', b'y',
        ];
        let mut request = format!(
            "POST /demo.Echo/Call HTTP/1.1\r\nHost: example.test\r\nContent-Type: application/grpc-web+proto\r\nContent-Length: {}\r\n\r\n",
            message.len()
        )
        .into_bytes();
        request.extend_from_slice(&message);
        assert!(
            handle_at(
                &mut registry,
                &raw_event(8081, &request, request.len() as u32),
                10_000,
            )
            .is_empty()
        );

        let trailer_payload = b"grpc-status: 0\r\n";
        let mut response_body = vec![0, 0, 0, 0, 2, b'o', b'k', 0x80];
        response_body.extend_from_slice(&(trailer_payload.len() as u32).to_be_bytes());
        response_body.extend_from_slice(trailer_payload);
        let encoded = STANDARD.encode(response_body);
        let mut response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/grpc-web-text+proto\r\nContent-Length: {}\r\n\r\n",
            encoded.len()
        )
        .into_bytes();
        response.extend_from_slice(encoded.as_bytes());
        let signals = handle_at(&mut registry, &response_event(8081, &response), 12_500);

        assert_eq!(signals.len(), 1);
        let rpc = observation(&signals[0]);
        assert_eq!(rpc.protocol, ProtocolKind::Grpc);
        assert_eq!(rpc.method.as_deref(), Some("Call"));
        assert_eq!(rpc.status_code, Some(0));
        assert_eq!(rpc.duration_nanos, Some(2_500));
        assert!(rpc.attributes.iter().any(|attribute| {
            attribute.key == "rpc.grpc.transport" && attribute.value == "grpc_web"
        }));
        let serialized = serde_json::to_string(&signals).expect("signals serialize");
        assert!(!serialized.contains("secret-body"));
        assert_eq!(registry.counters().grpc_web_requests, 1);
    }

    #[test]
    fn connection_generation_prevents_websocket_state_leaking_across_fd_reuse() {
        use base64::{Engine as _, engine::general_purpose::STANDARD};

        let mut registry = http_registry(8082);
        let websocket_request = b"GET /websocket-proof HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
        assert!(
            handle_at(
                &mut registry,
                &raw_event(8082, websocket_request, websocket_request.len() as u32),
                1_000,
            )
            .is_empty()
        );
        let websocket_response = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n";
        assert_eq!(
            handle_at(
                &mut registry,
                &response_event(8082, websocket_response),
                2_000,
            )
            .len(),
            1
        );

        let message = b"\x00\x00\x00\x00\x12client-secret-blue";
        let mut request = format!(
            "POST /proof.Echo/Call HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/grpc-web+proto\r\nContent-Length: {}\r\n\r\n",
            message.len()
        )
        .into_bytes();
        request.extend_from_slice(message);
        let mut request_event = raw_event(8082, &request, request.len() as u32);
        request_event.connection_started_at_nanos = 200;
        assert!(handle_at(&mut registry, &request_event, 3_000).is_empty());

        let trailer = b"grpc-status: 0\r\n";
        let mut body = vec![0, 0, 0, 0, 2, b'o', b'k', 0x80];
        body.extend_from_slice(&(trailer.len() as u32).to_be_bytes());
        body.extend_from_slice(trailer);
        let encoded = STANDARD.encode(body);
        let mut response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/grpc-web-text+proto\r\nContent-Length: {}\r\n\r\n",
            encoded.len()
        )
        .into_bytes();
        response.extend_from_slice(encoded.as_bytes());
        let mut response_event = response_event(8082, &response);
        response_event.connection_started_at_nanos = 200;
        let signals = handle_at(&mut registry, &response_event, 4_000);

        assert_eq!(signals.len(), 1);
        assert_eq!(observation(&signals[0]).protocol, ProtocolKind::Grpc);
        assert_eq!(observation(&signals[0]).status_code, Some(0));
        assert_eq!(registry.counters().evicted_connections, 1);
        assert_eq!(registry.counters().grpc_web_requests, 1);
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
        let reads_before = crate::procfs::container_cgroup_read_count();

        let request = raw_event(6379, b"*1\r\n$4\r\nPING\r\n", 14);
        assert!(handle_at(&mut registry, &request, 5_000).is_empty());
        std::fs::remove_file(&cgroup_path).expect("remove cgroup fixture after connection start");

        let response = response_event(6379, b"+PONG\r\n");
        let signals = handle_at(&mut registry, &response, 6_000);

        assert_eq!(
            crate::procfs::container_cgroup_read_count() - reads_before,
            1,
            "an established connection must not reopen its procfs cgroup file"
        );
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
        assert_eq!(observation.start_unix_nanos, 5_000);
        assert_eq!(observation.duration_nanos, Some(4_100));
        assert_eq!(registry.counters().matched_responses, 1);
    }

    #[test]
    fn kafka_response_correlation_id_prevents_destructive_fifo_mismatch() {
        let mut registry = registry();
        let frame = kafka_api_versions_request(7);
        assert!(
            handle_at(
                &mut registry,
                &raw_event(9092, &frame, frame.len() as u32),
                5_000
            )
            .is_empty()
        );

        let mismatched_frame = kafka_api_versions_response(6);
        let mismatched = response_event(9092, &mismatched_frame);
        assert!(handle_at(&mut registry, &mismatched, 6_000).is_empty());
        assert_eq!(registry.counters().matched_responses, 0);
        assert_eq!(registry.counters().kafka_correlation_mismatches, 1);

        let matched_frame = kafka_api_versions_response(7);
        let matched = response_event(9092, &matched_frame);
        let signals = handle_at(&mut registry, &matched, 7_000);
        assert_eq!(signals.len(), 1);
        assert_eq!(registry.counters().matched_responses, 1);
    }

    #[test]
    fn kafka_response_correlation_id_matches_out_of_order_requests() {
        let mut registry = registry();
        for (correlation_id, observed_at) in [(7, 5_000), (8, 6_000)] {
            let request = kafka_api_versions_request(correlation_id);
            assert!(
                handle_at(
                    &mut registry,
                    &raw_event(9092, &request, request.len() as u32),
                    observed_at,
                )
                .is_empty()
            );
        }

        let response_eight = kafka_api_versions_response(8);
        let signals = handle_at(&mut registry, &response_event(9092, &response_eight), 7_000);
        assert_eq!(signals.len(), 1);
        assert_eq!(observation(&signals[0]).duration_nanos, Some(1_000));

        let response_seven = kafka_api_versions_response(7);
        let signals = handle_at(&mut registry, &response_event(9092, &response_seven), 8_000);
        assert_eq!(signals.len(), 1);
        assert_eq!(observation(&signals[0]).duration_nanos, Some(3_000));
        assert_eq!(registry.counters().matched_responses, 2);
        assert_eq!(registry.counters().kafka_correlation_mismatches, 0);
    }

    #[test]
    fn mongodb_response_to_matches_out_of_order_requests() {
        let mut registry = registry();
        for (request_id, collection, observed_at) in [(7, "customers", 5_000), (8, "orders", 6_000)]
        {
            let request = mongodb_op_msg(request_id, 0, &mongodb_find_document(collection));
            assert!(
                handle_at(
                    &mut registry,
                    &raw_event(27017, &request, request.len() as u32),
                    observed_at,
                )
                .is_empty()
            );
        }

        let response_eight = mongodb_op_msg(80, 8, &mongodb_ok_document());
        let signals = handle_at(
            &mut registry,
            &response_event(27017, &response_eight),
            7_000,
        );
        assert_eq!(signals.len(), 1);
        assert_eq!(observation(&signals[0]).duration_nanos, Some(1_000));
        assert!(observation(&signals[0]).attributes.iter().any(|attribute| {
            attribute.key == "db.collection.name" && attribute.value == "orders"
        }));

        let response_seven = mongodb_op_msg(70, 7, &mongodb_ok_document());
        let signals = handle_at(
            &mut registry,
            &response_event(27017, &response_seven),
            8_000,
        );
        assert_eq!(signals.len(), 1);
        assert_eq!(observation(&signals[0]).duration_nanos, Some(3_000));
        assert!(observation(&signals[0]).attributes.iter().any(|attribute| {
            attribute.key == "db.collection.name" && attribute.value == "customers"
        }));
        assert_eq!(registry.counters().matched_responses, 2);
        assert_eq!(registry.counters().mongodb_correlation_mismatches, 0);
    }

    #[test]
    fn mongodb_response_to_mismatch_retains_the_request() {
        let mut registry = registry();
        let request = mongodb_op_msg(7, 0, &mongodb_find_document("customers"));
        assert!(
            handle_at(
                &mut registry,
                &raw_event(27017, &request, request.len() as u32),
                5_000,
            )
            .is_empty()
        );

        let mismatched_response = mongodb_op_msg(60, 6, &mongodb_ok_document());
        assert!(
            handle_at(
                &mut registry,
                &response_event(27017, &mismatched_response),
                6_000,
            )
            .is_empty()
        );
        assert_eq!(registry.counters().matched_responses, 0);
        assert_eq!(registry.counters().mongodb_correlation_mismatches, 1);

        let matched_response = mongodb_op_msg(70, 7, &mongodb_ok_document());
        let signals = handle_at(
            &mut registry,
            &response_event(27017, &matched_response),
            7_000,
        );
        assert_eq!(signals.len(), 1);
        assert_eq!(observation(&signals[0]).duration_nanos, Some(2_000));
        assert_eq!(registry.counters().matched_responses, 1);
    }

    #[test]
    fn mongodb_fire_and_forget_request_emits_without_waiting_for_a_response() {
        let mut registry = registry();
        let request = mongodb_op_msg_with_flags(7, 0, 0x02, &mongodb_find_document("customers"));

        let signals = handle_at(
            &mut registry,
            &raw_event(27017, &request, request.len() as u32),
            5_000,
        );

        assert_eq!(signals.len(), 1);
        assert_eq!(observation(&signals[0]).duration_nanos, None);
        assert_eq!(registry.counters().mongodb_fire_and_forget_requests, 1);
    }

    #[test]
    fn mongodb_exhaust_request_is_retained_until_the_final_response() {
        let mut registry = registry();
        let request =
            mongodb_op_msg_with_flags(7, 0, 0x0001_0000, &mongodb_find_document("customers"));
        assert!(
            handle_at(
                &mut registry,
                &raw_event(27017, &request, request.len() as u32),
                5_000,
            )
            .is_empty()
        );

        let continued = mongodb_op_msg_with_flags(70, 7, 0x02, &mongodb_ok_document());
        assert!(handle_at(&mut registry, &response_event(27017, &continued), 6_000,).is_empty());
        assert_eq!(registry.counters().mongodb_response_continuations, 1);

        let final_response = mongodb_op_msg(71, 7, &mongodb_ok_document());
        let signals = handle_at(
            &mut registry,
            &response_event(27017, &final_response),
            8_000,
        );
        assert_eq!(signals.len(), 1);
        assert_eq!(observation(&signals[0]).duration_nanos, Some(3_000));
        assert_eq!(registry.counters().matched_responses, 1);
    }

    #[test]
    fn mongodb_unexpected_continuation_fails_closed_and_retains_request() {
        let mut registry = registry();
        let request = mongodb_op_msg(7, 0, &mongodb_find_document("customers"));
        assert!(
            handle_at(
                &mut registry,
                &raw_event(27017, &request, request.len() as u32),
                5_000,
            )
            .is_empty()
        );

        let unexpected = mongodb_op_msg_with_flags(70, 7, 0x02, &mongodb_ok_document());
        assert!(handle_at(&mut registry, &response_event(27017, &unexpected), 6_000,).is_empty());
        assert_eq!(registry.counters().mongodb_lifecycle_failures, 1);

        let final_response = mongodb_op_msg(71, 7, &mongodb_ok_document());
        let signals = handle_at(
            &mut registry,
            &response_event(27017, &final_response),
            8_000,
        );
        assert_eq!(signals.len(), 1);
        assert_eq!(observation(&signals[0]).duration_nanos, Some(3_000));
    }

    #[test]
    fn dynamic_discovery_matches_redis_on_an_unconfigured_port() {
        let mut registry = discovery_registry();
        let request = raw_event(16_379, b"*1\r\n$4\r\nPING\r\n", 14);
        assert!(handle_at(&mut registry, &request, 5_000).is_empty());

        let response = response_event(16_379, b"+OK\r\n");
        let signals = handle_at(&mut registry, &response, 7_000);
        assert_eq!(signals.len(), 1);
        assert_eq!(observation(&signals[0]).protocol, ProtocolKind::Redis);
        assert_eq!(observation(&signals[0]).duration_nanos, Some(2_000));
        assert_eq!(registry.counters().discovered_connections, 1);
    }

    #[test]
    fn dynamic_discovery_does_not_guess_an_ambiguous_prefix() {
        let mut registry = discovery_registry();
        let request = raw_event(16_379, b"PING\r\n", 6);

        assert!(handle_at(&mut registry, &request, 5_000).is_empty());
        assert_eq!(registry.tracked_connections(), 0);
        assert_eq!(registry.counters().discovery_unclassified_events, 1);
    }

    #[test]
    fn dynamic_discovery_reassembles_a_request_across_syscalls() {
        let mut registry = discovery_registry();
        let first = raw_event(16_379, b"*1\r\n", 4);
        assert!(handle_at(&mut registry, &first, 5_000).is_empty());

        let mut second = raw_event(16_379, b"$4\r\nPING\r\n", 10);
        second.timestamp_unix_nanos = 2_000;
        assert!(handle_at(&mut registry, &second, 6_000).is_empty());

        let response = response_event(16_379, b"+OK\r\n");
        let signals = handle_at(&mut registry, &response, 7_000);
        assert_eq!(signals.len(), 1);
        assert_eq!(observation(&signals[0]).protocol, ProtocolKind::Redis);
        assert_eq!(observation(&signals[0]).duration_nanos, Some(2_000));
        assert_eq!(registry.counters().discovered_connections, 1);
    }

    #[test]
    fn configured_port_precedes_dynamic_discovery() {
        let config = ProtocolSourceConfig {
            discovery_enabled: true,
            nats_ports: vec![16_379],
            ..ProtocolSourceConfig::default()
        };
        let mut registry = ProtocolStreamRegistry::new(
            Some("test-host".to_string()),
            std::path::PathBuf::from("__e_navigator_test_no_procfs__"),
            &config,
        );

        let signals = handle_at(&mut registry, &raw_event(16_379, b"PING\r\n", 6), 5_000);
        assert_eq!(signals.len(), 1);
        assert_eq!(observation(&signals[0]).protocol, ProtocolKind::Nats);
        assert_eq!(registry.counters().discovered_connections, 0);
        assert_eq!(registry.counters().discovery_unclassified_events, 0);
    }

    #[test]
    fn dynamic_discovery_candidate_count_is_bounded() {
        let config = ProtocolSourceConfig {
            discovery_enabled: true,
            max_tracked_connections: 1,
            ..ProtocolSourceConfig::default()
        };
        let mut registry = ProtocolStreamRegistry::new(
            Some("test-host".to_string()),
            std::path::PathBuf::from("__e_navigator_test_no_procfs__"),
            &config,
        );
        assert!(handle_at(&mut registry, &raw_event(16_379, b"PING\r\n", 6), 5_000,).is_empty());
        let mut second = raw_event(16_380, b"PING\r\n", 6);
        second.fd = 10;
        assert!(handle_at(&mut registry, &second, 6_000).is_empty());

        assert_eq!(registry.discovery_candidates.len(), 1);
        assert_eq!(registry.counters().discovery_candidate_evictions, 1);
    }

    #[test]
    fn kafka_duplicate_in_flight_correlation_id_is_non_destructive() {
        let mut registry = registry();
        let request = kafka_api_versions_request(7);
        for observed_at in [5_000, 6_000] {
            assert!(
                handle_at(
                    &mut registry,
                    &raw_event(9092, &request, request.len() as u32),
                    observed_at,
                )
                .is_empty()
            );
        }

        let response = kafka_api_versions_response(7);
        for expected_mismatches in [1, 2] {
            assert!(handle_at(&mut registry, &response_event(9092, &response), 7_000,).is_empty());
            assert_eq!(
                registry.counters().kafka_correlation_mismatches,
                expected_mismatches
            );
        }
        assert_eq!(registry.counters().matched_responses, 0);
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
    fn unmapped_port_is_an_explicit_filter() {
        let mut registry = registry();
        let payload = b"PING\r\n";
        let event = raw_event(8080, payload, payload.len() as u32);
        let mut signals = Vec::new();
        let err = registry
            .handle_event(raw_as_bytes(&event), 5_000, &mut signals)
            .expect_err("unmapped port is rejected");
        assert_eq!(err.reason_name(), "unmapped_port");
        assert!(err.is_filtered_sample());
    }

    #[test]
    fn unresolved_server_port_remains_invalid() {
        let mut registry = registry();
        let payload = b"PING\r\n";
        let mut event = raw_event(0, payload, payload.len() as u32);
        event.local_port_be = 0;
        event.role = RAW_PROTOCOL_ROLE_SERVER;
        event.direction = RAW_PROTOCOL_DIRECTION_READ;
        let mut signals = Vec::new();
        let err = registry
            .handle_event(raw_as_bytes(&event), 5_000, &mut signals)
            .expect_err("unresolved server port is rejected");
        assert_eq!(err.reason_name(), "unresolved_server_port");
        assert!(!err.is_filtered_sample());
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

        let response = response_event(3306, &[7, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0]);
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
    fn http2_request_continuation_reassembles_before_matching() {
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
        request_payload.extend_from_slice(&http2_frame(HTTP2_FRAME_TYPE_HEADERS, 0, 1, &[0x82]));
        let request = raw_event(50051, &request_payload, request_payload.len() as u32);
        assert!(handle_at(&mut registry, &request, 5_000).is_empty());

        let continuation = http2_frame(HTTP2_FRAME_TYPE_CONTINUATION, 0x4, 1, &[0x84]);
        let request = raw_event(50051, &continuation, continuation.len() as u32);
        assert!(handle_at(&mut registry, &request, 5_100).is_empty());

        let response_payload = http2_frame(HTTP2_FRAME_TYPE_HEADERS, 0x4 | 0x1, 1, &[0x88]);
        let mut response = raw_event(50051, &response_payload, response_payload.len() as u32);
        response.direction = RAW_PROTOCOL_DIRECTION_READ;
        let signals = handle_at(&mut registry, &response, 6_200);

        assert_eq!(signals.len(), 1);
        let observation = observation(&signals[0]);
        assert_eq!(observation.method.as_deref(), Some("GET"));
        assert_eq!(observation.duration_nanos, Some(1_200));
        assert_eq!(registry.counters().unparsed_frames, 0);
        assert_eq!(registry.counters().unparsed_responses, 0);
    }

    #[test]
    fn http2_response_continuation_preserves_initial_end_stream() {
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
        request_payload.extend_from_slice(&http2_frame(
            HTTP2_FRAME_TYPE_HEADERS,
            0x4,
            1,
            &[0x82, 0x84],
        ));
        let request = raw_event(50051, &request_payload, request_payload.len() as u32);
        assert!(handle_at(&mut registry, &request, 5_000).is_empty());

        let response_headers = http2_frame(HTTP2_FRAME_TYPE_HEADERS, 0x1, 1, &[]);
        let mut response = raw_event(50051, &response_headers, response_headers.len() as u32);
        response.direction = RAW_PROTOCOL_DIRECTION_READ;
        assert!(handle_at(&mut registry, &response, 5_500).is_empty());

        let response_continuation = http2_frame(HTTP2_FRAME_TYPE_CONTINUATION, 0x4, 1, &[0x88]);
        let mut response = raw_event(
            50051,
            &response_continuation,
            response_continuation.len() as u32,
        );
        response.direction = RAW_PROTOCOL_DIRECTION_READ;
        let signals = handle_at(&mut registry, &response, 6_000);

        assert_eq!(signals.len(), 1);
        let observation = observation(&signals[0]);
        assert_eq!(observation.duration_nanos, Some(1_000));
        assert!(
            observation
                .attributes
                .iter()
                .any(|attribute| attribute.key == "http.response.status_code"
                    && attribute.value == "200"),
        );
        assert_eq!(registry.counters().unparsed_frames, 0);
        assert_eq!(registry.counters().unparsed_responses, 0);
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
    fn registry_preserves_tls_source_provenance() {
        let config = ProtocolSourceConfig {
            http1_ports: vec![8443],
            ..ProtocolSourceConfig::default()
        };
        let mut registry = ProtocolStreamRegistry::new_with_source(
            None,
            std::path::PathBuf::from("__e_navigator_test_no_procfs__"),
            &config,
            "source.aya_tls",
        );
        let request = b"GET / HTTP/1.1\r\nHost: api.test\r\n\r\n";
        let event = raw_event(8443, request, request.len() as u32);
        assert!(handle_at(&mut registry, &event, 5_000).is_empty());
        let response = response_event(8443, b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
        let signals = handle_at(&mut registry, &response, 6_000);

        assert_eq!(signals.len(), 1);
        assert_eq!(signals[0].source, "source.aya_tls");
    }

    #[test]
    fn server_role_uses_local_port_and_read_as_request_direction() {
        let config = ProtocolSourceConfig {
            http1_ports: vec![8443],
            ..ProtocolSourceConfig::default()
        };
        let mut registry = ProtocolStreamRegistry::new(
            None,
            std::path::PathBuf::from("__e_navigator_test_no_procfs__"),
            &config,
        );

        let request = b"GET /inbound HTTP/1.1\r\nHost: api.test\r\n\r\n";
        let mut event = raw_event(51_000, request, request.len() as u32);
        event.local_port_be = 8443_u16.to_be();
        event.role = RAW_PROTOCOL_ROLE_SERVER;
        event.direction = RAW_PROTOCOL_DIRECTION_READ;
        assert!(handle_at(&mut registry, &event, 5_000).is_empty());

        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
        let mut event = raw_event(51_000, response, response.len() as u32);
        event.local_port_be = 8443_u16.to_be();
        event.role = RAW_PROTOCOL_ROLE_SERVER;
        event.direction = RAW_PROTOCOL_DIRECTION_WRITE;
        let signals = handle_at(&mut registry, &event, 6_000);

        assert_eq!(signals.len(), 1);
        let observation = observation(&signals[0]);
        assert_eq!(observation.role, Some(ProtocolCaptureRole::Server));
        assert_eq!(observation.method.as_deref(), Some("GET"));
        assert_eq!(observation.duration_nanos, Some(1_000));
    }

    #[cfg(unix)]
    #[test]
    fn server_role_resolves_preexisting_listener_port_from_bounded_procfs() {
        use std::os::unix::fs::symlink;

        let fixture_root = std::env::temp_dir().join(format!(
            "e-navigator-protocol-procfs-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock after epoch")
                .as_nanos(),
        ));
        let pid = 4_242_u32;
        let fd = 17_i32;
        let fd_root = fixture_root.join(pid.to_string()).join("fd");
        let net_root = fixture_root.join(pid.to_string()).join("net");
        std::fs::create_dir_all(&fd_root).expect("fixture fd directory");
        std::fs::create_dir_all(&net_root).expect("fixture net directory");
        symlink("socket:[12345]", fd_root.join(fd.to_string())).expect("fixture socket link");
        std::fs::write(
            net_root.join("tcp"),
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
               0: 00000000:20FB 00000000:0000 0A 00000000:00000000 00:00000000 00000000 1000 0 12345\n",
        )
        .expect("fixture tcp table");

        let listeners = discover_existing_listener_endpoints(&fixture_root);
        assert_eq!(listeners.len(), 1);
        assert_eq!(listeners[0].pid, pid);
        assert_eq!(listeners[0].fd, fd);
        assert_eq!(listeners[0].family, RAW_PROTOCOL_AF_INET);
        assert_eq!(u16::from_be(listeners[0].local_port_be), 8_443);

        let config = ProtocolSourceConfig {
            inbound_enabled: true,
            http1_ports: vec![8_443],
            ..ProtocolSourceConfig::default()
        };
        let mut registry = ProtocolStreamRegistry::new(None, fixture_root.clone(), &config);

        let request = b"GET /inbound HTTP/1.1\r\nHost: api.test\r\n\r\n";
        let mut event = raw_event(51_000, request, request.len() as u32);
        event.pid = pid;
        event.fd = fd;
        event.local_port_be = 0;
        event.role = RAW_PROTOCOL_ROLE_SERVER;
        event.direction = RAW_PROTOCOL_DIRECTION_READ;
        assert!(handle_at(&mut registry, &event, 5_000).is_empty());

        // The resolved endpoint is connection-scoped; later frames do not
        // depend on the procfs entry remaining readable.
        std::fs::remove_file(fd_root.join(fd.to_string())).expect("remove fixture link");
        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
        let mut event = raw_event(51_000, response, response.len() as u32);
        event.pid = pid;
        event.fd = fd;
        event.local_port_be = 0;
        event.role = RAW_PROTOCOL_ROLE_SERVER;
        event.direction = RAW_PROTOCOL_DIRECTION_WRITE;
        let signals = handle_at(&mut registry, &event, 6_000);

        assert_eq!(signals.len(), 1);
        let observation = observation(&signals[0]);
        assert_eq!(observation.role, Some(ProtocolCaptureRole::Server));
        assert_eq!(observation.method.as_deref(), Some("GET"));
        std::fs::remove_dir_all(&fixture_root).expect("remove fixture procfs");
    }

    #[test]
    fn server_grpc_capture_preserves_hpack_trace_context() {
        let config = ProtocolSourceConfig {
            http2_ports: vec![50051],
            ..ProtocolSourceConfig::default()
        };
        let mut registry = ProtocolStreamRegistry::new(
            None,
            std::path::PathBuf::from("__e_navigator_test_no_procfs__"),
            &config,
        );

        let mut block = vec![0x83]; // :method POST
        append_hpack_literal(&mut block, ":path", "/pkg.Svc/Call");
        append_hpack_literal(&mut block, "content-type", "application/grpc");
        append_hpack_literal(
            &mut block,
            "traceparent",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
        );
        append_hpack_literal(&mut block, "tracestate", "vendor=opaque");
        let mut request_payload = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
        request_payload.extend_from_slice(&http2_frame(1, 0x4, 1, &block));
        let mut request = raw_event(51_000, &request_payload, request_payload.len() as u32);
        request.local_port_be = 50051_u16.to_be();
        request.role = RAW_PROTOCOL_ROLE_SERVER;
        request.direction = RAW_PROTOCOL_DIRECTION_READ;
        assert!(handle_at(&mut registry, &request, 5_000).is_empty());

        let response_payload = http2_frame(1, 0x4 | 0x1, 1, &[0x88]);
        let mut response = raw_event(51_000, &response_payload, response_payload.len() as u32);
        response.local_port_be = 50051_u16.to_be();
        response.role = RAW_PROTOCOL_ROLE_SERVER;
        response.direction = RAW_PROTOCOL_DIRECTION_WRITE;
        let signals = handle_at(&mut registry, &response, 6_000);

        assert_eq!(signals.len(), 1);
        let observation = observation(&signals[0]);
        assert_eq!(observation.protocol, ProtocolKind::Grpc);
        assert_eq!(observation.role, Some(ProtocolCaptureRole::Server));
        assert_eq!(
            observation.trace_id.as_deref(),
            Some("4bf92f3577b34da6a3ce929d0e0e4736")
        );
        assert_eq!(observation.span_id.as_deref(), Some("00f067aa0ba902b7"));
        assert!(observation.attributes.iter().any(|attribute| {
            attribute.key == "e.navigator.trace.tracestate"
                && attribute.value == "validated_discarded"
        }));
    }

    #[test]
    fn server_grpc_cross_cpu_arrival_is_decoded_in_kernel_time_order() {
        let config = ProtocolSourceConfig {
            http2_ports: vec![50051],
            ..ProtocolSourceConfig::default()
        };
        let mut registry = ProtocolStreamRegistry::new(
            None,
            std::path::PathBuf::from("__e_navigator_test_no_procfs__"),
            &config,
        );

        let mut preface_and_settings = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
        preface_and_settings.extend_from_slice(&http2_frame(4, 0, 0, &[0; 36]));
        preface_and_settings.extend_from_slice(&http2_frame(8, 0, 0, &[0, 0, 0, 1]));
        let mut preface = raw_event(
            51_000,
            &preface_and_settings,
            preface_and_settings.len() as u32,
        );
        preface.local_port_be = 50051_u16.to_be();
        preface.role = RAW_PROTOCOL_ROLE_SERVER;
        preface.direction = RAW_PROTOCOL_DIRECTION_READ;
        preface.timestamp_unix_nanos = 100;

        let settings_ack_payload = http2_frame(4, 0x1, 0, &[]);
        let mut settings_ack = raw_event(
            51_000,
            &settings_ack_payload,
            settings_ack_payload.len() as u32,
        );
        settings_ack.local_port_be = 50051_u16.to_be();
        settings_ack.role = RAW_PROTOCOL_ROLE_SERVER;
        settings_ack.direction = RAW_PROTOCOL_DIRECTION_READ;
        settings_ack.timestamp_unix_nanos = 200;

        let mut block = vec![0x83]; // :method POST
        append_hpack_literal(&mut block, ":path", "/acceptance.Echo/Unary");
        append_hpack_literal(&mut block, "content-type", "application/grpc");
        append_hpack_literal(
            &mut block,
            "traceparent",
            "00-d60e3b12000000000000000000000001-face000000000001-01",
        );
        append_hpack_literal(&mut block, "user-agent", &"x".repeat(100));
        let mut request_payload = http2_frame(1, 0x4, 1, &block);
        request_payload.extend_from_slice(&http2_frame(0, 0x1, 1, &[0; 32]));
        assert!(request_payload.len() > RAW_PROTOCOL_DATA_BYTES);
        let mut request_segments = segmented_events(51_000, &request_payload);
        for segment in &mut request_segments {
            segment.local_port_be = 50051_u16.to_be();
            segment.role = RAW_PROTOCOL_ROLE_SERVER;
            segment.direction = RAW_PROTOCOL_DIRECTION_READ;
            segment.timestamp_unix_nanos = 300;
        }

        let response_payload = http2_frame(1, 0x4 | 0x1, 1, &[0x88]);
        let mut response = raw_event(51_000, &response_payload, response_payload.len() as u32);
        response.local_port_be = 50051_u16.to_be();
        response.role = RAW_PROTOCOL_ROLE_SERVER;
        response.direction = RAW_PROTOCOL_DIRECTION_WRITE;
        response.timestamp_unix_nanos = 400;

        let mut order = ProtocolSampleOrder::new(2, 16);
        // Model the observed grpcio scheduling: a worker CPU's HEADERS and
        // response arrive at userspace before another CPU's connection
        // preface and SETTINGS samples.
        for segment in &request_segments {
            assert!(order.push_sample(inline_sample(segment)).is_none());
        }
        assert!(order.push_sample(inline_sample(&response)).is_none());
        assert!(order.push_sample(inline_sample(&preface)).is_none());
        assert!(order.push_sample(inline_sample(&settings_ack)).is_none());
        order.update_watermark(0, 500);
        assert!(order.pop_ready().is_none());
        order.update_watermark(1, 500);

        let mut signals = Vec::new();
        while let Some(sample) = order.pop_ready() {
            let observed_unix_nanos =
                10_000 + protocol_sample_timestamp(&sample).expect("kernel timestamp");
            registry
                .handle_event(sample.as_bytes(), observed_unix_nanos, &mut signals)
                .expect("ordered raw event decodes");
        }

        assert_eq!(signals.len(), 1);
        let observation = observation(&signals[0]);
        assert_eq!(observation.protocol, ProtocolKind::Grpc);
        assert_eq!(observation.method.as_deref(), Some("POST"));
        assert!(observation.attributes.iter().any(|attribute| {
            attribute.key == "rpc.service" && attribute.value == "acceptance.Echo"
        }));
        assert!(
            observation
                .attributes
                .iter()
                .any(|attribute| { attribute.key == "rpc.method" && attribute.value == "Unary" })
        );
        assert_eq!(
            observation.trace_id.as_deref(),
            Some("d60e3b12000000000000000000000001")
        );
        assert_eq!(observation.span_id.as_deref(), Some("face000000000001"));
        assert_eq!(registry.counters().segment_gaps, 0);
        assert_eq!(registry.counters().unparsed_frames, 0);
    }

    fn append_hpack_literal(block: &mut Vec<u8>, name: &str, value: &str) {
        assert!(name.len() < 127);
        assert!(value.len() < 127);
        block.push(0x00);
        block.push(name.len() as u8);
        block.extend_from_slice(name.as_bytes());
        block.push(value.len() as u8);
        block.extend_from_slice(value.as_bytes());
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
    fn postgres_startup_owns_authentication_and_emits_one_private_connect_span() {
        let mut registry = registry();
        let startup = postgres_startup(b"user\0secret-user\0database\0secret-db\0\0");
        assert!(
            handle_at(
                &mut registry,
                &raw_event(5432, &startup, startup.len() as u32),
                5_000,
            )
            .is_empty()
        );

        let authentication_sasl = postgres_frame(
            b'R',
            &[
                0, 0, 0, 10, b'S', b'C', b'R', b'A', b'M', b'-', b'S', b'H', b'A', b'-', b'2',
                b'5', b'6', 0, 0,
            ],
        );
        assert!(
            handle_at(
                &mut registry,
                &response_event(5432, &authentication_sasl),
                6_000,
            )
            .is_empty()
        );

        // SASL responses are opaque bytes, not necessarily C strings. The
        // startup lifecycle owns them and must never emit their contents.
        let sasl_response = postgres_frame(b'p', b"secret-client-proof");
        assert!(
            handle_at(
                &mut registry,
                &raw_event(5432, &sasl_response, sasl_response.len() as u32),
                7_000,
            )
            .is_empty()
        );

        for response in [
            postgres_frame(b'R', &[0, 0, 0, 0]),
            postgres_frame(b'S', b"server_version\x0017.11\0"),
            postgres_frame(b'K', &[0xaa; 8]),
        ] {
            assert!(handle_at(&mut registry, &response_event(5432, &response), 8_000,).is_empty());
        }

        let ready = postgres_frame(b'Z', b"I");
        let signals = handle_at(&mut registry, &response_event(5432, &ready), 10_000);
        assert_eq!(signals.len(), 1);
        let observation = observation(&signals[0]);
        assert_eq!(observation.method.as_deref(), Some("CONNECT"));
        assert_eq!(observation.duration_nanos, Some(5_000));
        assert_eq!(registry.counters().matched_responses, 1);
        assert_eq!(registry.counters().unparsed_frames, 0);
        assert!(
            registry
                .connections
                .values()
                .next()
                .expect("postgres connection is tracked")
                .in_flight
                .is_empty()
        );
        let serialized = serde_json::to_string(&signals).expect("signals serialize");
        for secret in ["secret-user", "secret-db", "secret-client-proof"] {
            assert!(!serialized.contains(secret));
        }
    }

    #[test]
    fn postgres_ssl_rejection_keeps_cleartext_startup_aligned() {
        let mut registry = registry();
        let mut ssl_request = 8_u32.to_be_bytes().to_vec();
        ssl_request.extend_from_slice(&80_877_103_u32.to_be_bytes());
        assert!(
            handle_at(
                &mut registry,
                &raw_event(5432, &ssl_request, ssl_request.len() as u32),
                5_000,
            )
            .is_empty()
        );
        assert!(handle_at(&mut registry, &response_event(5432, b"N"), 6_000).is_empty());

        let startup = postgres_startup(b"user\0secret-user\0\0");
        assert!(
            handle_at(
                &mut registry,
                &raw_event(5432, &startup, startup.len() as u32),
                7_000,
            )
            .is_empty()
        );
        let ready = postgres_frame(b'Z', b"I");
        let signals = handle_at(&mut registry, &response_event(5432, &ready), 9_000);
        assert_eq!(signals.len(), 1);
        assert_eq!(observation(&signals[0]).method.as_deref(), Some("CONNECT"));
        assert_eq!(
            registry.counters().postgres_encryption_negotiation_rejected,
            1
        );
        assert_eq!(registry.counters().unparsed_frames, 0);
        assert_eq!(registry.counters().unparsed_responses, 0);
    }

    #[test]
    fn postgres_accepted_ssl_marks_raw_transport_opaque() {
        let mut registry = registry();
        let mut ssl_request = 8_u32.to_be_bytes().to_vec();
        ssl_request.extend_from_slice(&80_877_103_u32.to_be_bytes());
        assert!(
            handle_at(
                &mut registry,
                &raw_event(5432, &ssl_request, ssl_request.len() as u32),
                5_000,
            )
            .is_empty()
        );
        assert!(handle_at(&mut registry, &response_event(5432, b"S"), 6_000).is_empty());

        let tls_record = [0x16, 0x03, 0x03, 0, 8, 0xaa, 0xbb, 0xcc];
        assert!(
            handle_at(
                &mut registry,
                &raw_event(5432, &tls_record, tls_record.len() as u32),
                7_000,
            )
            .is_empty()
        );
        assert_eq!(
            registry.counters().postgres_encryption_negotiation_accepted,
            1
        );
        assert_eq!(registry.counters().postgres_encrypted_transport_events, 1);
        assert_eq!(registry.counters().unparsed_frames, 0);
    }

    #[test]
    fn postgres_ssl_buffer_stuffing_fails_closed_with_diagnostic() {
        let mut registry = registry();
        let mut ssl_request = 8_u32.to_be_bytes().to_vec();
        ssl_request.extend_from_slice(&80_877_103_u32.to_be_bytes());
        assert!(
            handle_at(
                &mut registry,
                &raw_event(5432, &ssl_request, ssl_request.len() as u32),
                5_000,
            )
            .is_empty()
        );

        // PostgreSQL requires exactly one negotiation byte before the TLS
        // library takes ownership. Extra bytes are ambiguous and must not be
        // parsed as either backend messages or ciphertext.
        let stuffed = [b'S', 0x16, 0x03, 0x03];
        assert!(handle_at(&mut registry, &response_event(5432, &stuffed), 6_000,).is_empty());
        assert_eq!(registry.counters().postgres_negotiation_failures, 1);
        assert_eq!(
            registry.counters().postgres_encryption_negotiation_accepted,
            0
        );
        assert_eq!(registry.counters().unparsed_responses, 0);

        let ciphertext = [0x16, 0x03, 0x03, 0, 1, 0];
        assert!(
            handle_at(
                &mut registry,
                &raw_event(5432, &ciphertext, ciphertext.len() as u32),
                7_000,
            )
            .is_empty()
        );
        assert_eq!(registry.counters().postgres_encrypted_transport_events, 1);
    }

    #[test]
    fn postgres_query_retains_error_until_ready_for_query() {
        let mut registry = registry();
        let request = postgres_frame(
            b'Q',
            b"INSERT INTO accounts VALUES (1); SELECT secret_value\0",
        );
        assert!(
            handle_at(
                &mut registry,
                &raw_event(5432, &request, request.len() as u32),
                5_000,
            )
            .is_empty()
        );

        let error = postgres_error(b"23505", b"secret constraint detail");
        assert!(
            handle_at(&mut registry, &response_event(5432, &error), 7_000).is_empty(),
            "ErrorResponse is not the simple-query cycle terminator"
        );

        let ready = postgres_frame(b'Z', b"E");
        let signals = handle_at(&mut registry, &response_event(5432, &ready), 9_000);

        assert_eq!(signals.len(), 1);
        let observation = observation(&signals[0]);
        assert_eq!(observation.method.as_deref(), Some("INSERT"));
        assert_eq!(observation.duration_nanos, Some(4_000));
        assert!(observation.attributes.iter().any(|attribute| {
            attribute.key == "db.response.status_code" && attribute.value == "23505"
        }));
        assert!(
            observation
                .attributes
                .iter()
                .any(|attribute| { attribute.key == "error.type" && attribute.value == "23505" })
        );
        assert!(observation.attributes.iter().any(|attribute| {
            attribute.key == "db.postgresql.transaction.status"
                && attribute.value == "failed_transaction"
        }));
        assert_eq!(registry.counters().matched_responses, 1);
        assert_eq!(registry.counters().orphan_responses, 0);
        let serialized = serde_json::to_string(&signals).expect("signals serialize");
        assert!(!serialized.contains("secret"));
        assert!(!serialized.contains("constraint"));
        assert!(!serialized.contains("accounts"));
    }

    #[test]
    fn postgres_extended_pipeline_matches_each_protocol_terminal() {
        let mut registry = registry();
        let requests = [
            postgres_frame(b'P', b"\0SELECT secret_value\0\0\0"),
            postgres_frame(b'B', &[0; 8]),
            postgres_frame(b'D', b"S\0"),
            postgres_frame(b'E', &[0; 5]),
            postgres_frame(b'S', b""),
        ];
        for (index, request) in requests.iter().enumerate() {
            assert!(
                handle_at(
                    &mut registry,
                    &raw_event(5432, request, request.len() as u32),
                    5_000 + index as u64,
                )
                .is_empty()
            );
        }
        let stream = registry
            .connections
            .values()
            .next()
            .expect("postgres connection is tracked");
        assert_eq!(stream.in_flight.len(), requests.len());
        assert!(
            stream
                .in_flight
                .front()
                .is_some_and(|entry| entry.postgres_request_response.is_some())
        );

        for (response, expected_method) in [
            (postgres_frame(b'1', b""), "SELECT"),
            (postgres_frame(b'2', b""), "BIND"),
        ] {
            let signals = handle_at(&mut registry, &response_event(5432, &response), 8_000);
            assert_eq!(signals.len(), 1, "counters: {:?}", registry.counters());
            assert_eq!(
                observation(&signals[0]).method.as_deref(),
                Some(expected_method)
            );
        }

        let parameter_description = postgres_frame(b't', &[0, 0]);
        assert!(
            handle_at(
                &mut registry,
                &response_event(5432, &parameter_description),
                8_000,
            )
            .is_empty()
        );
        let no_data = postgres_frame(b'n', b"");
        let signals = handle_at(&mut registry, &response_event(5432, &no_data), 8_000);
        assert_eq!(signals.len(), 1);
        assert_eq!(observation(&signals[0]).method.as_deref(), Some("DESCRIBE"));

        let command_complete = postgres_frame(b'C', b"SELECT 1\0");
        let signals = handle_at(
            &mut registry,
            &response_event(5432, &command_complete),
            8_000,
        );
        assert_eq!(signals.len(), 1);
        assert_eq!(observation(&signals[0]).method.as_deref(), Some("EXECUTE"));

        let ready = postgres_frame(b'Z', b"I");
        let signals = handle_at(&mut registry, &response_event(5432, &ready), 8_000);
        assert_eq!(signals.len(), 1);
        let observation = observation(&signals[0]);
        assert_eq!(observation.method.as_deref(), Some("SYNC"));
        assert!(observation.attributes.iter().any(|attribute| {
            attribute.key == "db.postgresql.transaction.status" && attribute.value == "idle"
        }));
        assert_eq!(registry.counters().matched_responses, 5);
        let serialized = serde_json::to_string(&signals).expect("signals serialize");
        assert!(!serialized.contains("secret_value"));
    }

    #[test]
    fn postgres_extended_error_discards_pipeline_until_sync() {
        let mut registry = registry();
        let requests = [
            postgres_frame(b'P', b"\0SELECT secret_value\0\0\0"),
            postgres_frame(b'B', &[0; 8]),
            postgres_frame(b'E', &[0; 5]),
            postgres_frame(b'S', b""),
            postgres_frame(b'P', b"\0SELECT another_secret\0\0\0"),
        ];
        for (index, request) in requests.iter().enumerate() {
            assert!(
                handle_at(
                    &mut registry,
                    &raw_event(5432, request, request.len() as u32),
                    5_000 + index as u64,
                )
                .is_empty()
            );
        }

        let error = postgres_error(b"23505", b"secret constraint detail");
        let signals = handle_at(&mut registry, &response_event(5432, &error), 8_000);
        assert_eq!(signals.len(), 3);
        let parse = observation(&signals[0]);
        assert_eq!(parse.method.as_deref(), Some("SELECT"));
        assert_eq!(parse.duration_nanos, Some(3_000));
        assert!(
            parse
                .attributes
                .iter()
                .any(|attribute| { attribute.key == "error.type" && attribute.value == "23505" })
        );
        for skipped in &signals[1..] {
            let skipped = observation(skipped);
            assert_eq!(skipped.duration_nanos, None);
            assert_eq!(skipped.confidence, TraceConfidence::Low);
        }
        assert_eq!(registry.counters().postgres_skipped_requests, 2);
        let ready = postgres_frame(b'Z', b"I");
        let signals = handle_at(&mut registry, &response_event(5432, &ready), 9_000);
        assert_eq!(signals.len(), 1);
        assert_eq!(observation(&signals[0]).method.as_deref(), Some("SYNC"));

        let parse_complete = postgres_frame(b'1', b"");
        let signals = handle_at(
            &mut registry,
            &response_event(5432, &parse_complete),
            11_000,
        );
        assert_eq!(signals.len(), 1);
        assert_eq!(observation(&signals[0]).method.as_deref(), Some("SELECT"));
        let serialized = serde_json::to_string(&signals).expect("signals serialize");
        assert!(!serialized.contains("secret"));
    }

    #[test]
    fn postgres_copy_control_frames_do_not_displace_the_initiating_query() {
        let mut registry = registry();
        let query = postgres_frame(b'Q', b"COPY secret_table FROM STDIN\0");
        assert!(
            handle_at(
                &mut registry,
                &raw_event(5432, &query, query.len() as u32),
                5_000,
            )
            .is_empty()
        );

        let copy_in = postgres_frame(b'G', &[0, 0, 0]);
        assert!(handle_at(&mut registry, &response_event(5432, &copy_in), 6_000,).is_empty());
        for (request, method) in [
            (postgres_frame(b'd', b"secret-copy-row"), "COPY_DATA"),
            (postgres_frame(b'c', b""), "COPY_DONE"),
        ] {
            let signals = handle_at(
                &mut registry,
                &raw_event(5432, &request, request.len() as u32),
                7_000,
            );
            assert_eq!(signals.len(), 1);
            let observation = observation(&signals[0]);
            assert_eq!(observation.method.as_deref(), Some(method));
            assert_eq!(observation.duration_nanos, None);
            let serialized = serde_json::to_string(&signals).expect("signals serialize");
            assert!(!serialized.contains("secret-copy-row"));
        }
        assert_eq!(
            registry
                .connections
                .values()
                .next()
                .expect("postgres connection is tracked")
                .in_flight
                .len(),
            1
        );

        let command_complete = postgres_frame(b'C', b"COPY 1\0");
        assert!(
            handle_at(
                &mut registry,
                &response_event(5432, &command_complete),
                8_000,
            )
            .is_empty()
        );
        let ready = postgres_frame(b'Z', b"I");
        let signals = handle_at(&mut registry, &response_event(5432, &ready), 9_000);
        assert_eq!(signals.len(), 1);
        assert_eq!(observation(&signals[0]).method.as_deref(), Some("COPY"));
        assert_eq!(observation(&signals[0]).duration_nanos, Some(4_000));
        assert!(
            registry
                .connections
                .values()
                .next()
                .expect("postgres connection is tracked")
                .in_flight
                .is_empty()
        );
    }

    #[test]
    fn postgres_copy_in_ignores_prequeued_and_in_mode_sync_without_displacing_query() {
        let mut registry = registry();
        let query = postgres_frame(b'Q', b"COPY secret_table FROM STDIN\0");
        let sync = postgres_frame(b'S', b"");
        for (timestamp, request) in [(5_000, &query), (5_100, &sync)] {
            assert!(
                handle_at(
                    &mut registry,
                    &raw_event(5432, request, request.len() as u32),
                    timestamp,
                )
                .is_empty()
            );
        }
        assert_eq!(
            registry
                .connections
                .values()
                .next()
                .expect("postgres connection is tracked")
                .in_flight
                .len(),
            2
        );

        let copy_in = postgres_frame(b'G', &[0, 0, 0]);
        assert!(handle_at(&mut registry, &response_event(5432, &copy_in), 6_000).is_empty());
        assert_eq!(
            registry
                .connections
                .values()
                .next()
                .expect("postgres connection is tracked")
                .in_flight
                .len(),
            1
        );

        // Sync and Flush received during copy-in are protocol-defined no-ops.
        for request in [postgres_frame(b'S', b""), postgres_frame(b'H', b"")] {
            assert!(
                handle_at(
                    &mut registry,
                    &raw_event(5432, &request, request.len() as u32),
                    6_500,
                )
                .is_empty()
            );
        }
        assert_eq!(registry.counters().postgres_copy_ignored_controls, 3);

        for request in [
            postgres_frame(b'd', b"secret-copy-row"),
            postgres_frame(b'c', b""),
        ] {
            let signals = handle_at(
                &mut registry,
                &raw_event(5432, &request, request.len() as u32),
                7_000,
            );
            assert_eq!(signals.len(), 1);
        }
        let command_complete = postgres_frame(b'C', b"COPY 1\0");
        assert!(
            handle_at(
                &mut registry,
                &response_event(5432, &command_complete),
                8_000,
            )
            .is_empty()
        );
        let ready = postgres_frame(b'Z', b"I");
        let signals = handle_at(&mut registry, &response_event(5432, &ready), 9_000);
        assert_eq!(signals.len(), 1);
        assert_eq!(observation(&signals[0]).method.as_deref(), Some("COPY"));
        assert!(
            registry
                .connections
                .values()
                .next()
                .expect("postgres connection is tracked")
                .in_flight
                .is_empty()
        );
    }

    #[test]
    fn postgres_late_pipeline_requests_resume_immediately_after_sync_is_sent() {
        let mut registry = registry();
        let parse = postgres_frame(b'P', b"\0SELECT secret_value\0\0\0");
        assert!(
            handle_at(
                &mut registry,
                &raw_event(5432, &parse, parse.len() as u32),
                5_000,
            )
            .is_empty()
        );
        let error = postgres_error(b"23505", b"secret constraint detail");
        let signals = handle_at(&mut registry, &response_event(5432, &error), 6_000);
        assert_eq!(signals.len(), 1);

        let skipped_bind = postgres_frame(b'B', &[0; 8]);
        let signals = handle_at(
            &mut registry,
            &raw_event(5432, &skipped_bind, skipped_bind.len() as u32),
            7_000,
        );
        assert_eq!(signals.len(), 1);
        assert_eq!(observation(&signals[0]).method.as_deref(), Some("BIND"));
        assert_eq!(observation(&signals[0]).confidence, TraceConfidence::Low);
        assert_eq!(observation(&signals[0]).duration_nanos, None);

        let sync = postgres_frame(b'S', b"");
        assert!(
            handle_at(
                &mut registry,
                &raw_event(5432, &sync, sync.len() as u32),
                8_000,
            )
            .is_empty()
        );
        let next_parse = postgres_frame(b'P', b"\0SELECT another_secret\0\0\0");
        assert!(
            handle_at(
                &mut registry,
                &raw_event(5432, &next_parse, next_parse.len() as u32),
                9_000,
            )
            .is_empty(),
            "messages after the observed Sync belong to the next pipeline segment"
        );

        let ready = postgres_frame(b'Z', b"I");
        let signals = handle_at(&mut registry, &response_event(5432, &ready), 10_000);
        assert_eq!(signals.len(), 1);
        assert_eq!(observation(&signals[0]).method.as_deref(), Some("SYNC"));
        let parse_complete = postgres_frame(b'1', b"");
        let signals = handle_at(
            &mut registry,
            &response_event(5432, &parse_complete),
            11_000,
        );
        assert_eq!(signals.len(), 1);
        assert_eq!(observation(&signals[0]).method.as_deref(), Some("SELECT"));
        assert_eq!(registry.counters().postgres_skipped_requests, 1);
    }

    #[test]
    fn mysql_result_set_completes_only_at_the_terminal_packet() {
        let mut registry = registry();
        let request = [7, 0, 0, 0, 3, b's', b'e', b'l', b'e', b'c', b't'];
        let event = raw_event(3306, &request, request.len() as u32);
        assert!(handle_at(&mut registry, &event, 5_000).is_empty());
        let column_definition = mysql_column_definition_packet(2);

        // One column, its definition, the metadata terminator, and one text
        // row are all continuations of the same command lifecycle.
        for packet in [
            &[1, 0, 0, 1, 1][..],
            column_definition.as_slice(),
            &[5, 0, 0, 3, 0xfe, 0, 0, 2, 0][..],
            &[2, 0, 0, 4, 1, b'x'][..],
        ] {
            assert!(
                handle_at(&mut registry, &response_event(3306, packet), 6_000).is_empty(),
                "intermediate result-set packet completed the request"
            );
        }

        let terminal = [5, 0, 0, 5, 0xfe, 0, 0, 2, 0];
        let signals = handle_at(&mut registry, &response_event(3306, &terminal), 9_000);

        assert_eq!(signals.len(), 1);
        let observation = observation(&signals[0]);
        assert_eq!(observation.protocol, ProtocolKind::Mysql);
        assert_eq!(observation.method.as_deref(), Some("SELECT"));
        assert_eq!(observation.duration_nanos, Some(4_000));
        assert!(observation.attributes.iter().any(|attribute| {
            attribute.key == "db.response.status_code" && attribute.value == "EOF"
        }));
        assert_eq!(registry.counters().response_continuations, 4);
        assert_eq!(registry.counters().orphan_responses, 0);
    }

    #[test]
    fn mysql_zlib_handshake_activates_only_after_auth_ok_and_correlates_frames() {
        let mut registry = registry();
        let capabilities = (1 << 9) | (1 << 5);
        let greeting = mysql_server_greeting(capabilities);
        assert!(handle_at(&mut registry, &response_event(3306, &greeting), 1_000).is_empty());
        let handshake = mysql_client_handshake_response(1, capabilities);
        assert!(
            handle_at(
                &mut registry,
                &raw_event(3306, &handshake, handshake.len() as u32),
                2_000,
            )
            .is_empty()
        );
        let auth_ok = mysql_wire_packet(2, &[0, 0, 0, 2, 0, 0, 0]);
        assert!(handle_at(&mut registry, &response_event(3306, &auth_ok), 3_000).is_empty());

        let query = mysql_wire_packet(0, b"\x03SELECT secret FROM private_table");
        let request = mysql_compressed_packet(0, &query, true);
        assert!(
            handle_at(
                &mut registry,
                &raw_event(3306, &request, request.len() as u32),
                5_000,
            )
            .is_empty()
        );
        let ok = mysql_wire_packet(1, &[0, 0, 0, 2, 0, 0, 0]);
        let response = mysql_compressed_packet(1, &ok, false);
        let signals = handle_at(&mut registry, &response_event(3306, &response), 9_000);

        assert_eq!(signals.len(), 1);
        let observation = observation(&signals[0]);
        assert_eq!(observation.protocol, ProtocolKind::Mysql);
        assert_eq!(observation.method.as_deref(), Some("SELECT"));
        assert_eq!(observation.duration_nanos, Some(4_000));
        assert_eq!(registry.counters().mysql_server_greetings, 1);
        assert_eq!(registry.counters().mysql_client_handshakes, 1);
        assert_eq!(registry.counters().mysql_compression_zlib_connections, 1);
        assert_eq!(registry.counters().mysql_compressed_packets, 2);
        assert_eq!(registry.counters().mysql_compression_failures, 0);
        assert_eq!(registry.counters().orphan_responses, 0);
        assert_eq!(registry.counters().unparsed_frames, 0);
        let serialized = serde_json::to_string(&signals).expect("signals serialize");
        assert!(!serialized.contains("secret"));
        assert!(!serialized.contains("private_table"));
    }

    #[test]
    fn mysql_zlib_auth_switch_split_packets_and_sequence_reset_remain_correlated() {
        let mut registry = registry();
        let capabilities = (1 << 9) | (1 << 5);
        let greeting = mysql_server_greeting(capabilities);
        assert!(handle(&mut registry, &response_event(3306, &greeting)).is_empty());
        let handshake = mysql_client_handshake_response(1, capabilities);
        assert!(
            handle(
                &mut registry,
                &raw_event(3306, &handshake, handshake.len() as u32),
            )
            .is_empty()
        );
        let auth_switch = mysql_wire_packet(2, b"\xfecaching_sha2_password\0salt\0");
        assert!(handle(&mut registry, &response_event(3306, &auth_switch)).is_empty());
        let auth_reply = mysql_wire_packet(3, b"private-auth-response");
        assert!(
            handle(
                &mut registry,
                &raw_event(3306, &auth_reply, auth_reply.len() as u32),
            )
            .is_empty()
        );
        let auth_ok = mysql_wire_packet(4, &[0, 0, 0, 2, 0, 0, 0]);
        assert!(handle(&mut registry, &response_event(3306, &auth_ok)).is_empty());

        let query = mysql_wire_packet(0, b"\x03SELECT secret FROM private_table");
        let split_at = 9;
        let first = mysql_compressed_packet(0, &query[..split_at], false);
        let second = mysql_compressed_packet(1, &query[split_at..], true);
        assert!(
            handle_at(
                &mut registry,
                &raw_event(3306, &first, first.len() as u32),
                5_000,
            )
            .is_empty()
        );
        assert!(
            handle_at(
                &mut registry,
                &raw_event(3306, &second, second.len() as u32),
                5_500,
            )
            .is_empty()
        );

        let resultset = [
            mysql_wire_packet(1, &[1]),
            mysql_column_definition_packet(2),
            mysql_wire_packet(3, &[0xfe, 0, 0, 2, 0]),
            mysql_wire_packet(4, &[1, b'x']),
            mysql_wire_packet(5, &[0xfe, 0, 0, 2, 0]),
        ]
        .concat();
        let response = mysql_compressed_packet(2, &resultset, true);
        let signals = handle_at(&mut registry, &response_event(3306, &response), 9_000);
        assert_eq!(signals.len(), 1);
        assert_eq!(observation(&signals[0]).method.as_deref(), Some("SELECT"));
        assert_eq!(observation(&signals[0]).duration_nanos, Some(4_000));

        let ping = mysql_wire_packet(0, &[0x0e]);
        let ping = mysql_compressed_packet(0, &ping, false);
        assert!(
            handle_at(
                &mut registry,
                &raw_event(3306, &ping, ping.len() as u32),
                10_000,
            )
            .is_empty()
        );
        let pong = mysql_wire_packet(1, &[0, 0, 0, 2, 0, 0, 0]);
        let pong = mysql_compressed_packet(1, &pong, false);
        let signals = handle_at(&mut registry, &response_event(3306, &pong), 11_000);
        assert_eq!(signals.len(), 1);
        assert_eq!(observation(&signals[0]).method.as_deref(), Some("PING"));
        assert_eq!(registry.counters().mysql_auth_packets, 3);
        assert_eq!(registry.counters().mysql_compressed_packets, 5);
        assert_eq!(registry.counters().mysql_compression_failures, 0);
        assert_eq!(registry.counters().mysql_handshake_failures, 0);
        let serialized = serde_json::to_string(&signals).expect("signals serialize");
        assert!(!serialized.contains("private"));
    }

    #[test]
    fn mysql_tls_boundary_handshake_is_counted_as_unverified_but_bounded() {
        let mut registry = registry();
        let capabilities = (1 << 9) | (1 << 5);
        let handshake = mysql_client_handshake_response(2, capabilities);
        assert!(
            handle(
                &mut registry,
                &raw_event(3306, &handshake, handshake.len() as u32),
            )
            .is_empty()
        );
        let auth_ok = mysql_wire_packet(3, &[0, 0, 0, 2, 0, 0, 0]);
        assert!(handle(&mut registry, &response_event(3306, &auth_ok)).is_empty());

        let ping = mysql_compressed_packet(0, &mysql_wire_packet(0, &[0x0e]), false);
        assert!(handle(&mut registry, &raw_event(3306, &ping, ping.len() as u32),).is_empty());
        let pong = mysql_compressed_packet(1, &mysql_wire_packet(1, &[0, 0, 0, 2, 0, 0, 0]), false);
        let signals = handle(&mut registry, &response_event(3306, &pong));
        assert_eq!(signals.len(), 1);
        assert_eq!(observation(&signals[0]).method.as_deref(), Some("PING"));
        assert_eq!(registry.counters().mysql_server_greetings, 0);
        assert_eq!(registry.counters().mysql_compression_zlib_connections, 1);
        assert_eq!(
            registry.counters().mysql_compression_unverified_connections,
            1
        );
    }

    #[test]
    fn mysql_compression_negotiation_falls_back_or_fails_closed_explicitly() {
        let mut fallback = registry();
        let protocol_41 = 1 << 9;
        let greeting = mysql_server_greeting(protocol_41);
        assert!(handle(&mut fallback, &response_event(3306, &greeting)).is_empty());
        let handshake = mysql_client_handshake_response(1, protocol_41 | (1 << 5));
        assert!(
            handle(
                &mut fallback,
                &raw_event(3306, &handshake, handshake.len() as u32),
            )
            .is_empty()
        );
        let auth_ok = mysql_wire_packet(2, &[0, 0, 0, 2, 0, 0, 0]);
        assert!(handle(&mut fallback, &response_event(3306, &auth_ok)).is_empty());
        let ping = mysql_wire_packet(0, &[0x0e]);
        assert!(handle(&mut fallback, &raw_event(3306, &ping, ping.len() as u32),).is_empty());
        let pong = mysql_wire_packet(1, &[0, 0, 0, 2, 0, 0, 0]);
        assert_eq!(handle(&mut fallback, &response_event(3306, &pong)).len(), 1);
        assert_eq!(fallback.counters().mysql_compression_zlib_connections, 0);

        let mut zstd = registry();
        let zstd_capabilities = protocol_41 | (1 << 26);
        let greeting = mysql_server_greeting(zstd_capabilities);
        assert!(handle(&mut zstd, &response_event(3306, &greeting)).is_empty());
        let handshake = mysql_client_handshake_response(1, zstd_capabilities);
        assert!(
            handle(
                &mut zstd,
                &raw_event(3306, &handshake, handshake.len() as u32),
            )
            .is_empty()
        );
        let auth_ok = mysql_wire_packet(2, &[0, 0, 0, 2, 0, 0, 0]);
        assert!(handle(&mut zstd, &response_event(3306, &auth_ok)).is_empty());
        assert_eq!(zstd.counters().mysql_compression_zstd_rejections, 1);
        let opaque = mysql_compressed_packet(0, &mysql_wire_packet(0, &[0x0e]), false);
        assert!(handle(&mut zstd, &raw_event(3306, &opaque, opaque.len() as u32),).is_empty());
        assert_eq!(zstd.counters().mysql_compression_opaque_events, 1);
        assert_eq!(zstd.counters().unparsed_frames, 0);
    }

    #[test]
    fn mysql_compressed_sequence_mismatch_makes_transport_opaque() {
        let mut registry = registry();
        let capabilities = (1 << 9) | (1 << 5);
        let greeting = mysql_server_greeting(capabilities);
        assert!(handle(&mut registry, &response_event(3306, &greeting)).is_empty());
        let handshake = mysql_client_handshake_response(1, capabilities);
        assert!(
            handle(
                &mut registry,
                &raw_event(3306, &handshake, handshake.len() as u32),
            )
            .is_empty()
        );
        let auth_ok = mysql_wire_packet(2, &[0, 0, 0, 2, 0, 0, 0]);
        assert!(handle(&mut registry, &response_event(3306, &auth_ok)).is_empty());

        let wrong_sequence = mysql_compressed_packet(1, &mysql_wire_packet(0, &[0x0e]), false);
        assert!(
            handle(
                &mut registry,
                &raw_event(3306, &wrong_sequence, wrong_sequence.len() as u32),
            )
            .is_empty()
        );
        assert_eq!(registry.counters().mysql_compression_failures, 1);
        let valid = mysql_compressed_packet(0, &mysql_wire_packet(0, &[0x0e]), false);
        assert!(handle(&mut registry, &raw_event(3306, &valid, valid.len() as u32),).is_empty());
        assert_eq!(registry.counters().mysql_compression_opaque_events, 1);
        assert!(
            registry
                .connections
                .values()
                .next()
                .expect("mysql connection remains diagnosed")
                .in_flight
                .is_empty()
        );
    }

    #[test]
    fn mysql_local_infile_upload_remains_owned_by_the_original_query() {
        let mut registry = registry();
        let request = mysql_wire_packet(
            0,
            b"\x03LOAD DATA LOCAL INFILE 'secret.csv' INTO TABLE private_table",
        );
        assert!(
            handle_at(
                &mut registry,
                &raw_event(3306, &request, request.len() as u32),
                5_000,
            )
            .is_empty()
        );

        let local_infile = mysql_wire_packet(1, b"\xfbsecret-server-path.csv");
        assert!(handle_at(&mut registry, &response_event(3306, &local_infile), 6_000,).is_empty());

        // Only a bounded prefix is captured from a 1024-byte file packet.
        // The lifecycle needs its header and sequence, never the file body.
        let mut large_prefix = vec![0, 4, 0, 2];
        large_prefix.extend_from_slice(b"secret-file-prefix");
        assert!(
            handle_at(&mut registry, &raw_event(3306, &large_prefix, 1_028), 7_000,).is_empty()
        );
        let terminator = mysql_wire_packet(3, b"");
        assert!(
            handle_at(
                &mut registry,
                &raw_event(3306, &terminator, terminator.len() as u32),
                8_000,
            )
            .is_empty()
        );

        let ok = mysql_wire_packet(4, &[0, 0, 0, 2, 0, 0, 0]);
        let signals = handle_at(&mut registry, &response_event(3306, &ok), 10_000);
        assert_eq!(signals.len(), 1);
        let observation = observation(&signals[0]);
        assert_eq!(observation.method.as_deref(), Some("LOAD"));
        assert_eq!(observation.duration_nanos, Some(5_000));
        assert_eq!(registry.counters().mysql_local_infile_packets, 2);
        assert_eq!(registry.counters().mysql_local_infile_bytes, 1_024);
        assert_eq!(registry.counters().unparsed_frames, 0);
        assert!(
            registry
                .connections
                .values()
                .next()
                .expect("mysql connection is tracked")
                .in_flight
                .is_empty()
        );
        let serialized = serde_json::to_string(&signals).expect("signals serialize");
        for secret in [
            "secret.csv",
            "private_table",
            "secret-server-path",
            "secret-file-prefix",
        ] {
            assert!(!serialized.contains(secret));
        }
    }

    #[test]
    fn mysql_large_logical_request_is_correlated_once_from_its_bounded_prefix() {
        let mut registry = registry();
        let declared_len = 0x00ff_ffff_u32 + 4;
        let first_prefix = [
            0xff, 0xff, 0xff, 0, 0x03, b'S', b'E', b'L', b'E', b'C', b'T', b' ', b's', b'e', b'c',
            b'r', b'e', b't',
        ];
        assert!(
            handle_at(
                &mut registry,
                &raw_event(3306, &first_prefix, declared_len),
                5_000,
            )
            .is_empty()
        );

        let final_packet = mysql_wire_packet(1, b"private-tail");
        assert!(
            handle_at(
                &mut registry,
                &raw_event(3306, &final_packet, final_packet.len() as u32),
                6_000,
            )
            .is_empty()
        );

        let ok = mysql_wire_packet(2, &[0, 0, 0, 2, 0, 0, 0]);
        let signals = handle_at(&mut registry, &response_event(3306, &ok), 9_000);
        assert_eq!(signals.len(), 1);
        let observation = observation(&signals[0]);
        assert_eq!(observation.method.as_deref(), Some("SELECT"));
        assert_eq!(observation.duration_nanos, Some(4_000));
        assert_eq!(registry.counters().mysql_logical_request_continuations, 1);
        assert_eq!(registry.counters().mysql_logical_sequence_failures, 0);
        assert_eq!(registry.counters().unmatched_overflow, 0);
        let serialized = serde_json::to_string(&signals).expect("signals serialize");
        assert!(!serialized.contains("secret"));
        assert!(!serialized.contains("private-tail"));
    }

    #[test]
    fn mysql_large_result_row_does_not_complete_or_displace_the_query() {
        let mut registry = registry();
        let request = mysql_wire_packet(0, b"\x03SELECT secret FROM private_table");
        assert!(
            handle_at(
                &mut registry,
                &raw_event(3306, &request, request.len() as u32),
                5_000,
            )
            .is_empty()
        );
        for packet in [
            mysql_wire_packet(1, &[1]),
            mysql_column_definition_packet(2),
            mysql_wire_packet(3, &[0xfe, 0, 0, 2, 0]),
        ] {
            assert!(handle_at(&mut registry, &response_event(3306, &packet), 6_000).is_empty());
        }

        let declared_len = 0x00ff_ffff_u32 + 4;
        let row_prefix = [
            0xff, 0xff, 0xff, 4, 0x03, b's', b'e', b'c', b'r', b'e', b't',
        ];
        assert!(
            handle_at(
                &mut registry,
                &response_event_with_total(3306, &row_prefix, declared_len),
                7_000,
            )
            .is_empty()
        );
        let final_row_packet = mysql_wire_packet(5, b"private-tail");
        assert!(
            handle_at(
                &mut registry,
                &response_event(3306, &final_row_packet),
                8_000,
            )
            .is_empty()
        );

        let terminal = mysql_wire_packet(6, &[0xfe, 0, 0, 2, 0]);
        let signals = handle_at(&mut registry, &response_event(3306, &terminal), 9_000);
        assert_eq!(signals.len(), 1);
        assert_eq!(observation(&signals[0]).method.as_deref(), Some("SELECT"));
        assert_eq!(registry.counters().mysql_logical_response_continuations, 1);
        assert_eq!(registry.counters().mysql_logical_sequence_failures, 0);
        assert_eq!(registry.counters().unparsed_responses, 0);
        let serialized = serde_json::to_string(&signals).expect("signals serialize");
        assert!(!serialized.contains("secret"));
        assert!(!serialized.contains("private-tail"));
    }

    #[test]
    fn mysql_result_set_accepts_deprecated_eof_ok_terminator() {
        let mut registry = registry();
        let request = [7, 0, 0, 0, 3, b's', b'e', b'l', b'e', b'c', b't'];
        assert!(
            handle_at(
                &mut registry,
                &raw_event(3306, &request, request.len() as u32),
                5_000,
            )
            .is_empty()
        );
        let column_definition = mysql_column_definition_packet(2);

        for packet in [
            &[1, 0, 0, 1, 1][..],
            column_definition.as_slice(),
            &[2, 0, 0, 3, 1, b'x'][..],
        ] {
            assert!(handle_at(&mut registry, &response_event(3306, packet), 6_000).is_empty());
        }

        // Header 0xfe with a nine-byte payload is an OK packet, not the
        // legacy short EOF packet. The two trailing bytes model bounded info.
        let terminal = [9, 0, 0, 4, 0xfe, 0, 0, 2, 0, 0, 0, 0, 0];
        let signals = handle_at(&mut registry, &response_event(3306, &terminal), 8_000);

        assert_eq!(signals.len(), 1);
        let observation = observation(&signals[0]);
        assert_eq!(observation.duration_nanos, Some(3_000));
        assert!(observation.attributes.iter().any(|attribute| {
            attribute.key == "db.response.status_code" && attribute.value == "OK"
        }));
    }

    #[test]
    fn mysql_prepare_completes_after_parameter_and_column_metadata() {
        let mut registry = registry();
        let request = [
            9, 0, 0, 0, 0x16, b'S', b'E', b'L', b'E', b'C', b'T', b' ', b'?',
        ];
        assert!(
            handle_at(
                &mut registry,
                &raw_event(3306, &request, request.len() as u32),
                5_000,
            )
            .is_empty()
        );

        let prepare_ok = [12, 0, 0, 1, 0, 7, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0];
        let parameter_definition = mysql_column_definition_packet(2);
        let column_definition = mysql_column_definition_packet(4);
        for packet in [
            &prepare_ok[..],
            parameter_definition.as_slice(),
            &[5, 0, 0, 3, 0xfe, 0, 0, 2, 0][..],
            column_definition.as_slice(),
        ] {
            assert!(
                handle_at(&mut registry, &response_event(3306, packet), 6_000).is_empty(),
                "prepared statement completed before all metadata arrived"
            );
        }

        let terminal = [5, 0, 0, 5, 0xfe, 0, 0, 2, 0];
        let signals = handle_at(&mut registry, &response_event(3306, &terminal), 8_000);

        assert_eq!(signals.len(), 1);
        let observation = observation(&signals[0]);
        assert_eq!(observation.method.as_deref(), Some("SELECT"));
        assert_eq!(observation.duration_nanos, Some(3_000));
        assert_eq!(registry.counters().response_continuations, 4);
    }

    #[test]
    fn mysql_statement_execute_does_not_treat_binary_row_as_ok() {
        let mut registry = registry();
        let request = [10, 0, 0, 0, 0x17, 7, 0, 0, 0, 0, 1, 0, 0, 0];
        assert!(
            handle_at(
                &mut registry,
                &raw_event(3306, &request, request.len() as u32),
                5_000,
            )
            .is_empty()
        );
        let column_definition = mysql_column_definition_packet(2);

        for packet in [
            &[1, 0, 0, 1, 1][..],
            column_definition.as_slice(),
            &[5, 0, 0, 3, 0xfe, 0, 0, 2, 0][..],
            &[8, 0, 0, 4, 0, 0, 6, b'f', b'o', b'o', b'b', b'a'][..],
        ] {
            assert!(
                handle_at(&mut registry, &response_event(3306, packet), 6_000).is_empty(),
                "binary row completed the prepared execution"
            );
        }

        let terminal = [5, 0, 0, 5, 0xfe, 0, 0, 2, 0];
        let signals = handle_at(&mut registry, &response_event(3306, &terminal), 8_000);

        assert_eq!(signals.len(), 1);
        let observation = observation(&signals[0]);
        assert_eq!(observation.method.as_deref(), Some("EXECUTE"));
        assert_eq!(observation.duration_nanos, Some(3_000));
    }

    #[test]
    fn mysql_no_response_command_never_enters_the_correlation_queue() {
        let mut registry = registry();
        let request = [5, 0, 0, 0, 0x19, 7, 0, 0, 0];
        let signals = handle_at(
            &mut registry,
            &raw_event(3306, &request, request.len() as u32),
            5_000,
        );

        assert_eq!(signals.len(), 1);
        let observation = observation(&signals[0]);
        assert_eq!(observation.method.as_deref(), Some("CLOSE"));
        assert_eq!(observation.end_unix_nanos, None);
        assert_eq!(registry.counters().matched_responses, 0);

        let orphan = [7, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0];
        assert!(handle_at(&mut registry, &response_event(3306, &orphan), 6_000).is_empty());
        assert_eq!(registry.counters().orphan_responses, 1);
    }

    #[test]
    fn mysql_statement_fetch_waits_for_terminal_packet_after_binary_rows() {
        let mut registry = registry();
        let request = [9, 0, 0, 0, 0x1c, 7, 0, 0, 0, 1, 0, 0, 0];
        assert!(
            handle_at(
                &mut registry,
                &raw_event(3306, &request, request.len() as u32),
                5_000,
            )
            .is_empty()
        );

        let row = [8, 0, 0, 1, 0, 0, 6, b'f', b'o', b'o', b'b', b'a'];
        assert!(
            handle_at(&mut registry, &response_event(3306, &row), 6_000).is_empty(),
            "binary fetch row completed the request"
        );

        let terminal = [5, 0, 0, 2, 0xfe, 0, 0, 2, 0];
        let signals = handle_at(&mut registry, &response_event(3306, &terminal), 8_000);

        assert_eq!(signals.len(), 1);
        let observation = observation(&signals[0]);
        assert_eq!(observation.method.as_deref(), Some("FETCH"));
        assert_eq!(observation.duration_nanos, Some(3_000));
    }

    #[test]
    fn mysql_more_results_flag_keeps_the_command_in_flight() {
        let mut registry = registry();
        let request = [7, 0, 0, 0, 3, b's', b'e', b'l', b'e', b'c', b't'];
        assert!(
            handle_at(
                &mut registry,
                &raw_event(3306, &request, request.len() as u32),
                5_000,
            )
            .is_empty()
        );

        let more_results = [7, 0, 0, 1, 0, 0, 0, 0x0a, 0, 0, 0];
        assert!(handle_at(&mut registry, &response_event(3306, &more_results), 6_000,).is_empty());

        let terminal = [7, 0, 0, 2, 0, 0, 0, 2, 0, 0, 0];
        let signals = handle_at(&mut registry, &response_event(3306, &terminal), 8_000);
        assert_eq!(signals.len(), 1);
        assert_eq!(observation(&signals[0]).duration_nanos, Some(3_000));
        assert_eq!(registry.counters().response_continuations, 1);
    }

    #[test]
    fn mysql_sequence_gap_is_non_destructive() {
        let mut registry = registry();
        let request = [1, 0, 0, 0, 0x0e];
        assert!(
            handle_at(
                &mut registry,
                &raw_event(3306, &request, request.len() as u32),
                5_000,
            )
            .is_empty()
        );

        let wrong_sequence = [7, 0, 0, 2, 0, 0, 0, 2, 0, 0, 0];
        assert!(
            handle_at(&mut registry, &response_event(3306, &wrong_sequence), 6_000,).is_empty()
        );
        assert_eq!(registry.counters().unparsed_responses, 1);

        let terminal = [7, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0];
        let signals = handle_at(&mut registry, &response_event(3306, &terminal), 7_000);
        assert_eq!(signals.len(), 1);
        assert_eq!(observation(&signals[0]).method.as_deref(), Some("PING"));
        assert_eq!(observation(&signals[0]).duration_nanos, Some(2_000));
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
