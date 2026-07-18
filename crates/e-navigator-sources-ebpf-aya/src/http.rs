#![allow(dead_code)]

#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
use e_navigator_protocol::{
    ProtocolExtractionConfig,
    http::{HttpExtraction, parse_http_request},
};
#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
use e_navigator_signals::{
    NetworkProcessIdentity, ProtocolCaptureRole, ProtocolRequestObservation, SignalEnvelope,
    TraceConfidence, TraceCorrelationKind, TracePeerContext,
};

#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
const RAW_HTTP_MAX_IOVECS: usize = 3;
#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
const RAW_HTTP_IOVEC_CHUNK_BYTES: usize = 96;
#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
pub(crate) const RAW_HTTP_REQUEST_BYTES: usize = 1024;
#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
pub(crate) const RAW_HTTP_AF_INET: u32 = 2;
#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
pub(crate) const RAW_HTTP_AF_INET6: u32 = 10;
#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
pub(crate) const RAW_HTTP_ROLE_CLIENT: u32 = 0;
#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
pub(crate) const RAW_HTTP_ROLE_SERVER: u32 = 1;
#[cfg(any(target_os = "linux", test))]
const MAX_HTTP_REASSEMBLY_STREAMS: usize = 4096;
#[cfg(any(target_os = "linux", test))]
const HTTP_REASSEMBLY_STALE_NANOS: u64 = 5 * 60 * 1_000_000_000;
#[cfg(any(target_os = "linux", test))]
const PERF_BUFFER_PAGE_COUNT: usize = 64;
#[cfg(any(target_os = "linux", test))]
const PERF_READER_POLL_INTERVAL_MS: u64 = 25;
#[cfg(any(target_os = "linux", test))]
const HTTP_DIAGNOSTIC_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_secs(10);
#[cfg(any(target_os = "linux", test))]
const HTTP_DIAGNOSTIC_COUNTERS_LEN: usize = 19;
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
    "accept_active",
    "inbound_read_enter",
    "inbound_output_attempt",
    "server_write_suppressed",
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
    pub role: u32,
    pub remote_port_be: u16,
    pub local_port_be: u16,
    pub remote_addr_v4: u32,
    pub local_addr_v4: u32,
    pub remote_addr_v6: [u8; 16],
    pub local_addr_v6: [u8; 16],
    pub timestamp_unix_nanos: u64,
    pub request_len: u32,
    pub request_total_len: u32,
    pub request_iovec_lens: [u16; RAW_HTTP_MAX_IOVECS],
    pub command: [u8; 16],
    pub request: [u8; RAW_HTTP_REQUEST_BYTES],
}

#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RawHttpInvalidSampleMetadata {
    pid: u32,
    uid: u32,
    cgroup_id: u64,
    fd: i32,
    family: u32,
    role: u32,
    remote_port_be: u16,
    local_port_be: u16,
    request_len: u32,
    request_total_len: u32,
    request_iovec_lens: [u16; RAW_HTTP_MAX_IOVECS],
    command: [u8; 16],
}

#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
impl RawHttpInvalidSampleMetadata {
    fn from_raw(raw: &RawHttpRequestEvent) -> Self {
        Self {
            pid: raw.pid,
            uid: raw.uid,
            cgroup_id: raw.cgroup_id,
            fd: raw.fd,
            family: raw.family,
            role: raw.role,
            remote_port_be: raw.remote_port_be,
            local_port_be: raw.local_port_be,
            request_len: raw.request_len,
            request_total_len: raw.request_total_len,
            request_iovec_lens: raw.request_iovec_lens,
            command: raw.command,
        }
    }
}

#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RawHttpDecodeError {
    RawSampleTooShort,
    InvalidIovecLength {
        sample: RawHttpInvalidSampleMetadata,
    },
    ReassemblyGap {
        sample: RawHttpInvalidSampleMetadata,
    },
    ReassemblyLimit {
        sample: RawHttpInvalidSampleMetadata,
    },
    HttpExtraction {
        reason: HttpExtraction,
        sample: RawHttpInvalidSampleMetadata,
    },
}

#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
impl RawHttpDecodeError {
    fn reason_name(self) -> &'static str {
        match self {
            Self::RawSampleTooShort => "raw_sample_too_short",
            Self::InvalidIovecLength { .. } => "invalid_iovec_length",
            Self::ReassemblyGap { .. } => "reassembly_gap",
            Self::ReassemblyLimit { .. } => "reassembly_limit",
            Self::HttpExtraction {
                reason: HttpExtraction::HeadersTooLong,
                ..
            } => "headers_too_long",
            Self::HttpExtraction {
                reason: HttpExtraction::InvalidUtf8,
                ..
            } => "invalid_utf8",
            Self::HttpExtraction {
                reason: HttpExtraction::RequestLineTooLong,
                ..
            } => "request_line_too_long",
            Self::HttpExtraction {
                reason: HttpExtraction::MalformedRequestLine,
                ..
            } => "malformed_request_line",
            Self::HttpExtraction {
                reason: HttpExtraction::ResponseLineTooLong,
                ..
            } => "response_line_too_long",
            Self::HttpExtraction {
                reason: HttpExtraction::MalformedResponseLine,
                ..
            } => "malformed_response_line",
            Self::HttpExtraction {
                reason: HttpExtraction::InvalidStatusCode,
                ..
            } => "invalid_status_code",
        }
    }

    fn sample_metadata(self) -> Option<RawHttpInvalidSampleMetadata> {
        match self {
            Self::RawSampleTooShort => None,
            Self::InvalidIovecLength { sample } => Some(sample),
            Self::ReassemblyGap { sample } => Some(sample),
            Self::ReassemblyLimit { sample } => Some(sample),
            Self::HttpExtraction { sample, .. } => Some(sample),
        }
    }
}

#[cfg(any(target_os = "linux", test))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct HttpStreamKey {
    pid: u32,
    fd: i32,
    role: u32,
    family: u32,
    remote_port_be: u16,
    local_port_be: u16,
    remote_addr_v4: u32,
    local_addr_v4: u32,
    remote_addr_v6: [u8; 16],
    local_addr_v6: [u8; 16],
}

#[cfg(any(target_os = "linux", test))]
#[derive(Debug, Default)]
struct HttpStreamState {
    buffer: Vec<u8>,
    buffer_first_monotonic_nanos: u64,
    body_bytes_remaining: usize,
    last_seen_unix_nanos: u64,
}

#[cfg(any(target_os = "linux", test))]
#[derive(Debug, Default)]
struct HttpReassemblyOutcome {
    requests: Vec<Vec<u8>>,
    errors: Vec<RawHttpDecodeError>,
    evicted_streams: u64,
}

/// Bounded per-connection HTTP/1 header reassembly.
///
/// The eBPF side emits every read chunk for accepted server sockets. This
/// state joins segmented headers, consumes fixed-length request bodies, and
/// extracts multiple pipelined requests without retaining payload bodies.
#[cfg(any(target_os = "linux", test))]
#[derive(Debug)]
struct HttpRequestReassembler {
    max_streams: usize,
    max_header_bytes: usize,
    streams: std::collections::BTreeMap<HttpStreamKey, HttpStreamState>,
}

#[cfg(any(target_os = "linux", test))]
impl HttpRequestReassembler {
    fn new(max_streams: usize, max_header_bytes: usize) -> Self {
        Self {
            max_streams: max_streams.max(1),
            max_header_bytes: max_header_bytes.max(1),
            streams: std::collections::BTreeMap::new(),
        }
    }

    fn push(
        &mut self,
        raw: &RawHttpRequestEvent,
        captured: &[u8],
        observed_unix_nanos: u64,
        protocol_config: &ProtocolExtractionConfig,
    ) -> HttpReassemblyOutcome {
        let mut outcome = HttpReassemblyOutcome::default();
        self.reap_stale(observed_unix_nanos);

        let key = HttpStreamKey {
            pid: raw.pid,
            fd: raw.fd,
            role: raw.role,
            family: raw.family,
            remote_port_be: raw.remote_port_be,
            local_port_be: raw.local_port_be,
            remote_addr_v4: raw.remote_addr_v4,
            local_addr_v4: raw.local_addr_v4,
            remote_addr_v6: raw.remote_addr_v6,
            local_addr_v6: raw.local_addr_v6,
        };
        if !self.streams.contains_key(&key)
            && self.streams.len() >= self.max_streams
            && let Some(oldest) = self
                .streams
                .iter()
                .min_by_key(|(_, state)| state.last_seen_unix_nanos)
                .map(|(key, _)| *key)
        {
            self.streams.remove(&oldest);
            outcome.evicted_streams = 1;
        }

        let state = self.streams.entry(key).or_default();
        state.last_seen_unix_nanos = observed_unix_nanos;

        let total_len = usize::try_from(raw.request_total_len)
            .unwrap_or(usize::MAX)
            .max(captured.len());
        let mut uncaptured_bytes = total_len.saturating_sub(captured.len());

        let mut visible = captured;
        if state.body_bytes_remaining > 0 {
            let skipped = state.body_bytes_remaining.min(visible.len());
            state.body_bytes_remaining -= skipped;
            visible = &visible[skipped..];
            let skipped = state.body_bytes_remaining.min(uncaptured_bytes);
            state.body_bytes_remaining -= skipped;
            uncaptured_bytes -= skipped;
            if state.body_bytes_remaining > 0 {
                return outcome;
            }
            if visible.is_empty() {
                if uncaptured_bytes > 0 {
                    state.buffer.clear();
                    state.buffer_first_monotonic_nanos = 0;
                    outcome.errors.push(RawHttpDecodeError::ReassemblyGap {
                        sample: RawHttpInvalidSampleMetadata::from_raw(raw),
                    });
                }
                return outcome;
            }
        }

        let chunk_monotonic_nanos = raw.timestamp_unix_nanos;
        if state.buffer.is_empty() {
            state.buffer_first_monotonic_nanos = chunk_monotonic_nanos;
            state.buffer.extend_from_slice(visible);
        } else if starts_with_http_request(visible) {
            if !starts_with_http_request(&state.buffer)
                && chunk_monotonic_nanos < state.buffer_first_monotonic_nanos
            {
                // Perf buffers preserve order per CPU, not across CPUs. A
                // task can migrate between segmented syscalls, so retain an
                // already-seen suffix when its kernel timestamp proves this
                // self-identifying prefix happened first.
                let suffix = std::mem::take(&mut state.buffer);
                state.buffer.extend_from_slice(visible);
                state.buffer.extend_from_slice(&suffix);
                state.buffer_first_monotonic_nanos = chunk_monotonic_nanos;
            } else {
                // A later self-identifying request means the fd was reused or
                // an orphaned suffix can no longer be completed safely.
                state.buffer.clear();
                state.buffer.extend_from_slice(visible);
                state.buffer_first_monotonic_nanos = chunk_monotonic_nanos;
            }
        } else if chunk_monotonic_nanos < state.buffer_first_monotonic_nanos {
            let suffix = std::mem::take(&mut state.buffer);
            state.buffer.extend_from_slice(visible);
            state.buffer.extend_from_slice(&suffix);
            state.buffer_first_monotonic_nanos = chunk_monotonic_nanos;
        } else {
            state.buffer.extend_from_slice(visible);
        }

        if !starts_with_http_request(&state.buffer) {
            if state.buffer.len() > self.max_header_bytes || uncaptured_bytes > 0 {
                state.buffer.clear();
                state.buffer_first_monotonic_nanos = 0;
                state.body_bytes_remaining = 0;
                outcome.errors.push(if uncaptured_bytes > 0 {
                    RawHttpDecodeError::ReassemblyGap {
                        sample: RawHttpInvalidSampleMetadata::from_raw(raw),
                    }
                } else {
                    RawHttpDecodeError::ReassemblyLimit {
                        sample: RawHttpInvalidSampleMetadata::from_raw(raw),
                    }
                });
            }
            return outcome;
        }

        loop {
            if state.buffer.len() > self.max_header_bytes {
                state.buffer.clear();
                state.buffer_first_monotonic_nanos = 0;
                state.body_bytes_remaining = 0;
                outcome.errors.push(RawHttpDecodeError::ReassemblyLimit {
                    sample: RawHttpInvalidSampleMetadata::from_raw(raw),
                });
                return outcome;
            }

            let Some(header_end) = find_http_header_end(&state.buffer) else {
                if uncaptured_bytes > 0 {
                    state.buffer.clear();
                    state.buffer_first_monotonic_nanos = 0;
                    state.body_bytes_remaining = 0;
                    outcome.errors.push(RawHttpDecodeError::ReassemblyGap {
                        sample: RawHttpInvalidSampleMetadata::from_raw(raw),
                    });
                }
                return outcome;
            };
            let request = state.buffer[..header_end].to_vec();
            if let Err(reason) = parse_http_request(&request, protocol_config) {
                state.buffer.clear();
                state.buffer_first_monotonic_nanos = 0;
                state.body_bytes_remaining = 0;
                outcome.errors.push(RawHttpDecodeError::HttpExtraction {
                    reason,
                    sample: RawHttpInvalidSampleMetadata::from_raw(raw),
                });
                return outcome;
            }

            let body_len = http_content_length(&request).unwrap_or(0);
            state.buffer.drain(..header_end);
            let buffered_body = body_len.min(state.buffer.len());
            state.buffer.drain(..buffered_body);
            state.body_bytes_remaining = body_len.saturating_sub(buffered_body);
            let uncaptured_body = state.body_bytes_remaining.min(uncaptured_bytes);
            state.body_bytes_remaining -= uncaptured_body;
            uncaptured_bytes -= uncaptured_body;
            outcome.requests.push(request);

            if state.body_bytes_remaining > 0 {
                return outcome;
            }
            if state.buffer.is_empty() {
                state.buffer_first_monotonic_nanos = 0;
                if uncaptured_bytes > 0 {
                    outcome.errors.push(RawHttpDecodeError::ReassemblyGap {
                        sample: RawHttpInvalidSampleMetadata::from_raw(raw),
                    });
                }
                return outcome;
            }
        }
    }

    fn reap_stale(&mut self, observed_unix_nanos: u64) {
        self.streams.retain(|_, state| {
            observed_unix_nanos.saturating_sub(state.last_seen_unix_nanos)
                <= HTTP_REASSEMBLY_STALE_NANOS
        });
    }

    #[cfg(test)]
    fn stream_count(&self) -> usize {
        self.streams.len()
    }
}

#[cfg(any(target_os = "linux", test))]
fn find_http_header_end(bytes: &[u8]) -> Option<usize> {
    bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|index| index + 4)
}

#[cfg(any(target_os = "linux", test))]
fn starts_with_http_request(bytes: &[u8]) -> bool {
    let Some(space) = bytes.iter().position(|byte| *byte == b' ') else {
        return false;
    };
    space > 0
        && space <= 16
        && bytes[..space]
            .iter()
            .all(|byte| byte.is_ascii_uppercase() || *byte == b'-')
}

#[cfg(any(target_os = "linux", test))]
fn http_content_length(request: &[u8]) -> Option<usize> {
    let header = std::str::from_utf8(request).ok()?;
    header.split("\r\n").skip(1).find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.eq_ignore_ascii_case("content-length")
            .then(|| value.trim().parse::<usize>().ok())
            .flatten()
    })
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
    raw_http_request_to_signal_result_with_config(
        bytes,
        host,
        observed_unix_nanos,
        procfs_root,
        &ProtocolExtractionConfig::default(),
    )
}

#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
fn raw_http_request_to_signal_result_with_config(
    bytes: &[u8],
    host: Option<String>,
    observed_unix_nanos: u64,
    procfs_root: &std::path::Path,
    protocol_config: &ProtocolExtractionConfig,
) -> Result<SignalEnvelope, RawHttpDecodeError> {
    if bytes.len() < core::mem::size_of::<RawHttpRequestEvent>() {
        return Err(RawHttpDecodeError::RawSampleTooShort);
    }

    let raw = unsafe { core::ptr::read_unaligned(bytes.as_ptr().cast::<RawHttpRequestEvent>()) };
    let request = compact_raw_http_request(&raw)?;
    raw_http_request_parts_to_signal(
        &raw,
        &request,
        host,
        observed_unix_nanos,
        procfs_root,
        protocol_config,
    )
}

#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
fn raw_http_request_parts_to_signal(
    raw: &RawHttpRequestEvent,
    request: &[u8],
    host: Option<String>,
    observed_unix_nanos: u64,
    procfs_root: &std::path::Path,
    protocol_config: &ProtocolExtractionConfig,
) -> Result<SignalEnvelope, RawHttpDecodeError> {
    let parsed = parse_http_request(request, protocol_config).map_err(|reason| {
        RawHttpDecodeError::HttpExtraction {
            reason,
            sample: RawHttpInvalidSampleMetadata::from_raw(raw),
        }
    })?;
    let trace_context = parsed.trace_context.as_ref();
    let peer = peer_context(raw, &parsed.attributes);
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
            role: Some(if raw.role == RAW_HTTP_ROLE_SERVER {
                ProtocolCaptureRole::Server
            } else {
                ProtocolCaptureRole::Client
            }),
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
fn compact_raw_http_request(raw: &RawHttpRequestEvent) -> Result<Vec<u8>, RawHttpDecodeError> {
    let request_len = (raw.request_len as usize).min(RAW_HTTP_REQUEST_BYTES);
    if raw.request_iovec_lens.iter().all(|len| *len == 0) {
        return Ok(raw.request[..request_len].to_vec());
    }

    let mut request = Vec::with_capacity(request_len);
    for (index, len) in raw.request_iovec_lens.iter().enumerate() {
        if usize::from(*len) > RAW_HTTP_IOVEC_CHUNK_BYTES {
            return Err(RawHttpDecodeError::InvalidIovecLength {
                sample: RawHttpInvalidSampleMetadata::from_raw(raw),
            });
        }
        let start = index * RAW_HTTP_IOVEC_CHUNK_BYTES;
        let end = (start + usize::from(*len)).min(RAW_HTTP_REQUEST_BYTES);
        if start >= end || request.len() >= request_len {
            continue;
        }

        let remaining = request_len - request.len();
        let segment = &raw.request[start..end];
        request.extend_from_slice(&segment[..segment.len().min(remaining)]);
    }
    Ok(request)
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
    use crate::reader_shutdown::ReaderShutdown;
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
    use e_navigator_core::{
        CoreError, CoreResult, HttpSourceConfig, ModuleKind, ModuleMetadata, Source,
    };
    use e_navigator_protocol::ProtocolExtractionConfig;
    use e_navigator_signals::{SignalEnvelope, SignalPayload};
    use std::{
        path::PathBuf,
        sync::{Arc, Mutex},
    };
    use tokio::{sync::mpsc, task::JoinHandle};
    use tracing::{debug, info, warn};

    #[derive(Debug, Default)]
    pub struct AyaHttpSource {
        host: Option<String>,
        procfs_root: PathBuf,
        protocol_config: ProtocolExtractionConfig,
        inbound_enabled: bool,
    }

    impl AyaHttpSource {
        pub fn new(host: Option<String>, procfs_root: PathBuf, config: HttpSourceConfig) -> Self {
            let inbound_enabled = config.inbound_enabled;
            Self {
                host,
                procfs_root,
                protocol_config: protocol_config(config),
                inbound_enabled,
            }
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
            if self.inbound_enabled {
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
                attach_tracepoint(
                    &mut ebpf,
                    "tracepoint_http_read_enter",
                    "syscalls",
                    "sys_enter_read",
                )?;
                attach_tracepoint(
                    &mut ebpf,
                    "tracepoint_http_read_exit",
                    "syscalls",
                    "sys_exit_read",
                )?;
                attach_tracepoint(
                    &mut ebpf,
                    "tracepoint_http_recvfrom_enter",
                    "syscalls",
                    "sys_enter_recvfrom",
                )?;
                attach_tracepoint(
                    &mut ebpf,
                    "tracepoint_http_recvfrom_exit",
                    "syscalls",
                    "sys_exit_recvfrom",
                )?;
            }

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

            if let Some(handle) =
                crate::capture_filter::attach_capture_filter(&mut ebpf, "source.aya_http", {
                    let shutdown = shutdown.clone();
                    move || shutdown.is_stopped()
                })?
            {
                reader_handles.push(handle);
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
            let reassembler = Arc::new(Mutex::new(super::HttpRequestReassembler::new(
                super::MAX_HTTP_REASSEMBLY_STREAMS,
                self.protocol_config.max_header_bytes,
            )));
            for cpu_id in cpus {
                let mut buffer = perf_array
                    .open(cpu_id, Some(super::PERF_BUFFER_PAGE_COUNT))
                    .map_err(module_error)?;
                let cpu_tx = tx.clone();
                let host = self.host.clone();
                let procfs_root = self.procfs_root.clone();
                let protocol_config = self.protocol_config;
                let reader_shutdown = shutdown.clone();
                let diagnostics = diagnostics.clone();
                let telemetry = telemetry.clone();
                let reassembler = reassembler.clone();

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
                                    let observed_unix_nanos = super::now_unix_nanos();
                                    let decoded = if bytes.len()
                                        < core::mem::size_of::<super::RawHttpRequestEvent>()
                                    {
                                        Err(super::RawHttpDecodeError::RawSampleTooShort)
                                    } else {
                                        let raw = unsafe {
                                            core::ptr::read_unaligned(
                                                bytes
                                                    .as_ptr()
                                                    .cast::<super::RawHttpRequestEvent>(),
                                            )
                                        };
                                        super::compact_raw_http_request(&raw).map(|captured| {
                                            let outcome = reassembler
                                                .lock()
                                                .unwrap_or_else(|poisoned| poisoned.into_inner())
                                                .push(
                                                    &raw,
                                                    &captured,
                                                    observed_unix_nanos,
                                                    &protocol_config,
                                                );
                                            (raw, outcome)
                                        })
                                    };

                                    match decoded {
                                        Err(err) => {
                                            record_invalid(&telemetry, &diagnostics, err);
                                        }
                                        Ok((raw, outcome)) => {
                                            if outcome.evicted_streams > 0 {
                                                telemetry.record_invalid_sample();
                                                warn!(
                                                    evicted_streams = outcome.evicted_streams,
                                                    max_streams = super::MAX_HTTP_REASSEMBLY_STREAMS,
                                                    "bounded HTTP reassembly evicted connection state"
                                                );
                                            }
                                            for err in outcome.errors {
                                                record_invalid(&telemetry, &diagnostics, err);
                                            }
                                            for request in outcome.requests {
                                                match super::raw_http_request_parts_to_signal(
                                                    &raw,
                                                    &request,
                                                    host.clone(),
                                                    observed_unix_nanos,
                                                    &procfs_root,
                                                    &protocol_config,
                                                ) {
                                                    Ok(signal) => {
                                                        telemetry.record_decoded_sample();
                                                        let diagnostic_decision =
                                                            log_signal_diagnostic(
                                                                &diagnostics,
                                                                &signal,
                                                            );
                                                        telemetry.record_diagnostic_decision(
                                                            diagnostic_decision,
                                                        );
                                                        if cpu_tx
                                                            .blocking_send(signal)
                                                            .is_err()
                                                        {
                                                            telemetry.record_send_failure();
                                                            closed = true;
                                                            break;
                                                        }
                                                        telemetry.record_sent_signal();
                                                    }
                                                    Err(err) => {
                                                        record_invalid(
                                                            &telemetry,
                                                            &diagnostics,
                                                            err,
                                                        );
                                                    }
                                                }
                                            }
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
            telemetry.mark_initialized();
            debug!("aya http source attached");
            crate::shutdown::signal().await.map_err(module_error)?;
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
        let request_iovec_lens = sample.map(|sample| sample.request_iovec_lens);
        info!(
            target: "e_navigator_sources_ebpf_aya::source_diagnostics",
            source = "source.aya_http",
            raw_event = "invalid_http_request_sample",
            invalid_reason = reason,
            pid = ?sample.map(|sample| sample.pid),
            uid = ?sample.map(|sample| sample.uid),
            command = ?redacted_command,
            cgroup_id = ?diagnostics.redact_optional_u64(cgroup_id),
            fd = ?sample.map(|sample| sample.fd),
            family = ?sample.map(|sample| sample.family),
            remote_port = ?sample.map(|sample| u16::from_be(sample.remote_port_be)),
            local_port = ?sample.map(|sample| u16::from_be(sample.local_port_be)),
            role = ?sample.map(|sample| sample.role),
            request_len = ?sample.map(|sample| sample.request_len),
            request_total_len = ?sample.map(|sample| sample.request_total_len),
            request_iovec_lens = ?request_iovec_lens,
            "source diagnostic raw event invalid"
        );
        DiagnosticSampleDecision::Matched
    }

    fn record_invalid(
        telemetry: &SourceTelemetry,
        diagnostics: &SourceDiagnostics,
        err: super::RawHttpDecodeError,
    ) {
        telemetry.record_invalid_sample();
        let decision = log_invalid_http_sample_diagnostic(diagnostics, err);
        telemetry.record_diagnostic_decision(decision);
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
                            accept_active = delta.get(15),
                            inbound_read_enter = delta.get(16),
                            inbound_output_attempt = delta.get(17),
                            server_write_suppressed = delta.get(18),
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

    fn protocol_config(config: HttpSourceConfig) -> ProtocolExtractionConfig {
        ProtocolExtractionConfig {
            max_header_bytes: config.max_header_bytes,
            max_request_line_bytes: config.max_request_line_bytes,
            max_attributes: config.max_attributes,
            max_tracestate_bytes: config.max_tracestate_bytes,
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
    use e_navigator_core::{
        CoreError, CoreResult, HttpSourceConfig, ModuleKind, ModuleMetadata, Source,
    };
    use e_navigator_signals::SignalEnvelope;
    use tokio::sync::mpsc;

    #[derive(Debug, Default)]
    pub struct AyaHttpSource {
        host: Option<String>,
        _procfs_root: std::path::PathBuf,
        _config: HttpSourceConfig,
    }

    impl AyaHttpSource {
        pub fn new(
            host: Option<String>,
            procfs_root: std::path::PathBuf,
            config: HttpSourceConfig,
        ) -> Self {
            Self {
                host,
                _procfs_root: procfs_root,
                _config: config,
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
            role: RAW_HTTP_ROLE_CLIENT,
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
            request_total_len: request.len() as u32,
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
        assert!(
            !event
                .attributes
                .iter()
                .any(|attribute| attribute.value.contains("secret"))
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
            role: RAW_HTTP_ROLE_CLIENT,
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
            request_total_len: (part1.len() + part2.len()) as u32,
            request_iovec_lens: [part1.len() as u16, part2.len() as u16, 0],
            command: fixed_command("curl"),
            request: [0; RAW_HTTP_REQUEST_BYTES],
        };
        raw.request[..part1.len()].copy_from_slice(part1);
        let second_offset = RAW_HTTP_IOVEC_CHUNK_BYTES;
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
            role: RAW_HTTP_ROLE_CLIENT,
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
            request_total_len: (part1.len() + part2.len() + part3.len()) as u32,
            request_iovec_lens: [part1.len() as u16, part2.len() as u16, part3.len() as u16],
            command: fixed_command("curl"),
            request: [0; RAW_HTTP_REQUEST_BYTES],
        };
        raw.request[..part1.len()].copy_from_slice(part1);
        let slot_len = RAW_HTTP_IOVEC_CHUNK_BYTES;
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
            role: RAW_HTTP_ROLE_CLIENT,
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
            request_total_len: payload.len() as u32,
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
    fn raw_http_decode_result_uses_configured_parser_limits() {
        let request = b"GET /checkout HTTP/1.1\r\nHost: example.test\r\n\r\n";
        let mut raw = RawHttpRequestEvent {
            pid: 42,
            role: RAW_HTTP_ROLE_CLIENT,
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
            request_total_len: request.len() as u32,
            request_iovec_lens: [0; RAW_HTTP_MAX_IOVECS],
            command: fixed_command("curl"),
            request: [0; RAW_HTTP_REQUEST_BYTES],
        };
        raw.request[..request.len()].copy_from_slice(request);

        let err = raw_http_request_to_signal_result_with_config(
            raw_as_bytes(&raw),
            None,
            1_000,
            std::path::Path::new("/proc"),
            &ProtocolExtractionConfig {
                max_header_bytes: 256,
                max_request_line_bytes: 4,
                max_attributes: 8,
                max_tracestate_bytes: 512,
            },
        )
        .expect_err("configured parser limits reject oversized request lines");

        assert!(matches!(
            err,
            RawHttpDecodeError::HttpExtraction {
                reason: HttpExtraction::RequestLineTooLong,
                ..
            }
        ));
        assert_eq!(err.reason_name(), "request_line_too_long");
    }

    #[test]
    fn raw_http_decode_result_classifies_non_http_payloads() {
        let payload = b"not an http request";
        let mut raw = RawHttpRequestEvent {
            pid: 42,
            role: RAW_HTTP_ROLE_CLIENT,
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
            request_total_len: payload.len() as u32,
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

        assert!(matches!(
            err,
            RawHttpDecodeError::HttpExtraction {
                reason: HttpExtraction::HeadersTooLong,
                ..
            }
        ));
        assert_eq!(err.reason_name(), "headers_too_long");
    }

    #[test]
    fn raw_http_decode_result_preserves_invalid_sample_metadata() {
        let payload = b"not an http request";
        let mut raw = RawHttpRequestEvent {
            pid: 42,
            role: RAW_HTTP_ROLE_CLIENT,
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
            request_total_len: payload.len() as u32,
            request_iovec_lens: [3, 5, 7],
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
        let sample = err
            .sample_metadata()
            .expect("invalid raw HTTP samples preserve bounded metadata");

        assert_eq!(sample.pid, 42);
        assert_eq!(sample.uid, 1000);
        assert_eq!(sample.cgroup_id, 7);
        assert_eq!(sample.fd, 9);
        assert_eq!(sample.family, RAW_HTTP_AF_INET);
        assert_eq!(u16::from_be(sample.remote_port_be), 8080);
        assert_eq!(u16::from_be(sample.local_port_be), 39000);
        assert_eq!(sample.request_len, payload.len() as u32);
        assert_eq!(sample.request_iovec_lens, [3, 5, 7]);
        assert_eq!(bytes_to_string(&sample.command), "curl");
    }

    #[test]
    fn raw_http_decode_result_rejects_oversized_iovec_lengths() {
        let part1 = b"GET /oversized";
        let part2 = b"-iovec HTTP/1.1\r\nHost: api.example.test\r\n\r\n";
        let mut raw = RawHttpRequestEvent {
            pid: 42,
            role: RAW_HTTP_ROLE_CLIENT,
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
            request_total_len: (part1.len() + part2.len()) as u32,
            request_iovec_lens: [
                part1.len() as u16,
                (RAW_HTTP_IOVEC_CHUNK_BYTES + 1) as u16,
                0,
            ],
            command: fixed_command("curl"),
            request: [0; RAW_HTTP_REQUEST_BYTES],
        };
        raw.request[..part1.len()].copy_from_slice(part1);
        let second_offset = RAW_HTTP_IOVEC_CHUNK_BYTES;
        raw.request[second_offset..second_offset + part2.len()].copy_from_slice(part2);

        let err = raw_http_request_to_signal_result(
            raw_as_bytes(&raw),
            None,
            1_000,
            std::path::Path::new("/proc"),
        )
        .expect_err("oversized iovec length is invalid");
        let sample = err
            .sample_metadata()
            .expect("invalid raw HTTP samples preserve bounded metadata");

        assert!(matches!(err, RawHttpDecodeError::InvalidIovecLength { .. }));
        assert_eq!(err.reason_name(), "invalid_iovec_length");
        assert_eq!(
            sample.request_iovec_lens[1],
            (RAW_HTTP_IOVEC_CHUNK_BYTES + 1) as u16
        );
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
            role: RAW_HTTP_ROLE_CLIENT,
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
            request_total_len: request.len() as u32,
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
            10, 5, 100, 30, 1, 0, 2, 7, 0, 20, 3, 20, 4, 3, 1, 0, 0, 0, 0,
        ]);
        let current = HttpDiagnosticCounterSnapshot::from_counters([
            12, 8, 100, 45, 1, 4, 2, 11, 0, 35, 3, 35, 10, 8, 2, 5, 6, 7, 8,
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
                "accept_active",
                "inbound_read_enter",
                "inbound_output_attempt",
                "server_write_suppressed",
            ]
        );
    }

    #[test]
    fn server_role_event_reports_server_capture_role() {
        let request = b"GET /inbound HTTP/1.1\r\nHost: svc.local\r\n\r\n";
        let mut raw = RawHttpRequestEvent {
            pid: 77,
            role: RAW_HTTP_ROLE_CLIENT,
            uid: 10,
            cgroup_id: 5,
            fd: 4,
            family: RAW_HTTP_AF_INET,
            remote_port_be: 51000_u16.to_be(),
            local_port_be: 8080_u16.to_be(),
            remote_addr_v4: u32::from_ne_bytes([10, 0, 0, 40]),
            local_addr_v4: u32::from_ne_bytes([10, 0, 0, 41]),
            remote_addr_v6: [0; 16],
            local_addr_v6: [0; 16],
            timestamp_unix_nanos: 1,
            request_len: request.len() as u32,
            request_total_len: request.len() as u32,
            request_iovec_lens: [0; RAW_HTTP_MAX_IOVECS],
            command: fixed_command("server"),
            request: [0; RAW_HTTP_REQUEST_BYTES],
        };
        raw.role = RAW_HTTP_ROLE_SERVER;
        raw.request[..request.len()].copy_from_slice(request);

        let signal = raw_http_request_to_signal_result(
            raw_as_bytes(&raw),
            None,
            9,
            std::path::Path::new("__missing__"),
        )
        .expect("server-side request decodes");
        let e_navigator_signals::SignalPayload::ProtocolRequestObservation(observation) =
            &signal.payload
        else {
            panic!("expected protocol request observation");
        };
        assert_eq!(
            observation.role,
            Some(e_navigator_signals::ProtocolCaptureRole::Server)
        );
        assert_eq!(observation.method.as_deref(), Some("GET"));
    }

    #[test]
    fn reassembler_joins_segmented_server_request_headers() {
        let config = ProtocolExtractionConfig::default();
        let mut reassembler = HttpRequestReassembler::new(8, config.max_header_bytes);
        let first = raw_http_chunk(
            77,
            4,
            RAW_HTTP_ROLE_SERVER,
            b"GET /segmented HTTP/1.1\r\nHost:",
        );
        let second = raw_http_chunk(77, 4, RAW_HTTP_ROLE_SERVER, b" svc.local\r\n\r\n");

        let first_outcome = reassembler.push(
            &first,
            &compact_raw_http_request(&first).expect("first chunk compacts"),
            1,
            &config,
        );
        assert!(first_outcome.requests.is_empty());
        assert!(first_outcome.errors.is_empty());

        let second_outcome = reassembler.push(
            &second,
            &compact_raw_http_request(&second).expect("second chunk compacts"),
            2,
            &config,
        );
        assert_eq!(second_outcome.requests.len(), 1);
        assert_eq!(
            second_outcome.requests[0],
            b"GET /segmented HTTP/1.1\r\nHost: svc.local\r\n\r\n"
        );
        assert!(second_outcome.errors.is_empty());
    }

    #[test]
    fn reassembler_orders_segmented_headers_by_kernel_timestamp() {
        let config = ProtocolExtractionConfig::default();
        let mut reassembler = HttpRequestReassembler::new(8, config.max_header_bytes);
        let mut first = raw_http_chunk(
            77,
            4,
            RAW_HTTP_ROLE_SERVER,
            b"GET /segmented HTTP/1.1\r\nHost: svc.local\r\n",
        );
        first.timestamp_unix_nanos = 10;
        let mut second = raw_http_chunk(77, 4, RAW_HTTP_ROLE_SERVER, b"Connection: close\r\n\r\n");
        second.timestamp_unix_nanos = 20;

        let second_outcome = reassembler.push(
            &second,
            &compact_raw_http_request(&second).expect("second chunk compacts"),
            1,
            &config,
        );
        assert!(second_outcome.requests.is_empty());
        assert!(second_outcome.errors.is_empty());

        let first_outcome = reassembler.push(
            &first,
            &compact_raw_http_request(&first).expect("first chunk compacts"),
            2,
            &config,
        );
        assert_eq!(first_outcome.requests.len(), 1);
        assert_eq!(
            first_outcome.requests[0],
            concat!(
                "GET /segmented HTTP/1.1\r\n",
                "Host: svc.local\r\n",
                "Connection: close\r\n",
                "\r\n"
            )
            .as_bytes()
        );
        assert!(first_outcome.errors.is_empty());
    }

    #[test]
    fn reassembler_drops_older_orphan_for_later_request_on_reused_fd() {
        let config = ProtocolExtractionConfig::default();
        let mut reassembler = HttpRequestReassembler::new(8, config.max_header_bytes);
        let mut orphan = raw_http_chunk(77, 4, RAW_HTTP_ROLE_SERVER, b"Connection: close\r\n\r\n");
        orphan.timestamp_unix_nanos = 10;
        let mut request = raw_http_chunk(
            77,
            4,
            RAW_HTTP_ROLE_SERVER,
            b"GET /reused HTTP/1.1\r\nHost: svc.local\r\n\r\n",
        );
        request.timestamp_unix_nanos = 20;

        let orphan_outcome = reassembler.push(
            &orphan,
            &compact_raw_http_request(&orphan).expect("orphan chunk compacts"),
            1,
            &config,
        );
        assert!(orphan_outcome.requests.is_empty());
        assert!(orphan_outcome.errors.is_empty());

        let request_outcome = reassembler.push(
            &request,
            &compact_raw_http_request(&request).expect("request compacts"),
            2,
            &config,
        );
        assert_eq!(request_outcome.requests.len(), 1);
        assert!(request_outcome.requests[0].starts_with(b"GET /reused "));
        assert!(request_outcome.errors.is_empty());
    }

    #[test]
    fn reassembler_isolates_body_state_when_a_socket_fd_is_reused() {
        let config = ProtocolExtractionConfig::default();
        let mut reassembler = HttpRequestReassembler::new(8, config.max_header_bytes);
        let mut first_connection = raw_http_chunk(
            77,
            4,
            RAW_HTTP_ROLE_SERVER,
            b"POST /first HTTP/1.1\r\nHost: svc.local\r\nContent-Length: 100\r\n\r\n",
        );
        first_connection.remote_port_be = 40_000_u16.to_be();
        let mut reused_fd = raw_http_chunk(
            77,
            4,
            RAW_HTTP_ROLE_SERVER,
            b"GET /reused HTTP/1.1\r\nHost: svc.local\r\n\r\n",
        );
        reused_fd.remote_port_be = 40_001_u16.to_be();

        let first_outcome = reassembler.push(
            &first_connection,
            &compact_raw_http_request(&first_connection).expect("first request compacts"),
            1,
            &config,
        );
        assert_eq!(first_outcome.requests.len(), 1);
        assert!(first_outcome.errors.is_empty());

        let reused_outcome = reassembler.push(
            &reused_fd,
            &compact_raw_http_request(&reused_fd).expect("reused request compacts"),
            2,
            &config,
        );
        assert_eq!(reused_outcome.requests.len(), 1);
        assert!(reused_outcome.requests[0].starts_with(b"GET /reused "));
        assert!(reused_outcome.errors.is_empty());
    }

    #[test]
    fn reassembler_extracts_pipelined_requests_after_fixed_body() {
        let config = ProtocolExtractionConfig::default();
        let mut reassembler = HttpRequestReassembler::new(8, config.max_header_bytes);
        let payload = concat!(
            "POST /first HTTP/1.1\r\n",
            "Host: svc.local\r\n",
            "Content-Length: 4\r\n",
            "\r\n",
            "DATA",
            "GET /second HTTP/1.1\r\n",
            "Host: svc.local\r\n",
            "\r\n"
        );
        let raw = raw_http_chunk(77, 4, RAW_HTTP_ROLE_SERVER, payload.as_bytes());

        let outcome = reassembler.push(
            &raw,
            &compact_raw_http_request(&raw).expect("pipeline compacts"),
            1,
            &config,
        );

        assert!(outcome.errors.is_empty());
        assert_eq!(outcome.requests.len(), 2);
        assert!(outcome.requests[0].starts_with(b"POST /first "));
        assert!(outcome.requests[1].starts_with(b"GET /second "));
    }

    #[test]
    fn reassembler_accepts_uncaptured_tail_within_declared_body() {
        let config = ProtocolExtractionConfig::default();
        let mut reassembler = HttpRequestReassembler::new(8, config.max_header_bytes);
        let captured = concat!(
            "POST /body HTTP/1.1\r\n",
            "Host: svc.local\r\n",
            "Content-Length: 4\r\n",
            "\r\n",
            "DA"
        );
        let mut raw = raw_http_chunk(77, 4, RAW_HTTP_ROLE_SERVER, captured.as_bytes());
        raw.request_total_len += 2;

        let outcome = reassembler.push(
            &raw,
            &compact_raw_http_request(&raw).expect("captured body prefix compacts"),
            1,
            &config,
        );

        assert!(outcome.errors.is_empty());
        assert_eq!(outcome.requests.len(), 1);
        assert!(outcome.requests[0].starts_with(b"POST /body "));
    }

    #[test]
    fn reassembler_reports_uncaptured_bytes_beyond_declared_body() {
        let config = ProtocolExtractionConfig::default();
        let mut reassembler = HttpRequestReassembler::new(8, config.max_header_bytes);
        let captured = concat!(
            "POST /body HTTP/1.1\r\n",
            "Host: svc.local\r\n",
            "Content-Length: 4\r\n",
            "\r\n",
            "DATA"
        );
        let mut raw = raw_http_chunk(77, 4, RAW_HTTP_ROLE_SERVER, captured.as_bytes());
        raw.request_total_len += 1;

        let outcome = reassembler.push(
            &raw,
            &compact_raw_http_request(&raw).expect("captured request compacts"),
            1,
            &config,
        );

        assert_eq!(outcome.requests.len(), 1);
        assert!(matches!(
            outcome.errors.as_slice(),
            [RawHttpDecodeError::ReassemblyGap { .. }]
        ));
    }

    #[test]
    fn reassembler_reports_capture_gaps_without_splicing_streams() {
        let config = ProtocolExtractionConfig::default();
        let mut reassembler = HttpRequestReassembler::new(8, config.max_header_bytes);
        let mut raw = raw_http_chunk(77, 4, RAW_HTTP_ROLE_SERVER, b"GET /gap HTTP/1.1\r\n");
        raw.request_total_len = raw.request_len + 1;

        let outcome = reassembler.push(
            &raw,
            &compact_raw_http_request(&raw).expect("captured prefix compacts"),
            1,
            &config,
        );

        assert!(outcome.requests.is_empty());
        assert!(matches!(
            outcome.errors.as_slice(),
            [RawHttpDecodeError::ReassemblyGap { .. }]
        ));
    }

    #[test]
    fn reassembler_evicts_oldest_stream_at_capacity_and_reaps_stale_state() {
        let config = ProtocolExtractionConfig::default();
        let mut reassembler = HttpRequestReassembler::new(1, config.max_header_bytes);
        let first = raw_http_chunk(1, 4, RAW_HTTP_ROLE_SERVER, b"GET /one HTTP/1.1\r\n");
        let second = raw_http_chunk(2, 5, RAW_HTTP_ROLE_SERVER, b"GET /two HTTP/1.1\r\n");

        let _ = reassembler.push(
            &first,
            &first.request[..first.request_len as usize],
            1,
            &config,
        );
        let outcome = reassembler.push(
            &second,
            &second.request[..second.request_len as usize],
            2,
            &config,
        );
        assert_eq!(outcome.evicted_streams, 1);
        assert_eq!(reassembler.stream_count(), 1);

        reassembler.reap_stale(HTTP_REASSEMBLY_STALE_NANOS + 3);
        assert_eq!(reassembler.stream_count(), 0);
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

    fn raw_http_chunk(pid: u32, fd: i32, role: u32, bytes: &[u8]) -> RawHttpRequestEvent {
        assert!(bytes.len() <= RAW_HTTP_REQUEST_BYTES);
        let mut raw = RawHttpRequestEvent {
            pid,
            uid: 1000,
            cgroup_id: 7,
            fd,
            family: RAW_HTTP_AF_INET,
            role,
            remote_port_be: 51000_u16.to_be(),
            local_port_be: 8080_u16.to_be(),
            remote_addr_v4: u32::from_ne_bytes([10, 0, 0, 40]),
            local_addr_v4: u32::from_ne_bytes([10, 0, 0, 41]),
            remote_addr_v6: [0; 16],
            local_addr_v6: [0; 16],
            timestamp_unix_nanos: 1,
            request_len: bytes.len() as u32,
            request_total_len: bytes.len() as u32,
            request_iovec_lens: [0; RAW_HTTP_MAX_IOVECS],
            command: fixed_command("server"),
            request: [0; RAW_HTTP_REQUEST_BYTES],
        };
        raw.request[..bytes.len()].copy_from_slice(bytes);
        raw
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
