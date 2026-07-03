use async_trait::async_trait;
use e_navigator_core::{CoreError, CoreResult, Generator, ModuleKind, ModuleMetadata, Signal};
use e_navigator_protocol::trace_context::parse_traceparent;
use e_navigator_signals::{
    ProtocolKind, ProtocolRequestObservation, RequestCorrelationWarning, RequestSpanObservation,
    SignalEnvelope, SignalPayload, TraceAttribute, TraceConfidence, TraceCorrelationKind,
};
use std::{
    collections::BTreeSet,
    sync::{Mutex, MutexGuard},
};
use tokio::sync::mpsc;

const DEFAULT_MAX_SEEN_REQUESTS: usize = 8192;
const DEFAULT_MAX_WARNINGS: usize = 1024;
const MAX_REQUEST_ATTRIBUTES: usize = 8;
const MAX_REQUEST_ATTRIBUTE_KEY_BYTES: usize = 128;
const MAX_REQUEST_ATTRIBUTE_VALUE_BYTES: usize = 256;
const MAX_FINGERPRINT_VALUE_BYTES: usize = 64;

#[derive(Debug)]
pub struct RequestCorrelationGenerator {
    max_seen_requests: usize,
    max_warnings: usize,
    seen_requests: Mutex<BTreeSet<RequestFingerprint>>,
    seen_warnings: Mutex<BTreeSet<WarningFingerprint>>,
}

impl Default for RequestCorrelationGenerator {
    fn default() -> Self {
        Self::with_limits(DEFAULT_MAX_SEEN_REQUESTS, DEFAULT_MAX_WARNINGS)
    }
}

impl RequestCorrelationGenerator {
    pub fn with_limits(max_seen_requests: usize, max_warnings: usize) -> Self {
        Self {
            max_seen_requests,
            max_warnings,
            seen_requests: Mutex::new(BTreeSet::new()),
            seen_warnings: Mutex::new(BTreeSet::new()),
        }
    }
}

#[async_trait]
impl Generator<SignalEnvelope> for RequestCorrelationGenerator {
    fn metadata(&self) -> ModuleMetadata {
        ModuleMetadata::new("generator.request_correlation", ModuleKind::Generator)
    }

    async fn observe(
        &self,
        signal: &SignalEnvelope,
        tx: &mpsc::Sender<SignalEnvelope>,
    ) -> CoreResult<()> {
        let outputs = match &signal.payload {
            SignalPayload::ProtocolRequestObservation(request) => {
                self.observe_protocol_request(signal, request)?
            }
            _ => Vec::new(),
        };

        for output in outputs {
            tx.send(output)
                .await
                .map_err(|_| CoreError::PipelineClosed)?;
        }

        Ok(())
    }
}

impl RequestCorrelationGenerator {
    fn observe_protocol_request(
        &self,
        signal: &SignalEnvelope,
        request: &ProtocolRequestObservation,
    ) -> CoreResult<Vec<SignalEnvelope>> {
        let trace_context = trace_context(request);
        let fingerprint = RequestFingerprint::from_request(request, &trace_context);
        if !self.mark_request_seen(fingerprint)? {
            return Ok(Vec::new());
        }

        let has_trace_context = trace_context.trace_id.is_some();
        let correlation_kind = if request.correlation_kind == TraceCorrelationKind::Synthetic {
            TraceCorrelationKind::Synthetic
        } else if has_trace_context {
            TraceCorrelationKind::ObservedTraceContext
        } else {
            request.correlation_kind
        };
        let confidence =
            if has_trace_context && request.correlation_kind != TraceCorrelationKind::Synthetic {
                TraceConfidence::High
            } else {
                request.confidence
            };

        let mut outputs = vec![SignalEnvelope::request_span_observation(
            "generator.request_correlation",
            signal.host.clone(),
            RequestSpanObservation {
                name: request_span_name(request.protocol).to_string(),
                protocol: request.protocol,
                trace_id: trace_context.trace_id,
                span_id: trace_context.span_id,
                parent_span_id: request.parent_span_id.clone(),
                start_unix_nanos: request.start_unix_nanos,
                end_unix_nanos: request.end_unix_nanos,
                duration_nanos: request.duration_nanos,
                correlation_kind,
                confidence,
                service_name: request.service_name.clone(),
                method: request.method.clone(),
                status_code: request.status_code,
                process: request.process.clone(),
                container: request.container.clone(),
                kubernetes: request.kubernetes.clone(),
                peer: request.peer.clone(),
                attributes: bounded_attributes(&request.attributes),
            },
        )];

        if let Some(warning_type) = trace_context.warning_type
            && let Some(warning) = self.warning(signal, request, warning_type)?
        {
            outputs.push(warning);
        }

        if request.container.is_none()
            && request.kubernetes.is_none()
            && let Some(warning) = self.warning(signal, request, "missing_attribution")?
        {
            outputs.push(warning);
        }

        Ok(outputs)
    }

    fn mark_request_seen(&self, fingerprint: RequestFingerprint) -> CoreResult<bool> {
        let mut seen = self.seen_requests()?;
        if seen.contains(&fingerprint) {
            return Ok(false);
        }
        if seen.len() >= self.max_seen_requests.max(1)
            && let Some(first) = seen.iter().next().cloned()
        {
            seen.remove(&first);
        }
        seen.insert(fingerprint);
        Ok(true)
    }

    fn warning(
        &self,
        signal: &SignalEnvelope,
        request: &ProtocolRequestObservation,
        warning_type: &str,
    ) -> CoreResult<Option<SignalEnvelope>> {
        let fingerprint = WarningFingerprint {
            warning_type: warning_type.to_string(),
            source_signal_kind: signal.kind().to_string(),
            source_module: signal.source.clone(),
            timestamp_unix_nanos: request.start_unix_nanos,
        };
        let mut seen = self.seen_warnings()?;
        if seen.contains(&fingerprint) {
            return Ok(None);
        }
        if seen.len() >= self.max_warnings.max(1)
            && let Some(first) = seen.iter().next().cloned()
        {
            seen.remove(&first);
        }
        seen.insert(fingerprint);
        drop(seen);

        Ok(Some(SignalEnvelope::request_correlation_warning(
            "generator.request_correlation",
            signal.host.clone(),
            RequestCorrelationWarning {
                warning_type: warning_type.to_string(),
                message: warning_message(warning_type).to_string(),
                timestamp_unix_nanos: request.start_unix_nanos,
                source_signal_kind: signal.kind().to_string(),
                source_module: signal.source.clone(),
                correlation_kind: request.correlation_kind,
                protocol: request.protocol,
                process: request.process.clone(),
                container: request.container.clone(),
                kubernetes: request.kubernetes.clone(),
                peer: request.peer.clone(),
            },
        )))
    }

    fn seen_requests(&self) -> CoreResult<MutexGuard<'_, BTreeSet<RequestFingerprint>>> {
        self.seen_requests.lock().map_err(module_error)
    }

    fn seen_warnings(&self) -> CoreResult<MutexGuard<'_, BTreeSet<WarningFingerprint>>> {
        self.seen_warnings.lock().map_err(module_error)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct RequestFingerprint {
    protocol: ProtocolKind,
    start_unix_nanos: u64,
    end_unix_nanos: Option<u64>,
    pid: Option<u32>,
    trace_id_hash: Option<u64>,
    span_id_hash: Option<u64>,
    method: Option<String>,
    status_code: Option<u16>,
    request_target_hash: Option<u64>,
    peer_key: String,
}

impl RequestFingerprint {
    fn from_request(
        request: &ProtocolRequestObservation,
        trace_context: &RequestTraceContext,
    ) -> Self {
        Self {
            protocol: request.protocol,
            start_unix_nanos: request.start_unix_nanos,
            end_unix_nanos: request.end_unix_nanos,
            pid: request.process.as_ref().map(|process| process.pid),
            trace_id_hash: trace_context
                .trace_id
                .as_deref()
                .map(|value| stable_hash64(value.as_bytes())),
            span_id_hash: trace_context
                .span_id
                .as_deref()
                .map(|value| stable_hash64(value.as_bytes())),
            method: request.method.as_deref().map(bounded_fingerprint_value),
            status_code: request.status_code,
            request_target_hash: request_target_fingerprint(&request.attributes),
            peer_key: peer_key(request),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct WarningFingerprint {
    warning_type: String,
    source_signal_kind: String,
    source_module: String,
    timestamp_unix_nanos: u64,
}

#[derive(Debug, Clone)]
struct RequestTraceContext {
    trace_id: Option<String>,
    span_id: Option<String>,
    warning_type: Option<&'static str>,
}

fn trace_context(request: &ProtocolRequestObservation) -> RequestTraceContext {
    if let (Some(trace_id), Some(span_id)) = (&request.trace_id, &request.span_id) {
        if valid_trace_id(trace_id) && valid_span_id(span_id) {
            return RequestTraceContext {
                trace_id: Some(trace_id.clone()),
                span_id: Some(span_id.clone()),
                warning_type: None,
            };
        }
        if request.traceparent.is_none() {
            return RequestTraceContext {
                trace_id: None,
                span_id: None,
                warning_type: Some("malformed_trace_context"),
            };
        }
    }

    if let Some(traceparent) = &request.traceparent {
        return match parse_traceparent(traceparent) {
            Ok(context) => RequestTraceContext {
                trace_id: Some(context.trace_id),
                span_id: Some(context.span_id),
                warning_type: None,
            },
            Err(_) => RequestTraceContext {
                trace_id: None,
                span_id: None,
                warning_type: Some("malformed_trace_context"),
            },
        };
    }

    RequestTraceContext {
        trace_id: None,
        span_id: None,
        warning_type: Some("missing_trace_context"),
    }
}

fn request_span_name(protocol: ProtocolKind) -> &'static str {
    match protocol {
        ProtocolKind::Http => "http request",
        ProtocolKind::Grpc => "grpc request",
        ProtocolKind::Kafka => "kafka request",
        ProtocolKind::Mongodb => "mongodb command",
        ProtocolKind::Mysql => "mysql query",
        ProtocolKind::Nats => "nats message",
        ProtocolKind::Postgresql => "postgresql query",
        ProtocolKind::Redis => "redis command",
        ProtocolKind::Unknown => "protocol request",
        _ => "protocol request",
    }
}

fn bounded_attributes(attributes: &[TraceAttribute]) -> Vec<TraceAttribute> {
    attributes
        .iter()
        .filter(|attribute| {
            attribute.key.len() <= MAX_REQUEST_ATTRIBUTE_KEY_BYTES
                && attribute.value.len() <= MAX_REQUEST_ATTRIBUTE_VALUE_BYTES
        })
        .take(MAX_REQUEST_ATTRIBUTES)
        .cloned()
        .collect()
}

fn bounded_fingerprint_value(value: &str) -> String {
    if value.len() <= MAX_FINGERPRINT_VALUE_BYTES {
        value.to_string()
    } else {
        format!("hash:{:016x}", stable_hash64(value.as_bytes()))
    }
}

fn request_target_fingerprint(attributes: &[TraceAttribute]) -> Option<u64> {
    attributes.iter().find_map(|attribute| {
        if !matches!(
            attribute.key.as_str(),
            "url.path" | "http.route" | "http.request.target" | "db.operation"
        ) || attribute.key.len() > MAX_REQUEST_ATTRIBUTE_KEY_BYTES
            || attribute.value.len() > MAX_REQUEST_ATTRIBUTE_VALUE_BYTES
        {
            return None;
        }
        Some(stable_hash64(attribute.value.as_bytes()))
    })
}

fn valid_trace_id(value: &str) -> bool {
    value.len() == 32 && is_lower_hex(value) && !is_all_zero(value)
}

fn valid_span_id(value: &str) -> bool {
    value.len() == 16 && is_lower_hex(value) && !is_all_zero(value)
}

fn is_lower_hex(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_all_zero(value: &str) -> bool {
    value.bytes().all(|byte| byte == b'0')
}

fn peer_key(request: &ProtocolRequestObservation) -> String {
    let Some(peer) = &request.peer else {
        return "unknown-peer".to_string();
    };
    if let Some(domain) = &peer.domain {
        return format!(
            "domain:{:016x}:{}",
            stable_hash64(domain.as_bytes()),
            peer.port
                .map(|port| port.to_string())
                .unwrap_or_else(|| "unknown".to_string())
        );
    }
    if let Some(address) = &peer.address {
        return format!(
            "address:{:016x}:{}",
            stable_hash64(address.as_bytes()),
            peer.port
                .map(|port| port.to_string())
                .unwrap_or_else(|| "unknown".to_string())
        );
    }
    "unknown-peer".to_string()
}

fn stable_hash64(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

fn warning_message(warning_type: &str) -> &'static str {
    match warning_type {
        "missing_trace_context" => "protocol request had no observed trace context",
        "malformed_trace_context" => "protocol request had malformed trace context",
        "missing_attribution" => "protocol request has no container or Kubernetes context",
        _ => "request correlation warning",
    }
}

fn module_error<T>(err: std::sync::PoisonError<T>) -> CoreError {
    CoreError::ModuleFailed {
        module: "generator.request_correlation".to_string(),
        message: err.to_string(),
    }
}
