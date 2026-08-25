use async_trait::async_trait;
use e_navigator_core::{
    CoreError, CoreResult, Generator, ModuleKind, ModuleMetadata, RequestCorrelationConfig, Signal,
};
use e_navigator_protocol::trace_context::parse_traceparent;
use e_navigator_signals::{
    ProtocolCaptureRole, ProtocolKind, ProtocolRequestObservation, RequestCorrelationWarning,
    RequestSpanObservation, SignalEnvelope, SignalPayload, TraceAttribute, TraceConfidence,
    TraceCorrelationKind,
};
use std::{
    collections::{BTreeMap, HashSet, VecDeque},
    fmt,
    hash::Hash,
    sync::{Arc, Mutex, MutexGuard},
};
use tokio::sync::mpsc;

use crate::otel_coexistence::OtelSdkDetector;

const DEFAULT_MAX_SEEN_REQUESTS: usize = 8192;
const DEFAULT_MAX_WARNINGS: usize = 1024;
const MAX_REQUEST_ATTRIBUTES: usize = 8;
const MAX_REQUEST_ATTRIBUTE_KEY_BYTES: usize = 128;
const MAX_REQUEST_ATTRIBUTE_VALUE_BYTES: usize = 256;
const MAX_REQUEST_SERVICE_NAME_BYTES: usize = 253;
const MAX_REQUEST_METHOD_BYTES: usize = 128;
const MAX_FINGERPRINT_VALUE_BYTES: usize = 64;

#[derive(Debug)]
pub struct RequestCorrelationGenerator {
    max_seen_requests: usize,
    max_warnings: usize,
    generate_trace_ids: bool,
    application_span_ownership_labels: BTreeMap<String, String>,
    otel_sdk_detector: Option<Mutex<OtelSdkDetector>>,
    seen_requests: Mutex<BoundedFingerprints<RequestFingerprint>>,
    seen_warnings: Mutex<BoundedFingerprints<WarningFingerprint>>,
}

impl Default for RequestCorrelationGenerator {
    fn default() -> Self {
        Self::with_limits(DEFAULT_MAX_SEEN_REQUESTS, DEFAULT_MAX_WARNINGS)
    }
}

impl RequestCorrelationGenerator {
    pub fn with_limits(max_seen_requests: usize, max_warnings: usize) -> Self {
        Self::with_options(max_seen_requests, max_warnings, true)
    }

    pub fn with_options(
        max_seen_requests: usize,
        max_warnings: usize,
        generate_trace_ids: bool,
    ) -> Self {
        Self {
            max_seen_requests,
            max_warnings,
            generate_trace_ids,
            application_span_ownership_labels: BTreeMap::new(),
            otel_sdk_detector: None,
            seen_requests: Mutex::new(BoundedFingerprints::default()),
            seen_warnings: Mutex::new(BoundedFingerprints::default()),
        }
    }

    pub fn from_config(config: &RequestCorrelationConfig, procfs_root: std::path::PathBuf) -> Self {
        let mut generator = Self::with_options(
            config.max_seen_requests,
            config.max_warnings,
            config.generate_trace_ids,
        );
        generator.application_span_ownership_labels =
            config.application_span_ownership_labels.clone();
        if config.suppress_otel_sdk_spans {
            generator.otel_sdk_detector = Some(Mutex::new(OtelSdkDetector::new(procfs_root)));
        }
        generator
    }
}

#[async_trait]
impl Generator<SignalEnvelope> for RequestCorrelationGenerator {
    fn metadata(&self) -> ModuleMetadata {
        ModuleMetadata::new("generator.request_correlation", ModuleKind::Generator)
    }

    fn accepts(&self, signal: &SignalEnvelope) -> bool {
        matches!(
            &signal.payload,
            SignalPayload::ProtocolRequestObservation(_)
        )
    }

    fn observe_immediate(
        &self,
        signal: &SignalEnvelope,
    ) -> Option<CoreResult<Vec<SignalEnvelope>>> {
        Some(self.outputs_for_signal(signal))
    }

    async fn observe(
        &self,
        signal: &SignalEnvelope,
        tx: &mpsc::Sender<SignalEnvelope>,
    ) -> CoreResult<()> {
        let outputs = self.outputs_for_signal(signal)?;

        for output in outputs {
            tx.send(output)
                .await
                .map_err(|_| CoreError::PipelineClosed)?;
        }

        Ok(())
    }
}

impl RequestCorrelationGenerator {
    fn outputs_for_signal(&self, signal: &SignalEnvelope) -> CoreResult<Vec<SignalEnvelope>> {
        match &signal.payload {
            SignalPayload::ProtocolRequestObservation(request) => {
                self.observe_protocol_request(signal, request)
            }
            _ => Ok(Vec::new()),
        }
    }

    fn observe_protocol_request(
        &self,
        signal: &SignalEnvelope,
        request: &ProtocolRequestObservation,
    ) -> CoreResult<Vec<SignalEnvelope>> {
        if let Some(reason) = self.span_suppression_reason(request)? {
            let warning = self.span_suppression_warning(signal, request, reason)?;
            return Ok(warning.into_iter().collect());
        }
        let mut trace_context = trace_context(request);

        // On an outbound request, the span id carried by traceparent belongs
        // to the instrumentation that injected the header. Re-exporting that
        // identity as an E-Navigator client span would create a duplicate OTLP
        // span and can merge unrelated requests when callers reuse a parent
        // context. Keep the passive collector out of that ownership boundary;
        // the downstream server capture will still attach to this remote
        // parent. Requests without an observed context continue to receive a
        // generated E-Navigator identity below.
        if request.role == Some(ProtocolCaptureRole::Client)
            && trace_context.trace_id.is_some()
            && trace_context.span_id.is_some()
            && trace_context.warning_kind.is_none()
            && request.correlation_kind != TraceCorrelationKind::GeneratedTraceContext
        {
            return Ok(Vec::new());
        }

        let peer_fingerprint = PeerFingerprint::from_request(request);
        let fingerprint =
            RequestFingerprint::from_request(request, &trace_context, peer_fingerprint);
        if !self.mark_request_seen(fingerprint)? {
            return Ok(Vec::new());
        }

        if self.generate_trace_ids && trace_context.trace_id.is_none() {
            let (trace_id, span_id) = generated_trace_identity(request, peer_fingerprint);
            trace_context.trace_id = Some(trace_id);
            trace_context.span_id = Some(span_id);
            trace_context.generated = true;
        }

        let mut parent_span_id = request.parent_span_id.clone();
        if request.role == Some(ProtocolCaptureRole::Server)
            && !trace_context.generated
            && let Some(remote_parent_span_id) = trace_context.span_id.clone()
        {
            let (_, server_span_id) = generated_trace_identity(request, peer_fingerprint);
            trace_context.span_id = Some(server_span_id);
            parent_span_id = Some(remote_parent_span_id);
        }

        let has_trace_context = trace_context.trace_id.is_some();
        let correlation_kind = if request.correlation_kind == TraceCorrelationKind::Synthetic {
            TraceCorrelationKind::Synthetic
        } else if has_trace_context {
            if trace_context.generated {
                TraceCorrelationKind::GeneratedTraceContext
            } else {
                TraceCorrelationKind::ObservedTraceContext
            }
        } else {
            request.correlation_kind
        };
        let confidence =
            if has_trace_context && request.correlation_kind != TraceCorrelationKind::Synthetic {
                TraceConfidence::High
            } else {
                request.confidence
            };

        let mut attributes = bounded_attributes(&request.attributes);
        if let Some(role) = request.role {
            insert_provenance_attribute(
                &mut attributes,
                "e.navigator.protocol.capture.role",
                match role {
                    ProtocolCaptureRole::Client => "client",
                    ProtocolCaptureRole::Server => "server",
                    _ => "unknown",
                },
            );
        }
        if request.role == Some(ProtocolCaptureRole::Server)
            && parent_span_id.is_some()
            && !trace_context.generated
        {
            insert_provenance_attribute(
                &mut attributes,
                "e.navigator.trace.context.role",
                "remote_parent",
            );
        }
        if trace_context.generated {
            insert_provenance_attribute(
                &mut attributes,
                "e.navigator.trace.identity.source",
                "generated",
            );
        }

        let mut outputs = vec![SignalEnvelope::request_span_observation(
            "generator.request_correlation",
            signal.host.clone(),
            RequestSpanObservation {
                name: request_span_name(request.protocol).to_string(),
                protocol: request.protocol,
                trace_id: trace_context.trace_id,
                span_id: trace_context.span_id,
                parent_span_id,
                start_unix_nanos: request.start_unix_nanos,
                end_unix_nanos: request.end_unix_nanos,
                duration_nanos: request.duration_nanos,
                correlation_kind,
                confidence,
                service_name: bounded_optional_value(
                    request.service_name.as_deref(),
                    MAX_REQUEST_SERVICE_NAME_BYTES,
                ),
                method: bounded_optional_value(request.method.as_deref(), MAX_REQUEST_METHOD_BYTES),
                status_code: request.status_code,
                process: request.process.clone(),
                container: request.container.clone(),
                kubernetes: request.kubernetes.clone(),
                peer: request.peer.clone(),
                attributes,
            },
        )];

        if let Some(warning_kind) = trace_context.warning_kind
            && let Some(warning) = self.warning(signal, request, warning_kind)?
        {
            outputs.push(warning);
        }

        if request.container.is_none()
            && request.kubernetes.is_none()
            && let Some(warning) =
                self.warning(signal, request, RequestWarningKind::MissingAttribution)?
        {
            outputs.push(warning);
        }

        Ok(outputs)
    }

    fn mark_request_seen(&self, fingerprint: RequestFingerprint) -> CoreResult<bool> {
        let mut seen = self.seen_requests()?;
        Ok(seen.insert_if_new(fingerprint, self.max_seen_requests))
    }

    fn span_suppression_reason(
        &self,
        request: &ProtocolRequestObservation,
    ) -> CoreResult<Option<SpanSuppressionReason>> {
        if !self.application_span_ownership_labels.is_empty()
            && let Some(kubernetes) = request.kubernetes.as_ref().filter(|kubernetes| {
                self.application_span_ownership_labels
                    .iter()
                    .all(|(key, value)| kubernetes.labels.get(key) == Some(value))
            })
        {
            return Ok(Some(SpanSuppressionReason::ApplicationOwner {
                namespace: kubernetes.namespace.clone(),
                pod_name: kubernetes.pod_name.clone(),
                pod_uid: kubernetes.pod_uid.clone(),
            }));
        }
        let (Some(detector), Some(process)) = (&self.otel_sdk_detector, &request.process) else {
            return Ok(None);
        };
        detector.lock().map_err(module_error).map(|mut detector| {
            detector
                .has_supported_zero_code_trace_agent(process)
                .then_some(SpanSuppressionReason::DetectedOtelSdk)
        })
    }

    fn warning(
        &self,
        signal: &SignalEnvelope,
        request: &ProtocolRequestObservation,
        warning_kind: RequestWarningKind,
    ) -> CoreResult<Option<SignalEnvelope>> {
        let fingerprint = WarningFingerprint::Request {
            warning_kind,
            source_module: signal.source.clone(),
            timestamp_unix_nanos: request.start_unix_nanos,
        };
        let mut seen = self.seen_warnings()?;
        if !seen.insert_if_new(fingerprint, self.max_warnings) {
            return Ok(None);
        }
        drop(seen);

        Ok(Some(SignalEnvelope::request_correlation_warning(
            "generator.request_correlation",
            signal.host.clone(),
            RequestCorrelationWarning {
                warning_type: warning_kind.code().to_string(),
                message: warning_kind.message().to_string(),
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

    fn span_suppression_warning(
        &self,
        signal: &SignalEnvelope,
        request: &ProtocolRequestObservation,
        reason: SpanSuppressionReason,
    ) -> CoreResult<Option<SignalEnvelope>> {
        let warning_kind = reason.warning_kind();
        let fingerprint = match reason {
            SpanSuppressionReason::ApplicationOwner {
                namespace,
                pod_name,
                pod_uid,
            } => WarningFingerprint::ApplicationSpanOwnership {
                source_module: signal.source.clone(),
                namespace,
                pod_name,
                pod_uid,
            },
            SpanSuppressionReason::DetectedOtelSdk => WarningFingerprint::OtelSdkSuppression {
                source_module: signal.source.clone(),
                pid: request.process.as_ref().map(|process| process.pid),
            },
        };
        let mut seen = self.seen_warnings()?;
        if !seen.insert_if_new(fingerprint, self.max_warnings) {
            return Ok(None);
        }
        drop(seen);

        Ok(Some(SignalEnvelope::request_correlation_warning(
            "generator.request_correlation",
            signal.host.clone(),
            RequestCorrelationWarning {
                warning_type: warning_kind.code().to_string(),
                message: warning_kind.message().to_string(),
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

    fn seen_requests(&self) -> CoreResult<MutexGuard<'_, BoundedFingerprints<RequestFingerprint>>> {
        self.seen_requests.lock().map_err(module_error)
    }

    fn seen_warnings(&self) -> CoreResult<MutexGuard<'_, BoundedFingerprints<WarningFingerprint>>> {
        self.seen_warnings.lock().map_err(module_error)
    }
}

#[derive(Debug)]
struct BoundedFingerprints<T> {
    entries: HashSet<Arc<T>>,
    insertion_order: VecDeque<Arc<T>>,
}

impl<T> Default for BoundedFingerprints<T> {
    fn default() -> Self {
        Self {
            entries: HashSet::new(),
            insertion_order: VecDeque::new(),
        }
    }
}

impl<T> BoundedFingerprints<T>
where
    T: Eq + Hash,
{
    fn insert_if_new(&mut self, fingerprint: T, max_entries: usize) -> bool {
        let fingerprint = Arc::new(fingerprint);
        if !self.entries.insert(fingerprint.clone()) {
            return false;
        }

        let max_entries = max_entries.max(1);
        while self.entries.len() > max_entries {
            let Some(oldest) = self.insertion_order.pop_front() else {
                break;
            };
            self.entries.remove(oldest.as_ref());
        }

        self.insertion_order.push_back(fingerprint);
        true
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
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
    peer: PeerFingerprint,
}

impl RequestFingerprint {
    fn from_request(
        request: &ProtocolRequestObservation,
        trace_context: &RequestTraceContext,
        peer: PeerFingerprint,
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
            peer,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum PeerFingerprint {
    Unknown,
    Domain { hash: u64, port: Option<u16> },
    Address { hash: u64, port: Option<u16> },
}

impl PeerFingerprint {
    fn from_request(request: &ProtocolRequestObservation) -> Self {
        let Some(peer) = &request.peer else {
            return Self::Unknown;
        };
        if let Some(domain) = &peer.domain {
            return Self::Domain {
                hash: stable_hash64(domain.as_bytes()),
                port: peer.port,
            };
        }
        if let Some(address) = &peer.address {
            return Self::Address {
                hash: stable_hash64(address.as_bytes()),
                port: peer.port,
            };
        }
        Self::Unknown
    }
}

impl fmt::Display for PeerFingerprint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unknown => formatter.write_str("unknown-peer"),
            Self::Domain { hash, port } => {
                write_peer_fingerprint(formatter, "domain", *hash, *port)
            }
            Self::Address { hash, port } => {
                write_peer_fingerprint(formatter, "address", *hash, *port)
            }
        }
    }
}

fn write_peer_fingerprint(
    formatter: &mut fmt::Formatter<'_>,
    kind: &str,
    hash: u64,
    port: Option<u16>,
) -> fmt::Result {
    write!(formatter, "{kind}:{hash:016x}:")?;
    match port {
        Some(port) => write!(formatter, "{port}"),
        None => formatter.write_str("unknown"),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum WarningFingerprint {
    Request {
        warning_kind: RequestWarningKind,
        source_module: String,
        timestamp_unix_nanos: u64,
    },
    OtelSdkSuppression {
        source_module: String,
        pid: Option<u32>,
    },
    ApplicationSpanOwnership {
        source_module: String,
        namespace: String,
        pod_name: String,
        pod_uid: Option<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum SpanSuppressionReason {
    ApplicationOwner {
        namespace: String,
        pod_name: String,
        pod_uid: Option<String>,
    },
    DetectedOtelSdk,
}

impl SpanSuppressionReason {
    fn warning_kind(&self) -> RequestWarningKind {
        match self {
            Self::ApplicationOwner { .. } => RequestWarningKind::ApplicationSpanOwnerSuppressed,
            Self::DetectedOtelSdk => RequestWarningKind::OtelSdkSpanSuppressed,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum RequestWarningKind {
    MissingTraceContext,
    MalformedTraceContext,
    MissingAttribution,
    OtelSdkSpanSuppressed,
    ApplicationSpanOwnerSuppressed,
}

impl RequestWarningKind {
    fn code(self) -> &'static str {
        match self {
            Self::MissingTraceContext => "missing_trace_context",
            Self::MalformedTraceContext => "malformed_trace_context",
            Self::MissingAttribution => "missing_attribution",
            Self::OtelSdkSpanSuppressed => "otel_sdk_span_suppressed",
            Self::ApplicationSpanOwnerSuppressed => "application_span_owner_suppressed",
        }
    }

    fn message(self) -> &'static str {
        match self {
            Self::MissingTraceContext => "protocol request had no observed trace context",
            Self::MalformedTraceContext => "protocol request had malformed trace context",
            Self::MissingAttribution => "protocol request has no container or Kubernetes context",
            Self::OtelSdkSpanSuppressed => {
                "request span suppressed because the process has a supported OpenTelemetry zero-code agent"
            }
            Self::ApplicationSpanOwnerSuppressed => {
                "request span suppressed because matching Kubernetes labels declare application ownership"
            }
        }
    }
}

#[derive(Debug, Clone)]
struct RequestTraceContext {
    trace_id: Option<String>,
    span_id: Option<String>,
    warning_kind: Option<RequestWarningKind>,
    generated: bool,
}

fn trace_context(request: &ProtocolRequestObservation) -> RequestTraceContext {
    if let (Some(trace_id), Some(span_id)) = (&request.trace_id, &request.span_id) {
        if valid_trace_id(trace_id) && valid_span_id(span_id) {
            return RequestTraceContext {
                trace_id: Some(trace_id.clone()),
                span_id: Some(span_id.clone()),
                warning_kind: None,
                generated: request.correlation_kind == TraceCorrelationKind::GeneratedTraceContext,
            };
        }
        if request.traceparent.is_none() {
            return RequestTraceContext {
                trace_id: None,
                span_id: None,
                warning_kind: Some(RequestWarningKind::MalformedTraceContext),
                generated: false,
            };
        }
    }

    if let Some(traceparent) = &request.traceparent {
        return match parse_traceparent(traceparent) {
            Ok(context) => RequestTraceContext {
                trace_id: Some(context.trace_id),
                span_id: Some(context.span_id),
                warning_kind: None,
                generated: request.correlation_kind == TraceCorrelationKind::GeneratedTraceContext,
            },
            Err(_) => RequestTraceContext {
                trace_id: None,
                span_id: None,
                warning_kind: Some(RequestWarningKind::MalformedTraceContext),
                generated: false,
            },
        };
    }

    RequestTraceContext {
        trace_id: None,
        span_id: None,
        warning_kind: Some(RequestWarningKind::MissingTraceContext),
        generated: false,
    }
}

fn generated_trace_identity(
    request: &ProtocolRequestObservation,
    peer: PeerFingerprint,
) -> (String, String) {
    let pid = request
        .process
        .as_ref()
        .map(|process| process.pid)
        .unwrap_or_default();
    let cgroup_id = request
        .process
        .as_ref()
        .and_then(|process| process.cgroup_id)
        .unwrap_or_default();
    let method_hash = request
        .method
        .as_deref()
        .map(|method| stable_hash64(method.as_bytes()))
        .unwrap_or_default();
    let target_hash = request_target_fingerprint(&request.attributes).unwrap_or_default();
    let material = format!(
        "{:?}|{:?}|{}|{}|{}|{}|{}|{}|{}|{}",
        request.protocol,
        request.role,
        request.start_unix_nanos,
        request.end_unix_nanos.unwrap_or_default(),
        pid,
        cgroup_id,
        method_hash,
        target_hash,
        request.status_code.unwrap_or_default(),
        peer,
    );
    let [first, second, span] = generated_identity_hashes(material.as_bytes()).map(nonzero_hash);
    (format!("{first:016x}{second:016x}"), format!("{span:016x}"))
}

fn generated_identity_hashes(bytes: &[u8]) -> [u64; 3] {
    let mut hashes = [
        0xcbf2_9ce4_8422_2325_u64 ^ 0x9e37_79b9_7f4a_7c15,
        0xcbf2_9ce4_8422_2325_u64 ^ 0xd1b5_4a32_d192_ed03,
        0xcbf2_9ce4_8422_2325_u64 ^ 0x94d0_49bb_1331_11eb,
    ];
    for byte in bytes {
        for hash in &mut hashes {
            *hash ^= u64::from(*byte);
            *hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
    }
    hashes
}

fn nonzero_hash(hash: u64) -> u64 {
    if hash == 0 { 1 } else { hash }
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
        ProtocolKind::Websocket => "websocket frame",
        ProtocolKind::Unknown => "protocol request",
        _ => "protocol request",
    }
}

fn bounded_attributes(attributes: &[TraceAttribute]) -> Vec<TraceAttribute> {
    let mut bounded = Vec::new();
    for attribute in attributes.iter().filter(|attribute| {
        attribute.key.len() <= MAX_REQUEST_ATTRIBUTE_KEY_BYTES
            && attribute.value.len() <= MAX_REQUEST_ATTRIBUTE_VALUE_BYTES
    }) {
        if bounded.len() < MAX_REQUEST_ATTRIBUTES {
            bounded.push(attribute.clone());
            continue;
        }
        if is_request_error_attribute(&attribute.key)
            && !bounded.iter().any(|existing| existing.key == attribute.key)
            && let Some(index) = bounded
                .iter()
                .rposition(|existing| !is_request_error_attribute(&existing.key))
        {
            bounded.remove(index);
            bounded.push(attribute.clone());
        }
    }
    bounded
}

fn insert_provenance_attribute(attributes: &mut Vec<TraceAttribute>, key: &str, value: &str) {
    if attributes.iter().any(|attribute| attribute.key == key) {
        return;
    }
    if attributes.len() >= MAX_REQUEST_ATTRIBUTES
        && let Some(index) = attributes
            .iter()
            .rposition(|attribute| !is_request_error_attribute(&attribute.key))
    {
        attributes.remove(index);
    }
    if attributes.len() < MAX_REQUEST_ATTRIBUTES {
        attributes.push(TraceAttribute {
            key: key.to_string(),
            value: value.to_string(),
        });
    }
}

fn is_request_error_attribute(key: &str) -> bool {
    matches!(
        key,
        "error.type"
            | "http.response.status_code"
            | "rpc.grpc.status_code"
            | "db.response.status_code"
            | "messaging.kafka.response.error_code"
            | "messaging.nats.status_code"
    )
}

fn bounded_optional_value(value: Option<&str>, max_bytes: usize) -> Option<String> {
    let value = value?;
    (value.len() <= max_bytes).then(|| value.to_string())
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
            "url.path" | "http.route" | "http.request.target" | "db.operation.name"
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

fn stable_hash64(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

fn module_error<T>(err: std::sync::PoisonError<T>) -> CoreError {
    CoreError::ModuleFailed {
        module: "generator.request_correlation".to_string(),
        message: err.to_string(),
    }
}
