use e_navigator_signals::{
    ContainerContext, DependencyEndpoint, KubernetesContext, NetworkAddressFamily,
    NetworkFlowWarning, NetworkProcessIdentity, NetworkProtocol, ProfilingAttribute,
    ProfilingConfidence, ProfilingCorrelationKind, ProfilingKind, ProfilingWarningObservation,
    ProtocolKind, RequestCorrelationWarning, RequestSpanObservation,
    ServiceInteractionSpanObservation, SignalEnvelope, SignalPayload, TraceAttribute,
    TraceConfidence, TraceCorrelationKind, TraceCorrelationWarning, TracePeerContext,
    TraceServicePathObservation, TraceSpanObservation,
};
use serde::Serialize;
use std::collections::BTreeMap;

const MAX_FORMATTED_TRACE_ATTRIBUTES: usize = 16;
const MAX_TRACE_ATTRIBUTE_KEY_BYTES: usize = 128;
const MAX_TRACE_ATTRIBUTE_VALUE_BYTES: usize = 256;
const PROTOCOL_CAPTURE_ROLE_ATTRIBUTE: &str = "e.navigator.protocol.capture.role";

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OtelTraceRecordKind {
    Span,
    ServiceInteraction,
    ServicePath,
    CorrelationWarning,
    RequestSpan,
    RequestWarning,
    NetworkFlowWarning,
    ProfilingWarning,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "code")]
pub enum OtelSpanStatus {
    Error { message: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OtelTraceRecord {
    pub name: String,
    pub kind: OtelTraceRecordKind,
    pub status: Option<OtelSpanStatus>,
    pub trace_id: Option<String>,
    pub span_id: Option<String>,
    pub parent_span_id: Option<String>,
    pub start_unix_nanos: u64,
    pub end_unix_nanos: Option<u64>,
    pub duration_nanos: Option<u64>,
    pub resource: BTreeMap<String, serde_json::Value>,
    pub attributes: BTreeMap<String, serde_json::Value>,
}

pub fn format_otel_trace_record(signal: &SignalEnvelope) -> Option<OtelTraceRecord> {
    match &signal.payload {
        SignalPayload::TraceSpanObservation(span) => Some(trace_span_record(signal, span)),
        SignalPayload::ServiceInteractionSpanObservation(span) => {
            Some(service_interaction_record(signal, span))
        }
        SignalPayload::TraceServicePathObservation(path) => Some(service_path_record(signal, path)),
        SignalPayload::TraceCorrelationWarning(warning) => {
            Some(correlation_warning_record(signal, warning))
        }
        SignalPayload::RequestSpanObservation(span) => Some(request_span_record(signal, span)),
        SignalPayload::RequestCorrelationWarning(warning) => {
            Some(request_warning_record(signal, warning))
        }
        SignalPayload::NetworkFlowWarning(warning) => {
            Some(network_flow_warning_record(signal, warning))
        }
        SignalPayload::ProfilingWarningObservation(warning) => {
            Some(profiling_warning_record(signal, warning))
        }
        _ => None,
    }
}

fn trace_span_record(signal: &SignalEnvelope, span: &TraceSpanObservation) -> OtelTraceRecord {
    let resource = resource_attributes(
        signal,
        span.container.as_ref(),
        span.kubernetes.as_ref(),
        span.service_name.as_deref(),
    );

    let mut attributes = correlation_attributes(span.correlation_kind, span.confidence);
    append_process_attributes(&mut attributes, span.process.as_ref());
    append_peer_attributes(&mut attributes, span.peer.as_ref());
    append_trace_attributes(&mut attributes, &span.attributes);
    let (trace_id, span_id, parent_span_id) =
        trace_identity(&span.trace_id, &span.span_id, &span.parent_span_id);

    OtelTraceRecord {
        name: truncate_utf8(&span.name, MAX_TRACE_ATTRIBUTE_VALUE_BYTES),
        kind: OtelTraceRecordKind::Span,
        status: None,
        trace_id,
        span_id,
        parent_span_id,
        start_unix_nanos: span.start_unix_nanos,
        end_unix_nanos: span.end_unix_nanos,
        duration_nanos: span.duration_nanos,
        resource,
        attributes,
    }
}

fn service_interaction_record(
    signal: &SignalEnvelope,
    span: &ServiceInteractionSpanObservation,
) -> OtelTraceRecord {
    let mut attributes = correlation_attributes(span.correlation_kind, span.confidence);
    attributes.insert(
        "net.transport".to_string(),
        serde_json::json!(protocol_name(span.protocol)),
    );
    append_process_attributes(&mut attributes, span.process.as_ref());
    append_endpoint_attributes(&mut attributes, "client", &span.source);
    append_endpoint_attributes(&mut attributes, "server", &span.destination);
    append_trace_attributes(&mut attributes, &span.attributes);
    if let Some(error_type) = &span.error_type {
        attributes.insert("error.type".to_string(), bounded_json_string(error_type));
    }
    let (trace_id, span_id, parent_span_id) =
        trace_identity(&span.trace_id, &span.span_id, &span.parent_span_id);

    OtelTraceRecord {
        name: truncate_utf8(&span.name, MAX_TRACE_ATTRIBUTE_VALUE_BYTES),
        kind: OtelTraceRecordKind::ServiceInteraction,
        status: span.error_type.as_deref().map(error_status),
        trace_id,
        span_id,
        parent_span_id,
        start_unix_nanos: span.start_unix_nanos,
        end_unix_nanos: span.end_unix_nanos,
        duration_nanos: span.duration_nanos,
        resource: resource_attributes(
            signal,
            span.source.container.as_ref(),
            span.source.workload.as_ref(),
            None,
        ),
        attributes,
    }
}

fn service_path_record(
    signal: &SignalEnvelope,
    path: &TraceServicePathObservation,
) -> OtelTraceRecord {
    let mut attributes = correlation_attributes(path.correlation_kind, path.confidence);
    attributes.insert(
        "trace.service.path.key".to_string(),
        bounded_json_string(&path.path_key),
    );
    attributes.insert(
        "trace.service.path.observations".to_string(),
        serde_json::json!(path.observations),
    );
    attributes.insert(
        "net.transport".to_string(),
        serde_json::json!(protocol_name(path.protocol)),
    );
    append_endpoint_attributes(&mut attributes, "client", &path.source);
    append_endpoint_attributes(&mut attributes, "server", &path.destination);
    append_trace_attributes(&mut attributes, &path.attributes);

    OtelTraceRecord {
        name: "trace.service.path".to_string(),
        kind: OtelTraceRecordKind::ServicePath,
        status: None,
        trace_id: None,
        span_id: None,
        parent_span_id: None,
        start_unix_nanos: path.first_seen_unix_nanos,
        end_unix_nanos: Some(path.last_seen_unix_nanos),
        duration_nanos: Some(
            path.last_seen_unix_nanos
                .saturating_sub(path.first_seen_unix_nanos),
        ),
        resource: resource_attributes(
            signal,
            path.source.container.as_ref(),
            path.source.workload.as_ref(),
            None,
        ),
        attributes,
    }
}

fn correlation_warning_record(
    signal: &SignalEnvelope,
    warning: &TraceCorrelationWarning,
) -> OtelTraceRecord {
    let mut attributes = BTreeMap::new();
    attributes.insert(
        "trace.correlation.kind".to_string(),
        serde_json::json!(correlation_kind_name(warning.correlation_kind)),
    );
    attributes.insert(
        "warning.type".to_string(),
        bounded_json_string(&warning.warning_type),
    );
    attributes.insert(
        "warning.message".to_string(),
        bounded_json_string(&warning.message),
    );
    attributes.insert(
        "trace.source.signal.kind".to_string(),
        bounded_json_string(&warning.source_signal_kind),
    );
    attributes.insert(
        "trace.source.module".to_string(),
        bounded_json_string(&warning.source_module),
    );
    append_process_attributes(&mut attributes, warning.process.as_ref());
    append_peer_attributes(&mut attributes, warning.peer.as_ref());

    OtelTraceRecord {
        name: "trace.correlation.warning".to_string(),
        kind: OtelTraceRecordKind::CorrelationWarning,
        status: None,
        trace_id: None,
        span_id: None,
        parent_span_id: None,
        start_unix_nanos: warning.timestamp_unix_nanos,
        end_unix_nanos: Some(warning.timestamp_unix_nanos),
        duration_nanos: Some(0),
        resource: resource_attributes(
            signal,
            warning.container.as_ref(),
            warning.kubernetes.as_ref(),
            None,
        ),
        attributes,
    }
}

fn request_span_record(signal: &SignalEnvelope, span: &RequestSpanObservation) -> OtelTraceRecord {
    let mut attributes = correlation_attributes(span.correlation_kind, span.confidence);
    attributes.insert(
        "network.protocol.name".to_string(),
        serde_json::json!(protocol_kind_name(span.protocol)),
    );
    if let Some(method) = &span.method {
        attributes.insert(
            "http.request.method".to_string(),
            bounded_json_string(method),
        );
    }
    append_request_status_attribute(&mut attributes, span.protocol, span.status_code);
    append_process_attributes(&mut attributes, span.process.as_ref());
    append_request_peer_attributes(&mut attributes, span);
    append_trace_attributes(&mut attributes, &span.attributes);
    let (trace_id, span_id, parent_span_id) =
        trace_identity(&span.trace_id, &span.span_id, &span.parent_span_id);

    OtelTraceRecord {
        name: truncate_utf8(&span.name, MAX_TRACE_ATTRIBUTE_VALUE_BYTES),
        kind: OtelTraceRecordKind::RequestSpan,
        status: request_span_status(span),
        trace_id,
        span_id,
        parent_span_id,
        start_unix_nanos: span.start_unix_nanos,
        end_unix_nanos: span.end_unix_nanos,
        duration_nanos: span.duration_nanos,
        resource: resource_attributes(
            signal,
            span.container.as_ref(),
            span.kubernetes.as_ref(),
            span.service_name.as_deref(),
        ),
        attributes,
    }
}

fn request_warning_record(
    signal: &SignalEnvelope,
    warning: &RequestCorrelationWarning,
) -> OtelTraceRecord {
    let mut attributes = BTreeMap::new();
    attributes.insert(
        "trace.correlation.kind".to_string(),
        serde_json::json!(correlation_kind_name(warning.correlation_kind)),
    );
    attributes.insert(
        "warning.type".to_string(),
        bounded_json_string(&warning.warning_type),
    );
    attributes.insert(
        "warning.message".to_string(),
        bounded_json_string(&warning.message),
    );
    attributes.insert(
        "trace.source.signal.kind".to_string(),
        bounded_json_string(&warning.source_signal_kind),
    );
    attributes.insert(
        "trace.source.module".to_string(),
        bounded_json_string(&warning.source_module),
    );
    attributes.insert(
        "network.protocol.name".to_string(),
        serde_json::json!(protocol_kind_name(warning.protocol)),
    );
    append_process_attributes(&mut attributes, warning.process.as_ref());
    append_peer_attributes(&mut attributes, warning.peer.as_ref());

    OtelTraceRecord {
        name: "request.correlation.warning".to_string(),
        kind: OtelTraceRecordKind::RequestWarning,
        status: None,
        trace_id: None,
        span_id: None,
        parent_span_id: None,
        start_unix_nanos: warning.timestamp_unix_nanos,
        end_unix_nanos: Some(warning.timestamp_unix_nanos),
        duration_nanos: Some(0),
        resource: resource_attributes(
            signal,
            warning.container.as_ref(),
            warning.kubernetes.as_ref(),
            None,
        ),
        attributes,
    }
}

fn network_flow_warning_record(
    signal: &SignalEnvelope,
    warning: &NetworkFlowWarning,
) -> OtelTraceRecord {
    let mut attributes = BTreeMap::new();
    attributes.insert(
        "warning.type".to_string(),
        bounded_json_string(&warning.warning_type),
    );
    attributes.insert(
        "warning.message".to_string(),
        bounded_json_string(&warning.message),
    );
    attributes.insert(
        "trace.source.signal.kind".to_string(),
        bounded_json_string(&warning.source_signal_kind),
    );
    attributes.insert(
        "trace.source.module".to_string(),
        bounded_json_string(&warning.source_module),
    );
    attributes.insert(
        "network.protocol.name".to_string(),
        serde_json::json!(protocol_name(warning.protocol)),
    );
    attributes.insert(
        "network.address.family".to_string(),
        serde_json::json!(address_family_name(warning.address_family)),
    );
    attributes.insert(
        "server.address".to_string(),
        bounded_json_string(&warning.remote_address),
    );
    attributes.insert(
        "server.port".to_string(),
        serde_json::json!(warning.remote_port),
    );
    append_process_attributes(&mut attributes, Some(&warning.process));

    OtelTraceRecord {
        name: "network.flow.warning".to_string(),
        kind: OtelTraceRecordKind::NetworkFlowWarning,
        status: None,
        trace_id: None,
        span_id: None,
        parent_span_id: None,
        start_unix_nanos: warning.timestamp_unix_nanos,
        end_unix_nanos: Some(warning.timestamp_unix_nanos),
        duration_nanos: Some(0),
        resource: resource_attributes(
            signal,
            warning.container.as_ref(),
            warning.kubernetes.as_ref(),
            None,
        ),
        attributes,
    }
}

fn profiling_warning_record(
    signal: &SignalEnvelope,
    warning: &ProfilingWarningObservation,
) -> OtelTraceRecord {
    let mut attributes = BTreeMap::new();
    attributes.insert(
        "warning.type".to_string(),
        bounded_json_string(&warning.warning_type),
    );
    attributes.insert(
        "warning.message".to_string(),
        bounded_json_string(&warning.message),
    );
    attributes.insert(
        "trace.source.signal.kind".to_string(),
        bounded_json_string(&warning.source_signal_kind),
    );
    attributes.insert(
        "trace.source.module".to_string(),
        bounded_json_string(&warning.source_module),
    );
    attributes.insert(
        "profile.kind".to_string(),
        serde_json::json!(profiling_kind_name(warning.profiling_kind)),
    );
    attributes.insert(
        "profile.correlation.kind".to_string(),
        serde_json::json!(profiling_correlation_kind_name(warning.correlation_kind)),
    );
    attributes.insert(
        "profile.confidence".to_string(),
        serde_json::json!(profiling_confidence_name(warning.confidence)),
    );
    append_process_attributes(&mut attributes, warning.process.as_ref());
    append_profiling_attributes(&mut attributes, &warning.attributes);

    OtelTraceRecord {
        name: "profiling.warning".to_string(),
        kind: OtelTraceRecordKind::ProfilingWarning,
        status: None,
        trace_id: None,
        span_id: None,
        parent_span_id: None,
        start_unix_nanos: warning.timestamp_unix_nanos,
        end_unix_nanos: Some(warning.timestamp_unix_nanos),
        duration_nanos: Some(0),
        resource: resource_attributes(
            signal,
            warning.container.as_ref(),
            warning.kubernetes.as_ref(),
            None,
        ),
        attributes,
    }
}

fn request_span_status(span: &RequestSpanObservation) -> Option<OtelSpanStatus> {
    match (span.protocol, span.status_code) {
        (ProtocolKind::Http, Some(status_code)) if status_code >= 400 => {
            Some(error_status(&format!("HTTP status code {status_code}")))
        }
        (ProtocolKind::Grpc, Some(status_code)) if status_code != 0 => {
            Some(error_status(&format!(
                "gRPC status code {status_code} ({})",
                grpc_status_name(status_code)
            )))
        }
        _ => request_error_type(span)
            .or_else(|| request_error_status_attribute(span))
            .map(error_status),
    }
}

fn request_error_type(span: &RequestSpanObservation) -> Option<&str> {
    span.attributes
        .iter()
        .find(|attribute| attribute.key == "error.type")
        .map(|attribute| attribute.value.as_str())
        .filter(|value| valid_request_status_message(value))
}

fn request_error_status_attribute(span: &RequestSpanObservation) -> Option<&str> {
    span.attributes.iter().find_map(|attribute| {
        let value = attribute.value.as_str();
        if !valid_request_status_message(value) {
            return None;
        }
        match attribute.key.as_str() {
            "http.response.status_code" if matches!(value.parse::<u16>(), Ok(code) if code >= 400) => {
                Some(value)
            }
            "rpc.grpc.status_code" if value != "0" => Some(value),
            "db.response.status_code" if !matches!(value, "OK" | "1") => Some(value),
            "messaging.kafka.response.error_code" if value != "0" => Some(value),
            "messaging.nats.status_code" if value.eq_ignore_ascii_case("ERR") => Some(value),
            _ => None,
        }
    })
}

fn valid_request_status_message(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_TRACE_ATTRIBUTE_VALUE_BYTES
        && !value.bytes().any(|byte| byte.is_ascii_control())
}

fn trace_identity(
    trace_id: &Option<String>,
    span_id: &Option<String>,
    parent_span_id: &Option<String>,
) -> (Option<String>, Option<String>, Option<String>) {
    let trace_id = trace_id.as_deref().and_then(valid_trace_id);
    let span_id = span_id.as_deref().and_then(valid_span_id);
    match (trace_id, span_id) {
        (Some(trace_id), Some(span_id)) => (
            Some(trace_id),
            Some(span_id),
            parent_span_id.as_deref().and_then(valid_span_id),
        ),
        _ => (None, None, None),
    }
}

fn valid_trace_id(value: &str) -> Option<String> {
    valid_hex_id(value, 32)
}

fn valid_span_id(value: &str) -> Option<String> {
    valid_hex_id(value, 16)
}

fn valid_hex_id(value: &str, expected_len: usize) -> Option<String> {
    if value.len() != expected_len
        || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
        || value.bytes().all(|byte| byte == b'0')
    {
        return None;
    }
    Some(value.to_ascii_lowercase())
}

fn error_status(message: &str) -> OtelSpanStatus {
    OtelSpanStatus::Error {
        message: truncate_utf8(message, MAX_TRACE_ATTRIBUTE_VALUE_BYTES),
    }
}

fn append_request_status_attribute(
    attributes: &mut BTreeMap<String, serde_json::Value>,
    protocol: ProtocolKind,
    status_code: Option<u16>,
) {
    let Some(status_code) = status_code else {
        return;
    };
    match protocol {
        ProtocolKind::Http => {
            attributes.insert(
                "http.response.status_code".to_string(),
                serde_json::json!(status_code),
            );
        }
        ProtocolKind::Grpc => {
            attributes.insert(
                "rpc.grpc.status_code".to_string(),
                serde_json::json!(status_code),
            );
        }
        _ => {}
    }
}

fn grpc_status_name(status_code: u16) -> &'static str {
    match status_code {
        0 => "ok",
        1 => "cancelled",
        2 => "unknown",
        3 => "invalid_argument",
        4 => "deadline_exceeded",
        5 => "not_found",
        6 => "already_exists",
        7 => "permission_denied",
        8 => "resource_exhausted",
        9 => "failed_precondition",
        10 => "aborted",
        11 => "out_of_range",
        12 => "unimplemented",
        13 => "internal",
        14 => "unavailable",
        15 => "data_loss",
        16 => "unauthenticated",
        _ => "unknown",
    }
}

fn resource_attributes(
    signal: &SignalEnvelope,
    container: Option<&ContainerContext>,
    kubernetes: Option<&KubernetesContext>,
    service_name: Option<&str>,
) -> BTreeMap<String, serde_json::Value> {
    let mut resource = BTreeMap::new();
    if let Some(host) = &signal.host {
        insert_resource_string(&mut resource, "host.name", host);
    }
    if let Some(service_name) = service_name {
        insert_resource_string(&mut resource, "service.name", service_name);
    }
    if let Some(container) = container {
        insert_resource_string(&mut resource, "container.id", &container.container_id);
        if let Some(runtime) = &container.runtime {
            insert_resource_string(&mut resource, "container.runtime", runtime);
        }
    }
    if let Some(kubernetes) = kubernetes {
        insert_resource_string(&mut resource, "k8s.namespace.name", &kubernetes.namespace);
        insert_resource_string(&mut resource, "k8s.pod.name", &kubernetes.pod_name);
        if let Some(uid) = &kubernetes.pod_uid {
            insert_resource_string(&mut resource, "k8s.pod.uid", uid);
        }
        if let Some(container_name) = &kubernetes.container_name {
            insert_resource_string(&mut resource, "k8s.container.name", container_name);
        }
        if let Some(node_name) = &kubernetes.node_name {
            insert_resource_string(&mut resource, "k8s.node.name", node_name);
        }
        if let Some(deployment_name) = kubernetes
            .labels
            .get("app.kubernetes.io/name")
            .or_else(|| kubernetes.labels.get("app"))
            .filter(|name| !name.is_empty())
        {
            insert_resource_string(&mut resource, "k8s.deployment.name", deployment_name);
        }
    }
    resource
}

fn insert_resource_string(
    resource: &mut BTreeMap<String, serde_json::Value>,
    key: &'static str,
    value: &str,
) {
    resource.insert(key.to_string(), bounded_json_string(value));
}

fn bounded_json_string(value: &str) -> serde_json::Value {
    serde_json::json!(truncate_utf8(value, MAX_TRACE_ATTRIBUTE_VALUE_BYTES))
}

fn truncate_utf8(value: &str, max_bytes: usize) -> String {
    if value.len() <= max_bytes {
        return value.to_string();
    }

    let mut end = max_bytes;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_string()
}

fn correlation_attributes(
    correlation_kind: TraceCorrelationKind,
    confidence: TraceConfidence,
) -> BTreeMap<String, serde_json::Value> {
    let mut attributes = BTreeMap::new();
    attributes.insert(
        "trace.correlation.kind".to_string(),
        serde_json::json!(correlation_kind_name(correlation_kind)),
    );
    attributes.insert(
        "trace.correlation.confidence".to_string(),
        serde_json::json!(confidence_name(confidence)),
    );
    attributes
}

fn append_process_attributes(
    attributes: &mut BTreeMap<String, serde_json::Value>,
    process: Option<&NetworkProcessIdentity>,
) {
    if let Some(process) = process {
        attributes.insert("process.pid".to_string(), serde_json::json!(process.pid));
        if let Some(ppid) = process.ppid {
            attributes.insert("process.parent_pid".to_string(), serde_json::json!(ppid));
        }
        if let Some(uid) = process.uid {
            attributes.insert("process.owner.id".to_string(), serde_json::json!(uid));
        }
        attributes.insert(
            "process.command".to_string(),
            bounded_json_string(&process.command),
        );
    }
}

fn append_endpoint_attributes(
    attributes: &mut BTreeMap<String, serde_json::Value>,
    prefix: &str,
    endpoint: &DependencyEndpoint,
) {
    if let Some(owner_name) = &endpoint.owner_name {
        insert_string_attribute(
            attributes,
            format!("{prefix}.k8s.workload.name"),
            owner_name,
        );
    }
    if let Some(owner_type) = &endpoint.owner_type {
        insert_string_attribute(
            attributes,
            format!("{prefix}.k8s.workload.type"),
            owner_type,
        );
    }
    if let Some(address) = &endpoint.address {
        insert_string_attribute(attributes, format!("{prefix}.address"), address);
    }
    if let Some(port) = endpoint.port {
        attributes.insert(format!("{prefix}.port"), serde_json::json!(port));
    }
    if let Some(domain) = &endpoint.domain {
        insert_string_attribute(attributes, "dns.question.name", domain);
    }
    if let Some(workload) = &endpoint.workload {
        append_workload_attributes(attributes, prefix, workload);
    }
    if let Some(container) = &endpoint.container {
        append_container_attributes(attributes, prefix, container);
    }
}

fn append_peer_attributes(
    attributes: &mut BTreeMap<String, serde_json::Value>,
    peer: Option<&TracePeerContext>,
) {
    append_peer_endpoint_attributes(attributes, "server", peer);
}

fn append_request_peer_attributes(
    attributes: &mut BTreeMap<String, serde_json::Value>,
    span: &RequestSpanObservation,
) {
    let is_server_capture = span.attributes.iter().any(|attribute| {
        attribute.key == PROTOCOL_CAPTURE_ROLE_ATTRIBUTE && attribute.value == "server"
    });
    if !is_server_capture {
        append_peer_attributes(attributes, span.peer.as_ref());
        return;
    }

    append_peer_endpoint_attributes(attributes, "client", span.peer.as_ref());
    if let Some(peer) = span.peer.as_ref() {
        if let Some(address) = &peer.address {
            insert_string_attribute(attributes, "network.peer.address", address);
        }
        if let Some(port) = peer.port {
            attributes.insert("network.peer.port".to_string(), serde_json::json!(port));
        }
    }
}

fn append_peer_endpoint_attributes(
    attributes: &mut BTreeMap<String, serde_json::Value>,
    prefix: &str,
    peer: Option<&TracePeerContext>,
) {
    if let Some(peer) = peer {
        if let Some(address) = &peer.address {
            insert_string_attribute(attributes, format!("{prefix}.address"), address);
        }
        if let Some(port) = peer.port {
            attributes.insert(format!("{prefix}.port"), serde_json::json!(port));
        }
        if let Some(domain) = &peer.domain {
            insert_string_attribute(attributes, "dns.question.name", domain);
        }
        if let Some(workload) = &peer.workload {
            append_workload_attributes(attributes, prefix, workload);
        }
        if let Some(container) = &peer.container {
            append_container_attributes(attributes, prefix, container);
        }
    }
}

fn append_workload_attributes(
    attributes: &mut BTreeMap<String, serde_json::Value>,
    prefix: &str,
    workload: &KubernetesContext,
) {
    insert_string_attribute(
        attributes,
        format!("{prefix}.k8s.namespace.name"),
        &workload.namespace,
    );
    insert_string_attribute(
        attributes,
        format!("{prefix}.k8s.pod.name"),
        &workload.pod_name,
    );
    if let Some(pod_uid) = &workload.pod_uid {
        insert_string_attribute(attributes, format!("{prefix}.k8s.pod.uid"), pod_uid);
    }
    if let Some(container_name) = &workload.container_name {
        insert_string_attribute(
            attributes,
            format!("{prefix}.k8s.container.name"),
            container_name,
        );
    }
}

fn append_container_attributes(
    attributes: &mut BTreeMap<String, serde_json::Value>,
    prefix: &str,
    container: &ContainerContext,
) {
    insert_string_attribute(
        attributes,
        format!("{prefix}.container.id"),
        &container.container_id,
    );
    if let Some(runtime) = &container.runtime {
        insert_string_attribute(attributes, format!("{prefix}.container.runtime"), runtime);
    }
}

fn insert_string_attribute(
    attributes: &mut BTreeMap<String, serde_json::Value>,
    key: impl Into<String>,
    value: &str,
) {
    attributes.insert(key.into(), bounded_json_string(value));
}

fn append_trace_attributes(
    attributes: &mut BTreeMap<String, serde_json::Value>,
    source: &[TraceAttribute],
) {
    let mut accepted = 0;
    for attribute in source {
        if accepted >= MAX_FORMATTED_TRACE_ATTRIBUTES {
            break;
        }
        if !trace_attribute_allowed(attribute, attributes) {
            continue;
        }
        attributes.insert(
            attribute.key.clone(),
            serde_json::json!(attribute.value.clone()),
        );
        accepted += 1;
    }
}

fn append_profiling_attributes(
    attributes: &mut BTreeMap<String, serde_json::Value>,
    source: &[ProfilingAttribute],
) {
    let mut accepted = 0;
    for attribute in source {
        if accepted >= MAX_FORMATTED_TRACE_ATTRIBUTES
            || attributes.len() >= MAX_FORMATTED_TRACE_ATTRIBUTES
        {
            break;
        }
        if !profiling_attribute_allowed(attribute, attributes) {
            continue;
        }
        attributes.insert(
            attribute.key.clone(),
            serde_json::json!(attribute.value.clone()),
        );
        accepted += 1;
    }
}

fn trace_attribute_allowed(
    attribute: &TraceAttribute,
    existing: &BTreeMap<String, serde_json::Value>,
) -> bool {
    if attribute.key.is_empty()
        || attribute.key.len() > MAX_TRACE_ATTRIBUTE_KEY_BYTES
        || attribute.value.len() > MAX_TRACE_ATTRIBUTE_VALUE_BYTES
        || existing.contains_key(&attribute.key)
    {
        return false;
    }

    let key = attribute.key.to_ascii_lowercase();
    ![
        "password",
        "passwd",
        "secret",
        "token",
        "authorization",
        "cookie",
    ]
    .iter()
    .any(|sensitive| key.contains(sensitive))
}

fn profiling_attribute_allowed(
    attribute: &ProfilingAttribute,
    existing: &BTreeMap<String, serde_json::Value>,
) -> bool {
    if attribute.key.is_empty()
        || attribute.key.len() > MAX_TRACE_ATTRIBUTE_KEY_BYTES
        || attribute.value.len() > MAX_TRACE_ATTRIBUTE_VALUE_BYTES
        || existing.contains_key(&attribute.key)
    {
        return false;
    }

    let key = attribute.key.to_ascii_lowercase();
    ![
        "password",
        "passwd",
        "secret",
        "token",
        "authorization",
        "cookie",
        "api_key",
        "apikey",
        "credential",
    ]
    .iter()
    .any(|sensitive| key.contains(sensitive))
}

fn protocol_name(protocol: NetworkProtocol) -> &'static str {
    match protocol {
        NetworkProtocol::Tcp => "tcp",
        NetworkProtocol::Udp => "udp",
        _ => "other",
    }
}

fn protocol_kind_name(protocol: ProtocolKind) -> &'static str {
    match protocol {
        ProtocolKind::Http => "http",
        ProtocolKind::Grpc => "grpc",
        ProtocolKind::Kafka => "kafka",
        ProtocolKind::Mongodb => "mongodb",
        ProtocolKind::Mysql => "mysql",
        ProtocolKind::Nats => "nats",
        ProtocolKind::Postgresql => "postgresql",
        ProtocolKind::Redis => "redis",
        ProtocolKind::Websocket => "websocket",
        ProtocolKind::Unknown => "unknown",
        _ => "other",
    }
}

fn address_family_name(address_family: NetworkAddressFamily) -> &'static str {
    match address_family {
        NetworkAddressFamily::Ipv4 => "ipv4",
        NetworkAddressFamily::Ipv6 => "ipv6",
        _ => "other",
    }
}

fn profiling_kind_name(kind: ProfilingKind) -> &'static str {
    match kind {
        ProfilingKind::Cpu => "cpu",
        ProfilingKind::Memory => "memory",
        ProfilingKind::Lock => "lock",
        ProfilingKind::Unknown => "unknown",
        _ => "unknown",
    }
}

fn profiling_correlation_kind_name(kind: ProfilingCorrelationKind) -> &'static str {
    match kind {
        ProfilingCorrelationKind::ObservedProfileSample => "observed_profile_sample",
        ProfilingCorrelationKind::Synthetic => "synthetic",
        ProfilingCorrelationKind::RuntimeInferred => "runtime_inferred",
        _ => "unknown",
    }
}

fn profiling_confidence_name(kind: ProfilingConfidence) -> &'static str {
    match kind {
        ProfilingConfidence::Low => "low",
        ProfilingConfidence::Medium => "medium",
        ProfilingConfidence::High => "high",
        _ => "unknown",
    }
}

fn correlation_kind_name(kind: TraceCorrelationKind) -> &'static str {
    match kind {
        TraceCorrelationKind::ObservedTraceContext => "observed_trace_context",
        TraceCorrelationKind::GeneratedTraceContext => "generated_trace_context",
        TraceCorrelationKind::ProtocolObserved => "protocol_observed",
        TraceCorrelationKind::NetworkInferred => "network_inferred",
        TraceCorrelationKind::DependencyInferred => "dependency_inferred",
        TraceCorrelationKind::Synthetic => "synthetic",
        _ => "other",
    }
}

fn confidence_name(confidence: TraceConfidence) -> &'static str {
    match confidence {
        TraceConfidence::Low => "low",
        TraceConfidence::Medium => "medium",
        TraceConfidence::High => "high",
        _ => "other",
    }
}
