use e_navigator_signals::{
    ContainerContext, DependencyEndpoint, KubernetesContext, NetworkProcessIdentity,
    NetworkProtocol, ProtocolKind, RequestCorrelationWarning, RequestSpanObservation,
    ServiceInteractionSpanObservation, SignalEnvelope, SignalPayload, TraceAttribute,
    TraceConfidence, TraceCorrelationKind, TraceCorrelationWarning, TracePeerContext,
    TraceServicePathObservation, TraceSpanObservation,
};
use serde::Serialize;
use std::collections::BTreeMap;

const MAX_FORMATTED_TRACE_ATTRIBUTES: usize = 16;
const MAX_TRACE_ATTRIBUTE_KEY_BYTES: usize = 128;
const MAX_TRACE_ATTRIBUTE_VALUE_BYTES: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OtelTraceRecordKind {
    Span,
    ServiceInteraction,
    ServicePath,
    CorrelationWarning,
    RequestSpan,
    RequestWarning,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OtelTraceRecord {
    pub name: String,
    pub kind: OtelTraceRecordKind,
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
        _ => None,
    }
}

fn trace_span_record(signal: &SignalEnvelope, span: &TraceSpanObservation) -> OtelTraceRecord {
    let mut resource = resource_attributes(
        signal,
        span.container.as_ref(),
        span.kubernetes.as_ref(),
        span.service_name.as_deref(),
    );
    if let Some(service_name) = &span.service_name {
        resource.insert("service.name".to_string(), serde_json::json!(service_name));
    }

    let mut attributes = correlation_attributes(span.correlation_kind, span.confidence);
    append_process_attributes(&mut attributes, span.process.as_ref());
    append_peer_attributes(&mut attributes, span.peer.as_ref());
    append_trace_attributes(&mut attributes, &span.attributes);

    OtelTraceRecord {
        name: span.name.clone(),
        kind: OtelTraceRecordKind::Span,
        trace_id: span.trace_id.clone(),
        span_id: span.span_id.clone(),
        parent_span_id: span.parent_span_id.clone(),
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
        attributes.insert("error.type".to_string(), serde_json::json!(error_type));
    }

    OtelTraceRecord {
        name: span.name.clone(),
        kind: OtelTraceRecordKind::ServiceInteraction,
        trace_id: span.trace_id.clone(),
        span_id: span.span_id.clone(),
        parent_span_id: span.parent_span_id.clone(),
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
        serde_json::json!(path.path_key),
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
        serde_json::json!(warning.warning_type),
    );
    attributes.insert(
        "warning.message".to_string(),
        serde_json::json!(warning.message),
    );
    attributes.insert(
        "trace.source.signal.kind".to_string(),
        serde_json::json!(warning.source_signal_kind),
    );
    attributes.insert(
        "trace.source.module".to_string(),
        serde_json::json!(warning.source_module),
    );
    append_process_attributes(&mut attributes, warning.process.as_ref());
    append_peer_attributes(&mut attributes, warning.peer.as_ref());

    OtelTraceRecord {
        name: "trace.correlation.warning".to_string(),
        kind: OtelTraceRecordKind::CorrelationWarning,
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
        attributes.insert("http.request.method".to_string(), serde_json::json!(method));
    }
    if let Some(status_code) = span.status_code {
        attributes.insert(
            "http.response.status_code".to_string(),
            serde_json::json!(status_code),
        );
    }
    append_process_attributes(&mut attributes, span.process.as_ref());
    append_peer_attributes(&mut attributes, span.peer.as_ref());
    append_trace_attributes(&mut attributes, &span.attributes);

    OtelTraceRecord {
        name: span.name.clone(),
        kind: OtelTraceRecordKind::RequestSpan,
        trace_id: span.trace_id.clone(),
        span_id: span.span_id.clone(),
        parent_span_id: span.parent_span_id.clone(),
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
        serde_json::json!(warning.warning_type),
    );
    attributes.insert(
        "warning.message".to_string(),
        serde_json::json!(warning.message),
    );
    attributes.insert(
        "trace.source.signal.kind".to_string(),
        serde_json::json!(warning.source_signal_kind),
    );
    attributes.insert(
        "trace.source.module".to_string(),
        serde_json::json!(warning.source_module),
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

fn resource_attributes(
    signal: &SignalEnvelope,
    container: Option<&ContainerContext>,
    kubernetes: Option<&KubernetesContext>,
    service_name: Option<&str>,
) -> BTreeMap<String, serde_json::Value> {
    let mut resource = BTreeMap::new();
    if let Some(host) = &signal.host {
        resource.insert("host.name".to_string(), serde_json::json!(host));
    }
    if let Some(service_name) = service_name {
        resource.insert("service.name".to_string(), serde_json::json!(service_name));
    }
    if let Some(container) = container {
        resource.insert(
            "container.id".to_string(),
            serde_json::json!(container.container_id),
        );
        if let Some(runtime) = &container.runtime {
            resource.insert("container.runtime".to_string(), serde_json::json!(runtime));
        }
    }
    if let Some(kubernetes) = kubernetes {
        resource.insert(
            "k8s.namespace.name".to_string(),
            serde_json::json!(kubernetes.namespace),
        );
        resource.insert(
            "k8s.pod.name".to_string(),
            serde_json::json!(kubernetes.pod_name),
        );
        if let Some(uid) = &kubernetes.pod_uid {
            resource.insert("k8s.pod.uid".to_string(), serde_json::json!(uid));
        }
        if let Some(container_name) = &kubernetes.container_name {
            resource.insert(
                "k8s.container.name".to_string(),
                serde_json::json!(container_name),
            );
        }
        if let Some(node_name) = &kubernetes.node_name {
            resource.insert("k8s.node.name".to_string(), serde_json::json!(node_name));
        }
        if let Some(deployment_name) = kubernetes
            .labels
            .get("app.kubernetes.io/name")
            .or_else(|| kubernetes.labels.get("app"))
            .filter(|name| !name.is_empty())
        {
            resource.insert(
                "k8s.deployment.name".to_string(),
                serde_json::json!(deployment_name),
            );
        }
    }
    resource
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
            serde_json::json!(process.command),
        );
    }
}

fn append_endpoint_attributes(
    attributes: &mut BTreeMap<String, serde_json::Value>,
    prefix: &str,
    endpoint: &DependencyEndpoint,
) {
    if let Some(address) = &endpoint.address {
        attributes.insert(format!("{prefix}.address"), serde_json::json!(address));
    }
    if let Some(port) = endpoint.port {
        attributes.insert(format!("{prefix}.port"), serde_json::json!(port));
    }
    if let Some(domain) = &endpoint.domain {
        attributes.insert("dns.question.name".to_string(), serde_json::json!(domain));
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
    if let Some(peer) = peer {
        if let Some(address) = &peer.address {
            attributes.insert("server.address".to_string(), serde_json::json!(address));
        }
        if let Some(port) = peer.port {
            attributes.insert("server.port".to_string(), serde_json::json!(port));
        }
        if let Some(domain) = &peer.domain {
            attributes.insert("dns.question.name".to_string(), serde_json::json!(domain));
        }
        if let Some(workload) = &peer.workload {
            append_workload_attributes(attributes, "server", workload);
        }
        if let Some(container) = &peer.container {
            append_container_attributes(attributes, "server", container);
        }
    }
}

fn append_workload_attributes(
    attributes: &mut BTreeMap<String, serde_json::Value>,
    prefix: &str,
    workload: &KubernetesContext,
) {
    attributes.insert(
        format!("{prefix}.k8s.namespace.name"),
        serde_json::json!(workload.namespace),
    );
    attributes.insert(
        format!("{prefix}.k8s.pod.name"),
        serde_json::json!(workload.pod_name),
    );
    if let Some(pod_uid) = &workload.pod_uid {
        attributes.insert(format!("{prefix}.k8s.pod.uid"), serde_json::json!(pod_uid));
    }
    if let Some(container_name) = &workload.container_name {
        attributes.insert(
            format!("{prefix}.k8s.container.name"),
            serde_json::json!(container_name),
        );
    }
}

fn append_container_attributes(
    attributes: &mut BTreeMap<String, serde_json::Value>,
    prefix: &str,
    container: &ContainerContext,
) {
    attributes.insert(
        format!("{prefix}.container.id"),
        serde_json::json!(container.container_id),
    );
    if let Some(runtime) = &container.runtime {
        attributes.insert(
            format!("{prefix}.container.runtime"),
            serde_json::json!(runtime),
        );
    }
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
        ProtocolKind::Mongodb => "mongodb",
        ProtocolKind::Mysql => "mysql",
        ProtocolKind::Postgresql => "postgresql",
        ProtocolKind::Redis => "redis",
        ProtocolKind::Unknown => "unknown",
        _ => "other",
    }
}

fn correlation_kind_name(kind: TraceCorrelationKind) -> &'static str {
    match kind {
        TraceCorrelationKind::ObservedTraceContext => "observed_trace_context",
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
