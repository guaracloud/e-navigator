use e_navigator_signals::{
    ContainerContext, KubernetesContext, ProtocolKind, ProtocolRequestObservation, SignalEnvelope,
    TraceAttribute, TraceConfidence, TraceCorrelationKind, TracePeerContext,
};

pub(super) fn signals(
    host: Option<String>,
    container: ContainerContext,
    kubernetes: KubernetesContext,
    started: u64,
    duration_nanos: u64,
) -> Vec<SignalEnvelope> {
    let process = super::process_identity();
    let peer = TracePeerContext {
        address: Some("203.0.113.10".to_string()),
        port: Some(443),
        domain: Some("api.example.com".to_string()),
        workload: None,
        container: None,
    };
    let traceparent = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";

    vec![
        SignalEnvelope::protocol_request_observation(
            super::source_name(),
            host.clone(),
            ProtocolRequestObservation {
                protocol: ProtocolKind::Http,
                start_unix_nanos: started,
                end_unix_nanos: Some(started.saturating_add(duration_nanos)),
                duration_nanos: Some(duration_nanos),
                trace_id: Some("4bf92f3577b34da6a3ce929d0e0e4736".to_string()),
                span_id: Some("00f067aa0ba902b7".to_string()),
                parent_span_id: None,
                traceparent: Some(traceparent.to_string()),
                tracestate: Some("synthetic=value".to_string()),
                correlation_kind: TraceCorrelationKind::Synthetic,
                confidence: TraceConfidence::High,
                service_name: Some("synthetic-api".to_string()),
                method: Some("GET".to_string()),
                status_code: Some(200),
                process: Some(process.clone()),
                container: Some(container.clone()),
                kubernetes: Some(kubernetes.clone()),
                peer: Some(peer.clone()),
                attributes: vec![TraceAttribute {
                    key: "trace.synthetic.fixture".to_string(),
                    value: "http_trace_context_request".to_string(),
                }],
            },
        ),
        SignalEnvelope::protocol_request_observation(
            super::source_name(),
            host.clone(),
            ProtocolRequestObservation {
                protocol: ProtocolKind::Http,
                start_unix_nanos: started.saturating_add(duration_nanos + 10_000),
                end_unix_nanos: Some(started.saturating_add(duration_nanos + 11_000)),
                duration_nanos: Some(1_000),
                trace_id: None,
                span_id: None,
                parent_span_id: None,
                traceparent: Some("00-bad".to_string()),
                tracestate: None,
                correlation_kind: TraceCorrelationKind::Synthetic,
                confidence: TraceConfidence::Low,
                service_name: Some("synthetic-api".to_string()),
                method: Some("GET".to_string()),
                status_code: None,
                process: Some(process.clone()),
                container: Some(container.clone()),
                kubernetes: Some(kubernetes.clone()),
                peer: Some(peer.clone()),
                attributes: vec![TraceAttribute {
                    key: "trace.synthetic.fixture".to_string(),
                    value: "malformed_trace_context_request".to_string(),
                }],
            },
        ),
        SignalEnvelope::protocol_request_observation(
            super::source_name(),
            host,
            ProtocolRequestObservation {
                protocol: ProtocolKind::Http,
                start_unix_nanos: started.saturating_add(duration_nanos + 20_000),
                end_unix_nanos: Some(started.saturating_add(duration_nanos + 21_000)),
                duration_nanos: Some(1_000),
                trace_id: None,
                span_id: None,
                parent_span_id: None,
                traceparent: None,
                tracestate: None,
                correlation_kind: TraceCorrelationKind::Synthetic,
                confidence: TraceConfidence::Low,
                service_name: Some("synthetic-api".to_string()),
                method: Some("POST".to_string()),
                status_code: None,
                process: Some(process),
                container: Some(container),
                kubernetes: Some(kubernetes),
                peer: Some(peer),
                attributes: vec![TraceAttribute {
                    key: "trace.synthetic.fixture".to_string(),
                    value: "missing_trace_context_request".to_string(),
                }],
            },
        ),
    ]
}
