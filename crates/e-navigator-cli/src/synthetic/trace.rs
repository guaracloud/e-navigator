use e_navigator_signals::{
    ContainerContext, KubernetesContext, SignalEnvelope, TraceAttribute, TraceConfidence,
    TraceCorrelationKind, TracePeerContext, TraceSpanObservation,
};

pub(super) fn span_signal(
    host: Option<String>,
    container: ContainerContext,
    kubernetes: KubernetesContext,
    opened_at: u64,
    duration_nanos: u64,
) -> SignalEnvelope {
    SignalEnvelope::trace_span_observation(
        super::source_name(),
        host,
        TraceSpanObservation {
            name: "synthetic checkout".to_string(),
            trace_id: Some("4bf92f3577b34da6a3ce929d0e0e4736".to_string()),
            span_id: Some("00f067aa0ba902b7".to_string()),
            parent_span_id: None,
            start_unix_nanos: opened_at,
            end_unix_nanos: Some(opened_at.saturating_add(duration_nanos)),
            duration_nanos: Some(duration_nanos),
            correlation_kind: TraceCorrelationKind::Synthetic,
            confidence: TraceConfidence::High,
            service_name: Some("synthetic-api".to_string()),
            process: Some(super::process_identity()),
            container: Some(container),
            kubernetes: Some(kubernetes),
            peer: Some(TracePeerContext {
                address: Some("203.0.113.10".to_string()),
                port: Some(443),
                domain: Some("api.example.com".to_string()),
                workload: None,
                container: None,
            }),
            attributes: vec![TraceAttribute {
                key: "trace.synthetic.fixture".to_string(),
                value: "true_trace_context".to_string(),
            }],
        },
    )
}
