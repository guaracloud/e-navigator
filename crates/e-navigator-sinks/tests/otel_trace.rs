use e_navigator_signals::{
    ContainerContext, DependencyEndpoint, KubernetesContext, NetworkProcessIdentity,
    NetworkProtocol, ServiceInteractionSpanObservation, SignalEnvelope, TraceAttribute,
    TraceConfidence, TraceCorrelationKind, TraceCorrelationWarning, TracePeerContext,
    TraceServicePathObservation, TraceSpanObservation,
};
use e_navigator_sinks::{OtelTraceRecordKind, format_otel_trace_record};
use std::collections::BTreeMap;

#[test]
fn formats_trace_span_observation_as_stable_internal_trace_record() {
    let signal = SignalEnvelope::trace_span_observation(
        "source.synthetic_exec",
        Some("node-a".to_string()),
        TraceSpanObservation {
            name: "synthetic checkout".to_string(),
            trace_id: Some("4bf92f3577b34da6a3ce929d0e0e4736".to_string()),
            span_id: Some("00f067aa0ba902b7".to_string()),
            parent_span_id: None,
            start_unix_nanos: 1_000,
            end_unix_nanos: Some(2_000),
            duration_nanos: Some(1_000),
            correlation_kind: TraceCorrelationKind::Synthetic,
            confidence: TraceConfidence::High,
            service_name: Some("checkout-api".to_string()),
            process: Some(network_process()),
            container: Some(container_context()),
            kubernetes: Some(kubernetes_context()),
            peer: Some(trace_peer_context()),
            attributes: vec![TraceAttribute {
                key: "net.transport".to_string(),
                value: "tcp".to_string(),
            }],
        },
    );

    let record = format_otel_trace_record(&signal).expect("trace signal formats");

    assert_eq!(record.name, "synthetic checkout");
    assert_eq!(record.kind, OtelTraceRecordKind::Span);
    assert_eq!(
        record.trace_id,
        Some("4bf92f3577b34da6a3ce929d0e0e4736".to_string())
    );
    assert_eq!(record.span_id, Some("00f067aa0ba902b7".to_string()));
    assert_eq!(record.resource["host.name"], "node-a");
    assert_eq!(record.resource["service.name"], "checkout-api");
    assert_eq!(record.attributes["trace.correlation.kind"], "synthetic");
    assert_eq!(record.attributes["trace.correlation.confidence"], "high");
    assert_eq!(record.attributes["server.address"], "203.0.113.10");
    assert_eq!(record.attributes["server.port"], 443);
    assert_eq!(record.attributes["process.pid"], 42);
}

#[test]
fn formats_service_interaction_without_inventing_trace_ids() {
    let signal = SignalEnvelope::service_interaction_span_observation(
        "generator.trace_correlation",
        Some("node-a".to_string()),
        ServiceInteractionSpanObservation {
            name: "tcp client 203.0.113.10:443".to_string(),
            trace_id: None,
            span_id: None,
            parent_span_id: None,
            start_unix_nanos: 1_000,
            end_unix_nanos: Some(2_000),
            duration_nanos: Some(1_000),
            correlation_kind: TraceCorrelationKind::NetworkInferred,
            confidence: TraceConfidence::Medium,
            source: source_endpoint(),
            destination: destination_endpoint(),
            protocol: NetworkProtocol::Tcp,
            process: Some(network_process()),
            error_type: None,
            attributes: vec![],
        },
    );

    let record = format_otel_trace_record(&signal).expect("trace signal formats");

    assert_eq!(record.kind, OtelTraceRecordKind::ServiceInteraction);
    assert_eq!(record.trace_id, None);
    assert_eq!(record.span_id, None);
    assert_eq!(record.attributes["net.transport"], "tcp");
    assert_eq!(record.attributes["server.address"], "203.0.113.10");
    assert_eq!(record.attributes["server.port"], 443);
}

#[test]
fn formats_service_path_and_warning_trace_foundation_records() {
    let path = SignalEnvelope::trace_service_path_observation(
        "generator.trace_correlation",
        Some("node-a".to_string()),
        TraceServicePathObservation {
            path_key: "default/api-123/api->api.example.com:unknown/udp".to_string(),
            source: source_endpoint(),
            destination: DependencyEndpoint {
                workload: None,
                container: None,
                address: None,
                port: None,
                domain: Some("api.example.com".to_string()),
            },
            protocol: NetworkProtocol::Udp,
            observations: 2,
            first_seen_unix_nanos: 1_000,
            last_seen_unix_nanos: 2_000,
            correlation_kind: TraceCorrelationKind::DependencyInferred,
            confidence: TraceConfidence::Low,
            attributes: vec![],
        },
    );
    let warning = SignalEnvelope::trace_correlation_warning(
        "generator.trace_correlation",
        Some("node-a".to_string()),
        TraceCorrelationWarning {
            warning_type: "missing_attribution".to_string(),
            message: "trace correlation source signal has no container or Kubernetes context"
                .to_string(),
            timestamp_unix_nanos: 1_500,
            source_signal_kind: "network_connection_close".to_string(),
            source_module: "source.test".to_string(),
            correlation_kind: TraceCorrelationKind::NetworkInferred,
            process: None,
            container: None,
            kubernetes: None,
            peer: Some(trace_peer_context()),
        },
    );

    let path_record = format_otel_trace_record(&path).expect("path formats");
    let warning_record = format_otel_trace_record(&warning).expect("warning formats");

    assert_eq!(path_record.kind, OtelTraceRecordKind::ServicePath);
    assert_eq!(path_record.name, "trace.service.path");
    assert_eq!(
        path_record.attributes["trace.service.path.key"],
        "default/api-123/api->api.example.com:unknown/udp"
    );
    assert_eq!(
        path_record.attributes["dns.question.name"],
        "api.example.com"
    );
    assert_eq!(warning_record.kind, OtelTraceRecordKind::CorrelationWarning);
    assert_eq!(warning_record.name, "trace.correlation.warning");
    assert_eq!(
        warning_record.attributes["warning.type"],
        "missing_attribution"
    );
    assert_eq!(
        warning_record.attributes["trace.source.signal.kind"],
        "network_connection_close"
    );
}

#[test]
fn ignores_non_trace_signals() {
    let signal = SignalEnvelope::dependency_edge(
        "generator.dependency_graph",
        None,
        e_navigator_signals::DependencyEdgeEvent {
            source: source_endpoint(),
            destination: destination_endpoint(),
            protocol: NetworkProtocol::Tcp,
            observations: 1,
            first_seen_unix_nanos: 1_000,
            last_seen_unix_nanos: 1_000,
        },
    );

    assert_eq!(format_otel_trace_record(&signal), None);
}

fn source_endpoint() -> DependencyEndpoint {
    DependencyEndpoint {
        workload: Some(kubernetes_context()),
        container: Some(container_context()),
        address: Some("10.0.0.5".to_string()),
        port: Some(43512),
        domain: None,
    }
}

fn destination_endpoint() -> DependencyEndpoint {
    DependencyEndpoint {
        workload: None,
        container: None,
        address: Some("203.0.113.10".to_string()),
        port: Some(443),
        domain: None,
    }
}

fn trace_peer_context() -> TracePeerContext {
    TracePeerContext {
        address: Some("203.0.113.10".to_string()),
        port: Some(443),
        domain: None,
        workload: None,
        container: None,
    }
}

fn network_process() -> NetworkProcessIdentity {
    NetworkProcessIdentity {
        pid: 42,
        ppid: Some(1),
        uid: Some(1000),
        command: "api".to_string(),
        executable: Some("/app/api".to_string()),
    }
}

fn container_context() -> ContainerContext {
    ContainerContext {
        container_id: "container-a".to_string(),
        runtime: Some("containerd".to_string()),
    }
}

fn kubernetes_context() -> KubernetesContext {
    KubernetesContext {
        namespace: "default".to_string(),
        pod_name: "api-123".to_string(),
        pod_uid: Some("pod-uid".to_string()),
        container_name: Some("api".to_string()),
        node_name: Some("node-a".to_string()),
        labels: BTreeMap::new(),
    }
}
