use e_navigator_signals::{
    ContainerContext, DependencyEndpoint, KubernetesContext, NetworkProcessIdentity,
    NetworkProtocol, ProtocolKind, RequestCorrelationWarning, RequestSpanObservation,
    ServiceInteractionSpanObservation, SignalEnvelope, TraceAttribute, TraceConfidence,
    TraceCorrelationKind, TraceCorrelationWarning, TracePeerContext, TraceServicePathObservation,
    TraceSpanObservation,
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
            attributes: vec![
                TraceAttribute {
                    key: "net.transport".to_string(),
                    value: "tcp".to_string(),
                },
                TraceAttribute {
                    key: "trace.correlation.kind".to_string(),
                    value: "overridden".to_string(),
                },
                TraceAttribute {
                    key: "auth.token".to_string(),
                    value: "sensitive".to_string(),
                },
                TraceAttribute {
                    key: "custom.too_large".to_string(),
                    value: "x".repeat(257),
                },
            ],
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
    assert_eq!(record.resource["k8s.namespace.name"], "default");
    assert_eq!(record.resource["k8s.pod.name"], "api-123");
    assert_eq!(record.resource["k8s.deployment.name"], "api");
    assert_eq!(record.attributes["trace.correlation.kind"], "synthetic");
    assert_eq!(record.attributes["trace.correlation.confidence"], "high");
    assert_eq!(record.attributes["net.transport"], "tcp");
    assert!(!record.attributes.contains_key("auth.token"));
    assert!(!record.attributes.contains_key("custom.too_large"));
    assert_eq!(record.attributes["server.address"], "203.0.113.10");
    assert_eq!(record.attributes["server.port"], 443);
    assert_eq!(record.attributes["server.k8s.namespace.name"], "default");
    assert_eq!(record.attributes["server.k8s.pod.name"], "api-123");
    assert_eq!(record.attributes["server.container.id"], "container-a");
    assert_eq!(record.attributes["process.pid"], 42);
}

#[test]
fn formats_service_interaction_without_inventing_trace_ids() {
    let signal = SignalEnvelope::service_interaction_span_observation(
        "generator.trace_correlation",
        Some("node-a".to_string()),
        ServiceInteractionSpanObservation {
            name: "tcp client".to_string(),
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
            path_key: "trace-path:0123456789abcdef".to_string(),
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
        "trace-path:0123456789abcdef"
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
    assert_eq!(
        warning_record.attributes["server.k8s.namespace.name"],
        "default"
    );
    assert_eq!(warning_record.attributes["server.k8s.pod.name"], "api-123");
    assert_eq!(
        warning_record.attributes["server.container.id"],
        "container-a"
    );
}

#[test]
fn formats_request_span_with_bounded_stable_attributes() {
    let signal = SignalEnvelope::request_span_observation(
        "generator.request_correlation",
        Some("node-a".to_string()),
        RequestSpanObservation {
            name: "http request".to_string(),
            protocol: ProtocolKind::Http,
            trace_id: Some("4bf92f3577b34da6a3ce929d0e0e4736".to_string()),
            span_id: Some("00f067aa0ba902b7".to_string()),
            parent_span_id: Some("7c0ffee000000001".to_string()),
            start_unix_nanos: 1_000,
            end_unix_nanos: Some(2_000),
            duration_nanos: Some(1_000),
            correlation_kind: TraceCorrelationKind::ObservedTraceContext,
            confidence: TraceConfidence::High,
            service_name: Some("checkout-api".to_string()),
            method: Some("GET".to_string()),
            status_code: Some(200),
            process: Some(network_process()),
            container: Some(container_context()),
            kubernetes: Some(kubernetes_context()),
            peer: Some(trace_peer_context()),
            attributes: vec![
                TraceAttribute {
                    key: "http.request.method".to_string(),
                    value: "POST".to_string(),
                },
                TraceAttribute {
                    key: "authorization".to_string(),
                    value: "secret".to_string(),
                },
                TraceAttribute {
                    key: "custom.value".to_string(),
                    value: "kept".to_string(),
                },
            ],
        },
    );

    let record = format_otel_trace_record(&signal).expect("request span formats");

    assert_eq!(record.name, "http request");
    assert_eq!(record.kind, OtelTraceRecordKind::RequestSpan);
    assert_eq!(
        record.trace_id,
        Some("4bf92f3577b34da6a3ce929d0e0e4736".to_string())
    );
    assert_eq!(record.span_id, Some("00f067aa0ba902b7".to_string()));
    assert_eq!(record.parent_span_id, Some("7c0ffee000000001".to_string()));
    assert_eq!(record.start_unix_nanos, 1_000);
    assert_eq!(record.end_unix_nanos, Some(2_000));
    assert_eq!(record.duration_nanos, Some(1_000));
    assert_eq!(record.resource["service.name"], "checkout-api");
    assert_eq!(
        record.attributes["trace.correlation.kind"],
        "observed_trace_context"
    );
    assert_eq!(record.attributes["trace.correlation.confidence"], "high");
    assert_eq!(record.attributes["network.protocol.name"], "http");
    assert_eq!(record.attributes["http.request.method"], "GET");
    assert_eq!(record.attributes["http.response.status_code"], 200);
    assert_eq!(record.attributes["custom.value"], "kept");
    assert!(!record.attributes.contains_key("authorization"));
}

#[test]
fn formats_request_correlation_warning() {
    let signal = SignalEnvelope::request_correlation_warning(
        "generator.request_correlation",
        Some("node-a".to_string()),
        RequestCorrelationWarning {
            warning_type: "missing_trace_context".to_string(),
            message: "protocol request had no observed trace context".to_string(),
            timestamp_unix_nanos: 1_500,
            source_signal_kind: "protocol_request_observation".to_string(),
            source_module: "source.protocol_fixture".to_string(),
            correlation_kind: TraceCorrelationKind::ProtocolObserved,
            protocol: ProtocolKind::Http,
            process: Some(network_process()),
            container: Some(container_context()),
            kubernetes: Some(kubernetes_context()),
            peer: Some(trace_peer_context()),
        },
    );

    let record = format_otel_trace_record(&signal).expect("request warning formats");

    assert_eq!(record.kind, OtelTraceRecordKind::RequestWarning);
    assert_eq!(record.name, "request.correlation.warning");
    assert_eq!(record.attributes["warning.type"], "missing_trace_context");
    assert_eq!(
        record.attributes["trace.source.signal.kind"],
        "protocol_request_observation"
    );
    assert_eq!(record.attributes["network.protocol.name"], "http");
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
        workload: Some(kubernetes_context()),
        container: Some(container_context()),
    }
}

fn network_process() -> NetworkProcessIdentity {
    NetworkProcessIdentity {
        pid: 42,
        ppid: Some(1),
        uid: Some(1000),
        command: "api".to_string(),
        executable: Some("/app/api".to_string()),
        cgroup_id: None,
    }
}

fn container_context() -> ContainerContext {
    ContainerContext {
        container_id: "container-a".to_string(),
        runtime: Some("containerd".to_string()),
    }
}

fn kubernetes_context() -> KubernetesContext {
    let mut labels = BTreeMap::new();
    labels.insert("app.kubernetes.io/name".to_string(), "api".to_string());

    KubernetesContext {
        namespace: "default".to_string(),
        pod_name: "api-123".to_string(),
        pod_uid: Some("pod-uid".to_string()),
        container_name: Some("api".to_string()),
        node_name: Some("node-a".to_string()),
        labels,
    }
}
