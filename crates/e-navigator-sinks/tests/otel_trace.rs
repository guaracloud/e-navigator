use e_navigator_signals::{
    ContainerContext, DependencyEndpoint, KubernetesContext, NetworkAddressFamily,
    NetworkFlowWarning, NetworkProcessIdentity, NetworkProtocol, ProfilingAttribute,
    ProfilingConfidence, ProfilingCorrelationKind, ProfilingKind, ProfilingWarningObservation,
    ProtocolKind, RequestCorrelationWarning, RequestSpanObservation,
    ServiceInteractionSpanObservation, SignalEnvelope, TraceAttribute, TraceConfidence,
    TraceCorrelationKind, TraceCorrelationWarning, TracePeerContext, TraceServicePathObservation,
    TraceSpanObservation,
};
use e_navigator_sinks::{OtelSpanStatus, OtelTraceRecordKind, format_otel_trace_record};
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
    assert_eq!(record.status, None);
    assert_eq!(record.trace_id, None);
    assert_eq!(record.span_id, None);
    assert_eq!(record.attributes["net.transport"], "tcp");
    assert_eq!(record.attributes["server.address"], "203.0.113.10");
    assert_eq!(record.attributes["server.port"], 443);
}

#[test]
fn formats_service_interaction_error_status() {
    let signal = SignalEnvelope::service_interaction_span_observation(
        "generator.trace_correlation",
        Some("node-a".to_string()),
        ServiceInteractionSpanObservation {
            name: "tcp client".to_string(),
            trace_id: Some("4bf92f3577b34da6a3ce929d0e0e4736".to_string()),
            span_id: Some("00f067aa0ba902b7".to_string()),
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
            error_type: Some("connection_refused".to_string()),
            attributes: vec![],
        },
    );

    let record = format_otel_trace_record(&signal).expect("trace signal formats");

    assert_eq!(
        record.status,
        Some(OtelSpanStatus::Error {
            message: "connection_refused".to_string()
        })
    );
    assert_eq!(record.attributes["error.type"], "connection_refused");
}

#[test]
fn bounds_trace_record_name_and_status_message() {
    const MAX_VALUE_BYTES: usize = 256;

    let long_value = "e".repeat(MAX_VALUE_BYTES + 64);
    let signal = SignalEnvelope::service_interaction_span_observation(
        "generator.trace_correlation",
        Some("node-a".to_string()),
        ServiceInteractionSpanObservation {
            name: long_value.clone(),
            trace_id: Some("4bf92f3577b34da6a3ce929d0e0e4736".to_string()),
            span_id: Some("00f067aa0ba902b7".to_string()),
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
            error_type: Some(long_value),
            attributes: vec![],
        },
    );

    let record = format_otel_trace_record(&signal).expect("trace signal formats");

    assert_eq!(record.name.len(), MAX_VALUE_BYTES);
    assert_eq!(
        record.attributes["error.type"].as_str().map(str::len),
        Some(MAX_VALUE_BYTES)
    );
    assert_eq!(
        record.status,
        Some(OtelSpanStatus::Error {
            message: "e".repeat(MAX_VALUE_BYTES)
        })
    );
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
fn bounds_trace_service_path_key() {
    const MAX_VALUE_BYTES: usize = 256;

    let signal = SignalEnvelope::trace_service_path_observation(
        "generator.trace_correlation",
        Some("node-a".to_string()),
        TraceServicePathObservation {
            path_key: "p".repeat(MAX_VALUE_BYTES + 64),
            source: source_endpoint(),
            destination: destination_endpoint(),
            protocol: NetworkProtocol::Tcp,
            first_seen_unix_nanos: 1_000,
            last_seen_unix_nanos: 2_500,
            observations: 3,
            correlation_kind: TraceCorrelationKind::NetworkInferred,
            confidence: TraceConfidence::Medium,
            attributes: vec![],
        },
    );

    let record = format_otel_trace_record(&signal).expect("service path formats");

    assert_eq!(
        record.attributes["trace.service.path.key"]
            .as_str()
            .map(str::len),
        Some(MAX_VALUE_BYTES)
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
    assert_eq!(record.status, None);
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
fn bounds_trace_resource_attributes() {
    const MAX_VALUE_BYTES: usize = 256;

    let long_value = "r".repeat(MAX_VALUE_BYTES + 64);
    let mut kubernetes = kubernetes_context();
    kubernetes.namespace = long_value.clone();
    kubernetes.pod_name = long_value.clone();
    kubernetes.pod_uid = Some(long_value.clone());
    kubernetes.container_name = Some(long_value.clone());
    kubernetes.node_name = Some(long_value.clone());
    kubernetes
        .labels
        .insert("app.kubernetes.io/name".to_string(), long_value.clone());
    let container = ContainerContext {
        container_id: long_value.clone(),
        runtime: Some(long_value.clone()),
    };
    let signal = SignalEnvelope::request_span_observation(
        "generator.request_correlation",
        Some(long_value.clone()),
        RequestSpanObservation {
            name: "http request".to_string(),
            protocol: ProtocolKind::Http,
            trace_id: Some("4bf92f3577b34da6a3ce929d0e0e4736".to_string()),
            span_id: Some("00f067aa0ba902b7".to_string()),
            parent_span_id: None,
            start_unix_nanos: 1_000,
            end_unix_nanos: Some(2_000),
            duration_nanos: Some(1_000),
            correlation_kind: TraceCorrelationKind::ObservedTraceContext,
            confidence: TraceConfidence::High,
            service_name: Some(long_value),
            method: Some("GET".to_string()),
            status_code: Some(200),
            process: Some(network_process()),
            container: Some(container),
            kubernetes: Some(kubernetes),
            peer: None,
            attributes: vec![],
        },
    );

    let record = format_otel_trace_record(&signal).expect("request span formats");

    for key in [
        "host.name",
        "service.name",
        "container.id",
        "container.runtime",
        "k8s.namespace.name",
        "k8s.pod.name",
        "k8s.pod.uid",
        "k8s.container.name",
        "k8s.node.name",
        "k8s.deployment.name",
    ] {
        assert_eq!(
            record.resource[key].as_str().map(str::len),
            Some(MAX_VALUE_BYTES)
        );
    }
}

#[test]
fn bounds_trace_context_attributes() {
    const MAX_VALUE_BYTES: usize = 256;

    let long_value = "c".repeat(MAX_VALUE_BYTES + 64);
    let mut process = network_process();
    process.command = long_value.clone();
    let mut workload = kubernetes_context();
    workload.namespace = long_value.clone();
    workload.pod_name = long_value.clone();
    workload.pod_uid = Some(long_value.clone());
    workload.container_name = Some(long_value.clone());
    let container = ContainerContext {
        container_id: long_value.clone(),
        runtime: Some(long_value.clone()),
    };
    let peer = TracePeerContext {
        address: Some(long_value.clone()),
        port: Some(443),
        domain: Some(long_value.clone()),
        workload: Some(workload),
        container: Some(container),
    };
    let signal = SignalEnvelope::request_span_observation(
        "generator.request_correlation",
        Some("node-a".to_string()),
        RequestSpanObservation {
            name: "http request".to_string(),
            protocol: ProtocolKind::Http,
            trace_id: Some("4bf92f3577b34da6a3ce929d0e0e4736".to_string()),
            span_id: Some("00f067aa0ba902b7".to_string()),
            parent_span_id: None,
            start_unix_nanos: 1_000,
            end_unix_nanos: Some(2_000),
            duration_nanos: Some(1_000),
            correlation_kind: TraceCorrelationKind::ObservedTraceContext,
            confidence: TraceConfidence::High,
            service_name: Some("checkout-api".to_string()),
            method: Some(long_value.clone()),
            status_code: Some(200),
            process: Some(process),
            container: Some(container_context()),
            kubernetes: Some(kubernetes_context()),
            peer: Some(peer),
            attributes: vec![],
        },
    );

    let record = format_otel_trace_record(&signal).expect("request span formats");

    for key in [
        "process.command",
        "server.address",
        "dns.question.name",
        "server.k8s.namespace.name",
        "server.k8s.pod.name",
        "server.k8s.pod.uid",
        "server.k8s.container.name",
        "server.container.id",
        "server.container.runtime",
        "http.request.method",
    ] {
        assert_eq!(
            record.attributes[key].as_str().map(str::len),
            Some(MAX_VALUE_BYTES)
        );
    }
}

#[test]
fn formats_http_request_span_error_status_from_status_code() {
    let signal = SignalEnvelope::request_span_observation(
        "generator.request_correlation",
        Some("node-a".to_string()),
        RequestSpanObservation {
            name: "http request".to_string(),
            protocol: ProtocolKind::Http,
            trace_id: Some("4bf92f3577b34da6a3ce929d0e0e4736".to_string()),
            span_id: Some("00f067aa0ba902b7".to_string()),
            parent_span_id: None,
            start_unix_nanos: 1_000,
            end_unix_nanos: Some(2_000),
            duration_nanos: Some(1_000),
            correlation_kind: TraceCorrelationKind::ObservedTraceContext,
            confidence: TraceConfidence::High,
            service_name: Some("checkout-api".to_string()),
            method: Some("GET".to_string()),
            status_code: Some(503),
            process: Some(network_process()),
            container: Some(container_context()),
            kubernetes: Some(kubernetes_context()),
            peer: Some(trace_peer_context()),
            attributes: vec![],
        },
    );

    let record = format_otel_trace_record(&signal).expect("request span formats");

    assert_eq!(
        record.status,
        Some(OtelSpanStatus::Error {
            message: "HTTP status code 503".to_string()
        })
    );
    assert_eq!(record.attributes["http.response.status_code"], 503);
}

#[test]
fn formats_grpc_request_span_error_status_from_grpc_status_code() {
    let signal = SignalEnvelope::request_span_observation(
        "generator.request_correlation",
        Some("node-a".to_string()),
        RequestSpanObservation {
            name: "grpc request".to_string(),
            protocol: ProtocolKind::Grpc,
            trace_id: Some("4bf92f3577b34da6a3ce929d0e0e4736".to_string()),
            span_id: Some("00f067aa0ba902b7".to_string()),
            parent_span_id: None,
            start_unix_nanos: 1_000,
            end_unix_nanos: Some(2_000),
            duration_nanos: Some(1_000),
            correlation_kind: TraceCorrelationKind::ObservedTraceContext,
            confidence: TraceConfidence::High,
            service_name: Some("checkout-api".to_string()),
            method: Some("GetCart".to_string()),
            status_code: Some(13),
            process: Some(network_process()),
            container: Some(container_context()),
            kubernetes: Some(kubernetes_context()),
            peer: Some(trace_peer_context()),
            attributes: vec![TraceAttribute {
                key: "rpc.system".to_string(),
                value: "grpc".to_string(),
            }],
        },
    );

    let record = format_otel_trace_record(&signal).expect("grpc request span formats");

    assert_eq!(
        record.status,
        Some(OtelSpanStatus::Error {
            message: "gRPC status code 13 (internal)".to_string()
        })
    );
    assert_eq!(record.attributes["network.protocol.name"], "grpc");
    assert_eq!(record.attributes["rpc.grpc.status_code"], 13);
    assert!(!record.attributes.contains_key("http.response.status_code"));
}

#[test]
fn formats_grpc_ok_status_without_error_status() {
    let signal = SignalEnvelope::request_span_observation(
        "generator.request_correlation",
        Some("node-a".to_string()),
        RequestSpanObservation {
            name: "grpc request".to_string(),
            protocol: ProtocolKind::Grpc,
            trace_id: Some("4bf92f3577b34da6a3ce929d0e0e4736".to_string()),
            span_id: Some("00f067aa0ba902b7".to_string()),
            parent_span_id: None,
            start_unix_nanos: 1_000,
            end_unix_nanos: Some(2_000),
            duration_nanos: Some(1_000),
            correlation_kind: TraceCorrelationKind::ObservedTraceContext,
            confidence: TraceConfidence::High,
            service_name: Some("checkout-api".to_string()),
            method: Some("GetCart".to_string()),
            status_code: Some(0),
            process: Some(network_process()),
            container: Some(container_context()),
            kubernetes: Some(kubernetes_context()),
            peer: Some(trace_peer_context()),
            attributes: vec![],
        },
    );

    let record = format_otel_trace_record(&signal).expect("grpc request span formats");

    assert_eq!(record.status, None);
    assert_eq!(record.attributes["rpc.grpc.status_code"], 0);
    assert!(!record.attributes.contains_key("http.response.status_code"));
}

#[test]
fn formats_redis_request_span_with_protocol_name() {
    let signal = SignalEnvelope::request_span_observation(
        "generator.request_correlation",
        Some("node-a".to_string()),
        RequestSpanObservation {
            name: "redis command".to_string(),
            protocol: ProtocolKind::Redis,
            trace_id: None,
            span_id: None,
            parent_span_id: None,
            start_unix_nanos: 1_000,
            end_unix_nanos: Some(1_500),
            duration_nanos: Some(500),
            correlation_kind: TraceCorrelationKind::ProtocolObserved,
            confidence: TraceConfidence::Medium,
            service_name: Some("cache-client".to_string()),
            method: Some("GET".to_string()),
            status_code: None,
            process: Some(network_process()),
            container: Some(container_context()),
            kubernetes: Some(kubernetes_context()),
            peer: Some(trace_peer_context()),
            attributes: vec![
                TraceAttribute {
                    key: "db.system".to_string(),
                    value: "redis".to_string(),
                },
                TraceAttribute {
                    key: "db.operation".to_string(),
                    value: "GET".to_string(),
                },
            ],
        },
    );

    let record = format_otel_trace_record(&signal).expect("redis request span formats");

    assert_eq!(record.name, "redis command");
    assert_eq!(record.attributes["network.protocol.name"], "redis");
    assert_eq!(record.attributes["db.system"], "redis");
    assert_eq!(record.attributes["db.operation"], "GET");
}

#[test]
fn formats_redis_request_span_error_status_from_error_type_attribute() {
    let signal = SignalEnvelope::request_span_observation(
        "generator.request_correlation",
        Some("node-a".to_string()),
        RequestSpanObservation {
            name: "redis command".to_string(),
            protocol: ProtocolKind::Redis,
            trace_id: Some("4bf92f3577b34da6a3ce929d0e0e4736".to_string()),
            span_id: Some("00f067aa0ba902b7".to_string()),
            parent_span_id: None,
            start_unix_nanos: 1_000,
            end_unix_nanos: Some(1_500),
            duration_nanos: Some(500),
            correlation_kind: TraceCorrelationKind::ObservedTraceContext,
            confidence: TraceConfidence::High,
            service_name: Some("cache-client".to_string()),
            method: Some("GET".to_string()),
            status_code: None,
            process: Some(network_process()),
            container: Some(container_context()),
            kubernetes: Some(kubernetes_context()),
            peer: Some(trace_peer_context()),
            attributes: vec![
                TraceAttribute {
                    key: "db.system".to_string(),
                    value: "redis".to_string(),
                },
                TraceAttribute {
                    key: "db.response.status_code".to_string(),
                    value: "WRONGTYPE".to_string(),
                },
                TraceAttribute {
                    key: "error.type".to_string(),
                    value: "redis_wrongtype".to_string(),
                },
            ],
        },
    );

    let record = format_otel_trace_record(&signal).expect("redis request span formats");

    assert_eq!(
        record.status,
        Some(OtelSpanStatus::Error {
            message: "redis_wrongtype".to_string()
        })
    );
    assert_eq!(record.attributes["network.protocol.name"], "redis");
    assert_eq!(record.attributes["db.response.status_code"], "WRONGTYPE");
    assert_eq!(record.attributes["error.type"], "redis_wrongtype");
}

#[test]
fn ignores_oversized_request_error_type_for_status() {
    let signal = SignalEnvelope::request_span_observation(
        "generator.request_correlation",
        Some("node-a".to_string()),
        RequestSpanObservation {
            name: "redis command".to_string(),
            protocol: ProtocolKind::Redis,
            trace_id: Some("4bf92f3577b34da6a3ce929d0e0e4736".to_string()),
            span_id: Some("00f067aa0ba902b7".to_string()),
            parent_span_id: None,
            start_unix_nanos: 1_000,
            end_unix_nanos: Some(1_500),
            duration_nanos: Some(500),
            correlation_kind: TraceCorrelationKind::ObservedTraceContext,
            confidence: TraceConfidence::High,
            service_name: Some("cache-client".to_string()),
            method: Some("GET".to_string()),
            status_code: None,
            process: Some(network_process()),
            container: Some(container_context()),
            kubernetes: Some(kubernetes_context()),
            peer: Some(trace_peer_context()),
            attributes: vec![TraceAttribute {
                key: "error.type".to_string(),
                value: "x".repeat(257),
            }],
        },
    );

    let record = format_otel_trace_record(&signal).expect("redis request span formats");

    assert_eq!(record.status, None);
    assert!(!record.attributes.contains_key("error.type"));
}

#[test]
fn formats_grpc_request_span_with_protocol_name() {
    let signal = SignalEnvelope::request_span_observation(
        "generator.request_correlation",
        Some("node-a".to_string()),
        RequestSpanObservation {
            name: "grpc request".to_string(),
            protocol: ProtocolKind::Grpc,
            trace_id: None,
            span_id: None,
            parent_span_id: None,
            start_unix_nanos: 1_000,
            end_unix_nanos: Some(1_500),
            duration_nanos: Some(500),
            correlation_kind: TraceCorrelationKind::ProtocolObserved,
            confidence: TraceConfidence::Medium,
            service_name: Some("checkout-client".to_string()),
            method: Some("GetCart".to_string()),
            status_code: None,
            process: Some(network_process()),
            container: Some(container_context()),
            kubernetes: Some(kubernetes_context()),
            peer: Some(trace_peer_context()),
            attributes: vec![
                TraceAttribute {
                    key: "rpc.system".to_string(),
                    value: "grpc".to_string(),
                },
                TraceAttribute {
                    key: "rpc.service".to_string(),
                    value: "checkout.v1.CheckoutService".to_string(),
                },
                TraceAttribute {
                    key: "rpc.method".to_string(),
                    value: "GetCart".to_string(),
                },
            ],
        },
    );

    let record = format_otel_trace_record(&signal).expect("grpc request span formats");

    assert_eq!(record.name, "grpc request");
    assert_eq!(record.attributes["network.protocol.name"], "grpc");
    assert_eq!(record.attributes["rpc.system"], "grpc");
    assert_eq!(
        record.attributes["rpc.service"],
        "checkout.v1.CheckoutService"
    );
    assert_eq!(record.attributes["rpc.method"], "GetCart");
}

#[test]
fn formats_postgresql_request_span_with_protocol_name() {
    let signal = SignalEnvelope::request_span_observation(
        "generator.request_correlation",
        Some("node-a".to_string()),
        RequestSpanObservation {
            name: "postgresql query".to_string(),
            protocol: ProtocolKind::Postgresql,
            trace_id: None,
            span_id: None,
            parent_span_id: None,
            start_unix_nanos: 1_000,
            end_unix_nanos: Some(1_500),
            duration_nanos: Some(500),
            correlation_kind: TraceCorrelationKind::ProtocolObserved,
            confidence: TraceConfidence::Medium,
            service_name: Some("database-client".to_string()),
            method: Some("SELECT".to_string()),
            status_code: None,
            process: Some(network_process()),
            container: Some(container_context()),
            kubernetes: Some(kubernetes_context()),
            peer: Some(trace_peer_context()),
            attributes: vec![
                TraceAttribute {
                    key: "db.system".to_string(),
                    value: "postgresql".to_string(),
                },
                TraceAttribute {
                    key: "db.operation".to_string(),
                    value: "SELECT".to_string(),
                },
            ],
        },
    );

    let record = format_otel_trace_record(&signal).expect("postgresql request span formats");

    assert_eq!(record.name, "postgresql query");
    assert_eq!(record.attributes["network.protocol.name"], "postgresql");
    assert_eq!(record.attributes["db.system"], "postgresql");
    assert_eq!(record.attributes["db.operation"], "SELECT");
}

#[test]
fn formats_mysql_request_span_with_protocol_name() {
    let signal = SignalEnvelope::request_span_observation(
        "generator.request_correlation",
        Some("node-a".to_string()),
        RequestSpanObservation {
            name: "mysql query".to_string(),
            protocol: ProtocolKind::Mysql,
            trace_id: None,
            span_id: None,
            parent_span_id: None,
            start_unix_nanos: 1_000,
            end_unix_nanos: Some(1_500),
            duration_nanos: Some(500),
            correlation_kind: TraceCorrelationKind::ProtocolObserved,
            confidence: TraceConfidence::Medium,
            service_name: Some("database-client".to_string()),
            method: Some("SELECT".to_string()),
            status_code: None,
            process: Some(network_process()),
            container: Some(container_context()),
            kubernetes: Some(kubernetes_context()),
            peer: Some(trace_peer_context()),
            attributes: vec![
                TraceAttribute {
                    key: "db.system".to_string(),
                    value: "mysql".to_string(),
                },
                TraceAttribute {
                    key: "db.operation".to_string(),
                    value: "SELECT".to_string(),
                },
            ],
        },
    );

    let record = format_otel_trace_record(&signal).expect("mysql request span formats");

    assert_eq!(record.name, "mysql query");
    assert_eq!(record.attributes["network.protocol.name"], "mysql");
    assert_eq!(record.attributes["db.system"], "mysql");
    assert_eq!(record.attributes["db.operation"], "SELECT");
}

#[test]
fn formats_mongodb_request_span_with_protocol_name() {
    let signal = SignalEnvelope::request_span_observation(
        "generator.request_correlation",
        Some("node-a".to_string()),
        RequestSpanObservation {
            name: "mongodb command".to_string(),
            protocol: ProtocolKind::Mongodb,
            trace_id: None,
            span_id: None,
            parent_span_id: None,
            start_unix_nanos: 1_000,
            end_unix_nanos: Some(1_500),
            duration_nanos: Some(500),
            correlation_kind: TraceCorrelationKind::ProtocolObserved,
            confidence: TraceConfidence::Medium,
            service_name: Some("database-client".to_string()),
            method: Some("find".to_string()),
            status_code: None,
            process: Some(network_process()),
            container: Some(container_context()),
            kubernetes: Some(kubernetes_context()),
            peer: Some(trace_peer_context()),
            attributes: vec![
                TraceAttribute {
                    key: "db.system".to_string(),
                    value: "mongodb".to_string(),
                },
                TraceAttribute {
                    key: "db.operation".to_string(),
                    value: "find".to_string(),
                },
            ],
        },
    );

    let record = format_otel_trace_record(&signal).expect("mongodb request span formats");

    assert_eq!(record.name, "mongodb command");
    assert_eq!(record.attributes["network.protocol.name"], "mongodb");
    assert_eq!(record.attributes["db.system"], "mongodb");
    assert_eq!(record.attributes["db.operation"], "find");
}

#[test]
fn formats_mongodb_request_span_error_status_from_error_type_attribute() {
    let signal = SignalEnvelope::request_span_observation(
        "generator.request_correlation",
        Some("node-a".to_string()),
        RequestSpanObservation {
            name: "mongodb command".to_string(),
            protocol: ProtocolKind::Mongodb,
            trace_id: Some("4bf92f3577b34da6a3ce929d0e0e4736".to_string()),
            span_id: Some("00f067aa0ba902b7".to_string()),
            parent_span_id: None,
            start_unix_nanos: 1_000,
            end_unix_nanos: Some(1_500),
            duration_nanos: Some(500),
            correlation_kind: TraceCorrelationKind::ObservedTraceContext,
            confidence: TraceConfidence::High,
            service_name: Some("database-client".to_string()),
            method: Some("find".to_string()),
            status_code: None,
            process: Some(network_process()),
            container: Some(container_context()),
            kubernetes: Some(kubernetes_context()),
            peer: Some(trace_peer_context()),
            attributes: vec![
                TraceAttribute {
                    key: "db.system".to_string(),
                    value: "mongodb".to_string(),
                },
                TraceAttribute {
                    key: "db.response.status_code".to_string(),
                    value: "13".to_string(),
                },
                TraceAttribute {
                    key: "error.type".to_string(),
                    value: "13".to_string(),
                },
            ],
        },
    );

    let record = format_otel_trace_record(&signal).expect("mongodb request span formats");

    assert_eq!(
        record.status,
        Some(OtelSpanStatus::Error {
            message: "13".to_string()
        })
    );
    assert_eq!(record.attributes["network.protocol.name"], "mongodb");
    assert_eq!(record.attributes["db.response.status_code"], "13");
    assert_eq!(record.attributes["error.type"], "13");
}

#[test]
fn formats_kafka_request_span_with_protocol_name() {
    let signal = SignalEnvelope::request_span_observation(
        "generator.request_correlation",
        Some("node-a".to_string()),
        RequestSpanObservation {
            name: "kafka request".to_string(),
            protocol: ProtocolKind::Kafka,
            trace_id: None,
            span_id: None,
            parent_span_id: None,
            start_unix_nanos: 1_000,
            end_unix_nanos: Some(1_500),
            duration_nanos: Some(500),
            correlation_kind: TraceCorrelationKind::ProtocolObserved,
            confidence: TraceConfidence::Medium,
            service_name: Some("messaging-client".to_string()),
            method: Some("produce".to_string()),
            status_code: None,
            process: Some(network_process()),
            container: Some(container_context()),
            kubernetes: Some(kubernetes_context()),
            peer: Some(trace_peer_context()),
            attributes: vec![
                TraceAttribute {
                    key: "messaging.system".to_string(),
                    value: "kafka".to_string(),
                },
                TraceAttribute {
                    key: "messaging.operation".to_string(),
                    value: "produce".to_string(),
                },
            ],
        },
    );

    let record = format_otel_trace_record(&signal).expect("kafka request span formats");

    assert_eq!(record.name, "kafka request");
    assert_eq!(record.attributes["network.protocol.name"], "kafka");
    assert_eq!(record.attributes["messaging.system"], "kafka");
    assert_eq!(record.attributes["messaging.operation"], "produce");
}

#[test]
fn formats_kafka_request_span_error_status_from_error_type_attribute() {
    let signal = SignalEnvelope::request_span_observation(
        "generator.request_correlation",
        Some("node-a".to_string()),
        RequestSpanObservation {
            name: "kafka request".to_string(),
            protocol: ProtocolKind::Kafka,
            trace_id: Some("4bf92f3577b34da6a3ce929d0e0e4736".to_string()),
            span_id: Some("00f067aa0ba902b7".to_string()),
            parent_span_id: None,
            start_unix_nanos: 1_000,
            end_unix_nanos: Some(1_500),
            duration_nanos: Some(500),
            correlation_kind: TraceCorrelationKind::ObservedTraceContext,
            confidence: TraceConfidence::High,
            service_name: Some("messaging-client".to_string()),
            method: Some("api_versions".to_string()),
            status_code: None,
            process: Some(network_process()),
            container: Some(container_context()),
            kubernetes: Some(kubernetes_context()),
            peer: Some(trace_peer_context()),
            attributes: vec![
                TraceAttribute {
                    key: "messaging.system".to_string(),
                    value: "kafka".to_string(),
                },
                TraceAttribute {
                    key: "messaging.kafka.response.error_code".to_string(),
                    value: "35".to_string(),
                },
                TraceAttribute {
                    key: "error.type".to_string(),
                    value: "35".to_string(),
                },
            ],
        },
    );

    let record = format_otel_trace_record(&signal).expect("kafka request span formats");

    assert_eq!(
        record.status,
        Some(OtelSpanStatus::Error {
            message: "35".to_string()
        })
    );
    assert_eq!(record.attributes["network.protocol.name"], "kafka");
    assert_eq!(
        record.attributes["messaging.kafka.response.error_code"],
        "35"
    );
    assert_eq!(record.attributes["error.type"], "35");
}

#[test]
fn formats_nats_request_span_with_protocol_name() {
    let signal = SignalEnvelope::request_span_observation(
        "generator.request_correlation",
        Some("node-a".to_string()),
        RequestSpanObservation {
            name: "nats message".to_string(),
            protocol: ProtocolKind::Nats,
            trace_id: None,
            span_id: None,
            parent_span_id: None,
            start_unix_nanos: 1_000,
            end_unix_nanos: Some(1_500),
            duration_nanos: Some(500),
            correlation_kind: TraceCorrelationKind::ProtocolObserved,
            confidence: TraceConfidence::Medium,
            service_name: Some("messaging-client".to_string()),
            method: Some("pub".to_string()),
            status_code: None,
            process: Some(network_process()),
            container: Some(container_context()),
            kubernetes: Some(kubernetes_context()),
            peer: Some(trace_peer_context()),
            attributes: vec![
                TraceAttribute {
                    key: "messaging.system".to_string(),
                    value: "nats".to_string(),
                },
                TraceAttribute {
                    key: "messaging.operation".to_string(),
                    value: "pub".to_string(),
                },
            ],
        },
    );

    let record = format_otel_trace_record(&signal).expect("nats request span formats");

    assert_eq!(record.name, "nats message");
    assert_eq!(record.attributes["network.protocol.name"], "nats");
    assert_eq!(record.attributes["messaging.system"], "nats");
    assert_eq!(record.attributes["messaging.operation"], "pub");
}

#[test]
fn formats_nats_request_span_error_status_from_error_type_attribute() {
    let signal = SignalEnvelope::request_span_observation(
        "generator.request_correlation",
        Some("node-a".to_string()),
        RequestSpanObservation {
            name: "nats message".to_string(),
            protocol: ProtocolKind::Nats,
            trace_id: Some("4bf92f3577b34da6a3ce929d0e0e4736".to_string()),
            span_id: Some("00f067aa0ba902b7".to_string()),
            parent_span_id: None,
            start_unix_nanos: 1_000,
            end_unix_nanos: Some(1_500),
            duration_nanos: Some(500),
            correlation_kind: TraceCorrelationKind::ObservedTraceContext,
            confidence: TraceConfidence::High,
            service_name: Some("messaging-client".to_string()),
            method: Some("pub".to_string()),
            status_code: None,
            process: Some(network_process()),
            container: Some(container_context()),
            kubernetes: Some(kubernetes_context()),
            peer: Some(trace_peer_context()),
            attributes: vec![
                TraceAttribute {
                    key: "messaging.system".to_string(),
                    value: "nats".to_string(),
                },
                TraceAttribute {
                    key: "messaging.nats.status_code".to_string(),
                    value: "ERR".to_string(),
                },
                TraceAttribute {
                    key: "error.type".to_string(),
                    value: "nats_error".to_string(),
                },
            ],
        },
    );

    let record = format_otel_trace_record(&signal).expect("nats request span formats");

    assert_eq!(
        record.status,
        Some(OtelSpanStatus::Error {
            message: "nats_error".to_string()
        })
    );
    assert_eq!(record.attributes["network.protocol.name"], "nats");
    assert_eq!(record.attributes["messaging.nats.status_code"], "ERR");
    assert_eq!(record.attributes["error.type"], "nats_error");
}

#[test]
fn formats_request_span_error_status_from_response_status_without_error_type() {
    for (protocol, name, method, key, value) in [
        (
            ProtocolKind::Redis,
            "redis command",
            "GET",
            "db.response.status_code",
            "WRONGTYPE",
        ),
        (
            ProtocolKind::Kafka,
            "kafka request",
            "produce",
            "messaging.kafka.response.error_code",
            "6",
        ),
        (
            ProtocolKind::Nats,
            "nats message",
            "pub",
            "messaging.nats.status_code",
            "ERR",
        ),
    ] {
        let signal = request_span_signal(
            protocol,
            name,
            method,
            vec![TraceAttribute {
                key: key.to_string(),
                value: value.to_string(),
            }],
        );

        let record = format_otel_trace_record(&signal).expect("request span formats");

        assert_eq!(
            record.status,
            Some(OtelSpanStatus::Error {
                message: value.to_string()
            }),
            "{key}"
        );
        assert_eq!(record.attributes[key], value);
        assert!(!record.attributes.contains_key("error.type"));
    }
}

#[test]
fn formats_ok_response_status_attributes_without_error_status() {
    for (protocol, name, method, key, value) in [
        (
            ProtocolKind::Redis,
            "redis command",
            "GET",
            "db.response.status_code",
            "OK",
        ),
        (
            ProtocolKind::Mongodb,
            "mongodb command",
            "find",
            "db.response.status_code",
            "1",
        ),
        (
            ProtocolKind::Kafka,
            "kafka request",
            "produce",
            "messaging.kafka.response.error_code",
            "0",
        ),
        (
            ProtocolKind::Nats,
            "nats message",
            "pub",
            "messaging.nats.status_code",
            "OK",
        ),
    ] {
        let signal = request_span_signal(
            protocol,
            name,
            method,
            vec![TraceAttribute {
                key: key.to_string(),
                value: value.to_string(),
            }],
        );

        let record = format_otel_trace_record(&signal).expect("request span formats");

        assert_eq!(record.status, None, "{key}");
        assert_eq!(record.attributes[key], value);
    }
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
fn bounds_trace_warning_attributes() {
    const MAX_VALUE_BYTES: usize = 256;

    let long_value = "w".repeat(MAX_VALUE_BYTES + 64);
    let signal = SignalEnvelope::request_correlation_warning(
        "generator.request_correlation",
        Some("node-a".to_string()),
        RequestCorrelationWarning {
            warning_type: long_value.clone(),
            message: long_value.clone(),
            timestamp_unix_nanos: 1_500,
            source_signal_kind: long_value.clone(),
            source_module: long_value,
            correlation_kind: TraceCorrelationKind::ProtocolObserved,
            protocol: ProtocolKind::Http,
            process: Some(network_process()),
            container: Some(container_context()),
            kubernetes: Some(kubernetes_context()),
            peer: None,
        },
    );

    let record = format_otel_trace_record(&signal).expect("request warning formats");

    for key in [
        "warning.type",
        "warning.message",
        "trace.source.signal.kind",
        "trace.source.module",
    ] {
        assert_eq!(
            record.attributes[key].as_str().map(str::len),
            Some(MAX_VALUE_BYTES)
        );
    }
}

#[test]
fn formats_network_flow_warning_without_inventing_trace_ids() {
    let signal = SignalEnvelope::network_flow_warning(
        "generator.network_metrics",
        Some("node-a".to_string()),
        NetworkFlowWarning {
            warning_type: "missing_attribution".to_string(),
            message: "network flow has byte counters but incomplete source attribution".to_string(),
            timestamp_unix_nanos: 1_500,
            source_signal_kind: "network_connection_close".to_string(),
            source_module: "source.synthetic_network".to_string(),
            protocol: NetworkProtocol::Tcp,
            address_family: NetworkAddressFamily::Ipv4,
            remote_address: "198.51.100.30".to_string(),
            remote_port: 9443,
            process: network_process(),
            container: None,
            kubernetes: Some(kubernetes_context()),
        },
    );

    let record = format_otel_trace_record(&signal).expect("network flow warning formats");

    assert_eq!(record.kind, OtelTraceRecordKind::NetworkFlowWarning);
    assert_eq!(record.name, "network.flow.warning");
    assert_eq!(record.trace_id, None);
    assert_eq!(record.span_id, None);
    assert_eq!(record.parent_span_id, None);
    assert_eq!(record.start_unix_nanos, 1_500);
    assert_eq!(record.end_unix_nanos, Some(1_500));
    assert_eq!(record.duration_nanos, Some(0));
    assert_eq!(record.resource["host.name"], "node-a");
    assert_eq!(record.resource["k8s.namespace.name"], "default");
    assert_eq!(record.attributes["warning.type"], "missing_attribution");
    assert_eq!(
        record.attributes["trace.source.signal.kind"],
        "network_connection_close"
    );
    assert_eq!(record.attributes["network.protocol.name"], "tcp");
    assert_eq!(record.attributes["network.address.family"], "ipv4");
    assert_eq!(record.attributes["server.address"], "198.51.100.30");
    assert_eq!(record.attributes["server.port"], 9443);
    assert_eq!(record.attributes["process.pid"], 42);
    assert_eq!(record.attributes["process.command"], "api");
    assert!(!record.attributes.contains_key("process.executable.path"));
}

#[test]
fn formats_profiling_warning_without_inventing_trace_ids() {
    let signal = SignalEnvelope::profiling_warning_observation(
        "generator.profiling",
        Some("node-a".to_string()),
        ProfilingWarningObservation {
            warning_type: "dropped_profile_samples".to_string(),
            message: "profile samples were dropped by bounded aggregation".to_string(),
            timestamp_unix_nanos: 1_500,
            source_signal_kind: "profile_sample_observation".to_string(),
            source_module: "source.aya_cpu_profile".to_string(),
            profiling_kind: ProfilingKind::Cpu,
            correlation_kind: ProfilingCorrelationKind::ObservedProfileSample,
            confidence: ProfilingConfidence::Medium,
            process: Some(network_process()),
            container: Some(container_context()),
            kubernetes: Some(kubernetes_context()),
            attributes: vec![
                ProfilingAttribute {
                    key: "profile.dropped_sample_count".to_string(),
                    value: "12".to_string(),
                },
                ProfilingAttribute {
                    key: "warning.type".to_string(),
                    value: "evil".to_string(),
                },
                ProfilingAttribute {
                    key: "authorization".to_string(),
                    value: "Bearer token".to_string(),
                },
            ],
        },
    );

    let record = format_otel_trace_record(&signal).expect("profiling warning formats");

    assert_eq!(record.kind, OtelTraceRecordKind::ProfilingWarning);
    assert_eq!(record.name, "profiling.warning");
    assert_eq!(record.trace_id, None);
    assert_eq!(record.span_id, None);
    assert_eq!(record.parent_span_id, None);
    assert_eq!(record.start_unix_nanos, 1_500);
    assert_eq!(record.end_unix_nanos, Some(1_500));
    assert_eq!(record.duration_nanos, Some(0));
    assert_eq!(record.resource["host.name"], "node-a");
    assert_eq!(record.resource["k8s.namespace.name"], "default");
    assert_eq!(record.attributes["warning.type"], "dropped_profile_samples");
    assert_eq!(
        record.attributes["trace.source.signal.kind"],
        "profile_sample_observation"
    );
    assert_eq!(
        record.attributes["trace.source.module"],
        "source.aya_cpu_profile"
    );
    assert_eq!(record.attributes["profile.kind"], "cpu");
    assert_eq!(
        record.attributes["profile.correlation.kind"],
        "observed_profile_sample"
    );
    assert_eq!(record.attributes["profile.confidence"], "medium");
    assert_eq!(record.attributes["profile.dropped_sample_count"], "12");
    assert_eq!(record.attributes["process.pid"], 42);
    assert_eq!(record.attributes["process.command"], "api");
    assert!(!record.attributes.contains_key("authorization"));
    assert_eq!(record.attributes["warning.type"], "dropped_profile_samples");
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

fn request_span_signal(
    protocol: ProtocolKind,
    name: &str,
    method: &str,
    attributes: Vec<TraceAttribute>,
) -> SignalEnvelope {
    SignalEnvelope::request_span_observation(
        "generator.request_correlation",
        Some("node-a".to_string()),
        RequestSpanObservation {
            name: name.to_string(),
            protocol,
            trace_id: Some("4bf92f3577b34da6a3ce929d0e0e4736".to_string()),
            span_id: Some("00f067aa0ba902b7".to_string()),
            parent_span_id: None,
            start_unix_nanos: 1_000,
            end_unix_nanos: Some(1_500),
            duration_nanos: Some(500),
            correlation_kind: TraceCorrelationKind::ObservedTraceContext,
            confidence: TraceConfidence::High,
            service_name: Some("service-a".to_string()),
            method: Some(method.to_string()),
            status_code: None,
            process: Some(network_process()),
            container: Some(container_context()),
            kubernetes: Some(kubernetes_context()),
            peer: Some(trace_peer_context()),
            attributes,
        },
    )
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
