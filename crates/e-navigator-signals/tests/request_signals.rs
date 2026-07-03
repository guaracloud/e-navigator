use e_navigator_core::Signal;
use e_navigator_signals::{
    ContainerContext, ExtractedTraceContextObservation, KubernetesContext, NetworkProcessIdentity,
    ProtocolKind, ProtocolRequestObservation, RequestCorrelationWarning, RequestSpanObservation,
    SignalEnvelope, SignalPayload, TraceAttribute, TraceConfidence, TraceCorrelationKind,
    TraceCorrelationWarning, TracePeerContext,
};
use proptest::prelude::*;
use std::collections::BTreeMap;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    #[test]
    fn constructed_request_envelopes_round_trip_without_changing_identity(
        source in "[a-z_\\.]{1,32}",
        host in prop::option::of("[a-z0-9.-]{1,32}"),
        method in prop::option::of("[A-Z-]{1,16}"),
    ) {
        let signal = SignalEnvelope::request_span_observation(
            source.clone(),
            host.clone(),
            RequestSpanObservation {
                name: "http request".to_string(),
                protocol: ProtocolKind::Http,
                trace_id: None,
                span_id: None,
                parent_span_id: None,
                start_unix_nanos: 1,
                end_unix_nanos: Some(2),
                duration_nanos: Some(1),
                correlation_kind: TraceCorrelationKind::ProtocolObserved,
                confidence: TraceConfidence::Medium,
                service_name: None,
                method,
                status_code: None,
                process: Some(process()),
                container: Some(container()),
                kubernetes: Some(kubernetes()),
                peer: Some(peer()),
                attributes: vec![],
            },
        );

        let json = serde_json::to_value(&signal).expect("serializes");
        let decoded: SignalEnvelope = serde_json::from_value(json).expect("deserializes");

        prop_assert_eq!(decoded.schema_version, signal.schema_version);
        prop_assert_eq!(decoded.kind(), signal.kind());
        prop_assert_eq!(decoded.source, source);
        prop_assert_eq!(decoded.host, host);
        prop_assert!(matches!(decoded.payload, SignalPayload::RequestSpanObservation(_)));
    }
}

#[test]
fn serializes_protocol_request_observation_with_explicit_context() {
    let signal = SignalEnvelope::protocol_request_observation(
        "source.protocol_fixture",
        Some("node-a".to_string()),
        ProtocolRequestObservation {
            protocol: ProtocolKind::Http,
            start_unix_nanos: 1_000,
            end_unix_nanos: Some(2_500),
            duration_nanos: Some(1_500),
            trace_id: Some("4bf92f3577b34da6a3ce929d0e0e4736".to_string()),
            span_id: Some("00f067aa0ba902b7".to_string()),
            parent_span_id: None,
            traceparent: Some(
                "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01".to_string(),
            ),
            tracestate: Some("vendor=value".to_string()),
            correlation_kind: TraceCorrelationKind::ProtocolObserved,
            confidence: TraceConfidence::High,
            service_name: Some("checkout-api".to_string()),
            method: Some("GET".to_string()),
            status_code: Some(200),
            process: Some(process()),
            container: Some(container()),
            kubernetes: Some(kubernetes()),
            peer: Some(peer()),
            attributes: vec![TraceAttribute {
                key: "http.request.method".to_string(),
                value: "GET".to_string(),
            }],
        },
    );

    let json = serde_json::to_value(&signal).expect("signal serializes");

    assert_eq!(json["schema_version"], 1);
    assert_eq!(json["kind"], "protocol_request_observation");
    assert_eq!(json["payload"]["protocol"], "http");
    assert_eq!(
        json["payload"]["trace_id"],
        "4bf92f3577b34da6a3ce929d0e0e4736"
    );
    assert!(json["payload"].get("traceparent").is_none());
    assert!(json["payload"].get("tracestate").is_none());
    assert_eq!(json["payload"]["correlation_kind"], "protocol_observed");
    assert_eq!(json["payload"]["method"], "GET");
    assert_eq!(json["payload"]["status_code"], 200);

    let decoded: SignalEnvelope = serde_json::from_value(json).expect("signal deserializes");
    assert!(matches!(
        decoded.payload,
        SignalPayload::ProtocolRequestObservation(_)
    ));
}

#[test]
fn serializes_redis_protocol_request_observation_without_payload_values() {
    let signal = SignalEnvelope::protocol_request_observation(
        "source.protocol_fixture",
        Some("node-a".to_string()),
        ProtocolRequestObservation {
            protocol: ProtocolKind::Redis,
            start_unix_nanos: 1_000,
            end_unix_nanos: None,
            duration_nanos: None,
            trace_id: None,
            span_id: None,
            parent_span_id: None,
            traceparent: None,
            tracestate: None,
            correlation_kind: TraceCorrelationKind::ProtocolObserved,
            confidence: TraceConfidence::Medium,
            service_name: Some("cache-client".to_string()),
            method: Some("GET".to_string()),
            status_code: None,
            process: Some(process()),
            container: Some(container()),
            kubernetes: Some(kubernetes()),
            peer: Some(peer()),
            attributes: vec![
                TraceAttribute {
                    key: "db.system".to_string(),
                    value: "redis".to_string(),
                },
                TraceAttribute {
                    key: "db.operation".to_string(),
                    value: "GET".to_string(),
                },
                TraceAttribute {
                    key: "db.redis.key_present".to_string(),
                    value: "true".to_string(),
                },
            ],
        },
    );

    let json = serde_json::to_value(&signal).expect("signal serializes");

    assert_eq!(json["payload"]["protocol"], "redis");
    assert_eq!(json["payload"]["method"], "GET");
    assert!(!json.to_string().contains("customer:pii"));

    let decoded: SignalEnvelope = serde_json::from_value(json).expect("signal deserializes");
    assert!(matches!(
        decoded.payload,
        SignalPayload::ProtocolRequestObservation(_)
    ));
}

#[test]
fn serializes_postgresql_protocol_request_observation_without_query_text() {
    let signal = SignalEnvelope::protocol_request_observation(
        "source.protocol_fixture",
        Some("node-a".to_string()),
        ProtocolRequestObservation {
            protocol: ProtocolKind::Postgresql,
            start_unix_nanos: 1_000,
            end_unix_nanos: None,
            duration_nanos: None,
            trace_id: None,
            span_id: None,
            parent_span_id: None,
            traceparent: None,
            tracestate: None,
            correlation_kind: TraceCorrelationKind::ProtocolObserved,
            confidence: TraceConfidence::Medium,
            service_name: Some("database-client".to_string()),
            method: Some("SELECT".to_string()),
            status_code: None,
            process: Some(process()),
            container: Some(container()),
            kubernetes: Some(kubernetes()),
            peer: Some(peer()),
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

    let json = serde_json::to_value(&signal).expect("signal serializes");

    assert_eq!(json["payload"]["protocol"], "postgresql");
    assert_eq!(json["payload"]["method"], "SELECT");
    assert!(!json.to_string().contains("where token"));

    let decoded: SignalEnvelope = serde_json::from_value(json).expect("signal deserializes");
    assert!(matches!(
        decoded.payload,
        SignalPayload::ProtocolRequestObservation(_)
    ));
}

#[test]
fn serializes_extracted_trace_context_observation() {
    let signal = SignalEnvelope::extracted_trace_context_observation(
        "parser.protocol",
        Some("node-a".to_string()),
        ExtractedTraceContextObservation {
            protocol: ProtocolKind::Http,
            timestamp_unix_nanos: 1_100,
            trace_id: Some("4bf92f3577b34da6a3ce929d0e0e4736".to_string()),
            span_id: Some("00f067aa0ba902b7".to_string()),
            parent_span_id: None,
            traceparent: Some(
                "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01".to_string(),
            ),
            tracestate: Some("vendor=value".to_string()),
            correlation_kind: TraceCorrelationKind::ObservedTraceContext,
            confidence: TraceConfidence::High,
            process: Some(process()),
            container: Some(container()),
            kubernetes: Some(kubernetes()),
            peer: Some(peer()),
            attributes: vec![],
        },
    );

    let json = serde_json::to_value(&signal).expect("signal serializes");

    assert_eq!(json["kind"], "extracted_trace_context_observation");
    assert_eq!(json["payload"]["protocol"], "http");
    assert_eq!(
        json["payload"]["trace_id"],
        "4bf92f3577b34da6a3ce929d0e0e4736"
    );
    assert!(json["payload"].get("traceparent").is_none());
    assert!(json["payload"].get("tracestate").is_none());

    let decoded: SignalEnvelope = serde_json::from_value(json).expect("signal deserializes");
    assert!(matches!(
        decoded.payload,
        SignalPayload::ExtractedTraceContextObservation(_)
    ));
}

#[test]
fn serializes_request_span_observation_without_inventing_context() {
    let signal = SignalEnvelope::request_span_observation(
        "generator.request_correlation",
        Some("node-a".to_string()),
        RequestSpanObservation {
            name: "http request".to_string(),
            protocol: ProtocolKind::Http,
            trace_id: None,
            span_id: None,
            parent_span_id: None,
            start_unix_nanos: 1_000,
            end_unix_nanos: Some(2_000),
            duration_nanos: Some(1_000),
            correlation_kind: TraceCorrelationKind::ProtocolObserved,
            confidence: TraceConfidence::Medium,
            service_name: None,
            method: Some("POST".to_string()),
            status_code: None,
            process: Some(process()),
            container: Some(container()),
            kubernetes: Some(kubernetes()),
            peer: Some(peer()),
            attributes: vec![],
        },
    );

    let json = serde_json::to_value(&signal).expect("signal serializes");

    assert_eq!(json["kind"], "request_span_observation");
    assert_eq!(json["payload"]["name"], "http request");
    assert_eq!(json["payload"]["trace_id"], serde_json::Value::Null);
    assert_eq!(json["payload"]["status_code"], serde_json::Value::Null);

    let decoded: SignalEnvelope = serde_json::from_value(json).expect("signal deserializes");
    assert!(matches!(
        decoded.payload,
        SignalPayload::RequestSpanObservation(_)
    ));
}

#[test]
fn serializes_request_correlation_warning() {
    let signal = SignalEnvelope::request_correlation_warning(
        "generator.request_correlation",
        Some("node-a".to_string()),
        RequestCorrelationWarning {
            warning_type: "missing_trace_context".to_string(),
            message: "protocol request had no observed trace context".to_string(),
            timestamp_unix_nanos: 2_000,
            source_signal_kind: "protocol_request_observation".to_string(),
            source_module: "source.protocol_fixture".to_string(),
            correlation_kind: TraceCorrelationKind::ProtocolObserved,
            protocol: ProtocolKind::Http,
            process: Some(process()),
            container: Some(container()),
            kubernetes: Some(kubernetes()),
            peer: Some(peer()),
        },
    );

    let json = serde_json::to_value(&signal).expect("signal serializes");

    assert_eq!(json["kind"], "request_correlation_warning");
    assert_eq!(json["payload"]["warning_type"], "missing_trace_context");
    assert_eq!(json["payload"]["protocol"], "http");

    let decoded: SignalEnvelope = serde_json::from_value(json).expect("signal deserializes");
    assert!(matches!(
        decoded.payload,
        SignalPayload::RequestCorrelationWarning(_)
    ));
}

#[test]
fn direct_signal_payload_deserialization_keeps_request_span_unambiguous() {
    let value = serde_json::json!({
        "name": "http request",
        "protocol": "http",
        "trace_id": null,
        "span_id": null,
        "parent_span_id": null,
        "start_unix_nanos": 1,
        "end_unix_nanos": 2,
        "duration_nanos": 1,
        "correlation_kind": "protocol_observed",
        "confidence": "medium",
        "service_name": null,
        "method": "GET",
        "status_code": 200,
        "process": null,
        "container": null,
        "kubernetes": null,
        "peer": null,
        "attributes": []
    });

    let payload: SignalPayload = serde_json::from_value(value).expect("payload deserializes");

    assert!(matches!(payload, SignalPayload::RequestSpanObservation(_)));
}

#[test]
fn direct_signal_payload_deserialization_keeps_warnings_unambiguous() {
    let trace_warning = serde_json::to_value(TraceCorrelationWarning {
        warning_type: "missing_attribution".to_string(),
        message: "trace correlation source signal has no container or Kubernetes context"
            .to_string(),
        timestamp_unix_nanos: 2_000,
        source_signal_kind: "network_connection_close".to_string(),
        source_module: "source.test".to_string(),
        correlation_kind: TraceCorrelationKind::NetworkInferred,
        process: None,
        container: None,
        kubernetes: None,
        peer: None,
    })
    .expect("trace warning serializes");
    let request_warning = serde_json::to_value(RequestCorrelationWarning {
        warning_type: "missing_trace_context".to_string(),
        message: "protocol request had no observed trace context".to_string(),
        timestamp_unix_nanos: 2_000,
        source_signal_kind: "protocol_request_observation".to_string(),
        source_module: "source.protocol_fixture".to_string(),
        correlation_kind: TraceCorrelationKind::ProtocolObserved,
        protocol: ProtocolKind::Http,
        process: None,
        container: None,
        kubernetes: None,
        peer: None,
    })
    .expect("request warning serializes");

    let trace_payload: SignalPayload =
        serde_json::from_value(trace_warning).expect("trace warning payload deserializes");
    let request_payload: SignalPayload =
        serde_json::from_value(request_warning).expect("request warning payload deserializes");

    assert!(matches!(
        trace_payload,
        SignalPayload::TraceCorrelationWarning(_)
    ));
    assert!(matches!(
        request_payload,
        SignalPayload::RequestCorrelationWarning(_)
    ));
}

fn process() -> NetworkProcessIdentity {
    NetworkProcessIdentity {
        pid: 42,
        ppid: Some(1),
        uid: Some(1000),
        command: "api".to_string(),
        executable: Some("/app/api".to_string()),
        cgroup_id: None,
    }
}

fn container() -> ContainerContext {
    ContainerContext {
        container_id: "container-a".to_string(),
        runtime: Some("containerd".to_string()),
    }
}

fn kubernetes() -> KubernetesContext {
    KubernetesContext {
        namespace: "default".to_string(),
        pod_name: "api-123".to_string(),
        pod_uid: Some("pod-uid".to_string()),
        container_name: Some("api".to_string()),
        node_name: Some("node-a".to_string()),
        labels: BTreeMap::new(),
    }
}

fn peer() -> TracePeerContext {
    TracePeerContext {
        address: Some("203.0.113.10".to_string()),
        port: Some(443),
        domain: Some("api.example.com".to_string()),
        workload: None,
        container: None,
    }
}
