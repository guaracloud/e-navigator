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
fn request_constructors_bound_and_filter_trace_attributes_before_json_stdout() {
    let attributes = oversized_trace_attributes();
    let protocol = SignalEnvelope::protocol_request_observation(
        "source.protocol_fixture",
        Some("node-a".to_string()),
        ProtocolRequestObservation {
            protocol: ProtocolKind::Http,
            start_unix_nanos: 1_000,
            end_unix_nanos: Some(2_500),
            duration_nanos: Some(1_500),
            trace_id: None,
            span_id: None,
            parent_span_id: None,
            traceparent: None,
            tracestate: None,
            correlation_kind: TraceCorrelationKind::ProtocolObserved,
            confidence: TraceConfidence::High,
            service_name: Some("checkout-api".to_string()),
            method: Some("GET".to_string()),
            status_code: Some(200),
            process: None,
            container: None,
            kubernetes: None,
            peer: None,
            attributes: attributes.clone(),
        },
    );
    let context = SignalEnvelope::extracted_trace_context_observation(
        "parser.protocol",
        Some("node-a".to_string()),
        ExtractedTraceContextObservation {
            protocol: ProtocolKind::Http,
            timestamp_unix_nanos: 1_100,
            trace_id: None,
            span_id: None,
            parent_span_id: None,
            traceparent: None,
            tracestate: None,
            correlation_kind: TraceCorrelationKind::ObservedTraceContext,
            confidence: TraceConfidence::High,
            process: None,
            container: None,
            kubernetes: None,
            peer: None,
            attributes: attributes.clone(),
        },
    );
    let request_span = SignalEnvelope::request_span_observation(
        "generator.request_correlation",
        Some("node-a".to_string()),
        RequestSpanObservation {
            name: "http request".to_string(),
            protocol: ProtocolKind::Http,
            trace_id: None,
            span_id: None,
            parent_span_id: None,
            start_unix_nanos: 1_000,
            end_unix_nanos: Some(2_500),
            duration_nanos: Some(1_500),
            correlation_kind: TraceCorrelationKind::ProtocolObserved,
            confidence: TraceConfidence::High,
            service_name: Some("checkout-api".to_string()),
            method: Some("GET".to_string()),
            status_code: Some(200),
            process: None,
            container: None,
            kubernetes: None,
            peer: None,
            attributes,
        },
    );

    assert_bounded_safe_trace_attributes(&protocol);
    assert_bounded_safe_trace_attributes(&context);
    assert_bounded_safe_trace_attributes(&request_span);
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
fn serializes_mysql_protocol_request_observation_without_query_text() {
    let signal = SignalEnvelope::protocol_request_observation(
        "source.protocol_fixture",
        Some("node-a".to_string()),
        ProtocolRequestObservation {
            protocol: ProtocolKind::Mysql,
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
                    value: "mysql".to_string(),
                },
                TraceAttribute {
                    key: "db.operation".to_string(),
                    value: "SELECT".to_string(),
                },
            ],
        },
    );

    let json = serde_json::to_value(&signal).expect("signal serializes");

    assert_eq!(json["payload"]["protocol"], "mysql");
    assert_eq!(json["payload"]["method"], "SELECT");
    assert!(!json.to_string().contains("where token"));

    let decoded: SignalEnvelope = serde_json::from_value(json).expect("signal deserializes");
    assert!(matches!(
        decoded.payload,
        SignalPayload::ProtocolRequestObservation(_)
    ));
}

#[test]
fn serializes_mongodb_protocol_request_observation_without_bson_values() {
    let signal = SignalEnvelope::protocol_request_observation(
        "source.protocol_fixture",
        Some("node-a".to_string()),
        ProtocolRequestObservation {
            protocol: ProtocolKind::Mongodb,
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
            method: Some("find".to_string()),
            status_code: None,
            process: Some(process()),
            container: Some(container()),
            kubernetes: Some(kubernetes()),
            peer: Some(peer()),
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

    let json = serde_json::to_value(&signal).expect("signal serializes");

    assert_eq!(json["payload"]["protocol"], "mongodb");
    assert_eq!(json["payload"]["method"], "find");
    assert!(!json.to_string().contains("customers-secret"));

    let decoded: SignalEnvelope = serde_json::from_value(json).expect("signal deserializes");
    assert!(matches!(
        decoded.payload,
        SignalPayload::ProtocolRequestObservation(_)
    ));
}

#[test]
fn serializes_kafka_protocol_request_observation_without_client_topic_or_payload() {
    let signal = SignalEnvelope::protocol_request_observation(
        "source.protocol_fixture",
        Some("node-a".to_string()),
        ProtocolRequestObservation {
            protocol: ProtocolKind::Kafka,
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
            service_name: Some("messaging-client".to_string()),
            method: Some("produce".to_string()),
            status_code: None,
            process: Some(process()),
            container: Some(container()),
            kubernetes: Some(kubernetes()),
            peer: Some(peer()),
            attributes: vec![
                TraceAttribute {
                    key: "messaging.system".to_string(),
                    value: "kafka".to_string(),
                },
                TraceAttribute {
                    key: "messaging.operation".to_string(),
                    value: "produce".to_string(),
                },
                TraceAttribute {
                    key: "messaging.kafka.client_id_present".to_string(),
                    value: "true".to_string(),
                },
            ],
        },
    );

    let json = serde_json::to_value(&signal).expect("signal serializes");

    assert_eq!(json["payload"]["protocol"], "kafka");
    assert_eq!(json["payload"]["method"], "produce");
    assert!(!json.to_string().contains("secret-client"));
    assert!(!json.to_string().contains("topic.secret"));
    assert!(!json.to_string().contains("secret-payload"));

    let decoded: SignalEnvelope = serde_json::from_value(json).expect("signal deserializes");
    assert!(matches!(
        decoded.payload,
        SignalPayload::ProtocolRequestObservation(_)
    ));
}

#[test]
fn serializes_nats_protocol_request_observation_without_subject_or_payload() {
    let signal = SignalEnvelope::protocol_request_observation(
        "source.protocol_fixture",
        Some("node-a".to_string()),
        ProtocolRequestObservation {
            protocol: ProtocolKind::Nats,
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
            service_name: Some("messaging-client".to_string()),
            method: Some("pub".to_string()),
            status_code: None,
            process: Some(process()),
            container: Some(container()),
            kubernetes: Some(kubernetes()),
            peer: Some(peer()),
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

    let json = serde_json::to_value(&signal).expect("signal serializes");

    assert_eq!(json["payload"]["protocol"], "nats");
    assert_eq!(json["payload"]["method"], "pub");
    assert!(!json.to_string().contains("customer.secret.subject"));
    assert!(!json.to_string().contains("secret-value"));

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

fn oversized_trace_attributes() -> Vec<TraceAttribute> {
    let mut attributes = vec![
        TraceAttribute {
            key: String::new(),
            value: "dropped".to_string(),
        },
        TraceAttribute {
            key: "authorization".to_string(),
            value: "Bearer secret".to_string(),
        },
        TraceAttribute {
            key: "k".repeat(160),
            value: "v".repeat(320),
        },
    ];
    attributes.extend((0..20).map(|index| TraceAttribute {
        key: format!("custom.attribute.{index}"),
        value: "value".to_string(),
    }));
    attributes
}

fn assert_bounded_safe_trace_attributes(signal: &SignalEnvelope) {
    let json = serde_json::to_value(signal).expect("signal serializes");
    let attributes = json["payload"]["attributes"]
        .as_array()
        .expect("attributes are serialized");

    assert_eq!(attributes.len(), 16);
    assert_eq!(attributes[0]["key"], "custom.attribute.0");
    assert_eq!(attributes[15]["key"], "custom.attribute.15");
    assert!(!json.to_string().contains("authorization"));
    assert!(!json.to_string().contains("Bearer secret"));
    assert!(!json.to_string().contains(&"k".repeat(160)));
    assert!(!json.to_string().contains(&"v".repeat(320)));
}
