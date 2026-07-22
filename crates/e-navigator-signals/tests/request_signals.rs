#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    reason = "integration tests use panic-oriented assertions for failed contracts"
)]

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
            role: None,
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

    assert_protocol_request_payload_has_no_raw_trace_headers(&signal);

    let decoded: SignalEnvelope = serde_json::from_value(json).expect("signal deserializes");
    match decoded.payload {
        SignalPayload::ProtocolRequestObservation(observation) => {
            assert!(observation.traceparent.is_none());
            assert!(observation.tracestate.is_none());
        }
        payload => panic!("unexpected payload: {payload:?}"),
    }
}

#[test]
fn serializes_websocket_frame_metadata_without_application_payload() {
    let signal = SignalEnvelope::protocol_request_observation(
        "source.protocol_fixture",
        Some("node-a".to_string()),
        ProtocolRequestObservation {
            protocol: ProtocolKind::Websocket,
            role: Some(e_navigator_signals::ProtocolCaptureRole::Server),
            start_unix_nanos: 1_000,
            end_unix_nanos: Some(1_500),
            duration_nanos: Some(500),
            trace_id: None,
            span_id: None,
            parent_span_id: None,
            traceparent: None,
            tracestate: None,
            correlation_kind: TraceCorrelationKind::ProtocolObserved,
            confidence: TraceConfidence::Medium,
            service_name: Some("websocket-fixture".to_string()),
            method: Some("text".to_string()),
            status_code: None,
            process: Some(process()),
            container: Some(container()),
            kubernetes: Some(kubernetes()),
            peer: Some(peer()),
            attributes: vec![
                TraceAttribute {
                    key: "websocket.frame.opcode".to_string(),
                    value: "1".to_string(),
                },
                TraceAttribute {
                    key: "websocket.frame.payload_length".to_string(),
                    value: "18".to_string(),
                },
            ],
        },
    );

    let json = serde_json::to_value(&signal).expect("signal serializes");
    let encoded = serde_json::to_string(&signal).expect("signal serializes to text");

    assert_eq!(json["payload"]["protocol"], "websocket");
    assert_eq!(json["payload"]["method"], "text");
    assert_eq!(
        json["payload"]["attributes"][1]["key"],
        "websocket.frame.payload_length"
    );
    assert!(!encoded.contains("client-secret-blue"));
    assert!(!encoded.contains("server-secret-red"));
}

#[test]
fn request_constructors_bound_and_filter_trace_attributes_before_json_stdout() {
    let attributes = oversized_trace_attributes();
    let protocol = SignalEnvelope::protocol_request_observation(
        "source.protocol_fixture",
        Some("node-a".to_string()),
        ProtocolRequestObservation {
            protocol: ProtocolKind::Http,
            role: None,
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
fn request_constructors_bound_scalar_strings_before_json_stdout() {
    let long_value = "r".repeat(320);
    let protocol = SignalEnvelope::protocol_request_observation(
        "source.protocol_fixture",
        Some("node-a".to_string()),
        ProtocolRequestObservation {
            protocol: ProtocolKind::Http,
            role: None,
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
            service_name: Some(long_value.clone()),
            method: Some(long_value.clone()),
            status_code: Some(200),
            process: None,
            container: None,
            kubernetes: None,
            peer: None,
            attributes: vec![],
        },
    );
    let span = SignalEnvelope::request_span_observation(
        "generator.request_correlation",
        Some("node-a".to_string()),
        RequestSpanObservation {
            name: long_value.clone(),
            protocol: ProtocolKind::Http,
            trace_id: None,
            span_id: None,
            parent_span_id: None,
            start_unix_nanos: 1_000,
            end_unix_nanos: Some(2_500),
            duration_nanos: Some(1_500),
            correlation_kind: TraceCorrelationKind::ProtocolObserved,
            confidence: TraceConfidence::High,
            service_name: Some(long_value.clone()),
            method: Some(long_value.clone()),
            status_code: Some(200),
            process: None,
            container: None,
            kubernetes: None,
            peer: None,
            attributes: vec![],
        },
    );
    let warning = SignalEnvelope::request_correlation_warning(
        "generator.request_correlation",
        Some("node-a".to_string()),
        RequestCorrelationWarning {
            warning_type: long_value.clone(),
            message: long_value.clone(),
            timestamp_unix_nanos: 1_200,
            source_signal_kind: long_value.clone(),
            source_module: long_value,
            correlation_kind: TraceCorrelationKind::ProtocolObserved,
            protocol: ProtocolKind::Http,
            process: None,
            container: None,
            kubernetes: None,
            peer: None,
        },
    );

    let protocol_json = serde_json::to_value(&protocol).expect("protocol serializes");
    let span_json = serde_json::to_value(&span).expect("span serializes");
    let warning_json = serde_json::to_value(&warning).expect("warning serializes");

    assert_eq!(
        protocol_json["payload"]["service_name"]
            .as_str()
            .map(str::len),
        Some(256)
    );
    assert_eq!(
        protocol_json["payload"]["method"].as_str().map(str::len),
        Some(256)
    );
    assert_eq!(
        span_json["payload"]["name"].as_str().map(str::len),
        Some(256)
    );
    assert_eq!(
        span_json["payload"]["service_name"].as_str().map(str::len),
        Some(256)
    );
    assert_eq!(
        warning_json["payload"]["warning_type"]
            .as_str()
            .map(str::len),
        Some(256)
    );
    assert_eq!(
        warning_json["payload"]["source_module"]
            .as_str()
            .map(str::len),
        Some(256)
    );
}

#[test]
fn request_constructors_bound_identifier_strings_before_json_stdout() {
    let long_value = "b".repeat(96);
    let protocol = SignalEnvelope::protocol_request_observation(
        "source.protocol_fixture",
        None,
        ProtocolRequestObservation {
            protocol: ProtocolKind::Http,
            role: None,
            start_unix_nanos: 1_000,
            end_unix_nanos: Some(2_500),
            duration_nanos: Some(1_500),
            trace_id: Some(long_value.clone()),
            span_id: Some(long_value.clone()),
            parent_span_id: Some(long_value.clone()),
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
            attributes: vec![],
        },
    );
    let context = SignalEnvelope::extracted_trace_context_observation(
        "parser.protocol",
        None,
        ExtractedTraceContextObservation {
            protocol: ProtocolKind::Http,
            timestamp_unix_nanos: 1_100,
            trace_id: Some(long_value.clone()),
            span_id: Some(long_value.clone()),
            parent_span_id: Some(long_value.clone()),
            traceparent: None,
            tracestate: None,
            correlation_kind: TraceCorrelationKind::ObservedTraceContext,
            confidence: TraceConfidence::High,
            process: None,
            container: None,
            kubernetes: None,
            peer: None,
            attributes: vec![],
        },
    );
    let span = SignalEnvelope::request_span_observation(
        "generator.request_correlation",
        None,
        RequestSpanObservation {
            name: "http request".to_string(),
            protocol: ProtocolKind::Http,
            trace_id: Some(long_value.clone()),
            span_id: Some(long_value.clone()),
            parent_span_id: Some(long_value),
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
            attributes: vec![],
        },
    );

    for signal in [protocol, context, span] {
        let json = serde_json::to_value(signal).expect("signal serializes");
        assert_eq!(json["payload"]["trace_id"].as_str().map(str::len), Some(64));
        assert_eq!(json["payload"]["span_id"].as_str().map(str::len), Some(64));
        assert_eq!(
            json["payload"]["parent_span_id"].as_str().map(str::len),
            Some(64)
        );
        assert!(!json.to_string().contains(&"b".repeat(65)));
    }
}

#[test]
fn request_constructors_bound_context_strings_before_json_stdout() {
    let long = "r".repeat(320);
    let process = NetworkProcessIdentity {
        pid: 42,
        ppid: Some(1),
        uid: Some(1000),
        command: long.clone(),
        executable: Some(long.clone()),
        cgroup_id: None,
    };
    let container = ContainerContext {
        container_id: long.clone(),
        runtime: Some(long.clone()),
    };
    let kubernetes = KubernetesContext {
        namespace: long.clone(),
        pod_name: long.clone(),
        pod_uid: Some(long.clone()),
        container_name: Some(long.clone()),
        node_name: Some(long.clone()),
        labels: BTreeMap::from_iter(
            (0..20).map(|index| (format!("label-{index}-{long}"), long.clone())),
        ),
    };
    let peer = TracePeerContext {
        address: Some(long.clone()),
        port: Some(443),
        domain: Some(long),
        workload: Some(kubernetes.clone()),
        container: Some(container.clone()),
    };

    let protocol = SignalEnvelope::protocol_request_observation(
        "source.protocol_fixture",
        None,
        ProtocolRequestObservation {
            protocol: ProtocolKind::Http,
            role: None,
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
            process: Some(process.clone()),
            container: Some(container.clone()),
            kubernetes: Some(kubernetes.clone()),
            peer: Some(peer.clone()),
            attributes: vec![],
        },
    );
    let context = SignalEnvelope::extracted_trace_context_observation(
        "parser.protocol",
        None,
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
            process: Some(process.clone()),
            container: Some(container.clone()),
            kubernetes: Some(kubernetes.clone()),
            peer: Some(peer.clone()),
            attributes: vec![],
        },
    );
    let span = SignalEnvelope::request_span_observation(
        "generator.request_correlation",
        None,
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
            process: Some(process.clone()),
            container: Some(container.clone()),
            kubernetes: Some(kubernetes.clone()),
            peer: Some(peer.clone()),
            attributes: vec![],
        },
    );
    let warning = SignalEnvelope::request_correlation_warning(
        "generator.request_correlation",
        None,
        RequestCorrelationWarning {
            warning_type: "missing_trace_context".to_string(),
            message: "protocol request had no observed trace context".to_string(),
            timestamp_unix_nanos: 1_200,
            source_signal_kind: "protocol_request_observation".to_string(),
            source_module: "source.protocol_fixture".to_string(),
            correlation_kind: TraceCorrelationKind::ProtocolObserved,
            protocol: ProtocolKind::Http,
            process: Some(process),
            container: Some(container),
            kubernetes: Some(kubernetes),
            peer: Some(peer),
        },
    );

    for signal in [&protocol, &context, &span, &warning] {
        assert_payload_string_lengths(
            signal,
            &[
                &["process", "command"],
                &["process", "executable"],
                &["container", "container_id"],
                &["container", "runtime"],
                &["kubernetes", "namespace"],
                &["kubernetes", "pod_name"],
                &["kubernetes", "pod_uid"],
                &["kubernetes", "container_name"],
                &["kubernetes", "node_name"],
                &["peer", "address"],
                &["peer", "domain"],
                &["peer", "container", "container_id"],
                &["peer", "workload", "namespace"],
            ],
        );
        assert_payload_label_bounds(signal, &["kubernetes", "labels"]);
        assert_payload_label_bounds(signal, &["peer", "workload", "labels"]);
    }
}

#[test]
fn serializes_redis_protocol_request_observation_without_payload_values() {
    let signal = SignalEnvelope::protocol_request_observation(
        "source.protocol_fixture",
        Some("node-a".to_string()),
        ProtocolRequestObservation {
            protocol: ProtocolKind::Redis,
            role: None,
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
            role: None,
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
            role: None,
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
            role: None,
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
            role: None,
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
            role: None,
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

    assert_extracted_trace_context_payload_has_no_raw_trace_headers(&signal);

    let decoded: SignalEnvelope = serde_json::from_value(json).expect("signal deserializes");
    match decoded.payload {
        SignalPayload::ExtractedTraceContextObservation(observation) => {
            assert!(observation.traceparent.is_none());
            assert!(observation.tracestate.is_none());
        }
        payload => panic!("unexpected payload: {payload:?}"),
    }
}

#[test]
fn deserializing_request_payload_ignores_raw_trace_headers() {
    let protocol = serde_json::json!({
        "protocol": "http",
        "start_unix_nanos": 1_000,
        "end_unix_nanos": 2_500,
        "duration_nanos": 1_500,
        "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736",
        "span_id": "00f067aa0ba902b7",
        "parent_span_id": null,
        "traceparent": "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
        "tracestate": "vendor=value",
        "correlation_kind": "protocol_observed",
        "confidence": "high",
        "service_name": "checkout-api",
        "method": "GET",
        "status_code": 200,
        "process": null,
        "container": null,
        "kubernetes": null,
        "peer": null,
        "attributes": []
    });
    let context = serde_json::json!({
        "protocol": "http",
        "timestamp_unix_nanos": 1_100,
        "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736",
        "span_id": "00f067aa0ba902b7",
        "parent_span_id": null,
        "traceparent": "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
        "tracestate": "vendor=value",
        "correlation_kind": "observed_trace_context",
        "confidence": "high",
        "process": null,
        "container": null,
        "kubernetes": null,
        "peer": null,
        "attributes": []
    });

    let protocol =
        serde_json::from_value::<ProtocolRequestObservation>(protocol).expect("protocol payload");
    let context = serde_json::from_value::<ExtractedTraceContextObservation>(context)
        .expect("context payload");

    assert!(protocol.traceparent.is_none());
    assert!(protocol.tracestate.is_none());
    assert!(context.traceparent.is_none());
    assert!(context.tracestate.is_none());
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

fn assert_protocol_request_payload_has_no_raw_trace_headers(signal: &SignalEnvelope) {
    match &signal.payload {
        SignalPayload::ProtocolRequestObservation(observation) => {
            assert!(observation.traceparent.is_none());
            assert!(observation.tracestate.is_none());
        }
        payload => panic!("unexpected payload: {payload:?}"),
    }
}

fn assert_extracted_trace_context_payload_has_no_raw_trace_headers(signal: &SignalEnvelope) {
    match &signal.payload {
        SignalPayload::ExtractedTraceContextObservation(observation) => {
            assert!(observation.traceparent.is_none());
            assert!(observation.tracestate.is_none());
        }
        payload => panic!("unexpected payload: {payload:?}"),
    }
}

fn assert_payload_string_lengths(signal: &SignalEnvelope, paths: &[&[&str]]) {
    let json = serde_json::to_value(signal).expect("signal serializes");
    for path in paths {
        let mut value = &json["payload"];
        for field in *path {
            value = &value[*field];
        }
        assert_eq!(
            value.as_str().map(str::len),
            Some(256),
            "{path:?} should be bounded"
        );
    }
}

fn assert_payload_label_bounds(signal: &SignalEnvelope, path: &[&str]) {
    let json = serde_json::to_value(signal).expect("signal serializes");
    let mut value = &json["payload"];
    for field in path {
        value = &value[*field];
    }
    let labels = value.as_object().expect("labels serialize as an object");
    assert_eq!(labels.len(), 16);
    assert!(
        labels
            .iter()
            .all(|(key, value)| key.len() == 128 && value.as_str().map(str::len) == Some(256))
    );
}
