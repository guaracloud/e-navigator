use e_navigator_core::Generator;
use e_navigator_generators::RequestCorrelationGenerator;
use e_navigator_signals::{
    ContainerContext, KubernetesContext, NetworkAddressFamily, NetworkConnectionCloseEvent,
    NetworkProcessIdentity, NetworkProtocol, ProtocolKind, ProtocolRequestObservation,
    RequestCorrelationWarning, SignalEnvelope, SignalPayload, TraceAttribute, TraceConfidence,
    TraceCorrelationKind, TracePeerContext,
};
use std::collections::BTreeMap;
use tokio::sync::mpsc;

#[tokio::test]
async fn observed_trace_context_protocol_request_generates_request_span() {
    let generator = RequestCorrelationGenerator::default();
    let signal = protocol_request_signal(Some(valid_traceparent()), true);

    let outputs = observe(&generator, &signal).await;

    assert_eq!(outputs.len(), 1);
    let SignalPayload::RequestSpanObservation(span) = &outputs[0].payload else {
        panic!("expected request span");
    };
    assert_eq!(span.name, "http request");
    assert_eq!(span.protocol, ProtocolKind::Http);
    assert_eq!(
        span.trace_id.as_deref(),
        Some("4bf92f3577b34da6a3ce929d0e0e4736")
    );
    assert_eq!(span.span_id.as_deref(), Some("00f067aa0ba902b7"));
    assert_eq!(
        span.correlation_kind,
        TraceCorrelationKind::ObservedTraceContext
    );
    assert_eq!(span.confidence, TraceConfidence::High);
    assert_eq!(span.method.as_deref(), Some("GET"));
    assert_eq!(span.status_code, Some(200));
    assert_eq!(span.process, Some(process()));
    assert_eq!(span.container, Some(container()));
    assert_eq!(span.kubernetes, Some(kubernetes()));
    assert_eq!(span.peer, Some(peer()));
}

#[tokio::test]
async fn redis_protocol_request_generates_named_request_span() {
    let generator = RequestCorrelationGenerator::default();
    let mut signal = protocol_request_signal(None, true);
    let SignalPayload::ProtocolRequestObservation(request) = &mut signal.payload else {
        panic!("expected protocol request");
    };
    request.protocol = ProtocolKind::Redis;
    request.method = Some("GET".to_string());
    request.status_code = None;
    request.attributes = vec![
        TraceAttribute {
            key: "db.system".to_string(),
            value: "redis".to_string(),
        },
        TraceAttribute {
            key: "db.operation".to_string(),
            value: "GET".to_string(),
        },
    ];

    let outputs = observe(&generator, &signal).await;

    let SignalPayload::RequestSpanObservation(span) = &outputs[0].payload else {
        panic!("expected request span");
    };
    assert_eq!(span.name, "redis command");
    assert_eq!(span.protocol, ProtocolKind::Redis);
    assert_eq!(span.method.as_deref(), Some("GET"));
    assert!(has_attribute(&span.attributes, "db.operation", "GET"));
}

#[tokio::test]
async fn grpc_protocol_request_generates_named_request_span() {
    let generator = RequestCorrelationGenerator::default();
    let mut signal = protocol_request_signal(None, true);
    let SignalPayload::ProtocolRequestObservation(request) = &mut signal.payload else {
        panic!("expected protocol request");
    };
    request.protocol = ProtocolKind::Grpc;
    request.method = Some("GetCart".to_string());
    request.status_code = None;
    request.attributes = vec![
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
    ];

    let outputs = observe(&generator, &signal).await;

    let SignalPayload::RequestSpanObservation(span) = &outputs[0].payload else {
        panic!("expected request span");
    };
    assert_eq!(span.name, "grpc request");
    assert_eq!(span.protocol, ProtocolKind::Grpc);
    assert_eq!(span.method.as_deref(), Some("GetCart"));
    assert!(has_attribute(&span.attributes, "rpc.system", "grpc"));
    assert!(has_attribute(
        &span.attributes,
        "rpc.service",
        "checkout.v1.CheckoutService"
    ));
}

#[tokio::test]
async fn grpc_protocol_request_preserves_response_status_for_span_export() {
    let generator = RequestCorrelationGenerator::default();
    let mut signal = protocol_request_signal(None, true);
    let SignalPayload::ProtocolRequestObservation(request) = &mut signal.payload else {
        panic!("expected protocol request");
    };
    request.protocol = ProtocolKind::Grpc;
    request.method = Some("GetCart".to_string());
    request.status_code = Some(13);
    request.attributes = vec![
        TraceAttribute {
            key: "rpc.system".to_string(),
            value: "grpc".to_string(),
        },
        TraceAttribute {
            key: "rpc.grpc.status_code".to_string(),
            value: "13".to_string(),
        },
    ];

    let outputs = observe(&generator, &signal).await;

    let SignalPayload::RequestSpanObservation(span) = &outputs[0].payload else {
        panic!("expected request span");
    };
    assert_eq!(span.name, "grpc request");
    assert_eq!(span.protocol, ProtocolKind::Grpc);
    assert_eq!(span.status_code, Some(13));
    assert!(has_attribute(
        &span.attributes,
        "rpc.grpc.status_code",
        "13"
    ));
}

#[tokio::test]
async fn postgresql_protocol_request_generates_named_request_span() {
    let generator = RequestCorrelationGenerator::default();
    let mut signal = protocol_request_signal(None, true);
    let SignalPayload::ProtocolRequestObservation(request) = &mut signal.payload else {
        panic!("expected protocol request");
    };
    request.protocol = ProtocolKind::Postgresql;
    request.method = Some("SELECT".to_string());
    request.status_code = None;
    request.attributes = vec![
        TraceAttribute {
            key: "db.system".to_string(),
            value: "postgresql".to_string(),
        },
        TraceAttribute {
            key: "db.operation".to_string(),
            value: "SELECT".to_string(),
        },
    ];

    let outputs = observe(&generator, &signal).await;

    let SignalPayload::RequestSpanObservation(span) = &outputs[0].payload else {
        panic!("expected request span");
    };
    assert_eq!(span.name, "postgresql query");
    assert_eq!(span.protocol, ProtocolKind::Postgresql);
    assert_eq!(span.method.as_deref(), Some("SELECT"));
    assert!(has_attribute(&span.attributes, "db.operation", "SELECT"));
}

#[tokio::test]
async fn mysql_protocol_request_generates_named_request_span() {
    let generator = RequestCorrelationGenerator::default();
    let mut signal = protocol_request_signal(None, true);
    let SignalPayload::ProtocolRequestObservation(request) = &mut signal.payload else {
        panic!("expected protocol request");
    };
    request.protocol = ProtocolKind::Mysql;
    request.method = Some("SELECT".to_string());
    request.status_code = None;
    request.attributes = vec![
        TraceAttribute {
            key: "db.system".to_string(),
            value: "mysql".to_string(),
        },
        TraceAttribute {
            key: "db.operation".to_string(),
            value: "SELECT".to_string(),
        },
    ];

    let outputs = observe(&generator, &signal).await;

    let SignalPayload::RequestSpanObservation(span) = &outputs[0].payload else {
        panic!("expected request span");
    };
    assert_eq!(span.name, "mysql query");
    assert_eq!(span.protocol, ProtocolKind::Mysql);
    assert_eq!(span.method.as_deref(), Some("SELECT"));
    assert!(has_attribute(&span.attributes, "db.operation", "SELECT"));
}

#[tokio::test]
async fn mongodb_protocol_request_generates_named_request_span() {
    let generator = RequestCorrelationGenerator::default();
    let mut signal = protocol_request_signal(None, true);
    let SignalPayload::ProtocolRequestObservation(request) = &mut signal.payload else {
        panic!("expected protocol request");
    };
    request.protocol = ProtocolKind::Mongodb;
    request.method = Some("find".to_string());
    request.status_code = None;
    request.attributes = vec![
        TraceAttribute {
            key: "db.system".to_string(),
            value: "mongodb".to_string(),
        },
        TraceAttribute {
            key: "db.operation".to_string(),
            value: "find".to_string(),
        },
    ];

    let outputs = observe(&generator, &signal).await;

    let SignalPayload::RequestSpanObservation(span) = &outputs[0].payload else {
        panic!("expected request span");
    };
    assert_eq!(span.name, "mongodb command");
    assert_eq!(span.protocol, ProtocolKind::Mongodb);
    assert_eq!(span.method.as_deref(), Some("find"));
    assert!(has_attribute(&span.attributes, "db.operation", "find"));
}

#[tokio::test]
async fn kafka_protocol_request_generates_named_request_span() {
    let generator = RequestCorrelationGenerator::default();
    let mut signal = protocol_request_signal(None, true);
    let SignalPayload::ProtocolRequestObservation(request) = &mut signal.payload else {
        panic!("expected protocol request");
    };
    request.protocol = ProtocolKind::Kafka;
    request.method = Some("produce".to_string());
    request.status_code = None;
    request.attributes = vec![
        TraceAttribute {
            key: "messaging.system".to_string(),
            value: "kafka".to_string(),
        },
        TraceAttribute {
            key: "messaging.operation".to_string(),
            value: "produce".to_string(),
        },
    ];

    let outputs = observe(&generator, &signal).await;

    let SignalPayload::RequestSpanObservation(span) = &outputs[0].payload else {
        panic!("expected request span");
    };
    assert_eq!(span.name, "kafka request");
    assert_eq!(span.protocol, ProtocolKind::Kafka);
    assert_eq!(span.method.as_deref(), Some("produce"));
    assert!(has_attribute(
        &span.attributes,
        "messaging.operation",
        "produce"
    ));
}

#[tokio::test]
async fn protocol_request_preserves_error_attributes_for_trace_export() {
    let generator = RequestCorrelationGenerator::default();

    for (protocol, method, status_key, status_value, error_type) in [
        (
            ProtocolKind::Redis,
            "GET",
            "db.response.status_code",
            "WRONGTYPE",
            "redis_wrongtype",
        ),
        (
            ProtocolKind::Kafka,
            "api_versions",
            "messaging.kafka.response.error_code",
            "35",
            "35",
        ),
        (
            ProtocolKind::Mongodb,
            "find",
            "db.response.status_code",
            "13",
            "13",
        ),
        (
            ProtocolKind::Mysql,
            "SELECT",
            "db.response.status_code",
            "42000/1064",
            "42000/1064",
        ),
        (
            ProtocolKind::Nats,
            "pub",
            "messaging.nats.status_code",
            "ERR",
            "nats_error",
        ),
        (
            ProtocolKind::Postgresql,
            "SELECT",
            "db.response.status_code",
            "23505",
            "23505",
        ),
    ] {
        let mut signal = protocol_request_signal(None, true);
        let SignalPayload::ProtocolRequestObservation(request) = &mut signal.payload else {
            panic!("expected protocol request");
        };
        request.protocol = protocol;
        request.method = Some(method.to_string());
        request.status_code = None;
        request.attributes = vec![
            TraceAttribute {
                key: status_key.to_string(),
                value: status_value.to_string(),
            },
            TraceAttribute {
                key: "error.type".to_string(),
                value: error_type.to_string(),
            },
        ];

        let outputs = observe(&generator, &signal).await;

        let SignalPayload::RequestSpanObservation(span) = &outputs[0].payload else {
            panic!("expected request span");
        };
        assert_eq!(span.protocol, protocol);
        assert_eq!(span.method.as_deref(), Some(method));
        assert!(has_attribute(&span.attributes, status_key, status_value));
        assert!(has_attribute(&span.attributes, "error.type", error_type));
    }
}

#[tokio::test]
async fn nats_protocol_request_generates_named_request_span() {
    let generator = RequestCorrelationGenerator::default();
    let mut signal = protocol_request_signal(None, true);
    let SignalPayload::ProtocolRequestObservation(request) = &mut signal.payload else {
        panic!("expected protocol request");
    };
    request.protocol = ProtocolKind::Nats;
    request.method = Some("pub".to_string());
    request.status_code = None;
    request.attributes = vec![
        TraceAttribute {
            key: "messaging.system".to_string(),
            value: "nats".to_string(),
        },
        TraceAttribute {
            key: "messaging.operation".to_string(),
            value: "pub".to_string(),
        },
    ];

    let outputs = observe(&generator, &signal).await;

    let SignalPayload::RequestSpanObservation(span) = &outputs[0].payload else {
        panic!("expected request span");
    };
    assert_eq!(span.name, "nats message");
    assert_eq!(span.protocol, ProtocolKind::Nats);
    assert_eq!(span.method.as_deref(), Some("pub"));
    assert!(has_attribute(
        &span.attributes,
        "messaging.operation",
        "pub"
    ));
}

#[tokio::test]
async fn valid_traceparent_fallback_generates_request_span_ids() {
    let generator = RequestCorrelationGenerator::default();
    let mut signal = protocol_request_signal(Some(valid_traceparent()), true);
    let SignalPayload::ProtocolRequestObservation(request) = &mut signal.payload else {
        panic!("expected protocol request");
    };
    request.trace_id = None;
    request.span_id = None;

    let outputs = observe(&generator, &signal).await;

    assert_eq!(outputs.len(), 1);
    let SignalPayload::RequestSpanObservation(span) = &outputs[0].payload else {
        panic!("expected request span");
    };
    assert_eq!(
        span.trace_id.as_deref(),
        Some("4bf92f3577b34da6a3ce929d0e0e4736")
    );
    assert_eq!(span.span_id.as_deref(), Some("00f067aa0ba902b7"));
    assert_eq!(
        span.correlation_kind,
        TraceCorrelationKind::ObservedTraceContext
    );
}

#[tokio::test]
async fn synthetic_protocol_requests_preserve_synthetic_provenance() {
    let generator = RequestCorrelationGenerator::default();
    let mut signal = protocol_request_signal(Some(valid_traceparent()), true);
    let SignalPayload::ProtocolRequestObservation(request) = &mut signal.payload else {
        panic!("expected protocol request");
    };
    request.correlation_kind = TraceCorrelationKind::Synthetic;
    request.confidence = TraceConfidence::High;

    let outputs = observe(&generator, &signal).await;

    assert_eq!(outputs.len(), 1);
    let SignalPayload::RequestSpanObservation(span) = &outputs[0].payload else {
        panic!("expected request span");
    };
    assert_eq!(span.correlation_kind, TraceCorrelationKind::Synthetic);
    assert_eq!(span.confidence, TraceConfidence::High);
}

#[tokio::test]
async fn synthetic_requests_without_trace_context_remain_synthetic() {
    let generator = RequestCorrelationGenerator::default();
    let mut signal = protocol_request_signal(None, true);
    let SignalPayload::ProtocolRequestObservation(request) = &mut signal.payload else {
        panic!("expected protocol request");
    };
    request.correlation_kind = TraceCorrelationKind::Synthetic;

    let outputs = observe(&generator, &signal).await;

    assert_eq!(outputs.len(), 2);
    assert!(outputs.iter().any(|signal| {
        matches!(
            &signal.payload,
            SignalPayload::RequestSpanObservation(span)
                if span.correlation_kind == TraceCorrelationKind::Synthetic
        )
    }));
    assert!(outputs.iter().any(|signal| {
        matches!(
            &signal.payload,
            SignalPayload::RequestCorrelationWarning(warning)
                if warning.correlation_kind == TraceCorrelationKind::Synthetic
                    && warning.warning_type == "missing_trace_context"
        )
    }));
}

#[tokio::test]
async fn method_and_status_are_only_copied_when_observed() {
    let generator = RequestCorrelationGenerator::default();
    let mut signal = protocol_request_signal(None, true);
    let SignalPayload::ProtocolRequestObservation(request) = &mut signal.payload else {
        panic!("expected protocol request");
    };
    request.method = None;
    request.status_code = None;

    let outputs = observe(&generator, &signal).await;

    let SignalPayload::RequestSpanObservation(span) = &outputs[0].payload else {
        panic!("expected request span");
    };
    assert_eq!(span.method, None);
    assert_eq!(span.status_code, None);
}

#[tokio::test]
async fn request_attributes_are_count_and_byte_bounded() {
    let generator = RequestCorrelationGenerator::default();
    let mut signal = protocol_request_signal(Some(valid_traceparent()), true);
    let SignalPayload::ProtocolRequestObservation(request) = &mut signal.payload else {
        panic!("expected protocol request");
    };
    request.attributes = vec![
        TraceAttribute {
            key: "custom.kept".to_string(),
            value: "value".to_string(),
        },
        TraceAttribute {
            key: "k".repeat(129),
            value: "dropped".to_string(),
        },
        TraceAttribute {
            key: "custom.too_large".to_string(),
            value: "v".repeat(257),
        },
    ];

    let outputs = observe(&generator, &signal).await;

    let SignalPayload::RequestSpanObservation(span) = &outputs[0].payload else {
        panic!("expected request span");
    };
    assert_eq!(span.attributes.len(), 1);
    assert_eq!(span.attributes[0].key, "custom.kept");
}

#[tokio::test]
async fn request_span_scalar_fields_are_byte_bounded() {
    let generator = RequestCorrelationGenerator::default();
    let mut signal = protocol_request_signal(Some(valid_traceparent()), true);
    let SignalPayload::ProtocolRequestObservation(request) = &mut signal.payload else {
        panic!("expected protocol request");
    };
    request.service_name = Some("s".repeat(254));
    request.method = Some("m".repeat(129));

    let outputs = observe(&generator, &signal).await;

    let SignalPayload::RequestSpanObservation(span) = &outputs[0].payload else {
        panic!("expected request span");
    };
    assert_eq!(span.service_name, None);
    assert_eq!(span.method, None);
    assert_eq!(span.status_code, Some(200));
}

#[tokio::test]
async fn missing_trace_context_emits_warning_and_span_without_ids() {
    let generator = RequestCorrelationGenerator::default();
    let signal = protocol_request_signal(None, true);

    let outputs = observe(&generator, &signal).await;

    assert_eq!(outputs.len(), 2);
    assert!(outputs.iter().any(|signal| {
        matches!(
            &signal.payload,
            SignalPayload::RequestSpanObservation(span)
                if span.trace_id.is_none() && span.span_id.is_none()
        )
    }));
    assert_request_warning(&outputs, "missing_trace_context");
    assert!(outputs.iter().any(|signal| {
        matches!(
            &signal.payload,
            SignalPayload::RequestSpanObservation(span)
                if span.correlation_kind == TraceCorrelationKind::ProtocolObserved
        )
    }));
}

#[tokio::test]
async fn malformed_trace_context_emits_warning_without_inventing_ids() {
    let generator = RequestCorrelationGenerator::default();
    let signal = protocol_request_signal(Some("00-bad".to_string()), true);

    let outputs = observe(&generator, &signal).await;

    assert_eq!(outputs.len(), 2);
    assert!(outputs.iter().any(|signal| {
        matches!(
            &signal.payload,
            SignalPayload::RequestSpanObservation(span)
                if span.trace_id.is_none() && span.span_id.is_none()
        )
    }));
    assert_request_warning(&outputs, "malformed_trace_context");
}

#[tokio::test]
async fn whitespace_wrapped_traceparent_is_malformed_without_inventing_ids() {
    let generator = RequestCorrelationGenerator::default();
    let signal = protocol_request_signal(Some(format!(" {} ", valid_traceparent())), true);

    let outputs = observe(&generator, &signal).await;

    assert_eq!(outputs.len(), 2);
    assert!(outputs.iter().any(|signal| {
        matches!(
            &signal.payload,
            SignalPayload::RequestSpanObservation(span)
                if span.trace_id.is_none() && span.span_id.is_none()
        )
    }));
    assert_request_warning(&outputs, "malformed_trace_context");
}

#[tokio::test]
async fn raw_tcp_only_signal_does_not_generate_request_span() {
    let generator = RequestCorrelationGenerator::default();
    let signal = network_close_signal();

    let outputs = observe(&generator, &signal).await;

    assert!(outputs.is_empty());
}

#[tokio::test]
async fn duplicate_protocol_request_is_suppressed_deterministically() {
    let generator = RequestCorrelationGenerator::default();
    let signal = protocol_request_signal(Some(valid_traceparent()), true);

    let first = observe(&generator, &signal).await;
    let second = observe(&generator, &signal).await;

    assert_eq!(first.len(), 1);
    assert!(second.is_empty());
}

#[tokio::test]
async fn duplicate_suppression_distinguishes_spanless_request_paths() {
    let generator = RequestCorrelationGenerator::default();
    let mut checkout = protocol_request_signal_at(1_000, None, true);
    let mut orders = protocol_request_signal_at(1_000, None, true);
    set_request_path(&mut checkout, "/checkout/123");
    set_request_path(&mut orders, "/orders/456");

    let first = observe(&generator, &checkout).await;
    let second = observe(&generator, &orders).await;

    assert!(first.iter().any(|signal| {
        matches!(
            &signal.payload,
            SignalPayload::RequestSpanObservation(span)
                if has_attribute(span.attributes.as_slice(), "url.path", "/checkout/123")
        )
    }));
    assert!(second.iter().any(|signal| {
        matches!(
            &signal.payload,
            SignalPayload::RequestSpanObservation(span)
                if has_attribute(span.attributes.as_slice(), "url.path", "/orders/456")
        )
    }));
}

#[tokio::test]
async fn request_span_preserves_bounded_request_id_attribute() {
    let generator = RequestCorrelationGenerator::default();
    let mut signal = protocol_request_signal(Some(valid_traceparent()), true);
    let SignalPayload::ProtocolRequestObservation(request) = &mut signal.payload else {
        panic!("expected protocol request");
    };
    request.attributes.push(TraceAttribute {
        key: "http.request.id".to_string(),
        value: "req-12345".to_string(),
    });

    let outputs = observe(&generator, &signal).await;

    assert!(outputs.iter().any(|signal| {
        matches!(
            &signal.payload,
            SignalPayload::RequestSpanObservation(span)
                if has_attribute(span.attributes.as_slice(), "http.request.id", "req-12345")
        )
    }));
}

#[tokio::test]
async fn bounded_seen_state_evicts_oldest_fingerprint() {
    let generator = RequestCorrelationGenerator::with_limits(1, 8);
    let first = protocol_request_signal_at(1_000, Some(valid_traceparent()), true);
    let second = protocol_request_signal_at(2_000, Some(valid_traceparent()), true);

    assert_eq!(observe(&generator, &first).await.len(), 1);
    assert_eq!(observe(&generator, &second).await.len(), 1);
    assert_eq!(observe(&generator, &first).await.len(), 1);
}

#[tokio::test]
async fn attribution_failure_warning_is_non_fatal_and_visible() {
    let generator = RequestCorrelationGenerator::default();
    let signal = protocol_request_signal(Some(valid_traceparent()), false);

    let outputs = observe(&generator, &signal).await;

    assert_eq!(outputs.len(), 2);
    assert!(outputs.iter().any(|signal| {
        matches!(
            &signal.payload,
            SignalPayload::RequestSpanObservation(span)
                if span.container.is_none() && span.kubernetes.is_none()
        )
    }));
    assert_request_warning(&outputs, "missing_attribution");
}

async fn observe(
    generator: &RequestCorrelationGenerator,
    signal: &SignalEnvelope,
) -> Vec<SignalEnvelope> {
    let (tx, mut rx) = mpsc::channel(8);
    generator
        .observe(signal, &tx)
        .await
        .expect("generator succeeds");
    drop(tx);

    let mut outputs = Vec::new();
    while let Some(output) = rx.recv().await {
        outputs.push(output);
    }
    outputs
}

fn assert_request_warning(outputs: &[SignalEnvelope], warning_type: &str) {
    assert!(outputs.iter().any(|signal| {
        matches!(
            &signal.payload,
            SignalPayload::RequestCorrelationWarning(RequestCorrelationWarning { warning_type: found, .. })
                if found == warning_type
        )
    }));
}

fn has_attribute(attributes: &[TraceAttribute], key: &str, value: &str) -> bool {
    attributes
        .iter()
        .any(|attribute| attribute.key == key && attribute.value == value)
}

fn set_request_path(signal: &mut SignalEnvelope, path: &str) {
    let SignalPayload::ProtocolRequestObservation(request) = &mut signal.payload else {
        panic!("expected protocol request");
    };
    request.attributes.push(TraceAttribute {
        key: "url.path".to_string(),
        value: path.to_string(),
    });
}

fn protocol_request_signal(traceparent: Option<String>, attributed: bool) -> SignalEnvelope {
    protocol_request_signal_at(1_000, traceparent, attributed)
}

fn protocol_request_signal_at(
    start_unix_nanos: u64,
    traceparent: Option<String>,
    attributed: bool,
) -> SignalEnvelope {
    let (trace_id, span_id) = if traceparent.as_deref() == Some(valid_traceparent().as_str()) {
        (
            Some("4bf92f3577b34da6a3ce929d0e0e4736".to_string()),
            Some("00f067aa0ba902b7".to_string()),
        )
    } else {
        (None, None)
    };
    let (container, kubernetes) = attribution(attributed);
    SignalEnvelope::protocol_request_observation(
        "source.protocol_fixture",
        Some("node-a".to_string()),
        ProtocolRequestObservation {
            protocol: ProtocolKind::Http,
            start_unix_nanos,
            end_unix_nanos: Some(start_unix_nanos + 1_500),
            duration_nanos: Some(1_500),
            trace_id,
            span_id,
            parent_span_id: None,
            traceparent,
            tracestate: None,
            correlation_kind: TraceCorrelationKind::ProtocolObserved,
            confidence: TraceConfidence::Medium,
            service_name: Some("checkout-api".to_string()),
            method: Some("GET".to_string()),
            status_code: Some(200),
            process: Some(process()),
            container,
            kubernetes,
            peer: Some(peer()),
            attributes: vec![TraceAttribute {
                key: "http.request.method".to_string(),
                value: "GET".to_string(),
            }],
        },
    )
}

fn network_close_signal() -> SignalEnvelope {
    SignalEnvelope::network_connection_close(
        "source.test",
        Some("node-a".to_string()),
        NetworkConnectionCloseEvent {
            process: process(),
            protocol: NetworkProtocol::Tcp,
            address_family: NetworkAddressFamily::Ipv4,
            local_address: Some("10.0.0.5".to_string()),
            local_port: Some(43512),
            remote_address: "203.0.113.10".to_string(),
            remote_port: 443,
            fd: Some(7),
            opened_at_unix_nanos: Some(1_000),
            closed_at_unix_nanos: 2_000,
            duration_nanos: Some(1_000),
            bytes_sent: None,
            bytes_received: None,
            container: Some(container()),
            kubernetes: Some(kubernetes()),
        },
    )
}

fn valid_traceparent() -> String {
    "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01".to_string()
}

fn attribution(attributed: bool) -> (Option<ContainerContext>, Option<KubernetesContext>) {
    if attributed {
        (Some(container()), Some(kubernetes()))
    } else {
        (None, None)
    }
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
