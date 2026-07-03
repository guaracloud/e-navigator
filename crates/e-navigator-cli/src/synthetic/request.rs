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

    let mut signals = vec![
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
                start_unix_nanos: started.saturating_add(duration_nanos + 5_000),
                end_unix_nanos: Some(started.saturating_add(duration_nanos + 6_000)),
                duration_nanos: Some(1_000),
                trace_id: None,
                span_id: None,
                parent_span_id: None,
                traceparent: None,
                tracestate: None,
                correlation_kind: TraceCorrelationKind::Synthetic,
                confidence: TraceConfidence::Medium,
                service_name: Some("synthetic-api".to_string()),
                method: Some("POST".to_string()),
                status_code: Some(503),
                process: Some(process.clone()),
                container: Some(container.clone()),
                kubernetes: Some(kubernetes.clone()),
                peer: Some(peer.clone()),
                attributes: vec![TraceAttribute {
                    key: "trace.synthetic.fixture".to_string(),
                    value: "http_protocol_error".to_string(),
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
            host.clone(),
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
                process: Some(process.clone()),
                container: Some(container.clone()),
                kubernetes: Some(kubernetes.clone()),
                peer: Some(peer.clone()),
                attributes: vec![TraceAttribute {
                    key: "trace.synthetic.fixture".to_string(),
                    value: "missing_trace_context_request".to_string(),
                }],
            },
        ),
    ];

    for (index, fixture) in protocol_fixtures().into_iter().enumerate() {
        let start = started.saturating_add(duration_nanos + 30_000 + (index as u64 * 10_000));
        let fixture_duration = 1_000 + index as u64;
        signals.push(SignalEnvelope::protocol_request_observation(
            super::source_name(),
            host.clone(),
            ProtocolRequestObservation {
                protocol: fixture.protocol,
                start_unix_nanos: start,
                end_unix_nanos: Some(start.saturating_add(fixture_duration)),
                duration_nanos: Some(fixture_duration),
                trace_id: None,
                span_id: None,
                parent_span_id: None,
                traceparent: None,
                tracestate: None,
                correlation_kind: TraceCorrelationKind::Synthetic,
                confidence: TraceConfidence::Medium,
                service_name: Some("synthetic-api".to_string()),
                method: Some(fixture.method.to_string()),
                status_code: None,
                process: Some(process.clone()),
                container: Some(container.clone()),
                kubernetes: Some(kubernetes.clone()),
                peer: Some(TracePeerContext {
                    address: Some(fixture.address.to_string()),
                    port: Some(fixture.port),
                    domain: Some(fixture.domain.to_string()),
                    workload: None,
                    container: None,
                }),
                attributes: fixture.attributes,
            },
        ));
    }

    signals
}

#[derive(Debug)]
struct ProtocolFixture {
    protocol: ProtocolKind,
    method: &'static str,
    address: &'static str,
    port: u16,
    domain: &'static str,
    attributes: Vec<TraceAttribute>,
}

fn protocol_fixtures() -> Vec<ProtocolFixture> {
    vec![
        ProtocolFixture {
            protocol: ProtocolKind::Grpc,
            method: "GetCart",
            address: "203.0.113.26",
            port: 443,
            domain: "grpc.example.com",
            attributes: vec![
                attr("rpc.system", "grpc"),
                attr("rpc.service", "checkout.v1.CheckoutService"),
                attr("rpc.method", "GetCart"),
                attr("trace.synthetic.fixture", "grpc_protocol_request"),
            ],
        },
        ProtocolFixture {
            protocol: ProtocolKind::Grpc,
            method: "GetCart",
            address: "203.0.113.26",
            port: 443,
            domain: "grpc.example.com",
            attributes: vec![
                attr("rpc.system", "grpc"),
                attr("rpc.service", "checkout.v1.CheckoutService"),
                attr("rpc.method", "GetCart"),
                attr("rpc.grpc.status_code", "13"),
                attr("trace.synthetic.fixture", "grpc_protocol_error"),
            ],
        },
        ProtocolFixture {
            protocol: ProtocolKind::Kafka,
            method: "produce",
            address: "203.0.113.20",
            port: 9092,
            domain: "kafka.example.com",
            attributes: vec![
                attr("messaging.system", "kafka"),
                attr("messaging.operation", "produce"),
                attr("messaging.kafka.client_id_present", "true"),
                attr("trace.synthetic.fixture", "kafka_protocol_request"),
            ],
        },
        ProtocolFixture {
            protocol: ProtocolKind::Kafka,
            method: "api_versions",
            address: "203.0.113.20",
            port: 9092,
            domain: "kafka.example.com",
            attributes: vec![
                attr("messaging.system", "kafka"),
                attr("messaging.operation", "api_versions"),
                attr("messaging.kafka.response.error_code", "35"),
                attr("error.type", "35"),
                attr("trace.synthetic.fixture", "kafka_protocol_error"),
            ],
        },
        ProtocolFixture {
            protocol: ProtocolKind::Mongodb,
            method: "find",
            address: "203.0.113.21",
            port: 27017,
            domain: "mongodb.example.com",
            attributes: vec![
                attr("db.system", "mongodb"),
                attr("db.operation", "find"),
                attr("trace.synthetic.fixture", "mongodb_protocol_request"),
            ],
        },
        ProtocolFixture {
            protocol: ProtocolKind::Mongodb,
            method: "find",
            address: "203.0.113.21",
            port: 27017,
            domain: "mongodb.example.com",
            attributes: vec![
                attr("db.system", "mongodb"),
                attr("db.response.status_code", "13"),
                attr("error.type", "13"),
                attr("trace.synthetic.fixture", "mongodb_protocol_error"),
            ],
        },
        ProtocolFixture {
            protocol: ProtocolKind::Mysql,
            method: "SELECT",
            address: "203.0.113.22",
            port: 3306,
            domain: "mysql.example.com",
            attributes: vec![
                attr("db.system", "mysql"),
                attr("db.operation", "SELECT"),
                attr("trace.synthetic.fixture", "mysql_protocol_request"),
            ],
        },
        ProtocolFixture {
            protocol: ProtocolKind::Mysql,
            method: "SELECT",
            address: "203.0.113.22",
            port: 3306,
            domain: "mysql.example.com",
            attributes: vec![
                attr("db.system", "mysql"),
                attr("db.response.status_code", "42000/1064"),
                attr("error.type", "42000/1064"),
                attr("trace.synthetic.fixture", "mysql_protocol_error"),
            ],
        },
        ProtocolFixture {
            protocol: ProtocolKind::Nats,
            method: "pub",
            address: "203.0.113.23",
            port: 4222,
            domain: "nats.example.com",
            attributes: vec![
                attr("messaging.system", "nats"),
                attr("messaging.operation", "pub"),
                attr("messaging.nats.subject_present", "true"),
                attr("trace.synthetic.fixture", "nats_protocol_request"),
            ],
        },
        ProtocolFixture {
            protocol: ProtocolKind::Nats,
            method: "pub",
            address: "203.0.113.23",
            port: 4222,
            domain: "nats.example.com",
            attributes: vec![
                attr("messaging.system", "nats"),
                attr("messaging.nats.status_code", "ERR"),
                attr("error.type", "nats_error"),
                attr("trace.synthetic.fixture", "nats_protocol_error"),
            ],
        },
        ProtocolFixture {
            protocol: ProtocolKind::Postgresql,
            method: "SELECT",
            address: "203.0.113.24",
            port: 5432,
            domain: "postgresql.example.com",
            attributes: vec![
                attr("db.system", "postgresql"),
                attr("db.operation", "SELECT"),
                attr("trace.synthetic.fixture", "postgresql_protocol_request"),
            ],
        },
        ProtocolFixture {
            protocol: ProtocolKind::Postgresql,
            method: "SELECT",
            address: "203.0.113.24",
            port: 5432,
            domain: "postgresql.example.com",
            attributes: vec![
                attr("db.system", "postgresql"),
                attr("db.response.status_code", "23505"),
                attr("error.type", "23505"),
                attr("trace.synthetic.fixture", "postgresql_protocol_error"),
            ],
        },
        ProtocolFixture {
            protocol: ProtocolKind::Redis,
            method: "GET",
            address: "203.0.113.25",
            port: 6379,
            domain: "redis.example.com",
            attributes: vec![
                attr("db.system", "redis"),
                attr("db.operation", "GET"),
                attr("db.redis.key_present", "true"),
                attr("trace.synthetic.fixture", "redis_protocol_request"),
            ],
        },
        ProtocolFixture {
            protocol: ProtocolKind::Redis,
            method: "GET",
            address: "203.0.113.25",
            port: 6379,
            domain: "redis.example.com",
            attributes: vec![
                attr("db.system", "redis"),
                attr("db.response.status_code", "WRONGTYPE"),
                attr("error.type", "redis_wrongtype"),
                attr("trace.synthetic.fixture", "redis_protocol_error"),
            ],
        },
    ]
}

fn attr(key: &str, value: &str) -> TraceAttribute {
    TraceAttribute {
        key: key.to_string(),
        value: value.to_string(),
    }
}
