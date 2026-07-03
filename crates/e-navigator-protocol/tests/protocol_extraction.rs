use e_navigator_protocol::{
    ProtocolExtractionConfig,
    grpc::{GrpcExtraction, parse_grpc_request_headers, parse_grpc_response_trailers},
    http::{HttpExtraction, parse_http_request, parse_http_response},
    kafka::{
        KafkaExtraction, parse_kafka_api_versions_response, parse_kafka_fetch_response,
        parse_kafka_produce_response, parse_kafka_request,
    },
    mongodb::{MongodbExtraction, parse_mongodb_message, parse_mongodb_response},
    mysql::{
        MysqlExtraction, parse_mysql_command, parse_mysql_error_response, parse_mysql_response,
    },
    nats::{NatsExtraction, parse_nats_command, parse_nats_response},
    postgres::{
        PostgresExtraction, parse_postgres_error_response, parse_postgres_message,
        parse_postgres_response,
    },
    redis::{RedisExtraction, parse_redis_command, parse_redis_response},
    trace_context::{TraceContextError, parse_traceparent},
};
use e_navigator_signals::ProtocolKind;
use proptest::prelude::*;

const VALID_TRACEPARENT: &str = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn valid_lowercase_traceparents_parse(
        version in lower_hex_string(2).prop_filter("reserved version is invalid", |value| value != "ff"),
        trace_id in non_zero_lower_hex_string(32),
        span_id in non_zero_lower_hex_string(16),
        flags in lower_hex_string(2),
    ) {
        let value = format!("{version}-{trace_id}-{span_id}-{flags}");

        let parsed = parse_traceparent(&value).expect("valid lowercase traceparent parses");

        prop_assert_eq!(parsed.version, version);
        prop_assert_eq!(parsed.trace_id, trace_id);
        prop_assert_eq!(parsed.span_id, span_id);
        prop_assert_eq!(parsed.flags, flags);
    }

    #[test]
    fn malformed_traceparent_lengths_reject(
        trace_id in lower_hex_string(0..40).prop_filter("exclude valid trace id length", |value| value.len() != 32),
        span_id in lower_hex_string(0..24).prop_filter("exclude valid span id length", |value| value.len() != 16),
        flags in lower_hex_string(0..6).prop_filter("exclude valid flags length", |value| value.len() != 2),
    ) {
        prop_assert_eq!(
            parse_traceparent(&format!("00-{trace_id}-00f067aa0ba902b7-01")).unwrap_err(),
            TraceContextError::Malformed
        );
        prop_assert_eq!(
            parse_traceparent(&format!("00-4bf92f3577b34da6a3ce929d0e0e4736-{span_id}-01")).unwrap_err(),
            TraceContextError::Malformed
        );
        prop_assert_eq!(
            parse_traceparent(&format!("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-{flags}")).unwrap_err(),
            TraceContextError::Malformed
        );
    }

    #[test]
    fn uppercase_traceparent_hex_rejects(
        trace_id in uppercase_hex_string(32),
        span_id in uppercase_hex_string(16),
        flags in uppercase_hex_string(2),
    ) {
        prop_assume!(trace_id.bytes().any(|byte| byte.is_ascii_uppercase()));
        prop_assume!(span_id.bytes().any(|byte| byte.is_ascii_uppercase()));
        prop_assume!(flags.bytes().any(|byte| byte.is_ascii_uppercase()));

        prop_assert_eq!(
            parse_traceparent(&format!("00-{trace_id}-00f067aa0ba902b7-01")).unwrap_err(),
            TraceContextError::InvalidHex
        );
        prop_assert_eq!(
            parse_traceparent(&format!("00-4bf92f3577b34da6a3ce929d0e0e4736-{span_id}-01")).unwrap_err(),
            TraceContextError::InvalidHex
        );
        prop_assert_eq!(
            parse_traceparent(&format!("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-{flags}")).unwrap_err(),
            TraceContextError::InvalidHex
        );
    }

    #[test]
    fn wrong_traceparent_separators_reject(separator in "[/:_| ]") {
        let value = format!(
            "00{separator}4bf92f3577b34da6a3ce929d0e0e4736{separator}00f067aa0ba902b7{separator}01"
        );

        prop_assert_eq!(parse_traceparent(&value).unwrap_err(), TraceContextError::Malformed);
    }

    #[test]
    fn arbitrary_http_fixture_bytes_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..=512)) {
        let config = ProtocolExtractionConfig {
            max_header_bytes: 256,
            max_request_line_bytes: 64,
            max_attributes: 2,
            max_tracestate_bytes: 32,
        };

        let _ = parse_http_request(&bytes, &config);
    }

    #[test]
    fn arbitrary_http_response_bytes_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..=512)) {
        let config = ProtocolExtractionConfig {
            max_header_bytes: 256,
            max_request_line_bytes: 64,
            max_attributes: 2,
            max_tracestate_bytes: 32,
        };

        let _ = parse_http_response(&bytes, &config);
    }

    #[test]
    fn arbitrary_grpc_header_bytes_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..=512)) {
        let config = ProtocolExtractionConfig {
            max_header_bytes: 256,
            max_request_line_bytes: 64,
            max_attributes: 3,
            max_tracestate_bytes: 32,
        };

        let _ = parse_grpc_request_headers(&bytes, &config);
    }

    #[test]
    fn arbitrary_grpc_trailer_bytes_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..=512)) {
        let config = ProtocolExtractionConfig {
            max_header_bytes: 256,
            max_request_line_bytes: 64,
            max_attributes: 2,
            max_tracestate_bytes: 32,
        };

        let _ = parse_grpc_response_trailers(&bytes, &config);
    }

    #[test]
    fn http_fixture_limits_are_respected(
        path in "[A-Za-z0-9/_-]{0,40}",
        tracestate in "[a-z0-9=,._-]{0,80}",
    ) {
        let bytes = format!(
            "GET /{path} HTTP/1.1\r\nTraceparent: {VALID_TRACEPARENT}\r\nTracestate: {tracestate}\r\nAuthorization: Bearer secret\r\nCookie: session=secret\r\n\r\n"
        );
        let config = ProtocolExtractionConfig {
            max_header_bytes: 256,
            max_request_line_bytes: 64,
            max_attributes: 1,
            max_tracestate_bytes: 16,
        };

        let parsed = parse_http_request(bytes.as_bytes(), &config);
        if let Ok(parsed) = parsed {
            prop_assert!(parsed.attributes.len() <= config.max_attributes);
            prop_assert!(parsed
                .tracestate
                .as_ref()
                .is_none_or(|value| value.len() <= config.max_tracestate_bytes));
            prop_assert!(!parsed
                .attributes
                .iter()
                .any(|attribute| attribute.value.contains("secret")));
        }
    }

    #[test]
    fn http_response_limits_are_respected(
        status in 100u16..=599,
        reason in "[A-Za-z0-9_.=/%+-]{0,80}",
    ) {
        let bytes = format!(
            "HTTP/1.1 {status} {reason}\r\nSet-Cookie: session=secret\r\nX-Error-Detail: {reason}\r\n\r\nbody"
        );
        let config = ProtocolExtractionConfig {
            max_header_bytes: 256,
            max_request_line_bytes: 128,
            max_attributes: 1,
            max_tracestate_bytes: 32,
        };

        let parsed = parse_http_response(bytes.as_bytes(), &config)
            .expect("bounded http response parses");
        prop_assert_eq!(parsed.status_code, status);
        prop_assert!(parsed.attributes.len() <= config.max_attributes);
        prop_assert!(!parsed
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("secret")));
    }

    #[test]
    fn arbitrary_redis_fixture_bytes_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..=512)) {
        let config = ProtocolExtractionConfig {
            max_header_bytes: 256,
            max_request_line_bytes: 64,
            max_attributes: 4,
            max_tracestate_bytes: 32,
        };

        let _ = parse_redis_command(&bytes, &config);
    }

    #[test]
    fn arbitrary_redis_response_bytes_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..=512)) {
        let config = ProtocolExtractionConfig {
            max_header_bytes: 256,
            max_request_line_bytes: 64,
            max_attributes: 4,
            max_tracestate_bytes: 32,
        };

        let _ = parse_redis_response(&bytes, &config);
    }

    #[test]
    fn redis_response_limits_are_respected(
        status in "[A-Za-z0-9_-]{1,64}",
        message in "[A-Za-z0-9_.=/%+-]{0,80}",
    ) {
        let bytes = format!("-{status} {message} secret-detail\r\n");
        let config = ProtocolExtractionConfig {
            max_header_bytes: 256,
            max_request_line_bytes: 64,
            max_attributes: 2,
            max_tracestate_bytes: 32,
        };

        let parsed = parse_redis_response(bytes.as_bytes(), &config)
            .expect("bounded redis error parses");
        let expected_status = status.to_ascii_uppercase();
        prop_assert_eq!(parsed.status_code.as_deref(), Some(expected_status.as_str()));
        prop_assert!(parsed.error_type.is_some());
        prop_assert!(parsed.attributes.len() <= config.max_attributes);
        prop_assert!(!parsed
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("secret")));
    }

    #[test]
    fn arbitrary_kafka_fixture_bytes_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..=512)) {
        let config = ProtocolExtractionConfig {
            max_header_bytes: 256,
            max_request_line_bytes: 64,
            max_attributes: 4,
            max_tracestate_bytes: 32,
        };

        let _ = parse_kafka_request(&bytes, &config);
    }

    #[test]
    fn arbitrary_kafka_response_bytes_never_panic(
        bytes in prop::collection::vec(any::<u8>(), 0..=512),
        api_version in 0i16..=4,
    ) {
        let config = ProtocolExtractionConfig {
            max_header_bytes: 256,
            max_request_line_bytes: 64,
            max_attributes: 4,
            max_tracestate_bytes: 32,
        };

        let _ = parse_kafka_api_versions_response(&bytes, api_version, &config);
        let _ = parse_kafka_produce_response(&bytes, api_version.min(4), &config);
        let _ = parse_kafka_fetch_response(&bytes, api_version.min(5), &config);
    }

    #[test]
    fn kafka_api_versions_response_limits_are_respected(
        error_code in 1i16..=1000,
    ) {
        let bytes = kafka_api_versions_response_frame(0, error_code, b"secret-broker-data");
        let config = ProtocolExtractionConfig {
            max_header_bytes: 256,
            max_request_line_bytes: 64,
            max_attributes: 3,
            max_tracestate_bytes: 32,
        };

        let parsed = parse_kafka_api_versions_response(&bytes, 0, &config)
            .expect("bounded kafka api versions response parses");
        let expected_status = error_code.to_string();
        prop_assert_eq!(parsed.status_code.as_str(), expected_status.as_str());
        prop_assert_eq!(parsed.error_type.as_deref(), Some(expected_status.as_str()));
        prop_assert!(parsed.attributes.len() <= config.max_attributes);
        prop_assert!(!parsed
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("secret")));
    }

    #[test]
    fn arbitrary_postgres_fixture_bytes_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..=512)) {
        let config = ProtocolExtractionConfig {
            max_header_bytes: 256,
            max_request_line_bytes: 64,
            max_attributes: 4,
            max_tracestate_bytes: 32,
        };

        let _ = parse_postgres_message(&bytes, &config);
    }

    #[test]
    fn arbitrary_postgres_response_bytes_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..=512)) {
        let config = ProtocolExtractionConfig {
            max_header_bytes: 256,
            max_request_line_bytes: 64,
            max_attributes: 4,
            max_tracestate_bytes: 32,
        };

        let _ = parse_postgres_response(&bytes, &config);
        let _ = parse_postgres_error_response(&bytes, &config);
    }

    #[test]
    fn postgres_error_response_limits_are_respected(
        sqlstate in "[A-Z0-9]{5}",
        message in "[A-Za-z0-9_.=/%+-]{0,80}",
    ) {
        let bytes = postgres_error_response_frame(sqlstate.as_bytes(), message.as_bytes());
        let config = ProtocolExtractionConfig {
            max_header_bytes: 256,
            max_request_line_bytes: 64,
            max_attributes: 2,
            max_tracestate_bytes: 32,
        };

        let parsed = parse_postgres_error_response(&bytes, &config)
            .expect("bounded postgres error parses");
        prop_assert_eq!(parsed.status_code.as_str(), sqlstate.as_str());
        prop_assert_eq!(parsed.error_type.as_deref(), Some(parsed.status_code.as_str()));
        prop_assert!(parsed.attributes.len() <= config.max_attributes);
        prop_assert!(!parsed
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("secret")));
    }

    #[test]
    fn arbitrary_mysql_fixture_bytes_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..=512)) {
        let config = ProtocolExtractionConfig {
            max_header_bytes: 256,
            max_request_line_bytes: 64,
            max_attributes: 4,
            max_tracestate_bytes: 32,
        };

        let _ = parse_mysql_command(&bytes, &config);
    }

    #[test]
    fn arbitrary_mysql_response_bytes_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..=512)) {
        let config = ProtocolExtractionConfig {
            max_header_bytes: 256,
            max_request_line_bytes: 64,
            max_attributes: 4,
            max_tracestate_bytes: 32,
        };

        let _ = parse_mysql_response(&bytes, &config);
        let _ = parse_mysql_error_response(&bytes, &config);
    }

    #[test]
    fn mysql_error_response_limits_are_respected(
        vendor_code in 1u16..=65535,
        sqlstate in "[A-Z0-9]{5}",
        message in "[A-Za-z0-9_.=/%+-]{0,80}",
    ) {
        let bytes = mysql_error_packet(vendor_code, Some(sqlstate.as_bytes()), message.as_bytes());
        let config = ProtocolExtractionConfig {
            max_header_bytes: 256,
            max_request_line_bytes: 64,
            max_attributes: 2,
            max_tracestate_bytes: 32,
        };

        let parsed = parse_mysql_error_response(&bytes, &config)
            .expect("bounded mysql error parses");
        let expected_status = format!("{sqlstate}/{vendor_code}");
        prop_assert_eq!(parsed.status_code.as_str(), expected_status.as_str());
        prop_assert_eq!(parsed.error_type.as_deref(), Some(parsed.status_code.as_str()));
        prop_assert!(parsed.attributes.len() <= config.max_attributes);
        prop_assert!(!parsed
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("secret")));
    }

    #[test]
    fn arbitrary_mongodb_fixture_bytes_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..=512)) {
        let config = ProtocolExtractionConfig {
            max_header_bytes: 256,
            max_request_line_bytes: 64,
            max_attributes: 4,
            max_tracestate_bytes: 32,
        };

        let _ = parse_mongodb_message(&bytes, &config);
    }

    #[test]
    fn arbitrary_mongodb_response_bytes_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..=512)) {
        let config = ProtocolExtractionConfig {
            max_header_bytes: 256,
            max_request_line_bytes: 64,
            max_attributes: 4,
            max_tracestate_bytes: 32,
        };

        let _ = parse_mongodb_response(&bytes, &config);
    }

    #[test]
    fn mongodb_response_limits_are_respected(
        code in 1i32..=65535,
        message in "[A-Za-z0-9_.=/%+-]{0,40}",
    ) {
        let bytes = mongodb_op_msg(&bson_mongodb_error_document(code, message.as_bytes()));
        let config = ProtocolExtractionConfig {
            max_header_bytes: 256,
            max_request_line_bytes: 128,
            max_attributes: 2,
            max_tracestate_bytes: 32,
        };

        let parsed = parse_mongodb_response(&bytes, &config)
            .expect("bounded mongodb error parses");
        let expected_status = code.to_string();
        prop_assert_eq!(parsed.status_code.as_str(), expected_status.as_str());
        prop_assert_eq!(parsed.error_type.as_deref(), Some(expected_status.as_str()));
        prop_assert!(parsed.attributes.len() <= config.max_attributes);
        prop_assert!(!parsed
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("secret")));
    }

    #[test]
    fn arbitrary_nats_fixture_bytes_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..=512)) {
        let config = ProtocolExtractionConfig {
            max_header_bytes: 256,
            max_request_line_bytes: 64,
            max_attributes: 4,
            max_tracestate_bytes: 32,
        };

        let _ = parse_nats_command(&bytes, &config);
    }

    #[test]
    fn arbitrary_nats_response_bytes_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..=512)) {
        let config = ProtocolExtractionConfig {
            max_header_bytes: 256,
            max_request_line_bytes: 64,
            max_attributes: 4,
            max_tracestate_bytes: 32,
        };

        let _ = parse_nats_response(&bytes, &config);
    }

    #[test]
    fn nats_response_limits_are_respected(
        message in "[A-Za-z0-9_.=/%+-]{0,40}",
    ) {
        let bytes = format!("-ERR {message} secret-detail\r\n");
        let config = ProtocolExtractionConfig {
            max_header_bytes: 256,
            max_request_line_bytes: 96,
            max_attributes: 2,
            max_tracestate_bytes: 32,
        };

        let parsed = parse_nats_response(bytes.as_bytes(), &config)
            .expect("bounded nats error parses");
        prop_assert_eq!(parsed.status_code.as_str(), "ERR");
        prop_assert_eq!(parsed.error_type.as_deref(), Some("nats_error"));
        prop_assert!(parsed.attributes.len() <= config.max_attributes);
        prop_assert!(!parsed
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("secret")));
    }

    #[test]
    fn grpc_fixture_limits_are_respected(
        service in "[A-Za-z0-9_.-]{1,40}",
        method in "[A-Za-z0-9_.-]{1,40}",
        tracestate in "[a-z0-9=,._-]{0,80}",
    ) {
        let bytes = format!(
            ":method: POST\n:path: /{service}/{method}\n:authority: checkout.example.com:443\ncontent-type: application/grpc\ntraceparent: {VALID_TRACEPARENT}\ntracestate: {tracestate}\nauthorization: Bearer secret\n\n"
        );
        let config = ProtocolExtractionConfig {
            max_header_bytes: 512,
            max_request_line_bytes: 64,
            max_attributes: 3,
            max_tracestate_bytes: 16,
        };

        let parsed = parse_grpc_request_headers(bytes.as_bytes(), &config)
            .expect("bounded grpc headers parse");
        prop_assert!(parsed.attributes.len() <= config.max_attributes);
        prop_assert!(parsed
            .tracestate
            .as_ref()
            .is_none_or(|value| value.len() <= config.max_tracestate_bytes));
        prop_assert!(!parsed
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("secret")));
    }

    #[test]
    fn grpc_trailer_limits_are_respected(
        status in 0u8..=16,
        message in "[A-Za-z0-9_.=/%+-]{0,80}",
    ) {
        let bytes = format!(
            "grpc-status: {status}\ngrpc-message: {message}\ngrpc-status-details-bin: c2VjcmV0\n\n"
        );
        let config = ProtocolExtractionConfig {
            max_header_bytes: 256,
            max_request_line_bytes: 64,
            max_attributes: 1,
            max_tracestate_bytes: 32,
        };

        let parsed = parse_grpc_response_trailers(bytes.as_bytes(), &config)
            .expect("bounded grpc trailers parse");
        prop_assert_eq!(parsed.status_code, u16::from(status));
        prop_assert!(parsed.attributes.len() <= config.max_attributes);
        prop_assert!(!parsed
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("secret")));
    }
}

#[test]
fn parses_valid_w3c_traceparent_strictly() {
    let context = parse_traceparent(VALID_TRACEPARENT).expect("traceparent parses");

    assert_eq!(context.version, "00");
    assert_eq!(context.trace_id, "4bf92f3577b34da6a3ce929d0e0e4736");
    assert_eq!(context.span_id, "00f067aa0ba902b7");
    assert_eq!(context.flags, "01");
}

#[test]
fn rejects_malformed_traceparents_and_all_zero_ids() {
    assert_eq!(
        parse_traceparent("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7").unwrap_err(),
        TraceContextError::Malformed
    );
    assert_eq!(
        parse_traceparent("00-zzzz2f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01").unwrap_err(),
        TraceContextError::InvalidHex
    );
    assert_eq!(
        parse_traceparent("00-4BF92F3577B34DA6A3CE929D0E0E4736-00f067aa0ba902b7-01").unwrap_err(),
        TraceContextError::InvalidHex
    );
    assert_eq!(
        parse_traceparent("ff-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01").unwrap_err(),
        TraceContextError::ReservedVersion
    );
    assert_eq!(
        parse_traceparent("00-00000000000000000000000000000000-00f067aa0ba902b7-01").unwrap_err(),
        TraceContextError::AllZeroTraceId
    );
    assert_eq!(
        parse_traceparent("00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01").unwrap_err(),
        TraceContextError::AllZeroSpanId
    );
}

#[test]
fn rejects_traceparent_length_and_separator_variants() {
    for value in [
        "",
        "00",
        "00-4bf92f3577b34da6a3ce929d0e0e473-00f067aa0ba902b7-01",
        "00-4bf92f3577b34da6a3ce929d0e0e473600-00f067aa0ba902b7-01",
        "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902-01",
        "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b700-01",
        "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-0",
        "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-011",
        "00:4bf92f3577b34da6a3ce929d0e0e4736:00f067aa0ba902b7:01",
        " 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
        "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01 ",
    ] {
        assert_eq!(
            parse_traceparent(value).unwrap_err(),
            TraceContextError::Malformed,
            "{value:?}"
        );
    }
}

#[test]
fn extracts_http_request_trace_context_from_bounded_fixture() {
    let bytes = b"GET /checkout/123 HTTP/1.1\r\nHost: api.example.com\r\nTraceparent: 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01\r\nTracestate: vendor=value\r\nAuthorization: Bearer secret\r\n\r\n";

    let extraction = parse_http_request(bytes, &ProtocolExtractionConfig::default())
        .expect("http request parses");

    assert_eq!(extraction.protocol, ProtocolKind::Http);
    assert_eq!(extraction.method.as_deref(), Some("GET"));
    assert_eq!(
        extraction.trace_context.as_ref().unwrap().trace_id,
        "4bf92f3577b34da6a3ce929d0e0e4736"
    );
    assert_eq!(
        extraction.trace_context.as_ref().unwrap().span_id,
        "00f067aa0ba902b7"
    );
    assert_eq!(extraction.tracestate.as_deref(), Some("vendor=value"));
    assert!(
        extraction.attributes.iter().any(|attribute| {
            attribute.key == "http.request.method" && attribute.value == "GET"
        })
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| { attribute.key == "url.path" && attribute.value == "/checkout/123" })
    );
}

#[test]
fn extracts_grpc_request_trace_context_from_decoded_http2_headers() {
    let bytes = b":method: POST\n:path: /checkout.v1.CheckoutService/GetCart\n:authority: checkout.example.com:8443\ncontent-type: application/grpc+proto\ntraceparent: 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01\ntracestate: vendor=value\nauthorization: Bearer secret\n\n";

    let extraction = parse_grpc_request_headers(bytes, &ProtocolExtractionConfig::default())
        .expect("grpc request headers parse");

    assert_eq!(extraction.protocol, ProtocolKind::Grpc);
    assert_eq!(extraction.method.as_deref(), Some("GetCart"));
    assert_eq!(
        extraction.trace_context.as_ref().unwrap().trace_id,
        "4bf92f3577b34da6a3ce929d0e0e4736"
    );
    assert_eq!(
        extraction.trace_context.as_ref().unwrap().span_id,
        "00f067aa0ba902b7"
    );
    assert_eq!(extraction.tracestate.as_deref(), Some("vendor=value"));
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "rpc.system" && attribute.value == "grpc")
    );
    assert!(extraction.attributes.iter().any(|attribute| {
        attribute.key == "rpc.service" && attribute.value == "checkout.v1.CheckoutService"
    }));
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "rpc.method" && attribute.value == "GetCart")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "server.address"
                && attribute.value == "checkout.example.com")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "server.port" && attribute.value == "8443")
    );
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("secret"))
    );
}

#[test]
fn extracts_grpc_status_from_decoded_http2_trailers() {
    let bytes = b"grpc-status: 13\ngrpc-message: internal%20database%20detail\ngrpc-status-details-bin: c2VjcmV0\n\n";

    let extraction = parse_grpc_response_trailers(bytes, &ProtocolExtractionConfig::default())
        .expect("grpc response trailers parse");

    assert_eq!(extraction.protocol, ProtocolKind::Grpc);
    assert_eq!(extraction.status_code, 13);
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| { attribute.key == "rpc.system" && attribute.value == "grpc" })
    );
    assert!(
        extraction.attributes.iter().any(|attribute| {
            attribute.key == "rpc.grpc.status_code" && attribute.value == "13"
        })
    );
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("database")
                || attribute.value.contains("c2VjcmV0"))
    );
}

#[test]
fn drops_malformed_grpc_authority_attributes() {
    for authority in [
        "checkout.example.com:70000",
        "checkout.example.com:notaport",
        "[2001:db8::1]invalid",
        "user@checkout.example.com",
        "checkout example.com",
        "checkout.example.com/path",
        "checkout\\example.com",
    ] {
        let bytes = format!(
            ":method: POST\n:path: /checkout.v1.CheckoutService/GetCart\n:authority: {authority}\ncontent-type: application/grpc\n\n"
        );
        let extraction =
            parse_grpc_request_headers(bytes.as_bytes(), &ProtocolExtractionConfig::default())
                .expect("grpc request headers parse without authority attributes");

        assert!(
            !extraction.attributes.iter().any(
                |attribute| attribute.key == "server.address" || attribute.key == "server.port"
            ),
            "{authority:?}"
        );
    }
}

#[test]
fn rejects_non_grpc_decoded_http2_headers() {
    for content_type in [
        "application/json",
        "application/grpc+",
        "application/grpc+proto; charset=utf-8",
    ] {
        let bytes = format!(":method: POST\n:path: /checkout\ncontent-type: {content_type}\n\n");

        assert_eq!(
            parse_grpc_request_headers(bytes.as_bytes(), &ProtocolExtractionConfig::default())
                .unwrap_err(),
            GrpcExtraction::MissingGrpcContentType,
            "{content_type:?}"
        );
    }
}

#[test]
fn rejects_grpc_headers_without_post_method() {
    for bytes in [
        b":path: /checkout.v1.CheckoutService/GetCart\ncontent-type: application/grpc\n\n"
            .as_slice(),
        b":method: GET\n:path: /checkout.v1.CheckoutService/GetCart\ncontent-type: application/grpc\n\n"
            .as_slice(),
    ] {
        assert_eq!(
            parse_grpc_request_headers(bytes, &ProtocolExtractionConfig::default()).unwrap_err(),
            GrpcExtraction::MissingGrpcMethod
        );
    }
}

#[test]
fn rejects_malformed_grpc_response_trailers() {
    let missing = b"grpc-message: no-status\n\n";
    let invalid = b"grpc-status: 17\n\n";
    let non_numeric = b"grpc-status: unavailable\n\n";

    assert_eq!(
        parse_grpc_response_trailers(missing, &ProtocolExtractionConfig::default()).unwrap_err(),
        GrpcExtraction::MissingGrpcStatus
    );
    assert_eq!(
        parse_grpc_response_trailers(invalid, &ProtocolExtractionConfig::default()).unwrap_err(),
        GrpcExtraction::InvalidGrpcStatus
    );
    assert_eq!(
        parse_grpc_response_trailers(non_numeric, &ProtocolExtractionConfig::default())
            .unwrap_err(),
        GrpcExtraction::InvalidGrpcStatus
    );
}

#[test]
fn reports_grpc_trace_context_warnings_without_inventing_ids() {
    let missing = b":method: POST\n:path: /checkout.v1.CheckoutService/GetCart\ncontent-type: application/grpc\n\n";
    let malformed = b":method: POST\n:path: /checkout.v1.CheckoutService/GetCart\ncontent-type: application/grpc\ntraceparent: 00-bad\n\n";

    let missing = parse_grpc_request_headers(missing, &ProtocolExtractionConfig::default())
        .expect("missing trace context still parses");
    let malformed = parse_grpc_request_headers(malformed, &ProtocolExtractionConfig::default())
        .expect("malformed trace context still parses");

    assert_eq!(missing.warning.as_deref(), Some("missing_trace_context"));
    assert!(missing.trace_context.is_none());
    assert_eq!(
        malformed.warning.as_deref(),
        Some("malformed_trace_context")
    );
    assert!(malformed.trace_context.is_none());
}

#[test]
fn extracts_http_request_path_without_query_or_fragment() {
    let bytes = b"GET /checkout/123?token=secret#frag HTTP/1.1\r\nHost: api.example.com\r\nTraceparent: 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01\r\n\r\n";

    let extraction = parse_http_request(bytes, &ProtocolExtractionConfig::default())
        .expect("http request parses");

    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| { attribute.key == "url.path" && attribute.value == "/checkout/123" })
    );
    assert!(!extraction
        .attributes
        .iter()
        .any(|attribute| attribute.value.contains("secret") || attribute.value.contains("frag")));
}

#[test]
fn extracts_http_response_status_without_reason_or_headers() {
    let bytes = b"HTTP/1.1 503 Service Unavailable\r\nSet-Cookie: session=secret\r\nX-Error-Detail: database offline\r\n\r\nbody";

    let extraction = parse_http_response(bytes, &ProtocolExtractionConfig::default())
        .expect("http response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Http);
    assert_eq!(extraction.status_code, 503);
    assert!(extraction.attributes.iter().any(|attribute| {
        attribute.key == "http.response.status_code" && attribute.value == "503"
    }));
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("Service")
                || attribute.value.contains("database")
                || attribute.value.contains("secret"))
    );
}

#[test]
fn rejects_malformed_http_response_status_lines() {
    let missing = b"HTTP/1.1\r\n\r\n";
    let malformed_version = b"HTTP/x 200 OK\r\n\r\n";
    let non_numeric = b"HTTP/1.1 OK\r\n\r\n";
    let out_of_range = b"HTTP/1.1 700 custom\r\n\r\n";
    let request = b"GET /checkout HTTP/1.1\r\n\r\n";

    assert_eq!(
        parse_http_response(missing, &ProtocolExtractionConfig::default()).unwrap_err(),
        HttpExtraction::MalformedResponseLine
    );
    assert_eq!(
        parse_http_response(malformed_version, &ProtocolExtractionConfig::default()).unwrap_err(),
        HttpExtraction::MalformedResponseLine
    );
    assert_eq!(
        parse_http_response(non_numeric, &ProtocolExtractionConfig::default()).unwrap_err(),
        HttpExtraction::InvalidStatusCode
    );
    assert_eq!(
        parse_http_response(out_of_range, &ProtocolExtractionConfig::default()).unwrap_err(),
        HttpExtraction::InvalidStatusCode
    );
    assert_eq!(
        parse_http_response(request, &ProtocolExtractionConfig::default()).unwrap_err(),
        HttpExtraction::MalformedResponseLine
    );
}

#[test]
fn extracts_bounded_http_request_id_without_secret_headers() {
    let bytes = b"GET /checkout/123 HTTP/1.1\r\nHost: api.example.com\r\nTraceparent: 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01\r\nX-Request-ID: req-12345\r\nAuthorization: Bearer secret\r\nCookie: session=secret\r\n\r\n";

    let extraction = parse_http_request(bytes, &ProtocolExtractionConfig::default())
        .expect("http request parses");

    assert!(
        extraction.attributes.iter().any(|attribute| {
            attribute.key == "http.request.id" && attribute.value == "req-12345"
        })
    );
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("secret"))
    );
}

#[test]
fn drops_oversized_http_request_id_attribute() {
    let request_id = "r".repeat(129);
    let bytes = format!(
        "GET /checkout/123 HTTP/1.1\r\nTraceparent: {VALID_TRACEPARENT}\r\nX-Request-ID: {request_id}\r\n\r\n"
    );

    let extraction = parse_http_request(bytes.as_bytes(), &ProtocolExtractionConfig::default())
        .expect("http request parses");

    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "http.request.id")
    );
}

#[test]
fn extracts_bounded_http_host_authority_without_secret_headers() {
    let bytes = b"GET /checkout/123 HTTP/1.1\r\nHost: checkout.example.com:8443\r\nTraceparent: 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01\r\nAuthorization: Bearer secret\r\nCookie: session=secret\r\n\r\n";

    let extraction = parse_http_request(bytes, &ProtocolExtractionConfig::default())
        .expect("http request parses");

    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "server.address"
                && attribute.value == "checkout.example.com")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "server.port" && attribute.value == "8443")
    );
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("secret"))
    );
}

#[test]
fn extracts_http_connect_authority_form_without_header_values() {
    let bytes = b"CONNECT checkout.example.com:443 HTTP/1.1\r\nTraceparent: 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01\r\nAuthorization: Bearer secret\r\n\r\n";

    let extraction = parse_http_request(bytes, &ProtocolExtractionConfig::default())
        .expect("http connect parses");

    assert_eq!(extraction.method.as_deref(), Some("CONNECT"));
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "server.address"
                && attribute.value == "checkout.example.com")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "server.port" && attribute.value == "443")
    );
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "url.path" || attribute.value.contains("secret"))
    );
}

#[test]
fn extracts_absolute_form_http_target_path_and_authority_without_secrets() {
    let bytes = b"GET https://checkout.example.com:8443/orders/123?token=secret#frag HTTP/1.1\r\nTraceparent: 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01\r\nAuthorization: Bearer secret\r\nCookie: session=secret\r\n\r\n";

    let extraction = parse_http_request(bytes, &ProtocolExtractionConfig::default())
        .expect("http request parses");

    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| { attribute.key == "url.path" && attribute.value == "/orders/123" })
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "server.address"
                && attribute.value == "checkout.example.com")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "server.port" && attribute.value == "8443")
    );
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("secret") || attribute.value.contains("frag"))
    );
}

#[test]
fn drops_malformed_and_oversized_http_host_authority_attributes() {
    for host in [
        "user:pass@checkout.example.com",
        "checkout.example.com:not-a-port",
        "checkout.example.com:70000",
    ] {
        let bytes = format!(
            "GET /checkout/123 HTTP/1.1\r\nHost: {host}\r\nTraceparent: {VALID_TRACEPARENT}\r\n\r\n"
        );

        let extraction = parse_http_request(bytes.as_bytes(), &ProtocolExtractionConfig::default())
            .expect("http request parses");

        assert!(
            !extraction.attributes.iter().any(
                |attribute| attribute.key == "server.address" || attribute.key == "server.port"
            ),
            "{host:?}"
        );
    }

    let oversized_host = "h".repeat(254);
    let bytes = format!(
        "GET /checkout/123 HTTP/1.1\r\nHost: {oversized_host}\r\nTraceparent: {VALID_TRACEPARENT}\r\n\r\n"
    );

    let extraction = parse_http_request(bytes.as_bytes(), &ProtocolExtractionConfig::default())
        .expect("http request parses");

    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "server.address" || attribute.key == "server.port")
    );
}

#[test]
fn drops_malformed_absolute_form_http_target_authority_attributes() {
    for target in [
        "ftp://checkout.example.com/orders/123",
        "https://user:pass@checkout.example.com/orders/123",
        "https://checkout.example.com:not-a-port/orders/123",
        "https://checkout.example.com:70000/orders/123",
    ] {
        let bytes = format!("GET {target} HTTP/1.1\r\nTraceparent: {VALID_TRACEPARENT}\r\n\r\n");

        let extraction = parse_http_request(bytes.as_bytes(), &ProtocolExtractionConfig::default())
            .expect("http request parses");

        assert!(
            !extraction
                .attributes
                .iter()
                .any(|attribute| attribute.key == "url.path"
                    || attribute.key == "server.address"
                    || attribute.key == "server.port"),
            "{target:?}"
        );
    }

    let oversized_host = "h".repeat(254);
    let target = format!("https://{oversized_host}/orders/123");
    let bytes = format!("GET {target} HTTP/1.1\r\nTraceparent: {VALID_TRACEPARENT}\r\n\r\n");

    let extraction = parse_http_request(bytes.as_bytes(), &ProtocolExtractionConfig::default())
        .expect("http request parses");

    assert!(!extraction.attributes.iter().any(|attribute| {
        attribute.key == "url.path"
            || attribute.key == "server.address"
            || attribute.key == "server.port"
    }));
}

#[test]
fn drops_malformed_http_connect_authority_attributes() {
    for target in [
        "user:pass@checkout.example.com:443",
        "checkout.example.com:not-a-port",
        "checkout.example.com:70000",
        "/not-authority-form",
    ] {
        let bytes =
            format!("CONNECT {target} HTTP/1.1\r\nTraceparent: {VALID_TRACEPARENT}\r\n\r\n");

        let extraction = parse_http_request(bytes.as_bytes(), &ProtocolExtractionConfig::default())
            .expect("http connect parses");

        assert!(
            !extraction.attributes.iter().any(
                |attribute| attribute.key == "server.address" || attribute.key == "server.port"
            ),
            "{target:?}"
        );
    }
}

#[test]
fn reports_missing_and_invalid_trace_context_without_inventing_ids() {
    let missing = parse_http_request(
        b"POST /orders HTTP/1.1\r\nHost: api.example.com\r\n\r\n",
        &ProtocolExtractionConfig::default(),
    )
    .expect("request without trace context parses");
    assert_eq!(missing.trace_context, None);
    assert_eq!(missing.warning.as_deref(), Some("missing_trace_context"));

    let malformed = parse_http_request(
        b"GET / HTTP/1.1\r\nTraceparent: 00-bad\r\n\r\n",
        &ProtocolExtractionConfig::default(),
    )
    .expect("request with malformed trace context still parses");
    assert_eq!(malformed.trace_context, None);
    assert_eq!(
        malformed.warning.as_deref(),
        Some("malformed_trace_context")
    );
}

#[test]
fn rejects_adversarial_http_header_fixtures_without_panicking() {
    let config = ProtocolExtractionConfig::default();

    assert_eq!(
        parse_http_request(b"\xff\xfe\xfd\r\n\r\n", &config).unwrap_err(),
        HttpExtraction::InvalidUtf8
    );
    assert_eq!(
        parse_http_request(b"GET\r\nHost: api.example.com\r\n\r\n", &config).unwrap_err(),
        HttpExtraction::MalformedRequestLine
    );
    assert_eq!(
        parse_http_request(b"GET / HTTP/x\r\nHost: api.example.com\r\n\r\n", &config).unwrap_err(),
        HttpExtraction::MalformedRequestLine
    );
    assert_eq!(
        parse_http_request(
            b"GET / HTTP/1.1 unexpected\r\nHost: api.example.com\r\n\r\n",
            &config
        )
        .unwrap_err(),
        HttpExtraction::MalformedRequestLine
    );
    assert_eq!(
        parse_http_request(b"GET / HTTP/1.1\nHost: api.example.com\n\n", &config).unwrap_err(),
        HttpExtraction::HeadersTooLong
    );

    let lowercase_method = parse_http_request(
        b"get / HTTP/1.1\r\nTraceparent: 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01\r\n\r\n",
        &config,
    )
    .expect("lowercase method is parsed without inventing normalized method context");
    assert_eq!(lowercase_method.method, None);
    assert!(lowercase_method.attributes.is_empty());
}

#[test]
fn enforces_fixed_header_request_line_tracestate_and_attribute_bounds() {
    let config = ProtocolExtractionConfig {
        max_header_bytes: 64,
        max_request_line_bytes: 16,
        max_attributes: 1,
        max_tracestate_bytes: 8,
    };

    assert_eq!(
        parse_http_request(
            b"GET /very-long-path HTTP/1.1\r\nHost: api.example.com\r\n\r\n",
            &config
        )
        .unwrap_err(),
        HttpExtraction::RequestLineTooLong
    );
    assert_eq!(
        parse_http_request(
            b"GET / HTTP/1.1\r\nHost: api.example.com\r\nX-A: 1\r\nX-B: 2\r\nX-C: 3\r\n\r\n",
            &config
        )
        .unwrap_err(),
        HttpExtraction::HeadersTooLong
    );

    let extraction = parse_http_request(
        b"GET / HTTP/1.1\r\nTraceparent: 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01\r\nTracestate: too-long-value\r\n\r\n",
        &ProtocolExtractionConfig {
            max_header_bytes: 256,
            max_request_line_bytes: 64,
            max_attributes: 1,
            max_tracestate_bytes: 8,
        },
    )
    .expect("bounded truncation parses deterministically");
    assert_eq!(extraction.tracestate, None);
    assert_eq!(extraction.attributes.len(), 1);
}

#[test]
fn extracts_redis_resp_command_without_raw_key_or_value() {
    let bytes = b"*3\r\n$3\r\nSET\r\n$16\r\ncustomer:pii:123\r\n$12\r\nsecret-value\r\n";

    let extraction = parse_redis_command(bytes, &ProtocolExtractionConfig::default())
        .expect("redis command parses");

    assert_eq!(extraction.protocol, ProtocolKind::Redis);
    assert_eq!(extraction.command.as_deref(), Some("SET"));
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "db.system" && attribute.value == "redis")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "db.operation" && attribute.value == "SET")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "db.redis.argument.count" && attribute.value == "2")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "db.redis.key_present" && attribute.value == "true")
    );
    assert!(!extraction.attributes.iter().any(
        |attribute| attribute.value.contains("customer") || attribute.value.contains("secret")
    ));
}

#[test]
fn extracts_redis_inline_command_without_raw_arguments() {
    let extraction = parse_redis_command(
        b"get customer:pii:123\r\n",
        &ProtocolExtractionConfig::default(),
    )
    .expect("inline redis command parses");

    assert_eq!(extraction.command.as_deref(), Some("GET"));
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "db.operation" && attribute.value == "GET")
    );
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("customer"))
    );
}

#[test]
fn extracts_redis_simple_response_status_without_message_values() {
    let extraction = parse_redis_response(
        b"+OK password-reset-complete\r\n",
        &ProtocolExtractionConfig::default(),
    )
    .expect("redis simple response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Redis);
    assert_eq!(extraction.status_code.as_deref(), Some("OK"));
    assert_eq!(extraction.error_type, None);
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "db.system" && attribute.value == "redis")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "db.response.status_code" && attribute.value == "OK")
    );
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("password"))
    );
}

#[test]
fn extracts_redis_integer_response_without_raw_count() {
    let extraction = parse_redis_response(b":42\r\n", &ProtocolExtractionConfig::default())
        .expect("integer parses");

    assert_eq!(extraction.protocol, ProtocolKind::Redis);
    assert_eq!(extraction.status_code.as_deref(), Some("OK"));
    assert_eq!(extraction.error_type, None);
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "db.response.status_code" && attribute.value == "OK")
    );
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("42"))
    );
}

#[test]
fn extracts_redis_resp3_scalar_responses_without_raw_values() {
    for bytes in [
        b"_\r\n".as_slice(),
        b"#t\r\n".as_slice(),
        b"#f\r\n".as_slice(),
        b",123.45\r\n".as_slice(),
        b"(-3492890328409238509324850943850943825024385\r\n".as_slice(),
    ] {
        let extraction = parse_redis_response(bytes, &ProtocolExtractionConfig::default())
            .expect("resp3 scalar response parses");

        assert_eq!(extraction.protocol, ProtocolKind::Redis);
        assert_eq!(extraction.status_code.as_deref(), Some("OK"));
        assert_eq!(extraction.error_type, None);
        assert!(
            extraction
                .attributes
                .iter()
                .any(|attribute| attribute.key == "db.response.status_code"
                    && attribute.value == "OK")
        );
        assert!(!extraction.attributes.iter().any(|attribute| {
            attribute.value.contains("123.45") || attribute.value.contains("349289")
        }));
    }
}

#[test]
fn extracts_redis_resp3_blob_responses_without_raw_values() {
    let verbatim = parse_redis_response(
        b"=16\r\ntxt:secret-value\r\n",
        &ProtocolExtractionConfig::default(),
    )
    .expect("resp3 verbatim string parses");

    assert_eq!(verbatim.protocol, ProtocolKind::Redis);
    assert_eq!(verbatim.status_code.as_deref(), Some("OK"));
    assert_eq!(verbatim.error_type, None);
    assert!(
        !verbatim
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("secret"))
    );

    let error = parse_redis_response(
        b"!15\r\nERR secret-data\r\n",
        &ProtocolExtractionConfig::default(),
    )
    .expect("resp3 blob error parses");

    assert_eq!(error.protocol, ProtocolKind::Redis);
    assert_eq!(error.status_code.as_deref(), Some("ERR"));
    assert_eq!(error.error_type.as_deref(), Some("redis_err"));
    assert!(
        error
            .attributes
            .iter()
            .any(|attribute| attribute.key == "error.type" && attribute.value == "redis_err")
    );
    assert!(
        !error
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("secret-data"))
    );
}

#[test]
fn extracts_redis_bulk_response_without_raw_value() {
    let extraction = parse_redis_response(
        b"$15\r\ncustomer-secret\r\n",
        &ProtocolExtractionConfig::default(),
    )
    .expect("bulk response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Redis);
    assert_eq!(extraction.status_code.as_deref(), Some("OK"));
    assert_eq!(extraction.error_type, None);
    assert!(!extraction.attributes.iter().any(
        |attribute| attribute.value.contains("customer") || attribute.value.contains("secret")
    ));
}

#[test]
fn extracts_redis_array_response_without_raw_values() {
    let extraction = parse_redis_response(
        b"*3\r\n$15\r\ncustomer-secret\r\n:42\r\n+OK hidden-details\r\n",
        &ProtocolExtractionConfig::default(),
    )
    .expect("array response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Redis);
    assert_eq!(extraction.status_code.as_deref(), Some("OK"));
    assert_eq!(extraction.error_type, None);
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "db.response.status_code" && attribute.value == "OK")
    );
    assert!(!extraction.attributes.iter().any(|attribute| {
        attribute.value.contains("customer")
            || attribute.value.contains("secret")
            || attribute.value.contains("42")
            || attribute.value.contains("hidden")
    }));
}

#[test]
fn extracts_redis_array_error_response_without_raw_error_message() {
    let extraction = parse_redis_response(
        b"*2\r\n$15\r\ncustomer-secret\r\n-WRONGTYPE secret-key type mismatch\r\n",
        &ProtocolExtractionConfig::default(),
    )
    .expect("array error response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Redis);
    assert_eq!(extraction.status_code.as_deref(), Some("WRONGTYPE"));
    assert_eq!(extraction.error_type.as_deref(), Some("redis_wrongtype"));
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "db.response.status_code"
                && attribute.value == "WRONGTYPE")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "error.type" && attribute.value == "redis_wrongtype")
    );
    assert!(!extraction.attributes.iter().any(
        |attribute| attribute.value.contains("customer") || attribute.value.contains("secret")
    ));
}

#[test]
fn extracts_redis_nested_array_response_without_raw_values() {
    let extraction = parse_redis_response(
        b"*2\r\n*2\r\n$15\r\ncustomer-secret\r\n:42\r\n+OK hidden-details\r\n",
        &ProtocolExtractionConfig::default(),
    )
    .expect("nested array response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Redis);
    assert_eq!(extraction.status_code.as_deref(), Some("OK"));
    assert_eq!(extraction.error_type, None);
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "db.response.status_code" && attribute.value == "OK")
    );
    assert!(!extraction.attributes.iter().any(|attribute| {
        attribute.value.contains("customer")
            || attribute.value.contains("secret")
            || attribute.value.contains("42")
            || attribute.value.contains("hidden")
    }));
}

#[test]
fn extracts_redis_nested_array_error_without_raw_error_message() {
    let extraction = parse_redis_response(
        b"*2\r\n*2\r\n$15\r\ncustomer-secret\r\n-BUSY secret script running\r\n+OK details\r\n",
        &ProtocolExtractionConfig::default(),
    )
    .expect("nested array error response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Redis);
    assert_eq!(extraction.status_code.as_deref(), Some("BUSY"));
    assert_eq!(extraction.error_type.as_deref(), Some("redis_busy"));
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "error.type" && attribute.value == "redis_busy")
    );
    assert!(!extraction.attributes.iter().any(
        |attribute| attribute.value.contains("customer") || attribute.value.contains("secret")
    ));
}

#[test]
fn extracts_redis_resp3_aggregate_responses_without_raw_values() {
    let set = parse_redis_response(
        b"~2\r\n$15\r\ncustomer-secret\r\n:42\r\n",
        &ProtocolExtractionConfig::default(),
    )
    .expect("resp3 set response parses");

    assert_eq!(set.protocol, ProtocolKind::Redis);
    assert_eq!(set.status_code.as_deref(), Some("OK"));
    assert_eq!(set.error_type, None);
    assert!(!set.attributes.iter().any(|attribute| {
        attribute.value.contains("customer")
            || attribute.value.contains("secret")
            || attribute.value.contains("42")
    }));

    let map = parse_redis_response(
        b"%2\r\n+field\r\n$15\r\ncustomer-secret\r\n+other\r\n-BUSY secret script\r\n",
        &ProtocolExtractionConfig::default(),
    )
    .expect("resp3 map response parses");

    assert_eq!(map.protocol, ProtocolKind::Redis);
    assert_eq!(map.status_code.as_deref(), Some("BUSY"));
    assert_eq!(map.error_type.as_deref(), Some("redis_busy"));
    assert!(
        map.attributes
            .iter()
            .any(|attribute| attribute.key == "error.type" && attribute.value == "redis_busy")
    );
    assert!(!map.attributes.iter().any(|attribute| {
        attribute.value.contains("field")
            || attribute.value.contains("customer")
            || attribute.value.contains("secret")
    }));
}

#[test]
fn extracts_redis_resp3_push_response_without_raw_values() {
    let push = parse_redis_response(
        b">3\r\n+message\r\n$15\r\ncustomer-secret\r\n-WRONGTYPE secret push detail\r\n",
        &ProtocolExtractionConfig::default(),
    )
    .expect("resp3 push response parses");

    assert_eq!(push.protocol, ProtocolKind::Redis);
    assert_eq!(push.status_code.as_deref(), Some("WRONGTYPE"));
    assert_eq!(push.error_type.as_deref(), Some("redis_wrongtype"));
    assert!(
        push.attributes
            .iter()
            .any(|attribute| attribute.key == "error.type" && attribute.value == "redis_wrongtype")
    );
    assert!(!push.attributes.iter().any(|attribute| {
        attribute.value.contains("message")
            || attribute.value.contains("customer")
            || attribute.value.contains("secret")
    }));
}

#[test]
fn extracts_redis_error_type_without_raw_error_message() {
    let extraction = parse_redis_response(
        b"-WRONGTYPE Operation against a key holding the wrong kind of value secret-key\r\n",
        &ProtocolExtractionConfig::default(),
    )
    .expect("redis error response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Redis);
    assert_eq!(extraction.status_code.as_deref(), Some("WRONGTYPE"));
    assert_eq!(extraction.error_type.as_deref(), Some("redis_wrongtype"));
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "db.response.status_code"
                && attribute.value == "WRONGTYPE")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "error.type" && attribute.value == "redis_wrongtype")
    );
    assert!(!extraction.attributes.iter().any(
        |attribute| attribute.value.contains("Operation") || attribute.value.contains("secret")
    ));
}

#[test]
fn enforces_redis_frame_attribute_and_bulk_bounds() {
    let bounded = parse_redis_command(
        b"*2\r\n$3\r\nGET\r\n$16\r\ncustomer:pii:123\r\n",
        &ProtocolExtractionConfig {
            max_header_bytes: 128,
            max_request_line_bytes: 64,
            max_attributes: 2,
            max_tracestate_bytes: 32,
        },
    )
    .expect("bounded redis command parses");
    assert_eq!(bounded.attributes.len(), 2);

    assert_eq!(
        parse_redis_command(
            b"*1\r\n$1025\r\nGET\r\n",
            &ProtocolExtractionConfig::default()
        )
        .unwrap_err(),
        RedisExtraction::BulkStringTooLong
    );
    assert_eq!(
        parse_redis_command(
            b"*1\r\n$64\r\nGET\r\n",
            &ProtocolExtractionConfig {
                max_header_bytes: 16,
                max_request_line_bytes: 64,
                max_attributes: 4,
                max_tracestate_bytes: 32,
            },
        )
        .unwrap_err(),
        RedisExtraction::FrameTooLong
    );
    assert_eq!(
        parse_redis_command(
            b"GET customer:pii:123\r\n",
            &ProtocolExtractionConfig {
                max_header_bytes: 128,
                max_request_line_bytes: 4,
                max_attributes: 4,
                max_tracestate_bytes: 32,
            },
        )
        .unwrap_err(),
        RedisExtraction::FrameTooLong
    );

    assert_eq!(
        parse_redis_response(
            b"+OK\r\n",
            &ProtocolExtractionConfig {
                max_header_bytes: 2,
                max_request_line_bytes: 64,
                max_attributes: 4,
                max_tracestate_bytes: 32,
            },
        )
        .unwrap_err(),
        RedisExtraction::FrameTooLong
    );
    assert_eq!(
        parse_redis_response(
            b"$64\r\nabc\r\n",
            &ProtocolExtractionConfig {
                max_header_bytes: 16,
                max_request_line_bytes: 64,
                max_attributes: 4,
                max_tracestate_bytes: 32,
            },
        )
        .unwrap_err(),
        RedisExtraction::FrameTooLong
    );
    assert_eq!(
        parse_redis_response(
            b"*65\r\n",
            &ProtocolExtractionConfig {
                max_header_bytes: 128,
                max_request_line_bytes: 64,
                max_attributes: 4,
                max_tracestate_bytes: 32,
            },
        )
        .unwrap_err(),
        RedisExtraction::FrameTooLong
    );
}

#[test]
fn rejects_malformed_and_unsupported_redis_fixtures() {
    let config = ProtocolExtractionConfig::default();

    assert_eq!(
        parse_redis_command(b"*0\r\n", &config).unwrap_err(),
        RedisExtraction::MalformedFrame
    );
    assert_eq!(
        parse_redis_command(b"*2\r\n+GET\r\n$3\r\nkey\r\n", &config).unwrap_err(),
        RedisExtraction::UnsupportedFrame
    );
    assert_eq!(
        parse_redis_command(b"*1\r\n$3\r\nG\xffT\r\n", &config).unwrap_err(),
        RedisExtraction::InvalidUtf8
    );
    assert_eq!(
        parse_redis_command(b"*2\r\n$3\r\nGET\r\n$3\r\nkey", &config).unwrap_err(),
        RedisExtraction::MalformedFrame
    );
    assert_eq!(
        parse_redis_response(b"+\r\n", &config).unwrap_err(),
        RedisExtraction::MalformedFrame
    );
    assert_eq!(
        parse_redis_response(b"+O\xff\r\n", &config).unwrap_err(),
        RedisExtraction::InvalidUtf8
    );
    assert_eq!(
        parse_redis_response(b"+OK!\r\n", &config).unwrap_err(),
        RedisExtraction::MalformedFrame
    );
    assert_eq!(
        parse_redis_response(b"-ERR!\r\n", &config).unwrap_err(),
        RedisExtraction::MalformedFrame
    );
    assert_eq!(
        parse_redis_response(b"_ignored\r\n", &config).unwrap_err(),
        RedisExtraction::MalformedFrame
    );
    assert_eq!(
        parse_redis_response(b"#x\r\n", &config).unwrap_err(),
        RedisExtraction::MalformedFrame
    );
    assert_eq!(
        parse_redis_response(b",\r\n", &config).unwrap_err(),
        RedisExtraction::MalformedFrame
    );
    assert_eq!(
        parse_redis_response(b",1.25\r\ntrailing", &config).unwrap_err(),
        RedisExtraction::MalformedFrame
    );
    assert_eq!(
        parse_redis_response(b"(12\r\ntrailing", &config).unwrap_err(),
        RedisExtraction::MalformedFrame
    );
    assert_eq!(
        parse_redis_response(b"=16\r\ntxt:secret-value", &config).unwrap_err(),
        RedisExtraction::MalformedFrame
    );
    assert_eq!(
        parse_redis_response(b"!15\r\nERR secret-data", &config).unwrap_err(),
        RedisExtraction::MalformedFrame
    );
    assert_eq!(
        parse_redis_response(b"!10\r\nERR \xff-data\r\n", &config).unwrap_err(),
        RedisExtraction::InvalidUtf8
    );
    assert_eq!(
        parse_redis_response(b"=1025\r\nignored\r\n", &config).unwrap_err(),
        RedisExtraction::BulkStringTooLong
    );
    assert_eq!(
        parse_redis_response(b"$3\r\nkey", &config).unwrap_err(),
        RedisExtraction::MalformedFrame
    );
    assert_eq!(
        parse_redis_response(b"$1025\r\nignored\r\n", &config).unwrap_err(),
        RedisExtraction::BulkStringTooLong
    );
    assert_eq!(
        parse_redis_response(b"*1\r\n+OK\r\ntrailing", &config).unwrap_err(),
        RedisExtraction::MalformedFrame
    );
    assert_eq!(
        parse_redis_response(b"*1\r\n*65\r\n", &config).unwrap_err(),
        RedisExtraction::FrameTooLong
    );
    assert_eq!(
        parse_redis_response(b"%65\r\n", &config).unwrap_err(),
        RedisExtraction::FrameTooLong
    );
    assert_eq!(
        parse_redis_response(b"%1\r\n+key\r\n", &config).unwrap_err(),
        RedisExtraction::MalformedFrame
    );
    assert_eq!(
        parse_redis_response(b"~1\r\n+OK\r\ntrailing", &config).unwrap_err(),
        RedisExtraction::MalformedFrame
    );
    assert_eq!(
        parse_redis_response(b">1\r\n+OK\r\ntrailing", &config).unwrap_err(),
        RedisExtraction::MalformedFrame
    );
}

#[test]
fn extracts_kafka_produce_request_without_client_topic_or_payload_values() {
    let bytes = kafka_request_frame(
        0,
        8,
        Some(b"secret-client"),
        b"topic.secret.name secret-payload",
    );

    let extraction =
        parse_kafka_request(&bytes, &ProtocolExtractionConfig::default()).expect("kafka parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation.as_deref(), Some("produce"));
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.system" && attribute.value == "kafka")
    );
    assert!(extraction.attributes.iter().any(|attribute| attribute.key
        == "messaging.operation"
        && attribute.value == "produce"));
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "0")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_version"
                && attribute.value == "8")
    );
    assert!(extraction.attributes.iter().any(|attribute| attribute.key
        == "messaging.kafka.client_id_present"
        && attribute.value == "true"));
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("secret")
                || attribute.value.contains("topic")
                || attribute.value.contains("payload"))
    );
}

#[test]
fn validates_kafka_produce_v2_request_without_topic_or_record_values() {
    let body = kafka_produce_request_body(&[("topic.secret.name", 0, b"secret-records")]);
    let bytes = kafka_request_frame(0, 2, Some(b"secret-client"), &body);

    let extraction = parse_kafka_request(&bytes, &ProtocolExtractionConfig::default())
        .expect("kafka produce v2 request parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation.as_deref(), Some("produce"));
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_version"
                && attribute.value == "2")
    );
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("secret")
                || attribute.value.contains("topic")
                || attribute.value.contains("records"))
    );
}

#[test]
fn extracts_kafka_flexible_api_versions_request_without_client_id_value() {
    let bytes = kafka_flexible_request_frame(
        18,
        3,
        Some(b"secret-flex-client"),
        b"\x0bsecret-app\x0fsecret-version\0",
    );

    let extraction = parse_kafka_request(&bytes, &ProtocolExtractionConfig::default())
        .expect("flexible kafka header parses");

    assert_eq!(extraction.operation.as_deref(), Some("api_versions"));
    assert!(extraction.attributes.iter().any(|attribute| attribute.key
        == "messaging.kafka.client_id_present"
        && attribute.value == "true"));
    assert!(!extraction.attributes.iter().any(|attribute| {
        attribute.value.contains("secret-flex-client")
            || attribute.value.contains("secret-app")
            || attribute.value.contains("secret-version")
    }));
}

#[test]
fn extracts_kafka_api_versions_ok_response_status() {
    let bytes = kafka_api_versions_response_frame(0, 0, b"secret-api-list");

    let extraction =
        parse_kafka_api_versions_response(&bytes, 0, &ProtocolExtractionConfig::default())
            .expect("api versions response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "api_versions");
    assert_eq!(extraction.status_code, "0");
    assert_eq!(extraction.error_type, None);
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.system" && attribute.value == "kafka")
    );
    assert!(extraction.attributes.iter().any(
        |attribute| attribute.key == "messaging.operation" && attribute.value == "api_versions"
    ));
    assert!(extraction.attributes.iter().any(|attribute| attribute.key
        == "messaging.kafka.response.error_code"
        && attribute.value == "0"));
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "error.type")
    );
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("secret"))
    );
}

#[test]
fn extracts_kafka_flexible_api_versions_error_response_without_raw_body_values() {
    let bytes = kafka_flexible_api_versions_response_frame(35, b"secret-api-list");

    let extraction =
        parse_kafka_api_versions_response(&bytes, 3, &ProtocolExtractionConfig::default())
            .expect("flexible api versions error response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.status_code, "35");
    assert_eq!(extraction.error_type.as_deref(), Some("35"));
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "18")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_version"
                && attribute.value == "3")
    );
    assert!(extraction.attributes.iter().any(|attribute| attribute.key
        == "messaging.kafka.response.error_code"
        && attribute.value == "35"));
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "error.type" && attribute.value == "35")
    );
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("secret"))
    );
}

#[test]
fn extracts_kafka_produce_ok_response_without_topic_values() {
    let bytes = kafka_produce_response_frame(0, 2, &[("orders.secret", 0)]);

    let extraction = parse_kafka_produce_response(&bytes, 2, &ProtocolExtractionConfig::default())
        .expect("produce ok response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "produce");
    assert_eq!(extraction.status_code, "0");
    assert_eq!(extraction.error_type, None);
    assert!(extraction.attributes.iter().any(|attribute| {
        attribute.key == "messaging.kafka.response.error_code" && attribute.value == "0"
    }));
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("orders")
                || attribute.value.contains("secret"))
    );
}

#[test]
fn extracts_kafka_produce_error_response_without_topic_values() {
    let bytes = kafka_produce_response_frame(0, 7, &[("orders.secret", 0), ("payments.secret", 6)]);

    let extraction = parse_kafka_produce_response(&bytes, 7, &ProtocolExtractionConfig::default())
        .expect("produce error response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "produce");
    assert_eq!(extraction.status_code, "6");
    assert_eq!(extraction.error_type.as_deref(), Some("6"));
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.operation" && attribute.value == "produce")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "0")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_version"
                && attribute.value == "7")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "error.type" && attribute.value == "6")
    );
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("orders")
                || attribute.value.contains("payments")
                || attribute.value.contains("secret"))
    );
}

#[test]
fn extracts_kafka_fetch_ok_response_without_topic_or_record_values() {
    let bytes = kafka_fetch_response_frame(0, 5, &[("orders.secret", 0, b"secret-records")]);

    let extraction = parse_kafka_fetch_response(&bytes, 5, &ProtocolExtractionConfig::default())
        .expect("fetch ok response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "fetch");
    assert_eq!(extraction.status_code, "0");
    assert_eq!(extraction.error_type, None);
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "1")
    );
    assert!(extraction.attributes.iter().any(|attribute| {
        attribute.key == "messaging.kafka.response.error_code" && attribute.value == "0"
    }));
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("orders")
                || attribute.value.contains("secret")
                || attribute.value.contains("record"))
    );
}

#[test]
fn extracts_kafka_fetch_error_response_without_topic_or_record_values() {
    let bytes = kafka_fetch_response_frame(
        0,
        4,
        &[
            ("orders.secret", 0, b"secret-records"),
            ("payments.secret", 6, b"more-secret-records"),
        ],
    );

    let extraction = parse_kafka_fetch_response(&bytes, 4, &ProtocolExtractionConfig::default())
        .expect("fetch error response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "fetch");
    assert_eq!(extraction.status_code, "6");
    assert_eq!(extraction.error_type.as_deref(), Some("6"));
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.operation" && attribute.value == "fetch")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_version"
                && attribute.value == "4")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "error.type" && attribute.value == "6")
    );
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("orders")
                || attribute.value.contains("payments")
                || attribute.value.contains("secret")
                || attribute.value.contains("record"))
    );
}

#[test]
fn enforces_kafka_frame_client_id_response_and_attribute_bounds() {
    let bounded = parse_kafka_request(
        &kafka_request_frame(3, 9, Some(b"client-a"), b"topic.secret"),
        &ProtocolExtractionConfig {
            max_header_bytes: 128,
            max_request_line_bytes: 64,
            max_attributes: 2,
            max_tracestate_bytes: 32,
        },
    )
    .expect("bounded kafka request parses");
    assert_eq!(bounded.attributes.len(), 2);

    let bounded_response = parse_kafka_api_versions_response(
        &kafka_api_versions_response_frame(0, 35, b"secret-api-list"),
        0,
        &ProtocolExtractionConfig {
            max_header_bytes: 128,
            max_request_line_bytes: 64,
            max_attributes: 2,
            max_tracestate_bytes: 32,
        },
    )
    .expect("bounded kafka response parses");
    assert_eq!(bounded_response.attributes.len(), 2);

    let bounded_produce_response = parse_kafka_produce_response(
        &kafka_produce_response_frame(0, 1, &[("orders.secret", 6)]),
        1,
        &ProtocolExtractionConfig {
            max_header_bytes: 128,
            max_request_line_bytes: 64,
            max_attributes: 2,
            max_tracestate_bytes: 32,
        },
    )
    .expect("bounded kafka produce response parses");
    assert_eq!(bounded_produce_response.attributes.len(), 2);

    let bounded_fetch_response = parse_kafka_fetch_response(
        &kafka_fetch_response_frame(0, 1, &[("orders.secret", 6, b"secret-records")]),
        1,
        &ProtocolExtractionConfig {
            max_header_bytes: 128,
            max_request_line_bytes: 64,
            max_attributes: 2,
            max_tracestate_bytes: 32,
        },
    )
    .expect("bounded kafka fetch response parses");
    assert_eq!(bounded_fetch_response.attributes.len(), 2);

    assert_eq!(
        parse_kafka_request(
            &kafka_request_frame(3, 9, Some(b"client-a"), b"topic.secret"),
            &ProtocolExtractionConfig {
                max_header_bytes: 16,
                max_request_line_bytes: 64,
                max_attributes: 4,
                max_tracestate_bytes: 32,
            },
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );

    assert_eq!(
        parse_kafka_request(
            &kafka_request_frame(3, 9, Some(b"client-a"), b""),
            &ProtocolExtractionConfig {
                max_header_bytes: 128,
                max_request_line_bytes: 4,
                max_attributes: 4,
                max_tracestate_bytes: 32,
            },
        )
        .unwrap_err(),
        KafkaExtraction::ClientIdTooLong
    );
    assert_eq!(
        parse_kafka_api_versions_response(
            &kafka_api_versions_response_frame(0, 35, b"secret-api-list"),
            0,
            &ProtocolExtractionConfig {
                max_header_bytes: 8,
                max_request_line_bytes: 64,
                max_attributes: 4,
                max_tracestate_bytes: 32,
            },
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );
    assert_eq!(
        parse_kafka_produce_response(
            &kafka_produce_response_frame(0, 1, &[("orders.secret", 6)]),
            1,
            &ProtocolExtractionConfig {
                max_header_bytes: 16,
                max_request_line_bytes: 64,
                max_attributes: 4,
                max_tracestate_bytes: 32,
            },
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );
    assert_eq!(
        parse_kafka_fetch_response(
            &kafka_fetch_response_frame(0, 1, &[("orders.secret", 6, b"secret-records")]),
            1,
            &ProtocolExtractionConfig {
                max_header_bytes: 16,
                max_request_line_bytes: 64,
                max_attributes: 4,
                max_tracestate_bytes: 32,
            },
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );
}

#[test]
fn rejects_malformed_and_unsupported_kafka_fixtures() {
    let config = ProtocolExtractionConfig::default();

    assert_eq!(
        parse_kafka_request(&[], &config).unwrap_err(),
        KafkaExtraction::MalformedFrame
    );
    assert_eq!(
        parse_kafka_request(&0_i32.to_be_bytes(), &config).unwrap_err(),
        KafkaExtraction::MalformedFrame
    );
    assert_eq!(
        parse_kafka_request(&kafka_request_frame(99, 0, None, b""), &config).unwrap_err(),
        KafkaExtraction::UnsupportedApiKey
    );
    assert_eq!(
        parse_kafka_request(&kafka_request_frame(18, 0, None, b"trailing"), &config).unwrap_err(),
        KafkaExtraction::MalformedFrame
    );
    assert_eq!(
        parse_kafka_request(&kafka_request_frame(0, 2, None, b"\0\x01"), &config).unwrap_err(),
        KafkaExtraction::MalformedFrame
    );
    let mut too_many_produce_topics = Vec::new();
    too_many_produce_topics.extend_from_slice(&1_i16.to_be_bytes());
    too_many_produce_topics.extend_from_slice(&1_000_i32.to_be_bytes());
    too_many_produce_topics.extend_from_slice(&1025_i32.to_be_bytes());
    assert_eq!(
        parse_kafka_request(
            &kafka_request_frame(0, 2, None, &too_many_produce_topics),
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );
    let body = kafka_produce_request_body(&[("topic.secret.name", 0, b"value")]);
    assert_eq!(
        parse_kafka_request(
            &kafka_request_frame(0, 2, None, &body),
            &ProtocolExtractionConfig {
                max_header_bytes: 128,
                max_request_line_bytes: 4,
                max_attributes: 4,
                max_tracestate_bytes: 32,
            },
        )
        .unwrap_err(),
        KafkaExtraction::ClientIdTooLong
    );
    assert_eq!(
        parse_kafka_request(
            &kafka_flexible_request_frame(18, 3, None, b"\0\x01\0"),
            &config
        )
        .unwrap_err(),
        KafkaExtraction::MalformedFrame
    );
    assert_eq!(
        parse_kafka_request(
            &kafka_flexible_request_frame(18, 3, None, b"\x0bsecret-app\x01\0"),
            &ProtocolExtractionConfig {
                max_header_bytes: 128,
                max_request_line_bytes: 4,
                max_attributes: 4,
                max_tracestate_bytes: 32,
            },
        )
        .unwrap_err(),
        KafkaExtraction::ClientIdTooLong
    );
    assert_eq!(
        parse_kafka_api_versions_response(&[], 0, &config).unwrap_err(),
        KafkaExtraction::MalformedFrame
    );
    assert_eq!(
        parse_kafka_api_versions_response(&kafka_frame(&0_i32.to_be_bytes()), 0, &config)
            .unwrap_err(),
        KafkaExtraction::MalformedFrame
    );
    assert_eq!(
        parse_kafka_api_versions_response(
            &kafka_flexible_api_versions_response_with_tags_frame(35, 17, b"secret"),
            3,
            &ProtocolExtractionConfig {
                max_header_bytes: 128,
                max_request_line_bytes: 4,
                max_attributes: 4,
                max_tracestate_bytes: 32,
            },
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );
    assert_eq!(
        parse_kafka_api_versions_response(
            &kafka_api_versions_response_frame(0, 35, b""),
            -1,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::UnsupportedApiVersion
    );
    assert_eq!(
        parse_kafka_produce_response(
            &kafka_produce_response_frame(0, 8, &[("orders", 0)]),
            8,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::UnsupportedApiVersion
    );
    assert_eq!(
        parse_kafka_produce_response(
            &kafka_produce_response_with_topic_count_frame(1025),
            1,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );
    assert_eq!(
        parse_kafka_produce_response(
            &kafka_produce_response_with_partition_count_frame(1025),
            1,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );
    assert_eq!(
        parse_kafka_fetch_response(
            &kafka_fetch_response_frame(0, 6, &[("orders", 0, b"")]),
            6,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::UnsupportedApiVersion
    );
    assert_eq!(
        parse_kafka_fetch_response(
            &kafka_fetch_response_with_topic_count_frame(1025),
            1,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );
    assert_eq!(
        parse_kafka_fetch_response(
            &kafka_fetch_response_with_partition_count_frame(1025),
            1,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );
    assert_eq!(
        parse_kafka_fetch_response(
            &kafka_fetch_response_with_record_len_frame(129),
            1,
            &ProtocolExtractionConfig {
                max_header_bytes: 128,
                max_request_line_bytes: 64,
                max_attributes: 4,
                max_tracestate_bytes: 32,
            },
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );

    let mut truncated = kafka_request_frame(3, 9, Some(b"client-a"), b"");
    truncated.truncate(8);
    assert_eq!(
        parse_kafka_request(&truncated, &config).unwrap_err(),
        KafkaExtraction::MalformedFrame
    );

    let mut truncated_response = kafka_produce_response_frame(0, 1, &[("orders", 6)]);
    truncated_response.truncate(10);
    assert_eq!(
        parse_kafka_produce_response(&truncated_response, 1, &config).unwrap_err(),
        KafkaExtraction::MalformedFrame
    );

    let mut truncated_fetch_response = kafka_fetch_response_frame(0, 5, &[("orders", 6, b"data")]);
    truncated_fetch_response.truncate(24);
    assert_eq!(
        parse_kafka_fetch_response(&truncated_fetch_response, 5, &config).unwrap_err(),
        KafkaExtraction::MalformedFrame
    );

    assert_eq!(
        parse_kafka_request(&kafka_request_frame(3, 9, Some(b"bad-\xff"), b""), &config)
            .unwrap_err(),
        KafkaExtraction::InvalidUtf8
    );
}

#[test]
fn extracts_postgres_simple_query_operation_without_raw_sql() {
    let bytes = postgres_frame(b'Q', b" select * from customers where token = 'secret'\0");

    let extraction = parse_postgres_message(&bytes, &ProtocolExtractionConfig::default())
        .expect("postgres simple query parses");

    assert_eq!(extraction.protocol, ProtocolKind::Postgresql);
    assert_eq!(extraction.operation.as_deref(), Some("SELECT"));
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "db.system" && attribute.value == "postgresql")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "db.operation" && attribute.value == "SELECT")
    );
    assert!(extraction.attributes.iter().any(|attribute| attribute.key
        == "db.postgresql.message.type"
        && attribute.value == "query"));
    assert!(!extraction.attributes.iter().any(
        |attribute| attribute.value.contains("customers") || attribute.value.contains("secret")
    ));
}

#[test]
fn extracts_postgres_parse_message_operation_without_statement_or_sql() {
    let mut body = Vec::new();
    body.extend_from_slice(b"prepared-secret-name\0");
    body.extend_from_slice(b"insert into orders values ($1, $2)\0");
    body.extend_from_slice(&2_u16.to_be_bytes());
    body.extend_from_slice(&23_u32.to_be_bytes());
    body.extend_from_slice(&25_u32.to_be_bytes());
    let bytes = postgres_frame(b'P', &body);

    let extraction = parse_postgres_message(&bytes, &ProtocolExtractionConfig::default())
        .expect("postgres parse message parses");

    assert_eq!(extraction.operation.as_deref(), Some("INSERT"));
    assert!(extraction.attributes.iter().any(|attribute| attribute.key
        == "db.postgresql.message.type"
        && attribute.value == "parse"));
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("prepared-secret-name")
                || attribute.value.contains("orders"))
    );
}

#[test]
fn extracts_postgres_bind_message_without_portal_statement_or_parameter_values() {
    let mut body = Vec::new();
    body.extend_from_slice(b"secret-portal-name\0");
    body.extend_from_slice(b"prepared-secret-name\0");
    body.extend_from_slice(&1_u16.to_be_bytes());
    body.extend_from_slice(&1_u16.to_be_bytes());
    body.extend_from_slice(&2_u16.to_be_bytes());
    body.extend_from_slice(&12_i32.to_be_bytes());
    body.extend_from_slice(b"secret-param");
    body.extend_from_slice(&(-1_i32).to_be_bytes());
    body.extend_from_slice(&1_u16.to_be_bytes());
    body.extend_from_slice(&0_u16.to_be_bytes());
    let bytes = postgres_frame(b'B', &body);

    let extraction = parse_postgres_message(&bytes, &ProtocolExtractionConfig::default())
        .expect("postgres bind message parses");

    assert_eq!(extraction.protocol, ProtocolKind::Postgresql);
    assert_eq!(extraction.operation.as_deref(), Some("BIND"));
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "db.operation" && attribute.value == "BIND")
    );
    assert!(extraction.attributes.iter().any(|attribute| attribute.key
        == "db.postgresql.message.type"
        && attribute.value == "bind"));
    assert!(!extraction.attributes.iter().any(
        |attribute| attribute.value.contains("secret") || attribute.value.contains("prepared")
    ));
}

#[test]
fn extracts_postgres_describe_message_without_statement_or_portal_name() {
    for (target, name) in [
        (b'S', b"prepared-secret-name".as_slice()),
        (b'P', b"secret-portal-name".as_slice()),
    ] {
        let mut body = Vec::new();
        body.push(target);
        body.extend_from_slice(name);
        body.push(0);
        let bytes = postgres_frame(b'D', &body);

        let extraction = parse_postgres_message(&bytes, &ProtocolExtractionConfig::default())
            .expect("postgres describe message parses");

        assert_eq!(extraction.protocol, ProtocolKind::Postgresql);
        assert_eq!(extraction.operation.as_deref(), Some("DESCRIBE"));
        assert!(
            extraction
                .attributes
                .iter()
                .any(|attribute| attribute.key == "db.operation" && attribute.value == "DESCRIBE")
        );
        assert!(
            extraction
                .attributes
                .iter()
                .any(|attribute| attribute.key == "db.postgresql.message.type"
                    && attribute.value == "describe")
        );
        assert!(
            !extraction
                .attributes
                .iter()
                .any(|attribute| attribute.value.contains("secret")
                    || attribute.value.contains("prepared"))
        );
    }
}

#[test]
fn extracts_postgres_close_message_without_statement_or_portal_name() {
    for (target, name) in [
        (b'S', b"prepared-secret-name".as_slice()),
        (b'P', b"secret-portal-name".as_slice()),
    ] {
        let mut body = Vec::new();
        body.push(target);
        body.extend_from_slice(name);
        body.push(0);
        let bytes = postgres_frame(b'C', &body);

        let extraction = parse_postgres_message(&bytes, &ProtocolExtractionConfig::default())
            .expect("postgres close message parses");

        assert_eq!(extraction.protocol, ProtocolKind::Postgresql);
        assert_eq!(extraction.operation.as_deref(), Some("CLOSE"));
        assert!(
            extraction
                .attributes
                .iter()
                .any(|attribute| attribute.key == "db.operation" && attribute.value == "CLOSE")
        );
        assert!(
            extraction
                .attributes
                .iter()
                .any(|attribute| attribute.key == "db.postgresql.message.type"
                    && attribute.value == "close")
        );
        assert!(
            !extraction
                .attributes
                .iter()
                .any(|attribute| attribute.value.contains("secret")
                    || attribute.value.contains("prepared"))
        );
    }
}

#[test]
fn extracts_postgres_password_message_without_password_value() {
    let bytes = postgres_frame(b'p', b"secret-password-value\0");

    let extraction = parse_postgres_message(&bytes, &ProtocolExtractionConfig::default())
        .expect("postgres password message parses");

    assert_eq!(extraction.protocol, ProtocolKind::Postgresql);
    assert_eq!(extraction.operation.as_deref(), Some("PASSWORD"));
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "db.operation" && attribute.value == "PASSWORD")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "db.postgresql.message.type"
                && attribute.value == "password")
    );
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("secret")
                || attribute.value.contains("password-value"))
    );
}

#[test]
fn extracts_postgres_execute_message_without_portal_name() {
    let mut body = Vec::new();
    body.extend_from_slice(b"secret-portal-name\0");
    body.extend_from_slice(&0_i32.to_be_bytes());
    let bytes = postgres_frame(b'E', &body);

    let extraction = parse_postgres_message(&bytes, &ProtocolExtractionConfig::default())
        .expect("postgres execute message parses");

    assert_eq!(extraction.protocol, ProtocolKind::Postgresql);
    assert_eq!(extraction.operation.as_deref(), Some("EXECUTE"));
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "db.operation" && attribute.value == "EXECUTE")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "db.postgresql.message.type"
                && attribute.value == "execute")
    );
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("secret-portal-name"))
    );
}

#[test]
fn extracts_postgres_function_call_message_without_argument_values() {
    let mut body = Vec::new();
    body.extend_from_slice(&12_345_u32.to_be_bytes());
    body.extend_from_slice(&1_u16.to_be_bytes());
    body.extend_from_slice(&1_u16.to_be_bytes());
    body.extend_from_slice(&2_u16.to_be_bytes());
    body.extend_from_slice(&5_i32.to_be_bytes());
    body.extend_from_slice(b"first");
    body.extend_from_slice(&(-1_i32).to_be_bytes());
    body.extend_from_slice(&1_u16.to_be_bytes());
    body.extend_from_slice(&1_u16.to_be_bytes());
    let bytes = postgres_frame(b'F', &body);

    let extraction = parse_postgres_message(&bytes, &ProtocolExtractionConfig::default())
        .expect("postgres function call message parses");

    assert_eq!(extraction.protocol, ProtocolKind::Postgresql);
    assert_eq!(extraction.operation.as_deref(), Some("FUNCTION_CALL"));
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "db.operation" && attribute.value == "FUNCTION_CALL")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "db.postgresql.message.type"
                && attribute.value == "function_call")
    );
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("12345")
                || attribute.value.contains("first"))
    );
}

#[test]
fn extracts_postgres_function_call_response_without_result_values() {
    for value in [Some(b"secret-function-result".as_slice()), None] {
        let bytes = postgres_function_call_response_frame(value);

        let extraction = parse_postgres_response(&bytes, &ProtocolExtractionConfig::default())
            .expect("postgres function call response parses");

        assert_eq!(extraction.protocol, ProtocolKind::Postgresql);
        assert_eq!(extraction.status_code, "OK");
        assert_eq!(extraction.error_type, None);
        assert!(extraction.attributes.iter().any(|attribute| {
            attribute.key == "db.response.status_code" && attribute.value == "OK"
        }));
        assert!(
            !extraction
                .attributes
                .iter()
                .any(|attribute| attribute.value.contains("secret")
                    || attribute.value.contains("function-result"))
        );
    }
}

#[test]
fn extracts_postgres_copy_messages_without_payload_values() {
    for (message_type, body, operation, message_type_name) in [
        (
            b'd',
            b"secret-copy-row\tvalue\n".as_slice(),
            "COPY_DATA",
            "copy_data",
        ),
        (b'c', b"".as_slice(), "COPY_DONE", "copy_done"),
        (
            b'f',
            b"secret-copy-failure-message\0".as_slice(),
            "COPY_FAIL",
            "copy_fail",
        ),
    ] {
        let bytes = postgres_frame(message_type, body);

        let extraction = parse_postgres_message(&bytes, &ProtocolExtractionConfig::default())
            .expect("postgres copy message parses");

        assert_eq!(extraction.protocol, ProtocolKind::Postgresql);
        assert_eq!(extraction.operation.as_deref(), Some(operation));
        assert!(
            extraction
                .attributes
                .iter()
                .any(|attribute| attribute.key == "db.operation" && attribute.value == operation)
        );
        assert!(
            extraction
                .attributes
                .iter()
                .any(|attribute| attribute.key == "db.postgresql.message.type"
                    && attribute.value == message_type_name)
        );
        assert!(
            !extraction
                .attributes
                .iter()
                .any(|attribute| attribute.value.contains("secret")
                    || attribute.value.contains("copy-row")
                    || attribute.value.contains("copy-failure"))
        );
    }
}

#[test]
fn extracts_postgres_copy_mode_responses_without_format_values() {
    for message_type in [b'G', b'H', b'W'] {
        let bytes = postgres_copy_mode_response_frame(message_type, &[0, 1]);

        let extraction = parse_postgres_response(&bytes, &ProtocolExtractionConfig::default())
            .expect("postgres copy mode response parses");

        assert_eq!(extraction.protocol, ProtocolKind::Postgresql);
        assert_eq!(extraction.status_code, "OK");
        assert_eq!(extraction.error_type, None);
        assert!(extraction.attributes.iter().any(|attribute| {
            attribute.key == "db.response.status_code" && attribute.value == "OK"
        }));
        assert!(
            !extraction
                .attributes
                .iter()
                .any(|attribute| attribute.value.contains("secret"))
        );
    }
}

#[test]
fn extracts_postgres_copy_data_responses_without_payload_values() {
    let bytes = postgres_frame(b'd', b"secret-copy-output-row\tvalue\n");

    let extraction = parse_postgres_response(&bytes, &ProtocolExtractionConfig::default())
        .expect("postgres copy data response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Postgresql);
    assert_eq!(extraction.status_code, "OK");
    assert_eq!(extraction.error_type, None);
    assert!(extraction.attributes.iter().any(|attribute| {
        attribute.key == "db.response.status_code" && attribute.value == "OK"
    }));
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("secret")
                || attribute.value.contains("copy-output"))
    );
}

#[test]
fn extracts_postgres_sync_message_without_payload_values() {
    let bytes = postgres_frame(b'S', b"");

    let extraction = parse_postgres_message(&bytes, &ProtocolExtractionConfig::default())
        .expect("postgres sync message parses");

    assert_eq!(extraction.protocol, ProtocolKind::Postgresql);
    assert_eq!(extraction.operation.as_deref(), Some("SYNC"));
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "db.operation" && attribute.value == "SYNC")
    );
    assert!(extraction.attributes.iter().any(|attribute| attribute.key
        == "db.postgresql.message.type"
        && attribute.value == "sync"));
}

#[test]
fn extracts_postgres_flush_message_without_payload_values() {
    let bytes = postgres_frame(b'H', b"");

    let extraction = parse_postgres_message(&bytes, &ProtocolExtractionConfig::default())
        .expect("postgres flush message parses");

    assert_eq!(extraction.protocol, ProtocolKind::Postgresql);
    assert_eq!(extraction.operation.as_deref(), Some("FLUSH"));
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "db.operation" && attribute.value == "FLUSH")
    );
    assert!(extraction.attributes.iter().any(|attribute| attribute.key
        == "db.postgresql.message.type"
        && attribute.value == "flush"));
}

#[test]
fn extracts_postgres_terminate_message_without_payload_values() {
    let bytes = postgres_frame(b'X', b"");

    let extraction = parse_postgres_message(&bytes, &ProtocolExtractionConfig::default())
        .expect("postgres terminate message parses");

    assert_eq!(extraction.protocol, ProtocolKind::Postgresql);
    assert_eq!(extraction.operation.as_deref(), Some("TERMINATE"));
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "db.operation" && attribute.value == "TERMINATE")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "db.postgresql.message.type"
                && attribute.value == "terminate")
    );
}

#[test]
fn extracts_postgres_operation_after_comments() {
    let bytes = postgres_frame(
        b'Q',
        b"/* application comment */\n-- request secret\nupdate accounts set balance = 0\0",
    );

    let extraction = parse_postgres_message(&bytes, &ProtocolExtractionConfig::default())
        .expect("postgres query with comments parses");

    assert_eq!(extraction.operation.as_deref(), Some("UPDATE"));
}

#[test]
fn extracts_postgres_command_complete_without_raw_tag() {
    let bytes = postgres_frame(b'C', b"INSERT 0 1 secret-row-count-context\0");

    let extraction = parse_postgres_response(&bytes, &ProtocolExtractionConfig::default())
        .expect("postgres command complete response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Postgresql);
    assert_eq!(extraction.status_code, "OK");
    assert_eq!(extraction.error_type, None);
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "db.system" && attribute.value == "postgresql")
    );
    assert!(extraction.attributes.iter().any(|attribute| {
        attribute.key == "db.response.status_code" && attribute.value == "OK"
    }));
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "error.type")
    );
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("secret"))
    );
}

#[test]
fn extracts_postgres_notification_response_without_channel_or_payload_values() {
    let bytes = postgres_notification_response_frame(b"secret_channel", b"secret payload");

    let extraction = parse_postgres_response(&bytes, &ProtocolExtractionConfig::default())
        .expect("postgres notification response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Postgresql);
    assert_eq!(extraction.status_code, "OK");
    assert_eq!(extraction.error_type, None);
    assert!(extraction.attributes.iter().any(|attribute| {
        attribute.key == "db.response.status_code" && attribute.value == "OK"
    }));
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("secret")
                || attribute.value.contains("channel")
                || attribute.value.contains("payload"))
    );
}

#[test]
fn extracts_postgres_negotiate_protocol_version_without_option_values() {
    let bytes = postgres_negotiate_protocol_version_frame(196_608, &[b"_pq_.secret_option"]);

    let extraction = parse_postgres_response(&bytes, &ProtocolExtractionConfig::default())
        .expect("postgres negotiate protocol response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Postgresql);
    assert_eq!(extraction.status_code, "OK");
    assert_eq!(extraction.error_type, None);
    assert!(extraction.attributes.iter().any(|attribute| {
        attribute.key == "db.response.status_code" && attribute.value == "OK"
    }));
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("196608")
                || attribute.value.contains("_pq_")
                || attribute.value.contains("secret"))
    );
}

#[test]
fn extracts_postgres_data_row_without_column_values() {
    let bytes = postgres_data_row_frame(&[Some(b"secret-cell-value".as_slice()), None]);

    let extraction = parse_postgres_response(&bytes, &ProtocolExtractionConfig::default())
        .expect("postgres data row response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Postgresql);
    assert_eq!(extraction.status_code, "OK");
    assert_eq!(extraction.error_type, None);
    assert!(extraction.attributes.iter().any(|attribute| {
        attribute.key == "db.response.status_code" && attribute.value == "OK"
    }));
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("secret")
                || attribute.value.contains("cell"))
    );
}

#[test]
fn extracts_postgres_authentication_responses_without_auth_payload_values() {
    let ok = parse_postgres_response(
        &postgres_authentication_frame(0, b""),
        &ProtocolExtractionConfig::default(),
    )
    .expect("postgres authentication ok parses");
    assert_eq!(ok.status_code, "OK");
    assert_eq!(ok.error_type, None);

    let md5 = parse_postgres_response(
        &postgres_authentication_frame(5, b"salt"),
        &ProtocolExtractionConfig::default(),
    )
    .expect("postgres md5 authentication parses");
    assert_eq!(md5.status_code, "AUTHENTICATION_REQUIRED");
    assert_eq!(md5.error_type, None);
    assert!(
        !md5.attributes
            .iter()
            .any(|attribute| attribute.value.contains("salt"))
    );

    let sasl = parse_postgres_response(
        &postgres_authentication_frame(10, b"SCRAM-SHA-256\0secret-mechanism\0\0"),
        &ProtocolExtractionConfig::default(),
    )
    .expect("postgres sasl authentication parses");
    assert_eq!(sasl.status_code, "AUTHENTICATION_REQUIRED");
    assert!(
        !sasl.attributes.iter().any(
            |attribute| attribute.value.contains("SCRAM") || attribute.value.contains("secret")
        )
    );
}

#[test]
fn extracts_postgres_backend_key_data_without_key_values() {
    let mut body = Vec::new();
    body.extend_from_slice(&12_345_i32.to_be_bytes());
    body.extend_from_slice(&67_890_i32.to_be_bytes());
    let bytes = postgres_frame(b'K', &body);

    let extraction = parse_postgres_response(&bytes, &ProtocolExtractionConfig::default())
        .expect("postgres backend key data response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Postgresql);
    assert_eq!(extraction.status_code, "OK");
    assert_eq!(extraction.error_type, None);
    assert!(extraction.attributes.iter().any(|attribute| {
        attribute.key == "db.response.status_code" && attribute.value == "OK"
    }));
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("12345")
                || attribute.value.contains("67890"))
    );
}

#[test]
fn extracts_postgres_empty_success_responses_without_payload_values() {
    for message_type in [b'1', b'2', b'3', b'I', b'n', b's'] {
        let bytes = postgres_frame(message_type, b"");

        let extraction = parse_postgres_response(&bytes, &ProtocolExtractionConfig::default())
            .expect("postgres empty success response parses");

        assert_eq!(extraction.protocol, ProtocolKind::Postgresql);
        assert_eq!(extraction.status_code, "OK");
        assert_eq!(extraction.error_type, None);
        assert!(
            extraction
                .attributes
                .iter()
                .any(|attribute| attribute.key == "db.response.status_code"
                    && attribute.value == "OK")
        );
        assert!(
            !extraction
                .attributes
                .iter()
                .any(|attribute| attribute.value.contains("secret"))
        );
    }
}

#[test]
fn extracts_postgres_parameter_status_without_parameter_values() {
    let bytes = postgres_frame(b'S', b"application_name\0secret-client-name\0");

    let extraction = parse_postgres_response(&bytes, &ProtocolExtractionConfig::default())
        .expect("postgres parameter status response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Postgresql);
    assert_eq!(extraction.status_code, "OK");
    assert_eq!(extraction.error_type, None);
    assert!(extraction.attributes.iter().any(|attribute| {
        attribute.key == "db.response.status_code" && attribute.value == "OK"
    }));
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("application_name")
                || attribute.value.contains("secret"))
    );
}

#[test]
fn extracts_postgres_row_description_without_field_names() {
    let bytes = postgres_row_description_frame(&[b"secret_customer_token"]);

    let extraction = parse_postgres_response(&bytes, &ProtocolExtractionConfig::default())
        .expect("postgres row description response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Postgresql);
    assert_eq!(extraction.status_code, "OK");
    assert_eq!(extraction.error_type, None);
    assert!(extraction.attributes.iter().any(|attribute| {
        attribute.key == "db.response.status_code" && attribute.value == "OK"
    }));
    assert!(!extraction.attributes.iter().any(
        |attribute| attribute.value.contains("secret") || attribute.value.contains("customer")
    ));
}

#[test]
fn extracts_postgres_parameter_description_without_type_oids() {
    let bytes = postgres_parameter_description_frame(&[23, 25]);

    let extraction = parse_postgres_response(&bytes, &ProtocolExtractionConfig::default())
        .expect("postgres parameter description response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Postgresql);
    assert_eq!(extraction.status_code, "OK");
    assert_eq!(extraction.error_type, None);
    assert!(extraction.attributes.iter().any(|attribute| {
        attribute.key == "db.response.status_code" && attribute.value == "OK"
    }));
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("23") || attribute.value.contains("25"))
    );
}

#[test]
fn extracts_postgres_ready_for_query_status_without_raw_fields() {
    let bytes = postgres_frame(b'Z', b"I");

    let extraction = parse_postgres_response(&bytes, &ProtocolExtractionConfig::default())
        .expect("postgres ready response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Postgresql);
    assert_eq!(extraction.status_code, "OK");
    assert_eq!(extraction.error_type, None);
    assert!(extraction.attributes.iter().any(|attribute| {
        attribute.key == "db.response.status_code" && attribute.value == "OK"
    }));
    assert!(extraction.attributes.iter().any(|attribute| {
        attribute.key == "db.postgresql.transaction.status" && attribute.value == "idle"
    }));
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "error.type")
    );
}

#[test]
fn extracts_postgres_failed_transaction_ready_status() {
    let bytes = postgres_frame(b'Z', b"E");

    let extraction = parse_postgres_response(&bytes, &ProtocolExtractionConfig::default())
        .expect("postgres failed transaction ready response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Postgresql);
    assert_eq!(extraction.status_code, "FAILED_TRANSACTION");
    assert_eq!(
        extraction.error_type.as_deref(),
        Some("postgresql_failed_transaction")
    );
    assert!(extraction.attributes.iter().any(|attribute| {
        attribute.key == "db.response.status_code" && attribute.value == "FAILED_TRANSACTION"
    }));
    assert!(extraction.attributes.iter().any(|attribute| {
        attribute.key == "db.postgresql.transaction.status"
            && attribute.value == "failed_transaction"
    }));
    assert!(extraction.attributes.iter().any(|attribute| {
        attribute.key == "error.type" && attribute.value == "postgresql_failed_transaction"
    }));
}

#[test]
fn extracts_postgres_error_response_without_raw_message_fields() {
    let bytes =
        postgres_error_response_frame(b"23505", b"duplicate key value violates secret constraint");

    let extraction = parse_postgres_error_response(&bytes, &ProtocolExtractionConfig::default())
        .expect("postgres error response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Postgresql);
    assert_eq!(extraction.status_code, "23505");
    assert_eq!(extraction.error_type.as_deref(), Some("23505"));
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "db.system" && attribute.value == "postgresql")
    );
    assert!(extraction.attributes.iter().any(|attribute| {
        attribute.key == "db.response.status_code" && attribute.value == "23505"
    }));
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "error.type" && attribute.value == "23505")
    );
    assert!(!extraction.attributes.iter().any(
        |attribute| attribute.value.contains("duplicate") || attribute.value.contains("secret")
    ));
}

#[test]
fn extracts_postgres_notice_response_without_raw_message_fields() {
    let bytes =
        postgres_notice_response_frame(b"01000", b"secret notice detail should stay private");

    let extraction = parse_postgres_response(&bytes, &ProtocolExtractionConfig::default())
        .expect("postgres notice response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Postgresql);
    assert_eq!(extraction.status_code, "01000");
    assert_eq!(extraction.error_type, None);
    assert!(extraction.attributes.iter().any(|attribute| {
        attribute.key == "db.response.status_code" && attribute.value == "01000"
    }));
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "error.type")
    );
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("secret")
                || attribute.value.contains("notice detail"))
    );
}

#[test]
fn enforces_postgres_frame_query_and_attribute_bounds() {
    let bounded = parse_postgres_message(
        &postgres_frame(b'Q', b"select * from customers\0"),
        &ProtocolExtractionConfig {
            max_header_bytes: 128,
            max_request_line_bytes: 64,
            max_attributes: 2,
            max_tracestate_bytes: 32,
        },
    )
    .expect("bounded postgres query parses");
    assert_eq!(bounded.attributes.len(), 2);

    assert_eq!(
        parse_postgres_message(
            &postgres_frame(b'Q', b"select * from customers\0"),
            &ProtocolExtractionConfig {
                max_header_bytes: 16,
                max_request_line_bytes: 64,
                max_attributes: 4,
                max_tracestate_bytes: 32,
            },
        )
        .unwrap_err(),
        PostgresExtraction::FrameTooLong
    );

    assert_eq!(
        parse_postgres_message(
            &postgres_frame(b'Q', b"select * from customers\0"),
            &ProtocolExtractionConfig {
                max_header_bytes: 128,
                max_request_line_bytes: 4,
                max_attributes: 4,
                max_tracestate_bytes: 32,
            },
        )
        .unwrap_err(),
        PostgresExtraction::QueryTooLong
    );

    let mut oversized_bind = Vec::new();
    oversized_bind.extend_from_slice(b"portal\0statement\0");
    oversized_bind.extend_from_slice(&0_u16.to_be_bytes());
    oversized_bind.extend_from_slice(&1_u16.to_be_bytes());
    oversized_bind.extend_from_slice(&5_i32.to_be_bytes());
    oversized_bind.extend_from_slice(b"value");
    oversized_bind.extend_from_slice(&0_u16.to_be_bytes());
    assert_eq!(
        parse_postgres_message(
            &postgres_frame(b'B', &oversized_bind),
            &ProtocolExtractionConfig {
                max_header_bytes: 128,
                max_request_line_bytes: 4,
                max_attributes: 4,
                max_tracestate_bytes: 32,
            },
        )
        .unwrap_err(),
        PostgresExtraction::QueryTooLong
    );

    assert_eq!(
        parse_postgres_error_response(
            &postgres_error_response_frame(b"23505", b"duplicate key"),
            &ProtocolExtractionConfig {
                max_header_bytes: 8,
                max_request_line_bytes: 64,
                max_attributes: 4,
                max_tracestate_bytes: 32,
            },
        )
        .unwrap_err(),
        PostgresExtraction::FrameTooLong
    );

    let bounded_response = parse_postgres_response(
        &postgres_frame(b'Z', b"T"),
        &ProtocolExtractionConfig {
            max_header_bytes: 128,
            max_request_line_bytes: 64,
            max_attributes: 2,
            max_tracestate_bytes: 32,
        },
    )
    .expect("bounded postgres ready response parses");
    assert_eq!(bounded_response.attributes.len(), 2);
}

#[test]
fn rejects_malformed_and_unsupported_postgres_fixtures() {
    let config = ProtocolExtractionConfig::default();

    assert_eq!(
        parse_postgres_message(&[], &config).unwrap_err(),
        PostgresExtraction::MalformedFrame
    );
    assert_eq!(
        parse_postgres_message(&[b'Q', 0, 0, 0, 3], &config).unwrap_err(),
        PostgresExtraction::MalformedFrame
    );
    assert_eq!(
        parse_postgres_message(&postgres_frame(b'X', b"ignored\0"), &config).unwrap_err(),
        PostgresExtraction::MalformedFrame
    );
    assert_eq!(
        parse_postgres_message(&postgres_frame(b'Q', b"select 1"), &config).unwrap_err(),
        PostgresExtraction::MalformedFrame
    );
    assert_eq!(
        parse_postgres_message(&postgres_frame(b'Q', b"sel\xffct\0"), &config).unwrap_err(),
        PostgresExtraction::InvalidUtf8
    );
    assert_eq!(
        parse_postgres_message(&postgres_frame(b'B', b"portal\0statement\0"), &config).unwrap_err(),
        PostgresExtraction::MalformedFrame
    );
    let mut negative_bind = Vec::new();
    negative_bind.extend_from_slice(b"portal\0statement\0");
    negative_bind.extend_from_slice(&0_u16.to_be_bytes());
    negative_bind.extend_from_slice(&1_u16.to_be_bytes());
    negative_bind.extend_from_slice(&(-2_i32).to_be_bytes());
    negative_bind.extend_from_slice(&0_u16.to_be_bytes());
    assert_eq!(
        parse_postgres_message(&postgres_frame(b'B', &negative_bind), &config).unwrap_err(),
        PostgresExtraction::MalformedFrame
    );
    assert_eq!(
        parse_postgres_message(&postgres_frame(b'D', b"Xsecret\0"), &config).unwrap_err(),
        PostgresExtraction::MalformedFrame
    );
    assert_eq!(
        parse_postgres_message(&postgres_frame(b'D', b"Ssecret\0extra"), &config).unwrap_err(),
        PostgresExtraction::MalformedFrame
    );
    let long_describe = {
        let mut body = Vec::new();
        body.push(b'S');
        body.extend(std::iter::repeat_n(b'p', 129));
        body.push(0);
        body
    };
    assert_eq!(
        parse_postgres_message(&postgres_frame(b'D', &long_describe), &config).unwrap_err(),
        PostgresExtraction::QueryTooLong
    );
    assert_eq!(
        parse_postgres_message(&postgres_frame(b'C', b"Xsecret\0"), &config).unwrap_err(),
        PostgresExtraction::MalformedFrame
    );
    assert_eq!(
        parse_postgres_message(&postgres_frame(b'C', b"Ssecret\0extra"), &config).unwrap_err(),
        PostgresExtraction::MalformedFrame
    );
    assert_eq!(
        parse_postgres_message(&postgres_frame(b'p', b"secret\0extra"), &config).unwrap_err(),
        PostgresExtraction::MalformedFrame
    );
    assert_eq!(
        parse_postgres_message(
            &postgres_frame(b'p', b"secret-password-value\0"),
            &ProtocolExtractionConfig {
                max_header_bytes: 128,
                max_request_line_bytes: 4,
                max_attributes: 4,
                max_tracestate_bytes: 32,
            },
        )
        .unwrap_err(),
        PostgresExtraction::QueryTooLong
    );
    assert_eq!(
        parse_postgres_message(&postgres_frame(b'E', b"portal"), &config).unwrap_err(),
        PostgresExtraction::MalformedFrame
    );
    assert_eq!(
        parse_postgres_message(&postgres_frame(b'E', b"portal\0\x00\x00"), &config).unwrap_err(),
        PostgresExtraction::MalformedFrame
    );
    let long_portal = {
        let mut body = Vec::new();
        body.extend(std::iter::repeat_n(b'p', 129));
        body.push(0);
        body.extend_from_slice(&0_i32.to_be_bytes());
        body
    };
    assert_eq!(
        parse_postgres_message(&postgres_frame(b'E', &long_portal), &config).unwrap_err(),
        PostgresExtraction::QueryTooLong
    );
    assert_eq!(
        parse_postgres_message(&postgres_frame(b'F', b"\x00\x00"), &config).unwrap_err(),
        PostgresExtraction::MalformedFrame
    );
    let mut negative_function_call = Vec::new();
    negative_function_call.extend_from_slice(&12_345_u32.to_be_bytes());
    negative_function_call.extend_from_slice(&0_u16.to_be_bytes());
    negative_function_call.extend_from_slice(&1_u16.to_be_bytes());
    negative_function_call.extend_from_slice(&(-2_i32).to_be_bytes());
    negative_function_call.extend_from_slice(&0_u16.to_be_bytes());
    assert_eq!(
        parse_postgres_message(&postgres_frame(b'F', &negative_function_call), &config)
            .unwrap_err(),
        PostgresExtraction::MalformedFrame
    );
    let mut oversized_function_call = Vec::new();
    oversized_function_call.extend_from_slice(&12_345_u32.to_be_bytes());
    oversized_function_call.extend_from_slice(&0_u16.to_be_bytes());
    oversized_function_call.extend_from_slice(&1_u16.to_be_bytes());
    oversized_function_call.extend_from_slice(&5_i32.to_be_bytes());
    oversized_function_call.extend_from_slice(b"value");
    oversized_function_call.extend_from_slice(&0_u16.to_be_bytes());
    assert_eq!(
        parse_postgres_message(
            &postgres_frame(b'F', &oversized_function_call),
            &ProtocolExtractionConfig {
                max_header_bytes: 128,
                max_request_line_bytes: 4,
                max_attributes: 4,
                max_tracestate_bytes: 32,
            },
        )
        .unwrap_err(),
        PostgresExtraction::QueryTooLong
    );
    assert_eq!(
        parse_postgres_message(&postgres_frame(b'c', b"secret"), &config).unwrap_err(),
        PostgresExtraction::MalformedFrame
    );
    assert_eq!(
        parse_postgres_message(&postgres_frame(b'f', b"secret"), &config).unwrap_err(),
        PostgresExtraction::MalformedFrame
    );
    assert_eq!(
        parse_postgres_message(&postgres_frame(b'f', b"secret\0extra"), &config).unwrap_err(),
        PostgresExtraction::MalformedFrame
    );
    assert_eq!(
        parse_postgres_message(
            &postgres_frame(b'f', b"secret-copy-failure-message\0"),
            &ProtocolExtractionConfig {
                max_header_bytes: 128,
                max_request_line_bytes: 4,
                max_attributes: 4,
                max_tracestate_bytes: 32,
            },
        )
        .unwrap_err(),
        PostgresExtraction::QueryTooLong
    );
    assert_eq!(
        parse_postgres_message(&postgres_frame(b'S', b"secret"), &config).unwrap_err(),
        PostgresExtraction::MalformedFrame
    );
    assert_eq!(
        parse_postgres_message(&postgres_frame(b'H', b"secret"), &config).unwrap_err(),
        PostgresExtraction::MalformedFrame
    );
    assert_eq!(
        parse_postgres_message(&postgres_frame(b'X', b"secret"), &config).unwrap_err(),
        PostgresExtraction::MalformedFrame
    );
    assert_eq!(
        parse_postgres_error_response(&postgres_frame(b'Q', b"select 1\0"), &config).unwrap_err(),
        PostgresExtraction::UnsupportedMessage
    );
    assert_eq!(
        parse_postgres_error_response(&postgres_frame(b'C', b"SELECT 1\0"), &config).unwrap_err(),
        PostgresExtraction::UnsupportedMessage
    );
    assert_eq!(
        parse_postgres_error_response(
            &postgres_notice_response_frame(b"01000", b"secret notice"),
            &config,
        )
        .unwrap_err(),
        PostgresExtraction::UnsupportedMessage
    );
    assert_eq!(
        parse_postgres_response(&postgres_frame(b'Q', b"select 1\0"), &config).unwrap_err(),
        PostgresExtraction::UnsupportedMessage
    );
    assert_eq!(
        parse_postgres_response(&postgres_frame(b'A', b"\x00\x00\x00\x2achannel\0"), &config)
            .unwrap_err(),
        PostgresExtraction::MalformedFrame
    );
    assert_eq!(
        parse_postgres_response(
            &postgres_frame(b'A', b"\x00\x00\x00\x2achannel\0payload\0extra"),
            &config,
        )
        .unwrap_err(),
        PostgresExtraction::MalformedFrame
    );
    assert_eq!(
        parse_postgres_response(
            &postgres_notification_response_frame(b"secret_channel", b"secret payload"),
            &ProtocolExtractionConfig {
                max_header_bytes: 128,
                max_request_line_bytes: 4,
                max_attributes: 4,
                max_tracestate_bytes: 32,
            },
        )
        .unwrap_err(),
        PostgresExtraction::QueryTooLong
    );
    assert_eq!(
        parse_postgres_response(&postgres_frame(b'R', b""), &config).unwrap_err(),
        PostgresExtraction::MalformedFrame
    );
    assert_eq!(
        parse_postgres_response(&postgres_authentication_frame(5, b"sal"), &config).unwrap_err(),
        PostgresExtraction::MalformedFrame
    );
    assert_eq!(
        parse_postgres_response(
            &postgres_authentication_frame(10, b"SCRAM-SHA-256"),
            &config
        )
        .unwrap_err(),
        PostgresExtraction::MalformedFrame
    );
    assert_eq!(
        parse_postgres_response(&postgres_authentication_frame(99, b""), &config).unwrap_err(),
        PostgresExtraction::UnsupportedMessage
    );
    assert_eq!(
        parse_postgres_response(&postgres_frame(b'v', b"\x00\x03\x00\x00"), &config).unwrap_err(),
        PostgresExtraction::MalformedFrame
    );
    assert_eq!(
        parse_postgres_response(
            &postgres_frame(b'v', b"\x00\x03\x00\x00\xff\xff\xff\xff"),
            &config,
        )
        .unwrap_err(),
        PostgresExtraction::MalformedFrame
    );
    assert_eq!(
        parse_postgres_response(
            &postgres_frame(b'v', b"\x00\x03\x00\x00\x00\x00\x00\x01_pq_.secret"),
            &config,
        )
        .unwrap_err(),
        PostgresExtraction::MalformedFrame
    );
    assert_eq!(
        parse_postgres_response(
            &postgres_frame(b'v', b"\x00\x03\x00\x00\x00\x00\x04\x01"),
            &config,
        )
        .unwrap_err(),
        PostgresExtraction::QueryTooLong
    );
    assert_eq!(
        parse_postgres_response(
            &postgres_negotiate_protocol_version_frame(196_608, &[b"_pq_.secret_option"]),
            &ProtocolExtractionConfig {
                max_header_bytes: 128,
                max_request_line_bytes: 4,
                max_attributes: 4,
                max_tracestate_bytes: 32,
            },
        )
        .unwrap_err(),
        PostgresExtraction::QueryTooLong
    );
    assert_eq!(
        parse_postgres_response(&postgres_frame(b'G', b"\x00\x00"), &config).unwrap_err(),
        PostgresExtraction::MalformedFrame
    );
    assert_eq!(
        parse_postgres_response(&postgres_frame(b'G', b"\x00\x00\x01\x00"), &config).unwrap_err(),
        PostgresExtraction::MalformedFrame
    );
    assert_eq!(
        parse_postgres_response(
            &postgres_frame(b'G', &{
                let mut body = Vec::new();
                body.push(0);
                body.extend_from_slice(&1025_u16.to_be_bytes());
                body
            }),
            &config,
        )
        .unwrap_err(),
        PostgresExtraction::QueryTooLong
    );
    assert_eq!(
        parse_postgres_response(&postgres_frame(b'K', b"secret"), &config).unwrap_err(),
        PostgresExtraction::MalformedFrame
    );
    assert_eq!(
        parse_postgres_response(
            &postgres_authentication_frame(10, b"SCRAM-SHA-256\0\0"),
            &ProtocolExtractionConfig {
                max_header_bytes: 128,
                max_request_line_bytes: 4,
                max_attributes: 4,
                max_tracestate_bytes: 32,
            },
        )
        .unwrap_err(),
        PostgresExtraction::QueryTooLong
    );
    assert_eq!(
        parse_postgres_response(&postgres_frame(b'D', b"\x00\x01\xff\xff\xff\xfe"), &config)
            .unwrap_err(),
        PostgresExtraction::MalformedFrame
    );
    assert_eq!(
        parse_postgres_response(
            &postgres_frame(b'D', b"\x00\x01\x00\x00\x00\x06abc"),
            &config
        )
        .unwrap_err(),
        PostgresExtraction::MalformedFrame
    );
    assert_eq!(
        parse_postgres_response(
            &postgres_data_row_frame(&[Some(b"secret-cell-value".as_slice())]),
            &ProtocolExtractionConfig {
                max_header_bytes: 128,
                max_request_line_bytes: 4,
                max_attributes: 4,
                max_tracestate_bytes: 32,
            },
        )
        .unwrap_err(),
        PostgresExtraction::QueryTooLong
    );
    assert_eq!(
        parse_postgres_response(&postgres_frame(b'1', b"secret"), &config).unwrap_err(),
        PostgresExtraction::MalformedFrame
    );
    assert_eq!(
        parse_postgres_response(&postgres_frame(b'c', b"secret"), &config).unwrap_err(),
        PostgresExtraction::MalformedFrame
    );
    assert_eq!(
        parse_postgres_response(&postgres_frame(b'I', b"secret"), &config).unwrap_err(),
        PostgresExtraction::MalformedFrame
    );
    assert_eq!(
        parse_postgres_response(&postgres_frame(b's', b"secret"), &config).unwrap_err(),
        PostgresExtraction::MalformedFrame
    );
    assert_eq!(
        parse_postgres_response(&postgres_frame(b'S', b"application_name\0"), &config).unwrap_err(),
        PostgresExtraction::MalformedFrame
    );
    assert_eq!(
        parse_postgres_response(
            &postgres_frame(b'S', b"application_name\0secret\0extra"),
            &config
        )
        .unwrap_err(),
        PostgresExtraction::MalformedFrame
    );
    assert_eq!(
        parse_postgres_response(&postgres_frame(b'T', b"\x00\x01secret_name\0"), &config)
            .unwrap_err(),
        PostgresExtraction::MalformedFrame
    );
    assert_eq!(
        parse_postgres_response(&postgres_frame(b'V', b"\xff\xff\xff\xfe"), &config).unwrap_err(),
        PostgresExtraction::MalformedFrame
    );
    assert_eq!(
        parse_postgres_response(&postgres_frame(b'V', b"\x00\x00\x00\x06abc"), &config)
            .unwrap_err(),
        PostgresExtraction::MalformedFrame
    );
    assert_eq!(
        parse_postgres_response(
            &postgres_function_call_response_frame(Some(b"secret-function-result".as_slice())),
            &ProtocolExtractionConfig {
                max_header_bytes: 128,
                max_request_line_bytes: 4,
                max_attributes: 4,
                max_tracestate_bytes: 32,
            },
        )
        .unwrap_err(),
        PostgresExtraction::QueryTooLong
    );
    assert_eq!(
        parse_postgres_response(&postgres_frame(b't', b"\x00\x01\x00\x00"), &config).unwrap_err(),
        PostgresExtraction::MalformedFrame
    );
    assert_eq!(
        parse_postgres_response(
            &postgres_frame(b't', &{
                let mut body = Vec::new();
                body.extend_from_slice(&1025_u16.to_be_bytes());
                body
            }),
            &config,
        )
        .unwrap_err(),
        PostgresExtraction::QueryTooLong
    );
    assert_eq!(
        parse_postgres_response(&postgres_frame(b'Z', b""), &config).unwrap_err(),
        PostgresExtraction::MalformedFrame
    );
    assert_eq!(
        parse_postgres_response(&postgres_frame(b'Z', b"X"), &config).unwrap_err(),
        PostgresExtraction::MalformedFrame
    );
    assert_eq!(
        parse_postgres_error_response(&postgres_frame(b'E', b"Msecret message\0\0"), &config)
            .unwrap_err(),
        PostgresExtraction::MissingSqlstate
    );
    assert_eq!(
        parse_postgres_response(&postgres_frame(b'N', b"Msecret notice\0\0"), &config).unwrap_err(),
        PostgresExtraction::MissingSqlstate
    );
    assert_eq!(
        parse_postgres_error_response(
            &postgres_error_response_frame(b"23\xff05", b"secret message"),
            &config,
        )
        .unwrap_err(),
        PostgresExtraction::InvalidUtf8
    );
    assert_eq!(
        parse_postgres_error_response(
            &postgres_error_response_frame(b"23a05", b"secret message"),
            &config,
        )
        .unwrap_err(),
        PostgresExtraction::MalformedFrame
    );
    assert_eq!(
        parse_postgres_error_response(
            &postgres_error_response_frame(b"2350", b"secret message"),
            &config,
        )
        .unwrap_err(),
        PostgresExtraction::MalformedFrame
    );
    assert_eq!(
        parse_postgres_response(
            &postgres_notice_response_frame(b"01a00", b"secret notice"),
            &config,
        )
        .unwrap_err(),
        PostgresExtraction::MalformedFrame
    );
}

#[test]
fn extracts_mysql_query_operation_without_raw_sql() {
    let bytes = mysql_packet(0x03, b" select * from customers where token = 'secret'");

    let extraction =
        parse_mysql_command(&bytes, &ProtocolExtractionConfig::default()).expect("mysql parses");

    assert_eq!(extraction.protocol, ProtocolKind::Mysql);
    assert_eq!(extraction.operation.as_deref(), Some("SELECT"));
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "db.system" && attribute.value == "mysql")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "db.operation" && attribute.value == "SELECT")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "db.mysql.command" && attribute.value == "query")
    );
    assert!(!extraction.attributes.iter().any(
        |attribute| attribute.value.contains("customers") || attribute.value.contains("secret")
    ));
}

#[test]
fn extracts_mysql_connection_commands_without_schema_values() {
    for (command, payload, operation, command_name) in [
        (0x01, b"".as_slice(), "QUIT", "quit"),
        (0x02, b"secret_schema".as_slice(), "INIT_DB", "init_db"),
        (0x1f, b"".as_slice(), "RESET_CONNECTION", "reset_connection"),
    ] {
        let bytes = mysql_packet(command, payload);

        let extraction = parse_mysql_command(&bytes, &ProtocolExtractionConfig::default())
            .expect("mysql connection command parses");

        assert_eq!(extraction.protocol, ProtocolKind::Mysql);
        assert_eq!(extraction.operation.as_deref(), Some(operation));
        assert!(
            extraction
                .attributes
                .iter()
                .any(|attribute| attribute.key == "db.operation" && attribute.value == operation)
        );
        assert!(extraction.attributes.iter().any(
            |attribute| attribute.key == "db.mysql.command" && attribute.value == command_name
        ));
        assert!(
            !extraction
                .attributes
                .iter()
                .any(|attribute| attribute.value.contains("secret_schema"))
        );
    }
}

#[test]
fn extracts_mysql_stmt_prepare_operation_without_raw_sql() {
    let bytes = mysql_packet(0x16, b"insert into orders values (?, ?)");

    let extraction = parse_mysql_command(&bytes, &ProtocolExtractionConfig::default())
        .expect("mysql stmt prepare parses");

    assert_eq!(extraction.operation.as_deref(), Some("INSERT"));
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "db.mysql.command"
                && attribute.value == "stmt_prepare")
    );
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("orders"))
    );
}

#[test]
fn extracts_mysql_stmt_execute_operation_without_statement_or_parameter_values() {
    let mut payload = Vec::new();
    payload.extend_from_slice(&42_u32.to_le_bytes());
    payload.push(0);
    payload.extend_from_slice(&1_u32.to_le_bytes());
    payload.extend_from_slice(b"secret-binary-params");
    let bytes = mysql_packet(0x17, &payload);

    let extraction = parse_mysql_command(&bytes, &ProtocolExtractionConfig::default())
        .expect("mysql stmt execute parses");

    assert_eq!(extraction.protocol, ProtocolKind::Mysql);
    assert_eq!(extraction.operation.as_deref(), Some("EXECUTE"));
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "db.operation" && attribute.value == "EXECUTE")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "db.mysql.command"
                && attribute.value == "stmt_execute")
    );
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("42")
                || attribute.value.contains("secret")
                || attribute.value.contains("params"))
    );
}

#[test]
fn extracts_mysql_stmt_send_long_data_without_parameter_values() {
    let mut payload = Vec::new();
    payload.extend_from_slice(&42_u32.to_le_bytes());
    payload.extend_from_slice(&7_u16.to_le_bytes());
    payload.extend_from_slice(b"secret-long-parameter-value");
    let bytes = mysql_packet(0x18, &payload);

    let extraction = parse_mysql_command(&bytes, &ProtocolExtractionConfig::default())
        .expect("mysql stmt send long data parses");

    assert_eq!(extraction.protocol, ProtocolKind::Mysql);
    assert_eq!(extraction.operation.as_deref(), Some("SEND_LONG_DATA"));
    assert!(extraction.attributes.iter().any(|attribute| {
        attribute.key == "db.operation" && attribute.value == "SEND_LONG_DATA"
    }));
    assert!(extraction.attributes.iter().any(|attribute| {
        attribute.key == "db.mysql.command" && attribute.value == "stmt_send_long_data"
    }));
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("42")
                || attribute.value.contains("7")
                || attribute.value.contains("secret")
                || attribute.value.contains("parameter"))
    );
}

#[test]
fn extracts_mysql_stmt_lifecycle_operations_without_statement_ids() {
    for (command, payload, operation, command_name) in [
        (0x19, 42_u32.to_le_bytes().to_vec(), "CLOSE", "stmt_close"),
        (0x1a, 43_u32.to_le_bytes().to_vec(), "RESET", "stmt_reset"),
        (
            0x1c,
            [44_u32.to_le_bytes(), 10_u32.to_le_bytes()].concat(),
            "FETCH",
            "stmt_fetch",
        ),
    ] {
        let bytes = mysql_packet(command, &payload);

        let extraction = parse_mysql_command(&bytes, &ProtocolExtractionConfig::default())
            .expect("mysql stmt lifecycle command parses");

        assert_eq!(extraction.protocol, ProtocolKind::Mysql);
        assert_eq!(extraction.operation.as_deref(), Some(operation));
        assert!(
            extraction
                .attributes
                .iter()
                .any(|attribute| attribute.key == "db.operation" && attribute.value == operation)
        );
        assert!(extraction.attributes.iter().any(
            |attribute| attribute.key == "db.mysql.command" && attribute.value == command_name
        ));
        assert!(
            !extraction
                .attributes
                .iter()
                .any(|attribute| attribute.value.contains("42")
                    || attribute.value.contains("43")
                    || attribute.value.contains("44"))
        );
    }
}

#[test]
fn extracts_mysql_ping_operation_without_payload_values() {
    let bytes = mysql_packet(0x0e, b"");

    let extraction = parse_mysql_command(&bytes, &ProtocolExtractionConfig::default())
        .expect("mysql ping parses");

    assert_eq!(extraction.protocol, ProtocolKind::Mysql);
    assert_eq!(extraction.operation.as_deref(), Some("PING"));
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "db.operation" && attribute.value == "PING")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "db.mysql.command" && attribute.value == "ping")
    );
}

#[test]
fn extracts_mysql_operation_after_comments() {
    let bytes = mysql_packet(
        0x03,
        b"/* application comment */\n# secret note\nupdate accounts set balance = 0",
    );

    let extraction =
        parse_mysql_command(&bytes, &ProtocolExtractionConfig::default()).expect("mysql parses");

    assert_eq!(extraction.operation.as_deref(), Some("UPDATE"));
}

#[test]
fn extracts_mysql_ok_response_without_raw_session_state() {
    let bytes = mysql_ok_packet(b"\0\0\x02\0secret session state changed");

    let extraction = parse_mysql_response(&bytes, &ProtocolExtractionConfig::default())
        .expect("mysql ok parses");

    assert_eq!(extraction.protocol, ProtocolKind::Mysql);
    assert_eq!(extraction.status_code, "OK");
    assert_eq!(extraction.error_type, None);
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "db.system" && attribute.value == "mysql")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "db.response.status_code" && attribute.value == "OK")
    );
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "error.type")
    );
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("secret"))
    );
}

#[test]
fn extracts_mysql_eof_response_without_raw_status_flags() {
    let bytes = mysql_packet(0xfe, b"\0\0\x02\0");

    let extraction = parse_mysql_response(&bytes, &ProtocolExtractionConfig::default())
        .expect("mysql eof parses");

    assert_eq!(extraction.protocol, ProtocolKind::Mysql);
    assert_eq!(extraction.status_code, "EOF");
    assert_eq!(extraction.error_type, None);
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "db.system" && attribute.value == "mysql")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "db.response.status_code" && attribute.value == "EOF")
    );
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "error.type")
    );
}

#[test]
fn extracts_mysql_error_response_without_raw_message() {
    let bytes = mysql_error_packet(1064, Some(b"42000"), b"syntax near secret table customers");

    let extraction = parse_mysql_error_response(&bytes, &ProtocolExtractionConfig::default())
        .expect("mysql error response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Mysql);
    assert_eq!(extraction.status_code, "42000/1064");
    assert_eq!(extraction.error_type.as_deref(), Some("42000/1064"));
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "db.system" && attribute.value == "mysql")
    );
    assert!(extraction.attributes.iter().any(|attribute| {
        attribute.key == "db.response.status_code" && attribute.value == "42000/1064"
    }));
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "error.type" && attribute.value == "42000/1064")
    );
    assert!(!extraction.attributes.iter().any(
        |attribute| attribute.value.contains("secret") || attribute.value.contains("customers")
    ));
}

#[test]
fn extracts_mysql_error_response_without_sqlstate_marker() {
    let bytes = mysql_error_packet(1045, None, b"access denied for secret user");

    let extraction = parse_mysql_error_response(&bytes, &ProtocolExtractionConfig::default())
        .expect("mysql error response parses");

    assert_eq!(extraction.status_code, "1045");
    assert_eq!(extraction.error_type.as_deref(), Some("1045"));
    assert!(extraction.attributes.iter().any(|attribute| {
        attribute.key == "db.response.status_code" && attribute.value == "1045"
    }));
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("secret"))
    );
}

#[test]
fn enforces_mysql_packet_query_and_attribute_bounds() {
    let bounded = parse_mysql_command(
        &mysql_packet(0x03, b"select * from customers"),
        &ProtocolExtractionConfig {
            max_header_bytes: 128,
            max_request_line_bytes: 64,
            max_attributes: 2,
            max_tracestate_bytes: 32,
        },
    )
    .expect("bounded mysql query parses");
    assert_eq!(bounded.attributes.len(), 2);

    assert_eq!(
        parse_mysql_command(
            &mysql_packet(0x03, b"select * from customers"),
            &ProtocolExtractionConfig {
                max_header_bytes: 16,
                max_request_line_bytes: 64,
                max_attributes: 4,
                max_tracestate_bytes: 32,
            },
        )
        .unwrap_err(),
        MysqlExtraction::PacketTooLong
    );

    assert_eq!(
        parse_mysql_command(
            &mysql_packet(0x03, b"select * from customers"),
            &ProtocolExtractionConfig {
                max_header_bytes: 128,
                max_request_line_bytes: 4,
                max_attributes: 4,
                max_tracestate_bytes: 32,
            },
        )
        .unwrap_err(),
        MysqlExtraction::QueryTooLong
    );
    assert_eq!(
        parse_mysql_command(
            &mysql_packet(0x17, b"\x2a\0\0\0\0\x01\0\0\0secret"),
            &ProtocolExtractionConfig {
                max_header_bytes: 12,
                max_request_line_bytes: 64,
                max_attributes: 4,
                max_tracestate_bytes: 32,
            },
        )
        .unwrap_err(),
        MysqlExtraction::PacketTooLong
    );

    assert_eq!(
        parse_mysql_error_response(
            &mysql_error_packet(1064, Some(b"42000"), b"syntax error"),
            &ProtocolExtractionConfig {
                max_header_bytes: 8,
                max_request_line_bytes: 64,
                max_attributes: 4,
                max_tracestate_bytes: 32,
            },
        )
        .unwrap_err(),
        MysqlExtraction::PacketTooLong
    );

    let bounded_response = parse_mysql_response(
        &mysql_packet(0xfe, b"\0\0\x02\0"),
        &ProtocolExtractionConfig {
            max_header_bytes: 128,
            max_request_line_bytes: 64,
            max_attributes: 2,
            max_tracestate_bytes: 32,
        },
    )
    .expect("bounded mysql eof response parses");
    assert_eq!(bounded_response.attributes.len(), 2);
}

#[test]
fn rejects_malformed_and_unsupported_mysql_fixtures() {
    let config = ProtocolExtractionConfig::default();

    assert_eq!(
        parse_mysql_command(&[], &config).unwrap_err(),
        MysqlExtraction::MalformedPacket
    );
    assert_eq!(
        parse_mysql_command(&[0, 0, 0, 0], &config).unwrap_err(),
        MysqlExtraction::MalformedPacket
    );
    assert_eq!(
        parse_mysql_command(&mysql_packet(0x01, b"ignored"), &config).unwrap_err(),
        MysqlExtraction::MalformedPacket
    );

    let mut truncated = mysql_packet(0x03, b"select 1");
    truncated.truncate(5);
    assert_eq!(
        parse_mysql_command(&truncated, &config).unwrap_err(),
        MysqlExtraction::MalformedPacket
    );

    assert_eq!(
        parse_mysql_command(&mysql_packet(0x03, b"sel\xffct"), &config).unwrap_err(),
        MysqlExtraction::InvalidUtf8
    );
    assert_eq!(
        parse_mysql_command(&mysql_packet(0x02, b""), &config).unwrap_err(),
        MysqlExtraction::MalformedPacket
    );
    assert_eq!(
        parse_mysql_command(&mysql_packet(0x02, b"schema\xff"), &config).unwrap_err(),
        MysqlExtraction::InvalidUtf8
    );
    assert_eq!(
        parse_mysql_command(
            &mysql_packet(0x02, b"secret_schema"),
            &ProtocolExtractionConfig {
                max_header_bytes: 128,
                max_request_line_bytes: 4,
                max_attributes: 4,
                max_tracestate_bytes: 32,
            },
        )
        .unwrap_err(),
        MysqlExtraction::QueryTooLong
    );
    assert_eq!(
        parse_mysql_command(&mysql_packet(0x17, b"\x2a\0\0"), &config).unwrap_err(),
        MysqlExtraction::MalformedPacket
    );
    assert_eq!(
        parse_mysql_command(&mysql_packet(0x18, b"\x2a\0\0\0\x07"), &config).unwrap_err(),
        MysqlExtraction::MalformedPacket
    );
    let mut oversized_long_data = Vec::new();
    oversized_long_data.extend_from_slice(&42_u32.to_le_bytes());
    oversized_long_data.extend_from_slice(&7_u16.to_le_bytes());
    oversized_long_data.extend_from_slice(b"value");
    assert_eq!(
        parse_mysql_command(
            &mysql_packet(0x18, &oversized_long_data),
            &ProtocolExtractionConfig {
                max_header_bytes: 128,
                max_request_line_bytes: 4,
                max_attributes: 4,
                max_tracestate_bytes: 32,
            },
        )
        .unwrap_err(),
        MysqlExtraction::QueryTooLong
    );
    assert_eq!(
        parse_mysql_command(&mysql_packet(0x19, b"\x2a\0\0"), &config).unwrap_err(),
        MysqlExtraction::MalformedPacket
    );
    assert_eq!(
        parse_mysql_command(&mysql_packet(0x1a, b"\x2a\0\0\0extra"), &config).unwrap_err(),
        MysqlExtraction::MalformedPacket
    );
    assert_eq!(
        parse_mysql_command(&mysql_packet(0x1c, b"\x2a\0\0\0"), &config).unwrap_err(),
        MysqlExtraction::MalformedPacket
    );
    assert_eq!(
        parse_mysql_command(&mysql_packet(0x1f, b"secret"), &config).unwrap_err(),
        MysqlExtraction::MalformedPacket
    );
    assert_eq!(
        parse_mysql_command(&mysql_packet(0x0e, b"secret"), &config).unwrap_err(),
        MysqlExtraction::MalformedPacket
    );
    assert_eq!(
        parse_mysql_error_response(&mysql_packet(0x00, b"ok"), &config).unwrap_err(),
        MysqlExtraction::UnsupportedResponse
    );
    assert_eq!(
        parse_mysql_response(&mysql_packet(0x03, b"select 1"), &config).unwrap_err(),
        MysqlExtraction::UnsupportedResponse
    );
    assert_eq!(
        parse_mysql_response(&mysql_packet(0xfe, b"secret-payload"), &config).unwrap_err(),
        MysqlExtraction::UnsupportedResponse
    );
    assert_eq!(
        parse_mysql_error_response(&mysql_packet(0xfe, b"\0\0\x02\0"), &config).unwrap_err(),
        MysqlExtraction::UnsupportedResponse
    );

    let mut truncated_sqlstate = mysql_error_packet(1064, Some(b"42000"), b"secret");
    truncated_sqlstate.truncate(8);
    assert_eq!(
        parse_mysql_error_response(&truncated_sqlstate, &config).unwrap_err(),
        MysqlExtraction::MalformedPacket
    );

    let invalid_sqlstate = mysql_error_packet(1064, Some(b"42\xff00"), b"secret");
    assert_eq!(
        parse_mysql_error_response(&invalid_sqlstate, &config).unwrap_err(),
        MysqlExtraction::InvalidUtf8
    );

    let lowercase_sqlstate = mysql_error_packet(1064, Some(b"42a00"), b"secret");
    assert_eq!(
        parse_mysql_error_response(&lowercase_sqlstate, &config).unwrap_err(),
        MysqlExtraction::MalformedPacket
    );
}

#[test]
fn extracts_mongodb_op_msg_command_without_raw_bson_values() {
    let document = bson_command_document("find", "customers-secret");
    let bytes = mongodb_op_msg(&document);

    let extraction =
        parse_mongodb_message(&bytes, &ProtocolExtractionConfig::default()).expect("mongo parses");

    assert_eq!(extraction.protocol, ProtocolKind::Mongodb);
    assert_eq!(extraction.operation.as_deref(), Some("find"));
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "db.system" && attribute.value == "mongodb")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "db.operation" && attribute.value == "find")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "db.mongodb.opcode" && attribute.value == "op_msg")
    );
    assert!(!extraction.attributes.iter().any(
        |attribute| attribute.value.contains("customers") || attribute.value.contains("secret")
    ));
}

#[test]
fn extracts_mongodb_op_msg_with_checksum_without_raw_values() {
    let command_document = bson_command_document("find", "customers-secret");
    let command = mongodb_op_msg_with_checksum(&command_document, 0x1234_5678);

    let extraction = parse_mongodb_message(&command, &ProtocolExtractionConfig::default())
        .expect("mongo op_msg checksum command parses");

    assert_eq!(extraction.protocol, ProtocolKind::Mongodb);
    assert_eq!(extraction.operation.as_deref(), Some("find"));
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "db.mongodb.opcode" && attribute.value == "op_msg")
    );
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("customers")
                || attribute.value.contains("305419896"))
    );

    let response = mongodb_op_msg_with_checksum(&bson_mongodb_ok_document(), 0x8765_4321);
    let extraction = parse_mongodb_response(&response, &ProtocolExtractionConfig::default())
        .expect("mongo op_msg checksum response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Mongodb);
    assert_eq!(extraction.status_code, "1");
    assert_eq!(extraction.error_type, None);
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("2271560481"))
    );
}

#[test]
fn extracts_mongodb_op_query_command_without_namespace_or_values() {
    let document = bson_command_document("insert", "orders-secret");
    let bytes = mongodb_op_query("secret-db.$cmd", &document);

    let extraction = parse_mongodb_message(&bytes, &ProtocolExtractionConfig::default())
        .expect("mongo op_query parses");

    assert_eq!(extraction.operation.as_deref(), Some("insert"));
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "db.mongodb.opcode" && attribute.value == "op_query")
    );
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("orders")
                || attribute.value.contains("secret-db")
                || attribute.value.contains("secret"))
    );
}

#[test]
fn extracts_mongodb_ok_response_status() {
    let bytes = mongodb_op_msg(&bson_mongodb_ok_document());

    let extraction = parse_mongodb_response(&bytes, &ProtocolExtractionConfig::default())
        .expect("mongo response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Mongodb);
    assert_eq!(extraction.status_code, "1");
    assert_eq!(extraction.error_type, None);
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "db.system" && attribute.value == "mongodb")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "db.response.status_code" && attribute.value == "1")
    );
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "error.type")
    );
}

#[test]
fn extracts_mongodb_error_response_without_raw_error_message() {
    let bytes = mongodb_op_msg(&bson_mongodb_error_document(
        13,
        b"Authorization failed for secret.collection",
    ));

    let extraction = parse_mongodb_response(&bytes, &ProtocolExtractionConfig::default())
        .expect("mongo error response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Mongodb);
    assert_eq!(extraction.status_code, "13");
    assert_eq!(extraction.error_type.as_deref(), Some("13"));
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "db.response.status_code" && attribute.value == "13")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "error.type" && attribute.value == "13")
    );
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("Authorization")
                || attribute.value.contains("secret"))
    );
}

#[test]
fn extracts_mongodb_error_without_code_as_generic_status() {
    let bytes = mongodb_op_msg(&bson_mongodb_error_without_code_document(b"secret failure"));

    let extraction = parse_mongodb_response(&bytes, &ProtocolExtractionConfig::default())
        .expect("mongo code-less error response parses");

    assert_eq!(extraction.status_code, "0");
    assert_eq!(extraction.error_type.as_deref(), Some("0"));
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("secret"))
    );
}

#[test]
fn extracts_mongodb_op_reply_ok_response_status() {
    let bytes = mongodb_op_reply(&[bson_mongodb_ok_document()]);

    let extraction = parse_mongodb_response(&bytes, &ProtocolExtractionConfig::default())
        .expect("mongo op_reply ok response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Mongodb);
    assert_eq!(extraction.status_code, "1");
    assert_eq!(extraction.error_type, None);
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "db.response.status_code" && attribute.value == "1")
    );
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "error.type")
    );
}

#[test]
fn extracts_mongodb_op_reply_error_without_raw_error_message() {
    let bytes = mongodb_op_reply(&[
        bson_mongodb_error_document(13, b"Authorization failed for secret.collection"),
        bson_mongodb_ok_document(),
    ]);

    let extraction = parse_mongodb_response(&bytes, &ProtocolExtractionConfig::default())
        .expect("mongo op_reply error response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Mongodb);
    assert_eq!(extraction.status_code, "13");
    assert_eq!(extraction.error_type.as_deref(), Some("13"));
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "db.response.status_code" && attribute.value == "13")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "error.type" && attribute.value == "13")
    );
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("Authorization")
                || attribute.value.contains("secret"))
    );
}

#[test]
fn enforces_mongodb_frame_document_response_and_attribute_bounds() {
    let bounded = parse_mongodb_message(
        &mongodb_op_msg(&bson_command_document("find", "customers")),
        &ProtocolExtractionConfig {
            max_header_bytes: 128,
            max_request_line_bytes: 64,
            max_attributes: 2,
            max_tracestate_bytes: 32,
        },
    )
    .expect("bounded mongo command parses");
    assert_eq!(bounded.attributes.len(), 2);

    let bounded_response = parse_mongodb_response(
        &mongodb_op_msg(&bson_mongodb_error_document(13, b"secret")),
        &ProtocolExtractionConfig {
            max_header_bytes: 128,
            max_request_line_bytes: 96,
            max_attributes: 2,
            max_tracestate_bytes: 32,
        },
    )
    .expect("bounded mongo response parses");
    assert_eq!(bounded_response.attributes.len(), 2);

    assert_eq!(
        parse_mongodb_message(
            &mongodb_op_msg(&bson_command_document("find", "customers")),
            &ProtocolExtractionConfig {
                max_header_bytes: 16,
                max_request_line_bytes: 64,
                max_attributes: 4,
                max_tracestate_bytes: 32,
            },
        )
        .unwrap_err(),
        MongodbExtraction::FrameTooLong
    );

    assert_eq!(
        parse_mongodb_message(
            &mongodb_op_msg(&bson_command_document("find", "customers")),
            &ProtocolExtractionConfig {
                max_header_bytes: 128,
                max_request_line_bytes: 8,
                max_attributes: 4,
                max_tracestate_bytes: 32,
            },
        )
        .unwrap_err(),
        MongodbExtraction::DocumentTooLong
    );
    assert_eq!(
        parse_mongodb_response(
            &mongodb_op_msg(&bson_mongodb_error_document(13, b"secret")),
            &ProtocolExtractionConfig {
                max_header_bytes: 16,
                max_request_line_bytes: 96,
                max_attributes: 4,
                max_tracestate_bytes: 32,
            },
        )
        .unwrap_err(),
        MongodbExtraction::FrameTooLong
    );
    assert_eq!(
        parse_mongodb_response(
            &mongodb_op_msg(&bson_mongodb_error_document(13, b"secret")),
            &ProtocolExtractionConfig {
                max_header_bytes: 128,
                max_request_line_bytes: 8,
                max_attributes: 4,
                max_tracestate_bytes: 32,
            },
        )
        .unwrap_err(),
        MongodbExtraction::DocumentTooLong
    );
    assert_eq!(
        parse_mongodb_response(
            &mongodb_op_reply_with_document_count(17),
            &ProtocolExtractionConfig {
                max_header_bytes: 128,
                max_request_line_bytes: 96,
                max_attributes: 4,
                max_tracestate_bytes: 32,
            },
        )
        .unwrap_err(),
        MongodbExtraction::DocumentTooLong
    );
}

#[test]
fn rejects_malformed_and_unsupported_mongodb_fixtures() {
    let config = ProtocolExtractionConfig::default();

    assert_eq!(
        parse_mongodb_message(&[], &config).unwrap_err(),
        MongodbExtraction::MalformedFrame
    );
    assert_eq!(
        parse_mongodb_message(&mongodb_frame(1, b"ignored"), &config).unwrap_err(),
        MongodbExtraction::UnsupportedOpcode
    );
    assert_eq!(
        parse_mongodb_message(&mongodb_op_reply(&[bson_mongodb_ok_document()]), &config)
            .unwrap_err(),
        MongodbExtraction::UnsupportedOpcode
    );
    assert_eq!(
        parse_mongodb_response(&mongodb_frame(1, b"ignored"), &config).unwrap_err(),
        MongodbExtraction::MalformedFrame
    );
    assert_eq!(
        parse_mongodb_message(&mongodb_frame(2013, &1_i32.to_le_bytes()), &config).unwrap_err(),
        MongodbExtraction::MalformedFrame
    );

    let mut truncated = mongodb_op_msg(&bson_command_document("find", "customers"));
    truncated.truncate(18);
    assert_eq!(
        parse_mongodb_message(&truncated, &config).unwrap_err(),
        MongodbExtraction::MalformedFrame
    );
    assert_eq!(
        parse_mongodb_response(&truncated, &config).unwrap_err(),
        MongodbExtraction::MalformedFrame
    );
    assert_eq!(
        parse_mongodb_message(
            &mongodb_op_msg_with_extra_section(
                &bson_command_document("find", "customers"),
                &[0xff],
            ),
            &config,
        )
        .unwrap_err(),
        MongodbExtraction::MalformedFrame
    );
    assert_eq!(
        parse_mongodb_response(
            &mongodb_op_msg_with_extra_section(&bson_mongodb_ok_document(), &[0xff]),
            &config,
        )
        .unwrap_err(),
        MongodbExtraction::MalformedFrame
    );
    assert_eq!(
        parse_mongodb_response(
            &mongodb_op_msg_with_extra_section(
                &bson_mongodb_ok_document(),
                &mongodb_op_msg_body_section(&bson_mongodb_ok_document()),
            ),
            &config,
        )
        .unwrap_err(),
        MongodbExtraction::MalformedFrame
    );
    assert_eq!(
        parse_mongodb_response(
            &mongodb_op_msg(&bson_command_document("find", "customers")),
            &config,
        )
        .unwrap_err(),
        MongodbExtraction::MissingStatus
    );
    assert_eq!(
        parse_mongodb_response(
            &mongodb_op_msg(&bson_mongodb_error_document(-1, b"secret")),
            &config
        )
        .unwrap_err(),
        MongodbExtraction::MalformedFrame
    );
    assert_eq!(
        parse_mongodb_response(&mongodb_op_reply(&[]), &config).unwrap_err(),
        MongodbExtraction::MissingStatus
    );
    assert_eq!(
        parse_mongodb_response(
            &mongodb_op_reply(&[bson_mongodb_error_document(-1, b"secret")]),
            &config
        )
        .unwrap_err(),
        MongodbExtraction::MalformedFrame
    );
    let mut truncated_reply = mongodb_op_reply(&[bson_mongodb_ok_document()]);
    truncated_reply.truncate(24);
    assert_eq!(
        parse_mongodb_response(&truncated_reply, &config).unwrap_err(),
        MongodbExtraction::MalformedFrame
    );

    let invalid_key = {
        let mut document = Vec::new();
        document.extend_from_slice(&8_i32.to_le_bytes());
        document.push(0x10);
        document.push(0xff);
        document.push(0);
        document.push(0);
        document
    };
    assert_eq!(
        parse_mongodb_message(&mongodb_op_msg(&invalid_key), &config).unwrap_err(),
        MongodbExtraction::InvalidUtf8
    );
    assert_eq!(
        parse_mongodb_response(&mongodb_op_msg(&invalid_key), &config).unwrap_err(),
        MongodbExtraction::InvalidUtf8
    );
}

#[test]
fn extracts_nats_pub_operation_without_subject_or_payload() {
    let bytes = b"PUB customer.secret.subject reply.secret 12\r\nsecret-value\r\n";

    let extraction =
        parse_nats_command(bytes, &ProtocolExtractionConfig::default()).expect("nats parses");

    assert_eq!(extraction.protocol, ProtocolKind::Nats);
    assert_eq!(extraction.operation.as_deref(), Some("pub"));
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.system" && attribute.value == "nats")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.operation" && attribute.value == "pub")
    );
    assert!(extraction.attributes.iter().any(|attribute| attribute.key
        == "messaging.nats.subject_present"
        && attribute.value == "true"));
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("customer")
                || attribute.value.contains("subject")
                || attribute.value.contains("secret-value"))
    );
}

#[test]
fn extracts_nats_hpub_and_msg_operations_without_payload() {
    let hpub = b"HPUB headers.secret 6 13\r\nHEADR1payload\r\n";
    let msg = b"MSG subject.secret 7 5\r\nhello\r\n";

    let hpub_extraction =
        parse_nats_command(hpub, &ProtocolExtractionConfig::default()).expect("hpub parses");
    let msg_extraction =
        parse_nats_command(msg, &ProtocolExtractionConfig::default()).expect("msg parses");

    assert_eq!(hpub_extraction.operation.as_deref(), Some("hpub"));
    assert_eq!(msg_extraction.operation.as_deref(), Some("msg"));
    assert!(
        !hpub_extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("payload"))
    );
    assert!(
        !msg_extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("hello"))
    );
}

#[test]
fn extracts_nats_subscription_and_control_operations() {
    for (bytes, operation, subject_present) in [
        (b"SUB orders.secret queue 42\r\n".as_slice(), "sub", true),
        (b"UNSUB 42 1\r\n".as_slice(), "unsub", false),
        (
            b"CONNECT {\"user\":\"secret\"}\r\n".as_slice(),
            "connect",
            false,
        ),
        (b"PING\r\n".as_slice(), "ping", false),
        (b"PONG\r\n".as_slice(), "pong", false),
    ] {
        let extraction =
            parse_nats_command(bytes, &ProtocolExtractionConfig::default()).expect("nats parses");

        assert_eq!(extraction.operation.as_deref(), Some(operation));
        assert_eq!(
            extraction.attributes.iter().any(|attribute| {
                attribute.key == "messaging.nats.subject_present" && attribute.value == "true"
            }),
            subject_present
        );
        assert!(
            !extraction
                .attributes
                .iter()
                .any(|attribute| attribute.value.contains("secret"))
        );
    }
}

#[test]
fn extracts_nats_ok_response_status() {
    let extraction =
        parse_nats_response(b"+OK\r\n", &ProtocolExtractionConfig::default()).expect("ok parses");

    assert_eq!(extraction.protocol, ProtocolKind::Nats);
    assert_eq!(extraction.status_code, "OK");
    assert_eq!(extraction.error_type, None);
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.system" && attribute.value == "nats")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.nats.status_code"
                && attribute.value == "OK")
    );
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "error.type")
    );
}

#[test]
fn extracts_nats_error_type_without_raw_error_message() {
    let extraction = parse_nats_response(
        b"-ERR 'Authorization Violation for secret.subject'\r\n",
        &ProtocolExtractionConfig::default(),
    )
    .expect("error parses");

    assert_eq!(extraction.protocol, ProtocolKind::Nats);
    assert_eq!(extraction.status_code, "ERR");
    assert_eq!(extraction.error_type.as_deref(), Some("nats_error"));
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.nats.status_code"
                && attribute.value == "ERR")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "error.type" && attribute.value == "nats_error")
    );
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("Authorization")
                || attribute.value.contains("secret"))
    );
}

#[test]
fn enforces_nats_frame_payload_response_and_attribute_bounds() {
    let bounded = parse_nats_command(
        b"PUB orders.secret 5\r\nhello\r\n",
        &ProtocolExtractionConfig {
            max_header_bytes: 128,
            max_request_line_bytes: 64,
            max_attributes: 2,
            max_tracestate_bytes: 32,
        },
    )
    .expect("bounded nats command parses");
    assert_eq!(bounded.attributes.len(), 2);

    let bounded_response = parse_nats_response(
        b"-ERR secret-detail\r\n",
        &ProtocolExtractionConfig {
            max_header_bytes: 64,
            max_request_line_bytes: 32,
            max_attributes: 2,
            max_tracestate_bytes: 32,
        },
    )
    .expect("bounded nats response parses");
    assert_eq!(bounded_response.attributes.len(), 2);

    assert_eq!(
        parse_nats_command(
            b"PUB orders.secret 5\r\nhello\r\n",
            &ProtocolExtractionConfig {
                max_header_bytes: 16,
                max_request_line_bytes: 64,
                max_attributes: 4,
                max_tracestate_bytes: 32,
            },
        )
        .unwrap_err(),
        NatsExtraction::FrameTooLong
    );
    assert_eq!(
        parse_nats_command(
            b"PUB orders.secret 257\r\n",
            &ProtocolExtractionConfig {
                max_header_bytes: 256,
                max_request_line_bytes: 64,
                max_attributes: 4,
                max_tracestate_bytes: 32,
            },
        )
        .unwrap_err(),
        NatsExtraction::PayloadTooLong
    );
    assert_eq!(
        parse_nats_response(
            b"-ERR secret-detail\r\n",
            &ProtocolExtractionConfig {
                max_header_bytes: 8,
                max_request_line_bytes: 64,
                max_attributes: 4,
                max_tracestate_bytes: 32,
            },
        )
        .unwrap_err(),
        NatsExtraction::FrameTooLong
    );
    assert_eq!(
        parse_nats_response(
            b"-ERR secret-detail-that-exceeds-line-bound\r\n",
            &ProtocolExtractionConfig {
                max_header_bytes: 128,
                max_request_line_bytes: 8,
                max_attributes: 4,
                max_tracestate_bytes: 32,
            },
        )
        .unwrap_err(),
        NatsExtraction::FrameTooLong
    );
}

#[test]
fn rejects_malformed_and_unsupported_nats_fixtures() {
    let config = ProtocolExtractionConfig::default();

    assert_eq!(
        parse_nats_command(b"", &config).unwrap_err(),
        NatsExtraction::MalformedFrame
    );
    assert_eq!(
        parse_nats_command(b"PUB missing-payload 5\r\n", &config).unwrap_err(),
        NatsExtraction::MalformedFrame
    );
    assert_eq!(
        parse_nats_command(b"PUB subject not-a-size\r\n", &config).unwrap_err(),
        NatsExtraction::MalformedFrame
    );
    assert_eq!(
        parse_nats_command(b"HPUB subject 10 4\r\nabcd\r\n", &config).unwrap_err(),
        NatsExtraction::MalformedFrame
    );
    assert_eq!(
        parse_nats_command(b"UNKNOWN subject\r\n", &config).unwrap_err(),
        NatsExtraction::UnsupportedCommand
    );
    assert_eq!(
        parse_nats_command(b"PING\r\nsecret", &config).unwrap_err(),
        NatsExtraction::MalformedFrame
    );
    assert_eq!(
        parse_nats_command(b"SUB subject sid\r\nsecret", &config).unwrap_err(),
        NatsExtraction::MalformedFrame
    );
    assert_eq!(
        parse_nats_command(b"pub subject 0\r\n\r\n", &config).unwrap_err(),
        NatsExtraction::UnsupportedCommand
    );
    assert_eq!(
        parse_nats_command(b"P\xffNG\r\n", &config).unwrap_err(),
        NatsExtraction::InvalidUtf8
    );
    assert_eq!(
        parse_nats_response(b"-ERR\r\n", &config).unwrap_err(),
        NatsExtraction::UnsupportedCommand
    );
    assert_eq!(
        parse_nats_response(b"+OK details\r\n", &config).unwrap_err(),
        NatsExtraction::UnsupportedCommand
    );
    assert_eq!(
        parse_nats_response(b"+OK\r\nsecret", &config).unwrap_err(),
        NatsExtraction::MalformedFrame
    );
    assert_eq!(
        parse_nats_response(b"-ERR secret-detail\r\nextra", &config).unwrap_err(),
        NatsExtraction::MalformedFrame
    );
    assert_eq!(
        parse_nats_response(b"PING\r\n", &config).unwrap_err(),
        NatsExtraction::UnsupportedCommand
    );
    assert_eq!(
        parse_nats_response(b"+O\xff\r\n", &config).unwrap_err(),
        NatsExtraction::InvalidUtf8
    );
}

fn lower_hex_string(
    len: impl Into<proptest::collection::SizeRange>,
) -> impl Strategy<Value = String> {
    prop::collection::vec(prop_oneof![Just(b'0'), b'1'..=b'9', b'a'..=b'f'], len)
        .prop_map(|bytes| String::from_utf8(bytes).expect("ascii hex"))
}

fn non_zero_lower_hex_string(len: usize) -> impl Strategy<Value = String> {
    lower_hex_string(len).prop_filter("all-zero ids are invalid", |value| {
        value.bytes().any(|byte| byte != b'0')
    })
}

fn uppercase_hex_string(len: usize) -> impl Strategy<Value = String> {
    prop::collection::vec(prop_oneof![Just(b'0'), b'1'..=b'9', b'A'..=b'F'], len)
        .prop_map(|bytes| String::from_utf8(bytes).expect("ascii hex"))
}

fn postgres_frame(message_type: u8, body: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(body.len() + 5);
    frame.push(message_type);
    frame.extend_from_slice(&((body.len() + 4) as u32).to_be_bytes());
    frame.extend_from_slice(body);
    frame
}

fn postgres_error_response_frame(sqlstate: &[u8], message: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    body.push(b'S');
    body.extend_from_slice(b"ERROR\0");
    body.push(b'C');
    body.extend_from_slice(sqlstate);
    body.push(0);
    body.push(b'M');
    body.extend_from_slice(message);
    body.push(0);
    body.push(0);
    postgres_frame(b'E', &body)
}

fn postgres_notification_response_frame(channel: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&42_i32.to_be_bytes());
    body.extend_from_slice(channel);
    body.push(0);
    body.extend_from_slice(payload);
    body.push(0);
    postgres_frame(b'A', &body)
}

fn postgres_negotiate_protocol_version_frame(
    newest_protocol_version: i32,
    unrecognized_options: &[&[u8]],
) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&newest_protocol_version.to_be_bytes());
    body.extend_from_slice(&(unrecognized_options.len() as i32).to_be_bytes());
    for option in unrecognized_options {
        body.extend_from_slice(option);
        body.push(0);
    }
    postgres_frame(b'v', &body)
}

fn postgres_notice_response_frame(sqlstate: &[u8], message: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    body.push(b'S');
    body.extend_from_slice(b"NOTICE\0");
    body.push(b'C');
    body.extend_from_slice(sqlstate);
    body.push(0);
    body.push(b'M');
    body.extend_from_slice(message);
    body.push(0);
    body.push(0);
    postgres_frame(b'N', &body)
}

fn postgres_row_description_frame(field_names: &[&[u8]]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&(field_names.len() as u16).to_be_bytes());
    for field_name in field_names {
        body.extend_from_slice(field_name);
        body.push(0);
        body.extend_from_slice(&0_u32.to_be_bytes());
        body.extend_from_slice(&0_u16.to_be_bytes());
        body.extend_from_slice(&25_u32.to_be_bytes());
        body.extend_from_slice(&(-1_i16).to_be_bytes());
        body.extend_from_slice(&(-1_i32).to_be_bytes());
        body.extend_from_slice(&0_i16.to_be_bytes());
    }
    postgres_frame(b'T', &body)
}

fn postgres_parameter_description_frame(type_oids: &[u32]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&(type_oids.len() as u16).to_be_bytes());
    for type_oid in type_oids {
        body.extend_from_slice(&type_oid.to_be_bytes());
    }
    postgres_frame(b't', &body)
}

fn postgres_function_call_response_frame(value: Option<&[u8]>) -> Vec<u8> {
    let mut body = Vec::new();
    match value {
        Some(value) => {
            body.extend_from_slice(&(value.len() as i32).to_be_bytes());
            body.extend_from_slice(value);
        }
        None => body.extend_from_slice(&(-1_i32).to_be_bytes()),
    }
    postgres_frame(b'V', &body)
}

fn postgres_data_row_frame(values: &[Option<&[u8]>]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&(values.len() as u16).to_be_bytes());
    for value in values {
        match value {
            Some(value) => {
                body.extend_from_slice(&(value.len() as i32).to_be_bytes());
                body.extend_from_slice(value);
            }
            None => body.extend_from_slice(&(-1_i32).to_be_bytes()),
        }
    }
    postgres_frame(b'D', &body)
}

fn postgres_copy_mode_response_frame(message_type: u8, column_formats: &[u16]) -> Vec<u8> {
    let mut body = Vec::new();
    body.push(0);
    body.extend_from_slice(&(column_formats.len() as u16).to_be_bytes());
    for column_format in column_formats {
        body.extend_from_slice(&column_format.to_be_bytes());
    }
    postgres_frame(message_type, &body)
}

fn postgres_authentication_frame(auth_code: u32, payload: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&auth_code.to_be_bytes());
    body.extend_from_slice(payload);
    postgres_frame(b'R', &body)
}

fn mysql_packet(command: u8, query: &[u8]) -> Vec<u8> {
    let payload_len = query.len() + 1;
    let mut packet = Vec::with_capacity(payload_len + 4);
    packet.push((payload_len & 0xff) as u8);
    packet.push(((payload_len >> 8) & 0xff) as u8);
    packet.push(((payload_len >> 16) & 0xff) as u8);
    packet.push(0);
    packet.push(command);
    packet.extend_from_slice(query);
    packet
}

fn mysql_error_packet(vendor_code: u16, sqlstate: Option<&[u8]>, message: &[u8]) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.push(0xff);
    payload.extend_from_slice(&vendor_code.to_le_bytes());
    if let Some(sqlstate) = sqlstate {
        payload.push(b'#');
        payload.extend_from_slice(sqlstate);
    }
    payload.extend_from_slice(message);

    let mut packet = Vec::with_capacity(payload.len() + 4);
    packet.push((payload.len() & 0xff) as u8);
    packet.push(((payload.len() >> 8) & 0xff) as u8);
    packet.push(((payload.len() >> 16) & 0xff) as u8);
    packet.push(0);
    packet.extend_from_slice(&payload);
    packet
}

fn mysql_ok_packet(body: &[u8]) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.push(0x00);
    payload.extend_from_slice(body);

    let mut packet = Vec::with_capacity(payload.len() + 4);
    packet.push((payload.len() & 0xff) as u8);
    packet.push(((payload.len() >> 8) & 0xff) as u8);
    packet.push(((payload.len() >> 16) & 0xff) as u8);
    packet.push(0);
    packet.extend_from_slice(&payload);
    packet
}

fn kafka_request_frame(
    api_key: i16,
    api_version: i16,
    client_id: Option<&[u8]>,
    body: &[u8],
) -> Vec<u8> {
    let mut request = Vec::new();
    request.extend_from_slice(&api_key.to_be_bytes());
    request.extend_from_slice(&api_version.to_be_bytes());
    request.extend_from_slice(&42_i32.to_be_bytes());
    if let Some(client_id) = client_id {
        request.extend_from_slice(&(client_id.len() as i16).to_be_bytes());
        request.extend_from_slice(client_id);
    } else {
        request.extend_from_slice(&(-1_i16).to_be_bytes());
    }
    request.extend_from_slice(body);
    kafka_frame(&request)
}

fn kafka_produce_request_body(topics: &[(&str, i32, &[u8])]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&1_i16.to_be_bytes());
    body.extend_from_slice(&1_000_i32.to_be_bytes());
    body.extend_from_slice(&(topics.len() as i32).to_be_bytes());
    for (topic, partition, records) in topics {
        body.extend_from_slice(&(topic.len() as i16).to_be_bytes());
        body.extend_from_slice(topic.as_bytes());
        body.extend_from_slice(&1_i32.to_be_bytes());
        body.extend_from_slice(&partition.to_be_bytes());
        body.extend_from_slice(&(records.len() as i32).to_be_bytes());
        body.extend_from_slice(records);
    }
    body
}

fn kafka_flexible_request_frame(
    api_key: i16,
    api_version: i16,
    client_id: Option<&[u8]>,
    body: &[u8],
) -> Vec<u8> {
    let mut request = Vec::new();
    request.extend_from_slice(&api_key.to_be_bytes());
    request.extend_from_slice(&api_version.to_be_bytes());
    request.extend_from_slice(&42_i32.to_be_bytes());
    if let Some(client_id) = client_id {
        push_unsigned_varint(&mut request, client_id.len() + 1);
        request.extend_from_slice(client_id);
    } else {
        push_unsigned_varint(&mut request, 0);
    }
    push_unsigned_varint(&mut request, 0);
    request.extend_from_slice(body);
    kafka_frame(&request)
}

fn kafka_frame(request: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(request.len() + 4);
    frame.extend_from_slice(&(request.len() as i32).to_be_bytes());
    frame.extend_from_slice(request);
    frame
}

fn kafka_api_versions_response_frame(correlation_id: i32, error_code: i16, body: &[u8]) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&correlation_id.to_be_bytes());
    response.extend_from_slice(&error_code.to_be_bytes());
    response.extend_from_slice(body);
    kafka_frame(&response)
}

fn kafka_flexible_api_versions_response_frame(error_code: i16, body: &[u8]) -> Vec<u8> {
    kafka_flexible_api_versions_response_with_tags_frame(error_code, 0, body)
}

fn kafka_flexible_api_versions_response_with_tags_frame(
    error_code: i16,
    tag_value_len: usize,
    body: &[u8],
) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&42_i32.to_be_bytes());
    if tag_value_len == 0 {
        push_unsigned_varint(&mut response, 0);
    } else {
        push_unsigned_varint(&mut response, 1);
        push_unsigned_varint(&mut response, 0);
        push_unsigned_varint(&mut response, tag_value_len);
        response.extend(std::iter::repeat_n(0, tag_value_len));
    }
    response.extend_from_slice(&error_code.to_be_bytes());
    response.extend_from_slice(body);
    kafka_frame(&response)
}

fn kafka_produce_response_frame(
    correlation_id: i32,
    api_version: i16,
    topics: &[(&str, i16)],
) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&correlation_id.to_be_bytes());
    response.extend_from_slice(&(topics.len() as i32).to_be_bytes());
    for (topic, error_code) in topics {
        response.extend_from_slice(&(topic.len() as i16).to_be_bytes());
        response.extend_from_slice(topic.as_bytes());
        response.extend_from_slice(&1_i32.to_be_bytes());
        response.extend_from_slice(&0_i32.to_be_bytes());
        response.extend_from_slice(&error_code.to_be_bytes());
        response.extend_from_slice(&42_i64.to_be_bytes());
        if api_version >= 2 {
            response.extend_from_slice(&1_700_000_000_i64.to_be_bytes());
        }
        if api_version >= 5 {
            response.extend_from_slice(&7_i64.to_be_bytes());
        }
    }
    if api_version >= 1 {
        response.extend_from_slice(&0_i32.to_be_bytes());
    }
    kafka_frame(&response)
}

fn kafka_produce_response_with_topic_count_frame(topic_count: i32) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&topic_count.to_be_bytes());
    kafka_frame(&response)
}

fn kafka_produce_response_with_partition_count_frame(partition_count: i32) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&1_i32.to_be_bytes());
    response.extend_from_slice(&6_i16.to_be_bytes());
    response.extend_from_slice(b"orders");
    response.extend_from_slice(&partition_count.to_be_bytes());
    kafka_frame(&response)
}

fn kafka_fetch_response_frame(
    correlation_id: i32,
    api_version: i16,
    topics: &[(&str, i16, &[u8])],
) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&correlation_id.to_be_bytes());
    if api_version >= 1 {
        response.extend_from_slice(&0_i32.to_be_bytes());
    }
    response.extend_from_slice(&(topics.len() as i32).to_be_bytes());
    for (topic, error_code, records) in topics {
        response.extend_from_slice(&(topic.len() as i16).to_be_bytes());
        response.extend_from_slice(topic.as_bytes());
        response.extend_from_slice(&1_i32.to_be_bytes());
        response.extend_from_slice(&0_i32.to_be_bytes());
        response.extend_from_slice(&error_code.to_be_bytes());
        response.extend_from_slice(&42_i64.to_be_bytes());
        if api_version >= 4 {
            response.extend_from_slice(&40_i64.to_be_bytes());
        }
        if api_version >= 5 {
            response.extend_from_slice(&1_i64.to_be_bytes());
        }
        if api_version >= 4 {
            response.extend_from_slice(&0_i32.to_be_bytes());
        }
        response.extend_from_slice(&(records.len() as i32).to_be_bytes());
        response.extend_from_slice(records);
    }
    kafka_frame(&response)
}

fn kafka_fetch_response_with_topic_count_frame(topic_count: i32) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&topic_count.to_be_bytes());
    kafka_frame(&response)
}

fn kafka_fetch_response_with_partition_count_frame(partition_count: i32) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&1_i32.to_be_bytes());
    response.extend_from_slice(&6_i16.to_be_bytes());
    response.extend_from_slice(b"orders");
    response.extend_from_slice(&partition_count.to_be_bytes());
    kafka_frame(&response)
}

fn kafka_fetch_response_with_record_len_frame(record_len: i32) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&1_i32.to_be_bytes());
    response.extend_from_slice(&6_i16.to_be_bytes());
    response.extend_from_slice(b"orders");
    response.extend_from_slice(&1_i32.to_be_bytes());
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&0_i16.to_be_bytes());
    response.extend_from_slice(&42_i64.to_be_bytes());
    response.extend_from_slice(&record_len.to_be_bytes());
    kafka_frame(&response)
}

fn push_unsigned_varint(bytes: &mut Vec<u8>, mut value: usize) {
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        bytes.push(byte);
        if value == 0 {
            return;
        }
    }
}

fn mongodb_frame(opcode: i32, body: &[u8]) -> Vec<u8> {
    let message_len = body.len() + 16;
    let mut frame = Vec::with_capacity(message_len);
    frame.extend_from_slice(&(message_len as i32).to_le_bytes());
    frame.extend_from_slice(&1_i32.to_le_bytes());
    frame.extend_from_slice(&0_i32.to_le_bytes());
    frame.extend_from_slice(&opcode.to_le_bytes());
    frame.extend_from_slice(body);
    frame
}

fn mongodb_op_msg(document: &[u8]) -> Vec<u8> {
    mongodb_op_msg_with_extra_section(document, &[])
}

fn mongodb_op_msg_with_checksum(document: &[u8], checksum: u32) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&1_u32.to_le_bytes());
    body.extend_from_slice(&mongodb_op_msg_body_section(document));
    body.extend_from_slice(&checksum.to_le_bytes());
    mongodb_frame(2013, &body)
}

fn mongodb_op_msg_with_extra_section(document: &[u8], extra_section: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&0_u32.to_le_bytes());
    body.extend_from_slice(&mongodb_op_msg_body_section(document));
    body.extend_from_slice(extra_section);
    mongodb_frame(2013, &body)
}

fn mongodb_op_msg_body_section(document: &[u8]) -> Vec<u8> {
    let mut section = Vec::new();
    section.push(0);
    section.extend_from_slice(document);
    section
}

fn mongodb_op_query(namespace: &str, document: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&0_i32.to_le_bytes());
    body.extend_from_slice(namespace.as_bytes());
    body.push(0);
    body.extend_from_slice(&0_i32.to_le_bytes());
    body.extend_from_slice(&1_i32.to_le_bytes());
    body.extend_from_slice(document);
    mongodb_frame(2004, &body)
}

fn mongodb_op_reply(documents: &[Vec<u8>]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&0_i32.to_le_bytes());
    body.extend_from_slice(&0_i64.to_le_bytes());
    body.extend_from_slice(&0_i32.to_le_bytes());
    body.extend_from_slice(&(documents.len() as i32).to_le_bytes());
    for document in documents {
        body.extend_from_slice(document);
    }
    mongodb_frame(1, &body)
}

fn mongodb_op_reply_with_document_count(document_count: i32) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&0_i32.to_le_bytes());
    body.extend_from_slice(&0_i64.to_le_bytes());
    body.extend_from_slice(&0_i32.to_le_bytes());
    body.extend_from_slice(&document_count.to_le_bytes());
    mongodb_frame(1, &body)
}

fn bson_command_document(command: &str, value: &str) -> Vec<u8> {
    let value_len = value.len() + 1;
    let document_len = 4 + 1 + command.len() + 1 + 4 + value_len + 1;
    let mut document = Vec::with_capacity(document_len);
    document.extend_from_slice(&(document_len as i32).to_le_bytes());
    document.push(0x02);
    document.extend_from_slice(command.as_bytes());
    document.push(0);
    document.extend_from_slice(&(value_len as i32).to_le_bytes());
    document.extend_from_slice(value.as_bytes());
    document.push(0);
    document.push(0);
    document
}

fn bson_mongodb_ok_document() -> Vec<u8> {
    let mut elements = Vec::new();
    push_bson_bool(&mut elements, "ok", true);
    bson_document(elements)
}

fn bson_mongodb_error_document(code: i32, message: &[u8]) -> Vec<u8> {
    let mut elements = Vec::new();
    push_bson_bool(&mut elements, "ok", false);
    push_bson_i32(&mut elements, "code", code);
    push_bson_string(&mut elements, "errmsg", message);
    bson_document(elements)
}

fn bson_mongodb_error_without_code_document(message: &[u8]) -> Vec<u8> {
    let mut elements = Vec::new();
    push_bson_i32(&mut elements, "ok", 0);
    push_bson_string(&mut elements, "errmsg", message);
    bson_document(elements)
}

fn bson_document(elements: Vec<u8>) -> Vec<u8> {
    let document_len = elements.len() + 5;
    let mut document = Vec::with_capacity(document_len);
    document.extend_from_slice(&(document_len as i32).to_le_bytes());
    document.extend_from_slice(&elements);
    document.push(0);
    document
}

fn push_bson_bool(elements: &mut Vec<u8>, key: &str, value: bool) {
    elements.push(0x08);
    elements.extend_from_slice(key.as_bytes());
    elements.push(0);
    elements.push(u8::from(value));
}

fn push_bson_i32(elements: &mut Vec<u8>, key: &str, value: i32) {
    elements.push(0x10);
    elements.extend_from_slice(key.as_bytes());
    elements.push(0);
    elements.extend_from_slice(&value.to_le_bytes());
}

fn push_bson_string(elements: &mut Vec<u8>, key: &str, value: &[u8]) {
    let value_len = value.len() + 1;
    elements.push(0x02);
    elements.extend_from_slice(key.as_bytes());
    elements.push(0);
    elements.extend_from_slice(&(value_len as i32).to_le_bytes());
    elements.extend_from_slice(value);
    elements.push(0);
}
