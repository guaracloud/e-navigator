use e_navigator_protocol::{
    ProtocolExtractionConfig,
    http::{HttpExtraction, parse_http_request},
    kafka::{KafkaExtraction, parse_kafka_request},
    mongodb::{MongodbExtraction, parse_mongodb_message},
    mysql::{MysqlExtraction, parse_mysql_command},
    nats::{NatsExtraction, parse_nats_command},
    postgres::{PostgresExtraction, parse_postgres_message},
    redis::{RedisExtraction, parse_redis_command},
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
    fn arbitrary_nats_fixture_bytes_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..=512)) {
        let config = ProtocolExtractionConfig {
            max_header_bytes: 256,
            max_request_line_bytes: 64,
            max_attributes: 4,
            max_tracestate_bytes: 32,
        };

        let _ = parse_nats_command(&bytes, &config);
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
fn extracts_kafka_flexible_api_versions_request_without_client_id_value() {
    let bytes = kafka_flexible_request_frame(18, 3, Some(b"secret-flex-client"), b"\0\0");

    let extraction = parse_kafka_request(&bytes, &ProtocolExtractionConfig::default())
        .expect("flexible kafka header parses");

    assert_eq!(extraction.operation.as_deref(), Some("api_versions"));
    assert!(extraction.attributes.iter().any(|attribute| attribute.key
        == "messaging.kafka.client_id_present"
        && attribute.value == "true"));
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("secret-flex-client"))
    );
}

#[test]
fn enforces_kafka_frame_client_id_and_attribute_bounds() {
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

    let mut truncated = kafka_request_frame(3, 9, Some(b"client-a"), b"");
    truncated.truncate(8);
    assert_eq!(
        parse_kafka_request(&truncated, &config).unwrap_err(),
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
        PostgresExtraction::UnsupportedMessage
    );
    assert_eq!(
        parse_postgres_message(&postgres_frame(b'Q', b"select 1"), &config).unwrap_err(),
        PostgresExtraction::MalformedFrame
    );
    assert_eq!(
        parse_postgres_message(&postgres_frame(b'Q', b"sel\xffct\0"), &config).unwrap_err(),
        PostgresExtraction::InvalidUtf8
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
        MysqlExtraction::UnsupportedCommand
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
fn enforces_mongodb_frame_document_and_attribute_bounds() {
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

    let mut truncated = mongodb_op_msg(&bson_command_document("find", "customers"));
    truncated.truncate(18);
    assert_eq!(
        parse_mongodb_message(&truncated, &config).unwrap_err(),
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
fn enforces_nats_frame_payload_and_attribute_bounds() {
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
        parse_nats_command(b"P\xffNG\r\n", &config).unwrap_err(),
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
    let mut body = Vec::new();
    body.extend_from_slice(&0_u32.to_le_bytes());
    body.push(0);
    body.extend_from_slice(document);
    mongodb_frame(2013, &body)
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
