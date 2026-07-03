use e_navigator_protocol::{
    ProtocolExtractionConfig,
    http::{HttpExtraction, parse_http_request},
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
