use super::*;

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
