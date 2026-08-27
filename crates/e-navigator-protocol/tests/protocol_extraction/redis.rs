use super::*;

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
            .any(|attribute| attribute.key == "db.system.name" && attribute.value == "redis")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "db.operation.name" && attribute.value == "SET")
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
            .any(|attribute| attribute.key == "db.operation.name" && attribute.value == "GET")
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
            .any(|attribute| attribute.key == "db.system.name" && attribute.value == "redis")
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
fn classifies_redis_resp3_out_of_band_frames_without_parsing_values() {
    assert_eq!(
        redis_response_role(b">2\r\n+invalidate\r\n$3\r\nkey\r\n"),
        Ok(RedisResponseRole::Push)
    );
    assert_eq!(
        redis_response_role(b"|1\r\n+ttl\r\n:10\r\n"),
        Ok(RedisResponseRole::Attribute)
    );
    assert_eq!(
        redis_response_role(b"$5\r\nvalue\r\n"),
        Ok(RedisResponseRole::Reply)
    );
    assert_eq!(
        redis_response_role(b""),
        Err(RedisExtraction::MalformedFrame)
    );
}

#[test]
fn classifies_resp2_pubsub_deliveries_only_with_connection_evidence() {
    for delivery in [
        b"*3\r\n$7\r\nmessage\r\n$7\r\nchannel\r\n$7\r\npayload\r\n".as_slice(),
        b"*4\r\n$8\r\npmessage\r\n$7\r\npattern\r\n$7\r\nchannel\r\n$7\r\npayload\r\n".as_slice(),
        b"*3\r\n$8\r\nsmessage\r\n$7\r\nchannel\r\n$7\r\npayload\r\n".as_slice(),
    ] {
        assert_eq!(redis_response_role(delivery), Ok(RedisResponseRole::Reply));
        assert_eq!(
            redis_connection_response_role(delivery, RedisSubscriptionState::Resp2),
            Ok(RedisResponseRole::Push)
        );
        assert_eq!(
            redis_connection_response_role(delivery, RedisSubscriptionState::Resp3),
            Ok(RedisResponseRole::Reply)
        );
    }
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
