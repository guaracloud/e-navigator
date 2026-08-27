use super::*;

#[test]
fn extracts_mongodb_op_msg_command_and_unambiguous_collection() {
    let document = bson_command_document("find", "customers-secret");
    let bytes = mongodb_op_msg_with_ids(&document, 73, 0);

    let extraction =
        parse_mongodb_message(&bytes, &ProtocolExtractionConfig::default()).expect("mongo parses");

    assert_eq!(extraction.protocol, ProtocolKind::Mongodb);
    assert_eq!(extraction.request_id, 73);
    assert_eq!(extraction.operation.as_deref(), Some("find"));
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "db.system.name" && attribute.value == "mongodb")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "db.operation.name" && attribute.value == "find")
    );
    assert!(extraction.attributes.iter().any(|attribute| {
        attribute.key == "db.collection.name" && attribute.value == "customers-secret"
    }));
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "db.mongodb.opcode" && attribute.value == "op_msg")
    );
    assert_eq!(
        extraction
            .attributes
            .iter()
            .filter(|attribute| attribute.value.contains("customers-secret"))
            .count(),
        1
    );
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
    assert!(extraction.attributes.iter().any(|attribute| {
        attribute.key == "db.collection.name" && attribute.value == "customers-secret"
    }));
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("305419896"))
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
fn extracts_mongodb_op_msg_response_lifecycle_flags() {
    let config = ProtocolExtractionConfig::default();
    let command_document = bson_command_document("find", "customers");

    let fire_and_forget = mongodb_op_msg_with_flags_and_ids(&command_document, 0x02, 73, 0);
    let parsed =
        parse_mongodb_message(&fire_and_forget, &config).expect("fire-and-forget command parses");
    assert!(!parsed.expects_response);
    assert!(!parsed.allows_multiple_responses);

    let exhaust = mongodb_op_msg_with_flags_and_ids(&command_document, 0x0001_0000, 74, 0);
    let parsed = parse_mongodb_message(&exhaust, &config).expect("exhaust command parses");
    assert!(parsed.expects_response);
    assert!(parsed.allows_multiple_responses);

    let optional_unknown = mongodb_op_msg_with_flags_and_ids(&command_document, 0x8000_0000, 75, 0);
    let parsed = parse_mongodb_message(&optional_unknown, &config)
        .expect("unknown optional flags are ignored");
    assert!(parsed.expects_response);
    assert!(!parsed.allows_multiple_responses);

    let continued_response =
        mongodb_op_msg_with_flags_and_ids(&bson_mongodb_ok_document(), 0x02, 76, 74);
    let parsed = parse_mongodb_response(&continued_response, &config)
        .expect("continued exhaust response parses");
    assert!(parsed.more_to_come);
}

#[test]
fn rejects_invalid_mongodb_op_msg_required_and_directional_flags() {
    let config = ProtocolExtractionConfig::default();
    let command_document = bson_command_document("find", "customers");

    assert_eq!(
        parse_mongodb_message(
            &mongodb_op_msg_with_flags_and_ids(&command_document, 0x04, 73, 0),
            &config,
        ),
        Err(MongodbExtraction::UnsupportedRequiredFlag)
    );
    assert_eq!(
        parse_mongodb_response(
            &mongodb_op_msg_with_flags_and_ids(&bson_mongodb_ok_document(), 0x0001_0000, 74, 73,),
            &config,
        ),
        Err(MongodbExtraction::InvalidFlags)
    );
}

#[test]
fn mongodb_exhaust_lifecycle_completes_on_the_final_response() {
    let config = ProtocolExtractionConfig::default();
    let request = mongodb_op_msg_with_flags_and_ids(
        &bson_command_document("find", "customers"),
        0x0001_0000,
        73,
        0,
    );
    let mut lifecycle = MongodbResponseLifecycle::from_request(&request, &config)
        .expect("exhaust lifecycle starts");

    assert!(lifecycle.expects_response());
    assert_eq!(lifecycle.request_id(), 73);
    let continued = parse_mongodb_response(
        &mongodb_op_msg_with_flags_and_ids(&bson_mongodb_ok_document(), 0x02, 74, 73),
        &config,
    )
    .expect("continued response parses");
    assert_eq!(
        lifecycle.observe_response(continued),
        Ok(MongodbResponseProgress::Continue)
    );

    let final_response = parse_mongodb_response(
        &mongodb_op_msg_with_flags_and_ids(&bson_mongodb_ok_document(), 0, 75, 73),
        &config,
    )
    .expect("final response parses");
    assert!(matches!(
        lifecycle.observe_response(final_response),
        Ok(MongodbResponseProgress::Complete(response))
            if response.status_code == "1" && !response.more_to_come
    ));
}

#[test]
fn mongodb_lifecycle_fails_closed_on_an_unexpected_continuation() {
    let config = ProtocolExtractionConfig::default();
    let request = mongodb_op_msg_with_ids(&bson_command_document("find", "customers"), 73, 0);
    let mut lifecycle = MongodbResponseLifecycle::from_request(&request, &config)
        .expect("single-response lifecycle starts");
    let continued = parse_mongodb_response(
        &mongodb_op_msg_with_flags_and_ids(&bson_mongodb_ok_document(), 0x02, 74, 73),
        &config,
    )
    .expect("continued response parses");

    assert_eq!(
        lifecycle.observe_response(continued),
        Err(MongodbExtraction::UnexpectedResponse)
    );
}

#[test]
fn extracts_mongodb_op_query_collection_without_legacy_namespace() {
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
    assert!(extraction.attributes.iter().any(|attribute| {
        attribute.key == "db.collection.name" && attribute.value == "orders-secret"
    }));
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("secret-db"))
    );
}

#[test]
fn extracts_mongodb_ok_response_status() {
    let bytes = mongodb_op_msg_with_ids(&bson_mongodb_ok_document(), 74, 73);

    let extraction = parse_mongodb_response(&bytes, &ProtocolExtractionConfig::default())
        .expect("mongo response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Mongodb);
    assert_eq!(extraction.response_to, 73);
    assert_eq!(extraction.status_code, "1");
    assert_eq!(extraction.error_type, None);
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "db.system.name" && attribute.value == "mongodb")
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
fn extracts_mongodb_write_error_codes_without_raw_error_details() {
    let bytes = mongodb_op_msg(&bson_mongodb_write_error_document(
        11_000,
        b"duplicate secret.customer key",
        Some((64, b"secret replica timeout")),
    ));

    let extraction = parse_mongodb_response(&bytes, &ProtocolExtractionConfig::default())
        .expect("write error response parses");

    assert_eq!(extraction.status_code, "11000");
    assert_eq!(extraction.error_type.as_deref(), Some("11000"));
    assert!(extraction.attributes.iter().all(|attribute| {
        !attribute.value.contains("duplicate")
            && !attribute.value.contains("replica")
            && !attribute.value.contains("secret")
    }));
}

#[test]
fn extracts_mongodb_write_concern_error_when_no_write_error_exists() {
    let bytes = mongodb_op_msg(&bson_mongodb_write_error_document(
        0,
        b"",
        Some((64, b"secret replica timeout")),
    ));

    let extraction = parse_mongodb_response(&bytes, &ProtocolExtractionConfig::default())
        .expect("write concern response parses");

    assert_eq!(extraction.status_code, "64");
    assert_eq!(extraction.error_type.as_deref(), Some("64"));
    assert!(
        extraction
            .attributes
            .iter()
            .all(|attribute| !attribute.value.contains("secret"))
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

fn mongodb_frame(opcode: i32, body: &[u8]) -> Vec<u8> {
    mongodb_frame_with_ids(opcode, body, 1, 0)
}

fn mongodb_frame_with_ids(opcode: i32, body: &[u8], request_id: i32, response_to: i32) -> Vec<u8> {
    let message_len = body.len() + 16;
    let mut frame = Vec::with_capacity(message_len);
    frame.extend_from_slice(&(message_len as i32).to_le_bytes());
    frame.extend_from_slice(&request_id.to_le_bytes());
    frame.extend_from_slice(&response_to.to_le_bytes());
    frame.extend_from_slice(&opcode.to_le_bytes());
    frame.extend_from_slice(body);
    frame
}

pub(super) fn mongodb_op_msg(document: &[u8]) -> Vec<u8> {
    mongodb_op_msg_with_extra_section(document, &[])
}

fn mongodb_op_msg_with_ids(document: &[u8], request_id: i32, response_to: i32) -> Vec<u8> {
    mongodb_op_msg_with_flags_and_ids(document, 0, request_id, response_to)
}

fn mongodb_op_msg_with_flags_and_ids(
    document: &[u8],
    flags: u32,
    request_id: i32,
    response_to: i32,
) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&flags.to_le_bytes());
    body.extend_from_slice(&mongodb_op_msg_body_section(document));
    mongodb_frame_with_ids(2013, &body, request_id, response_to)
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

pub(super) fn bson_mongodb_error_document(code: i32, message: &[u8]) -> Vec<u8> {
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

fn bson_mongodb_write_error_document(
    write_error_code: i32,
    write_error_message: &[u8],
    write_concern_error: Option<(i32, &[u8])>,
) -> Vec<u8> {
    let mut elements = Vec::new();
    push_bson_bool(&mut elements, "ok", true);
    if write_error_code != 0 {
        let mut error = Vec::new();
        push_bson_i32(&mut error, "index", 0);
        push_bson_i32(&mut error, "code", write_error_code);
        push_bson_string(&mut error, "errmsg", write_error_message);
        let error = bson_document(error);

        let mut array = Vec::new();
        push_bson_document(&mut array, "0", &error, false);
        push_bson_document(&mut elements, "writeErrors", &bson_document(array), true);
    }
    if let Some((code, message)) = write_concern_error {
        let mut error = Vec::new();
        push_bson_i32(&mut error, "code", code);
        push_bson_string(&mut error, "errmsg", message);
        push_bson_document(
            &mut elements,
            "writeConcernError",
            &bson_document(error),
            false,
        );
    }
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

fn push_bson_document(elements: &mut Vec<u8>, key: &str, document: &[u8], array: bool) {
    elements.push(if array { 0x04 } else { 0x03 });
    elements.extend_from_slice(key.as_bytes());
    elements.push(0);
    elements.extend_from_slice(document);
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
