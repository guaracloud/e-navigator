use super::*;

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
            .any(|attribute| attribute.key == "db.system.name" && attribute.value == "mysql")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "db.operation.name" && attribute.value == "SELECT")
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
fn parses_mysql_handshake_capabilities_and_prefers_mutual_zlib() {
    let server = mysql_server_greeting((1 << 9) | (1 << 5) | (1 << 26));
    let client = mysql_client_handshake_response(1, (1 << 9) | (1 << 5) | (1 << 26));

    let server = parse_mysql_server_greeting(&server, 512).expect("server greeting parses");
    let client =
        parse_mysql_client_handshake_response(&client, 512).expect("client handshake parses");

    assert_eq!(server.capabilities, (1 << 9) | (1 << 5) | (1 << 26));
    assert_eq!(client.capabilities, (1 << 9) | (1 << 5) | (1 << 26));
    assert_eq!(
        negotiate_mysql_compression(server, client),
        MysqlCompressionAlgorithm::Zlib,
        "zlib has protocol-defined precedence when both algorithms are mutual",
    );
}

#[test]
fn mysql_compression_negotiation_requires_mutual_capabilities() {
    let zstd_server =
        parse_mysql_server_greeting(&mysql_server_greeting((1 << 9) | (1 << 26)), 512)
            .expect("server greeting parses");
    let zstd_client = parse_mysql_client_handshake_response(
        &mysql_client_handshake_response(1, (1 << 9) | (1 << 26)),
        512,
    )
    .expect("client handshake parses");
    assert_eq!(
        negotiate_mysql_compression(zstd_server, zstd_client),
        MysqlCompressionAlgorithm::Zstd,
    );

    let no_compression_client =
        parse_mysql_client_handshake_response(&mysql_client_handshake_response(1, 1 << 9), 512)
            .expect("client handshake parses");
    assert_eq!(
        negotiate_mysql_compression(zstd_server, no_compression_client),
        MysqlCompressionAlgorithm::Disabled,
    );
}

#[test]
fn decodes_bounded_mysql_zlib_and_passthrough_compressed_packets() {
    let logical_packets = [
        mysql_packet(0x03, b"SELECT secret FROM private_table"),
        mysql_packet(0x0e, b""),
    ]
    .concat();
    let compressed = mysql_compressed_packet(7, &logical_packets, true);
    let decoded = decode_mysql_compressed_packet(&compressed, 4_096)
        .expect("bounded zlib packet decompresses");
    assert_eq!(decoded.sequence_id, 7);
    assert_eq!(decoded.payload, logical_packets);

    let passthrough = mysql_compressed_packet(8, &logical_packets, false);
    let decoded = decode_mysql_compressed_packet(&passthrough, 4_096)
        .expect("zero uncompressed length passes payload through");
    assert_eq!(decoded.sequence_id, 8);
    assert_eq!(decoded.payload, logical_packets);
}

#[test]
fn rejects_ambiguous_or_unbounded_mysql_compression_frames() {
    let ssl_request = mysql_client_ssl_request((1 << 9) | (1 << 11) | (1 << 5));
    assert_eq!(
        parse_mysql_client_handshake_response(&ssl_request, 512).unwrap_err(),
        MysqlCompressionExtraction::MalformedHandshake,
        "an SSLRequest is not a full HandshakeResponse",
    );

    let payload = mysql_packet(0x0e, b"");
    let mut oversized = mysql_compressed_packet(0, &payload, true);
    oversized[4..7].copy_from_slice(&4_097_u32.to_le_bytes()[..3]);
    assert_eq!(
        decode_mysql_compressed_packet(&oversized, 4_096).unwrap_err(),
        MysqlCompressionExtraction::PacketTooLong,
    );

    let mut mismatched = mysql_compressed_packet(0, &payload, true);
    let wrong_len = u32::try_from(payload.len() + 1).expect("fixture length fits u32");
    mismatched[4..7].copy_from_slice(&wrong_len.to_le_bytes()[..3]);
    assert_eq!(
        decode_mysql_compressed_packet(&mismatched, 4_096).unwrap_err(),
        MysqlCompressionExtraction::LengthMismatch,
    );

    let mut trailing = mysql_compressed_packet(0, &payload, false);
    trailing.push(0);
    assert_eq!(
        decode_mysql_compressed_packet(&trailing, 4_096).unwrap_err(),
        MysqlCompressionExtraction::MalformedPacket,
    );
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
                .any(|attribute| attribute.key == "db.operation.name"
                    && attribute.value == operation)
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
            .any(|attribute| attribute.key == "db.operation.name" && attribute.value == "EXECUTE")
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
        attribute.key == "db.operation.name" && attribute.value == "SEND_LONG_DATA"
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
                .any(|attribute| attribute.key == "db.operation.name"
                    && attribute.value == operation)
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
            .any(|attribute| attribute.key == "db.operation.name" && attribute.value == "PING")
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
            .any(|attribute| attribute.key == "db.system.name" && attribute.value == "mysql")
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
            .any(|attribute| attribute.key == "db.system.name" && attribute.value == "mysql")
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
            .any(|attribute| attribute.key == "db.system.name" && attribute.value == "mysql")
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
fn mysql_local_infile_lifecycle_correlates_upload_without_retaining_file_bytes() {
    let config = ProtocolExtractionConfig::default();
    let request = mysql_packet(
        0x03,
        b"LOAD DATA LOCAL INFILE 'secret.csv' INTO TABLE private",
    );
    let mut lifecycle =
        MysqlResponseLifecycle::from_request(&request, &config).expect("query starts lifecycle");

    assert_eq!(
        lifecycle.observe_packet(
            &mysql_packet_with_sequence(1, b"\xfbsecret-server-path.csv"),
            &config,
        ),
        Ok(MysqlResponseProgress::Continue)
    );
    let data = mysql_packet_with_sequence(2, b"secret-file-row\n");
    assert_eq!(
        lifecycle.observe_client_packet(&data, data.len() as u64),
        Ok(MysqlClientPacketProgress::Continue)
    );
    let terminator = mysql_packet_with_sequence(3, b"");
    assert_eq!(
        lifecycle.observe_client_packet(&terminator, terminator.len() as u64),
        Ok(MysqlClientPacketProgress::UploadComplete)
    );
    let extra = mysql_packet_with_sequence(4, b"unexpected-secret-row");
    assert_eq!(
        lifecycle.observe_client_packet(&extra, extra.len() as u64),
        Err(MysqlExtraction::UnsupportedResponse)
    );

    let MysqlResponseProgress::Complete(response) = lifecycle
        .observe_packet(
            &mysql_packet_with_sequence(4, &[0, 0, 0, 2, 0, 0, 0]),
            &config,
        )
        .expect("terminal response completes original query")
    else {
        panic!("expected terminal LOCAL INFILE response");
    };
    assert_eq!(response.status_code, "OK");
    assert!(
        !response
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("secret-file-row")
                || attribute.value.contains("secret-server-path"))
    );
}

#[test]
fn mysql_local_infile_sequence_error_is_non_destructive() {
    let config = ProtocolExtractionConfig::default();
    let request = mysql_packet(0x03, b"LOAD DATA LOCAL INFILE 'secret.csv'");
    let mut lifecycle =
        MysqlResponseLifecycle::from_request(&request, &config).expect("query starts lifecycle");
    lifecycle
        .observe_packet(&mysql_packet_with_sequence(1, b"\xfbsecret.csv"), &config)
        .expect("server requests upload");

    let wrong = mysql_packet_with_sequence(3, b"secret");
    assert_eq!(
        lifecycle.observe_client_packet(&wrong, wrong.len() as u64),
        Err(MysqlExtraction::UnexpectedSequence)
    );
    let correct = mysql_packet_with_sequence(2, b"secret");
    assert_eq!(
        lifecycle.observe_client_packet(&correct, correct.len() as u64),
        Ok(MysqlClientPacketProgress::Continue)
    );
}

#[test]
fn mysql_large_logical_request_uses_one_lifecycle_and_advances_response_sequence() {
    let config = ProtocolExtractionConfig::default();
    let declared_len = (MYSQL_MAX_PHYSICAL_PAYLOAD_BYTES + 4) as u64;
    let first_prefix = [
        0xff, 0xff, 0xff, 0, 0x03, b'S', b'E', b'L', b'E', b'C', b'T', b' ',
    ];

    let parsed = parse_mysql_command_prefix(&first_prefix, declared_len, &config)
        .expect("bounded prefix identifies the first logical command");
    assert_eq!(parsed.operation.as_deref(), Some("SELECT"));

    let mut lifecycle =
        MysqlResponseLifecycle::from_request_prefix(&first_prefix, declared_len, &config)
            .expect("large query prefix starts one lifecycle");
    assert!(lifecycle.owns_request_continuation());

    let second_prefix = [0xff, 0xff, 0xff, 1, b's', b'e', b'c', b'r', b'e', b't'];
    assert_eq!(
        lifecycle.observe_request_continuation(&second_prefix, declared_len),
        Ok(MysqlLogicalPacketProgress::Continue)
    );
    let final_packet = mysql_packet_with_sequence(2, b"tail");
    assert_eq!(
        lifecycle.observe_request_continuation(&final_packet, final_packet.len() as u64),
        Ok(MysqlLogicalPacketProgress::Complete)
    );
    assert!(!lifecycle.owns_request_continuation());

    let MysqlResponseProgress::Complete(response) = lifecycle
        .observe_packet(
            &mysql_packet_with_sequence(3, &[0, 0, 0, 2, 0, 0, 0]),
            &config,
        )
        .expect("response starts after the final request packet sequence")
    else {
        panic!("expected the response to complete the logical query");
    };
    assert_eq!(response.status_code, "OK");
}

#[test]
fn mysql_large_logical_request_sequence_error_is_non_destructive() {
    let config = ProtocolExtractionConfig::default();
    let declared_len = (MYSQL_MAX_PHYSICAL_PAYLOAD_BYTES + 4) as u64;
    let first_prefix = [
        0xff, 0xff, 0xff, 0, 0x03, b'S', b'E', b'L', b'E', b'C', b'T',
    ];
    let mut lifecycle =
        MysqlResponseLifecycle::from_request_prefix(&first_prefix, declared_len, &config)
            .expect("large query prefix starts one lifecycle");

    let wrong = mysql_packet_with_sequence(2, b"tail");
    assert_eq!(
        lifecycle.observe_request_continuation(&wrong, wrong.len() as u64),
        Err(MysqlExtraction::UnexpectedSequence)
    );
    let correct = mysql_packet_with_sequence(1, b"tail");
    assert_eq!(
        lifecycle.observe_request_continuation(&correct, correct.len() as u64),
        Ok(MysqlLogicalPacketProgress::Complete)
    );
}

#[test]
fn mysql_large_command_prefix_does_not_guess_a_split_operation_token() {
    let config = ProtocolExtractionConfig::default();
    let declared_len = (MYSQL_MAX_PHYSICAL_PAYLOAD_BYTES + 4) as u64;
    let prefix = [
        0xff, 0xff, 0xff, 0, 0x03, b'S', b'E', b'L', b'E', b'C', b'T',
    ];

    let parsed = parse_mysql_command_prefix(&prefix, declared_len, &config)
        .expect("bounded prefix is a valid logical command");
    assert_eq!(parsed.operation, None);
}

#[test]
fn mysql_large_no_response_command_completes_after_its_final_physical_packet() {
    let config = ProtocolExtractionConfig::default();
    let declared_len = (MYSQL_MAX_PHYSICAL_PAYLOAD_BYTES + 4) as u64;
    let first_prefix = [
        0xff, 0xff, 0xff, 0, 0x18, 1, 0, 0, 0, 2, 0, b's', b'e', b'c', b'r', b'e', b't',
    ];
    let parsed = parse_mysql_command_prefix(&first_prefix, declared_len, &config)
        .expect("long-data prefix identifies the command");
    assert_eq!(parsed.operation.as_deref(), Some("SEND_LONG_DATA"));
    let mut lifecycle =
        MysqlResponseLifecycle::from_request_prefix(&first_prefix, declared_len, &config)
            .expect("large long-data command starts a lifecycle");
    assert!(!lifecycle.expects_response());
    assert!(lifecycle.owns_request_continuation());

    let final_packet = mysql_packet_with_sequence(1, b"tail");
    assert_eq!(
        lifecycle.observe_request_continuation(&final_packet, final_packet.len() as u64),
        Ok(MysqlLogicalPacketProgress::Complete)
    );
    assert!(!lifecycle.owns_request_continuation());
}

#[test]
fn mysql_large_result_row_continuations_do_not_complete_the_query() {
    let config = ProtocolExtractionConfig::default();
    let request = mysql_packet(0x03, b"SELECT secret_column FROM private_table");
    let mut lifecycle =
        MysqlResponseLifecycle::from_request(&request, &config).expect("query starts lifecycle");

    assert_eq!(
        lifecycle.observe_packet(&mysql_packet_with_sequence(1, &[1]), &config),
        Ok(MysqlResponseProgress::Continue)
    );
    assert_eq!(
        lifecycle.observe_packet(
            &mysql_packet_with_sequence(2, &mysql_column_definition()),
            &config,
        ),
        Ok(MysqlResponseProgress::Continue)
    );
    assert_eq!(
        lifecycle.observe_packet(&mysql_packet_with_sequence(3, &[0xfe, 0, 0, 2, 0]), &config,),
        Ok(MysqlResponseProgress::Continue)
    );

    let declared_len = (MYSQL_MAX_PHYSICAL_PAYLOAD_BYTES + 4) as u64;
    let row_prefix = [
        0xff, 0xff, 0xff, 4, 0x03, b's', b'e', b'c', b'r', b'e', b't',
    ];
    assert_eq!(
        lifecycle.observe_response_prefix(&row_prefix, declared_len),
        Ok(MysqlResponseProgress::Continue)
    );
    assert!(lifecycle.owns_response_continuation());
    assert_eq!(
        lifecycle.observe_packet(&mysql_packet_with_sequence(5, b"tail"), &config),
        Ok(MysqlResponseProgress::Continue)
    );
    assert!(!lifecycle.owns_response_continuation());

    assert!(matches!(
        lifecycle.observe_packet(&mysql_packet_with_sequence(6, &[0xfe, 0, 0, 2, 0]), &config,),
        Ok(MysqlResponseProgress::Complete(_))
    ));
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
        parse_mysql_response(&mysql_packet(0x00, b""), &config).unwrap_err(),
        MysqlExtraction::UnsupportedResponse
    );
    assert_eq!(
        parse_mysql_response(&mysql_packet(0x03, b"select 1"), &config).unwrap_err(),
        MysqlExtraction::UnsupportedResponse
    );
    assert_eq!(
        parse_mysql_response(&mysql_packet(0xfe, b"\xfbsecret-payload"), &config).unwrap_err(),
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

pub(super) fn mysql_packet(command: u8, query: &[u8]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(query.len() + 1);
    payload.push(command);
    payload.extend_from_slice(query);
    mysql_packet_with_sequence(0, &payload)
}

pub(super) fn mysql_packet_with_sequence(sequence: u8, payload: &[u8]) -> Vec<u8> {
    let payload_len = payload.len();
    let mut packet = Vec::with_capacity(payload_len + 4);
    packet.push((payload_len & 0xff) as u8);
    packet.push(((payload_len >> 8) & 0xff) as u8);
    packet.push(((payload_len >> 16) & 0xff) as u8);
    packet.push(sequence);
    packet.extend_from_slice(payload);
    packet
}

fn mysql_server_greeting(capabilities: u32) -> Vec<u8> {
    let mut payload = vec![0x0a];
    payload.extend_from_slice(b"8.0.36\0");
    payload.extend_from_slice(&42_u32.to_le_bytes());
    payload.extend_from_slice(b"12345678");
    payload.push(0);
    payload.extend_from_slice(&(capabilities as u16).to_le_bytes());
    payload.push(0x21);
    payload.extend_from_slice(&2_u16.to_le_bytes());
    payload.extend_from_slice(&((capabilities >> 16) as u16).to_le_bytes());
    payload.push(21);
    payload.extend_from_slice(&[0; 10]);
    payload.extend_from_slice(b"abcdefghijkl\0");
    mysql_packet_with_sequence(0, &payload)
}

fn mysql_client_handshake_response(sequence: u8, capabilities: u32) -> Vec<u8> {
    let mut payload = capabilities.to_le_bytes().to_vec();
    payload.extend_from_slice(&16_777_216_u32.to_le_bytes());
    payload.push(0x21);
    payload.extend_from_slice(&[0; 23]);
    payload.extend_from_slice(b"fixture-user\0");
    payload.push(0);
    mysql_packet_with_sequence(sequence, &payload)
}

fn mysql_client_ssl_request(capabilities: u32) -> Vec<u8> {
    let mut payload = capabilities.to_le_bytes().to_vec();
    payload.extend_from_slice(&16_777_216_u32.to_le_bytes());
    payload.push(0x21);
    payload.extend_from_slice(&[0; 23]);
    mysql_packet_with_sequence(1, &payload)
}

fn mysql_compressed_packet(sequence: u8, payload: &[u8], compress: bool) -> Vec<u8> {
    let (body, uncompressed_len) = if compress {
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::fast());
        encoder
            .write_all(payload)
            .expect("fixture zlib write succeeds");
        let body = encoder.finish().expect("fixture zlib finish succeeds");
        (body, payload.len())
    } else {
        (payload.to_vec(), 0)
    };
    let body_len = u32::try_from(body.len()).expect("fixture length fits u32");
    let uncompressed_len = u32::try_from(uncompressed_len).expect("fixture length fits u32");
    let mut packet = Vec::with_capacity(body.len() + 7);
    packet.extend_from_slice(&body_len.to_le_bytes()[..3]);
    packet.push(sequence);
    packet.extend_from_slice(&uncompressed_len.to_le_bytes()[..3]);
    packet.extend_from_slice(&body);
    packet
}

fn mysql_column_definition() -> Vec<u8> {
    let mut payload = Vec::new();
    for value in [
        b"def".as_slice(),
        b"db",
        b"table",
        b"table",
        b"name",
        b"name",
    ] {
        payload.push(u8::try_from(value.len()).expect("fixture component length fits u8"));
        payload.extend_from_slice(value);
    }
    payload.extend_from_slice(&[0x0c, 0x21, 0x00, 0, 0, 0, 0, 0xfd, 0, 0, 0, 0, 0]);
    payload
}

pub(super) fn mysql_error_packet(
    vendor_code: u16,
    sqlstate: Option<&[u8]>,
    message: &[u8],
) -> Vec<u8> {
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
