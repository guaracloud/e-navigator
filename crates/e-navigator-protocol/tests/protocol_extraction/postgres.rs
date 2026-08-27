use super::*;

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
            .any(|attribute| attribute.key == "db.system.name" && attribute.value == "postgresql")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "db.operation.name" && attribute.value == "SELECT")
    );
    assert!(extraction.attributes.iter().any(|attribute| attribute.key
        == "db.postgresql.message.type"
        && attribute.value == "query"));
    assert!(!extraction.attributes.iter().any(
        |attribute| attribute.value.contains("customers") || attribute.value.contains("secret")
    ));
}

#[test]
fn postgres_startup_parser_identifies_bounded_variants_without_exporting_parameters() {
    let config = ProtocolExtractionConfig::default();
    let mut startup_body = 196_608_u32.to_be_bytes().to_vec();
    startup_body.extend_from_slice(
        b"user\0secret-user\0database\0secret-database\0application_name\0secret-app\0\0",
    );
    let mut startup = ((startup_body.len() + 4) as u32).to_be_bytes().to_vec();
    startup.extend_from_slice(&startup_body);

    let parsed =
        parse_postgres_startup_message(&startup, &config).expect("protocol 3.0 startup parses");
    assert_eq!(parsed.kind, PostgresStartupKind::Startup);
    assert_eq!(parsed.operation.as_deref(), Some("CONNECT"));
    assert!(parsed.attributes.iter().any(|attribute| {
        attribute.key == "db.postgresql.message.type" && attribute.value == "startup"
    }));
    for secret in ["secret-user", "secret-database", "secret-app"] {
        assert!(
            !parsed
                .attributes
                .iter()
                .any(|attribute| attribute.value.contains(secret))
        );
    }

    for (code, kind, operation) in [
        (
            80877103_u32,
            PostgresStartupKind::SslRequest,
            "SSL_NEGOTIATE",
        ),
        (
            80877104_u32,
            PostgresStartupKind::GssEncryptionRequest,
            "GSS_NEGOTIATE",
        ),
    ] {
        let mut request = 8_u32.to_be_bytes().to_vec();
        request.extend_from_slice(&code.to_be_bytes());
        let parsed = parse_postgres_startup_message(&request, &config)
            .expect("encryption negotiation parses");
        assert_eq!(parsed.kind, kind);
        assert_eq!(parsed.operation.as_deref(), Some(operation));
    }

    let mut cancel = 16_u32.to_be_bytes().to_vec();
    cancel.extend_from_slice(&80877102_u32.to_be_bytes());
    cancel.extend_from_slice(&1234_u32.to_be_bytes());
    cancel.extend_from_slice(&0xfeed_beef_u32.to_be_bytes());
    let parsed = parse_postgres_startup_message(&cancel, &config).expect("cancel request parses");
    assert_eq!(parsed.kind, PostgresStartupKind::CancelRequest);
    assert_eq!(parsed.operation.as_deref(), Some("CANCEL"));
    assert!(
        !parsed
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("feed"))
    );
}

#[test]
fn postgres_startup_parser_rejects_unsupported_versions_and_unpaired_parameters() {
    let config = ProtocolExtractionConfig::default();
    let mut unsupported = 8_u32.to_be_bytes().to_vec();
    unsupported.extend_from_slice(&196_609_u32.to_be_bytes());
    assert_eq!(
        parse_postgres_startup_message(&unsupported, &config),
        Err(PostgresExtraction::UnsupportedMessage)
    );

    let body = b"\0\x03\0\0user\0missing-value\0";
    let mut malformed = ((body.len() + 4) as u32).to_be_bytes().to_vec();
    malformed.extend_from_slice(body);
    assert_eq!(
        parse_postgres_startup_message(&malformed, &config),
        Err(PostgresExtraction::MalformedFrame)
    );
}

#[test]
fn postgres_startup_lifecycle_owns_authentication_until_ready_for_query() {
    let config = ProtocolExtractionConfig::default();
    let mut body = 196_608_u32.to_be_bytes().to_vec();
    body.extend_from_slice(b"user\0secret-user\0\0");
    let mut startup = ((body.len() + 4) as u32).to_be_bytes().to_vec();
    startup.extend_from_slice(&body);
    let mut lifecycle = PostgresStartupLifecycle::from_request(&startup, &config)
        .expect("startup lifecycle begins");

    for response in [
        postgres_authentication_frame(10, b"SCRAM-SHA-256\0\0"),
        postgres_authentication_frame(11, b"secret-server-first"),
        postgres_authentication_frame(12, b"secret-server-final"),
        postgres_authentication_frame(0, b""),
        postgres_frame(b'S', b"server_version\x0017.11\0"),
        postgres_frame(b'K', &[0xaa; 8]),
    ] {
        assert_eq!(
            lifecycle.observe_response(&response, &config),
            Ok(PostgresStartupProgress::Continue)
        );
    }

    let PostgresStartupProgress::Complete(response) = lifecycle
        .observe_response(&postgres_frame(b'Z', b"I"), &config)
        .expect("ready completes startup")
    else {
        panic!("expected completed startup");
    };
    assert_eq!(response.status_code, "OK");
    assert!(
        !response
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("secret"))
    );
}

#[test]
fn postgres_simple_query_lifecycle_completes_only_at_ready_for_query() {
    let config = ProtocolExtractionConfig::default();
    let request = postgres_frame(b'Q', b"SELECT secret_value\0");
    let mut lifecycle = PostgresSimpleQueryLifecycle::from_request(&request, &config)
        .expect("postgres Query lifecycle starts");

    let command_complete = postgres_frame(b'C', b"SELECT 1\0");
    assert_eq!(
        lifecycle.observe_response(&command_complete, &config),
        Ok(PostgresSimpleQueryProgress::Continue)
    );

    let ready = postgres_frame(b'Z', b"I");
    let PostgresSimpleQueryProgress::Complete(response) = lifecycle
        .observe_response(&ready, &config)
        .expect("ReadyForQuery completes the cycle")
    else {
        panic!("expected terminal PostgreSQL response");
    };
    assert_eq!(response.status_code, "OK");
    assert_eq!(response.error_type, None);
    assert!(!response.attributes.iter().any(|attribute| {
        attribute.value.contains("secret") || attribute.value.contains("SELECT 1")
    }));
}

#[test]
fn postgres_simple_query_lifecycle_retains_first_error_until_readiness() {
    let config = ProtocolExtractionConfig::default();
    let request = postgres_frame(b'Q', b"INSERT INTO accounts VALUES (1)\0");
    let mut lifecycle = PostgresSimpleQueryLifecycle::from_request(&request, &config)
        .expect("postgres Query lifecycle starts");
    let error = postgres_error_response_frame(b"23505", b"secret constraint detail");

    assert_eq!(
        lifecycle.observe_response(&error, &config),
        Ok(PostgresSimpleQueryProgress::Continue)
    );
    assert_eq!(
        lifecycle.observe_response(&error, &config),
        Err(PostgresExtraction::UnexpectedMessage)
    );
    assert_eq!(
        lifecycle.observe_response(&postgres_frame(b'Z', b"X"), &config),
        Err(PostgresExtraction::MalformedFrame)
    );

    let ready = postgres_frame(b'Z', b"E");
    let PostgresSimpleQueryProgress::Complete(response) = lifecycle
        .observe_response(&ready, &config)
        .expect("ReadyForQuery completes the failed cycle")
    else {
        panic!("expected terminal PostgreSQL error");
    };
    assert_eq!(response.status_code, "23505");
    assert_eq!(response.error_type.as_deref(), Some("23505"));
    assert!(response.attributes.iter().any(|attribute| {
        attribute.key == "db.postgresql.transaction.status"
            && attribute.value == "failed_transaction"
    }));
    assert!(!response.attributes.iter().any(|attribute| {
        attribute.value.contains("secret")
            || attribute.value.contains("constraint")
            || attribute.value.contains("accounts")
    }));
}

#[test]
fn postgres_extended_lifecycles_require_their_exact_terminals() {
    let config = ProtocolExtractionConfig::default();

    let mut parse = PostgresRequestLifecycle::from_request(
        &postgres_frame(b'P', b"\0SELECT secret_value\0\0\0"),
        &config,
    )
    .expect("Parse lifecycle starts");
    assert_eq!(
        parse.observe_response(&postgres_frame(b'2', b""), &config),
        Err(PostgresExtraction::UnexpectedMessage)
    );
    assert!(matches!(
        parse.observe_response(&postgres_frame(b'1', b""), &config),
        Ok(PostgresRequestProgress::Complete {
            discard_until_sync: false,
            ..
        })
    ));

    let mut bind = PostgresRequestLifecycle::from_request(&postgres_frame(b'B', &[0; 8]), &config)
        .expect("Bind lifecycle starts");
    assert!(matches!(
        bind.observe_response(&postgres_frame(b'2', b""), &config),
        Ok(PostgresRequestProgress::Complete {
            discard_until_sync: false,
            ..
        })
    ));

    let mut statement_description =
        PostgresRequestLifecycle::from_request(&postgres_frame(b'D', b"S\0"), &config)
            .expect("statement Describe lifecycle starts");
    assert_eq!(
        statement_description.observe_response(&postgres_frame(b't', &[0, 0]), &config),
        Ok(PostgresRequestProgress::Continue)
    );
    assert_eq!(
        statement_description.observe_response(&postgres_frame(b't', &[0, 0]), &config),
        Err(PostgresExtraction::UnexpectedMessage)
    );
    assert!(matches!(
        statement_description.observe_response(&postgres_frame(b'n', b""), &config),
        Ok(PostgresRequestProgress::Complete {
            discard_until_sync: false,
            ..
        })
    ));

    let mut portal_description =
        PostgresRequestLifecycle::from_request(&postgres_frame(b'D', b"P\0"), &config)
            .expect("portal Describe lifecycle starts");
    assert!(matches!(
        portal_description.observe_response(
            &postgres_row_description_frame(&[b"secret_column_name"]),
            &config,
        ),
        Ok(PostgresRequestProgress::Complete {
            discard_until_sync: false,
            ..
        })
    ));

    let mut close = PostgresRequestLifecycle::from_request(&postgres_frame(b'C', b"P\0"), &config)
        .expect("Close lifecycle starts");
    assert!(matches!(
        close.observe_response(&postgres_frame(b'3', b""), &config),
        Ok(PostgresRequestProgress::Complete {
            discard_until_sync: false,
            ..
        })
    ));

    let mut execute =
        PostgresRequestLifecycle::from_request(&postgres_frame(b'E', &[0; 5]), &config)
            .expect("Execute lifecycle starts");
    assert_eq!(
        execute.observe_response(&postgres_data_row_frame(&[Some(b"secret-cell")]), &config),
        Ok(PostgresRequestProgress::Continue)
    );
    assert!(matches!(
        execute.observe_response(&postgres_frame(b's', b""), &config),
        Ok(PostgresRequestProgress::Complete {
            discard_until_sync: false,
            ..
        })
    ));
}

#[test]
fn postgres_extended_errors_discard_only_until_sync() {
    let config = ProtocolExtractionConfig::default();
    let error = postgres_error_response_frame(b"23505", b"secret constraint detail");
    let mut execute =
        PostgresRequestLifecycle::from_request(&postgres_frame(b'E', &[0; 5]), &config)
            .expect("Execute lifecycle starts");
    let PostgresRequestProgress::Complete {
        response,
        discard_until_sync,
    } = execute
        .observe_response(&error, &config)
        .expect("Execute error is terminal")
    else {
        panic!("expected terminal Execute error");
    };
    assert!(discard_until_sync);
    assert_eq!(response.error_type.as_deref(), Some("23505"));

    let mut sync = PostgresRequestLifecycle::from_request(&postgres_frame(b'S', b""), &config)
        .expect("Sync lifecycle starts");
    assert_eq!(
        sync.observe_response(&error, &config),
        Ok(PostgresRequestProgress::Continue)
    );
    assert_eq!(
        sync.observe_response(&postgres_frame(b'Z', b"X"), &config),
        Err(PostgresExtraction::MalformedFrame)
    );
    let PostgresRequestProgress::Complete {
        response,
        discard_until_sync,
    } = sync
        .observe_response(&postgres_frame(b'Z', b"E"), &config)
        .expect("ReadyForQuery completes Sync")
    else {
        panic!("expected terminal Sync response");
    };
    assert!(!discard_until_sync);
    assert_eq!(response.error_type.as_deref(), Some("23505"));
    assert!(response.attributes.iter().any(|attribute| {
        attribute.key == "db.postgresql.transaction.status"
            && attribute.value == "failed_transaction"
    }));
    assert!(!response.attributes.iter().any(|attribute| {
        attribute.value.contains("secret") || attribute.value.contains("constraint")
    }));
}

#[test]
fn postgres_function_call_and_authentication_follow_their_own_cycles() {
    let config = ProtocolExtractionConfig::default();
    let mut function =
        PostgresRequestLifecycle::from_request(&postgres_frame(b'F', &[0; 10]), &config)
            .expect("FunctionCall lifecycle starts");
    assert_eq!(
        function.observe_response(&postgres_frame(b'V', &[0xff; 4]), &config),
        Ok(PostgresRequestProgress::Continue)
    );
    assert!(matches!(
        function.observe_response(&postgres_frame(b'Z', b"I"), &config),
        Ok(PostgresRequestProgress::Complete {
            discard_until_sync: false,
            ..
        })
    ));

    let mut password = PostgresRequestLifecycle::from_request(
        &postgres_frame(b'p', b"secret-password\0"),
        &config,
    )
    .expect("Password lifecycle starts");
    let PostgresRequestProgress::Complete {
        response,
        discard_until_sync,
    } = password
        .observe_response(
            &postgres_authentication_frame(11, b"secret-challenge"),
            &config,
        )
        .expect("one authentication exchange completes")
    else {
        panic!("expected authentication response");
    };
    assert!(!discard_until_sync);
    assert_eq!(response.status_code, "AUTHENTICATION_REQUIRED");
    assert!(
        !response
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("secret"))
    );
}

#[test]
fn postgres_control_messages_explicitly_expect_no_response() {
    let config = ProtocolExtractionConfig::default();
    for request in [
        postgres_frame(b'd', b"secret-copy-row"),
        postgres_frame(b'c', b""),
        postgres_frame(b'f', b"secret-copy-error\0"),
        postgres_frame(b'H', b""),
        postgres_frame(b'X', b""),
    ] {
        let lifecycle = PostgresRequestLifecycle::from_request(&request, &config)
            .expect("control message lifecycle starts");
        assert!(!lifecycle.expects_response());
        assert!(!lifecycle.is_sync());
    }

    let sync = PostgresRequestLifecycle::from_request(&postgres_frame(b'S', b""), &config)
        .expect("Sync lifecycle starts");
    assert!(sync.expects_response());
    assert!(sync.is_sync());
    assert_eq!(
        PostgresRequestLifecycle::from_request(&postgres_frame(b'Q', b"SELECT 1\0"), &config,),
        Err(PostgresExtraction::UnsupportedMessage)
    );
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
            .any(|attribute| attribute.key == "db.operation.name" && attribute.value == "BIND")
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
                .any(|attribute| attribute.key == "db.operation.name"
                    && attribute.value == "DESCRIBE")
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
                .any(|attribute| attribute.key == "db.operation.name" && attribute.value == "CLOSE")
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
            .any(|attribute| attribute.key == "db.operation.name" && attribute.value == "PASSWORD")
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
            .any(|attribute| attribute.key == "db.operation.name" && attribute.value == "EXECUTE")
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
    assert!(extraction.attributes.iter().any(
        |attribute| attribute.key == "db.operation.name" && attribute.value == "FUNCTION_CALL"
    ));
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
                .any(|attribute| attribute.key == "db.operation.name"
                    && attribute.value == operation)
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
    for message_type in *b"GHW" {
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
            .any(|attribute| attribute.key == "db.operation.name" && attribute.value == "SYNC")
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
            .any(|attribute| attribute.key == "db.operation.name" && attribute.value == "FLUSH")
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
            .any(|attribute| attribute.key == "db.operation.name" && attribute.value == "TERMINATE")
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
            .any(|attribute| attribute.key == "db.system.name" && attribute.value == "postgresql")
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
    for message_type in *b"123Ins" {
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
            .any(|attribute| attribute.key == "db.system.name" && attribute.value == "postgresql")
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

pub(super) fn postgres_frame(message_type: u8, body: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(body.len() + 5);
    frame.push(message_type);
    frame.extend_from_slice(&((body.len() + 4) as u32).to_be_bytes());
    frame.extend_from_slice(body);
    frame
}

pub(super) fn postgres_error_response_frame(sqlstate: &[u8], message: &[u8]) -> Vec<u8> {
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
