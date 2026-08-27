use super::*;

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
fn extracts_kafka_offset_commit_ok_response_without_topic_values() {
    let bytes = kafka_offset_commit_response_frame(0, 7, &[("orders.secret", 0)]);

    let extraction =
        parse_kafka_offset_commit_response(&bytes, 7, &ProtocolExtractionConfig::default())
            .expect("offset commit ok response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "offset_commit");
    assert_eq!(extraction.status_code, "0");
    assert_eq!(extraction.error_type, None);
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "8")
    );
    assert!(extraction.attributes.iter().any(|attribute| {
        attribute.key == "messaging.kafka.response.error_code" && attribute.value == "0"
    }));
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("secret")
                || attribute.value.contains("orders"))
    );
}

#[test]
fn extracts_kafka_offset_commit_error_response_without_topic_values() {
    let bytes =
        kafka_offset_commit_response_frame(0, 3, &[("orders.secret", 0), ("payments.secret", 25)]);

    let extraction =
        parse_kafka_offset_commit_response(&bytes, 3, &ProtocolExtractionConfig::default())
            .expect("offset commit error response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "offset_commit");
    assert_eq!(extraction.status_code, "25");
    assert_eq!(extraction.error_type.as_deref(), Some("25"));
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_version"
                && attribute.value == "3")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "error.type" && attribute.value == "25")
    );
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("secret")
                || attribute.value.contains("orders")
                || attribute.value.contains("payments"))
    );
}

#[test]
fn extracts_kafka_offset_fetch_ok_response_without_topic_or_metadata_values() {
    let bytes = kafka_offset_fetch_response_frame(0, 5, 0, &[("orders.secret", 0)]);

    let extraction =
        parse_kafka_offset_fetch_response(&bytes, 5, &ProtocolExtractionConfig::default())
            .expect("offset fetch ok response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "offset_fetch");
    assert_eq!(extraction.status_code, "0");
    assert_eq!(extraction.error_type, None);
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "9")
    );
    assert!(extraction.attributes.iter().any(|attribute| {
        attribute.key == "messaging.kafka.response.error_code" && attribute.value == "0"
    }));
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("secret")
                || attribute.value.contains("orders")
                || attribute.value.contains("metadata"))
    );
}

#[test]
fn extracts_kafka_offset_fetch_partition_error_response_without_topic_or_metadata_values() {
    let bytes =
        kafka_offset_fetch_response_frame(0, 1, 0, &[("orders.secret", 0), ("other.secret", 25)]);

    let extraction =
        parse_kafka_offset_fetch_response(&bytes, 1, &ProtocolExtractionConfig::default())
            .expect("offset fetch partition error response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "offset_fetch");
    assert_eq!(extraction.status_code, "25");
    assert_eq!(extraction.error_type.as_deref(), Some("25"));
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_version"
                && attribute.value == "1")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "error.type" && attribute.value == "25")
    );
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("secret")
                || attribute.value.contains("orders")
                || attribute.value.contains("metadata"))
    );
}

#[test]
fn extracts_kafka_offset_fetch_top_level_error_response() {
    let bytes = kafka_offset_fetch_response_frame(0, 4, 30, &[("orders.secret", 0)]);

    let extraction =
        parse_kafka_offset_fetch_response(&bytes, 4, &ProtocolExtractionConfig::default())
            .expect("offset fetch top-level error response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "offset_fetch");
    assert_eq!(extraction.status_code, "30");
    assert_eq!(extraction.error_type.as_deref(), Some("30"));
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "error.type" && attribute.value == "30")
    );
}

#[test]
fn extracts_kafka_offset_delete_ok_response_without_topic_values() {
    let bytes = kafka_offset_delete_response_frame(0, 0, &[("orders.secret", 0)]);

    let extraction =
        parse_kafka_offset_delete_response(&bytes, 0, &ProtocolExtractionConfig::default())
            .expect("offset delete ok response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "offset_delete");
    assert_eq!(extraction.status_code, "0");
    assert_eq!(extraction.error_type, None);
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "47")
    );
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
fn extracts_kafka_offset_delete_partition_error_response_without_topic_values() {
    let bytes =
        kafka_offset_delete_response_frame(0, 0, &[("orders.secret", 0), ("payments.secret", 6)]);

    let extraction =
        parse_kafka_offset_delete_response(&bytes, 0, &ProtocolExtractionConfig::default())
            .expect("offset delete partition error response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "offset_delete");
    assert_eq!(extraction.status_code, "6");
    assert_eq!(extraction.error_type.as_deref(), Some("6"));
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
fn extracts_kafka_offset_delete_top_level_error_response() {
    let bytes = kafka_offset_delete_response_frame(0, 30, &[("orders.secret", 0)]);

    let extraction =
        parse_kafka_offset_delete_response(&bytes, 0, &ProtocolExtractionConfig::default())
            .expect("offset delete top-level error response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "offset_delete");
    assert_eq!(extraction.status_code, "30");
    assert_eq!(extraction.error_type.as_deref(), Some("30"));
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "error.type" && attribute.value == "30")
    );
}

#[test]
fn extracts_kafka_describe_client_quotas_v0_ok_response_without_entity_or_quota_values() {
    let entities: &[DescribeClientQuotasEntityFixture<'_>] =
        &[("client-id", Some("secret-client-a"))];
    let values: &[DescribeClientQuotasValueFixture<'_>] = &[("producer_byte_rate.secret", 42.0)];
    let entries: &[DescribeClientQuotasEntryFixture<'_>] = &[(entities, values)];
    let bytes = kafka_describe_client_quotas_response_frame(0, 0, 0, None, Some(entries));

    let extraction = parse_kafka_describe_client_quotas_response(
        &bytes,
        0,
        &ProtocolExtractionConfig::default(),
    )
    .expect("describe client quotas v0 ok response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "describe_client_quotas");
    assert_eq!(extraction.status_code, "0");
    assert_eq!(extraction.error_type, None);
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "48")
    );
    assert!(extraction.attributes.iter().any(|attribute| {
        attribute.key == "messaging.kafka.response.error_code" && attribute.value == "0"
    }));
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("client-id")
                || attribute.value.contains("producer")
                || attribute.value.contains("secret"))
    );
}

#[test]
fn extracts_kafka_describe_client_quotas_v1_error_response_without_entity_or_message_values() {
    let entities: &[DescribeClientQuotasEntityFixture<'_>] =
        &[("client-id", Some("secret-client-a"))];
    let values: &[DescribeClientQuotasValueFixture<'_>] = &[("producer_byte_rate.secret", 42.0)];
    let entries: &[DescribeClientQuotasEntryFixture<'_>] = &[(entities, values)];
    let bytes = kafka_describe_client_quotas_response_frame(
        0,
        1,
        31,
        Some("top secret denied"),
        Some(entries),
    );

    let extraction = parse_kafka_describe_client_quotas_response(
        &bytes,
        1,
        &ProtocolExtractionConfig::default(),
    )
    .expect("describe client quotas v1 error response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "describe_client_quotas");
    assert_eq!(extraction.status_code, "31");
    assert_eq!(extraction.error_type.as_deref(), Some("31"));
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_version"
                && attribute.value == "1")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "error.type" && attribute.value == "31")
    );
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("client-id")
                || attribute.value.contains("producer")
                || attribute.value.contains("denied")
                || attribute.value.contains("secret"))
    );
}

#[test]
fn extracts_kafka_alter_client_quotas_v0_ok_response_without_entity_values() {
    let entities: &[ClientQuotaEntityFixture<'_>] = &[("client-id", Some("secret-client-a"))];
    let entries: &[AlterClientQuotaResultFixture<'_>] = &[(0, None, entities)];
    let bytes = kafka_alter_client_quotas_response_frame(0, 0, entries);

    let extraction =
        parse_kafka_alter_client_quotas_response(&bytes, 0, &ProtocolExtractionConfig::default())
            .expect("alter client quotas v0 ok response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "alter_client_quotas");
    assert_eq!(extraction.status_code, "0");
    assert_eq!(extraction.error_type, None);
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "49")
    );
    assert!(extraction.attributes.iter().any(|attribute| {
        attribute.key == "messaging.kafka.response.error_code" && attribute.value == "0"
    }));
    assert!(!extraction.attributes.iter().any(
        |attribute| attribute.value.contains("client-id") || attribute.value.contains("secret")
    ));
}

#[test]
fn extracts_kafka_alter_client_quotas_v1_error_response_without_entity_or_message_values() {
    let entities: &[ClientQuotaEntityFixture<'_>] = &[("client-id", Some("secret-client-a"))];
    let entries: &[AlterClientQuotaResultFixture<'_>] = &[
        (0, None, entities),
        (31, Some("top secret denied"), entities),
    ];
    let bytes = kafka_alter_client_quotas_response_frame(0, 1, entries);

    let extraction =
        parse_kafka_alter_client_quotas_response(&bytes, 1, &ProtocolExtractionConfig::default())
            .expect("alter client quotas v1 error response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "alter_client_quotas");
    assert_eq!(extraction.status_code, "31");
    assert_eq!(extraction.error_type.as_deref(), Some("31"));
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_version"
                && attribute.value == "1")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "error.type" && attribute.value == "31")
    );
    assert!(!extraction.attributes.iter().any(|attribute| {
        attribute.value.contains("client-id")
            || attribute.value.contains("denied")
            || attribute.value.contains("secret")
    }));
}

#[test]
fn extracts_kafka_describe_user_scram_credentials_ok_response_without_user_values() {
    let credentials: &[UserScramCredentialInfoFixture] = &[(0, 4096)];
    let results: &[DescribeUserScramCredentialsResultFixture<'_>] =
        &[("alice.secret", 0, None, credentials)];
    let bytes = kafka_describe_user_scram_credentials_response_frame(0, 0, None, results);

    let extraction = parse_kafka_describe_user_scram_credentials_response(
        &bytes,
        0,
        &ProtocolExtractionConfig::default(),
    )
    .expect("describe user scram credentials ok response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "describe_user_scram_credentials");
    assert_eq!(extraction.status_code, "0");
    assert_eq!(extraction.error_type, None);
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "50")
    );
    assert!(extraction.attributes.iter().any(|attribute| {
        attribute.key == "messaging.kafka.response.error_code" && attribute.value == "0"
    }));
    assert!(
        !extraction.attributes.iter().any(
            |attribute| attribute.value.contains("alice") || attribute.value.contains("secret")
        )
    );
}

#[test]
fn extracts_kafka_describe_user_scram_credentials_user_error_without_user_or_message_values() {
    let results: &[DescribeUserScramCredentialsResultFixture<'_>] = &[
        ("alice.secret", 0, None, &[]),
        ("bob.secret", 51, Some("user secret denied"), &[]),
    ];
    let bytes = kafka_describe_user_scram_credentials_response_frame(0, 0, None, results);

    let extraction = parse_kafka_describe_user_scram_credentials_response(
        &bytes,
        0,
        &ProtocolExtractionConfig::default(),
    )
    .expect("describe user scram credentials user error response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "describe_user_scram_credentials");
    assert_eq!(extraction.status_code, "51");
    assert_eq!(extraction.error_type.as_deref(), Some("51"));
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "error.type" && attribute.value == "51")
    );
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("alice")
                || attribute.value.contains("bob")
                || attribute.value.contains("denied")
                || attribute.value.contains("secret"))
    );
}

#[test]
fn extracts_kafka_describe_user_scram_credentials_top_level_error_before_user_error() {
    let results: &[DescribeUserScramCredentialsResultFixture<'_>] =
        &[("alice.secret", 51, Some("user secret denied"), &[])];
    let bytes = kafka_describe_user_scram_credentials_response_frame(
        0,
        31,
        Some("top secret denied"),
        results,
    );

    let extraction = parse_kafka_describe_user_scram_credentials_response(
        &bytes,
        0,
        &ProtocolExtractionConfig::default(),
    )
    .expect("describe user scram credentials top-level error response parses");

    assert_eq!(extraction.status_code, "31");
    assert_eq!(extraction.error_type.as_deref(), Some("31"));
}

#[test]
fn extracts_kafka_alter_user_scram_credentials_ok_response_without_user_values() {
    let results: &[AlterUserScramCredentialsResultFixture<'_>] = &[("alice.secret", 0, None)];
    let bytes = kafka_alter_user_scram_credentials_response_frame(0, results);

    let extraction = parse_kafka_alter_user_scram_credentials_response(
        &bytes,
        0,
        &ProtocolExtractionConfig::default(),
    )
    .expect("alter user scram credentials ok response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "alter_user_scram_credentials");
    assert_eq!(extraction.status_code, "0");
    assert_eq!(extraction.error_type, None);
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "51")
    );
    assert!(extraction.attributes.iter().any(|attribute| {
        attribute.key == "messaging.kafka.response.error_code" && attribute.value == "0"
    }));
    assert!(
        !extraction.attributes.iter().any(
            |attribute| attribute.value.contains("alice") || attribute.value.contains("secret")
        )
    );
}

#[test]
fn extracts_kafka_alter_user_scram_credentials_error_response_without_user_or_message_values() {
    let results: &[AlterUserScramCredentialsResultFixture<'_>] = &[
        ("alice.secret", 0, None),
        ("bob.secret", 51, Some("user secret denied")),
    ];
    let bytes = kafka_alter_user_scram_credentials_response_frame(0, results);

    let extraction = parse_kafka_alter_user_scram_credentials_response(
        &bytes,
        0,
        &ProtocolExtractionConfig::default(),
    )
    .expect("alter user scram credentials error response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "alter_user_scram_credentials");
    assert_eq!(extraction.status_code, "51");
    assert_eq!(extraction.error_type.as_deref(), Some("51"));
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "error.type" && attribute.value == "51")
    );
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("alice")
                || attribute.value.contains("bob")
                || attribute.value.contains("denied")
                || attribute.value.contains("secret"))
    );
}

#[test]
fn extracts_kafka_describe_quorum_v0_ok_response_without_topic_or_replica_values() {
    let partitions: &[DescribeQuorumPartitionFixture<'_>] = &[(0, 0, None)];
    let topics: &[DescribeQuorumTopicFixture<'_>] = &[("orders.secret", partitions)];
    let bytes = kafka_describe_quorum_response_frame(0, 0, 0, None, topics, &[]);

    let extraction =
        parse_kafka_describe_quorum_response(&bytes, 0, &ProtocolExtractionConfig::default())
            .expect("describe quorum v0 ok response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "describe_quorum");
    assert_eq!(extraction.status_code, "0");
    assert_eq!(extraction.error_type, None);
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "55")
    );
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
fn extracts_kafka_describe_quorum_v1_partition_error_without_topic_values() {
    let partitions: &[DescribeQuorumPartitionFixture<'_>] =
        &[(0, 0, None), (1, 35, Some("partition secret denied"))];
    let topics: &[DescribeQuorumTopicFixture<'_>] = &[("metadata.secret", partitions)];
    let bytes = kafka_describe_quorum_response_frame(0, 1, 0, None, topics, &[]);

    let extraction =
        parse_kafka_describe_quorum_response(&bytes, 1, &ProtocolExtractionConfig::default())
            .expect("describe quorum v1 partition error response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "describe_quorum");
    assert_eq!(extraction.status_code, "35");
    assert_eq!(extraction.error_type.as_deref(), Some("35"));
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_version"
                && attribute.value == "1")
    );
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
            .any(|attribute| attribute.value.contains("metadata")
                || attribute.value.contains("denied")
                || attribute.value.contains("secret"))
    );
}

#[test]
fn extracts_kafka_describe_quorum_v2_top_level_error_before_partition_error() {
    let partitions: &[DescribeQuorumPartitionFixture<'_>] =
        &[(0, 35, Some("partition secret denied"))];
    let topics: &[DescribeQuorumTopicFixture<'_>] = &[("metadata.secret", partitions)];
    let listeners: &[DescribeQuorumListenerFixture<'_>] =
        &[("CONTROLLER.secret", "controller.secret.internal", 9093)];
    let nodes: &[DescribeQuorumNodeFixture<'_>] = &[(1, listeners)];
    let bytes =
        kafka_describe_quorum_response_frame(0, 2, 31, Some("top secret denied"), topics, nodes);

    let extraction =
        parse_kafka_describe_quorum_response(&bytes, 2, &ProtocolExtractionConfig::default())
            .expect("describe quorum v2 top-level error response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "describe_quorum");
    assert_eq!(extraction.status_code, "31");
    assert_eq!(extraction.error_type.as_deref(), Some("31"));
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
            .any(|attribute| attribute.value.contains("metadata")
                || attribute.value.contains("controller")
                || attribute.value.contains("denied")
                || attribute.value.contains("secret"))
    );
}

#[test]
fn extracts_kafka_update_features_v0_ok_response_without_feature_values() {
    let results: &[UpdateFeaturesResultFixture<'_>] = &[("metadata.version.secret", 0, None)];
    let bytes = kafka_update_features_response_frame(0, 0, 0, None, results);

    let extraction =
        parse_kafka_update_features_response(&bytes, 0, &ProtocolExtractionConfig::default())
            .expect("update features v0 ok response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "update_features");
    assert_eq!(extraction.status_code, "0");
    assert_eq!(extraction.error_type, None);
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "57")
    );
    assert!(extraction.attributes.iter().any(|attribute| {
        attribute.key == "messaging.kafka.response.error_code" && attribute.value == "0"
    }));
    assert!(!extraction.attributes.iter().any(
        |attribute| attribute.value.contains("metadata") || attribute.value.contains("secret")
    ));
}

#[test]
fn extracts_kafka_update_features_v1_feature_error_without_feature_or_message_values() {
    let results: &[UpdateFeaturesResultFixture<'_>] = &[
        ("metadata.version.secret", 0, None),
        ("kraft.version.secret", 35, Some("feature secret denied")),
    ];
    let bytes = kafka_update_features_response_frame(0, 1, 0, None, results);

    let extraction =
        parse_kafka_update_features_response(&bytes, 1, &ProtocolExtractionConfig::default())
            .expect("update features v1 feature error response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "update_features");
    assert_eq!(extraction.status_code, "35");
    assert_eq!(extraction.error_type.as_deref(), Some("35"));
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_version"
                && attribute.value == "1")
    );
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
            .any(|attribute| attribute.value.contains("metadata")
                || attribute.value.contains("kraft")
                || attribute.value.contains("denied")
                || attribute.value.contains("secret"))
    );
}

#[test]
fn extracts_kafka_update_features_v2_top_level_error_without_message_values() {
    let bytes = kafka_update_features_response_frame(0, 2, 31, Some("top secret denied"), &[]);

    let extraction =
        parse_kafka_update_features_response(&bytes, 2, &ProtocolExtractionConfig::default())
            .expect("update features v2 top-level error response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "update_features");
    assert_eq!(extraction.status_code, "31");
    assert_eq!(extraction.error_type.as_deref(), Some("31"));
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
            .any(|attribute| attribute.value.contains("denied")
                || attribute.value.contains("secret"))
    );
}

#[test]
fn extracts_kafka_describe_cluster_v0_ok_response_without_cluster_or_broker_values() {
    let brokers: &[DescribeClusterBrokerFixture<'_>] = &[(
        1,
        "broker.secret.internal",
        9092,
        Some("rack.secret"),
        false,
    )];
    let bytes = kafka_describe_cluster_response_frame(0, 0, 0, None, "cluster.secret", brokers);

    let extraction =
        parse_kafka_describe_cluster_response(&bytes, 0, &ProtocolExtractionConfig::default())
            .expect("describe cluster v0 ok response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "describe_cluster");
    assert_eq!(extraction.status_code, "0");
    assert_eq!(extraction.error_type, None);
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "60")
    );
    assert!(extraction.attributes.iter().any(|attribute| {
        attribute.key == "messaging.kafka.response.error_code" && attribute.value == "0"
    }));
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("broker")
                || attribute.value.contains("rack")
                || attribute.value.contains("secret"))
    );
}

#[test]
fn extracts_kafka_describe_cluster_v2_error_response_without_message_or_broker_values() {
    let brokers: &[DescribeClusterBrokerFixture<'_>] = &[(
        1,
        "controller.secret.internal",
        9093,
        Some("rack.secret"),
        true,
    )];
    let bytes = kafka_describe_cluster_response_frame(
        0,
        2,
        31,
        Some("cluster secret denied"),
        "cluster.secret",
        brokers,
    );

    let extraction =
        parse_kafka_describe_cluster_response(&bytes, 2, &ProtocolExtractionConfig::default())
            .expect("describe cluster v2 error response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "describe_cluster");
    assert_eq!(extraction.status_code, "31");
    assert_eq!(extraction.error_type.as_deref(), Some("31"));
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
            .any(|attribute| attribute.value.contains("controller")
                || attribute.value.contains("denied")
                || attribute.value.contains("secret"))
    );
}

#[test]
fn extracts_kafka_describe_producers_ok_response_without_topic_or_producer_values() {
    let partitions: &[DescribeProducersPartitionFixture<'_>] = &[(0, 0, None, 1)];
    let topics: &[DescribeProducersTopicFixture<'_>] = &[("orders.secret", partitions)];
    let bytes = kafka_describe_producers_response_frame(0, topics);

    let extraction =
        parse_kafka_describe_producers_response(&bytes, 0, &ProtocolExtractionConfig::default())
            .expect("describe producers ok response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "describe_producers");
    assert_eq!(extraction.status_code, "0");
    assert_eq!(extraction.error_type, None);
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "61")
    );
    assert!(extraction.attributes.iter().any(|attribute| {
        attribute.key == "messaging.kafka.response.error_code" && attribute.value == "0"
    }));
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("orders")
                || attribute.value.contains("1001")
                || attribute.value.contains("secret"))
    );
}

#[test]
fn extracts_kafka_describe_producers_partition_error_without_topic_or_message_values() {
    let partitions: &[DescribeProducersPartitionFixture<'_>] =
        &[(0, 0, None, 1), (1, 35, Some("producer secret denied"), 2)];
    let topics: &[DescribeProducersTopicFixture<'_>] = &[("orders.secret", partitions)];
    let bytes = kafka_describe_producers_response_frame(0, topics);

    let extraction =
        parse_kafka_describe_producers_response(&bytes, 0, &ProtocolExtractionConfig::default())
            .expect("describe producers partition error response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "describe_producers");
    assert_eq!(extraction.status_code, "35");
    assert_eq!(extraction.error_type.as_deref(), Some("35"));
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_version"
                && attribute.value == "0")
    );
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
            .any(|attribute| attribute.value.contains("orders")
                || attribute.value.contains("denied")
                || attribute.value.contains("1002")
                || attribute.value.contains("secret"))
    );
}

#[test]
fn extracts_kafka_unregister_broker_ok_response() {
    let bytes = kafka_unregister_broker_response_frame(0, 0, None);

    let extraction =
        parse_kafka_unregister_broker_response(&bytes, 0, &ProtocolExtractionConfig::default())
            .expect("unregister broker ok response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "unregister_broker");
    assert_eq!(extraction.status_code, "0");
    assert_eq!(extraction.error_type, None);
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "64")
    );
    assert!(extraction.attributes.iter().any(|attribute| {
        attribute.key == "messaging.kafka.response.error_code" && attribute.value == "0"
    }));
}

#[test]
fn extracts_kafka_broker_heartbeat_ok_response() {
    let bytes = kafka_broker_heartbeat_response_frame(0, 0, true, false, false);

    let extraction =
        parse_kafka_broker_heartbeat_response(&bytes, 0, &ProtocolExtractionConfig::default())
            .expect("broker heartbeat ok response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "broker_heartbeat");
    assert_eq!(extraction.status_code, "0");
    assert_eq!(extraction.error_type, None);
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "63")
    );
    assert!(extraction.attributes.iter().any(|attribute| {
        attribute.key == "messaging.kafka.response.error_code" && attribute.value == "0"
    }));
}

#[test]
fn extracts_kafka_broker_heartbeat_error_response() {
    let bytes = kafka_broker_heartbeat_response_frame(0, 35, false, true, true);

    let extraction =
        parse_kafka_broker_heartbeat_response(&bytes, 2, &ProtocolExtractionConfig::default())
            .expect("broker heartbeat error response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "broker_heartbeat");
    assert_eq!(extraction.status_code, "35");
    assert_eq!(extraction.error_type.as_deref(), Some("35"));
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_version"
                && attribute.value == "2")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "error.type" && attribute.value == "35")
    );
}

#[test]
fn rejects_malformed_kafka_broker_heartbeat_responses() {
    let config = ProtocolExtractionConfig::default();

    assert_eq!(
        parse_kafka_broker_heartbeat_response(
            &kafka_broker_heartbeat_response_frame(0, 0, true, false, false),
            3,
            &config,
        ),
        Err(KafkaExtraction::UnsupportedApiVersion)
    );

    let mut truncated = kafka_broker_heartbeat_response_frame(0, 0, true, false, false);
    truncated.truncate(12);
    assert_eq!(
        parse_kafka_broker_heartbeat_response(&truncated, 0, &config),
        Err(KafkaExtraction::MalformedFrame)
    );
    assert_eq!(
        parse_kafka_broker_heartbeat_response(
            &kafka_broker_heartbeat_response_with_tag_value_len_frame(5),
            2,
            &ProtocolExtractionConfig {
                max_header_bytes: 128,
                max_request_line_bytes: 4,
                max_attributes: 8,
                max_tracestate_bytes: 32,
            },
        ),
        Err(KafkaExtraction::FrameTooLong)
    );
}

#[test]
fn extracts_kafka_unregister_broker_error_without_message_values() {
    let bytes = kafka_unregister_broker_response_frame(0, 35, Some("broker secret denied"));

    let extraction =
        parse_kafka_unregister_broker_response(&bytes, 0, &ProtocolExtractionConfig::default())
            .expect("unregister broker error response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "unregister_broker");
    assert_eq!(extraction.status_code, "35");
    assert_eq!(extraction.error_type.as_deref(), Some("35"));
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_version"
                && attribute.value == "0")
    );
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
            .any(|attribute| attribute.value.contains("denied")
                || attribute.value.contains("secret"))
    );
}

#[test]
fn extracts_kafka_describe_transactions_ok_response_without_transaction_or_topic_values() {
    let topics: &[DescribeTransactionsTopicFixture<'_>] = &[("orders.secret", &[0, 1])];
    let states: &[DescribeTransactionsStateFixture<'_>] =
        &[(0, "txn.secret", "ongoing.secret", 1001, topics)];
    let bytes = kafka_describe_transactions_response_frame(0, states);

    let extraction =
        parse_kafka_describe_transactions_response(&bytes, 0, &ProtocolExtractionConfig::default())
            .expect("describe transactions ok response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "describe_transactions");
    assert_eq!(extraction.status_code, "0");
    assert_eq!(extraction.error_type, None);
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "65")
    );
    assert!(extraction.attributes.iter().any(|attribute| {
        attribute.key == "messaging.kafka.response.error_code" && attribute.value == "0"
    }));
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("txn")
                || attribute.value.contains("ongoing")
                || attribute.value.contains("orders")
                || attribute.value.contains("1001")
                || attribute.value.contains("secret"))
    );
}

#[test]
fn extracts_kafka_describe_transactions_error_without_transaction_or_state_values() {
    let topics: &[DescribeTransactionsTopicFixture<'_>] = &[("payments.secret", &[2])];
    let states: &[DescribeTransactionsStateFixture<'_>] = &[
        (0, "txn-ok.secret", "ongoing.secret", 1001, &[]),
        (
            35,
            "txn-denied.secret",
            "prepare_abort.secret",
            1002,
            topics,
        ),
    ];
    let bytes = kafka_describe_transactions_response_frame(0, states);

    let extraction =
        parse_kafka_describe_transactions_response(&bytes, 0, &ProtocolExtractionConfig::default())
            .expect("describe transactions error response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "describe_transactions");
    assert_eq!(extraction.status_code, "35");
    assert_eq!(extraction.error_type.as_deref(), Some("35"));
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_version"
                && attribute.value == "0")
    );
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
            .any(|attribute| attribute.value.contains("txn")
                || attribute.value.contains("abort")
                || attribute.value.contains("payments")
                || attribute.value.contains("1002")
                || attribute.value.contains("secret"))
    );
}

#[test]
fn extracts_kafka_list_transactions_ok_response_without_transaction_values() {
    let states: &[ListTransactionsStateFixture<'_>] = &[("txn.secret", 1001, "ongoing.secret")];
    let bytes = kafka_list_transactions_response_frame(0, 0, &[], states);

    let extraction =
        parse_kafka_list_transactions_response(&bytes, 0, &ProtocolExtractionConfig::default())
            .expect("list transactions ok response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "list_transactions");
    assert_eq!(extraction.status_code, "0");
    assert_eq!(extraction.error_type, None);
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "66")
    );
    assert!(extraction.attributes.iter().any(|attribute| {
        attribute.key == "messaging.kafka.response.error_code" && attribute.value == "0"
    }));
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("txn")
                || attribute.value.contains("ongoing")
                || attribute.value.contains("1001")
                || attribute.value.contains("secret"))
    );
}

#[test]
fn extracts_kafka_list_transactions_error_without_filter_or_state_values() {
    let states: &[ListTransactionsStateFixture<'_>] =
        &[("txn-denied.secret", 1002, "prepare_abort.secret")];
    let bytes = kafka_list_transactions_response_frame(0, 35, &["unknown.secret"], states);

    let extraction =
        parse_kafka_list_transactions_response(&bytes, 2, &ProtocolExtractionConfig::default())
            .expect("list transactions error response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "list_transactions");
    assert_eq!(extraction.status_code, "35");
    assert_eq!(extraction.error_type.as_deref(), Some("35"));
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_version"
                && attribute.value == "2")
    );
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
            .any(|attribute| attribute.value.contains("unknown")
                || attribute.value.contains("txn")
                || attribute.value.contains("abort")
                || attribute.value.contains("1002")
                || attribute.value.contains("secret"))
    );
}

#[test]
fn extracts_kafka_allocate_producer_ids_ok_response_without_producer_values() {
    let bytes = kafka_allocate_producer_ids_response_frame(0, 0, 9_000_000, 1_000);

    let extraction =
        parse_kafka_allocate_producer_ids_response(&bytes, 0, &ProtocolExtractionConfig::default())
            .expect("allocate producer ids ok response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "allocate_producer_ids");
    assert_eq!(extraction.status_code, "0");
    assert_eq!(extraction.error_type, None);
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "67")
    );
    assert!(extraction.attributes.iter().any(|attribute| {
        attribute.key == "messaging.kafka.response.error_code" && attribute.value == "0"
    }));
    assert!(
        !extraction.attributes.iter().any(
            |attribute| attribute.value.contains("9000000") || attribute.value.contains("1000")
        )
    );
}

#[test]
fn extracts_kafka_allocate_producer_ids_error_response_without_producer_values() {
    let bytes = kafka_allocate_producer_ids_response_frame(0, 35, 9_000_000, 1_000);

    let extraction =
        parse_kafka_allocate_producer_ids_response(&bytes, 0, &ProtocolExtractionConfig::default())
            .expect("allocate producer ids error response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "allocate_producer_ids");
    assert_eq!(extraction.status_code, "35");
    assert_eq!(extraction.error_type.as_deref(), Some("35"));
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_version"
                && attribute.value == "0")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "error.type" && attribute.value == "35")
    );
    assert!(
        !extraction.attributes.iter().any(
            |attribute| attribute.value.contains("9000000") || attribute.value.contains("1000")
        )
    );
}

#[test]
fn rejects_malformed_kafka_allocate_producer_ids_responses() {
    let config = ProtocolExtractionConfig::default();

    assert_eq!(
        parse_kafka_allocate_producer_ids_response(
            &kafka_allocate_producer_ids_response_frame(0, 0, 9_000_000, 1_000),
            1,
            &config,
        ),
        Err(KafkaExtraction::UnsupportedApiVersion)
    );

    let mut truncated = kafka_allocate_producer_ids_response_frame(0, 0, 9_000_000, 1_000);
    truncated.truncate(16);
    assert_eq!(
        parse_kafka_allocate_producer_ids_response(&truncated, 0, &config),
        Err(KafkaExtraction::MalformedFrame)
    );
}

#[test]
fn extracts_kafka_consumer_group_heartbeat_ok_response_without_member_or_assignment_values() {
    let assignment: &[ConsumerGroupHeartbeatTopicPartitionsFixture<'_>] = &[([9_u8; 16], &[0, 1])];
    let bytes = kafka_consumer_group_heartbeat_response_frame(
        0,
        0,
        None,
        Some("member.secret"),
        Some(assignment),
    );

    let extraction = parse_kafka_consumer_group_heartbeat_response(
        &bytes,
        0,
        &ProtocolExtractionConfig::default(),
    )
    .expect("consumer group heartbeat ok response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "consumer_group_heartbeat");
    assert_eq!(extraction.status_code, "0");
    assert_eq!(extraction.error_type, None);
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "68")
    );
    assert!(extraction.attributes.iter().any(|attribute| {
        attribute.key == "messaging.kafka.response.error_code" && attribute.value == "0"
    }));
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("member")
                || attribute.value.contains("secret")
                || attribute.value.contains("9"))
    );
}

#[test]
fn extracts_kafka_consumer_group_heartbeat_error_without_message_values() {
    let bytes = kafka_consumer_group_heartbeat_response_frame(
        0,
        35,
        Some("heartbeat secret denied"),
        Some("member.secret"),
        None,
    );

    let extraction = parse_kafka_consumer_group_heartbeat_response(
        &bytes,
        1,
        &ProtocolExtractionConfig::default(),
    )
    .expect("consumer group heartbeat error response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "consumer_group_heartbeat");
    assert_eq!(extraction.status_code, "35");
    assert_eq!(extraction.error_type.as_deref(), Some("35"));
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_version"
                && attribute.value == "1")
    );
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
            .any(|attribute| attribute.value.contains("denied")
                || attribute.value.contains("member")
                || attribute.value.contains("secret"))
    );
}

#[test]
fn extracts_kafka_share_group_heartbeat_ok_response_without_member_or_assignment_values() {
    let assignment: &[ConsumerGroupHeartbeatTopicPartitionsFixture<'_>] = &[([9_u8; 16], &[0, 1])];
    let bytes = kafka_share_group_heartbeat_response_frame(
        0,
        0,
        None,
        Some("member.secret"),
        Some(assignment),
    );

    let extraction =
        parse_kafka_share_group_heartbeat_response(&bytes, 1, &ProtocolExtractionConfig::default())
            .expect("share group heartbeat ok response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "share_group_heartbeat");
    assert_eq!(extraction.status_code, "0");
    assert_eq!(extraction.error_type, None);
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "76")
    );
    assert!(extraction.attributes.iter().any(|attribute| {
        attribute.key == "messaging.kafka.response.error_code" && attribute.value == "0"
    }));
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("member")
                || attribute.value.contains("secret")
                || attribute.value.contains("9"))
    );
}

#[test]
fn extracts_kafka_share_group_heartbeat_error_without_message_values() {
    let bytes = kafka_share_group_heartbeat_response_frame(
        0,
        35,
        Some("heartbeat secret denied"),
        Some("member.secret"),
        None,
    );

    let extraction =
        parse_kafka_share_group_heartbeat_response(&bytes, 1, &ProtocolExtractionConfig::default())
            .expect("share group heartbeat error response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "share_group_heartbeat");
    assert_eq!(extraction.status_code, "35");
    assert_eq!(extraction.error_type.as_deref(), Some("35"));
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_version"
                && attribute.value == "1")
    );
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
            .any(|attribute| attribute.value.contains("denied")
                || attribute.value.contains("member")
                || attribute.value.contains("secret"))
    );
}

#[test]
fn rejects_malformed_kafka_share_group_heartbeat_responses() {
    let config = ProtocolExtractionConfig::default();

    assert_eq!(
        parse_kafka_share_group_heartbeat_response(
            &kafka_share_group_heartbeat_response_frame(0, 0, None, None, None),
            0,
            &config,
        ),
        Err(KafkaExtraction::UnsupportedApiVersion)
    );
    assert_eq!(
        parse_kafka_share_group_heartbeat_response(
            &kafka_share_group_heartbeat_response_frame(
                0,
                35,
                Some("heartbeat-secret-denied"),
                None,
                None,
            ),
            1,
            &ProtocolExtractionConfig {
                max_header_bytes: 128,
                max_request_line_bytes: 4,
                max_attributes: 8,
                max_tracestate_bytes: 32,
            },
        ),
        Err(KafkaExtraction::ClientIdTooLong)
    );
    assert_eq!(
        parse_kafka_share_group_heartbeat_response(
            &kafka_share_group_heartbeat_response_with_assignment_count_frame(1025),
            1,
            &config,
        ),
        Err(KafkaExtraction::FrameTooLong)
    );
    assert_eq!(
        parse_kafka_share_group_heartbeat_response(
            &kafka_share_group_heartbeat_response_with_partition_count_frame(1025),
            1,
            &config,
        ),
        Err(KafkaExtraction::FrameTooLong)
    );

    let mut truncated =
        kafka_share_group_heartbeat_response_frame(0, 0, None, Some("member.secret"), None);
    truncated.truncate(18);
    assert_eq!(
        parse_kafka_share_group_heartbeat_response(&truncated, 1, &config),
        Err(KafkaExtraction::MalformedFrame)
    );
}

#[test]
fn extracts_kafka_controller_registration_ok_response_without_message_values() {
    let bytes = kafka_controller_registration_response_frame(0, 0, None);

    let extraction = parse_kafka_controller_registration_response(
        &bytes,
        0,
        &ProtocolExtractionConfig::default(),
    )
    .expect("controller registration ok response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "controller_registration");
    assert_eq!(extraction.status_code, "0");
    assert_eq!(extraction.error_type, None);
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "70")
    );
    assert!(extraction.attributes.iter().any(|attribute| {
        attribute.key == "messaging.kafka.response.error_code" && attribute.value == "0"
    }));
}

#[test]
fn extracts_kafka_controller_registration_error_without_message_values() {
    let bytes =
        kafka_controller_registration_response_frame(0, 35, Some("controller secret denied"));

    let extraction = parse_kafka_controller_registration_response(
        &bytes,
        0,
        &ProtocolExtractionConfig::default(),
    )
    .expect("controller registration error response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "controller_registration");
    assert_eq!(extraction.status_code, "35");
    assert_eq!(extraction.error_type.as_deref(), Some("35"));
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_version"
                && attribute.value == "0")
    );
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
            .any(|attribute| attribute.value.contains("denied")
                || attribute.value.contains("secret"))
    );
}

#[test]
fn rejects_malformed_kafka_controller_registration_responses() {
    let config = ProtocolExtractionConfig::default();

    assert_eq!(
        parse_kafka_controller_registration_response(
            &kafka_controller_registration_response_frame(0, 0, None),
            1,
            &config,
        ),
        Err(KafkaExtraction::UnsupportedApiVersion)
    );

    let mut truncated = kafka_controller_registration_response_frame(0, 0, None);
    truncated.truncate(10);
    assert_eq!(
        parse_kafka_controller_registration_response(&truncated, 0, &config),
        Err(KafkaExtraction::MalformedFrame)
    );
    assert_eq!(
        parse_kafka_controller_registration_response(
            &kafka_controller_registration_response_with_tag_value_len_frame(5),
            0,
            &ProtocolExtractionConfig {
                max_header_bytes: 128,
                max_request_line_bytes: 4,
                max_attributes: 8,
                max_tracestate_bytes: 32,
            },
        ),
        Err(KafkaExtraction::FrameTooLong)
    );
}

#[test]
fn extracts_kafka_consumer_group_describe_ok_response_without_group_or_member_values() {
    let assignments: &[ConsumerGroupDescribeTopicPartitionsFixture<'_>] =
        &[([11_u8; 16], "orders.secret", &[0, 1])];
    let members: &[ConsumerGroupDescribeMemberFixture<'_>] =
        &[ConsumerGroupDescribeMemberFixture {
            member_id: "member.secret",
            instance_id: Some("instance.secret"),
            rack_id: Some("rack.secret"),
            client_id: "client.secret",
            client_host: "host.secret",
            subscribed_topic_names: &["orders.secret"],
            subscribed_topic_regex: Some("orders.*secret"),
            assignment: assignments,
            target_assignment: assignments,
        }];
    let groups: &[ConsumerGroupDescribeGroupFixture<'_>] = &[ConsumerGroupDescribeGroupFixture {
        error_code: 0,
        error_message: None,
        group_id: "alpha.secret",
        group_state: "stable.secret",
        assignor_name: "range.secret",
        members,
    }];
    let bytes = kafka_consumer_group_describe_response_frame(0, 1, groups);

    let extraction = parse_kafka_consumer_group_describe_response(
        &bytes,
        1,
        &ProtocolExtractionConfig::default(),
    )
    .expect("consumer group describe ok response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "consumer_group_describe");
    assert_eq!(extraction.status_code, "0");
    assert_eq!(extraction.error_type, None);
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "69")
    );
    assert!(extraction.attributes.iter().any(|attribute| {
        attribute.key == "messaging.kafka.response.error_code" && attribute.value == "0"
    }));
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("alpha")
                || attribute.value.contains("member")
                || attribute.value.contains("orders")
                || attribute.value.contains("stable")
                || attribute.value.contains("range")
                || attribute.value.contains("client")
                || attribute.value.contains("host")
                || attribute.value.contains("secret")
                || attribute.value.contains("11"))
    );
}

#[test]
fn extracts_kafka_consumer_group_describe_error_without_message_values() {
    let groups: &[ConsumerGroupDescribeGroupFixture<'_>] = &[ConsumerGroupDescribeGroupFixture {
        error_code: 30,
        error_message: Some("describe secret denied"),
        group_id: "alpha.secret",
        group_state: "dead.secret",
        assignor_name: "range.secret",
        members: &[],
    }];
    let bytes = kafka_consumer_group_describe_response_frame(0, 0, groups);

    let extraction = parse_kafka_consumer_group_describe_response(
        &bytes,
        0,
        &ProtocolExtractionConfig::default(),
    )
    .expect("consumer group describe error response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "consumer_group_describe");
    assert_eq!(extraction.status_code, "30");
    assert_eq!(extraction.error_type.as_deref(), Some("30"));
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_version"
                && attribute.value == "0")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "error.type" && attribute.value == "30")
    );
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("denied")
                || attribute.value.contains("alpha")
                || attribute.value.contains("dead")
                || attribute.value.contains("range")
                || attribute.value.contains("secret"))
    );
}

#[test]
fn extracts_kafka_get_telemetry_subscriptions_ok_response_without_metric_or_instance_values() {
    let bytes = kafka_get_telemetry_subscriptions_response_frame(
        0,
        0,
        [19_u8; 16],
        &[1, 2],
        &["secret.metric", "another.secret.metric"],
    );

    let extraction = parse_kafka_get_telemetry_subscriptions_response(
        &bytes,
        0,
        &ProtocolExtractionConfig::default(),
    )
    .expect("get telemetry subscriptions ok response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "get_telemetry_subscriptions");
    assert_eq!(extraction.status_code, "0");
    assert_eq!(extraction.error_type, None);
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "71")
    );
    assert!(extraction.attributes.iter().any(|attribute| {
        attribute.key == "messaging.kafka.response.error_code" && attribute.value == "0"
    }));
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("metric")
                || attribute.value.contains("secret")
                || attribute.value.contains("19"))
    );
}

#[test]
fn extracts_kafka_get_telemetry_subscriptions_error_without_metric_values() {
    let bytes = kafka_get_telemetry_subscriptions_response_frame(
        0,
        35,
        [23_u8; 16],
        &[1],
        &["secret.metric"],
    );

    let extraction = parse_kafka_get_telemetry_subscriptions_response(
        &bytes,
        0,
        &ProtocolExtractionConfig::default(),
    )
    .expect("get telemetry subscriptions error response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "get_telemetry_subscriptions");
    assert_eq!(extraction.status_code, "35");
    assert_eq!(extraction.error_type.as_deref(), Some("35"));
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
            .any(|attribute| attribute.value.contains("metric")
                || attribute.value.contains("secret")
                || attribute.value.contains("23"))
    );
}

#[test]
fn extracts_kafka_push_telemetry_ok_response() {
    let bytes = kafka_push_telemetry_response_frame(0, 0);

    let extraction =
        parse_kafka_push_telemetry_response(&bytes, 0, &ProtocolExtractionConfig::default())
            .expect("push telemetry ok response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "push_telemetry");
    assert_eq!(extraction.status_code, "0");
    assert_eq!(extraction.error_type, None);
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "72")
    );
    assert!(extraction.attributes.iter().any(|attribute| {
        attribute.key == "messaging.kafka.response.error_code" && attribute.value == "0"
    }));
}

#[test]
fn extracts_kafka_push_telemetry_error_response() {
    let bytes = kafka_push_telemetry_response_frame(0, 35);

    let extraction =
        parse_kafka_push_telemetry_response(&bytes, 0, &ProtocolExtractionConfig::default())
            .expect("push telemetry error response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "push_telemetry");
    assert_eq!(extraction.status_code, "35");
    assert_eq!(extraction.error_type.as_deref(), Some("35"));
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "error.type" && attribute.value == "35")
    );
}

#[test]
fn extracts_kafka_list_config_resources_v0_ok_response_without_resource_values() {
    let bytes = kafka_list_config_resources_response_frame(0, 0, 0, &[("secret.config", 2)]);

    let extraction =
        parse_kafka_list_config_resources_response(&bytes, 0, &ProtocolExtractionConfig::default())
            .expect("list config resources v0 ok response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "list_config_resources");
    assert_eq!(extraction.status_code, "0");
    assert_eq!(extraction.error_type, None);
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "74")
    );
    assert!(extraction.attributes.iter().any(|attribute| {
        attribute.key == "messaging.kafka.response.error_code" && attribute.value == "0"
    }));
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("secret"))
    );
}

#[test]
fn extracts_kafka_list_config_resources_v1_error_response_without_resource_values() {
    let bytes = kafka_list_config_resources_response_frame(0, 1, 35, &[("secret.config", 2)]);

    let extraction =
        parse_kafka_list_config_resources_response(&bytes, 1, &ProtocolExtractionConfig::default())
            .expect("list config resources v1 error response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "list_config_resources");
    assert_eq!(extraction.status_code, "35");
    assert_eq!(extraction.error_type.as_deref(), Some("35"));
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
fn extracts_kafka_describe_topic_partitions_ok_response_without_topic_values() {
    let partitions: &[DescribeTopicPartitionsPartitionFixture<'_>] =
        &[DescribeTopicPartitionsPartitionFixture {
            error_code: 0,
            partition_index: 0,
            replica_nodes: &[1, 2],
            isr_nodes: &[1],
            eligible_leader_replicas: Some(&[2]),
            last_known_elr: Some(&[3]),
            offline_replicas: &[4],
        }];
    let topics: &[DescribeTopicPartitionsTopicFixture<'_>] =
        &[DescribeTopicPartitionsTopicFixture {
            error_code: 0,
            name: Some("orders.secret"),
            topic_id: [31_u8; 16],
            partitions,
        }];
    let bytes =
        kafka_describe_topic_partitions_response_frame(0, topics, Some(("cursor.secret", 12)));

    let extraction = parse_kafka_describe_topic_partitions_response(
        &bytes,
        0,
        &ProtocolExtractionConfig::default(),
    )
    .expect("describe topic partitions ok response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "describe_topic_partitions");
    assert_eq!(extraction.status_code, "0");
    assert_eq!(extraction.error_type, None);
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "75")
    );
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("orders")
                || attribute.value.contains("cursor")
                || attribute.value.contains("secret")
                || attribute.value.contains("31"))
    );
}

#[test]
fn extracts_kafka_describe_topic_partitions_topic_error_without_topic_values() {
    let topics: &[DescribeTopicPartitionsTopicFixture<'_>] =
        &[DescribeTopicPartitionsTopicFixture {
            error_code: 35,
            name: Some("orders.secret"),
            topic_id: [31_u8; 16],
            partitions: &[],
        }];
    let bytes = kafka_describe_topic_partitions_response_frame(0, topics, None);

    let extraction = parse_kafka_describe_topic_partitions_response(
        &bytes,
        0,
        &ProtocolExtractionConfig::default(),
    )
    .expect("describe topic partitions topic error response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "describe_topic_partitions");
    assert_eq!(extraction.status_code, "35");
    assert_eq!(extraction.error_type.as_deref(), Some("35"));
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
            .any(|attribute| attribute.value.contains("orders")
                || attribute.value.contains("secret")
                || attribute.value.contains("31"))
    );
}

#[test]
fn extracts_kafka_describe_topic_partitions_partition_error_without_topic_values() {
    let partitions: &[DescribeTopicPartitionsPartitionFixture<'_>] =
        &[DescribeTopicPartitionsPartitionFixture {
            error_code: 6,
            partition_index: 1,
            replica_nodes: &[1],
            isr_nodes: &[1],
            eligible_leader_replicas: None,
            last_known_elr: None,
            offline_replicas: &[],
        }];
    let topics: &[DescribeTopicPartitionsTopicFixture<'_>] =
        &[DescribeTopicPartitionsTopicFixture {
            error_code: 0,
            name: Some("orders.secret"),
            topic_id: [31_u8; 16],
            partitions,
        }];
    let bytes = kafka_describe_topic_partitions_response_frame(0, topics, None);

    let extraction = parse_kafka_describe_topic_partitions_response(
        &bytes,
        0,
        &ProtocolExtractionConfig::default(),
    )
    .expect("describe topic partitions partition error response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "describe_topic_partitions");
    assert_eq!(extraction.status_code, "6");
    assert_eq!(extraction.error_type.as_deref(), Some("6"));
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("orders")
                || attribute.value.contains("secret")
                || attribute.value.contains("31"))
    );
}

#[test]
fn extracts_kafka_add_raft_voter_v0_ok_response_without_message_values() {
    let bytes = kafka_add_raft_voter_response_frame(0, 0, Some("secret message"));

    let extraction =
        parse_kafka_add_raft_voter_response(&bytes, 0, &ProtocolExtractionConfig::default())
            .expect("add raft voter v0 ok response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "add_raft_voter");
    assert_eq!(extraction.status_code, "0");
    assert_eq!(extraction.error_type, None);
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "80")
    );
    assert!(extraction.attributes.iter().any(|attribute| {
        attribute.key == "messaging.kafka.response.error_code" && attribute.value == "0"
    }));
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("secret")
                || attribute.value.contains("message"))
    );
}

#[test]
fn extracts_kafka_add_raft_voter_v1_error_response_without_message_values() {
    let bytes = kafka_add_raft_voter_response_frame(0, 35, Some("secret message"));

    let extraction =
        parse_kafka_add_raft_voter_response(&bytes, 1, &ProtocolExtractionConfig::default())
            .expect("add raft voter v1 error response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "add_raft_voter");
    assert_eq!(extraction.status_code, "35");
    assert_eq!(extraction.error_type.as_deref(), Some("35"));
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
            .any(|attribute| attribute.value.contains("secret")
                || attribute.value.contains("message"))
    );
}

#[test]
fn extracts_kafka_remove_raft_voter_ok_response_without_message_values() {
    let bytes = kafka_remove_raft_voter_response_frame(0, 0, Some("secret message"));

    let extraction =
        parse_kafka_remove_raft_voter_response(&bytes, 0, &ProtocolExtractionConfig::default())
            .expect("remove raft voter ok response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "remove_raft_voter");
    assert_eq!(extraction.status_code, "0");
    assert_eq!(extraction.error_type, None);
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "81")
    );
    assert!(extraction.attributes.iter().any(|attribute| {
        attribute.key == "messaging.kafka.response.error_code" && attribute.value == "0"
    }));
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("secret")
                || attribute.value.contains("message"))
    );
}

#[test]
fn extracts_kafka_remove_raft_voter_error_response_without_message_values() {
    let bytes = kafka_remove_raft_voter_response_frame(0, 35, Some("secret message"));

    let extraction =
        parse_kafka_remove_raft_voter_response(&bytes, 0, &ProtocolExtractionConfig::default())
            .expect("remove raft voter error response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "remove_raft_voter");
    assert_eq!(extraction.status_code, "35");
    assert_eq!(extraction.error_type.as_deref(), Some("35"));
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
            .any(|attribute| attribute.value.contains("secret")
                || attribute.value.contains("message"))
    );
}

#[test]
fn extracts_kafka_update_raft_voter_ok_response_without_leader_values() {
    let bytes = kafka_update_raft_voter_response_frame(
        0,
        0,
        Some(UpdateRaftVoterLeaderFixture {
            leader_id: 7,
            leader_epoch: 8,
            host: "leader.secret.internal",
            port: 9092,
        }),
    );

    let extraction =
        parse_kafka_update_raft_voter_response(&bytes, 0, &ProtocolExtractionConfig::default())
            .expect("update raft voter ok response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "update_raft_voter");
    assert_eq!(extraction.status_code, "0");
    assert_eq!(extraction.error_type, None);
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "82")
    );
    assert!(extraction.attributes.iter().any(|attribute| {
        attribute.key == "messaging.kafka.response.error_code" && attribute.value == "0"
    }));
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("leader")
                || attribute.value.contains("secret")
                || attribute.value.contains("9092"))
    );
}

#[test]
fn extracts_kafka_update_raft_voter_error_response_without_leader_values() {
    let bytes = kafka_update_raft_voter_response_frame(
        0,
        35,
        Some(UpdateRaftVoterLeaderFixture {
            leader_id: 7,
            leader_epoch: 8,
            host: "leader.secret.internal",
            port: 9092,
        }),
    );

    let extraction =
        parse_kafka_update_raft_voter_response(&bytes, 0, &ProtocolExtractionConfig::default())
            .expect("update raft voter error response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "update_raft_voter");
    assert_eq!(extraction.status_code, "35");
    assert_eq!(extraction.error_type.as_deref(), Some("35"));
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
            .any(|attribute| attribute.value.contains("leader")
                || attribute.value.contains("secret")
                || attribute.value.contains("9092"))
    );
}

#[test]
fn extracts_kafka_initialize_share_group_state_ok_response_without_topic_or_message_values() {
    let partitions: &[InitializeShareGroupStateResultPartitionFixture<'_>] =
        &[InitializeShareGroupStateResultPartitionFixture {
            partition: 1,
            error_code: 0,
            error_message: Some("secret message"),
        }];
    let topics: &[InitializeShareGroupStateResultTopicFixture<'_>] =
        &[InitializeShareGroupStateResultTopicFixture {
            topic_id: [29_u8; 16],
            partitions,
        }];
    let bytes = kafka_initialize_share_group_state_response_frame(0, topics);

    let extraction = parse_kafka_initialize_share_group_state_response(
        &bytes,
        0,
        &ProtocolExtractionConfig::default(),
    )
    .expect("initialize share group state ok response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "initialize_share_group_state");
    assert_eq!(extraction.status_code, "0");
    assert_eq!(extraction.error_type, None);
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "83")
    );
    assert!(extraction.attributes.iter().any(|attribute| {
        attribute.key == "messaging.kafka.response.error_code" && attribute.value == "0"
    }));
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("secret")
                || attribute.value.contains("message")
                || attribute.value.contains("29"))
    );
}

#[test]
fn extracts_kafka_initialize_share_group_state_error_response_without_topic_or_message_values() {
    let partitions: &[InitializeShareGroupStateResultPartitionFixture<'_>] =
        &[InitializeShareGroupStateResultPartitionFixture {
            partition: 1,
            error_code: 35,
            error_message: Some("secret message"),
        }];
    let topics: &[InitializeShareGroupStateResultTopicFixture<'_>] =
        &[InitializeShareGroupStateResultTopicFixture {
            topic_id: [29_u8; 16],
            partitions,
        }];
    let bytes = kafka_initialize_share_group_state_response_frame(0, topics);

    let extraction = parse_kafka_initialize_share_group_state_response(
        &bytes,
        0,
        &ProtocolExtractionConfig::default(),
    )
    .expect("initialize share group state error response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "initialize_share_group_state");
    assert_eq!(extraction.status_code, "35");
    assert_eq!(extraction.error_type.as_deref(), Some("35"));
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
            .any(|attribute| attribute.value.contains("secret")
                || attribute.value.contains("message")
                || attribute.value.contains("29"))
    );
}

#[test]
fn extracts_kafka_read_share_group_state_ok_response_without_topic_message_or_state_values() {
    let batches: &[ReadShareGroupStateBatchFixture] = &[ReadShareGroupStateBatchFixture {
        first_offset: 100,
        last_offset: 200,
        delivery_state: 2,
        delivery_count: 3,
    }];
    let partitions: &[ReadShareGroupStateResultPartitionFixture<'_>] =
        &[ReadShareGroupStateResultPartitionFixture {
            partition: 1,
            error_code: 0,
            error_message: Some("secret message"),
            state_epoch: 5,
            start_offset: 100,
            state_batches: batches,
        }];
    let topics: &[ReadShareGroupStateResultTopicFixture<'_>] =
        &[ReadShareGroupStateResultTopicFixture {
            topic_id: [29_u8; 16],
            partitions,
        }];
    let bytes = kafka_read_share_group_state_response_frame(0, topics);

    let extraction = parse_kafka_read_share_group_state_response(
        &bytes,
        0,
        &ProtocolExtractionConfig::default(),
    )
    .expect("read share group state ok response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "read_share_group_state");
    assert_eq!(extraction.status_code, "0");
    assert_eq!(extraction.error_type, None);
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "84")
    );
    assert!(extraction.attributes.iter().any(|attribute| {
        attribute.key == "messaging.kafka.response.error_code" && attribute.value == "0"
    }));
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("secret")
                || attribute.value.contains("message")
                || attribute.value.contains("29")
                || attribute.value.contains("100")
                || attribute.value.contains("200"))
    );
}

#[test]
fn extracts_kafka_read_share_group_state_error_response_without_topic_message_or_state_values() {
    let partitions: &[ReadShareGroupStateResultPartitionFixture<'_>] =
        &[ReadShareGroupStateResultPartitionFixture {
            partition: 1,
            error_code: 35,
            error_message: Some("secret message"),
            state_epoch: 5,
            start_offset: 100,
            state_batches: &[],
        }];
    let topics: &[ReadShareGroupStateResultTopicFixture<'_>] =
        &[ReadShareGroupStateResultTopicFixture {
            topic_id: [29_u8; 16],
            partitions,
        }];
    let bytes = kafka_read_share_group_state_response_frame(0, topics);

    let extraction = parse_kafka_read_share_group_state_response(
        &bytes,
        0,
        &ProtocolExtractionConfig::default(),
    )
    .expect("read share group state error response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "read_share_group_state");
    assert_eq!(extraction.status_code, "35");
    assert_eq!(extraction.error_type.as_deref(), Some("35"));
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
            .any(|attribute| attribute.value.contains("secret")
                || attribute.value.contains("message")
                || attribute.value.contains("29")
                || attribute.value.contains("100"))
    );
}

#[test]
fn extracts_kafka_write_share_group_state_ok_response_without_topic_or_message_values() {
    let partitions: &[WriteShareGroupStateResultPartitionFixture<'_>] =
        &[WriteShareGroupStateResultPartitionFixture {
            partition: 1,
            error_code: 0,
            error_message: Some("secret message"),
        }];
    let topics: &[WriteShareGroupStateResultTopicFixture<'_>] =
        &[WriteShareGroupStateResultTopicFixture {
            topic_id: [29_u8; 16],
            partitions,
        }];
    let bytes = kafka_write_share_group_state_response_frame(0, topics);

    let extraction = parse_kafka_write_share_group_state_response(
        &bytes,
        1,
        &ProtocolExtractionConfig::default(),
    )
    .expect("write share group state ok response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "write_share_group_state");
    assert_eq!(extraction.status_code, "0");
    assert_eq!(extraction.error_type, None);
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "85")
    );
    assert!(extraction.attributes.iter().any(|attribute| {
        attribute.key == "messaging.kafka.response.error_code" && attribute.value == "0"
    }));
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("secret")
                || attribute.value.contains("message")
                || attribute.value.contains("29"))
    );
}

#[test]
fn extracts_kafka_write_share_group_state_error_response_without_topic_or_message_values() {
    let partitions: &[WriteShareGroupStateResultPartitionFixture<'_>] =
        &[WriteShareGroupStateResultPartitionFixture {
            partition: 1,
            error_code: 35,
            error_message: Some("secret message"),
        }];
    let topics: &[WriteShareGroupStateResultTopicFixture<'_>] =
        &[WriteShareGroupStateResultTopicFixture {
            topic_id: [29_u8; 16],
            partitions,
        }];
    let bytes = kafka_write_share_group_state_response_frame(0, topics);

    let extraction = parse_kafka_write_share_group_state_response(
        &bytes,
        1,
        &ProtocolExtractionConfig::default(),
    )
    .expect("write share group state error response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "write_share_group_state");
    assert_eq!(extraction.status_code, "35");
    assert_eq!(extraction.error_type.as_deref(), Some("35"));
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
            .any(|attribute| attribute.value.contains("secret")
                || attribute.value.contains("message")
                || attribute.value.contains("29"))
    );
}

#[test]
fn extracts_kafka_delete_share_group_state_ok_response_without_topic_or_message_values() {
    let partitions: &[DeleteShareGroupStateResultPartitionFixture<'_>] =
        &[DeleteShareGroupStateResultPartitionFixture {
            partition: 1,
            error_code: 0,
            error_message: Some("secret message"),
        }];
    let topics: &[DeleteShareGroupStateResultTopicFixture<'_>] =
        &[DeleteShareGroupStateResultTopicFixture {
            topic_id: [29_u8; 16],
            partitions,
        }];
    let bytes = kafka_delete_share_group_state_response_frame(0, topics);

    let extraction = parse_kafka_delete_share_group_state_response(
        &bytes,
        0,
        &ProtocolExtractionConfig::default(),
    )
    .expect("delete share group state ok response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "delete_share_group_state");
    assert_eq!(extraction.status_code, "0");
    assert_eq!(extraction.error_type, None);
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "86")
    );
    assert!(extraction.attributes.iter().any(|attribute| {
        attribute.key == "messaging.kafka.response.error_code" && attribute.value == "0"
    }));
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("secret")
                || attribute.value.contains("message")
                || attribute.value.contains("29"))
    );
}

#[test]
fn extracts_kafka_delete_share_group_state_error_response_without_topic_or_message_values() {
    let partitions: &[DeleteShareGroupStateResultPartitionFixture<'_>] =
        &[DeleteShareGroupStateResultPartitionFixture {
            partition: 1,
            error_code: 35,
            error_message: Some("secret message"),
        }];
    let topics: &[DeleteShareGroupStateResultTopicFixture<'_>] =
        &[DeleteShareGroupStateResultTopicFixture {
            topic_id: [29_u8; 16],
            partitions,
        }];
    let bytes = kafka_delete_share_group_state_response_frame(0, topics);

    let extraction = parse_kafka_delete_share_group_state_response(
        &bytes,
        0,
        &ProtocolExtractionConfig::default(),
    )
    .expect("delete share group state error response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "delete_share_group_state");
    assert_eq!(extraction.status_code, "35");
    assert_eq!(extraction.error_type.as_deref(), Some("35"));
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
            .any(|attribute| attribute.value.contains("secret")
                || attribute.value.contains("message")
                || attribute.value.contains("29"))
    );
}

#[test]
fn extracts_kafka_read_share_group_state_summary_ok_response_without_topic_message_or_state_values()
{
    let partitions: &[ReadShareGroupStateSummaryResultPartitionFixture<'_>] =
        &[ReadShareGroupStateSummaryResultPartitionFixture {
            partition: 1,
            error_code: 0,
            error_message: Some("secret message"),
            state_epoch: 5,
            leader_epoch: 2,
            start_offset: 100,
            delivery_complete_count: Some(200),
        }];
    let topics: &[ReadShareGroupStateSummaryResultTopicFixture<'_>] =
        &[ReadShareGroupStateSummaryResultTopicFixture {
            topic_id: [29_u8; 16],
            partitions,
        }];
    let bytes = kafka_read_share_group_state_summary_response_frame(0, topics, 1);

    let extraction = parse_kafka_read_share_group_state_summary_response(
        &bytes,
        1,
        &ProtocolExtractionConfig::default(),
    )
    .expect("read share group state summary ok response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "read_share_group_state_summary");
    assert_eq!(extraction.status_code, "0");
    assert_eq!(extraction.error_type, None);
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "87")
    );
    assert!(extraction.attributes.iter().any(|attribute| {
        attribute.key == "messaging.kafka.response.error_code" && attribute.value == "0"
    }));
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("secret")
                || attribute.value.contains("message")
                || attribute.value.contains("29")
                || attribute.value.contains("100")
                || attribute.value.contains("200"))
    );
}

#[test]
fn extracts_kafka_read_share_group_state_summary_error_response_without_topic_message_or_state_values()
 {
    let partitions: &[ReadShareGroupStateSummaryResultPartitionFixture<'_>] =
        &[ReadShareGroupStateSummaryResultPartitionFixture {
            partition: 1,
            error_code: 35,
            error_message: Some("secret message"),
            state_epoch: 5,
            leader_epoch: 2,
            start_offset: 100,
            delivery_complete_count: Some(200),
        }];
    let topics: &[ReadShareGroupStateSummaryResultTopicFixture<'_>] =
        &[ReadShareGroupStateSummaryResultTopicFixture {
            topic_id: [29_u8; 16],
            partitions,
        }];
    let bytes = kafka_read_share_group_state_summary_response_frame(0, topics, 1);

    let extraction = parse_kafka_read_share_group_state_summary_response(
        &bytes,
        1,
        &ProtocolExtractionConfig::default(),
    )
    .expect("read share group state summary error response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "read_share_group_state_summary");
    assert_eq!(extraction.status_code, "35");
    assert_eq!(extraction.error_type.as_deref(), Some("35"));
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
            .any(|attribute| attribute.value.contains("secret")
                || attribute.value.contains("message")
                || attribute.value.contains("29")
                || attribute.value.contains("100")
                || attribute.value.contains("200"))
    );
}

#[test]
fn extracts_kafka_delete_share_group_offsets_ok_response_without_topic_or_message_values() {
    let topics: &[DeleteShareGroupOffsetsResponseTopicFixture<'_>] =
        &[("orders.secret", [29_u8; 16], 0, Some("secret message"))];
    let bytes = kafka_delete_share_group_offsets_response_frame(0, 0, None, topics);

    let extraction = parse_kafka_delete_share_group_offsets_response(
        &bytes,
        0,
        &ProtocolExtractionConfig::default(),
    )
    .expect("delete share group offsets ok response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "delete_share_group_offsets");
    assert_eq!(extraction.status_code, "0");
    assert_eq!(extraction.error_type, None);
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "92")
    );
    assert!(extraction.attributes.iter().any(|attribute| {
        attribute.key == "messaging.kafka.response.error_code" && attribute.value == "0"
    }));
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("secret")
                || attribute.value.contains("orders")
                || attribute.value.contains("message")
                || attribute.value.contains("29"))
    );
}

#[test]
fn extracts_kafka_delete_share_group_offsets_topic_error_without_topic_or_message_values() {
    let topics: &[DeleteShareGroupOffsetsResponseTopicFixture<'_>] =
        &[("orders.secret", [29_u8; 16], 6, Some("topic secret denied"))];
    let bytes = kafka_delete_share_group_offsets_response_frame(0, 0, None, topics);

    let extraction = parse_kafka_delete_share_group_offsets_response(
        &bytes,
        0,
        &ProtocolExtractionConfig::default(),
    )
    .expect("delete share group offsets topic error response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "delete_share_group_offsets");
    assert_eq!(extraction.status_code, "6");
    assert_eq!(extraction.error_type.as_deref(), Some("6"));
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
            .any(|attribute| attribute.value.contains("secret")
                || attribute.value.contains("orders")
                || attribute.value.contains("denied")
                || attribute.value.contains("29"))
    );
}

#[test]
fn extracts_kafka_delete_share_group_offsets_top_level_error_without_message_values() {
    let topics: &[DeleteShareGroupOffsetsResponseTopicFixture<'_>] =
        &[("orders.secret", [29_u8; 16], 6, Some("topic secret denied"))];
    let bytes =
        kafka_delete_share_group_offsets_response_frame(0, 30, Some("top secret denied"), topics);

    let extraction = parse_kafka_delete_share_group_offsets_response(
        &bytes,
        0,
        &ProtocolExtractionConfig::default(),
    )
    .expect("delete share group offsets top-level error response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "delete_share_group_offsets");
    assert_eq!(extraction.status_code, "30");
    assert_eq!(extraction.error_type.as_deref(), Some("30"));
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "error.type" && attribute.value == "30")
    );
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("secret")
                || attribute.value.contains("orders")
                || attribute.value.contains("denied")
                || attribute.value.contains("29"))
    );
}

#[test]
fn extracts_kafka_describe_share_group_offsets_ok_response_without_topic_or_offset_values() {
    let partitions: &[DescribeShareGroupOffsetsResponsePartitionFixture<'_>] =
        &[(3, 99_999, 12, 0, Some("secret message"))];
    let topics: &[DescribeShareGroupOffsetsResponseTopicFixture<'_>] =
        &[("orders.secret", [29_u8; 16], partitions)];
    let groups: &[DescribeShareGroupOffsetsResponseGroupFixture<'_>] =
        &[("group.secret", topics, 0, None)];
    let bytes = kafka_describe_share_group_offsets_response_frame(0, 0, groups);

    let extraction = parse_kafka_describe_share_group_offsets_response(
        &bytes,
        0,
        &ProtocolExtractionConfig::default(),
    )
    .expect("describe share group offsets ok response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "describe_share_group_offsets");
    assert_eq!(extraction.status_code, "0");
    assert_eq!(extraction.error_type, None);
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "90")
    );
    assert!(extraction.attributes.iter().any(|attribute| {
        attribute.key == "messaging.kafka.response.error_code" && attribute.value == "0"
    }));
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("secret")
                || attribute.value.contains("orders")
                || attribute.value.contains("message")
                || attribute.value.contains("99")
                || attribute.value.contains("29"))
    );
}

#[test]
fn extracts_kafka_describe_share_group_offsets_v1_ok_response_without_topic_or_offset_values() {
    let partitions: &[DescribeShareGroupOffsetsResponsePartitionFixture<'_>] =
        &[(3, 99_999, 12, 0, None)];
    let topics: &[DescribeShareGroupOffsetsResponseTopicFixture<'_>] =
        &[("orders.secret", [29_u8; 16], partitions)];
    let groups: &[DescribeShareGroupOffsetsResponseGroupFixture<'_>] =
        &[("group.secret", topics, 0, None)];
    let bytes = kafka_describe_share_group_offsets_response_frame(0, 1, groups);

    let extraction = parse_kafka_describe_share_group_offsets_response(
        &bytes,
        1,
        &ProtocolExtractionConfig::default(),
    )
    .expect("describe share group offsets v1 ok response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "describe_share_group_offsets");
    assert_eq!(extraction.status_code, "0");
    assert_eq!(extraction.error_type, None);
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_version"
                && attribute.value == "1")
    );
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("secret")
                || attribute.value.contains("orders")
                || attribute.value.contains("99")
                || attribute.value.contains("29"))
    );
}

#[test]
fn extracts_kafka_describe_share_group_offsets_partition_error_without_topic_or_offset_values() {
    let partitions: &[DescribeShareGroupOffsetsResponsePartitionFixture<'_>] =
        &[(3, -1, -1, 6, Some("partition secret denied"))];
    let topics: &[DescribeShareGroupOffsetsResponseTopicFixture<'_>] =
        &[("orders.secret", [29_u8; 16], partitions)];
    let groups: &[DescribeShareGroupOffsetsResponseGroupFixture<'_>] =
        &[("group.secret", topics, 0, None)];
    let bytes = kafka_describe_share_group_offsets_response_frame(0, 0, groups);

    let extraction = parse_kafka_describe_share_group_offsets_response(
        &bytes,
        0,
        &ProtocolExtractionConfig::default(),
    )
    .expect("describe share group offsets partition error response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "describe_share_group_offsets");
    assert_eq!(extraction.status_code, "6");
    assert_eq!(extraction.error_type.as_deref(), Some("6"));
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
            .any(|attribute| attribute.value.contains("secret")
                || attribute.value.contains("orders")
                || attribute.value.contains("denied")
                || attribute.value.contains("29"))
    );
}

#[test]
fn extracts_kafka_describe_share_group_offsets_group_error_without_message_values() {
    let partitions: &[DescribeShareGroupOffsetsResponsePartitionFixture<'_>] =
        &[(3, -1, -1, 6, Some("partition secret denied"))];
    let topics: &[DescribeShareGroupOffsetsResponseTopicFixture<'_>] =
        &[("orders.secret", [29_u8; 16], partitions)];
    let groups: &[DescribeShareGroupOffsetsResponseGroupFixture<'_>] =
        &[("group.secret", topics, 30, Some("group secret denied"))];
    let bytes = kafka_describe_share_group_offsets_response_frame(0, 0, groups);

    let extraction = parse_kafka_describe_share_group_offsets_response(
        &bytes,
        0,
        &ProtocolExtractionConfig::default(),
    )
    .expect("describe share group offsets group error response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "describe_share_group_offsets");
    assert_eq!(extraction.status_code, "30");
    assert_eq!(extraction.error_type.as_deref(), Some("30"));
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "error.type" && attribute.value == "30")
    );
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("secret")
                || attribute.value.contains("orders")
                || attribute.value.contains("denied")
                || attribute.value.contains("29"))
    );
}

#[test]
fn extracts_kafka_offset_for_leader_epoch_v2_ok_response_without_topic_or_offset_values() {
    let topics: &[OffsetForLeaderEpochResponseTopicFixture<'_>] =
        &[("orders.secret", &[(0, 0, 12, 99_999)])];
    let bytes = kafka_offset_for_leader_epoch_response_frame(0, 2, topics);

    let extraction = parse_kafka_offset_for_leader_epoch_response(
        &bytes,
        2,
        &ProtocolExtractionConfig::default(),
    )
    .expect("offset for leader epoch v2 response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "offset_for_leader_epoch");
    assert_eq!(extraction.status_code, "0");
    assert_eq!(extraction.error_type, None);
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "23")
    );
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("orders")
                || attribute.value.contains("99999")
                || attribute.value.contains("secret"))
    );
}

#[test]
fn extracts_kafka_offset_for_leader_epoch_v4_error_response_without_topic_or_offset_values() {
    let topics: &[OffsetForLeaderEpochResponseTopicFixture<'_>] =
        &[("orders.secret", &[(0, 0, 12, 99_999), (6, 1, 13, 100_000)])];
    let bytes = kafka_offset_for_leader_epoch_response_frame(0, 4, topics);

    let extraction = parse_kafka_offset_for_leader_epoch_response(
        &bytes,
        4,
        &ProtocolExtractionConfig::default(),
    )
    .expect("offset for leader epoch v4 response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "offset_for_leader_epoch");
    assert_eq!(extraction.status_code, "6");
    assert_eq!(extraction.error_type.as_deref(), Some("6"));
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
                || attribute.value.contains("100000")
                || attribute.value.contains("secret"))
    );
}

#[test]
fn rejects_malformed_kafka_offset_for_leader_epoch_responses() {
    let config = ProtocolExtractionConfig::default();
    let topics: &[OffsetForLeaderEpochResponseTopicFixture<'_>] =
        &[("orders.secret", &[(0, 0, 12, 99_999)])];

    assert_eq!(
        parse_kafka_offset_for_leader_epoch_response(
            &kafka_offset_for_leader_epoch_response_frame(0, 2, topics),
            1,
            &config,
        ),
        Err(KafkaExtraction::UnsupportedApiVersion)
    );

    let mut truncated = kafka_offset_for_leader_epoch_response_frame(0, 2, topics);
    truncated.truncate(14);
    assert_eq!(
        parse_kafka_offset_for_leader_epoch_response(&truncated, 2, &config),
        Err(KafkaExtraction::MalformedFrame)
    );
    assert_eq!(
        parse_kafka_offset_for_leader_epoch_response(
            &kafka_offset_for_leader_epoch_response_with_topic_count_frame(4, 1025),
            4,
            &config,
        ),
        Err(KafkaExtraction::FrameTooLong)
    );
}

#[test]
fn extracts_kafka_list_offsets_ok_response_without_topic_values() {
    let bytes = kafka_list_offsets_response_frame(0, 5, &[("orders.secret", 0)]);

    let extraction =
        parse_kafka_list_offsets_response(&bytes, 5, &ProtocolExtractionConfig::default())
            .expect("list offsets ok response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "list_offsets");
    assert_eq!(extraction.status_code, "0");
    assert_eq!(extraction.error_type, None);
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "2")
    );
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
fn extracts_kafka_list_offsets_error_response_without_topic_values() {
    let bytes =
        kafka_list_offsets_response_frame(0, 4, &[("orders.secret", 0), ("payments.secret", 6)]);

    let extraction =
        parse_kafka_list_offsets_response(&bytes, 4, &ProtocolExtractionConfig::default())
            .expect("list offsets error response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "list_offsets");
    assert_eq!(extraction.status_code, "6");
    assert_eq!(extraction.error_type.as_deref(), Some("6"));
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
                || attribute.value.contains("secret"))
    );
}

#[test]
fn extracts_kafka_delete_records_ok_response_without_topic_values() {
    let bytes = kafka_delete_records_response_frame(0, &[("orders.secret", 0)]);

    let extraction =
        parse_kafka_delete_records_response(&bytes, 1, &ProtocolExtractionConfig::default())
            .expect("delete records ok response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "delete_records");
    assert_eq!(extraction.status_code, "0");
    assert_eq!(extraction.error_type, None);
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "21")
    );
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
fn extracts_kafka_delete_records_error_response_without_topic_values() {
    let bytes =
        kafka_delete_records_response_frame(0, &[("orders.secret", 0), ("payments.secret", 6)]);

    let extraction =
        parse_kafka_delete_records_response(&bytes, 0, &ProtocolExtractionConfig::default())
            .expect("delete records error response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "delete_records");
    assert_eq!(extraction.status_code, "6");
    assert_eq!(extraction.error_type.as_deref(), Some("6"));
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_version"
                && attribute.value == "0")
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
fn extracts_kafka_delete_topics_ok_response_without_topic_values() {
    let bytes = kafka_delete_topics_response_frame(0, &[("orders.secret", 0)]);

    let extraction =
        parse_kafka_delete_topics_response(&bytes, 3, &ProtocolExtractionConfig::default())
            .expect("delete topics ok response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "delete_topics");
    assert_eq!(extraction.status_code, "0");
    assert_eq!(extraction.error_type, None);
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "20")
    );
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
fn extracts_kafka_delete_topics_error_response_without_topic_values() {
    let bytes =
        kafka_delete_topics_response_frame(0, &[("orders.secret", 0), ("payments.secret", 6)]);

    let extraction =
        parse_kafka_delete_topics_response(&bytes, 1, &ProtocolExtractionConfig::default())
            .expect("delete topics error response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "delete_topics");
    assert_eq!(extraction.status_code, "6");
    assert_eq!(extraction.error_type.as_deref(), Some("6"));
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_version"
                && attribute.value == "1")
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
fn extracts_kafka_create_topics_ok_response_without_topic_or_message_values() {
    let bytes = kafka_create_topics_response_frame(0, &[("orders.secret", 0, None)]);

    let extraction =
        parse_kafka_create_topics_response(&bytes, 4, &ProtocolExtractionConfig::default())
            .expect("create topics ok response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "create_topics");
    assert_eq!(extraction.status_code, "0");
    assert_eq!(extraction.error_type, None);
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "19")
    );
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
fn extracts_kafka_create_topics_error_response_without_topic_or_message_values() {
    let bytes = kafka_create_topics_response_frame(
        0,
        &[
            ("orders.secret", 0, None),
            ("payments.secret", 36, Some("topic secret exists")),
        ],
    );

    let extraction =
        parse_kafka_create_topics_response(&bytes, 2, &ProtocolExtractionConfig::default())
            .expect("create topics error response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "create_topics");
    assert_eq!(extraction.status_code, "36");
    assert_eq!(extraction.error_type.as_deref(), Some("36"));
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_version"
                && attribute.value == "2")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "error.type" && attribute.value == "36")
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
fn extracts_kafka_create_partitions_ok_response_without_topic_or_message_values() {
    let bytes = kafka_create_partitions_response_frame(0, &[("orders.secret", 0, None)]);

    let extraction =
        parse_kafka_create_partitions_response(&bytes, 1, &ProtocolExtractionConfig::default())
            .expect("create partitions ok response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "create_partitions");
    assert_eq!(extraction.status_code, "0");
    assert_eq!(extraction.error_type, None);
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "37")
    );
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
fn extracts_kafka_create_partitions_error_response_without_topic_or_message_values() {
    let bytes = kafka_create_partitions_response_frame(
        0,
        &[
            ("orders.secret", 0, None),
            ("payments.secret", 37, Some("partition secret invalid")),
        ],
    );

    let extraction =
        parse_kafka_create_partitions_response(&bytes, 0, &ProtocolExtractionConfig::default())
            .expect("create partitions error response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "create_partitions");
    assert_eq!(extraction.status_code, "37");
    assert_eq!(extraction.error_type.as_deref(), Some("37"));
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_version"
                && attribute.value == "0")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "error.type" && attribute.value == "37")
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
fn extracts_kafka_create_acls_ok_response_without_message_values() {
    let bytes = kafka_create_acls_response_frame(0, &[(0, None)]);

    let extraction =
        parse_kafka_create_acls_response(&bytes, 1, &ProtocolExtractionConfig::default())
            .expect("create acls ok response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "create_acls");
    assert_eq!(extraction.status_code, "0");
    assert_eq!(extraction.error_type, None);
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "30")
    );
    assert!(extraction.attributes.iter().any(|attribute| {
        attribute.key == "messaging.kafka.response.error_code" && attribute.value == "0"
    }));
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("secret"))
    );
}

#[test]
fn extracts_kafka_create_acls_error_response_without_message_values() {
    let bytes =
        kafka_create_acls_response_frame(0, &[(0, None), (31, Some("acl secret rejected"))]);

    let extraction =
        parse_kafka_create_acls_response(&bytes, 1, &ProtocolExtractionConfig::default())
            .expect("create acls error response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "create_acls");
    assert_eq!(extraction.status_code, "31");
    assert_eq!(extraction.error_type.as_deref(), Some("31"));
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_version"
                && attribute.value == "1")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "error.type" && attribute.value == "31")
    );
    assert!(!extraction.attributes.iter().any(
        |attribute| attribute.value.contains("secret") || attribute.value.contains("rejected")
    ));
}

#[test]
fn extracts_kafka_describe_acls_ok_response_without_acl_values() {
    let bytes = kafka_describe_acls_response_frame(
        0,
        0,
        None,
        &[("orders.secret", &[("User:secret", "host.secret")])],
    );

    let extraction =
        parse_kafka_describe_acls_response(&bytes, 1, &ProtocolExtractionConfig::default())
            .expect("describe acls ok response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "describe_acls");
    assert_eq!(extraction.status_code, "0");
    assert_eq!(extraction.error_type, None);
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "29")
    );
    assert!(extraction.attributes.iter().any(|attribute| {
        attribute.key == "messaging.kafka.response.error_code" && attribute.value == "0"
    }));
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("orders")
                || attribute.value.contains("User")
                || attribute.value.contains("host")
                || attribute.value.contains("secret"))
    );
}

#[test]
fn extracts_kafka_describe_acls_error_response_without_message_values() {
    let bytes = kafka_describe_acls_response_frame(0, 31, Some("acl secret rejected"), &[]);

    let extraction =
        parse_kafka_describe_acls_response(&bytes, 1, &ProtocolExtractionConfig::default())
            .expect("describe acls error response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "describe_acls");
    assert_eq!(extraction.status_code, "31");
    assert_eq!(extraction.error_type.as_deref(), Some("31"));
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_version"
                && attribute.value == "1")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "error.type" && attribute.value == "31")
    );
    assert!(!extraction.attributes.iter().any(
        |attribute| attribute.value.contains("secret") || attribute.value.contains("rejected")
    ));
}

#[test]
fn extracts_kafka_delete_acls_ok_response_without_acl_values() {
    let bytes = kafka_delete_acls_response_frame(
        0,
        &[(
            0,
            None,
            &[(0, None, "orders.secret", "User:secret", "host.secret")],
        )],
    );

    let extraction =
        parse_kafka_delete_acls_response(&bytes, 1, &ProtocolExtractionConfig::default())
            .expect("delete acls ok response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "delete_acls");
    assert_eq!(extraction.status_code, "0");
    assert_eq!(extraction.error_type, None);
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "31")
    );
    assert!(extraction.attributes.iter().any(|attribute| {
        attribute.key == "messaging.kafka.response.error_code" && attribute.value == "0"
    }));
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("orders")
                || attribute.value.contains("User")
                || attribute.value.contains("host")
                || attribute.value.contains("secret"))
    );
}

#[test]
fn extracts_kafka_delete_acls_filter_error_response_without_message_values() {
    let bytes = kafka_delete_acls_response_frame(0, &[(31, Some("filter secret rejected"), &[])]);

    let extraction =
        parse_kafka_delete_acls_response(&bytes, 1, &ProtocolExtractionConfig::default())
            .expect("delete acls filter error response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "delete_acls");
    assert_eq!(extraction.status_code, "31");
    assert_eq!(extraction.error_type.as_deref(), Some("31"));
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_version"
                && attribute.value == "1")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "error.type" && attribute.value == "31")
    );
    assert!(!extraction.attributes.iter().any(
        |attribute| attribute.value.contains("secret") || attribute.value.contains("rejected")
    ));
}

#[test]
fn extracts_kafka_delete_acls_matching_acl_error_response_without_acl_values() {
    let bytes = kafka_delete_acls_response_frame(
        0,
        &[(
            0,
            None,
            &[(
                30,
                Some("matching secret rejected"),
                "orders.secret",
                "User:secret",
                "host.secret",
            )],
        )],
    );

    let extraction =
        parse_kafka_delete_acls_response(&bytes, 1, &ProtocolExtractionConfig::default())
            .expect("delete acls matching acl error response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "delete_acls");
    assert_eq!(extraction.status_code, "30");
    assert_eq!(extraction.error_type.as_deref(), Some("30"));
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("orders")
                || attribute.value.contains("User")
                || attribute.value.contains("host")
                || attribute.value.contains("secret")
                || attribute.value.contains("rejected"))
    );
}

#[test]
fn extracts_kafka_describe_configs_ok_response_without_config_values() {
    let bytes = kafka_describe_configs_response_frame(
        0,
        3,
        &[(
            0,
            None,
            "orders.secret",
            &[(
                "retention.secret.ms",
                Some("token-secret"),
                &[("synonym.secret", Some("synonym-secret"))],
                Some("doc secret"),
            )],
        )],
    );

    let extraction =
        parse_kafka_describe_configs_response(&bytes, 3, &ProtocolExtractionConfig::default())
            .expect("describe configs ok response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "describe_configs");
    assert_eq!(extraction.status_code, "0");
    assert_eq!(extraction.error_type, None);
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "32")
    );
    assert!(extraction.attributes.iter().any(|attribute| {
        attribute.key == "messaging.kafka.response.error_code" && attribute.value == "0"
    }));
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("orders")
                || attribute.value.contains("retention")
                || attribute.value.contains("token")
                || attribute.value.contains("synonym")
                || attribute.value.contains("doc")
                || attribute.value.contains("secret"))
    );
}

#[test]
fn extracts_kafka_describe_configs_error_response_without_message_or_config_values() {
    let bytes = kafka_describe_configs_response_frame(
        0,
        2,
        &[(
            35,
            Some("config secret rejected"),
            "orders.secret",
            &[(
                "retention.secret.ms",
                Some("token-secret"),
                &[("synonym.secret", Some("synonym-secret"))],
                None,
            )],
        )],
    );

    let extraction =
        parse_kafka_describe_configs_response(&bytes, 2, &ProtocolExtractionConfig::default())
            .expect("describe configs error response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "describe_configs");
    assert_eq!(extraction.status_code, "35");
    assert_eq!(extraction.error_type.as_deref(), Some("35"));
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_version"
                && attribute.value == "2")
    );
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
            .any(|attribute| attribute.value.contains("orders")
                || attribute.value.contains("retention")
                || attribute.value.contains("token")
                || attribute.value.contains("synonym")
                || attribute.value.contains("rejected")
                || attribute.value.contains("secret"))
    );
}

#[test]
fn extracts_kafka_alter_configs_ok_response_without_resource_values() {
    let bytes = kafka_alter_configs_response_frame(0, &[(0, None, "orders.secret")]);

    let extraction =
        parse_kafka_alter_configs_response(&bytes, 1, &ProtocolExtractionConfig::default())
            .expect("alter configs ok response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "alter_configs");
    assert_eq!(extraction.status_code, "0");
    assert_eq!(extraction.error_type, None);
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "33")
    );
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
fn extracts_kafka_alter_configs_error_response_without_message_or_resource_values() {
    let bytes = kafka_alter_configs_response_frame(
        0,
        &[
            (0, None, "orders.secret"),
            (35, Some("config secret rejected"), "payments.secret"),
        ],
    );

    let extraction =
        parse_kafka_alter_configs_response(&bytes, 0, &ProtocolExtractionConfig::default())
            .expect("alter configs error response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "alter_configs");
    assert_eq!(extraction.status_code, "35");
    assert_eq!(extraction.error_type.as_deref(), Some("35"));
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_version"
                && attribute.value == "0")
    );
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
            .any(|attribute| attribute.value.contains("orders")
                || attribute.value.contains("payments")
                || attribute.value.contains("rejected")
                || attribute.value.contains("secret"))
    );
}

#[test]
fn extracts_kafka_alter_replica_log_dirs_ok_response_without_topic_values() {
    let bytes = kafka_alter_replica_log_dirs_response_frame(0, &[("orders.secret", &[(0, 0)])]);

    let extraction = parse_kafka_alter_replica_log_dirs_response(
        &bytes,
        1,
        &ProtocolExtractionConfig::default(),
    )
    .expect("alter replica log dirs ok response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "alter_replica_log_dirs");
    assert_eq!(extraction.status_code, "0");
    assert_eq!(extraction.error_type, None);
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "34")
    );
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
fn extracts_kafka_alter_replica_log_dirs_error_response_without_topic_values() {
    let bytes = kafka_alter_replica_log_dirs_response_frame(
        0,
        &[
            ("orders.secret", &[(0, 0)][..]),
            ("payments.secret", &[(1, 35)][..]),
        ],
    );

    let extraction = parse_kafka_alter_replica_log_dirs_response(
        &bytes,
        1,
        &ProtocolExtractionConfig::default(),
    )
    .expect("alter replica log dirs error response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "alter_replica_log_dirs");
    assert_eq!(extraction.status_code, "35");
    assert_eq!(extraction.error_type.as_deref(), Some("35"));
    assert!(extraction.attributes.iter().any(|attribute| {
        attribute.key == "messaging.kafka.api_version" && attribute.value == "1"
    }));
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
            .any(|attribute| attribute.value.contains("orders")
                || attribute.value.contains("payments")
                || attribute.value.contains("secret"))
    );
}
