use super::*;

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
fn extracts_kafka_correlation_ids_for_internal_response_matching() {
    let request = kafka_request_frame(18, 0, None, b"");
    let mut response_body = 73_i32.to_be_bytes().to_vec();
    response_body.extend_from_slice(&[0, 0]);
    let response = kafka_frame(&response_body);
    let config = ProtocolExtractionConfig::default();

    assert_eq!(
        parse_kafka_request_correlation_id(&request, &config),
        Ok(42)
    );
    assert_eq!(
        parse_kafka_response_correlation_id(&response, &config),
        Ok(73)
    );
    assert!(parse_kafka_response_correlation_id(&kafka_frame(&[0, 1]), &config).is_err());

    let request_attributes = parse_kafka_request(&request, &config)
        .expect("request parses")
        .attributes;
    let response_attributes = parse_kafka_api_versions_response(&response, 0, &config)
        .expect("response parses")
        .attributes;
    assert!(
        request_attributes
            .iter()
            .chain(&response_attributes)
            .all(|attribute| !attribute.key.contains("correlation") && attribute.value != "73")
    );

    let bounded = ProtocolExtractionConfig {
        max_header_bytes: request.len() - 1,
        ..config
    };
    assert_eq!(
        parse_kafka_request_correlation_id(&request, &bounded),
        Err(KafkaExtraction::FrameTooLong)
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
fn validates_kafka_fetch_v5_request_without_topic_values() {
    let body = kafka_fetch_request_body(5, &[("orders.secret", &[0, 1])]);
    let bytes = kafka_request_frame(1, 5, Some(b"secret-client"), &body);

    let extraction = parse_kafka_request(&bytes, &ProtocolExtractionConfig::default())
        .expect("kafka fetch v5 request parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation.as_deref(), Some("fetch"));
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "1")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_version"
                && attribute.value == "5")
    );
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("secret")
                || attribute.value.contains("orders"))
    );
}

#[test]
fn validates_kafka_fetch_legacy_requests_without_topic_values() {
    for api_version in 0..=4 {
        let body = kafka_fetch_request_body(api_version, &[("orders.secret", &[0])]);
        let bytes = kafka_request_frame(1, api_version, Some(b"secret-client"), &body);

        let extraction = parse_kafka_request(&bytes, &ProtocolExtractionConfig::default())
            .expect("kafka fetch request parses");

        assert_eq!(extraction.operation.as_deref(), Some("fetch"));
        assert!(
            extraction
                .attributes
                .iter()
                .any(|attribute| attribute.key == "messaging.kafka.api_version"
                    && attribute.value == api_version.to_string())
        );
        assert!(
            !extraction
                .attributes
                .iter()
                .any(|attribute| attribute.value.contains("secret")
                    || attribute.value.contains("orders"))
        );
    }
}

#[test]
fn validates_kafka_offset_commit_v7_request_without_group_topic_or_metadata_values() {
    let body = kafka_offset_commit_request_body(7, &[("orders.secret", &[0, 1])]);
    let bytes = kafka_request_frame(8, 7, Some(b"secret-client"), &body);

    let extraction = parse_kafka_request(&bytes, &ProtocolExtractionConfig::default())
        .expect("kafka offset commit v7 request parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation.as_deref(), Some("offset_commit"));
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "8")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_version"
                && attribute.value == "7")
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
fn validates_kafka_offset_commit_legacy_requests_without_group_topic_or_metadata_values() {
    for api_version in 2..=6 {
        let body = kafka_offset_commit_request_body(api_version, &[("orders.secret", &[0])]);
        let bytes = kafka_request_frame(8, api_version, Some(b"secret-client"), &body);

        let extraction = parse_kafka_request(&bytes, &ProtocolExtractionConfig::default())
            .expect("kafka offset commit request parses");

        assert_eq!(extraction.operation.as_deref(), Some("offset_commit"));
        assert!(
            extraction
                .attributes
                .iter()
                .any(|attribute| attribute.key == "messaging.kafka.api_version"
                    && attribute.value == api_version.to_string())
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
}

#[test]
fn validates_kafka_offset_fetch_v5_request_without_group_or_topic_values() {
    let body = kafka_offset_fetch_request_body(5, Some(&[("orders.secret", &[0, 1])]));
    let bytes = kafka_request_frame(9, 5, Some(b"secret-client"), &body);

    let extraction = parse_kafka_request(&bytes, &ProtocolExtractionConfig::default())
        .expect("kafka offset fetch v5 request parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation.as_deref(), Some("offset_fetch"));
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "9")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_version"
                && attribute.value == "5")
    );
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("secret")
                || attribute.value.contains("orders"))
    );
}

#[test]
fn validates_kafka_offset_fetch_legacy_requests_without_group_or_topic_values() {
    for api_version in 1..=4 {
        let body = kafka_offset_fetch_request_body(api_version, Some(&[("orders.secret", &[0])]));
        let bytes = kafka_request_frame(9, api_version, Some(b"secret-client"), &body);

        let extraction = parse_kafka_request(&bytes, &ProtocolExtractionConfig::default())
            .expect("kafka offset fetch request parses");

        assert_eq!(extraction.operation.as_deref(), Some("offset_fetch"));
        assert!(
            extraction
                .attributes
                .iter()
                .any(|attribute| attribute.key == "messaging.kafka.api_version"
                    && attribute.value == api_version.to_string())
        );
        assert!(
            !extraction
                .attributes
                .iter()
                .any(|attribute| attribute.value.contains("secret")
                    || attribute.value.contains("orders"))
        );
    }
}

#[test]
fn validates_kafka_offset_fetch_nullable_topics_request() {
    for api_version in 2..=5 {
        let body = kafka_offset_fetch_request_body(api_version, None);
        let bytes = kafka_request_frame(9, api_version, Some(b"secret-client"), &body);

        let extraction = parse_kafka_request(&bytes, &ProtocolExtractionConfig::default())
            .expect("kafka offset fetch nullable topics request parses");

        assert_eq!(extraction.operation.as_deref(), Some("offset_fetch"));
        assert!(
            !extraction
                .attributes
                .iter()
                .any(|attribute| attribute.value.contains("secret"))
        );
    }
}

#[test]
fn validates_kafka_offset_delete_request_without_group_or_topic_values() {
    let body = kafka_offset_delete_request_body(&[("orders.secret", &[0, 1])]);
    let bytes = kafka_request_frame(47, 0, Some(b"secret-client"), &body);

    let extraction = parse_kafka_request(&bytes, &ProtocolExtractionConfig::default())
        .expect("kafka offset delete request parses");

    assert_eq!(extraction.operation.as_deref(), Some("offset_delete"));
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "47")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_version"
                && attribute.value == "0")
    );
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("secret")
                || attribute.value.contains("orders")
                || attribute.value.contains("group"))
    );
}

#[test]
fn validates_kafka_offset_for_leader_epoch_v2_request_without_topic_values() {
    let topics: &[OffsetForLeaderEpochRequestTopicFixture<'_>] =
        &[("orders.secret", &[(0, 12, 11)])];
    let body = kafka_offset_for_leader_epoch_request_body(2, topics);
    let bytes = kafka_request_frame(23, 2, Some(b"secret-client"), &body);

    let extraction = parse_kafka_request(&bytes, &ProtocolExtractionConfig::default())
        .expect("kafka offset for leader epoch v2 request parses");

    assert_eq!(
        extraction.operation.as_deref(),
        Some("offset_for_leader_epoch")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "23")
    );
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
            .any(|attribute| attribute.value.contains("orders")
                || attribute.value.contains("secret"))
    );
}

#[test]
fn validates_kafka_offset_for_leader_epoch_v4_request_without_topic_values() {
    let topics: &[OffsetForLeaderEpochRequestTopicFixture<'_>] =
        &[("orders.secret", &[(0, 12, 11)])];
    let body = kafka_offset_for_leader_epoch_request_body(4, topics);
    let bytes = kafka_flexible_request_frame(23, 4, Some(b"secret-client"), &body);

    let extraction = parse_kafka_request(&bytes, &ProtocolExtractionConfig::default())
        .expect("kafka offset for leader epoch v4 request parses");

    assert_eq!(
        extraction.operation.as_deref(),
        Some("offset_for_leader_epoch")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "23")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_version"
                && attribute.value == "4")
    );
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("orders")
                || attribute.value.contains("secret"))
    );
}

#[test]
fn rejects_malformed_kafka_offset_for_leader_epoch_requests() {
    let config = ProtocolExtractionConfig::default();
    let topics: &[OffsetForLeaderEpochRequestTopicFixture<'_>] =
        &[("orders.secret", &[(0, 12, 11)])];
    let body = kafka_offset_for_leader_epoch_request_body(2, topics);

    assert_eq!(
        parse_kafka_request(&kafka_request_frame(23, 1, None, &body), &config),
        Err(KafkaExtraction::UnsupportedApiVersion)
    );
    assert_eq!(
        parse_kafka_request(&kafka_request_frame(23, 2, None, b"\0\0\0\x01"), &config),
        Err(KafkaExtraction::MalformedFrame)
    );
    assert_eq!(
        parse_kafka_request(
            &kafka_request_frame(
                23,
                2,
                None,
                &kafka_offset_for_leader_epoch_request_with_topic_count_body(1025),
            ),
            &config,
        ),
        Err(KafkaExtraction::FrameTooLong)
    );
    assert_eq!(
        parse_kafka_request(
            &kafka_flexible_request_frame(
                23,
                4,
                None,
                &kafka_offset_for_leader_epoch_flexible_request_with_partition_count_body(1025),
            ),
            &config,
        ),
        Err(KafkaExtraction::FrameTooLong)
    );
}

#[test]
fn validates_kafka_list_offsets_v5_request_without_topic_values() {
    let body = kafka_list_offsets_request_body(5, &[("orders.secret", &[0, 1])]);
    let bytes = kafka_request_frame(2, 5, Some(b"secret-client"), &body);

    let extraction = parse_kafka_request(&bytes, &ProtocolExtractionConfig::default())
        .expect("kafka list offsets v5 request parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation.as_deref(), Some("list_offsets"));
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "2")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_version"
                && attribute.value == "5")
    );
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("secret")
                || attribute.value.contains("orders"))
    );
}

#[test]
fn validates_kafka_list_offsets_legacy_requests_without_topic_values() {
    for api_version in 1..=4 {
        let body = kafka_list_offsets_request_body(api_version, &[("orders.secret", &[0])]);
        let bytes = kafka_request_frame(2, api_version, Some(b"secret-client"), &body);

        let extraction = parse_kafka_request(&bytes, &ProtocolExtractionConfig::default())
            .expect("kafka list offsets request parses");

        assert_eq!(extraction.operation.as_deref(), Some("list_offsets"));
        assert!(
            extraction
                .attributes
                .iter()
                .any(|attribute| attribute.key == "messaging.kafka.api_version"
                    && attribute.value == api_version.to_string())
        );
        assert!(
            !extraction
                .attributes
                .iter()
                .any(|attribute| attribute.value.contains("secret")
                    || attribute.value.contains("orders"))
        );
    }
}

#[test]
fn validates_kafka_delete_records_requests_without_topic_values() {
    for api_version in 0..=1 {
        let body = kafka_delete_records_request_body(&[("orders.secret", &[0, 1])]);
        let bytes = kafka_request_frame(21, api_version, Some(b"secret-client"), &body);

        let extraction = parse_kafka_request(&bytes, &ProtocolExtractionConfig::default())
            .expect("kafka delete records request parses");

        assert_eq!(extraction.operation.as_deref(), Some("delete_records"));
        assert!(
            extraction
                .attributes
                .iter()
                .any(|attribute| attribute.key == "messaging.kafka.api_key"
                    && attribute.value == "21")
        );
        assert!(
            extraction
                .attributes
                .iter()
                .any(|attribute| attribute.key == "messaging.kafka.api_version"
                    && attribute.value == api_version.to_string())
        );
        assert!(
            !extraction
                .attributes
                .iter()
                .any(|attribute| attribute.value.contains("secret")
                    || attribute.value.contains("orders"))
        );
    }
}

#[test]
fn validates_kafka_delete_topics_requests_without_topic_values() {
    for api_version in 1..=3 {
        let body = kafka_delete_topics_request_body(&["orders.secret", "payments.secret"]);
        let bytes = kafka_request_frame(20, api_version, Some(b"secret-client"), &body);

        let extraction = parse_kafka_request(&bytes, &ProtocolExtractionConfig::default())
            .expect("kafka delete topics request parses");

        assert_eq!(extraction.operation.as_deref(), Some("delete_topics"));
        assert!(
            extraction
                .attributes
                .iter()
                .any(|attribute| attribute.key == "messaging.kafka.api_key"
                    && attribute.value == "20")
        );
        assert!(
            extraction
                .attributes
                .iter()
                .any(|attribute| attribute.key == "messaging.kafka.api_version"
                    && attribute.value == api_version.to_string())
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
}

#[test]
fn validates_kafka_create_topics_requests_without_topic_or_config_values() {
    for api_version in 2..=4 {
        let body = kafka_create_topics_request_body(
            "orders.secret",
            "retention.ms.secret",
            Some("token-secret"),
        );
        let bytes = kafka_request_frame(19, api_version, Some(b"secret-client"), &body);

        let extraction = parse_kafka_request(&bytes, &ProtocolExtractionConfig::default())
            .expect("kafka create topics request parses");

        assert_eq!(extraction.operation.as_deref(), Some("create_topics"));
        assert!(
            extraction
                .attributes
                .iter()
                .any(|attribute| attribute.key == "messaging.kafka.api_key"
                    && attribute.value == "19")
        );
        assert!(
            extraction
                .attributes
                .iter()
                .any(|attribute| attribute.key == "messaging.kafka.api_version"
                    && attribute.value == api_version.to_string())
        );
        assert!(
            !extraction
                .attributes
                .iter()
                .any(|attribute| attribute.value.contains("secret")
                    || attribute.value.contains("orders")
                    || attribute.value.contains("retention")
                    || attribute.value.contains("token"))
        );
    }
}

#[test]
fn validates_kafka_create_partitions_requests_without_topic_values() {
    for api_version in 0..=1 {
        let body = kafka_create_partitions_request_body("orders.secret", Some(&[&[1, 2]]));
        let bytes = kafka_request_frame(37, api_version, Some(b"secret-client"), &body);

        let extraction = parse_kafka_request(&bytes, &ProtocolExtractionConfig::default())
            .expect("kafka create partitions request parses");

        assert_eq!(extraction.operation.as_deref(), Some("create_partitions"));
        assert!(
            extraction
                .attributes
                .iter()
                .any(|attribute| attribute.key == "messaging.kafka.api_key"
                    && attribute.value == "37")
        );
        assert!(
            extraction
                .attributes
                .iter()
                .any(|attribute| attribute.key == "messaging.kafka.api_version"
                    && attribute.value == api_version.to_string())
        );
        assert!(
            !extraction
                .attributes
                .iter()
                .any(|attribute| attribute.value.contains("secret")
                    || attribute.value.contains("orders"))
        );
    }
}

#[test]
fn validates_kafka_create_acls_requests_without_acl_values() {
    let body = kafka_create_acls_request_body("orders.secret", "User:secret", "host.secret");
    let bytes = kafka_request_frame(30, 1, Some(b"secret-client"), &body);

    let extraction = parse_kafka_request(&bytes, &ProtocolExtractionConfig::default())
        .expect("kafka create acls request parses");

    assert_eq!(extraction.operation.as_deref(), Some("create_acls"));
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "30")
    );
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
            .any(|attribute| attribute.value.contains("orders")
                || attribute.value.contains("User")
                || attribute.value.contains("host")
                || attribute.value.contains("secret"))
    );
}

#[test]
fn validates_kafka_describe_acls_requests_without_filter_values() {
    let body = kafka_describe_acls_request_body(
        Some("orders.secret"),
        Some("User:secret"),
        Some("host.secret"),
    );
    let bytes = kafka_request_frame(29, 1, Some(b"secret-client"), &body);

    let extraction = parse_kafka_request(&bytes, &ProtocolExtractionConfig::default())
        .expect("kafka describe acls request parses");

    assert_eq!(extraction.operation.as_deref(), Some("describe_acls"));
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "29")
    );
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
            .any(|attribute| attribute.value.contains("orders")
                || attribute.value.contains("User")
                || attribute.value.contains("host")
                || attribute.value.contains("secret"))
    );
}

#[test]
fn validates_kafka_delete_acls_requests_without_filter_values() {
    let body = kafka_delete_acls_request_body(
        Some("orders.secret"),
        Some("User:secret"),
        Some("host.secret"),
    );
    let bytes = kafka_request_frame(31, 1, Some(b"secret-client"), &body);

    let extraction = parse_kafka_request(&bytes, &ProtocolExtractionConfig::default())
        .expect("kafka delete acls request parses");

    assert_eq!(extraction.operation.as_deref(), Some("delete_acls"));
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "31")
    );
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
            .any(|attribute| attribute.value.contains("orders")
                || attribute.value.contains("User")
                || attribute.value.contains("host")
                || attribute.value.contains("secret"))
    );
}

#[test]
fn validates_kafka_describe_configs_requests_without_resource_or_key_values() {
    for api_version in 1..=3 {
        let body = kafka_describe_configs_request_body(
            api_version,
            "orders.secret",
            Some(&["retention.secret.ms", "password.secret"]),
        );
        let bytes = kafka_request_frame(32, api_version, Some(b"secret-client"), &body);

        let extraction = parse_kafka_request(&bytes, &ProtocolExtractionConfig::default())
            .expect("kafka describe configs request parses");

        assert_eq!(extraction.operation.as_deref(), Some("describe_configs"));
        assert!(
            extraction
                .attributes
                .iter()
                .any(|attribute| attribute.key == "messaging.kafka.api_key"
                    && attribute.value == "32")
        );
        assert!(
            extraction
                .attributes
                .iter()
                .any(|attribute| attribute.key == "messaging.kafka.api_version"
                    && attribute.value == api_version.to_string())
        );
        assert!(
            !extraction
                .attributes
                .iter()
                .any(|attribute| attribute.value.contains("orders")
                    || attribute.value.contains("retention")
                    || attribute.value.contains("password")
                    || attribute.value.contains("secret"))
        );
    }
}

#[test]
fn validates_kafka_alter_configs_requests_without_resource_key_or_value_values() {
    for api_version in 0..=1 {
        let body = kafka_alter_configs_request_body(
            "orders.secret",
            &[("retention.secret.ms", Some("token-secret"))],
        );
        let bytes = kafka_request_frame(33, api_version, Some(b"secret-client"), &body);

        let extraction = parse_kafka_request(&bytes, &ProtocolExtractionConfig::default())
            .expect("kafka alter configs request parses");

        assert_eq!(extraction.operation.as_deref(), Some("alter_configs"));
        assert!(
            extraction
                .attributes
                .iter()
                .any(|attribute| attribute.key == "messaging.kafka.api_key"
                    && attribute.value == "33")
        );
        assert!(
            extraction
                .attributes
                .iter()
                .any(|attribute| attribute.key == "messaging.kafka.api_version"
                    && attribute.value == api_version.to_string())
        );
        assert!(
            !extraction
                .attributes
                .iter()
                .any(|attribute| attribute.value.contains("orders")
                    || attribute.value.contains("retention")
                    || attribute.value.contains("token")
                    || attribute.value.contains("secret"))
        );
    }
}

#[test]
fn validates_kafka_incremental_alter_configs_v0_request_without_resource_key_or_value_values() {
    let configs: &[IncrementalAlterConfigFixture<'_>] =
        &[("retention.secret.ms", 0, Some("token-secret"))];
    let resources: &[IncrementalAlterConfigsResourceFixture<'_>] = &[(2, "orders.secret", configs)];
    let body = kafka_incremental_alter_configs_request_body(0, resources);
    let bytes = kafka_request_frame(44, 0, Some(b"secret-client"), &body);

    let extraction = parse_kafka_request(&bytes, &ProtocolExtractionConfig::default())
        .expect("kafka incremental alter configs v0 request parses");

    assert_eq!(
        extraction.operation.as_deref(),
        Some("incremental_alter_configs")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "44")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_version"
                && attribute.value == "0")
    );
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("orders")
                || attribute.value.contains("retention")
                || attribute.value.contains("token")
                || attribute.value.contains("secret"))
    );
}

#[test]
fn validates_kafka_incremental_alter_configs_v1_request_without_resource_key_or_value_values() {
    let configs: &[IncrementalAlterConfigFixture<'_>] =
        &[("retention.secret.ms", 0, Some("token-secret"))];
    let resources: &[IncrementalAlterConfigsResourceFixture<'_>] = &[(2, "orders.secret", configs)];
    let body = kafka_incremental_alter_configs_request_body(1, resources);
    let bytes = kafka_flexible_request_frame(44, 1, Some(b"secret-client"), &body);

    let extraction = parse_kafka_request(&bytes, &ProtocolExtractionConfig::default())
        .expect("kafka incremental alter configs v1 request parses");

    assert_eq!(
        extraction.operation.as_deref(),
        Some("incremental_alter_configs")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "44")
    );
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
            .any(|attribute| attribute.value.contains("orders")
                || attribute.value.contains("retention")
                || attribute.value.contains("token")
                || attribute.value.contains("secret"))
    );
}

#[test]
fn validates_kafka_alter_partition_reassignments_v0_request_without_topic_or_replica_values() {
    let partitions: &[AlterPartitionReassignmentFixture<'_>] = &[(0, Some(&[1, 2]))];
    let topics: &[AlterPartitionReassignmentsTopicFixture<'_>] = &[("orders.secret", partitions)];
    let body = kafka_alter_partition_reassignments_request_body(0, topics);
    let bytes = kafka_flexible_request_frame(45, 0, Some(b"secret-client"), &body);

    let extraction = parse_kafka_request(&bytes, &ProtocolExtractionConfig::default())
        .expect("kafka alter partition reassignments v0 request parses");

    assert_eq!(
        extraction.operation.as_deref(),
        Some("alter_partition_reassignments")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "45")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_version"
                && attribute.value == "0")
    );
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("orders")
                || attribute.value.contains("secret"))
    );
}

#[test]
fn validates_kafka_alter_partition_reassignments_v1_nullable_replicas_request() {
    let partitions: &[AlterPartitionReassignmentFixture<'_>] = &[(0, None)];
    let topics: &[AlterPartitionReassignmentsTopicFixture<'_>] = &[("orders.secret", partitions)];
    let body = kafka_alter_partition_reassignments_request_body(1, topics);
    let bytes = kafka_flexible_request_frame(45, 1, Some(b"secret-client"), &body);

    let extraction = parse_kafka_request(&bytes, &ProtocolExtractionConfig::default())
        .expect("kafka alter partition reassignments v1 request parses");

    assert_eq!(
        extraction.operation.as_deref(),
        Some("alter_partition_reassignments")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "45")
    );
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
            .any(|attribute| attribute.value.contains("orders")
                || attribute.value.contains("secret"))
    );
}

#[test]
fn validates_kafka_list_partition_reassignments_request_without_topic_values() {
    let topics: &[ListPartitionReassignmentsRequestTopicFixture<'_>] =
        &[("orders.secret", &[0, 1])];
    let body = kafka_list_partition_reassignments_request_body(Some(topics));
    let bytes = kafka_flexible_request_frame(46, 0, Some(b"secret-client"), &body);

    let extraction = parse_kafka_request(&bytes, &ProtocolExtractionConfig::default())
        .expect("kafka list partition reassignments request parses");

    assert_eq!(
        extraction.operation.as_deref(),
        Some("list_partition_reassignments")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "46")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_version"
                && attribute.value == "0")
    );
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("orders")
                || attribute.value.contains("secret"))
    );
}

#[test]
fn validates_kafka_list_partition_reassignments_null_topics_request() {
    let body = kafka_list_partition_reassignments_request_body(None);
    let bytes = kafka_flexible_request_frame(46, 0, Some(b"secret-client"), &body);

    let extraction = parse_kafka_request(&bytes, &ProtocolExtractionConfig::default())
        .expect("kafka list partition reassignments null topics request parses");

    assert_eq!(
        extraction.operation.as_deref(),
        Some("list_partition_reassignments")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "46")
    );
}

#[test]
fn validates_kafka_describe_client_quotas_v0_request_without_entity_values() {
    let components: &[DescribeClientQuotasComponentFixture<'_>] =
        &[("client-id", 0, Some("secret-client-a"))];
    let body = kafka_describe_client_quotas_request_body(0, components);
    let bytes = kafka_request_frame(48, 0, Some(b"secret-client"), &body);

    let extraction = parse_kafka_request(&bytes, &ProtocolExtractionConfig::default())
        .expect("kafka describe client quotas v0 request parses");

    assert_eq!(
        extraction.operation.as_deref(),
        Some("describe_client_quotas")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "48")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_version"
                && attribute.value == "0")
    );
    assert!(!extraction.attributes.iter().any(
        |attribute| attribute.value.contains("client-id") || attribute.value.contains("secret")
    ));
}

#[test]
fn validates_kafka_describe_client_quotas_v1_request_without_entity_values() {
    let components: &[DescribeClientQuotasComponentFixture<'_>] =
        &[("client-id", 0, Some("secret-client-a"))];
    let body = kafka_describe_client_quotas_request_body(1, components);
    let bytes = kafka_flexible_request_frame(48, 1, Some(b"secret-client"), &body);

    let extraction = parse_kafka_request(&bytes, &ProtocolExtractionConfig::default())
        .expect("kafka describe client quotas v1 request parses");

    assert_eq!(
        extraction.operation.as_deref(),
        Some("describe_client_quotas")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "48")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_version"
                && attribute.value == "1")
    );
    assert!(!extraction.attributes.iter().any(
        |attribute| attribute.value.contains("client-id") || attribute.value.contains("secret")
    ));
}

#[test]
fn validates_kafka_alter_client_quotas_v0_request_without_entity_or_quota_values() {
    let entities: &[ClientQuotaEntityFixture<'_>] = &[("client-id", Some("secret-client-a"))];
    let ops: &[AlterClientQuotaOpFixture<'_>] = &[("producer_byte_rate.secret", 42.0, false)];
    let entries: &[AlterClientQuotaEntryFixture<'_>] = &[(entities, ops)];
    let body = kafka_alter_client_quotas_request_body(0, entries);
    let bytes = kafka_request_frame(49, 0, Some(b"secret-client"), &body);

    let extraction = parse_kafka_request(&bytes, &ProtocolExtractionConfig::default())
        .expect("kafka alter client quotas v0 request parses");

    assert_eq!(extraction.operation.as_deref(), Some("alter_client_quotas"));
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "49")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_version"
                && attribute.value == "0")
    );
    assert!(!extraction.attributes.iter().any(|attribute| {
        attribute.value.contains("client-id")
            || attribute.value.contains("producer")
            || attribute.value.contains("secret")
    }));
}

#[test]
fn validates_kafka_alter_client_quotas_v1_request_without_entity_or_quota_values() {
    let entities: &[ClientQuotaEntityFixture<'_>] = &[("client-id", Some("secret-client-a"))];
    let ops: &[AlterClientQuotaOpFixture<'_>] = &[("producer_byte_rate.secret", 42.0, false)];
    let entries: &[AlterClientQuotaEntryFixture<'_>] = &[(entities, ops)];
    let body = kafka_alter_client_quotas_request_body(1, entries);
    let bytes = kafka_flexible_request_frame(49, 1, Some(b"secret-client"), &body);

    let extraction = parse_kafka_request(&bytes, &ProtocolExtractionConfig::default())
        .expect("kafka alter client quotas v1 request parses");

    assert_eq!(extraction.operation.as_deref(), Some("alter_client_quotas"));
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "49")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_version"
                && attribute.value == "1")
    );
    assert!(!extraction.attributes.iter().any(|attribute| {
        attribute.value.contains("client-id")
            || attribute.value.contains("producer")
            || attribute.value.contains("secret")
    }));
}

#[test]
fn validates_kafka_describe_user_scram_credentials_request_without_user_values() {
    let body = kafka_describe_user_scram_credentials_request_body(Some(&["alice.secret"]));
    let bytes = kafka_flexible_request_frame(50, 0, Some(b"secret-client"), &body);

    let extraction = parse_kafka_request(&bytes, &ProtocolExtractionConfig::default())
        .expect("kafka describe user scram credentials request parses");

    assert_eq!(
        extraction.operation.as_deref(),
        Some("describe_user_scram_credentials")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "50")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_version"
                && attribute.value == "0")
    );
    assert!(
        !extraction.attributes.iter().any(
            |attribute| attribute.value.contains("alice") || attribute.value.contains("secret")
        )
    );
}

#[test]
fn validates_kafka_describe_user_scram_credentials_null_users_request() {
    let body = kafka_describe_user_scram_credentials_request_body(None);
    let bytes = kafka_flexible_request_frame(50, 0, Some(b"secret-client"), &body);

    let extraction = parse_kafka_request(&bytes, &ProtocolExtractionConfig::default())
        .expect("kafka describe user scram credentials null users request parses");

    assert_eq!(
        extraction.operation.as_deref(),
        Some("describe_user_scram_credentials")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "50")
    );
}

#[test]
fn validates_kafka_alter_user_scram_credentials_request_without_user_or_secret_values() {
    let deletions: &[AlterUserScramCredentialDeletionFixture<'_>] = &[("alice.secret", 0)];
    let upsertions: &[AlterUserScramCredentialUpsertionFixture<'_>] =
        &[("bob.secret", 1, 4096, b"salt-secret", b"password-secret")];
    let body = kafka_alter_user_scram_credentials_request_body(deletions, upsertions);
    let bytes = kafka_flexible_request_frame(51, 0, Some(b"secret-client"), &body);

    let extraction = parse_kafka_request(&bytes, &ProtocolExtractionConfig::default())
        .expect("kafka alter user scram credentials request parses");

    assert_eq!(
        extraction.operation.as_deref(),
        Some("alter_user_scram_credentials")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "51")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_version"
                && attribute.value == "0")
    );
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("alice")
                || attribute.value.contains("bob")
                || attribute.value.contains("password")
                || attribute.value.contains("salt")
                || attribute.value.contains("secret"))
    );
}

#[test]
fn validates_kafka_describe_quorum_v0_request_without_topic_values() {
    let body = kafka_describe_quorum_request_body(&[("orders.secret", &[0, 1])]);
    let bytes = kafka_flexible_request_frame(55, 0, Some(b"secret-client"), &body);

    let extraction = parse_kafka_request(&bytes, &ProtocolExtractionConfig::default())
        .expect("kafka describe quorum v0 request parses");

    assert_eq!(extraction.operation.as_deref(), Some("describe_quorum"));
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "55")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_version"
                && attribute.value == "0")
    );
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("orders")
                || attribute.value.contains("secret"))
    );
}

#[test]
fn validates_kafka_describe_quorum_v2_request_without_topic_values() {
    let body = kafka_describe_quorum_request_body(&[("metadata.secret", &[0])]);
    let bytes = kafka_flexible_request_frame(55, 2, Some(b"secret-client"), &body);

    let extraction = parse_kafka_request(&bytes, &ProtocolExtractionConfig::default())
        .expect("kafka describe quorum v2 request parses");

    assert_eq!(extraction.operation.as_deref(), Some("describe_quorum"));
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "55")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_version"
                && attribute.value == "2")
    );
    assert!(!extraction.attributes.iter().any(
        |attribute| attribute.value.contains("metadata") || attribute.value.contains("secret")
    ));
}

#[test]
fn validates_kafka_update_features_v0_request_without_feature_values() {
    let updates: &[UpdateFeaturesRequestFixture<'_>] = &[("metadata.version.secret", 1, 1)];
    let body = kafka_update_features_request_body(0, updates, false);
    let bytes = kafka_flexible_request_frame(57, 0, Some(b"secret-client"), &body);

    let extraction = parse_kafka_request(&bytes, &ProtocolExtractionConfig::default())
        .expect("kafka update features v0 request parses");

    assert_eq!(extraction.operation.as_deref(), Some("update_features"));
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "57")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_version"
                && attribute.value == "0")
    );
    assert!(!extraction.attributes.iter().any(
        |attribute| attribute.value.contains("metadata") || attribute.value.contains("secret")
    ));
}

#[test]
fn validates_kafka_update_features_v2_request_without_feature_values() {
    let updates: &[UpdateFeaturesRequestFixture<'_>] = &[("kraft.version.secret", 2, 1)];
    let body = kafka_update_features_request_body(2, updates, true);
    let bytes = kafka_flexible_request_frame(57, 2, Some(b"secret-client"), &body);

    let extraction = parse_kafka_request(&bytes, &ProtocolExtractionConfig::default())
        .expect("kafka update features v2 request parses");

    assert_eq!(extraction.operation.as_deref(), Some("update_features"));
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "57")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_version"
                && attribute.value == "2")
    );
    assert!(
        !extraction.attributes.iter().any(
            |attribute| attribute.value.contains("kraft") || attribute.value.contains("secret")
        )
    );
}

#[test]
fn validates_kafka_describe_cluster_v0_request() {
    let body = kafka_describe_cluster_request_body(0);
    let bytes = kafka_flexible_request_frame(60, 0, Some(b"secret-client"), &body);

    let extraction = parse_kafka_request(&bytes, &ProtocolExtractionConfig::default())
        .expect("kafka describe cluster v0 request parses");

    assert_eq!(extraction.operation.as_deref(), Some("describe_cluster"));
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "60")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_version"
                && attribute.value == "0")
    );
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("secret"))
    );
}

#[test]
fn validates_kafka_describe_cluster_v2_request() {
    let body = kafka_describe_cluster_request_body(2);
    let bytes = kafka_flexible_request_frame(60, 2, Some(b"secret-client"), &body);

    let extraction = parse_kafka_request(&bytes, &ProtocolExtractionConfig::default())
        .expect("kafka describe cluster v2 request parses");

    assert_eq!(extraction.operation.as_deref(), Some("describe_cluster"));
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "60")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_version"
                && attribute.value == "2")
    );
}

#[test]
fn validates_kafka_describe_producers_request_without_topic_values() {
    let topics: &[DescribeProducersRequestTopicFixture<'_>] = &[("orders.secret", &[0, 1])];
    let body = kafka_describe_producers_request_body(topics);
    let bytes = kafka_flexible_request_frame(61, 0, Some(b"secret-client"), &body);

    let extraction = parse_kafka_request(&bytes, &ProtocolExtractionConfig::default())
        .expect("kafka describe producers request parses");

    assert_eq!(extraction.operation.as_deref(), Some("describe_producers"));
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "61")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_version"
                && attribute.value == "0")
    );
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("orders")
                || attribute.value.contains("secret"))
    );
}

#[test]
fn validates_kafka_broker_heartbeat_v0_request_without_broker_values() {
    let body = kafka_broker_heartbeat_request_body(0, 42, 9_876, 123_456, false, true);
    let bytes = kafka_flexible_request_frame(63, 0, Some(b"secret-client"), &body);

    let extraction = parse_kafka_request(&bytes, &ProtocolExtractionConfig::default())
        .expect("kafka broker heartbeat v0 request parses");

    assert_eq!(extraction.operation.as_deref(), Some("broker_heartbeat"));
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "63")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_version"
                && attribute.value == "0")
    );
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("42")
                || attribute.value.contains("9876")
                || attribute.value.contains("123456")
                || attribute.value.contains("secret"))
    );
}

#[test]
fn validates_kafka_broker_heartbeat_v2_request_without_tagged_log_dir_values() {
    let body = kafka_broker_heartbeat_request_body(2, 42, 9_876, 123_456, true, false);
    let bytes = kafka_flexible_request_frame(63, 2, Some(b"secret-client"), &body);

    let extraction = parse_kafka_request(&bytes, &ProtocolExtractionConfig::default())
        .expect("kafka broker heartbeat v2 request parses");

    assert_eq!(extraction.operation.as_deref(), Some("broker_heartbeat"));
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "63")
    );
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
            .any(|attribute| attribute.value.contains("42")
                || attribute.value.contains("9876")
                || attribute.value.contains("123456")
                || attribute.value.contains("secret"))
    );
}

#[test]
fn rejects_malformed_kafka_broker_heartbeat_requests() {
    let config = ProtocolExtractionConfig::default();
    let body = kafka_broker_heartbeat_request_body(0, 42, 9_876, 123_456, false, true);

    assert_eq!(
        parse_kafka_request(&kafka_flexible_request_frame(63, 3, None, &body), &config),
        Err(KafkaExtraction::UnsupportedApiVersion)
    );
    assert_eq!(
        parse_kafka_request(
            &kafka_flexible_request_frame(63, 0, None, b"\0\0\0\x2a"),
            &config,
        ),
        Err(KafkaExtraction::MalformedFrame)
    );
    assert_eq!(
        parse_kafka_request(
            &kafka_flexible_request_frame(
                63,
                2,
                None,
                &kafka_broker_heartbeat_request_body_with_tag_value_len(65),
            ),
            &ProtocolExtractionConfig {
                max_header_bytes: 128,
                max_request_line_bytes: 64,
                max_attributes: 8,
                max_tracestate_bytes: 32,
            },
        ),
        Err(KafkaExtraction::FrameTooLong)
    );
}

#[test]
fn validates_kafka_unregister_broker_request_without_broker_id_value() {
    let body = kafka_unregister_broker_request_body(42);
    let bytes = kafka_flexible_request_frame(64, 0, Some(b"secret-client"), &body);

    let extraction = parse_kafka_request(&bytes, &ProtocolExtractionConfig::default())
        .expect("kafka unregister broker request parses");

    assert_eq!(extraction.operation.as_deref(), Some("unregister_broker"));
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "64")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_version"
                && attribute.value == "0")
    );
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("42") || attribute.value.contains("secret"))
    );
}

#[test]
fn validates_kafka_describe_transactions_request_without_transactional_id_values() {
    let body = kafka_describe_transactions_request_body(&["txn.secret", "payments.secret"]);
    let bytes = kafka_flexible_request_frame(65, 0, Some(b"secret-client"), &body);

    let extraction = parse_kafka_request(&bytes, &ProtocolExtractionConfig::default())
        .expect("kafka describe transactions request parses");

    assert_eq!(
        extraction.operation.as_deref(),
        Some("describe_transactions")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "65")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_version"
                && attribute.value == "0")
    );
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("txn")
                || attribute.value.contains("payments")
                || attribute.value.contains("secret"))
    );
}

#[test]
fn validates_kafka_list_transactions_v0_request_without_filter_values() {
    let body = kafka_list_transactions_request_body(0, &["ongoing.secret"], &[1001], None);
    let bytes = kafka_flexible_request_frame(66, 0, Some(b"secret-client"), &body);

    let extraction = parse_kafka_request(&bytes, &ProtocolExtractionConfig::default())
        .expect("kafka list transactions v0 request parses");

    assert_eq!(extraction.operation.as_deref(), Some("list_transactions"));
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "66")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_version"
                && attribute.value == "0")
    );
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("ongoing")
                || attribute.value.contains("1001")
                || attribute.value.contains("secret"))
    );
}

#[test]
fn validates_kafka_list_transactions_v2_request_without_pattern_values() {
    let body = kafka_list_transactions_request_body(
        2,
        &["prepare_abort.secret"],
        &[1002],
        Some("txn.*secret"),
    );
    let bytes = kafka_flexible_request_frame(66, 2, Some(b"secret-client"), &body);

    let extraction = parse_kafka_request(&bytes, &ProtocolExtractionConfig::default())
        .expect("kafka list transactions v2 request parses");

    assert_eq!(extraction.operation.as_deref(), Some("list_transactions"));
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "66")
    );
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
            .any(|attribute| attribute.value.contains("abort")
                || attribute.value.contains("txn")
                || attribute.value.contains("1002")
                || attribute.value.contains("secret"))
    );
}

#[test]
fn validates_kafka_allocate_producer_ids_request_without_broker_values() {
    let body = kafka_allocate_producer_ids_request_body(12_345, 9_876_543);
    let bytes = kafka_flexible_request_frame(67, 0, Some(b"secret-client"), &body);

    let extraction = parse_kafka_request(&bytes, &ProtocolExtractionConfig::default())
        .expect("kafka allocate producer ids request parses");

    assert_eq!(
        extraction.operation.as_deref(),
        Some("allocate_producer_ids")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "67")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_version"
                && attribute.value == "0")
    );
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("12345")
                || attribute.value.contains("9876543")
                || attribute.value.contains("secret"))
    );
}

#[test]
fn rejects_malformed_kafka_allocate_producer_ids_requests() {
    let config = ProtocolExtractionConfig::default();
    let body = kafka_allocate_producer_ids_request_body(12_345, 9_876_543);

    assert_eq!(
        parse_kafka_request(&kafka_flexible_request_frame(67, 1, None, &body), &config),
        Err(KafkaExtraction::UnsupportedApiVersion)
    );
    assert_eq!(
        parse_kafka_request(
            &kafka_flexible_request_frame(67, 0, None, b"\0\0\0\x01"),
            &config,
        ),
        Err(KafkaExtraction::MalformedFrame)
    );

    let mut extra_body = body.clone();
    extra_body.push(0);
    assert_eq!(
        parse_kafka_request(
            &kafka_flexible_request_frame(67, 0, None, &extra_body),
            &config,
        ),
        Err(KafkaExtraction::MalformedFrame)
    );
}

#[test]
fn validates_kafka_consumer_group_heartbeat_v0_request_without_group_or_assignment_values() {
    let topic_partitions: &[ConsumerGroupHeartbeatTopicPartitionsFixture<'_>] =
        &[([7_u8; 16], &[0, 1])];
    let body = kafka_consumer_group_heartbeat_request_body(&ConsumerGroupHeartbeatRequestFixture {
        api_version: 0,
        group_id: "group.secret",
        member_id: "member.secret",
        instance_id: Some("instance.secret"),
        rack_id: Some("rack.secret"),
        subscribed_topic_names: Some(&["orders.secret"]),
        subscribed_topic_regex: None,
        server_assignor: Some("range.secret"),
        topic_partitions: Some(topic_partitions),
    });
    let bytes = kafka_flexible_request_frame(68, 0, Some(b"secret-client"), &body);

    let extraction = parse_kafka_request(&bytes, &ProtocolExtractionConfig::default())
        .expect("kafka consumer group heartbeat v0 request parses");

    assert_eq!(
        extraction.operation.as_deref(),
        Some("consumer_group_heartbeat")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "68")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_version"
                && attribute.value == "0")
    );
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("member")
                || attribute.value.contains("orders")
                || attribute.value.contains("range")
                || attribute.value.contains("secret"))
    );
}

#[test]
fn validates_kafka_consumer_group_heartbeat_v1_request_without_regex_values() {
    let body = kafka_consumer_group_heartbeat_request_body(&ConsumerGroupHeartbeatRequestFixture {
        api_version: 1,
        group_id: "group.secret",
        member_id: "member.secret",
        instance_id: None,
        rack_id: None,
        subscribed_topic_names: None,
        subscribed_topic_regex: Some("orders.*secret"),
        server_assignor: None,
        topic_partitions: None,
    });
    let bytes = kafka_flexible_request_frame(68, 1, Some(b"secret-client"), &body);

    let extraction = parse_kafka_request(&bytes, &ProtocolExtractionConfig::default())
        .expect("kafka consumer group heartbeat v1 request parses");

    assert_eq!(
        extraction.operation.as_deref(),
        Some("consumer_group_heartbeat")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "68")
    );
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
            .any(|attribute| attribute.value.contains("member")
                || attribute.value.contains("orders")
                || attribute.value.contains("secret"))
    );
}

#[test]
fn validates_kafka_consumer_group_describe_v0_request_without_group_values() {
    let body = kafka_consumer_group_describe_request_body(0, &["alpha.secret", "beta.secret"]);
    let bytes = kafka_flexible_request_frame(69, 0, Some(b"secret-client"), &body);

    let extraction = parse_kafka_request(&bytes, &ProtocolExtractionConfig::default())
        .expect("kafka consumer group describe v0 request parses");

    assert_eq!(
        extraction.operation.as_deref(),
        Some("consumer_group_describe")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "69")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_version"
                && attribute.value == "0")
    );
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("alpha")
                || attribute.value.contains("beta")
                || attribute.value.contains("secret"))
    );
}

#[test]
fn validates_kafka_share_group_heartbeat_request_without_group_member_rack_or_topic_values() {
    let body = kafka_share_group_heartbeat_request_body(&ShareGroupHeartbeatRequestFixture {
        group_id: "group.secret",
        member_id: "member.secret",
        rack_id: Some("rack.secret"),
        subscribed_topic_names: Some(&["orders.secret", "payments.secret"]),
    });
    let bytes = kafka_flexible_request_frame(76, 1, Some(b"secret-client"), &body);

    let extraction = parse_kafka_request(&bytes, &ProtocolExtractionConfig::default())
        .expect("kafka share group heartbeat request parses");

    assert_eq!(
        extraction.operation.as_deref(),
        Some("share_group_heartbeat")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "76")
    );
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
            .any(|attribute| attribute.value.contains("member")
                || attribute.value.contains("orders")
                || attribute.value.contains("payments")
                || attribute.value.contains("rack")
                || attribute.value.contains("secret"))
    );
}

#[test]
fn rejects_malformed_kafka_share_group_heartbeat_requests() {
    let config = ProtocolExtractionConfig::default();
    let body = kafka_share_group_heartbeat_request_body(&ShareGroupHeartbeatRequestFixture {
        group_id: "group",
        member_id: "member",
        rack_id: None,
        subscribed_topic_names: None,
    });

    assert_eq!(
        parse_kafka_request(&kafka_flexible_request_frame(76, 0, None, &body), &config),
        Err(KafkaExtraction::UnsupportedApiVersion)
    );

    let long_group_body =
        kafka_share_group_heartbeat_request_body(&ShareGroupHeartbeatRequestFixture {
            group_id: "group-secret",
            member_id: "member",
            rack_id: None,
            subscribed_topic_names: None,
        });
    assert_eq!(
        parse_kafka_request(
            &kafka_flexible_request_frame(76, 1, None, &long_group_body),
            &ProtocolExtractionConfig {
                max_header_bytes: 128,
                max_request_line_bytes: 4,
                max_attributes: 8,
                max_tracestate_bytes: 32,
            },
        ),
        Err(KafkaExtraction::ClientIdTooLong)
    );

    let mut oversized_topics_body = Vec::new();
    push_compact_string(&mut oversized_topics_body, "group");
    push_compact_string(&mut oversized_topics_body, "member");
    oversized_topics_body.extend_from_slice(&1_i32.to_be_bytes());
    push_compact_nullable_string(&mut oversized_topics_body, None);
    push_unsigned_varint(&mut oversized_topics_body, 1026);
    assert_eq!(
        parse_kafka_request(
            &kafka_flexible_request_frame(76, 1, None, &oversized_topics_body),
            &config,
        ),
        Err(KafkaExtraction::FrameTooLong)
    );

    assert_eq!(
        parse_kafka_request(&kafka_flexible_request_frame(76, 1, None, b"\0"), &config),
        Err(KafkaExtraction::MalformedFrame)
    );
}

#[test]
fn validates_kafka_controller_registration_request_without_listener_or_feature_values() {
    let listeners: &[ControllerRegistrationListenerFixture<'_>] =
        &[("controller.secret", "host.secret", 9093, 1)];
    let features: &[ControllerRegistrationFeatureFixture<'_>] = &[("metadata.secret", 1, 9)];
    let body = kafka_controller_registration_request_body(42, [7_u8; 16], listeners, features);
    let bytes = kafka_flexible_request_frame(70, 0, Some(b"secret-client"), &body);

    let extraction = parse_kafka_request(&bytes, &ProtocolExtractionConfig::default())
        .expect("kafka controller registration request parses");

    assert_eq!(
        extraction.operation.as_deref(),
        Some("controller_registration")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "70")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_version"
                && attribute.value == "0")
    );
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("42")
                || attribute.value.contains("host")
                || attribute.value.contains("metadata")
                || attribute.value.contains("secret"))
    );
}

#[test]
fn rejects_malformed_kafka_controller_registration_requests() {
    let config = ProtocolExtractionConfig::default();
    let body = kafka_controller_registration_request_body(42, [7_u8; 16], &[], &[]);

    assert_eq!(
        parse_kafka_request(&kafka_flexible_request_frame(70, 1, None, &body), &config),
        Err(KafkaExtraction::UnsupportedApiVersion)
    );
    assert_eq!(
        parse_kafka_request(
            &kafka_flexible_request_frame(70, 0, None, b"\0\0\0\x2a"),
            &config
        ),
        Err(KafkaExtraction::MalformedFrame)
    );

    let long_listener_body = kafka_controller_registration_request_body(
        42,
        [7_u8; 16],
        &[("controller.secret", "host", 9093, 1)],
        &[],
    );
    assert_eq!(
        parse_kafka_request(
            &kafka_flexible_request_frame(70, 0, None, &long_listener_body),
            &ProtocolExtractionConfig {
                max_header_bytes: 128,
                max_request_line_bytes: 4,
                max_attributes: 8,
                max_tracestate_bytes: 32,
            },
        ),
        Err(KafkaExtraction::ClientIdTooLong)
    );

    let mut oversized_listeners_body = Vec::new();
    oversized_listeners_body.extend_from_slice(&42_i32.to_be_bytes());
    oversized_listeners_body.extend_from_slice(&[7_u8; 16]);
    oversized_listeners_body.push(1);
    push_unsigned_varint(&mut oversized_listeners_body, 1026);
    assert_eq!(
        parse_kafka_request(
            &kafka_flexible_request_frame(70, 0, None, &oversized_listeners_body),
            &config,
        ),
        Err(KafkaExtraction::FrameTooLong)
    );
}

#[test]
fn validates_kafka_consumer_group_describe_v1_request_without_group_values() {
    let body = kafka_consumer_group_describe_request_body(1, &["alpha.secret"]);
    let bytes = kafka_flexible_request_frame(69, 1, Some(b"secret-client"), &body);

    let extraction = parse_kafka_request(&bytes, &ProtocolExtractionConfig::default())
        .expect("kafka consumer group describe v1 request parses");

    assert_eq!(
        extraction.operation.as_deref(),
        Some("consumer_group_describe")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "69")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_version"
                && attribute.value == "1")
    );
    assert!(
        !extraction.attributes.iter().any(
            |attribute| attribute.value.contains("alpha") || attribute.value.contains("secret")
        )
    );
}

#[test]
fn validates_kafka_get_telemetry_subscriptions_request_without_instance_values() {
    let body = kafka_get_telemetry_subscriptions_request_body([17_u8; 16]);
    let bytes = kafka_flexible_request_frame(71, 0, Some(b"secret-client"), &body);

    let extraction = parse_kafka_request(&bytes, &ProtocolExtractionConfig::default())
        .expect("kafka get telemetry subscriptions request parses");

    assert_eq!(
        extraction.operation.as_deref(),
        Some("get_telemetry_subscriptions")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "71")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_version"
                && attribute.value == "0")
    );
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("17") || attribute.value.contains("secret"))
    );
}

#[test]
fn validates_kafka_push_telemetry_request_without_metric_payload_values() {
    let body = kafka_push_telemetry_request_body([17_u8; 16], b"secret metric payload");
    let bytes = kafka_flexible_request_frame(72, 0, Some(b"secret-client"), &body);

    let extraction = parse_kafka_request(&bytes, &ProtocolExtractionConfig::default())
        .expect("kafka push telemetry request parses");

    assert_eq!(extraction.operation.as_deref(), Some("push_telemetry"));
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "72")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_version"
                && attribute.value == "0")
    );
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("metric")
                || attribute.value.contains("payload")
                || attribute.value.contains("17")
                || attribute.value.contains("secret"))
    );
}

#[test]
fn validates_kafka_list_config_resources_v0_request() {
    let bytes = kafka_flexible_request_frame(74, 0, Some(b"secret-client"), b"\0");

    let extraction = parse_kafka_request(&bytes, &ProtocolExtractionConfig::default())
        .expect("kafka list config resources v0 request parses");

    assert_eq!(
        extraction.operation.as_deref(),
        Some("list_config_resources")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "74")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_version"
                && attribute.value == "0")
    );
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("secret"))
    );
}

#[test]
fn validates_kafka_list_config_resources_v1_request_without_resource_type_values() {
    let body = kafka_list_config_resources_request_body(&[2, 4]);
    let bytes = kafka_flexible_request_frame(74, 1, Some(b"secret-client"), &body);

    let extraction = parse_kafka_request(&bytes, &ProtocolExtractionConfig::default())
        .expect("kafka list config resources v1 request parses");

    assert_eq!(
        extraction.operation.as_deref(),
        Some("list_config_resources")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "74")
    );
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
            .any(|attribute| attribute.value.contains("secret"))
    );
}

#[test]
fn validates_kafka_describe_topic_partitions_request_without_topic_values() {
    let body =
        kafka_describe_topic_partitions_request_body(&["orders.secret", "payments.secret"], None);
    let bytes = kafka_flexible_request_frame(75, 0, Some(b"secret-client"), &body);

    let extraction = parse_kafka_request(&bytes, &ProtocolExtractionConfig::default())
        .expect("kafka describe topic partitions request parses");

    assert_eq!(
        extraction.operation.as_deref(),
        Some("describe_topic_partitions")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "75")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_version"
                && attribute.value == "0")
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
fn validates_kafka_describe_topic_partitions_request_without_cursor_values() {
    let body = kafka_describe_topic_partitions_request_body(
        &["orders.secret"],
        Some(("cursor.secret", 12)),
    );
    let bytes = kafka_flexible_request_frame(75, 0, Some(b"secret-client"), &body);

    let extraction = parse_kafka_request(&bytes, &ProtocolExtractionConfig::default())
        .expect("kafka describe topic partitions cursor request parses");

    assert_eq!(
        extraction.operation.as_deref(),
        Some("describe_topic_partitions")
    );
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("orders")
                || attribute.value.contains("cursor")
                || attribute.value.contains("12")
                || attribute.value.contains("secret"))
    );
}

#[test]
fn validates_kafka_add_raft_voter_v0_request_without_cluster_or_listener_values() {
    let body = kafka_add_raft_voter_request_body(
        0,
        Some("cluster.secret"),
        &[("internal", "host.secret", 9093)],
    );
    let bytes = kafka_flexible_request_frame(80, 0, Some(b"secret-client"), &body);

    let extraction = parse_kafka_request(&bytes, &ProtocolExtractionConfig::default())
        .expect("kafka add raft voter v0 request parses");

    assert_eq!(extraction.operation.as_deref(), Some("add_raft_voter"));
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "80")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_version"
                && attribute.value == "0")
    );
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("cluster")
                || attribute.value.contains("internal")
                || attribute.value.contains("host")
                || attribute.value.contains("secret"))
    );
}

#[test]
fn validates_kafka_add_raft_voter_v1_request_without_cluster_or_listener_values() {
    let body = kafka_add_raft_voter_request_body(
        1,
        Some("cluster.secret"),
        &[("controller", "voter.secret", 9093)],
    );
    let bytes = kafka_flexible_request_frame(80, 1, Some(b"secret-client"), &body);

    let extraction = parse_kafka_request(&bytes, &ProtocolExtractionConfig::default())
        .expect("kafka add raft voter v1 request parses");

    assert_eq!(extraction.operation.as_deref(), Some("add_raft_voter"));
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("cluster")
                || attribute.value.contains("controller")
                || attribute.value.contains("secret"))
    );
}

#[test]
fn validates_kafka_remove_raft_voter_request_without_cluster_values() {
    let body = kafka_remove_raft_voter_request_body(Some("cluster.secret"));
    let bytes = kafka_flexible_request_frame(81, 0, Some(b"secret-client"), &body);

    let extraction = parse_kafka_request(&bytes, &ProtocolExtractionConfig::default())
        .expect("kafka remove raft voter request parses");

    assert_eq!(extraction.operation.as_deref(), Some("remove_raft_voter"));
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "81")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_version"
                && attribute.value == "0")
    );
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("cluster")
                || attribute.value.contains("secret")
                || attribute.value.contains("29"))
    );
}

#[test]
fn validates_kafka_update_raft_voter_request_without_cluster_or_listener_values() {
    let body = kafka_update_raft_voter_request_body(
        Some("cluster.secret"),
        &[("INTERNAL", "broker.secret.internal", 9092)],
    );
    let bytes = kafka_flexible_request_frame(82, 0, Some(b"secret-client"), &body);

    let extraction = parse_kafka_request(&bytes, &ProtocolExtractionConfig::default())
        .expect("kafka update raft voter request parses");

    assert_eq!(extraction.operation.as_deref(), Some("update_raft_voter"));
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "82")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_version"
                && attribute.value == "0")
    );
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("cluster")
                || attribute.value.contains("secret")
                || attribute.value.contains("broker")
                || attribute.value.contains("INTERNAL"))
    );
}

#[test]
fn validates_kafka_initialize_share_group_state_request_without_group_or_topic_values() {
    let partitions: &[InitializeShareGroupStatePartitionFixture] =
        &[InitializeShareGroupStatePartitionFixture {
            partition: 1,
            state_epoch: 2,
            start_offset: 100,
        }];
    let topics: &[InitializeShareGroupStateTopicFixture<'_>] =
        &[InitializeShareGroupStateTopicFixture {
            topic_id: [29_u8; 16],
            partitions,
        }];
    let body = kafka_initialize_share_group_state_request_body("group.secret", topics);
    let bytes = kafka_flexible_request_frame(83, 0, Some(b"secret-client"), &body);

    let extraction = parse_kafka_request(&bytes, &ProtocolExtractionConfig::default())
        .expect("kafka initialize share group state request parses");

    assert_eq!(
        extraction.operation.as_deref(),
        Some("initialize_share_group_state")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "83")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_version"
                && attribute.value == "0")
    );
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("secret")
                || attribute.value.contains("29")
                || attribute.value.contains("100"))
    );
}

#[test]
fn validates_kafka_read_share_group_state_request_without_group_or_topic_values() {
    let partitions: &[ReadShareGroupStatePartitionFixture] =
        &[ReadShareGroupStatePartitionFixture {
            partition: 1,
            leader_epoch: 2,
        }];
    let topics: &[ReadShareGroupStateTopicFixture<'_>] = &[ReadShareGroupStateTopicFixture {
        topic_id: [29_u8; 16],
        partitions,
    }];
    let body = kafka_read_share_group_state_request_body("group.secret", topics);
    let bytes = kafka_flexible_request_frame(84, 0, Some(b"secret-client"), &body);

    let extraction = parse_kafka_request(&bytes, &ProtocolExtractionConfig::default())
        .expect("kafka read share group state request parses");

    assert_eq!(
        extraction.operation.as_deref(),
        Some("read_share_group_state")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "84")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_version"
                && attribute.value == "0")
    );
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("secret") || attribute.value.contains("29"))
    );
}

#[test]
fn validates_kafka_write_share_group_state_request_without_group_or_state_values() {
    let batches: &[WriteShareGroupStateBatchFixture] = &[WriteShareGroupStateBatchFixture {
        first_offset: 100,
        last_offset: 200,
        delivery_state: 2,
        delivery_count: 3,
    }];
    let partitions: &[WriteShareGroupStatePartitionFixture<'_>] =
        &[WriteShareGroupStatePartitionFixture {
            partition: 1,
            state_epoch: 5,
            leader_epoch: 2,
            start_offset: 100,
            delivery_complete_count: Some(4),
            state_batches: batches,
        }];
    let topics: &[WriteShareGroupStateTopicFixture<'_>] = &[WriteShareGroupStateTopicFixture {
        topic_id: [29_u8; 16],
        partitions,
    }];
    let body = kafka_write_share_group_state_request_body("group.secret", topics, 1);
    let bytes = kafka_flexible_request_frame(85, 1, Some(b"secret-client"), &body);

    let extraction = parse_kafka_request(&bytes, &ProtocolExtractionConfig::default())
        .expect("kafka write share group state request parses");

    assert_eq!(
        extraction.operation.as_deref(),
        Some("write_share_group_state")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "85")
    );
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
                || attribute.value.contains("29")
                || attribute.value.contains("100")
                || attribute.value.contains("200"))
    );
}

#[test]
fn validates_kafka_delete_share_group_state_request_without_group_or_topic_values() {
    let partitions: &[DeleteShareGroupStatePartitionFixture] =
        &[DeleteShareGroupStatePartitionFixture { partition: 1 }];
    let topics: &[DeleteShareGroupStateTopicFixture<'_>] = &[DeleteShareGroupStateTopicFixture {
        topic_id: [29_u8; 16],
        partitions,
    }];
    let body = kafka_delete_share_group_state_request_body("group.secret", topics);
    let bytes = kafka_flexible_request_frame(86, 0, Some(b"secret-client"), &body);

    let extraction = parse_kafka_request(&bytes, &ProtocolExtractionConfig::default())
        .expect("kafka delete share group state request parses");

    assert_eq!(
        extraction.operation.as_deref(),
        Some("delete_share_group_state")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "86")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_version"
                && attribute.value == "0")
    );
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("secret") || attribute.value.contains("29"))
    );
}

#[test]
fn validates_kafka_read_share_group_state_summary_request_without_group_or_topic_values() {
    let partitions: &[ReadShareGroupStateSummaryPartitionFixture] =
        &[ReadShareGroupStateSummaryPartitionFixture {
            partition: 1,
            leader_epoch: 2,
        }];
    let topics: &[ReadShareGroupStateSummaryTopicFixture<'_>] =
        &[ReadShareGroupStateSummaryTopicFixture {
            topic_id: [29_u8; 16],
            partitions,
        }];
    let body = kafka_read_share_group_state_summary_request_body("group.secret", topics);
    let bytes = kafka_flexible_request_frame(87, 1, Some(b"secret-client"), &body);

    let extraction = parse_kafka_request(&bytes, &ProtocolExtractionConfig::default())
        .expect("kafka read share group state summary request parses");

    assert_eq!(
        extraction.operation.as_deref(),
        Some("read_share_group_state_summary")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "87")
    );
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
            .any(|attribute| attribute.value.contains("secret") || attribute.value.contains("29"))
    );
}

#[test]
fn validates_kafka_describe_share_group_offsets_request_without_group_or_topic_values() {
    let topics: &[DescribeShareGroupOffsetsRequestTopicFixture<'_>] = &[("orders.secret", &[0, 3])];
    let groups: &[DescribeShareGroupOffsetsRequestGroupFixture<'_>] =
        &[("group.secret", Some(topics)), ("group.all.secret", None)];
    let body = kafka_describe_share_group_offsets_request_body(groups);
    let bytes = kafka_flexible_request_frame(90, 0, Some(b"secret-client"), &body);

    let extraction = parse_kafka_request(&bytes, &ProtocolExtractionConfig::default())
        .expect("kafka describe share group offsets request parses");

    assert_eq!(
        extraction.operation.as_deref(),
        Some("describe_share_group_offsets")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "90")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_version"
                && attribute.value == "0")
    );
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("secret")
                || attribute.value.contains("orders"))
    );

    let v1_bytes = kafka_flexible_request_frame(90, 1, Some(b"secret-client"), &body);
    let v1_extraction = parse_kafka_request(&v1_bytes, &ProtocolExtractionConfig::default())
        .expect("kafka describe share group offsets v1 request parses");
    assert_eq!(
        v1_extraction.operation.as_deref(),
        Some("describe_share_group_offsets")
    );
    assert!(
        v1_extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_version"
                && attribute.value == "1")
    );
}

#[test]
fn validates_kafka_delete_share_group_offsets_request_without_group_or_topic_values() {
    let body = kafka_delete_share_group_offsets_request_body("group.secret", &["orders.secret"]);
    let bytes = kafka_flexible_request_frame(92, 0, Some(b"secret-client"), &body);

    let extraction = parse_kafka_request(&bytes, &ProtocolExtractionConfig::default())
        .expect("kafka delete share group offsets request parses");

    assert_eq!(
        extraction.operation.as_deref(),
        Some("delete_share_group_offsets")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "92")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_version"
                && attribute.value == "0")
    );
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("secret")
                || attribute.value.contains("orders"))
    );
}

#[test]
fn validates_kafka_alter_replica_log_dirs_requests_without_path_or_topic_values() {
    let body = kafka_alter_replica_log_dirs_request_body(
        "/var/lib/kafka/secret-dir",
        &[("orders.secret", &[0, 1])],
    );
    let bytes = kafka_request_frame(34, 1, Some(b"secret-client"), &body);

    let extraction = parse_kafka_request(&bytes, &ProtocolExtractionConfig::default())
        .expect("kafka alter replica log dirs request parses");

    assert_eq!(
        extraction.operation.as_deref(),
        Some("alter_replica_log_dirs")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "34")
    );
    assert!(extraction.attributes.iter().any(|attribute| {
        attribute.key == "messaging.kafka.api_version" && attribute.value == "1"
    }));
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("orders")
                || attribute.value.contains("secret")
                || attribute.value.contains("/var/lib"))
    );
}

#[test]
fn validates_kafka_describe_log_dirs_requests_without_topic_values() {
    let body = kafka_describe_log_dirs_request_body(Some(&[("orders.secret", &[0, 1])]));
    let bytes = kafka_request_frame(35, 1, Some(b"secret-client"), &body);

    let extraction = parse_kafka_request(&bytes, &ProtocolExtractionConfig::default())
        .expect("kafka describe log dirs request parses");

    assert_eq!(extraction.operation.as_deref(), Some("describe_log_dirs"));
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "35")
    );
    assert!(extraction.attributes.iter().any(|attribute| {
        attribute.key == "messaging.kafka.api_version" && attribute.value == "1"
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
fn validates_kafka_describe_log_dirs_nullable_topics_request() {
    let body = kafka_describe_log_dirs_request_body(None);
    let bytes = kafka_request_frame(35, 1, Some(b"secret-client"), &body);

    let extraction = parse_kafka_request(&bytes, &ProtocolExtractionConfig::default())
        .expect("kafka describe log dirs nullable topics request parses");

    assert_eq!(extraction.operation.as_deref(), Some("describe_log_dirs"));
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "35")
    );
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("secret"))
    );
}

#[test]
fn validates_kafka_create_delegation_token_requests_without_principal_values() {
    let body = kafka_create_delegation_token_request_body(&[("User", "alice.secret")]);
    let bytes = kafka_request_frame(38, 1, Some(b"secret-client"), &body);

    let extraction = parse_kafka_request(&bytes, &ProtocolExtractionConfig::default())
        .expect("kafka create delegation token request parses");

    assert_eq!(
        extraction.operation.as_deref(),
        Some("create_delegation_token")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "38")
    );
    assert!(extraction.attributes.iter().any(|attribute| {
        attribute.key == "messaging.kafka.api_version" && attribute.value == "1"
    }));
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("alice")
                || attribute.value.contains("User")
                || attribute.value.contains("secret"))
    );
}

#[test]
fn validates_kafka_renew_delegation_token_requests_without_hmac_values() {
    let body = kafka_renew_delegation_token_request_body(b"hmac-secret");
    let bytes = kafka_request_frame(39, 1, Some(b"secret-client"), &body);

    let extraction = parse_kafka_request(&bytes, &ProtocolExtractionConfig::default())
        .expect("kafka renew delegation token request parses");

    assert_eq!(
        extraction.operation.as_deref(),
        Some("renew_delegation_token")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "39")
    );
    assert!(extraction.attributes.iter().any(|attribute| {
        attribute.key == "messaging.kafka.api_version" && attribute.value == "1"
    }));
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("hmac")
                || attribute.value.contains("secret"))
    );
}

#[test]
fn validates_kafka_expire_delegation_token_requests_without_hmac_values() {
    let body = kafka_expire_delegation_token_request_body(b"hmac-secret");
    let bytes = kafka_request_frame(40, 1, Some(b"secret-client"), &body);

    let extraction = parse_kafka_request(&bytes, &ProtocolExtractionConfig::default())
        .expect("kafka expire delegation token request parses");

    assert_eq!(
        extraction.operation.as_deref(),
        Some("expire_delegation_token")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "40")
    );
    assert!(extraction.attributes.iter().any(|attribute| {
        attribute.key == "messaging.kafka.api_version" && attribute.value == "1"
    }));
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("hmac")
                || attribute.value.contains("secret"))
    );
}

#[test]
fn validates_kafka_describe_delegation_token_requests_without_owner_values() {
    let body = kafka_describe_delegation_token_request_body(Some(&[("User", "alice.secret")]));
    let bytes = kafka_request_frame(41, 1, Some(b"secret-client"), &body);

    let extraction = parse_kafka_request(&bytes, &ProtocolExtractionConfig::default())
        .expect("kafka describe delegation token request parses");

    assert_eq!(
        extraction.operation.as_deref(),
        Some("describe_delegation_token")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "41")
    );
    assert!(extraction.attributes.iter().any(|attribute| {
        attribute.key == "messaging.kafka.api_version" && attribute.value == "1"
    }));
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("alice")
                || attribute.value.contains("User")
                || attribute.value.contains("secret"))
    );
}

#[test]
fn validates_kafka_describe_delegation_token_nullable_owners_request() {
    let body = kafka_describe_delegation_token_request_body(None);
    let bytes = kafka_request_frame(41, 1, Some(b"secret-client"), &body);

    let extraction = parse_kafka_request(&bytes, &ProtocolExtractionConfig::default())
        .expect("kafka describe delegation token nullable owners request parses");

    assert_eq!(
        extraction.operation.as_deref(),
        Some("describe_delegation_token")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "41")
    );
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("secret"))
    );
}

#[test]
fn validates_kafka_find_coordinator_v2_request_without_key_value() {
    let body = kafka_find_coordinator_request_body(2, "group.secret");
    let bytes = kafka_request_frame(10, 2, Some(b"secret-client"), &body);

    let extraction = parse_kafka_request(&bytes, &ProtocolExtractionConfig::default())
        .expect("kafka find coordinator v2 request parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation.as_deref(), Some("find_coordinator"));
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "10")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_version"
                && attribute.value == "2")
    );
    assert!(
        !extraction.attributes.iter().any(
            |attribute| attribute.value.contains("secret") || attribute.value.contains("group")
        )
    );
}

#[test]
fn validates_kafka_find_coordinator_legacy_requests_without_key_value() {
    for api_version in 0..=1 {
        let body = kafka_find_coordinator_request_body(api_version, "group.secret");
        let bytes = kafka_request_frame(10, api_version, Some(b"secret-client"), &body);

        let extraction = parse_kafka_request(&bytes, &ProtocolExtractionConfig::default())
            .expect("kafka find coordinator request parses");

        assert_eq!(extraction.operation.as_deref(), Some("find_coordinator"));
        assert!(
            extraction
                .attributes
                .iter()
                .any(|attribute| attribute.key == "messaging.kafka.api_version"
                    && attribute.value == api_version.to_string())
        );
        assert!(!extraction.attributes.iter().any(
            |attribute| attribute.value.contains("secret") || attribute.value.contains("group")
        ));
    }
}

#[test]
fn validates_kafka_join_group_requests_without_group_member_or_protocol_values() {
    for api_version in 0..=5 {
        let body = kafka_join_group_request_body(
            api_version,
            &[("range.secret", b"secret-protocol-metadata".as_slice())],
        );
        let bytes = kafka_request_frame(11, api_version, Some(b"secret-client"), &body);

        let extraction = parse_kafka_request(&bytes, &ProtocolExtractionConfig::default())
            .expect("kafka join group request parses");

        assert_eq!(extraction.operation.as_deref(), Some("join_group"));
        assert!(
            extraction
                .attributes
                .iter()
                .any(|attribute| attribute.key == "messaging.kafka.api_key"
                    && attribute.value == "11")
        );
        assert!(
            extraction
                .attributes
                .iter()
                .any(|attribute| attribute.key == "messaging.kafka.api_version"
                    && attribute.value == api_version.to_string())
        );
        assert!(
            !extraction
                .attributes
                .iter()
                .any(|attribute| attribute.value.contains("secret")
                    || attribute.value.contains("member")
                    || attribute.value.contains("range"))
        );
    }
}

#[test]
fn validates_kafka_heartbeat_v3_request_without_group_or_member_values() {
    let body = kafka_heartbeat_request_body(3, Some("instance.secret"));
    let bytes = kafka_request_frame(12, 3, Some(b"secret-client"), &body);

    let extraction = parse_kafka_request(&bytes, &ProtocolExtractionConfig::default())
        .expect("kafka heartbeat v3 request parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation.as_deref(), Some("heartbeat"));
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "12")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_version"
                && attribute.value == "3")
    );
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("secret")
                || attribute.value.contains("member")
                || attribute.value.contains("instance"))
    );
}

#[test]
fn validates_kafka_heartbeat_legacy_requests_without_group_or_member_values() {
    for api_version in 0..=2 {
        let body = kafka_heartbeat_request_body(api_version, None);
        let bytes = kafka_request_frame(12, api_version, Some(b"secret-client"), &body);

        let extraction = parse_kafka_request(&bytes, &ProtocolExtractionConfig::default())
            .expect("kafka heartbeat request parses");

        assert_eq!(extraction.operation.as_deref(), Some("heartbeat"));
        assert!(
            extraction
                .attributes
                .iter()
                .any(|attribute| attribute.key == "messaging.kafka.api_version"
                    && attribute.value == api_version.to_string())
        );
        assert!(
            !extraction
                .attributes
                .iter()
                .any(|attribute| attribute.value.contains("secret")
                    || attribute.value.contains("member"))
        );
    }
}

#[test]
fn validates_kafka_leave_group_v3_request_without_group_or_member_values() {
    let body = kafka_leave_group_request_body(3);
    let bytes = kafka_request_frame(13, 3, Some(b"secret-client"), &body);

    let extraction = parse_kafka_request(&bytes, &ProtocolExtractionConfig::default())
        .expect("kafka leave group v3 request parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation.as_deref(), Some("leave_group"));
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "13")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_version"
                && attribute.value == "3")
    );
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("secret")
                || attribute.value.contains("member")
                || attribute.value.contains("instance"))
    );
}

#[test]
fn validates_kafka_leave_group_legacy_requests_without_group_or_member_values() {
    for api_version in 0..=2 {
        let body = kafka_leave_group_request_body(api_version);
        let bytes = kafka_request_frame(13, api_version, Some(b"secret-client"), &body);

        let extraction = parse_kafka_request(&bytes, &ProtocolExtractionConfig::default())
            .expect("kafka leave group request parses");

        assert_eq!(extraction.operation.as_deref(), Some("leave_group"));
        assert!(
            extraction
                .attributes
                .iter()
                .any(|attribute| attribute.key == "messaging.kafka.api_version"
                    && attribute.value == api_version.to_string())
        );
        assert!(
            !extraction
                .attributes
                .iter()
                .any(|attribute| attribute.value.contains("secret")
                    || attribute.value.contains("member"))
        );
    }
}

#[test]
fn validates_kafka_sync_group_v3_request_without_group_member_or_assignment_values() {
    let body = kafka_sync_group_request_body(3, b"secret-assignment");
    let bytes = kafka_request_frame(14, 3, Some(b"secret-client"), &body);

    let extraction = parse_kafka_request(&bytes, &ProtocolExtractionConfig::default())
        .expect("kafka sync group v3 request parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation.as_deref(), Some("sync_group"));
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "14")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_version"
                && attribute.value == "3")
    );
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("secret")
                || attribute.value.contains("member")
                || attribute.value.contains("assignment"))
    );
}

#[test]
fn validates_kafka_sync_group_legacy_requests_without_group_member_or_assignment_values() {
    for api_version in 0..=2 {
        let body = kafka_sync_group_request_body(api_version, b"secret-assignment");
        let bytes = kafka_request_frame(14, api_version, Some(b"secret-client"), &body);

        let extraction = parse_kafka_request(&bytes, &ProtocolExtractionConfig::default())
            .expect("kafka sync group request parses");

        assert_eq!(extraction.operation.as_deref(), Some("sync_group"));
        assert!(
            extraction
                .attributes
                .iter()
                .any(|attribute| attribute.key == "messaging.kafka.api_version"
                    && attribute.value == api_version.to_string())
        );
        assert!(
            !extraction
                .attributes
                .iter()
                .any(|attribute| attribute.value.contains("secret")
                    || attribute.value.contains("member")
                    || attribute.value.contains("assignment"))
        );
    }
}

#[test]
fn validates_kafka_describe_groups_v4_request_without_group_values() {
    let body = kafka_describe_groups_request_body(4, &["group.secret", "other.secret"]);
    let bytes = kafka_request_frame(15, 4, Some(b"secret-client"), &body);

    let extraction = parse_kafka_request(&bytes, &ProtocolExtractionConfig::default())
        .expect("kafka describe groups v4 request parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation.as_deref(), Some("describe_groups"));
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "15")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_version"
                && attribute.value == "4")
    );
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("secret"))
    );
}

#[test]
fn validates_kafka_describe_groups_legacy_requests_without_group_values() {
    for api_version in 0..=3 {
        let body = kafka_describe_groups_request_body(api_version, &["group.secret"]);
        let bytes = kafka_request_frame(15, api_version, Some(b"secret-client"), &body);

        let extraction = parse_kafka_request(&bytes, &ProtocolExtractionConfig::default())
            .expect("kafka describe groups request parses");

        assert_eq!(extraction.operation.as_deref(), Some("describe_groups"));
        assert!(
            extraction
                .attributes
                .iter()
                .any(|attribute| attribute.key == "messaging.kafka.api_version"
                    && attribute.value == api_version.to_string())
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
fn validates_kafka_list_groups_requests_without_body_values() {
    for api_version in 0..=3 {
        let bytes = kafka_request_frame(16, api_version, Some(b"secret-client"), b"");

        let extraction = parse_kafka_request(&bytes, &ProtocolExtractionConfig::default())
            .expect("kafka list groups request parses");

        assert_eq!(extraction.operation.as_deref(), Some("list_groups"));
        assert!(
            extraction
                .attributes
                .iter()
                .any(|attribute| attribute.key == "messaging.kafka.api_version"
                    && attribute.value == api_version.to_string())
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
fn validates_kafka_sasl_handshake_requests_without_mechanism_values() {
    for api_version in 0..=1 {
        let body = kafka_sasl_handshake_request_body("PLAIN.secret");
        let bytes = kafka_request_frame(17, api_version, Some(b"secret-client"), &body);

        let extraction = parse_kafka_request(&bytes, &ProtocolExtractionConfig::default())
            .expect("kafka sasl handshake request parses");

        assert_eq!(extraction.operation.as_deref(), Some("sasl_handshake"));
        assert!(
            extraction
                .attributes
                .iter()
                .any(|attribute| attribute.key == "messaging.kafka.api_key"
                    && attribute.value == "17")
        );
        assert!(
            extraction
                .attributes
                .iter()
                .any(|attribute| attribute.key == "messaging.kafka.api_version"
                    && attribute.value == api_version.to_string())
        );
        assert!(!extraction.attributes.iter().any(
            |attribute| attribute.value.contains("PLAIN") || attribute.value.contains("secret")
        ));
    }
}

#[test]
fn validates_kafka_sasl_authenticate_requests_without_auth_values() {
    for api_version in 0..=1 {
        let body = kafka_sasl_authenticate_request_body(b"secret-auth-bytes");
        let bytes = kafka_request_frame(36, api_version, Some(b"secret-client"), &body);

        let extraction = parse_kafka_request(&bytes, &ProtocolExtractionConfig::default())
            .expect("kafka sasl authenticate request parses");

        assert_eq!(extraction.operation.as_deref(), Some("sasl_authenticate"));
        assert!(
            extraction
                .attributes
                .iter()
                .any(|attribute| attribute.key == "messaging.kafka.api_key"
                    && attribute.value == "36")
        );
        assert!(
            extraction
                .attributes
                .iter()
                .any(|attribute| attribute.key == "messaging.kafka.api_version"
                    && attribute.value == api_version.to_string())
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
fn validates_kafka_delete_groups_requests_without_group_values() {
    for api_version in 0..=1 {
        let body = kafka_delete_groups_request_body(&["group.secret", "other.secret"]);
        let bytes = kafka_request_frame(42, api_version, Some(b"secret-client"), &body);

        let extraction = parse_kafka_request(&bytes, &ProtocolExtractionConfig::default())
            .expect("kafka delete groups request parses");

        assert_eq!(extraction.operation.as_deref(), Some("delete_groups"));
        assert!(
            extraction
                .attributes
                .iter()
                .any(|attribute| attribute.key == "messaging.kafka.api_key"
                    && attribute.value == "42")
        );
        assert!(
            extraction
                .attributes
                .iter()
                .any(|attribute| attribute.key == "messaging.kafka.api_version"
                    && attribute.value == api_version.to_string())
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
fn validates_kafka_elect_leaders_v0_request_without_topic_values() {
    let body = kafka_elect_leaders_request_body(0, Some(&[("orders.secret", &[0, 1])]));
    let bytes = kafka_request_frame(43, 0, Some(b"secret-client"), &body);

    let extraction = parse_kafka_request(&bytes, &ProtocolExtractionConfig::default())
        .expect("kafka elect leaders v0 request parses");

    assert_eq!(extraction.operation.as_deref(), Some("elect_leaders"));
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "43")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_version"
                && attribute.value == "0")
    );
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("orders")
                || attribute.value.contains("secret"))
    );
}

#[test]
fn validates_kafka_elect_leaders_v1_nullable_partitions_request() {
    let body = kafka_elect_leaders_request_body(1, None);
    let bytes = kafka_request_frame(43, 1, Some(b"secret-client"), &body);

    let extraction = parse_kafka_request(&bytes, &ProtocolExtractionConfig::default())
        .expect("kafka elect leaders v1 request parses");

    assert_eq!(extraction.operation.as_deref(), Some("elect_leaders"));
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "43")
    );
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
            .any(|attribute| attribute.value.contains("secret"))
    );
}

#[test]
fn validates_kafka_init_producer_id_requests_without_transactional_id_values() {
    for api_version in 0..=1 {
        let body = kafka_init_producer_id_request_body(Some("transaction.secret"));
        let bytes = kafka_request_frame(22, api_version, Some(b"secret-client"), &body);

        let extraction = parse_kafka_request(&bytes, &ProtocolExtractionConfig::default())
            .expect("kafka init producer id request parses");

        assert_eq!(extraction.operation.as_deref(), Some("init_producer_id"));
        assert!(
            extraction
                .attributes
                .iter()
                .any(|attribute| attribute.key == "messaging.kafka.api_key"
                    && attribute.value == "22")
        );
        assert!(
            extraction
                .attributes
                .iter()
                .any(|attribute| attribute.key == "messaging.kafka.api_version"
                    && attribute.value == api_version.to_string())
        );
        assert!(
            !extraction
                .attributes
                .iter()
                .any(|attribute| attribute.value.contains("secret")
                    || attribute.value.contains("transaction"))
        );
    }
}

#[test]
fn validates_kafka_init_producer_id_nullable_transactional_id_request() {
    let body = kafka_init_producer_id_request_body(None);
    let bytes = kafka_request_frame(22, 1, Some(b"secret-client"), &body);

    let extraction = parse_kafka_request(&bytes, &ProtocolExtractionConfig::default())
        .expect("kafka init producer id nullable request parses");

    assert_eq!(extraction.operation.as_deref(), Some("init_producer_id"));
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("secret"))
    );
}

#[test]
fn validates_kafka_add_partitions_to_txn_requests_without_transaction_or_topic_values() {
    for api_version in 0..=2 {
        let body = kafka_add_partitions_to_txn_request_body(&[("orders.secret", &[0, 1])]);
        let bytes = kafka_request_frame(24, api_version, Some(b"secret-client"), &body);

        let extraction = parse_kafka_request(&bytes, &ProtocolExtractionConfig::default())
            .expect("kafka add partitions to txn request parses");

        assert_eq!(
            extraction.operation.as_deref(),
            Some("add_partitions_to_txn")
        );
        assert!(
            extraction
                .attributes
                .iter()
                .any(|attribute| attribute.key == "messaging.kafka.api_key"
                    && attribute.value == "24")
        );
        assert!(
            extraction
                .attributes
                .iter()
                .any(|attribute| attribute.key == "messaging.kafka.api_version"
                    && attribute.value == api_version.to_string())
        );
        assert!(
            !extraction
                .attributes
                .iter()
                .any(|attribute| attribute.value.contains("secret")
                    || attribute.value.contains("orders")
                    || attribute.value.contains("transaction"))
        );
    }
}

#[test]
fn validates_kafka_add_offsets_to_txn_requests_without_transaction_or_group_values() {
    for api_version in 0..=2 {
        let body = kafka_add_offsets_to_txn_request_body();
        let bytes = kafka_request_frame(25, api_version, Some(b"secret-client"), &body);

        let extraction = parse_kafka_request(&bytes, &ProtocolExtractionConfig::default())
            .expect("kafka add offsets to txn request parses");

        assert_eq!(extraction.operation.as_deref(), Some("add_offsets_to_txn"));
        assert!(
            extraction
                .attributes
                .iter()
                .any(|attribute| attribute.key == "messaging.kafka.api_key"
                    && attribute.value == "25")
        );
        assert!(
            extraction
                .attributes
                .iter()
                .any(|attribute| attribute.key == "messaging.kafka.api_version"
                    && attribute.value == api_version.to_string())
        );
        assert!(
            !extraction
                .attributes
                .iter()
                .any(|attribute| attribute.value.contains("secret")
                    || attribute.value.contains("transaction")
                    || attribute.value.contains("group"))
        );
    }
}

#[test]
fn validates_kafka_end_txn_requests_without_transaction_values() {
    for api_version in 0..=2 {
        let body = kafka_end_txn_request_body();
        let bytes = kafka_request_frame(26, api_version, Some(b"secret-client"), &body);

        let extraction = parse_kafka_request(&bytes, &ProtocolExtractionConfig::default())
            .expect("kafka end txn request parses");

        assert_eq!(extraction.operation.as_deref(), Some("end_txn"));
        assert!(
            extraction
                .attributes
                .iter()
                .any(|attribute| attribute.key == "messaging.kafka.api_key"
                    && attribute.value == "26")
        );
        assert!(
            extraction
                .attributes
                .iter()
                .any(|attribute| attribute.key == "messaging.kafka.api_version"
                    && attribute.value == api_version.to_string())
        );
        assert!(
            !extraction
                .attributes
                .iter()
                .any(|attribute| attribute.value.contains("secret")
                    || attribute.value.contains("transaction"))
        );
    }
}

#[test]
fn validates_kafka_txn_offset_commit_requests_without_transaction_group_topic_or_metadata_values() {
    for api_version in 0..=2 {
        let body = kafka_txn_offset_commit_request_body(api_version, &[("orders.secret", &[0])]);
        let bytes = kafka_request_frame(28, api_version, Some(b"secret-client"), &body);

        let extraction = parse_kafka_request(&bytes, &ProtocolExtractionConfig::default())
            .expect("kafka txn offset commit request parses");

        assert_eq!(extraction.operation.as_deref(), Some("txn_offset_commit"));
        assert!(
            extraction
                .attributes
                .iter()
                .any(|attribute| attribute.key == "messaging.kafka.api_key"
                    && attribute.value == "28")
        );
        assert!(
            extraction
                .attributes
                .iter()
                .any(|attribute| attribute.key == "messaging.kafka.api_version"
                    && attribute.value == api_version.to_string())
        );
        assert!(
            !extraction
                .attributes
                .iter()
                .any(|attribute| attribute.value.contains("secret")
                    || attribute.value.contains("transaction")
                    || attribute.value.contains("group")
                    || attribute.value.contains("orders")
                    || attribute.value.contains("metadata"))
        );
    }
}

#[test]
fn validates_kafka_write_txn_markers_requests_without_topic_or_marker_values() {
    for api_version in 1..=2 {
        let body = kafka_write_txn_markers_request_body(api_version, &[("orders.secret", &[0])]);
        let bytes = kafka_flexible_request_frame(27, api_version, Some(b"secret-client"), &body);

        let extraction = parse_kafka_request(&bytes, &ProtocolExtractionConfig::default())
            .expect("kafka write txn markers request parses");

        assert_eq!(extraction.operation.as_deref(), Some("write_txn_markers"));
        assert!(
            extraction
                .attributes
                .iter()
                .any(|attribute| attribute.key == "messaging.kafka.api_key"
                    && attribute.value == "27")
        );
        assert!(
            extraction
                .attributes
                .iter()
                .any(|attribute| attribute.key == "messaging.kafka.api_version"
                    && attribute.value == api_version.to_string())
        );
        assert!(
            !extraction
                .attributes
                .iter()
                .any(|attribute| attribute.value.contains("secret")
                    || attribute.value.contains("orders"))
        );
    }
}

#[test]
fn validates_kafka_metadata_v8_request_without_topic_values() {
    let body = kafka_metadata_request_body(8, Some(&["orders.secret", "payments.secret"]));
    let bytes = kafka_request_frame(3, 8, Some(b"secret-client"), &body);

    let extraction = parse_kafka_request(&bytes, &ProtocolExtractionConfig::default())
        .expect("kafka metadata v8 request parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation.as_deref(), Some("metadata"));
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "3")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_version"
                && attribute.value == "8")
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
fn validates_kafka_metadata_legacy_requests_without_topic_values() {
    for api_version in 0..=7 {
        let body = kafka_metadata_request_body(api_version, Some(&["orders.secret"]));
        let bytes = kafka_request_frame(3, api_version, Some(b"secret-client"), &body);

        let extraction = parse_kafka_request(&bytes, &ProtocolExtractionConfig::default())
            .expect("kafka metadata request parses");

        assert_eq!(extraction.operation.as_deref(), Some("metadata"));
        assert!(
            extraction
                .attributes
                .iter()
                .any(|attribute| attribute.key == "messaging.kafka.api_version"
                    && attribute.value == api_version.to_string())
        );
        assert!(
            !extraction
                .attributes
                .iter()
                .any(|attribute| attribute.value.contains("secret")
                    || attribute.value.contains("orders"))
        );
    }
}

#[test]
fn validates_kafka_metadata_nullable_topic_requests() {
    for api_version in 1..=8 {
        let body = kafka_metadata_request_body(api_version, None);
        let bytes = kafka_request_frame(3, api_version, Some(b"secret-client"), &body);

        let extraction = parse_kafka_request(&bytes, &ProtocolExtractionConfig::default())
            .expect("kafka metadata nullable request parses");

        assert_eq!(extraction.operation.as_deref(), Some("metadata"));
        assert!(
            !extraction
                .attributes
                .iter()
                .any(|attribute| attribute.value.contains("secret"))
        );
    }
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
