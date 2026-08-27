use super::*;

#[test]
fn extracts_kafka_describe_log_dirs_ok_response_without_path_or_topic_values() {
    let bytes = kafka_describe_log_dirs_response_frame(
        0,
        &[(0, "/var/lib/kafka/secret-dir", &[("orders.secret", &[0])])],
    );

    let extraction =
        parse_kafka_describe_log_dirs_response(&bytes, 1, &ProtocolExtractionConfig::default())
            .expect("describe log dirs ok response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "describe_log_dirs");
    assert_eq!(extraction.status_code, "0");
    assert_eq!(extraction.error_type, None);
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "35")
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
                || attribute.value.contains("/var/lib"))
    );
}

#[test]
fn extracts_kafka_describe_log_dirs_error_response_without_path_or_topic_values() {
    let bytes = kafka_describe_log_dirs_response_frame(
        0,
        &[
            (0, "/var/lib/kafka/secret-dir", &[("orders.secret", &[0])]),
            (
                35,
                "/var/lib/kafka/payments-secret",
                &[("payments.secret", &[1])],
            ),
        ],
    );

    let extraction =
        parse_kafka_describe_log_dirs_response(&bytes, 1, &ProtocolExtractionConfig::default())
            .expect("describe log dirs error response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "describe_log_dirs");
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
                || attribute.value.contains("secret")
                || attribute.value.contains("/var/lib"))
    );
}

#[test]
fn extracts_kafka_create_delegation_token_ok_response_without_token_values() {
    let bytes = kafka_create_delegation_token_response_frame(
        0,
        0,
        "User",
        "alice.secret",
        "token.secret.id",
        b"hmac-secret",
    );

    let extraction = parse_kafka_create_delegation_token_response(
        &bytes,
        1,
        &ProtocolExtractionConfig::default(),
    )
    .expect("create delegation token ok response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "create_delegation_token");
    assert_eq!(extraction.status_code, "0");
    assert_eq!(extraction.error_type, None);
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "38")
    );
    assert!(extraction.attributes.iter().any(|attribute| {
        attribute.key == "messaging.kafka.response.error_code" && attribute.value == "0"
    }));
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("alice")
                || attribute.value.contains("token.secret")
                || attribute.value.contains("hmac")
                || attribute.value.contains("secret")
                || attribute.value.contains("User"))
    );
}

#[test]
fn extracts_kafka_create_delegation_token_error_response_without_token_values() {
    let bytes = kafka_create_delegation_token_response_frame(
        0,
        35,
        "User",
        "alice.secret",
        "token.secret.id",
        b"hmac-secret",
    );

    let extraction = parse_kafka_create_delegation_token_response(
        &bytes,
        1,
        &ProtocolExtractionConfig::default(),
    )
    .expect("create delegation token error response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "create_delegation_token");
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
            .any(|attribute| attribute.value.contains("alice")
                || attribute.value.contains("token.secret")
                || attribute.value.contains("hmac")
                || attribute.value.contains("secret")
                || attribute.value.contains("User"))
    );
}

#[test]
fn extracts_kafka_renew_delegation_token_ok_response() {
    let bytes = kafka_renew_delegation_token_response_frame(0, 0);

    let extraction = parse_kafka_renew_delegation_token_response(
        &bytes,
        1,
        &ProtocolExtractionConfig::default(),
    )
    .expect("renew delegation token ok response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "renew_delegation_token");
    assert_eq!(extraction.status_code, "0");
    assert_eq!(extraction.error_type, None);
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "39")
    );
    assert!(extraction.attributes.iter().any(|attribute| {
        attribute.key == "messaging.kafka.response.error_code" && attribute.value == "0"
    }));
}

#[test]
fn extracts_kafka_renew_delegation_token_error_response() {
    let bytes = kafka_renew_delegation_token_response_frame(0, 35);

    let extraction = parse_kafka_renew_delegation_token_response(
        &bytes,
        1,
        &ProtocolExtractionConfig::default(),
    )
    .expect("renew delegation token error response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "renew_delegation_token");
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
}

#[test]
fn extracts_kafka_expire_delegation_token_ok_response() {
    let bytes = kafka_expire_delegation_token_response_frame(0, 0);

    let extraction = parse_kafka_expire_delegation_token_response(
        &bytes,
        1,
        &ProtocolExtractionConfig::default(),
    )
    .expect("expire delegation token ok response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "expire_delegation_token");
    assert_eq!(extraction.status_code, "0");
    assert_eq!(extraction.error_type, None);
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "40")
    );
    assert!(extraction.attributes.iter().any(|attribute| {
        attribute.key == "messaging.kafka.response.error_code" && attribute.value == "0"
    }));
}

#[test]
fn extracts_kafka_expire_delegation_token_error_response() {
    let bytes = kafka_expire_delegation_token_response_frame(0, 35);

    let extraction = parse_kafka_expire_delegation_token_response(
        &bytes,
        1,
        &ProtocolExtractionConfig::default(),
    )
    .expect("expire delegation token error response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "expire_delegation_token");
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
}

#[test]
fn extracts_kafka_describe_delegation_token_ok_response_without_token_values() {
    let bytes = kafka_describe_delegation_token_response_frame(
        0,
        0,
        &[DescribeDelegationTokenFixture {
            principal_type: "User",
            principal_name: "alice.secret",
            token_id: "token.secret.id",
            hmac: b"hmac-secret",
            renewers: &[("User", "bob.secret")],
        }],
    );

    let extraction = parse_kafka_describe_delegation_token_response(
        &bytes,
        1,
        &ProtocolExtractionConfig::default(),
    )
    .expect("describe delegation token ok response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "describe_delegation_token");
    assert_eq!(extraction.status_code, "0");
    assert_eq!(extraction.error_type, None);
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "41")
    );
    assert!(extraction.attributes.iter().any(|attribute| {
        attribute.key == "messaging.kafka.response.error_code" && attribute.value == "0"
    }));
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("alice")
                || attribute.value.contains("bob")
                || attribute.value.contains("token.secret")
                || attribute.value.contains("hmac")
                || attribute.value.contains("secret")
                || attribute.value.contains("User"))
    );
}

#[test]
fn extracts_kafka_describe_delegation_token_error_response_without_token_values() {
    let bytes = kafka_describe_delegation_token_response_frame(
        0,
        35,
        &[DescribeDelegationTokenFixture {
            principal_type: "User",
            principal_name: "alice.secret",
            token_id: "token.secret.id",
            hmac: b"hmac-secret",
            renewers: &[("User", "bob.secret")],
        }],
    );

    let extraction = parse_kafka_describe_delegation_token_response(
        &bytes,
        1,
        &ProtocolExtractionConfig::default(),
    )
    .expect("describe delegation token error response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "describe_delegation_token");
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
            .any(|attribute| attribute.value.contains("alice")
                || attribute.value.contains("bob")
                || attribute.value.contains("token.secret")
                || attribute.value.contains("hmac")
                || attribute.value.contains("secret")
                || attribute.value.contains("User"))
    );
}

#[test]
fn extracts_kafka_elect_leaders_ok_response_without_topic_or_message_values() {
    let bytes = kafka_elect_leaders_response_frame(0, 0, 0, &[("orders.secret", &[(0, 0, None)])]);

    let extraction =
        parse_kafka_elect_leaders_response(&bytes, 0, &ProtocolExtractionConfig::default())
            .expect("elect leaders ok response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "elect_leaders");
    assert_eq!(extraction.status_code, "0");
    assert_eq!(extraction.error_type, None);
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "43")
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
fn extracts_kafka_elect_leaders_error_response_without_topic_or_message_values() {
    let bytes = kafka_elect_leaders_response_frame(
        0,
        1,
        0,
        &[
            ("orders.secret", &[(0, 0, None)]),
            ("payments.secret", &[(1, 35, Some("leader secret denied"))]),
        ],
    );

    let extraction =
        parse_kafka_elect_leaders_response(&bytes, 1, &ProtocolExtractionConfig::default())
            .expect("elect leaders error response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "elect_leaders");
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
            .any(|attribute| attribute.value.contains("orders")
                || attribute.value.contains("payments")
                || attribute.value.contains("denied")
                || attribute.value.contains("secret"))
    );
}

#[test]
fn extracts_kafka_elect_leaders_top_level_error_before_partition_error() {
    let bytes = kafka_elect_leaders_response_frame(
        0,
        1,
        31,
        &[("orders.secret", &[(0, 35, Some("secret"))])],
    );

    let extraction =
        parse_kafka_elect_leaders_response(&bytes, 1, &ProtocolExtractionConfig::default())
            .expect("elect leaders top-level error response parses");

    assert_eq!(extraction.status_code, "31");
    assert_eq!(extraction.error_type.as_deref(), Some("31"));
}

#[test]
fn extracts_kafka_incremental_alter_configs_v0_ok_response_without_resource_or_message_values() {
    let bytes =
        kafka_incremental_alter_configs_response_frame(0, 0, &[(0, None, 2, "orders.secret")]);

    let extraction = parse_kafka_incremental_alter_configs_response(
        &bytes,
        0,
        &ProtocolExtractionConfig::default(),
    )
    .expect("incremental alter configs v0 ok response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "incremental_alter_configs");
    assert_eq!(extraction.status_code, "0");
    assert_eq!(extraction.error_type, None);
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "44")
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
fn extracts_kafka_incremental_alter_configs_v1_error_response_without_resource_or_message_values() {
    let bytes = kafka_incremental_alter_configs_response_frame(
        0,
        1,
        &[
            (0, None, 2, "orders.secret"),
            (40, Some("config secret denied"), 2, "payments.secret"),
        ],
    );

    let extraction = parse_kafka_incremental_alter_configs_response(
        &bytes,
        1,
        &ProtocolExtractionConfig::default(),
    )
    .expect("incremental alter configs v1 error response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "incremental_alter_configs");
    assert_eq!(extraction.status_code, "40");
    assert_eq!(extraction.error_type.as_deref(), Some("40"));
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
            .any(|attribute| attribute.key == "error.type" && attribute.value == "40")
    );
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("orders")
                || attribute.value.contains("payments")
                || attribute.value.contains("denied")
                || attribute.value.contains("secret"))
    );
}

#[test]
fn extracts_kafka_alter_partition_reassignments_ok_response_without_topic_or_message_values() {
    let partitions: &[AlterPartitionReassignmentResultFixture<'_>] = &[(0, 0, None)];
    let topics: &[AlterPartitionReassignmentTopicResultFixture<'_>] =
        &[("orders.secret", partitions)];
    let bytes = kafka_alter_partition_reassignments_response_frame(0, 0, 0, None, topics);

    let extraction = parse_kafka_alter_partition_reassignments_response(
        &bytes,
        0,
        &ProtocolExtractionConfig::default(),
    )
    .expect("alter partition reassignments ok response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "alter_partition_reassignments");
    assert_eq!(extraction.status_code, "0");
    assert_eq!(extraction.error_type, None);
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "45")
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
fn extracts_kafka_alter_partition_reassignments_partition_error_without_topic_or_message_values() {
    let partitions: &[AlterPartitionReassignmentResultFixture<'_>] =
        &[(0, 0, None), (1, 35, Some("partition secret denied"))];
    let topics: &[AlterPartitionReassignmentTopicResultFixture<'_>] =
        &[("orders.secret", partitions)];
    let bytes = kafka_alter_partition_reassignments_response_frame(0, 1, 0, None, topics);

    let extraction = parse_kafka_alter_partition_reassignments_response(
        &bytes,
        1,
        &ProtocolExtractionConfig::default(),
    )
    .expect("alter partition reassignments partition error response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "alter_partition_reassignments");
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
            .any(|attribute| attribute.value.contains("orders")
                || attribute.value.contains("denied")
                || attribute.value.contains("secret"))
    );
}

#[test]
fn extracts_kafka_alter_partition_reassignments_top_level_error_before_partition_error() {
    let partitions: &[AlterPartitionReassignmentResultFixture<'_>] =
        &[(0, 35, Some("partition secret denied"))];
    let topics: &[AlterPartitionReassignmentTopicResultFixture<'_>] =
        &[("orders.secret", partitions)];
    let bytes = kafka_alter_partition_reassignments_response_frame(
        0,
        1,
        31,
        Some("top secret denied"),
        topics,
    );

    let extraction = parse_kafka_alter_partition_reassignments_response(
        &bytes,
        1,
        &ProtocolExtractionConfig::default(),
    )
    .expect("alter partition reassignments top-level error response parses");

    assert_eq!(extraction.status_code, "31");
    assert_eq!(extraction.error_type.as_deref(), Some("31"));
}

#[test]
fn extracts_kafka_list_partition_reassignments_ok_response_without_topic_values() {
    let partitions: &[ListPartitionReassignmentResultFixture<'_>] = &[(0, &[1, 2], &[3], &[4])];
    let topics: &[ListPartitionReassignmentTopicResultFixture<'_>] =
        &[("orders.secret", partitions)];
    let bytes = kafka_list_partition_reassignments_response_frame(0, 0, None, topics);

    let extraction = parse_kafka_list_partition_reassignments_response(
        &bytes,
        0,
        &ProtocolExtractionConfig::default(),
    )
    .expect("list partition reassignments ok response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "list_partition_reassignments");
    assert_eq!(extraction.status_code, "0");
    assert_eq!(extraction.error_type, None);
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "46")
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
fn extracts_kafka_list_partition_reassignments_error_without_message_values() {
    let bytes =
        kafka_list_partition_reassignments_response_frame(0, 31, Some("top secret denied"), &[]);

    let extraction = parse_kafka_list_partition_reassignments_response(
        &bytes,
        0,
        &ProtocolExtractionConfig::default(),
    )
    .expect("list partition reassignments error response parses");

    assert_eq!(extraction.status_code, "31");
    assert_eq!(extraction.error_type.as_deref(), Some("31"));
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
            .any(|attribute| attribute.value.contains("denied")
                || attribute.value.contains("secret"))
    );
}

#[test]
fn extracts_kafka_join_group_ok_response_without_group_member_or_metadata_values() {
    let bytes = kafka_join_group_response_frame(0, 5, 0, &[("member.secret", b"secret-metadata")]);

    let extraction =
        parse_kafka_join_group_response(&bytes, 5, &ProtocolExtractionConfig::default())
            .expect("join group ok response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "join_group");
    assert_eq!(extraction.status_code, "0");
    assert_eq!(extraction.error_type, None);
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "11")
    );
    assert!(extraction.attributes.iter().any(|attribute| {
        attribute.key == "messaging.kafka.response.error_code" && attribute.value == "0"
    }));
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("secret")
                || attribute.value.contains("member")
                || attribute.value.contains("range"))
    );
}

#[test]
fn extracts_kafka_join_group_error_response_without_group_member_or_metadata_values() {
    let bytes = kafka_join_group_response_frame(0, 2, 25, &[("member.secret", b"secret-metadata")]);

    let extraction =
        parse_kafka_join_group_response(&bytes, 2, &ProtocolExtractionConfig::default())
            .expect("join group error response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "join_group");
    assert_eq!(extraction.status_code, "25");
    assert_eq!(extraction.error_type.as_deref(), Some("25"));
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
            .any(|attribute| attribute.key == "error.type" && attribute.value == "25")
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

#[test]
fn extracts_kafka_find_coordinator_ok_response_without_host_or_message_values() {
    let bytes = kafka_find_coordinator_response_frame(0, 2, 0, None);

    let extraction =
        parse_kafka_find_coordinator_response(&bytes, 2, &ProtocolExtractionConfig::default())
            .expect("find coordinator ok response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "find_coordinator");
    assert_eq!(extraction.status_code, "0");
    assert_eq!(extraction.error_type, None);
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "10")
    );
    assert!(extraction.attributes.iter().any(|attribute| {
        attribute.key == "messaging.kafka.response.error_code" && attribute.value == "0"
    }));
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("secret")
                || attribute.value.contains("broker")
                || attribute.value.contains("coordinator.secret"))
    );
}

#[test]
fn extracts_kafka_find_coordinator_error_response_without_host_or_message_values() {
    let bytes = kafka_find_coordinator_response_frame(0, 1, 15, Some("coordinator.secret"));

    let extraction =
        parse_kafka_find_coordinator_response(&bytes, 1, &ProtocolExtractionConfig::default())
            .expect("find coordinator error response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "find_coordinator");
    assert_eq!(extraction.status_code, "15");
    assert_eq!(extraction.error_type.as_deref(), Some("15"));
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
            .any(|attribute| attribute.key == "error.type" && attribute.value == "15")
    );
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("secret")
                || attribute.value.contains("broker")
                || attribute.value.contains("coordinator.secret"))
    );
}

#[test]
fn extracts_kafka_heartbeat_ok_response() {
    let bytes = kafka_heartbeat_response_frame(0, 3, 0);

    let extraction =
        parse_kafka_heartbeat_response(&bytes, 3, &ProtocolExtractionConfig::default())
            .expect("heartbeat ok response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "heartbeat");
    assert_eq!(extraction.status_code, "0");
    assert_eq!(extraction.error_type, None);
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "12")
    );
    assert!(extraction.attributes.iter().any(|attribute| {
        attribute.key == "messaging.kafka.response.error_code" && attribute.value == "0"
    }));
}

#[test]
fn extracts_kafka_heartbeat_error_response() {
    let bytes = kafka_heartbeat_response_frame(0, 1, 27);

    let extraction =
        parse_kafka_heartbeat_response(&bytes, 1, &ProtocolExtractionConfig::default())
            .expect("heartbeat error response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "heartbeat");
    assert_eq!(extraction.status_code, "27");
    assert_eq!(extraction.error_type.as_deref(), Some("27"));
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
            .any(|attribute| attribute.key == "error.type" && attribute.value == "27")
    );
}

#[test]
fn extracts_kafka_leave_group_ok_response_without_member_values() {
    let bytes = kafka_leave_group_response_frame(0, 3, 0, &[("member.secret", None, 0)]);

    let extraction =
        parse_kafka_leave_group_response(&bytes, 3, &ProtocolExtractionConfig::default())
            .expect("leave group ok response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "leave_group");
    assert_eq!(extraction.status_code, "0");
    assert_eq!(extraction.error_type, None);
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "13")
    );
    assert!(extraction.attributes.iter().any(|attribute| {
        attribute.key == "messaging.kafka.response.error_code" && attribute.value == "0"
    }));
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("secret")
                || attribute.value.contains("member"))
    );
}

#[test]
fn extracts_kafka_leave_group_error_response_without_member_values() {
    let bytes = kafka_leave_group_response_frame(
        0,
        3,
        0,
        &[
            ("member.secret", Some("instance.secret"), 0),
            ("other.secret", None, 25),
        ],
    );

    let extraction =
        parse_kafka_leave_group_response(&bytes, 3, &ProtocolExtractionConfig::default())
            .expect("leave group error response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "leave_group");
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
                || attribute.value.contains("member")
                || attribute.value.contains("instance"))
    );
}

#[test]
fn extracts_kafka_sync_group_ok_response_without_assignment_values() {
    let bytes = kafka_sync_group_response_frame(0, 3, 0, b"secret-assignment");

    let extraction =
        parse_kafka_sync_group_response(&bytes, 3, &ProtocolExtractionConfig::default())
            .expect("sync group ok response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "sync_group");
    assert_eq!(extraction.status_code, "0");
    assert_eq!(extraction.error_type, None);
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "14")
    );
    assert!(extraction.attributes.iter().any(|attribute| {
        attribute.key == "messaging.kafka.response.error_code" && attribute.value == "0"
    }));
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("secret")
                || attribute.value.contains("assignment"))
    );
}

#[test]
fn extracts_kafka_sync_group_error_response_without_assignment_values() {
    let bytes = kafka_sync_group_response_frame(0, 1, 25, b"secret-assignment");

    let extraction =
        parse_kafka_sync_group_response(&bytes, 1, &ProtocolExtractionConfig::default())
            .expect("sync group error response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "sync_group");
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
                || attribute.value.contains("assignment"))
    );
}

#[test]
fn extracts_kafka_describe_groups_ok_response_without_group_or_member_values() {
    let bytes = kafka_describe_groups_response_frame(0, 4, &[("group.secret", 0, 0)]);

    let extraction =
        parse_kafka_describe_groups_response(&bytes, 4, &ProtocolExtractionConfig::default())
            .expect("describe groups ok response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "describe_groups");
    assert_eq!(extraction.status_code, "0");
    assert_eq!(extraction.error_type, None);
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "15")
    );
    assert!(extraction.attributes.iter().any(|attribute| {
        attribute.key == "messaging.kafka.response.error_code" && attribute.value == "0"
    }));
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("secret")
                || attribute.value.contains("client")
                || attribute.value.contains("host")
                || attribute.value.contains("metadata")
                || attribute.value.contains("assignment"))
    );
}

#[test]
fn extracts_kafka_describe_groups_error_response_without_group_or_member_values() {
    let bytes = kafka_describe_groups_response_frame(
        0,
        3,
        &[("group.secret", 0, 0), ("other.secret", 30, 0)],
    );

    let extraction =
        parse_kafka_describe_groups_response(&bytes, 3, &ProtocolExtractionConfig::default())
            .expect("describe groups error response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "describe_groups");
    assert_eq!(extraction.status_code, "30");
    assert_eq!(extraction.error_type.as_deref(), Some("30"));
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
            .any(|attribute| attribute.key == "error.type" && attribute.value == "30")
    );
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("secret")
                || attribute.value.contains("client")
                || attribute.value.contains("host"))
    );
}

#[test]
fn extracts_kafka_list_groups_ok_response_without_group_values() {
    let bytes = kafka_list_groups_response_frame(0, 3, 0, &[("group.secret", "consumer")]);

    let extraction =
        parse_kafka_list_groups_response(&bytes, 3, &ProtocolExtractionConfig::default())
            .expect("list groups ok response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "list_groups");
    assert_eq!(extraction.status_code, "0");
    assert_eq!(extraction.error_type, None);
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "16")
    );
    assert!(extraction.attributes.iter().any(|attribute| {
        attribute.key == "messaging.kafka.response.error_code" && attribute.value == "0"
    }));
    assert!(!extraction.attributes.iter().any(
        |attribute| attribute.value.contains("secret") || attribute.value.contains("consumer")
    ));
}

#[test]
fn extracts_kafka_list_groups_error_response_without_group_values() {
    let bytes = kafka_list_groups_response_frame(0, 1, 30, &[("group.secret", "consumer")]);

    let extraction =
        parse_kafka_list_groups_response(&bytes, 1, &ProtocolExtractionConfig::default())
            .expect("list groups error response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "list_groups");
    assert_eq!(extraction.status_code, "30");
    assert_eq!(extraction.error_type.as_deref(), Some("30"));
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
            .any(|attribute| attribute.key == "error.type" && attribute.value == "30")
    );
    assert!(!extraction.attributes.iter().any(
        |attribute| attribute.value.contains("secret") || attribute.value.contains("consumer")
    ));
}

#[test]
fn extracts_kafka_metadata_ok_response_without_cluster_broker_or_topic_values() {
    let bytes = kafka_metadata_response_frame(0, 8, &[("orders.secret", 0, 0)]);

    let extraction = parse_kafka_metadata_response(&bytes, 8, &ProtocolExtractionConfig::default())
        .expect("metadata ok response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "metadata");
    assert_eq!(extraction.status_code, "0");
    assert_eq!(extraction.error_type, None);
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "3")
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
                || attribute.value.contains("broker")
                || attribute.value.contains("cluster"))
    );
}

#[test]
fn extracts_kafka_metadata_error_response_without_raw_values() {
    let bytes = kafka_metadata_response_frame(
        0,
        7,
        &[
            ("orders.secret", 0, 0),
            ("payments.secret", 0, 6),
            ("inventory.secret", 17, 0),
        ],
    );

    let extraction = parse_kafka_metadata_response(&bytes, 7, &ProtocolExtractionConfig::default())
        .expect("metadata error response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "metadata");
    assert_eq!(extraction.status_code, "6");
    assert_eq!(extraction.error_type.as_deref(), Some("6"));
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
                || attribute.value.contains("inventory")
                || attribute.value.contains("secret"))
    );
}

#[test]
fn extracts_kafka_delete_groups_ok_response_without_group_values() {
    let bytes = kafka_delete_groups_response_frame(0, &[("group.secret", 0)]);

    let extraction =
        parse_kafka_delete_groups_response(&bytes, 1, &ProtocolExtractionConfig::default())
            .expect("delete groups ok response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "delete_groups");
    assert_eq!(extraction.status_code, "0");
    assert_eq!(extraction.error_type, None);
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "42")
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
fn extracts_kafka_delete_groups_error_response_without_group_values() {
    let bytes = kafka_delete_groups_response_frame(0, &[("group.secret", 0), ("other.secret", 30)]);

    let extraction =
        parse_kafka_delete_groups_response(&bytes, 0, &ProtocolExtractionConfig::default())
            .expect("delete groups error response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "delete_groups");
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
            .any(|attribute| attribute.value.contains("secret"))
    );
}

#[test]
fn extracts_kafka_sasl_handshake_ok_response_without_mechanism_values() {
    let bytes = kafka_sasl_handshake_response_frame(0, 0, &["PLAIN.secret", "SCRAM.secret"]);

    let extraction =
        parse_kafka_sasl_handshake_response(&bytes, 1, &ProtocolExtractionConfig::default())
            .expect("sasl handshake ok response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "sasl_handshake");
    assert_eq!(extraction.status_code, "0");
    assert_eq!(extraction.error_type, None);
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "17")
    );
    assert!(extraction.attributes.iter().any(|attribute| {
        attribute.key == "messaging.kafka.response.error_code" && attribute.value == "0"
    }));
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("PLAIN")
                || attribute.value.contains("SCRAM")
                || attribute.value.contains("secret"))
    );
}

#[test]
fn extracts_kafka_sasl_handshake_error_response_without_mechanism_values() {
    let bytes = kafka_sasl_handshake_response_frame(0, 33, &["PLAIN.secret"]);

    let extraction =
        parse_kafka_sasl_handshake_response(&bytes, 0, &ProtocolExtractionConfig::default())
            .expect("sasl handshake error response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "sasl_handshake");
    assert_eq!(extraction.status_code, "33");
    assert_eq!(extraction.error_type.as_deref(), Some("33"));
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
            .any(|attribute| attribute.key == "error.type" && attribute.value == "33")
    );
    assert!(
        !extraction.attributes.iter().any(
            |attribute| attribute.value.contains("PLAIN") || attribute.value.contains("secret")
        )
    );
}

#[test]
fn extracts_kafka_sasl_authenticate_ok_response_without_auth_or_message_values() {
    let bytes = kafka_sasl_authenticate_response_frame(0, 1, 0, None, b"secret-auth-response");

    let extraction =
        parse_kafka_sasl_authenticate_response(&bytes, 1, &ProtocolExtractionConfig::default())
            .expect("sasl authenticate ok response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "sasl_authenticate");
    assert_eq!(extraction.status_code, "0");
    assert_eq!(extraction.error_type, None);
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "36")
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
fn extracts_kafka_sasl_authenticate_error_response_without_auth_or_message_values() {
    let bytes = kafka_sasl_authenticate_response_frame(
        0,
        0,
        58,
        Some("secret auth failed"),
        b"secret-auth-response",
    );

    let extraction =
        parse_kafka_sasl_authenticate_response(&bytes, 0, &ProtocolExtractionConfig::default())
            .expect("sasl authenticate error response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "sasl_authenticate");
    assert_eq!(extraction.status_code, "58");
    assert_eq!(extraction.error_type.as_deref(), Some("58"));
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
            .any(|attribute| attribute.key == "error.type" && attribute.value == "58")
    );
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("secret"))
    );
}

#[test]
fn extracts_kafka_init_producer_id_ok_response_without_producer_values() {
    let bytes = kafka_init_producer_id_response_frame(0, 1, 0);

    let extraction =
        parse_kafka_init_producer_id_response(&bytes, 1, &ProtocolExtractionConfig::default())
            .expect("init producer id ok response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "init_producer_id");
    assert_eq!(extraction.status_code, "0");
    assert_eq!(extraction.error_type, None);
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "22")
    );
    assert!(extraction.attributes.iter().any(|attribute| {
        attribute.key == "messaging.kafka.response.error_code" && attribute.value == "0"
    }));
}

#[test]
fn extracts_kafka_init_producer_id_error_response_without_producer_values() {
    let bytes = kafka_init_producer_id_response_frame(0, 0, 49);

    let extraction =
        parse_kafka_init_producer_id_response(&bytes, 0, &ProtocolExtractionConfig::default())
            .expect("init producer id error response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "init_producer_id");
    assert_eq!(extraction.status_code, "49");
    assert_eq!(extraction.error_type.as_deref(), Some("49"));
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
            .any(|attribute| attribute.key == "error.type" && attribute.value == "49")
    );
}

#[test]
fn extracts_kafka_add_partitions_to_txn_ok_response_without_topic_values() {
    let bytes = kafka_add_partitions_to_txn_response_frame(0, &[("orders.secret", 0)]);

    let extraction =
        parse_kafka_add_partitions_to_txn_response(&bytes, 2, &ProtocolExtractionConfig::default())
            .expect("add partitions to txn ok response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "add_partitions_to_txn");
    assert_eq!(extraction.status_code, "0");
    assert_eq!(extraction.error_type, None);
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "24")
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
fn extracts_kafka_add_partitions_to_txn_error_response_without_topic_values() {
    let bytes = kafka_add_partitions_to_txn_response_frame(
        0,
        &[("orders.secret", 0), ("payments.secret", 53)],
    );

    let extraction =
        parse_kafka_add_partitions_to_txn_response(&bytes, 1, &ProtocolExtractionConfig::default())
            .expect("add partitions to txn error response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "add_partitions_to_txn");
    assert_eq!(extraction.status_code, "53");
    assert_eq!(extraction.error_type.as_deref(), Some("53"));
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
            .any(|attribute| attribute.key == "error.type" && attribute.value == "53")
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
fn extracts_kafka_add_offsets_to_txn_ok_response() {
    let bytes = kafka_throttled_error_response_frame(0, 0);

    let extraction =
        parse_kafka_add_offsets_to_txn_response(&bytes, 2, &ProtocolExtractionConfig::default())
            .expect("add offsets to txn ok response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "add_offsets_to_txn");
    assert_eq!(extraction.status_code, "0");
    assert_eq!(extraction.error_type, None);
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "25")
    );
    assert!(extraction.attributes.iter().any(|attribute| {
        attribute.key == "messaging.kafka.response.error_code" && attribute.value == "0"
    }));
}

#[test]
fn extracts_kafka_add_offsets_to_txn_error_response() {
    let bytes = kafka_throttled_error_response_frame(0, 49);

    let extraction =
        parse_kafka_add_offsets_to_txn_response(&bytes, 1, &ProtocolExtractionConfig::default())
            .expect("add offsets to txn error response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "add_offsets_to_txn");
    assert_eq!(extraction.status_code, "49");
    assert_eq!(extraction.error_type.as_deref(), Some("49"));
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
            .any(|attribute| attribute.key == "error.type" && attribute.value == "49")
    );
}

#[test]
fn extracts_kafka_end_txn_ok_response() {
    let bytes = kafka_throttled_error_response_frame(0, 0);

    let extraction = parse_kafka_end_txn_response(&bytes, 2, &ProtocolExtractionConfig::default())
        .expect("end txn ok response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "end_txn");
    assert_eq!(extraction.status_code, "0");
    assert_eq!(extraction.error_type, None);
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "26")
    );
    assert!(extraction.attributes.iter().any(|attribute| {
        attribute.key == "messaging.kafka.response.error_code" && attribute.value == "0"
    }));
}

#[test]
fn extracts_kafka_end_txn_error_response() {
    let bytes = kafka_throttled_error_response_frame(0, 48);

    let extraction = parse_kafka_end_txn_response(&bytes, 0, &ProtocolExtractionConfig::default())
        .expect("end txn error response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "end_txn");
    assert_eq!(extraction.status_code, "48");
    assert_eq!(extraction.error_type.as_deref(), Some("48"));
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
            .any(|attribute| attribute.key == "error.type" && attribute.value == "48")
    );
}

#[test]
fn extracts_kafka_txn_offset_commit_ok_response_without_topic_values() {
    let bytes = kafka_txn_offset_commit_response_frame(0, &[("orders.secret", &[(0, 0)])]);

    let extraction =
        parse_kafka_txn_offset_commit_response(&bytes, 2, &ProtocolExtractionConfig::default())
            .expect("txn offset commit ok response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "txn_offset_commit");
    assert_eq!(extraction.status_code, "0");
    assert_eq!(extraction.error_type, None);
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "28")
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
fn extracts_kafka_txn_offset_commit_error_response_without_topic_values() {
    let bytes = kafka_txn_offset_commit_response_frame(
        0,
        &[
            ("orders.secret", &[(0, 0)]),
            ("payments.secret", &[(1, 27)]),
        ],
    );

    let extraction =
        parse_kafka_txn_offset_commit_response(&bytes, 1, &ProtocolExtractionConfig::default())
            .expect("txn offset commit error response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "txn_offset_commit");
    assert_eq!(extraction.status_code, "27");
    assert_eq!(extraction.error_type.as_deref(), Some("27"));
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
            .any(|attribute| attribute.key == "error.type" && attribute.value == "27")
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
fn extracts_kafka_write_txn_markers_ok_response_without_topic_values() {
    let bytes = kafka_write_txn_markers_response_frame(&[("orders.secret", &[(0, 0)])]);

    let extraction =
        parse_kafka_write_txn_markers_response(&bytes, 2, &ProtocolExtractionConfig::default())
            .expect("write txn markers ok response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "write_txn_markers");
    assert_eq!(extraction.status_code, "0");
    assert_eq!(extraction.error_type, None);
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "messaging.kafka.api_key" && attribute.value == "27")
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
fn extracts_kafka_write_txn_markers_error_response_without_topic_values() {
    let bytes = kafka_write_txn_markers_response_frame(&[
        ("orders.secret", &[(0, 0)]),
        ("payments.secret", &[(1, 48)]),
    ]);

    let extraction =
        parse_kafka_write_txn_markers_response(&bytes, 1, &ProtocolExtractionConfig::default())
            .expect("write txn markers error response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Kafka);
    assert_eq!(extraction.operation, "write_txn_markers");
    assert_eq!(extraction.status_code, "48");
    assert_eq!(extraction.error_type.as_deref(), Some("48"));
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
            .any(|attribute| attribute.key == "error.type" && attribute.value == "48")
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

    let bounded_offset_for_leader_epoch_response = parse_kafka_offset_for_leader_epoch_response(
        &kafka_offset_for_leader_epoch_response_frame(0, 4, &[]),
        4,
        &ProtocolExtractionConfig {
            max_header_bytes: 128,
            max_request_line_bytes: 64,
            max_attributes: 2,
            max_tracestate_bytes: 32,
        },
    )
    .expect("bounded kafka offset for leader epoch response parses");
    assert_eq!(bounded_offset_for_leader_epoch_response.attributes.len(), 2);

    let bounded_describe_quorum_response = parse_kafka_describe_quorum_response(
        &kafka_describe_quorum_response_frame(0, 0, 0, None, &[], &[]),
        0,
        &ProtocolExtractionConfig {
            max_header_bytes: 128,
            max_request_line_bytes: 64,
            max_attributes: 2,
            max_tracestate_bytes: 32,
        },
    )
    .expect("bounded kafka describe quorum response parses");
    assert_eq!(bounded_describe_quorum_response.attributes.len(), 2);

    let bounded_update_features_response = parse_kafka_update_features_response(
        &kafka_update_features_response_frame(0, 2, 0, None, &[]),
        2,
        &ProtocolExtractionConfig {
            max_header_bytes: 128,
            max_request_line_bytes: 64,
            max_attributes: 2,
            max_tracestate_bytes: 32,
        },
    )
    .expect("bounded kafka update features response parses");
    assert_eq!(bounded_update_features_response.attributes.len(), 2);

    let bounded_describe_cluster_response = parse_kafka_describe_cluster_response(
        &kafka_describe_cluster_response_frame(0, 0, 0, None, "cluster.secret", &[]),
        0,
        &ProtocolExtractionConfig {
            max_header_bytes: 128,
            max_request_line_bytes: 64,
            max_attributes: 2,
            max_tracestate_bytes: 32,
        },
    )
    .expect("bounded kafka describe cluster response parses");
    assert_eq!(bounded_describe_cluster_response.attributes.len(), 2);

    let bounded_describe_producers_response = parse_kafka_describe_producers_response(
        &kafka_describe_producers_response_frame(0, &[("orders.secret", &[])]),
        0,
        &ProtocolExtractionConfig {
            max_header_bytes: 128,
            max_request_line_bytes: 64,
            max_attributes: 2,
            max_tracestate_bytes: 32,
        },
    )
    .expect("bounded kafka describe producers response parses");
    assert_eq!(bounded_describe_producers_response.attributes.len(), 2);

    let bounded_broker_heartbeat_response = parse_kafka_broker_heartbeat_response(
        &kafka_broker_heartbeat_response_frame(0, 0, true, false, false),
        2,
        &ProtocolExtractionConfig {
            max_header_bytes: 128,
            max_request_line_bytes: 64,
            max_attributes: 2,
            max_tracestate_bytes: 32,
        },
    )
    .expect("bounded kafka broker heartbeat response parses");
    assert_eq!(bounded_broker_heartbeat_response.attributes.len(), 2);

    let bounded_unregister_broker_response = parse_kafka_unregister_broker_response(
        &kafka_unregister_broker_response_frame(0, 0, None),
        0,
        &ProtocolExtractionConfig {
            max_header_bytes: 128,
            max_request_line_bytes: 64,
            max_attributes: 2,
            max_tracestate_bytes: 32,
        },
    )
    .expect("bounded kafka unregister broker response parses");
    assert_eq!(bounded_unregister_broker_response.attributes.len(), 2);

    let bounded_describe_transactions_response = parse_kafka_describe_transactions_response(
        &kafka_describe_transactions_response_frame(0, &[]),
        0,
        &ProtocolExtractionConfig {
            max_header_bytes: 128,
            max_request_line_bytes: 64,
            max_attributes: 2,
            max_tracestate_bytes: 32,
        },
    )
    .expect("bounded kafka describe transactions response parses");
    assert_eq!(bounded_describe_transactions_response.attributes.len(), 2);

    let bounded_list_transactions_response = parse_kafka_list_transactions_response(
        &kafka_list_transactions_response_frame(0, 0, &[], &[]),
        2,
        &ProtocolExtractionConfig {
            max_header_bytes: 128,
            max_request_line_bytes: 64,
            max_attributes: 2,
            max_tracestate_bytes: 32,
        },
    )
    .expect("bounded kafka list transactions response parses");
    assert_eq!(bounded_list_transactions_response.attributes.len(), 2);

    let bounded_allocate_producer_ids_response = parse_kafka_allocate_producer_ids_response(
        &kafka_allocate_producer_ids_response_frame(0, 0, 9_000_000, 1_000),
        0,
        &ProtocolExtractionConfig {
            max_header_bytes: 128,
            max_request_line_bytes: 64,
            max_attributes: 2,
            max_tracestate_bytes: 32,
        },
    )
    .expect("bounded kafka allocate producer ids response parses");
    assert_eq!(bounded_allocate_producer_ids_response.attributes.len(), 2);

    let bounded_consumer_group_heartbeat_response = parse_kafka_consumer_group_heartbeat_response(
        &kafka_consumer_group_heartbeat_response_frame(0, 0, None, None, None),
        1,
        &ProtocolExtractionConfig {
            max_header_bytes: 128,
            max_request_line_bytes: 64,
            max_attributes: 2,
            max_tracestate_bytes: 32,
        },
    )
    .expect("bounded kafka consumer group heartbeat response parses");
    assert_eq!(
        bounded_consumer_group_heartbeat_response.attributes.len(),
        2
    );

    let bounded_share_group_heartbeat_response = parse_kafka_share_group_heartbeat_response(
        &kafka_share_group_heartbeat_response_frame(0, 0, None, None, None),
        1,
        &ProtocolExtractionConfig {
            max_header_bytes: 128,
            max_request_line_bytes: 64,
            max_attributes: 2,
            max_tracestate_bytes: 32,
        },
    )
    .expect("bounded kafka share group heartbeat response parses");
    assert_eq!(bounded_share_group_heartbeat_response.attributes.len(), 2);

    let bounded_consumer_group_describe_response = parse_kafka_consumer_group_describe_response(
        &kafka_consumer_group_describe_response_frame(0, 1, &[]),
        1,
        &ProtocolExtractionConfig {
            max_header_bytes: 128,
            max_request_line_bytes: 64,
            max_attributes: 2,
            max_tracestate_bytes: 32,
        },
    )
    .expect("bounded kafka consumer group describe response parses");
    assert_eq!(bounded_consumer_group_describe_response.attributes.len(), 2);

    let bounded_controller_registration_response = parse_kafka_controller_registration_response(
        &kafka_controller_registration_response_frame(0, 0, None),
        0,
        &ProtocolExtractionConfig {
            max_header_bytes: 128,
            max_request_line_bytes: 64,
            max_attributes: 2,
            max_tracestate_bytes: 32,
        },
    )
    .expect("bounded kafka controller registration response parses");
    assert_eq!(bounded_controller_registration_response.attributes.len(), 2);

    let bounded_get_telemetry_subscriptions_response =
        parse_kafka_get_telemetry_subscriptions_response(
            &kafka_get_telemetry_subscriptions_response_frame(0, 0, [0_u8; 16], &[], &[]),
            0,
            &ProtocolExtractionConfig {
                max_header_bytes: 128,
                max_request_line_bytes: 64,
                max_attributes: 2,
                max_tracestate_bytes: 32,
            },
        )
        .expect("bounded kafka get telemetry subscriptions response parses");
    assert_eq!(
        bounded_get_telemetry_subscriptions_response
            .attributes
            .len(),
        2
    );

    let bounded_push_telemetry_response = parse_kafka_push_telemetry_response(
        &kafka_push_telemetry_response_frame(0, 0),
        0,
        &ProtocolExtractionConfig {
            max_header_bytes: 128,
            max_request_line_bytes: 64,
            max_attributes: 2,
            max_tracestate_bytes: 32,
        },
    )
    .expect("bounded kafka push telemetry response parses");
    assert_eq!(bounded_push_telemetry_response.attributes.len(), 2);

    let bounded_list_config_resources_response = parse_kafka_list_config_resources_response(
        &kafka_list_config_resources_response_frame(0, 1, 0, &[]),
        1,
        &ProtocolExtractionConfig {
            max_header_bytes: 128,
            max_request_line_bytes: 64,
            max_attributes: 2,
            max_tracestate_bytes: 32,
        },
    )
    .expect("bounded kafka list config resources response parses");
    assert_eq!(bounded_list_config_resources_response.attributes.len(), 2);

    let bounded_describe_topic_partitions_response =
        parse_kafka_describe_topic_partitions_response(
            &kafka_describe_topic_partitions_response_frame(0, &[], None),
            0,
            &ProtocolExtractionConfig {
                max_header_bytes: 128,
                max_request_line_bytes: 64,
                max_attributes: 2,
                max_tracestate_bytes: 32,
            },
        )
        .expect("bounded kafka describe topic partitions response parses");
    assert_eq!(
        bounded_describe_topic_partitions_response.attributes.len(),
        2
    );

    let bounded_add_raft_voter_response = parse_kafka_add_raft_voter_response(
        &kafka_add_raft_voter_response_frame(0, 0, None),
        0,
        &ProtocolExtractionConfig {
            max_header_bytes: 128,
            max_request_line_bytes: 64,
            max_attributes: 2,
            max_tracestate_bytes: 32,
        },
    )
    .expect("bounded kafka add raft voter response parses");
    assert_eq!(bounded_add_raft_voter_response.attributes.len(), 2);

    let bounded_remove_raft_voter_response = parse_kafka_remove_raft_voter_response(
        &kafka_remove_raft_voter_response_frame(0, 0, None),
        0,
        &ProtocolExtractionConfig {
            max_header_bytes: 128,
            max_request_line_bytes: 64,
            max_attributes: 2,
            max_tracestate_bytes: 32,
        },
    )
    .expect("bounded kafka remove raft voter response parses");
    assert_eq!(bounded_remove_raft_voter_response.attributes.len(), 2);

    let bounded_update_raft_voter_response = parse_kafka_update_raft_voter_response(
        &kafka_update_raft_voter_response_frame(0, 0, None),
        0,
        &ProtocolExtractionConfig {
            max_header_bytes: 128,
            max_request_line_bytes: 64,
            max_attributes: 2,
            max_tracestate_bytes: 32,
        },
    )
    .expect("bounded kafka update raft voter response parses");
    assert_eq!(bounded_update_raft_voter_response.attributes.len(), 2);

    let bounded_initialize_share_group_state_response =
        parse_kafka_initialize_share_group_state_response(
            &kafka_initialize_share_group_state_response_frame(0, &[]),
            0,
            &ProtocolExtractionConfig {
                max_header_bytes: 128,
                max_request_line_bytes: 64,
                max_attributes: 2,
                max_tracestate_bytes: 32,
            },
        )
        .expect("bounded kafka initialize share group state response parses");
    assert_eq!(
        bounded_initialize_share_group_state_response
            .attributes
            .len(),
        2
    );

    let bounded_read_share_group_state_response = parse_kafka_read_share_group_state_response(
        &kafka_read_share_group_state_response_frame(0, &[]),
        0,
        &ProtocolExtractionConfig {
            max_header_bytes: 128,
            max_request_line_bytes: 64,
            max_attributes: 2,
            max_tracestate_bytes: 32,
        },
    )
    .expect("bounded kafka read share group state response parses");
    assert_eq!(bounded_read_share_group_state_response.attributes.len(), 2);

    let bounded_write_share_group_state_response = parse_kafka_write_share_group_state_response(
        &kafka_write_share_group_state_response_frame(0, &[]),
        1,
        &ProtocolExtractionConfig {
            max_header_bytes: 128,
            max_request_line_bytes: 64,
            max_attributes: 2,
            max_tracestate_bytes: 32,
        },
    )
    .expect("bounded kafka write share group state response parses");
    assert_eq!(bounded_write_share_group_state_response.attributes.len(), 2);

    let bounded_delete_share_group_state_response = parse_kafka_delete_share_group_state_response(
        &kafka_delete_share_group_state_response_frame(0, &[]),
        0,
        &ProtocolExtractionConfig {
            max_header_bytes: 128,
            max_request_line_bytes: 64,
            max_attributes: 2,
            max_tracestate_bytes: 32,
        },
    )
    .expect("bounded kafka delete share group state response parses");
    assert_eq!(
        bounded_delete_share_group_state_response.attributes.len(),
        2
    );

    let bounded_read_share_group_state_summary_response =
        parse_kafka_read_share_group_state_summary_response(
            &kafka_read_share_group_state_summary_response_frame(0, &[], 1),
            1,
            &ProtocolExtractionConfig {
                max_header_bytes: 128,
                max_request_line_bytes: 64,
                max_attributes: 2,
                max_tracestate_bytes: 32,
            },
        )
        .expect("bounded kafka read share group state summary response parses");
    assert_eq!(
        bounded_read_share_group_state_summary_response
            .attributes
            .len(),
        2
    );

    let bounded_delete_share_group_offsets_response =
        parse_kafka_delete_share_group_offsets_response(
            &kafka_delete_share_group_offsets_response_frame(0, 0, None, &[]),
            0,
            &ProtocolExtractionConfig {
                max_header_bytes: 128,
                max_request_line_bytes: 64,
                max_attributes: 2,
                max_tracestate_bytes: 32,
            },
        )
        .expect("bounded kafka delete share group offsets response parses");
    assert_eq!(
        bounded_delete_share_group_offsets_response.attributes.len(),
        2
    );

    let bounded_describe_share_group_offsets_response =
        parse_kafka_describe_share_group_offsets_response(
            &kafka_describe_share_group_offsets_response_frame(0, 0, &[]),
            0,
            &ProtocolExtractionConfig {
                max_header_bytes: 128,
                max_request_line_bytes: 64,
                max_attributes: 2,
                max_tracestate_bytes: 32,
            },
        )
        .expect("bounded kafka describe share group offsets response parses");
    assert_eq!(
        bounded_describe_share_group_offsets_response
            .attributes
            .len(),
        2
    );

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

    let bounded_offset_commit_response = parse_kafka_offset_commit_response(
        &kafka_offset_commit_response_frame(0, 3, &[("orders.secret", 25)]),
        3,
        &ProtocolExtractionConfig {
            max_header_bytes: 128,
            max_request_line_bytes: 64,
            max_attributes: 2,
            max_tracestate_bytes: 32,
        },
    )
    .expect("bounded kafka offset commit response parses");
    assert_eq!(bounded_offset_commit_response.attributes.len(), 2);

    let bounded_offset_fetch_response = parse_kafka_offset_fetch_response(
        &kafka_offset_fetch_response_frame(0, 3, 25, &[("orders.secret", 0)]),
        3,
        &ProtocolExtractionConfig {
            max_header_bytes: 128,
            max_request_line_bytes: 64,
            max_attributes: 2,
            max_tracestate_bytes: 32,
        },
    )
    .expect("bounded kafka offset fetch response parses");
    assert_eq!(bounded_offset_fetch_response.attributes.len(), 2);

    let bounded_offset_delete_response = parse_kafka_offset_delete_response(
        &kafka_offset_delete_response_frame(0, 30, &[("orders.secret", 0)]),
        0,
        &ProtocolExtractionConfig {
            max_header_bytes: 128,
            max_request_line_bytes: 64,
            max_attributes: 2,
            max_tracestate_bytes: 32,
        },
    )
    .expect("bounded kafka offset delete response parses");
    assert_eq!(bounded_offset_delete_response.attributes.len(), 2);

    let bounded_list_offsets_response = parse_kafka_list_offsets_response(
        &kafka_list_offsets_response_frame(0, 1, &[("orders.secret", 6)]),
        1,
        &ProtocolExtractionConfig {
            max_header_bytes: 128,
            max_request_line_bytes: 64,
            max_attributes: 2,
            max_tracestate_bytes: 32,
        },
    )
    .expect("bounded kafka list offsets response parses");
    assert_eq!(bounded_list_offsets_response.attributes.len(), 2);

    let bounded_delete_records_response = parse_kafka_delete_records_response(
        &kafka_delete_records_response_frame(0, &[("orders.secret", 6)]),
        1,
        &ProtocolExtractionConfig {
            max_header_bytes: 128,
            max_request_line_bytes: 64,
            max_attributes: 2,
            max_tracestate_bytes: 32,
        },
    )
    .expect("bounded kafka delete records response parses");
    assert_eq!(bounded_delete_records_response.attributes.len(), 2);

    let bounded_delete_topics_response = parse_kafka_delete_topics_response(
        &kafka_delete_topics_response_frame(0, &[("orders.secret", 6)]),
        1,
        &ProtocolExtractionConfig {
            max_header_bytes: 128,
            max_request_line_bytes: 64,
            max_attributes: 2,
            max_tracestate_bytes: 32,
        },
    )
    .expect("bounded kafka delete topics response parses");
    assert_eq!(bounded_delete_topics_response.attributes.len(), 2);

    let bounded_create_topics_response = parse_kafka_create_topics_response(
        &kafka_create_topics_response_frame(0, &[("orders.secret", 36, Some("secret"))]),
        2,
        &ProtocolExtractionConfig {
            max_header_bytes: 128,
            max_request_line_bytes: 64,
            max_attributes: 2,
            max_tracestate_bytes: 32,
        },
    )
    .expect("bounded kafka create topics response parses");
    assert_eq!(bounded_create_topics_response.attributes.len(), 2);

    let bounded_create_partitions_response = parse_kafka_create_partitions_response(
        &kafka_create_partitions_response_frame(0, &[("orders.secret", 37, Some("secret"))]),
        0,
        &ProtocolExtractionConfig {
            max_header_bytes: 128,
            max_request_line_bytes: 64,
            max_attributes: 2,
            max_tracestate_bytes: 32,
        },
    )
    .expect("bounded kafka create partitions response parses");
    assert_eq!(bounded_create_partitions_response.attributes.len(), 2);

    let bounded_create_acls_response = parse_kafka_create_acls_response(
        &kafka_create_acls_response_frame(0, &[(31, Some("secret acl rejected"))]),
        1,
        &ProtocolExtractionConfig {
            max_header_bytes: 128,
            max_request_line_bytes: 64,
            max_attributes: 2,
            max_tracestate_bytes: 32,
        },
    )
    .expect("bounded kafka create acls response parses");
    assert_eq!(bounded_create_acls_response.attributes.len(), 2);

    let bounded_describe_acls_response = parse_kafka_describe_acls_response(
        &kafka_describe_acls_response_frame(
            0,
            31,
            Some("secret acl rejected"),
            &[("orders.secret", &[("User:secret", "host.secret")])],
        ),
        1,
        &ProtocolExtractionConfig {
            max_header_bytes: 256,
            max_request_line_bytes: 64,
            max_attributes: 2,
            max_tracestate_bytes: 32,
        },
    )
    .expect("bounded kafka describe acls response parses");
    assert_eq!(bounded_describe_acls_response.attributes.len(), 2);

    let bounded_delete_acls_response = parse_kafka_delete_acls_response(
        &kafka_delete_acls_response_frame(
            0,
            &[(
                31,
                Some("secret acl rejected"),
                &[(
                    30,
                    Some("matching secret"),
                    "orders.secret",
                    "User:secret",
                    "host.secret",
                )],
            )],
        ),
        1,
        &ProtocolExtractionConfig {
            max_header_bytes: 256,
            max_request_line_bytes: 64,
            max_attributes: 2,
            max_tracestate_bytes: 32,
        },
    )
    .expect("bounded kafka delete acls response parses");
    assert_eq!(bounded_delete_acls_response.attributes.len(), 2);

    let bounded_describe_configs_response = parse_kafka_describe_configs_response(
        &kafka_describe_configs_response_frame(
            0,
            1,
            &[(35, Some("secret rejected"), "orders.secret", &[])],
        ),
        1,
        &ProtocolExtractionConfig {
            max_header_bytes: 256,
            max_request_line_bytes: 64,
            max_attributes: 2,
            max_tracestate_bytes: 32,
        },
    )
    .expect("bounded kafka describe configs response parses");
    assert_eq!(bounded_describe_configs_response.attributes.len(), 2);

    let bounded_alter_configs_response = parse_kafka_alter_configs_response(
        &kafka_alter_configs_response_frame(0, &[(35, Some("secret rejected"), "orders.secret")]),
        1,
        &ProtocolExtractionConfig {
            max_header_bytes: 128,
            max_request_line_bytes: 64,
            max_attributes: 2,
            max_tracestate_bytes: 32,
        },
    )
    .expect("bounded kafka alter configs response parses");
    assert_eq!(bounded_alter_configs_response.attributes.len(), 2);

    let bounded_alter_replica_log_dirs_response = parse_kafka_alter_replica_log_dirs_response(
        &kafka_alter_replica_log_dirs_response_frame(0, &[("orders.secret", &[(0, 35)])]),
        1,
        &ProtocolExtractionConfig {
            max_header_bytes: 128,
            max_request_line_bytes: 64,
            max_attributes: 2,
            max_tracestate_bytes: 32,
        },
    )
    .expect("bounded kafka alter replica log dirs response parses");
    assert_eq!(bounded_alter_replica_log_dirs_response.attributes.len(), 2);

    let bounded_describe_log_dirs_response = parse_kafka_describe_log_dirs_response(
        &kafka_describe_log_dirs_response_frame(
            0,
            &[(35, "/var/lib/kafka/secret-dir", &[("orders.secret", &[0])])],
        ),
        1,
        &ProtocolExtractionConfig {
            max_header_bytes: 128,
            max_request_line_bytes: 64,
            max_attributes: 2,
            max_tracestate_bytes: 32,
        },
    )
    .expect("bounded kafka describe log dirs response parses");
    assert_eq!(bounded_describe_log_dirs_response.attributes.len(), 2);

    let bounded_create_delegation_token_response = parse_kafka_create_delegation_token_response(
        &kafka_create_delegation_token_response_frame(
            0,
            35,
            "User",
            "alice.secret",
            "token.secret.id",
            b"hmac-secret",
        ),
        1,
        &ProtocolExtractionConfig {
            max_header_bytes: 128,
            max_request_line_bytes: 64,
            max_attributes: 2,
            max_tracestate_bytes: 32,
        },
    )
    .expect("bounded kafka create delegation token response parses");
    assert_eq!(bounded_create_delegation_token_response.attributes.len(), 2);

    let bounded_renew_delegation_token_response = parse_kafka_renew_delegation_token_response(
        &kafka_renew_delegation_token_response_frame(0, 35),
        1,
        &ProtocolExtractionConfig {
            max_header_bytes: 128,
            max_request_line_bytes: 64,
            max_attributes: 2,
            max_tracestate_bytes: 32,
        },
    )
    .expect("bounded kafka renew delegation token response parses");
    assert_eq!(bounded_renew_delegation_token_response.attributes.len(), 2);

    let bounded_expire_delegation_token_response = parse_kafka_expire_delegation_token_response(
        &kafka_expire_delegation_token_response_frame(0, 35),
        1,
        &ProtocolExtractionConfig {
            max_header_bytes: 128,
            max_request_line_bytes: 64,
            max_attributes: 2,
            max_tracestate_bytes: 32,
        },
    )
    .expect("bounded kafka expire delegation token response parses");
    assert_eq!(bounded_expire_delegation_token_response.attributes.len(), 2);

    let bounded_describe_delegation_token_response =
        parse_kafka_describe_delegation_token_response(
            &kafka_describe_delegation_token_response_frame(
                0,
                35,
                &[DescribeDelegationTokenFixture {
                    principal_type: "User",
                    principal_name: "alice.secret",
                    token_id: "token.secret.id",
                    hmac: b"hmac-secret",
                    renewers: &[("User", "bob.secret")],
                }],
            ),
            1,
            &ProtocolExtractionConfig {
                max_header_bytes: 256,
                max_request_line_bytes: 64,
                max_attributes: 2,
                max_tracestate_bytes: 32,
            },
        )
        .expect("bounded kafka describe delegation token response parses");
    assert_eq!(
        bounded_describe_delegation_token_response.attributes.len(),
        2
    );

    let bounded_join_group_response = parse_kafka_join_group_response(
        &kafka_join_group_response_frame(0, 2, 25, &[("member.secret", b"secret-metadata")]),
        2,
        &ProtocolExtractionConfig {
            max_header_bytes: 128,
            max_request_line_bytes: 64,
            max_attributes: 2,
            max_tracestate_bytes: 32,
        },
    )
    .expect("bounded kafka join group response parses");
    assert_eq!(bounded_join_group_response.attributes.len(), 2);

    let bounded_find_coordinator_response = parse_kafka_find_coordinator_response(
        &kafka_find_coordinator_response_frame(0, 1, 15, Some("coordinator.secret")),
        1,
        &ProtocolExtractionConfig {
            max_header_bytes: 128,
            max_request_line_bytes: 64,
            max_attributes: 2,
            max_tracestate_bytes: 32,
        },
    )
    .expect("bounded kafka find coordinator response parses");
    assert_eq!(bounded_find_coordinator_response.attributes.len(), 2);

    let bounded_heartbeat_response = parse_kafka_heartbeat_response(
        &kafka_heartbeat_response_frame(0, 1, 27),
        1,
        &ProtocolExtractionConfig {
            max_header_bytes: 128,
            max_request_line_bytes: 64,
            max_attributes: 2,
            max_tracestate_bytes: 32,
        },
    )
    .expect("bounded kafka heartbeat response parses");
    assert_eq!(bounded_heartbeat_response.attributes.len(), 2);

    let bounded_leave_group_response = parse_kafka_leave_group_response(
        &kafka_leave_group_response_frame(0, 1, 25, &[]),
        1,
        &ProtocolExtractionConfig {
            max_header_bytes: 128,
            max_request_line_bytes: 64,
            max_attributes: 2,
            max_tracestate_bytes: 32,
        },
    )
    .expect("bounded kafka leave group response parses");
    assert_eq!(bounded_leave_group_response.attributes.len(), 2);

    let bounded_sync_group_response = parse_kafka_sync_group_response(
        &kafka_sync_group_response_frame(0, 1, 25, b"secret-assignment"),
        1,
        &ProtocolExtractionConfig {
            max_header_bytes: 128,
            max_request_line_bytes: 64,
            max_attributes: 2,
            max_tracestate_bytes: 32,
        },
    )
    .expect("bounded kafka sync group response parses");
    assert_eq!(bounded_sync_group_response.attributes.len(), 2);

    let bounded_describe_groups_response = parse_kafka_describe_groups_response(
        &kafka_describe_groups_response_frame(0, 1, &[("group.secret", 30, 0)]),
        1,
        &ProtocolExtractionConfig {
            max_header_bytes: 256,
            max_request_line_bytes: 64,
            max_attributes: 2,
            max_tracestate_bytes: 32,
        },
    )
    .expect("bounded kafka describe groups response parses");
    assert_eq!(bounded_describe_groups_response.attributes.len(), 2);

    let bounded_list_groups_response = parse_kafka_list_groups_response(
        &kafka_list_groups_response_frame(0, 1, 30, &[("group.secret", "consumer")]),
        1,
        &ProtocolExtractionConfig {
            max_header_bytes: 128,
            max_request_line_bytes: 64,
            max_attributes: 2,
            max_tracestate_bytes: 32,
        },
    )
    .expect("bounded kafka list groups response parses");
    assert_eq!(bounded_list_groups_response.attributes.len(), 2);

    let bounded_delete_groups_response = parse_kafka_delete_groups_response(
        &kafka_delete_groups_response_frame(0, &[("group.secret", 30)]),
        1,
        &ProtocolExtractionConfig {
            max_header_bytes: 128,
            max_request_line_bytes: 64,
            max_attributes: 2,
            max_tracestate_bytes: 32,
        },
    )
    .expect("bounded kafka delete groups response parses");
    assert_eq!(bounded_delete_groups_response.attributes.len(), 2);

    let bounded_elect_leaders_response = parse_kafka_elect_leaders_response(
        &kafka_elect_leaders_response_frame(
            0,
            1,
            0,
            &[("orders.secret", &[(0, 35, Some("leader secret denied"))])],
        ),
        1,
        &ProtocolExtractionConfig {
            max_header_bytes: 128,
            max_request_line_bytes: 64,
            max_attributes: 2,
            max_tracestate_bytes: 32,
        },
    )
    .expect("bounded kafka elect leaders response parses");
    assert_eq!(bounded_elect_leaders_response.attributes.len(), 2);

    let bounded_incremental_alter_configs_response =
        parse_kafka_incremental_alter_configs_response(
            &kafka_incremental_alter_configs_response_frame(
                0,
                1,
                &[(40, Some("config secret denied"), 2, "orders.secret")],
            ),
            1,
            &ProtocolExtractionConfig {
                max_header_bytes: 128,
                max_request_line_bytes: 64,
                max_attributes: 2,
                max_tracestate_bytes: 32,
            },
        )
        .expect("bounded kafka incremental alter configs response parses");
    assert_eq!(
        bounded_incremental_alter_configs_response.attributes.len(),
        2
    );

    let bounded_alter_partition_reassignments_response =
        parse_kafka_alter_partition_reassignments_response(
            &kafka_alter_partition_reassignments_response_frame(
                0,
                1,
                0,
                None,
                &[("orders.secret", &[(0, 35, Some("partition secret denied"))])],
            ),
            1,
            &ProtocolExtractionConfig {
                max_header_bytes: 128,
                max_request_line_bytes: 64,
                max_attributes: 2,
                max_tracestate_bytes: 32,
            },
        )
        .expect("bounded kafka alter partition reassignments response parses");
    assert_eq!(
        bounded_alter_partition_reassignments_response
            .attributes
            .len(),
        2
    );

    let bounded_list_partition_reassignments_response =
        parse_kafka_list_partition_reassignments_response(
            &kafka_list_partition_reassignments_response_frame(
                0,
                0,
                None,
                &[("orders.secret", &[(0, &[1, 2], &[3], &[4])])],
            ),
            0,
            &ProtocolExtractionConfig {
                max_header_bytes: 128,
                max_request_line_bytes: 64,
                max_attributes: 2,
                max_tracestate_bytes: 32,
            },
        )
        .expect("bounded kafka list partition reassignments response parses");
    assert_eq!(
        bounded_list_partition_reassignments_response
            .attributes
            .len(),
        2
    );

    let bounded_describe_client_quotas_response = parse_kafka_describe_client_quotas_response(
        &kafka_describe_client_quotas_response_frame(
            0,
            1,
            31,
            Some("top secret denied"),
            Some(&[(
                &[("client-id", Some("secret-client-a"))],
                &[("producer_byte_rate.secret", 42.0)],
            )]),
        ),
        1,
        &ProtocolExtractionConfig {
            max_header_bytes: 128,
            max_request_line_bytes: 64,
            max_attributes: 2,
            max_tracestate_bytes: 32,
        },
    )
    .expect("bounded kafka describe client quotas response parses");
    assert_eq!(bounded_describe_client_quotas_response.attributes.len(), 2);

    let bounded_alter_client_quotas_response = parse_kafka_alter_client_quotas_response(
        &kafka_alter_client_quotas_response_frame(
            0,
            1,
            &[(
                31,
                Some("top secret denied"),
                &[("client-id", Some("secret-client-a"))],
            )],
        ),
        1,
        &ProtocolExtractionConfig {
            max_header_bytes: 128,
            max_request_line_bytes: 64,
            max_attributes: 2,
            max_tracestate_bytes: 32,
        },
    )
    .expect("bounded kafka alter client quotas response parses");
    assert_eq!(bounded_alter_client_quotas_response.attributes.len(), 2);

    let bounded_describe_user_scram_credentials_response =
        parse_kafka_describe_user_scram_credentials_response(
            &kafka_describe_user_scram_credentials_response_frame(
                0,
                0,
                None,
                &[("alice.secret", 51, Some("user secret denied"), &[])],
            ),
            0,
            &ProtocolExtractionConfig {
                max_header_bytes: 128,
                max_request_line_bytes: 64,
                max_attributes: 2,
                max_tracestate_bytes: 32,
            },
        )
        .expect("bounded kafka describe user scram credentials response parses");
    assert_eq!(
        bounded_describe_user_scram_credentials_response
            .attributes
            .len(),
        2
    );

    let bounded_alter_user_scram_credentials_response =
        parse_kafka_alter_user_scram_credentials_response(
            &kafka_alter_user_scram_credentials_response_frame(
                0,
                &[("alice.secret", 51, Some("user secret denied"))],
            ),
            0,
            &ProtocolExtractionConfig {
                max_header_bytes: 128,
                max_request_line_bytes: 64,
                max_attributes: 2,
                max_tracestate_bytes: 32,
            },
        )
        .expect("bounded kafka alter user scram credentials response parses");
    assert_eq!(
        bounded_alter_user_scram_credentials_response
            .attributes
            .len(),
        2
    );

    let bounded_sasl_handshake_response = parse_kafka_sasl_handshake_response(
        &kafka_sasl_handshake_response_frame(0, 33, &["PLAIN.secret"]),
        1,
        &ProtocolExtractionConfig {
            max_header_bytes: 128,
            max_request_line_bytes: 64,
            max_attributes: 2,
            max_tracestate_bytes: 32,
        },
    )
    .expect("bounded kafka sasl handshake response parses");
    assert_eq!(bounded_sasl_handshake_response.attributes.len(), 2);

    let bounded_init_producer_id_response = parse_kafka_init_producer_id_response(
        &kafka_init_producer_id_response_frame(0, 1, 49),
        1,
        &ProtocolExtractionConfig {
            max_header_bytes: 128,
            max_request_line_bytes: 64,
            max_attributes: 2,
            max_tracestate_bytes: 32,
        },
    )
    .expect("bounded kafka init producer id response parses");
    assert_eq!(bounded_init_producer_id_response.attributes.len(), 2);

    let bounded_add_partitions_to_txn_response = parse_kafka_add_partitions_to_txn_response(
        &kafka_add_partitions_to_txn_response_frame(0, &[("orders.secret", 53)]),
        1,
        &ProtocolExtractionConfig {
            max_header_bytes: 128,
            max_request_line_bytes: 64,
            max_attributes: 2,
            max_tracestate_bytes: 32,
        },
    )
    .expect("bounded kafka add partitions to txn response parses");
    assert_eq!(bounded_add_partitions_to_txn_response.attributes.len(), 2);

    let bounded_add_offsets_to_txn_response = parse_kafka_add_offsets_to_txn_response(
        &kafka_throttled_error_response_frame(0, 49),
        1,
        &ProtocolExtractionConfig {
            max_header_bytes: 128,
            max_request_line_bytes: 64,
            max_attributes: 2,
            max_tracestate_bytes: 32,
        },
    )
    .expect("bounded kafka add offsets to txn response parses");
    assert_eq!(bounded_add_offsets_to_txn_response.attributes.len(), 2);

    let bounded_end_txn_response = parse_kafka_end_txn_response(
        &kafka_throttled_error_response_frame(0, 48),
        1,
        &ProtocolExtractionConfig {
            max_header_bytes: 128,
            max_request_line_bytes: 64,
            max_attributes: 2,
            max_tracestate_bytes: 32,
        },
    )
    .expect("bounded kafka end txn response parses");
    assert_eq!(bounded_end_txn_response.attributes.len(), 2);

    let bounded_write_txn_markers_response = parse_kafka_write_txn_markers_response(
        &kafka_write_txn_markers_response_frame(&[("orders.secret", &[(0, 48)])]),
        1,
        &ProtocolExtractionConfig {
            max_header_bytes: 128,
            max_request_line_bytes: 64,
            max_attributes: 2,
            max_tracestate_bytes: 32,
        },
    )
    .expect("bounded kafka write txn markers response parses");
    assert_eq!(bounded_write_txn_markers_response.attributes.len(), 2);

    let bounded_txn_offset_commit_response = parse_kafka_txn_offset_commit_response(
        &kafka_txn_offset_commit_response_frame(0, &[("orders.secret", &[(0, 27)])]),
        1,
        &ProtocolExtractionConfig {
            max_header_bytes: 128,
            max_request_line_bytes: 64,
            max_attributes: 2,
            max_tracestate_bytes: 32,
        },
    )
    .expect("bounded kafka txn offset commit response parses");
    assert_eq!(bounded_txn_offset_commit_response.attributes.len(), 2);

    let bounded_sasl_authenticate_response = parse_kafka_sasl_authenticate_response(
        &kafka_sasl_authenticate_response_frame(0, 1, 58, Some("secret"), b"secret-auth"),
        1,
        &ProtocolExtractionConfig {
            max_header_bytes: 128,
            max_request_line_bytes: 64,
            max_attributes: 2,
            max_tracestate_bytes: 32,
        },
    )
    .expect("bounded kafka sasl authenticate response parses");
    assert_eq!(bounded_sasl_authenticate_response.attributes.len(), 2);

    let bounded_metadata_response = parse_kafka_metadata_response(
        &kafka_metadata_response_frame(0, 1, &[("orders.secret", 6, 0)]),
        1,
        &ProtocolExtractionConfig {
            max_header_bytes: 256,
            max_request_line_bytes: 64,
            max_attributes: 2,
            max_tracestate_bytes: 32,
        },
    )
    .expect("bounded kafka metadata response parses");
    assert_eq!(bounded_metadata_response.attributes.len(), 2);

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
    assert_eq!(
        parse_kafka_offset_commit_response(
            &kafka_offset_commit_response_frame(0, 3, &[("orders.secret", 25)]),
            3,
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
        parse_kafka_list_offsets_response(
            &kafka_list_offsets_response_frame(0, 1, &[("orders.secret", 6)]),
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
        parse_kafka_delete_records_response(
            &kafka_delete_records_response_frame(0, &[("orders.secret", 6)]),
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
        parse_kafka_find_coordinator_response(
            &kafka_find_coordinator_response_frame(0, 1, 15, Some("coordinator.secret")),
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
        parse_kafka_heartbeat_response(
            &kafka_heartbeat_response_frame(0, 1, 27),
            1,
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
        parse_kafka_leave_group_response(
            &kafka_leave_group_response_frame(0, 1, 25, &[]),
            1,
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
        parse_kafka_sync_group_response(
            &kafka_sync_group_response_frame(0, 1, 25, b"secret-assignment"),
            1,
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
        parse_kafka_describe_groups_response(
            &kafka_describe_groups_response_frame(0, 1, &[("group.secret", 30, 0)]),
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
        parse_kafka_list_groups_response(
            &kafka_list_groups_response_frame(0, 1, 30, &[("group.secret", "consumer")]),
            1,
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
        parse_kafka_delete_groups_response(
            &kafka_delete_groups_response_frame(0, &[("group.secret", 30)]),
            1,
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
        parse_kafka_init_producer_id_response(
            &kafka_init_producer_id_response_frame(0, 1, 49),
            1,
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
        parse_kafka_add_partitions_to_txn_response(
            &kafka_add_partitions_to_txn_response_frame(0, &[("orders.secret", 53)]),
            1,
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
        parse_kafka_add_offsets_to_txn_response(
            &kafka_throttled_error_response_frame(0, 49),
            1,
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
        parse_kafka_end_txn_response(
            &kafka_throttled_error_response_frame(0, 48),
            1,
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
        parse_kafka_metadata_response(
            &kafka_metadata_response_frame(0, 1, &[("orders.secret", 6, 0)]),
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
