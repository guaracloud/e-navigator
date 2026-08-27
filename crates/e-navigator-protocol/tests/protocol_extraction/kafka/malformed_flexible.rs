use super::*;

#[test]
fn rejects_malformed_flexible_kafka_requests() {
    let config = ProtocolExtractionConfig::default();

    let mut truncated = kafka_request_frame(3, 9, Some(b"client-a"), b"");
    truncated.truncate(8);
    assert_eq!(
        parse_kafka_request(&truncated, &config).unwrap_err(),
        KafkaExtraction::MalformedFrame
    );

    let mut elect_leaders_unsupported_body = Vec::new();
    elect_leaders_unsupported_body.extend_from_slice(&(-1_i32).to_be_bytes());
    elect_leaders_unsupported_body.extend_from_slice(&60_000_i32.to_be_bytes());
    assert_eq!(
        parse_kafka_request(
            &kafka_request_frame(43, 2, Some(b"client-a"), &elect_leaders_unsupported_body),
            &config
        )
        .unwrap_err(),
        KafkaExtraction::UnsupportedApiVersion
    );

    let mut oversized_elect_leaders_body = Vec::new();
    oversized_elect_leaders_body.extend_from_slice(&1025_i32.to_be_bytes());
    assert_eq!(
        parse_kafka_request(
            &kafka_request_frame(43, 0, Some(b"client-a"), &oversized_elect_leaders_body),
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );

    let elect_leaders_long_topic_body =
        kafka_elect_leaders_request_body(0, Some(&[("orders.secret", &[0])]));
    assert_eq!(
        parse_kafka_request(
            &kafka_request_frame(43, 0, Some(b"client-a"), &elect_leaders_long_topic_body),
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

    let mut incremental_alter_configs_unsupported_body = Vec::new();
    incremental_alter_configs_unsupported_body.extend_from_slice(&0_i32.to_be_bytes());
    incremental_alter_configs_unsupported_body.push(1);
    assert_eq!(
        parse_kafka_request(
            &kafka_request_frame(
                44,
                2,
                Some(b"client-a"),
                &incremental_alter_configs_unsupported_body,
            ),
            &config
        )
        .unwrap_err(),
        KafkaExtraction::UnsupportedApiVersion
    );

    let mut oversized_incremental_alter_configs_body = Vec::new();
    oversized_incremental_alter_configs_body.extend_from_slice(&1025_i32.to_be_bytes());
    assert_eq!(
        parse_kafka_request(
            &kafka_request_frame(
                44,
                0,
                Some(b"client-a"),
                &oversized_incremental_alter_configs_body,
            ),
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );

    let incremental_configs: &[IncrementalAlterConfigFixture<'_>] =
        &[("retention.secret.ms", 0, Some("token-secret"))];
    let incremental_resources: &[IncrementalAlterConfigsResourceFixture<'_>] =
        &[(2, "orders.secret", incremental_configs)];
    let incremental_alter_configs_long_resource_body =
        kafka_incremental_alter_configs_request_body(1, incremental_resources);
    assert_eq!(
        parse_kafka_request(
            &kafka_flexible_request_frame(
                44,
                1,
                Some(b"client-a"),
                &incremental_alter_configs_long_resource_body,
            ),
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

    let mut alter_partition_reassignments_unsupported_body = Vec::new();
    alter_partition_reassignments_unsupported_body.extend_from_slice(&60_000_i32.to_be_bytes());
    push_unsigned_varint(&mut alter_partition_reassignments_unsupported_body, 1);
    push_unsigned_varint(&mut alter_partition_reassignments_unsupported_body, 0);
    assert_eq!(
        parse_kafka_request(
            &kafka_flexible_request_frame(
                45,
                2,
                Some(b"client-a"),
                &alter_partition_reassignments_unsupported_body,
            ),
            &config
        )
        .unwrap_err(),
        KafkaExtraction::UnsupportedApiVersion
    );

    let mut oversized_alter_partition_reassignments_body = Vec::new();
    oversized_alter_partition_reassignments_body.extend_from_slice(&60_000_i32.to_be_bytes());
    push_unsigned_varint(&mut oversized_alter_partition_reassignments_body, 1026);
    assert_eq!(
        parse_kafka_request(
            &kafka_flexible_request_frame(
                45,
                0,
                Some(b"client-a"),
                &oversized_alter_partition_reassignments_body,
            ),
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );

    let alter_reassignment_partitions: &[AlterPartitionReassignmentFixture<'_>] =
        &[(0, Some(&[1, 2]))];
    let alter_reassignment_topics: &[AlterPartitionReassignmentsTopicFixture<'_>] =
        &[("orders.secret", alter_reassignment_partitions)];
    let alter_partition_reassignments_long_topic_body =
        kafka_alter_partition_reassignments_request_body(0, alter_reassignment_topics);
    assert_eq!(
        parse_kafka_request(
            &kafka_flexible_request_frame(
                45,
                0,
                Some(b"client-a"),
                &alter_partition_reassignments_long_topic_body,
            ),
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

    let mut list_partition_reassignments_unsupported_body = Vec::new();
    list_partition_reassignments_unsupported_body.extend_from_slice(&60_000_i32.to_be_bytes());
    push_unsigned_varint(&mut list_partition_reassignments_unsupported_body, 0);
    push_unsigned_varint(&mut list_partition_reassignments_unsupported_body, 0);
    assert_eq!(
        parse_kafka_request(
            &kafka_flexible_request_frame(
                46,
                1,
                Some(b"client-a"),
                &list_partition_reassignments_unsupported_body,
            ),
            &config
        )
        .unwrap_err(),
        KafkaExtraction::UnsupportedApiVersion
    );

    let mut oversized_list_partition_reassignments_body = Vec::new();
    oversized_list_partition_reassignments_body.extend_from_slice(&60_000_i32.to_be_bytes());
    push_unsigned_varint(&mut oversized_list_partition_reassignments_body, 1026);
    assert_eq!(
        parse_kafka_request(
            &kafka_flexible_request_frame(
                46,
                0,
                Some(b"client-a"),
                &oversized_list_partition_reassignments_body,
            ),
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );

    let list_reassignment_topics: &[ListPartitionReassignmentsRequestTopicFixture<'_>] =
        &[("orders.secret", &[0, 1])];
    let list_partition_reassignments_long_topic_body =
        kafka_list_partition_reassignments_request_body(Some(list_reassignment_topics));
    assert_eq!(
        parse_kafka_request(
            &kafka_flexible_request_frame(
                46,
                0,
                Some(b"client-a"),
                &list_partition_reassignments_long_topic_body,
            ),
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

    let mut describe_client_quotas_unsupported_body = Vec::new();
    describe_client_quotas_unsupported_body.extend_from_slice(&0_i32.to_be_bytes());
    describe_client_quotas_unsupported_body.push(1);
    assert_eq!(
        parse_kafka_request(
            &kafka_request_frame(
                48,
                2,
                Some(b"client-a"),
                &describe_client_quotas_unsupported_body,
            ),
            &config
        )
        .unwrap_err(),
        KafkaExtraction::UnsupportedApiVersion
    );

    let mut oversized_describe_client_quotas_body = Vec::new();
    oversized_describe_client_quotas_body.extend_from_slice(&1025_i32.to_be_bytes());
    assert_eq!(
        parse_kafka_request(
            &kafka_request_frame(
                48,
                0,
                Some(b"client-a"),
                &oversized_describe_client_quotas_body,
            ),
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );

    let describe_client_quotas_components: &[DescribeClientQuotasComponentFixture<'_>] =
        &[("client-id", 0, Some("secret-client-a"))];
    let describe_client_quotas_long_entity_body =
        kafka_describe_client_quotas_request_body(1, describe_client_quotas_components);
    assert_eq!(
        parse_kafka_request(
            &kafka_flexible_request_frame(
                48,
                1,
                Some(b"client-a"),
                &describe_client_quotas_long_entity_body,
            ),
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

    let mut alter_client_quotas_unsupported_body = Vec::new();
    alter_client_quotas_unsupported_body.extend_from_slice(&0_i32.to_be_bytes());
    alter_client_quotas_unsupported_body.push(1);
    assert_eq!(
        parse_kafka_request(
            &kafka_request_frame(
                49,
                2,
                Some(b"client-a"),
                &alter_client_quotas_unsupported_body
            ),
            &config
        )
        .unwrap_err(),
        KafkaExtraction::UnsupportedApiVersion
    );

    let mut oversized_alter_client_quotas_body = Vec::new();
    oversized_alter_client_quotas_body.extend_from_slice(&1025_i32.to_be_bytes());
    assert_eq!(
        parse_kafka_request(
            &kafka_request_frame(
                49,
                0,
                Some(b"client-a"),
                &oversized_alter_client_quotas_body
            ),
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );

    let alter_client_quotas_entities: &[ClientQuotaEntityFixture<'_>] =
        &[("client-id", Some("secret-client-a"))];
    let alter_client_quotas_ops: &[AlterClientQuotaOpFixture<'_>] =
        &[("producer_byte_rate.secret", 42.0, false)];
    let alter_client_quotas_entries: &[AlterClientQuotaEntryFixture<'_>] =
        &[(alter_client_quotas_entities, alter_client_quotas_ops)];
    let alter_client_quotas_long_entity_body =
        kafka_alter_client_quotas_request_body(1, alter_client_quotas_entries);
    assert_eq!(
        parse_kafka_request(
            &kafka_flexible_request_frame(
                49,
                1,
                Some(b"client-a"),
                &alter_client_quotas_long_entity_body,
            ),
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

    let mut describe_user_scram_credentials_unsupported_body = Vec::new();
    push_unsigned_varint(&mut describe_user_scram_credentials_unsupported_body, 0);
    push_unsigned_varint(&mut describe_user_scram_credentials_unsupported_body, 0);
    assert_eq!(
        parse_kafka_request(
            &kafka_flexible_request_frame(
                50,
                1,
                Some(b"client-a"),
                &describe_user_scram_credentials_unsupported_body,
            ),
            &config
        )
        .unwrap_err(),
        KafkaExtraction::UnsupportedApiVersion
    );

    let mut oversized_describe_user_scram_credentials_body = Vec::new();
    push_unsigned_varint(&mut oversized_describe_user_scram_credentials_body, 1026);
    assert_eq!(
        parse_kafka_request(
            &kafka_flexible_request_frame(
                50,
                0,
                Some(b"client-a"),
                &oversized_describe_user_scram_credentials_body,
            ),
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );

    let describe_user_scram_credentials_long_user_body =
        kafka_describe_user_scram_credentials_request_body(Some(&["alice.secret"]));
    assert_eq!(
        parse_kafka_request(
            &kafka_flexible_request_frame(
                50,
                0,
                Some(b"client-a"),
                &describe_user_scram_credentials_long_user_body,
            ),
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

    let mut alter_user_scram_credentials_unsupported_body = Vec::new();
    push_unsigned_varint(&mut alter_user_scram_credentials_unsupported_body, 1);
    push_unsigned_varint(&mut alter_user_scram_credentials_unsupported_body, 1);
    push_unsigned_varint(&mut alter_user_scram_credentials_unsupported_body, 0);
    assert_eq!(
        parse_kafka_request(
            &kafka_flexible_request_frame(
                51,
                1,
                Some(b"client-a"),
                &alter_user_scram_credentials_unsupported_body,
            ),
            &config
        )
        .unwrap_err(),
        KafkaExtraction::UnsupportedApiVersion
    );

    let mut oversized_alter_user_scram_credentials_deletions_body = Vec::new();
    push_unsigned_varint(
        &mut oversized_alter_user_scram_credentials_deletions_body,
        1026,
    );
    assert_eq!(
        parse_kafka_request(
            &kafka_flexible_request_frame(
                51,
                0,
                Some(b"client-a"),
                &oversized_alter_user_scram_credentials_deletions_body,
            ),
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );

    let alter_user_scram_credentials_long_user_body =
        kafka_alter_user_scram_credentials_request_body(&[("alice.secret", 0)], &[]);
    assert_eq!(
        parse_kafka_request(
            &kafka_flexible_request_frame(
                51,
                0,
                Some(b"client-a"),
                &alter_user_scram_credentials_long_user_body,
            ),
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

    let alter_user_scram_credentials_large_secret_body =
        kafka_alter_user_scram_credentials_request_body(
            &[],
            &[("alice", 1, 4096, &[0_u8; 129], b"password")],
        );
    assert_eq!(
        parse_kafka_request(
            &kafka_flexible_request_frame(
                51,
                0,
                Some(b"client-a"),
                &alter_user_scram_credentials_large_secret_body,
            ),
            &ProtocolExtractionConfig {
                max_header_bytes: 128,
                max_request_line_bytes: 64,
                max_attributes: 4,
                max_tracestate_bytes: 32,
            },
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );

    let describe_quorum_body = kafka_describe_quorum_request_body(&[]);
    assert_eq!(
        parse_kafka_request(
            &kafka_flexible_request_frame(55, 3, Some(b"client-a"), &describe_quorum_body),
            &config
        )
        .unwrap_err(),
        KafkaExtraction::UnsupportedApiVersion
    );

    let mut oversized_describe_quorum_topics_body = Vec::new();
    push_unsigned_varint(&mut oversized_describe_quorum_topics_body, 1026);
    assert_eq!(
        parse_kafka_request(
            &kafka_flexible_request_frame(
                55,
                2,
                Some(b"client-a"),
                &oversized_describe_quorum_topics_body,
            ),
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );

    let mut oversized_describe_quorum_partitions_body = Vec::new();
    push_unsigned_varint(&mut oversized_describe_quorum_partitions_body, 2);
    push_compact_string(&mut oversized_describe_quorum_partitions_body, "orders");
    push_unsigned_varint(&mut oversized_describe_quorum_partitions_body, 1026);
    assert_eq!(
        parse_kafka_request(
            &kafka_flexible_request_frame(
                55,
                2,
                Some(b"client-a"),
                &oversized_describe_quorum_partitions_body,
            ),
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );

    let describe_quorum_long_topic_body =
        kafka_describe_quorum_request_body(&[("orders.secret", &[0])]);
    assert_eq!(
        parse_kafka_request(
            &kafka_flexible_request_frame(
                55,
                2,
                Some(b"client-a"),
                &describe_quorum_long_topic_body,
            ),
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

    let update_features_unsupported_body =
        kafka_update_features_request_body(2, &[("metadata.version", 1, 1)], true);
    assert_eq!(
        parse_kafka_request(
            &kafka_flexible_request_frame(
                57,
                3,
                Some(b"client-a"),
                &update_features_unsupported_body,
            ),
            &config
        )
        .unwrap_err(),
        KafkaExtraction::UnsupportedApiVersion
    );

    let mut oversized_update_features_body = Vec::new();
    oversized_update_features_body.extend_from_slice(&60_000_i32.to_be_bytes());
    push_unsigned_varint(&mut oversized_update_features_body, 1026);
    assert_eq!(
        parse_kafka_request(
            &kafka_flexible_request_frame(
                57,
                2,
                Some(b"client-a"),
                &oversized_update_features_body,
            ),
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );

    let update_features_long_feature_body =
        kafka_update_features_request_body(2, &[("metadata.version.secret", 1, 1)], true);
    assert_eq!(
        parse_kafka_request(
            &kafka_flexible_request_frame(
                57,
                2,
                Some(b"client-a"),
                &update_features_long_feature_body,
            ),
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

    let describe_cluster_body = kafka_describe_cluster_request_body(2);
    assert_eq!(
        parse_kafka_request(
            &kafka_flexible_request_frame(60, 3, Some(b"client-a"), &describe_cluster_body),
            &config
        )
        .unwrap_err(),
        KafkaExtraction::UnsupportedApiVersion
    );
    assert_eq!(
        parse_kafka_request(
            &kafka_flexible_request_frame(60, 2, Some(b"client-a"), b"\x01\x02\x01\x01"),
            &config
        )
        .unwrap_err(),
        KafkaExtraction::MalformedFrame
    );

    let describe_producers_body =
        kafka_describe_producers_request_body(&[("orders.secret", &[0, 1])]);
    assert_eq!(
        parse_kafka_request(
            &kafka_flexible_request_frame(61, 1, Some(b"client-a"), &describe_producers_body),
            &config
        )
        .unwrap_err(),
        KafkaExtraction::UnsupportedApiVersion
    );

    let mut oversized_describe_producers_topics_body = Vec::new();
    push_unsigned_varint(&mut oversized_describe_producers_topics_body, 1026);
    assert_eq!(
        parse_kafka_request(
            &kafka_flexible_request_frame(
                61,
                0,
                Some(b"client-a"),
                &oversized_describe_producers_topics_body,
            ),
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );

    let mut oversized_describe_producers_partitions_body = Vec::new();
    push_unsigned_varint(&mut oversized_describe_producers_partitions_body, 2);
    push_compact_string(&mut oversized_describe_producers_partitions_body, "orders");
    push_unsigned_varint(&mut oversized_describe_producers_partitions_body, 1026);
    assert_eq!(
        parse_kafka_request(
            &kafka_flexible_request_frame(
                61,
                0,
                Some(b"client-a"),
                &oversized_describe_producers_partitions_body,
            ),
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );

    let describe_producers_long_topic_body =
        kafka_describe_producers_request_body(&[("orders.secret", &[0])]);
    assert_eq!(
        parse_kafka_request(
            &kafka_flexible_request_frame(
                61,
                0,
                Some(b"client-a"),
                &describe_producers_long_topic_body,
            ),
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

    let unregister_broker_body = kafka_unregister_broker_request_body(42);
    assert_eq!(
        parse_kafka_request(
            &kafka_flexible_request_frame(64, 1, Some(b"client-a"), &unregister_broker_body),
            &config
        )
        .unwrap_err(),
        KafkaExtraction::UnsupportedApiVersion
    );
    assert_eq!(
        parse_kafka_request(
            &kafka_flexible_request_frame(64, 0, Some(b"client-a"), b"\0\0"),
            &config
        )
        .unwrap_err(),
        KafkaExtraction::MalformedFrame
    );
    assert_eq!(
        parse_kafka_request(
            &kafka_flexible_request_frame(64, 0, Some(b"client-a"), b"\0\0\0*\0\0"),
            &config
        )
        .unwrap_err(),
        KafkaExtraction::MalformedFrame
    );

    let describe_transactions_body =
        kafka_describe_transactions_request_body(&["txn.secret", "payments.secret"]);
    assert_eq!(
        parse_kafka_request(
            &kafka_flexible_request_frame(65, 1, Some(b"client-a"), &describe_transactions_body),
            &config
        )
        .unwrap_err(),
        KafkaExtraction::UnsupportedApiVersion
    );

    let mut oversized_describe_transactions_body = Vec::new();
    push_unsigned_varint(&mut oversized_describe_transactions_body, 1026);
    assert_eq!(
        parse_kafka_request(
            &kafka_flexible_request_frame(
                65,
                0,
                Some(b"client-a"),
                &oversized_describe_transactions_body,
            ),
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );

    let describe_transactions_long_id_body =
        kafka_describe_transactions_request_body(&["txn.secret"]);
    assert_eq!(
        parse_kafka_request(
            &kafka_flexible_request_frame(
                65,
                0,
                Some(b"client-a"),
                &describe_transactions_long_id_body,
            ),
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
        parse_kafka_request(
            &kafka_flexible_request_frame(65, 0, Some(b"client-a"), b"\x02\x04txn\0\0"),
            &config
        )
        .unwrap_err(),
        KafkaExtraction::MalformedFrame
    );

    let list_transactions_body =
        kafka_list_transactions_request_body(2, &["ongoing.secret"], &[1001], Some("txn.*secret"));
    assert_eq!(
        parse_kafka_request(
            &kafka_flexible_request_frame(66, 3, Some(b"client-a"), &list_transactions_body),
            &config
        )
        .unwrap_err(),
        KafkaExtraction::UnsupportedApiVersion
    );

    let mut oversized_list_transactions_states_body = Vec::new();
    push_unsigned_varint(&mut oversized_list_transactions_states_body, 1026);
    assert_eq!(
        parse_kafka_request(
            &kafka_flexible_request_frame(
                66,
                2,
                Some(b"client-a"),
                &oversized_list_transactions_states_body,
            ),
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );

    let mut oversized_list_transactions_producers_body = Vec::new();
    push_unsigned_varint(&mut oversized_list_transactions_producers_body, 1);
    push_unsigned_varint(&mut oversized_list_transactions_producers_body, 1026);
    assert_eq!(
        parse_kafka_request(
            &kafka_flexible_request_frame(
                66,
                2,
                Some(b"client-a"),
                &oversized_list_transactions_producers_body,
            ),
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );

    let list_transactions_long_state_body =
        kafka_list_transactions_request_body(2, &["ongoing.secret"], &[1001], None);
    assert_eq!(
        parse_kafka_request(
            &kafka_flexible_request_frame(
                66,
                2,
                Some(b"client-a"),
                &list_transactions_long_state_body,
            ),
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

    let list_transactions_long_pattern_body =
        kafka_list_transactions_request_body(2, &[], &[], Some("txn.*secret"));
    assert_eq!(
        parse_kafka_request(
            &kafka_flexible_request_frame(
                66,
                2,
                Some(b"client-a"),
                &list_transactions_long_pattern_body,
            ),
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
        parse_kafka_request(
            &kafka_flexible_request_frame(66, 2, Some(b"client-a"), b"\x01\x01\0"),
            &config
        )
        .unwrap_err(),
        KafkaExtraction::MalformedFrame
    );

    let consumer_group_heartbeat_body =
        kafka_consumer_group_heartbeat_request_body(&ConsumerGroupHeartbeatRequestFixture {
            api_version: 1,
            group_id: "group.secret",
            member_id: "member.secret",
            instance_id: Some("instance.secret"),
            rack_id: Some("rack.secret"),
            subscribed_topic_names: Some(&["orders.secret"]),
            subscribed_topic_regex: Some("orders.*secret"),
            server_assignor: Some("range.secret"),
            topic_partitions: None,
        });
    assert_eq!(
        parse_kafka_request(
            &kafka_flexible_request_frame(
                68,
                2,
                Some(b"client-a"),
                &consumer_group_heartbeat_body,
            ),
            &config
        )
        .unwrap_err(),
        KafkaExtraction::UnsupportedApiVersion
    );

    let consumer_group_heartbeat_long_group_body =
        kafka_consumer_group_heartbeat_request_body(&ConsumerGroupHeartbeatRequestFixture {
            api_version: 1,
            group_id: "group.secret",
            member_id: "member",
            instance_id: None,
            rack_id: None,
            subscribed_topic_names: None,
            subscribed_topic_regex: None,
            server_assignor: None,
            topic_partitions: None,
        });
    assert_eq!(
        parse_kafka_request(
            &kafka_flexible_request_frame(
                68,
                1,
                Some(b"client-a"),
                &consumer_group_heartbeat_long_group_body,
            ),
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

    let mut oversized_consumer_group_heartbeat_topics_body =
        kafka_consumer_group_heartbeat_prefix_body("group", "member", None, None);
    push_unsigned_varint(&mut oversized_consumer_group_heartbeat_topics_body, 1026);
    assert_eq!(
        parse_kafka_request(
            &kafka_flexible_request_frame(
                68,
                0,
                Some(b"client-a"),
                &oversized_consumer_group_heartbeat_topics_body,
            ),
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );

    let mut oversized_consumer_group_heartbeat_assignment_body =
        kafka_consumer_group_heartbeat_prefix_body("group", "member", None, None);
    push_unsigned_varint(&mut oversized_consumer_group_heartbeat_assignment_body, 0);
    push_unsigned_varint(&mut oversized_consumer_group_heartbeat_assignment_body, 0);
    push_unsigned_varint(
        &mut oversized_consumer_group_heartbeat_assignment_body,
        1026,
    );
    assert_eq!(
        parse_kafka_request(
            &kafka_flexible_request_frame(
                68,
                0,
                Some(b"client-a"),
                &oversized_consumer_group_heartbeat_assignment_body,
            ),
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );

    let mut malformed_consumer_group_heartbeat_assignment_body =
        kafka_consumer_group_heartbeat_prefix_body("group", "member", None, None);
    push_unsigned_varint(&mut malformed_consumer_group_heartbeat_assignment_body, 0);
    push_unsigned_varint(&mut malformed_consumer_group_heartbeat_assignment_body, 0);
    malformed_consumer_group_heartbeat_assignment_body.push(1);
    assert_eq!(
        parse_kafka_request(
            &kafka_flexible_request_frame(
                68,
                0,
                Some(b"client-a"),
                &malformed_consumer_group_heartbeat_assignment_body,
            ),
            &config
        )
        .unwrap_err(),
        KafkaExtraction::MalformedFrame
    );

    let consumer_group_describe_body =
        kafka_consumer_group_describe_request_body(1, &["alpha.secret", "beta.secret"]);
    assert_eq!(
        parse_kafka_request(
            &kafka_flexible_request_frame(69, 2, Some(b"client-a"), &consumer_group_describe_body),
            &config
        )
        .unwrap_err(),
        KafkaExtraction::UnsupportedApiVersion
    );

    let mut oversized_consumer_group_describe_groups_body = Vec::new();
    push_unsigned_varint(&mut oversized_consumer_group_describe_groups_body, 1026);
    assert_eq!(
        parse_kafka_request(
            &kafka_flexible_request_frame(
                69,
                1,
                Some(b"client-a"),
                &oversized_consumer_group_describe_groups_body,
            ),
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );

    let consumer_group_describe_long_group_body =
        kafka_consumer_group_describe_request_body(1, &["alpha.secret"]);
    assert_eq!(
        parse_kafka_request(
            &kafka_flexible_request_frame(
                69,
                1,
                Some(b"client-a"),
                &consumer_group_describe_long_group_body,
            ),
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
        parse_kafka_request(
            &kafka_flexible_request_frame(69, 1, Some(b"client-a"), b"\x01"),
            &config
        )
        .unwrap_err(),
        KafkaExtraction::MalformedFrame
    );

    let get_telemetry_subscriptions_body =
        kafka_get_telemetry_subscriptions_request_body([17_u8; 16]);
    assert_eq!(
        parse_kafka_request(
            &kafka_flexible_request_frame(
                71,
                1,
                Some(b"client-a"),
                &get_telemetry_subscriptions_body,
            ),
            &config
        )
        .unwrap_err(),
        KafkaExtraction::UnsupportedApiVersion
    );
    assert_eq!(
        parse_kafka_request(
            &kafka_flexible_request_frame(71, 0, Some(b"client-a"), b"\x00"),
            &config
        )
        .unwrap_err(),
        KafkaExtraction::MalformedFrame
    );
    let mut get_telemetry_subscriptions_trailing_body =
        kafka_get_telemetry_subscriptions_request_body([17_u8; 16]);
    get_telemetry_subscriptions_trailing_body.push(1);
    assert_eq!(
        parse_kafka_request(
            &kafka_flexible_request_frame(
                71,
                0,
                Some(b"client-a"),
                &get_telemetry_subscriptions_trailing_body,
            ),
            &config
        )
        .unwrap_err(),
        KafkaExtraction::MalformedFrame
    );

    let push_telemetry_body =
        kafka_push_telemetry_request_body([17_u8; 16], b"secret metric payload");
    assert_eq!(
        parse_kafka_request(
            &kafka_flexible_request_frame(72, 1, Some(b"client-a"), &push_telemetry_body),
            &config
        )
        .unwrap_err(),
        KafkaExtraction::UnsupportedApiVersion
    );
    assert_eq!(
        parse_kafka_request(
            &kafka_flexible_request_frame(72, 0, Some(b"client-a"), b"\x00"),
            &config
        )
        .unwrap_err(),
        KafkaExtraction::MalformedFrame
    );
    let mut malformed_push_telemetry_metrics_body = Vec::new();
    malformed_push_telemetry_metrics_body.extend_from_slice(&[17_u8; 16]);
    malformed_push_telemetry_metrics_body.extend_from_slice(&7_i32.to_be_bytes());
    malformed_push_telemetry_metrics_body.push(1);
    malformed_push_telemetry_metrics_body.push(0);
    push_unsigned_varint(&mut malformed_push_telemetry_metrics_body, 2);
    assert_eq!(
        parse_kafka_request(
            &kafka_flexible_request_frame(
                72,
                0,
                Some(b"client-a"),
                &malformed_push_telemetry_metrics_body,
            ),
            &config
        )
        .unwrap_err(),
        KafkaExtraction::MalformedFrame
    );
    let mut push_telemetry_trailing_body =
        kafka_push_telemetry_request_body([17_u8; 16], b"secret metric payload");
    push_telemetry_trailing_body.push(1);
    assert_eq!(
        parse_kafka_request(
            &kafka_flexible_request_frame(72, 0, Some(b"client-a"), &push_telemetry_trailing_body),
            &config
        )
        .unwrap_err(),
        KafkaExtraction::MalformedFrame
    );

    let list_config_resources_body = kafka_list_config_resources_request_body(&[2, 4]);
    assert_eq!(
        parse_kafka_request(
            &kafka_flexible_request_frame(74, 2, Some(b"client-a"), &list_config_resources_body),
            &config
        )
        .unwrap_err(),
        KafkaExtraction::UnsupportedApiVersion
    );
    let mut oversized_list_config_resources_body = Vec::new();
    push_unsigned_varint(&mut oversized_list_config_resources_body, 1026);
    assert_eq!(
        parse_kafka_request(
            &kafka_flexible_request_frame(
                74,
                1,
                Some(b"client-a"),
                &oversized_list_config_resources_body,
            ),
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );
    assert_eq!(
        parse_kafka_request(
            &kafka_flexible_request_frame(74, 1, Some(b"client-a"), b"\x01\x01"),
            &config
        )
        .unwrap_err(),
        KafkaExtraction::MalformedFrame
    );
    assert_eq!(
        parse_kafka_request(
            &kafka_flexible_request_frame(74, 0, Some(b"client-a"), b"\0\x01"),
            &config
        )
        .unwrap_err(),
        KafkaExtraction::MalformedFrame
    );

    let describe_topic_partitions_body =
        kafka_describe_topic_partitions_request_body(&["orders.secret"], None);
    assert_eq!(
        parse_kafka_request(
            &kafka_flexible_request_frame(
                75,
                1,
                Some(b"client-a"),
                &describe_topic_partitions_body
            ),
            &config
        )
        .unwrap_err(),
        KafkaExtraction::UnsupportedApiVersion
    );
    let mut oversized_describe_topic_partitions_body = Vec::new();
    push_unsigned_varint(&mut oversized_describe_topic_partitions_body, 1026);
    assert_eq!(
        parse_kafka_request(
            &kafka_flexible_request_frame(
                75,
                0,
                Some(b"client-a"),
                &oversized_describe_topic_partitions_body,
            ),
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );
    let describe_topic_partitions_long_topic_body =
        kafka_describe_topic_partitions_request_body(&["orders.secret"], None);
    assert_eq!(
        parse_kafka_request(
            &kafka_flexible_request_frame(
                75,
                0,
                Some(b"client-a"),
                &describe_topic_partitions_long_topic_body,
            ),
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
    let mut malformed_describe_topic_partitions_cursor_body =
        kafka_describe_topic_partitions_request_body(&["orders"], None);
    let cursor_marker_index = malformed_describe_topic_partitions_cursor_body.len() - 2;
    malformed_describe_topic_partitions_cursor_body[cursor_marker_index] = 1;
    assert_eq!(
        parse_kafka_request(
            &kafka_flexible_request_frame(
                75,
                0,
                Some(b"client-a"),
                &malformed_describe_topic_partitions_cursor_body,
            ),
            &config
        )
        .unwrap_err(),
        KafkaExtraction::MalformedFrame
    );

    let add_raft_voter_body = kafka_add_raft_voter_request_body(
        1,
        Some("cluster.secret"),
        &[("controller", "host.secret", 9093)],
    );
    assert_eq!(
        parse_kafka_request(
            &kafka_flexible_request_frame(80, 2, Some(b"client-a"), &add_raft_voter_body),
            &config
        )
        .unwrap_err(),
        KafkaExtraction::UnsupportedApiVersion
    );
    let mut oversized_add_raft_voter_body = Vec::new();
    push_compact_nullable_string(&mut oversized_add_raft_voter_body, None);
    oversized_add_raft_voter_body.extend_from_slice(&100_i32.to_be_bytes());
    oversized_add_raft_voter_body.extend_from_slice(&1_i32.to_be_bytes());
    oversized_add_raft_voter_body.extend_from_slice(&[29_u8; 16]);
    push_unsigned_varint(&mut oversized_add_raft_voter_body, 1026);
    assert_eq!(
        parse_kafka_request(
            &kafka_flexible_request_frame(80, 0, Some(b"client-a"), &oversized_add_raft_voter_body),
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );
    assert_eq!(
        parse_kafka_request(
            &kafka_flexible_request_frame(80, 0, Some(b"client-a"), &add_raft_voter_body),
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
        parse_kafka_request(
            &kafka_flexible_request_frame(80, 0, Some(b"client-a"), b"\0"),
            &config
        )
        .unwrap_err(),
        KafkaExtraction::MalformedFrame
    );

    let remove_raft_voter_body = kafka_remove_raft_voter_request_body(Some("cluster.secret"));
    assert_eq!(
        parse_kafka_request(
            &kafka_flexible_request_frame(81, 1, Some(b"client-a"), &remove_raft_voter_body),
            &config
        )
        .unwrap_err(),
        KafkaExtraction::UnsupportedApiVersion
    );
    assert_eq!(
        parse_kafka_request(
            &kafka_flexible_request_frame(81, 0, Some(b"client-a"), &remove_raft_voter_body),
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
        parse_kafka_request(
            &kafka_flexible_request_frame(81, 0, Some(b"client-a"), b"\0"),
            &config
        )
        .unwrap_err(),
        KafkaExtraction::MalformedFrame
    );

    let update_raft_voter_body = kafka_update_raft_voter_request_body(
        Some("cluster.secret"),
        &[("controller", "host.secret", 9093)],
    );
    assert_eq!(
        parse_kafka_request(
            &kafka_flexible_request_frame(82, 1, Some(b"client-a"), &update_raft_voter_body),
            &config
        )
        .unwrap_err(),
        KafkaExtraction::UnsupportedApiVersion
    );
    let mut oversized_update_raft_voter_body = Vec::new();
    push_compact_nullable_string(&mut oversized_update_raft_voter_body, None);
    oversized_update_raft_voter_body.extend_from_slice(&100_i32.to_be_bytes());
    oversized_update_raft_voter_body.extend_from_slice(&1_i32.to_be_bytes());
    oversized_update_raft_voter_body.extend_from_slice(&[29_u8; 16]);
    push_unsigned_varint(&mut oversized_update_raft_voter_body, 1026);
    assert_eq!(
        parse_kafka_request(
            &kafka_flexible_request_frame(
                82,
                0,
                Some(b"client-a"),
                &oversized_update_raft_voter_body,
            ),
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );
    assert_eq!(
        parse_kafka_request(
            &kafka_flexible_request_frame(82, 0, Some(b"client-a"), &update_raft_voter_body),
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
        parse_kafka_request(
            &kafka_flexible_request_frame(82, 0, Some(b"client-a"), b"\0"),
            &config
        )
        .unwrap_err(),
        KafkaExtraction::MalformedFrame
    );

    let initialize_share_group_state_partitions: &[InitializeShareGroupStatePartitionFixture] =
        &[InitializeShareGroupStatePartitionFixture {
            partition: 1,
            state_epoch: 2,
            start_offset: 100,
        }];
    let initialize_share_group_state_topics: &[InitializeShareGroupStateTopicFixture<'_>] =
        &[InitializeShareGroupStateTopicFixture {
            topic_id: [29_u8; 16],
            partitions: initialize_share_group_state_partitions,
        }];
    let initialize_share_group_state_body = kafka_initialize_share_group_state_request_body(
        "group.secret",
        initialize_share_group_state_topics,
    );
    assert_eq!(
        parse_kafka_request(
            &kafka_flexible_request_frame(
                83,
                1,
                Some(b"client-a"),
                &initialize_share_group_state_body,
            ),
            &config
        )
        .unwrap_err(),
        KafkaExtraction::UnsupportedApiVersion
    );
    assert_eq!(
        parse_kafka_request(
            &kafka_flexible_request_frame(
                83,
                0,
                Some(b"client-a"),
                &initialize_share_group_state_body,
            ),
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
    let mut oversized_initialize_share_group_state_body = Vec::new();
    push_compact_string(&mut oversized_initialize_share_group_state_body, "group");
    push_unsigned_varint(&mut oversized_initialize_share_group_state_body, 1026);
    assert_eq!(
        parse_kafka_request(
            &kafka_flexible_request_frame(
                83,
                0,
                Some(b"client-a"),
                &oversized_initialize_share_group_state_body,
            ),
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );
    let mut oversized_initialize_share_group_state_partition_body = Vec::new();
    push_compact_string(
        &mut oversized_initialize_share_group_state_partition_body,
        "group",
    );
    push_unsigned_varint(
        &mut oversized_initialize_share_group_state_partition_body,
        2,
    );
    oversized_initialize_share_group_state_partition_body.extend_from_slice(&[29_u8; 16]);
    push_unsigned_varint(
        &mut oversized_initialize_share_group_state_partition_body,
        1026,
    );
    assert_eq!(
        parse_kafka_request(
            &kafka_flexible_request_frame(
                83,
                0,
                Some(b"client-a"),
                &oversized_initialize_share_group_state_partition_body,
            ),
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );
    assert_eq!(
        parse_kafka_request(
            &kafka_flexible_request_frame(83, 0, Some(b"client-a"), b"\0"),
            &config
        )
        .unwrap_err(),
        KafkaExtraction::MalformedFrame
    );

    let read_share_group_state_partitions: &[ReadShareGroupStatePartitionFixture] =
        &[ReadShareGroupStatePartitionFixture {
            partition: 1,
            leader_epoch: 2,
        }];
    let read_share_group_state_topics: &[ReadShareGroupStateTopicFixture<'_>] =
        &[ReadShareGroupStateTopicFixture {
            topic_id: [29_u8; 16],
            partitions: read_share_group_state_partitions,
        }];
    let read_share_group_state_body =
        kafka_read_share_group_state_request_body("group.secret", read_share_group_state_topics);
    assert_eq!(
        parse_kafka_request(
            &kafka_flexible_request_frame(84, 1, Some(b"client-a"), &read_share_group_state_body),
            &config
        )
        .unwrap_err(),
        KafkaExtraction::UnsupportedApiVersion
    );
    assert_eq!(
        parse_kafka_request(
            &kafka_flexible_request_frame(84, 0, Some(b"client-a"), &read_share_group_state_body),
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
    let mut oversized_read_share_group_state_body = Vec::new();
    push_compact_string(&mut oversized_read_share_group_state_body, "group");
    push_unsigned_varint(&mut oversized_read_share_group_state_body, 1026);
    assert_eq!(
        parse_kafka_request(
            &kafka_flexible_request_frame(
                84,
                0,
                Some(b"client-a"),
                &oversized_read_share_group_state_body,
            ),
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );
    let mut oversized_read_share_group_state_partition_body = Vec::new();
    push_compact_string(
        &mut oversized_read_share_group_state_partition_body,
        "group",
    );
    push_unsigned_varint(&mut oversized_read_share_group_state_partition_body, 2);
    oversized_read_share_group_state_partition_body.extend_from_slice(&[29_u8; 16]);
    push_unsigned_varint(&mut oversized_read_share_group_state_partition_body, 1026);
    assert_eq!(
        parse_kafka_request(
            &kafka_flexible_request_frame(
                84,
                0,
                Some(b"client-a"),
                &oversized_read_share_group_state_partition_body,
            ),
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );
    assert_eq!(
        parse_kafka_request(
            &kafka_flexible_request_frame(84, 0, Some(b"client-a"), b"\0"),
            &config
        )
        .unwrap_err(),
        KafkaExtraction::MalformedFrame
    );

    let write_share_group_state_batches: &[WriteShareGroupStateBatchFixture] =
        &[WriteShareGroupStateBatchFixture {
            first_offset: 100,
            last_offset: 200,
            delivery_state: 2,
            delivery_count: 3,
        }];
    let write_share_group_state_partitions: &[WriteShareGroupStatePartitionFixture<'_>] =
        &[WriteShareGroupStatePartitionFixture {
            partition: 1,
            state_epoch: 5,
            leader_epoch: 2,
            start_offset: 100,
            delivery_complete_count: Some(4),
            state_batches: write_share_group_state_batches,
        }];
    let write_share_group_state_topics: &[WriteShareGroupStateTopicFixture<'_>] =
        &[WriteShareGroupStateTopicFixture {
            topic_id: [29_u8; 16],
            partitions: write_share_group_state_partitions,
        }];
    let write_share_group_state_body = kafka_write_share_group_state_request_body(
        "group.secret",
        write_share_group_state_topics,
        1,
    );
    assert_eq!(
        parse_kafka_request(
            &kafka_flexible_request_frame(85, 2, Some(b"client-a"), &write_share_group_state_body),
            &config
        )
        .unwrap_err(),
        KafkaExtraction::UnsupportedApiVersion
    );
    assert_eq!(
        parse_kafka_request(
            &kafka_flexible_request_frame(85, 1, Some(b"client-a"), &write_share_group_state_body),
            &ProtocolExtractionConfig {
                max_header_bytes: 256,
                max_request_line_bytes: 4,
                max_attributes: 4,
                max_tracestate_bytes: 32,
            },
        )
        .unwrap_err(),
        KafkaExtraction::ClientIdTooLong
    );
    let mut oversized_write_share_group_state_body = Vec::new();
    push_compact_string(&mut oversized_write_share_group_state_body, "group");
    push_unsigned_varint(&mut oversized_write_share_group_state_body, 1026);
    assert_eq!(
        parse_kafka_request(
            &kafka_flexible_request_frame(
                85,
                1,
                Some(b"client-a"),
                &oversized_write_share_group_state_body,
            ),
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );
    let mut oversized_write_share_group_state_partition_body = Vec::new();
    push_compact_string(
        &mut oversized_write_share_group_state_partition_body,
        "group",
    );
    push_unsigned_varint(&mut oversized_write_share_group_state_partition_body, 2);
    oversized_write_share_group_state_partition_body.extend_from_slice(&[29_u8; 16]);
    push_unsigned_varint(&mut oversized_write_share_group_state_partition_body, 1026);
    assert_eq!(
        parse_kafka_request(
            &kafka_flexible_request_frame(
                85,
                1,
                Some(b"client-a"),
                &oversized_write_share_group_state_partition_body,
            ),
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );
    let mut oversized_write_share_group_state_batch_body = Vec::new();
    push_compact_string(&mut oversized_write_share_group_state_batch_body, "group");
    push_unsigned_varint(&mut oversized_write_share_group_state_batch_body, 2);
    oversized_write_share_group_state_batch_body.extend_from_slice(&[29_u8; 16]);
    push_unsigned_varint(&mut oversized_write_share_group_state_batch_body, 2);
    oversized_write_share_group_state_batch_body.extend_from_slice(&1_i32.to_be_bytes());
    oversized_write_share_group_state_batch_body.extend_from_slice(&5_i32.to_be_bytes());
    oversized_write_share_group_state_batch_body.extend_from_slice(&2_i32.to_be_bytes());
    oversized_write_share_group_state_batch_body.extend_from_slice(&100_i64.to_be_bytes());
    oversized_write_share_group_state_batch_body.extend_from_slice(&4_i32.to_be_bytes());
    push_unsigned_varint(&mut oversized_write_share_group_state_batch_body, 1026);
    assert_eq!(
        parse_kafka_request(
            &kafka_flexible_request_frame(
                85,
                1,
                Some(b"client-a"),
                &oversized_write_share_group_state_batch_body,
            ),
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );
    assert_eq!(
        parse_kafka_request(
            &kafka_flexible_request_frame(85, 1, Some(b"client-a"), b"\0"),
            &config
        )
        .unwrap_err(),
        KafkaExtraction::MalformedFrame
    );

    let delete_share_group_state_partitions: &[DeleteShareGroupStatePartitionFixture] =
        &[DeleteShareGroupStatePartitionFixture { partition: 1 }];
    let delete_share_group_state_topics: &[DeleteShareGroupStateTopicFixture<'_>] =
        &[DeleteShareGroupStateTopicFixture {
            topic_id: [29_u8; 16],
            partitions: delete_share_group_state_partitions,
        }];
    let delete_share_group_state_body = kafka_delete_share_group_state_request_body(
        "group.secret",
        delete_share_group_state_topics,
    );
    assert_eq!(
        parse_kafka_request(
            &kafka_flexible_request_frame(86, 1, Some(b"client-a"), &delete_share_group_state_body),
            &config
        )
        .unwrap_err(),
        KafkaExtraction::UnsupportedApiVersion
    );
    assert_eq!(
        parse_kafka_request(
            &kafka_flexible_request_frame(86, 0, Some(b"client-a"), &delete_share_group_state_body),
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
    let mut oversized_delete_share_group_state_body = Vec::new();
    push_compact_string(&mut oversized_delete_share_group_state_body, "group");
    push_unsigned_varint(&mut oversized_delete_share_group_state_body, 1026);
    assert_eq!(
        parse_kafka_request(
            &kafka_flexible_request_frame(
                86,
                0,
                Some(b"client-a"),
                &oversized_delete_share_group_state_body,
            ),
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );
    let mut oversized_delete_share_group_state_partition_body = Vec::new();
    push_compact_string(
        &mut oversized_delete_share_group_state_partition_body,
        "group",
    );
    push_unsigned_varint(&mut oversized_delete_share_group_state_partition_body, 2);
    oversized_delete_share_group_state_partition_body.extend_from_slice(&[29_u8; 16]);
    push_unsigned_varint(&mut oversized_delete_share_group_state_partition_body, 1026);
    assert_eq!(
        parse_kafka_request(
            &kafka_flexible_request_frame(
                86,
                0,
                Some(b"client-a"),
                &oversized_delete_share_group_state_partition_body,
            ),
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );
    assert_eq!(
        parse_kafka_request(
            &kafka_flexible_request_frame(86, 0, Some(b"client-a"), b"\0"),
            &config
        )
        .unwrap_err(),
        KafkaExtraction::MalformedFrame
    );

    let read_share_group_state_summary_partitions: &[ReadShareGroupStateSummaryPartitionFixture] =
        &[ReadShareGroupStateSummaryPartitionFixture {
            partition: 1,
            leader_epoch: 2,
        }];
    let read_share_group_state_summary_topics: &[ReadShareGroupStateSummaryTopicFixture<'_>] =
        &[ReadShareGroupStateSummaryTopicFixture {
            topic_id: [29_u8; 16],
            partitions: read_share_group_state_summary_partitions,
        }];
    let read_share_group_state_summary_body = kafka_read_share_group_state_summary_request_body(
        "group.secret",
        read_share_group_state_summary_topics,
    );
    assert_eq!(
        parse_kafka_request(
            &kafka_flexible_request_frame(
                87,
                2,
                Some(b"client-a"),
                &read_share_group_state_summary_body,
            ),
            &config
        )
        .unwrap_err(),
        KafkaExtraction::UnsupportedApiVersion
    );
    assert_eq!(
        parse_kafka_request(
            &kafka_flexible_request_frame(
                87,
                1,
                Some(b"client-a"),
                &read_share_group_state_summary_body,
            ),
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
    let mut oversized_read_share_group_state_summary_body = Vec::new();
    push_compact_string(&mut oversized_read_share_group_state_summary_body, "group");
    push_unsigned_varint(&mut oversized_read_share_group_state_summary_body, 1026);
    assert_eq!(
        parse_kafka_request(
            &kafka_flexible_request_frame(
                87,
                1,
                Some(b"client-a"),
                &oversized_read_share_group_state_summary_body,
            ),
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );
    let mut oversized_read_share_group_state_summary_partition_body = Vec::new();
    push_compact_string(
        &mut oversized_read_share_group_state_summary_partition_body,
        "group",
    );
    push_unsigned_varint(
        &mut oversized_read_share_group_state_summary_partition_body,
        2,
    );
    oversized_read_share_group_state_summary_partition_body.extend_from_slice(&[29_u8; 16]);
    push_unsigned_varint(
        &mut oversized_read_share_group_state_summary_partition_body,
        1026,
    );
    assert_eq!(
        parse_kafka_request(
            &kafka_flexible_request_frame(
                87,
                1,
                Some(b"client-a"),
                &oversized_read_share_group_state_summary_partition_body,
            ),
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );
    assert_eq!(
        parse_kafka_request(
            &kafka_flexible_request_frame(87, 1, Some(b"client-a"), b"\0"),
            &config
        )
        .unwrap_err(),
        KafkaExtraction::MalformedFrame
    );

    let delete_share_group_offsets_body =
        kafka_delete_share_group_offsets_request_body("group.secret", &["orders.secret"]);
    assert_eq!(
        parse_kafka_request(
            &kafka_flexible_request_frame(
                92,
                1,
                Some(b"client-a"),
                &delete_share_group_offsets_body
            ),
            &config
        )
        .unwrap_err(),
        KafkaExtraction::UnsupportedApiVersion
    );
    assert_eq!(
        parse_kafka_request(
            &kafka_flexible_request_frame(
                92,
                0,
                Some(b"client-a"),
                &delete_share_group_offsets_body
            ),
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
    let mut oversized_delete_share_group_offsets_body = Vec::new();
    push_compact_string(&mut oversized_delete_share_group_offsets_body, "grp");
    push_unsigned_varint(&mut oversized_delete_share_group_offsets_body, 1026);
    assert_eq!(
        parse_kafka_request(
            &kafka_flexible_request_frame(
                92,
                0,
                Some(b"client-a"),
                &oversized_delete_share_group_offsets_body,
            ),
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );
    assert_eq!(
        parse_kafka_request(
            &kafka_flexible_request_frame(92, 0, Some(b"client-a"), b"\0"),
            &config
        )
        .unwrap_err(),
        KafkaExtraction::MalformedFrame
    );

    let describe_share_group_offsets_topics: &[DescribeShareGroupOffsetsRequestTopicFixture<'_>] =
        &[("orders.secret", &[0])];
    let describe_share_group_offsets_groups: &[DescribeShareGroupOffsetsRequestGroupFixture<'_>] =
        &[("group.secret", Some(describe_share_group_offsets_topics))];
    let describe_share_group_offsets_body =
        kafka_describe_share_group_offsets_request_body(describe_share_group_offsets_groups);
    assert_eq!(
        parse_kafka_request(
            &kafka_flexible_request_frame(
                90,
                2,
                Some(b"client-a"),
                &describe_share_group_offsets_body
            ),
            &config
        )
        .unwrap_err(),
        KafkaExtraction::UnsupportedApiVersion
    );
    assert_eq!(
        parse_kafka_request(
            &kafka_flexible_request_frame(
                90,
                0,
                Some(b"client-a"),
                &describe_share_group_offsets_body
            ),
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
    let mut oversized_describe_share_group_offsets_body = Vec::new();
    push_unsigned_varint(&mut oversized_describe_share_group_offsets_body, 1026);
    assert_eq!(
        parse_kafka_request(
            &kafka_flexible_request_frame(
                90,
                0,
                Some(b"client-a"),
                &oversized_describe_share_group_offsets_body,
            ),
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );
    assert_eq!(
        parse_kafka_request(
            &kafka_flexible_request_frame(90, 0, Some(b"client-a"), b"\0"),
            &config
        )
        .unwrap_err(),
        KafkaExtraction::MalformedFrame
    );
}
