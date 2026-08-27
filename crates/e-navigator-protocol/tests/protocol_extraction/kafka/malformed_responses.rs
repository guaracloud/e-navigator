use super::*;

#[test]
fn rejects_malformed_kafka_responses() {
    let config = ProtocolExtractionConfig::default();

    let mut truncated_response = kafka_produce_response_frame(0, 1, &[("orders", 6)]);
    truncated_response.truncate(10);
    assert_eq!(
        parse_kafka_produce_response(&truncated_response, 1, &config).unwrap_err(),
        KafkaExtraction::MalformedFrame
    );

    let mut truncated_fetch_response = kafka_fetch_response_frame(0, 5, &[("orders", 6, b"data")]);
    truncated_fetch_response.truncate(24);
    assert_eq!(
        parse_kafka_fetch_response(&truncated_fetch_response, 5, &config).unwrap_err(),
        KafkaExtraction::MalformedFrame
    );

    let mut truncated_offset_commit_response =
        kafka_offset_commit_response_frame(0, 7, &[("orders", 25)]);
    truncated_offset_commit_response.truncate(12);
    assert_eq!(
        parse_kafka_offset_commit_response(&truncated_offset_commit_response, 7, &config)
            .unwrap_err(),
        KafkaExtraction::MalformedFrame
    );

    let mut truncated_offset_fetch_response =
        kafka_offset_fetch_response_frame(0, 5, 0, &[("orders", 25)]);
    truncated_offset_fetch_response.truncate(20);
    assert_eq!(
        parse_kafka_offset_fetch_response(&truncated_offset_fetch_response, 5, &config)
            .unwrap_err(),
        KafkaExtraction::MalformedFrame
    );

    let mut truncated_offset_delete_response =
        kafka_offset_delete_response_frame(0, 0, &[("orders", 25)]);
    truncated_offset_delete_response.truncate(14);
    assert_eq!(
        parse_kafka_offset_delete_response(&truncated_offset_delete_response, 0, &config)
            .unwrap_err(),
        KafkaExtraction::MalformedFrame
    );

    let mut truncated_list_offsets_response =
        kafka_list_offsets_response_frame(0, 5, &[("orders", 6)]);
    truncated_list_offsets_response.truncate(24);
    assert_eq!(
        parse_kafka_list_offsets_response(&truncated_list_offsets_response, 5, &config)
            .unwrap_err(),
        KafkaExtraction::MalformedFrame
    );

    let mut truncated_delete_records_response =
        kafka_delete_records_response_frame(0, &[("orders", 6)]);
    truncated_delete_records_response.truncate(20);
    assert_eq!(
        parse_kafka_delete_records_response(&truncated_delete_records_response, 1, &config)
            .unwrap_err(),
        KafkaExtraction::MalformedFrame
    );

    let mut truncated_delete_topics_response =
        kafka_delete_topics_response_frame(0, &[("orders", 6)]);
    truncated_delete_topics_response.truncate(12);
    assert_eq!(
        parse_kafka_delete_topics_response(&truncated_delete_topics_response, 1, &config)
            .unwrap_err(),
        KafkaExtraction::MalformedFrame
    );

    let mut truncated_create_topics_response =
        kafka_create_topics_response_frame(0, &[("orders", 36, Some("secret"))]);
    truncated_create_topics_response.truncate(12);
    assert_eq!(
        parse_kafka_create_topics_response(&truncated_create_topics_response, 2, &config)
            .unwrap_err(),
        KafkaExtraction::MalformedFrame
    );

    let mut truncated_create_partitions_response =
        kafka_create_partitions_response_frame(0, &[("orders", 37, Some("secret"))]);
    truncated_create_partitions_response.truncate(12);
    assert_eq!(
        parse_kafka_create_partitions_response(&truncated_create_partitions_response, 0, &config)
            .unwrap_err(),
        KafkaExtraction::MalformedFrame
    );

    let mut truncated_create_acls_response =
        kafka_create_acls_response_frame(0, &[(31, Some("secret"))]);
    truncated_create_acls_response.truncate(10);
    assert_eq!(
        parse_kafka_create_acls_response(&truncated_create_acls_response, 1, &config).unwrap_err(),
        KafkaExtraction::MalformedFrame
    );

    let mut truncated_describe_acls_response =
        kafka_describe_acls_response_frame(0, 0, None, &[("orders", &[("User:secret", "host")])]);
    truncated_describe_acls_response.truncate(14);
    assert_eq!(
        parse_kafka_describe_acls_response(&truncated_describe_acls_response, 1, &config)
            .unwrap_err(),
        KafkaExtraction::MalformedFrame
    );

    let mut truncated_delete_acls_response = kafka_delete_acls_response_frame(
        0,
        &[(
            0,
            None,
            &[(30, Some("secret"), "orders", "User:secret", "host")],
        )],
    );
    truncated_delete_acls_response.truncate(14);
    assert_eq!(
        parse_kafka_delete_acls_response(&truncated_delete_acls_response, 1, &config).unwrap_err(),
        KafkaExtraction::MalformedFrame
    );

    let mut truncated_describe_configs_response =
        kafka_describe_configs_response_frame(0, 3, &[(35, Some("secret"), "orders", &[])]);
    truncated_describe_configs_response.truncate(14);
    assert_eq!(
        parse_kafka_describe_configs_response(&truncated_describe_configs_response, 3, &config)
            .unwrap_err(),
        KafkaExtraction::MalformedFrame
    );

    let mut truncated_alter_configs_response =
        kafka_alter_configs_response_frame(0, &[(35, Some("secret"), "orders")]);
    truncated_alter_configs_response.truncate(12);
    assert_eq!(
        parse_kafka_alter_configs_response(&truncated_alter_configs_response, 1, &config)
            .unwrap_err(),
        KafkaExtraction::MalformedFrame
    );

    let mut truncated_alter_replica_log_dirs_response =
        kafka_alter_replica_log_dirs_response_frame(0, &[("orders", &[(0, 35)])]);
    truncated_alter_replica_log_dirs_response.truncate(13);
    assert_eq!(
        parse_kafka_alter_replica_log_dirs_response(
            &truncated_alter_replica_log_dirs_response,
            1,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::MalformedFrame
    );

    let mut truncated_describe_log_dirs_response =
        kafka_describe_log_dirs_response_frame(0, &[(0, "/tmp/kafka", &[("orders", &[0])])]);
    truncated_describe_log_dirs_response.truncate(20);
    assert_eq!(
        parse_kafka_describe_log_dirs_response(&truncated_describe_log_dirs_response, 1, &config)
            .unwrap_err(),
        KafkaExtraction::MalformedFrame
    );

    let mut truncated_create_delegation_token_response =
        kafka_create_delegation_token_response_frame(0, 35, "User", "alice", "token", b"hmac");
    truncated_create_delegation_token_response.truncate(16);
    assert_eq!(
        parse_kafka_create_delegation_token_response(
            &truncated_create_delegation_token_response,
            1,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::MalformedFrame
    );

    let mut truncated_renew_delegation_token_response =
        kafka_renew_delegation_token_response_frame(0, 35);
    truncated_renew_delegation_token_response.truncate(12);
    assert_eq!(
        parse_kafka_renew_delegation_token_response(
            &truncated_renew_delegation_token_response,
            1,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::MalformedFrame
    );

    let mut truncated_expire_delegation_token_response =
        kafka_expire_delegation_token_response_frame(0, 35);
    truncated_expire_delegation_token_response.truncate(12);
    assert_eq!(
        parse_kafka_expire_delegation_token_response(
            &truncated_expire_delegation_token_response,
            1,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::MalformedFrame
    );

    let mut truncated_describe_delegation_token_response =
        kafka_describe_delegation_token_response_frame(
            0,
            0,
            &[DescribeDelegationTokenFixture {
                principal_type: "User",
                principal_name: "alice",
                token_id: "token",
                hmac: b"hmac",
                renewers: &[("User", "bob")],
            }],
        );
    truncated_describe_delegation_token_response.truncate(20);
    assert_eq!(
        parse_kafka_describe_delegation_token_response(
            &truncated_describe_delegation_token_response,
            1,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::MalformedFrame
    );

    let mut truncated_elect_leaders_response =
        kafka_elect_leaders_response_frame(0, 1, 0, &[("orders", &[(0, 35, Some("secret"))])]);
    truncated_elect_leaders_response.truncate(16);
    assert_eq!(
        parse_kafka_elect_leaders_response(&truncated_elect_leaders_response, 1, &config)
            .unwrap_err(),
        KafkaExtraction::MalformedFrame
    );

    let mut truncated_incremental_alter_configs_response =
        kafka_incremental_alter_configs_response_frame(0, 1, &[(40, Some("secret"), 2, "orders")]);
    truncated_incremental_alter_configs_response.truncate(14);
    assert_eq!(
        parse_kafka_incremental_alter_configs_response(
            &truncated_incremental_alter_configs_response,
            1,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::MalformedFrame
    );

    let mut truncated_alter_partition_reassignments_response =
        kafka_alter_partition_reassignments_response_frame(
            0,
            1,
            0,
            None,
            &[("orders", &[(0, 35, Some("secret"))])],
        );
    truncated_alter_partition_reassignments_response.truncate(18);
    assert_eq!(
        parse_kafka_alter_partition_reassignments_response(
            &truncated_alter_partition_reassignments_response,
            1,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::MalformedFrame
    );

    let mut truncated_list_partition_reassignments_response =
        kafka_list_partition_reassignments_response_frame(
            0,
            0,
            None,
            &[("orders", &[(0, &[1, 2], &[3], &[4])])],
        );
    truncated_list_partition_reassignments_response.truncate(18);
    assert_eq!(
        parse_kafka_list_partition_reassignments_response(
            &truncated_list_partition_reassignments_response,
            0,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::MalformedFrame
    );

    let mut truncated_describe_client_quotas_response = kafka_describe_client_quotas_response_frame(
        0,
        1,
        0,
        None,
        Some(&[(
            &[("client-id", Some("secret-client-a"))],
            &[("producer_byte_rate.secret", 42.0)],
        )]),
    );
    truncated_describe_client_quotas_response.truncate(18);
    assert_eq!(
        parse_kafka_describe_client_quotas_response(
            &truncated_describe_client_quotas_response,
            1,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::MalformedFrame
    );

    let mut truncated_alter_client_quotas_response = kafka_alter_client_quotas_response_frame(
        0,
        1,
        &[(
            31,
            Some("top secret denied"),
            &[("client-id", Some("secret-client-a"))],
        )],
    );
    truncated_alter_client_quotas_response.truncate(14);
    assert_eq!(
        parse_kafka_alter_client_quotas_response(
            &truncated_alter_client_quotas_response,
            1,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::MalformedFrame
    );

    let mut truncated_describe_user_scram_credentials_response =
        kafka_describe_user_scram_credentials_response_frame(
            0,
            0,
            None,
            &[("alice.secret", 51, Some("user secret denied"), &[])],
        );
    truncated_describe_user_scram_credentials_response.truncate(16);
    assert_eq!(
        parse_kafka_describe_user_scram_credentials_response(
            &truncated_describe_user_scram_credentials_response,
            0,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::MalformedFrame
    );

    let mut truncated_alter_user_scram_credentials_response =
        kafka_alter_user_scram_credentials_response_frame(
            0,
            &[("alice.secret", 51, Some("user secret denied"))],
        );
    truncated_alter_user_scram_credentials_response.truncate(14);
    assert_eq!(
        parse_kafka_alter_user_scram_credentials_response(
            &truncated_alter_user_scram_credentials_response,
            0,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::MalformedFrame
    );

    let mut truncated_describe_quorum_response = kafka_describe_quorum_response_frame(
        0,
        2,
        0,
        None,
        &[(
            "metadata.secret",
            &[(0, 35, Some("partition secret denied"))],
        )],
        &[(
            1,
            &[("CONTROLLER.secret", "controller.secret.internal", 9093)],
        )],
    );
    truncated_describe_quorum_response.truncate(24);
    assert_eq!(
        parse_kafka_describe_quorum_response(&truncated_describe_quorum_response, 2, &config)
            .unwrap_err(),
        KafkaExtraction::MalformedFrame
    );

    let mut truncated_update_features_response = kafka_update_features_response_frame(
        0,
        1,
        0,
        None,
        &[("metadata.version.secret", 35, Some("feature secret denied"))],
    );
    truncated_update_features_response.truncate(16);
    assert_eq!(
        parse_kafka_update_features_response(&truncated_update_features_response, 1, &config)
            .unwrap_err(),
        KafkaExtraction::MalformedFrame
    );

    let mut truncated_describe_cluster_response = kafka_describe_cluster_response_frame(
        0,
        2,
        0,
        None,
        "cluster.secret",
        &[(1, "broker.secret.internal", 9092, Some("rack.secret"), true)],
    );
    truncated_describe_cluster_response.truncate(20);
    assert_eq!(
        parse_kafka_describe_cluster_response(&truncated_describe_cluster_response, 2, &config)
            .unwrap_err(),
        KafkaExtraction::MalformedFrame
    );

    let mut truncated_describe_producers_response = kafka_describe_producers_response_frame(
        0,
        &[(
            "orders.secret",
            &[(0, 35, Some("producer secret denied"), 1)],
        )],
    );
    truncated_describe_producers_response.truncate(20);
    assert_eq!(
        parse_kafka_describe_producers_response(
            &truncated_describe_producers_response,
            0,
            &config,
        )
        .unwrap_err(),
        KafkaExtraction::MalformedFrame
    );

    let mut truncated_unregister_broker_response =
        kafka_unregister_broker_response_frame(0, 35, Some("broker secret denied"));
    truncated_unregister_broker_response.truncate(10);
    assert_eq!(
        parse_kafka_unregister_broker_response(&truncated_unregister_broker_response, 0, &config)
            .unwrap_err(),
        KafkaExtraction::MalformedFrame
    );

    let mut truncated_describe_transactions_response = kafka_describe_transactions_response_frame(
        0,
        &[(35, "txn.secret", "prepare_abort.secret", 1001, &[])],
    );
    truncated_describe_transactions_response.truncate(18);
    assert_eq!(
        parse_kafka_describe_transactions_response(
            &truncated_describe_transactions_response,
            0,
            &config,
        )
        .unwrap_err(),
        KafkaExtraction::MalformedFrame
    );

    let mut truncated_list_transactions_response = kafka_list_transactions_response_frame(
        0,
        35,
        &["unknown.secret"],
        &[("txn.secret", 1001, "ongoing.secret")],
    );
    truncated_list_transactions_response.truncate(18);
    assert_eq!(
        parse_kafka_list_transactions_response(&truncated_list_transactions_response, 2, &config)
            .unwrap_err(),
        KafkaExtraction::MalformedFrame
    );

    let mut truncated_consumer_group_heartbeat_response =
        kafka_consumer_group_heartbeat_response_frame(
            0,
            35,
            Some("heartbeat secret denied"),
            Some("member.secret"),
            None,
        );
    truncated_consumer_group_heartbeat_response.truncate(18);
    assert_eq!(
        parse_kafka_consumer_group_heartbeat_response(
            &truncated_consumer_group_heartbeat_response,
            1,
            &config,
        )
        .unwrap_err(),
        KafkaExtraction::MalformedFrame
    );

    let mut truncated_consumer_group_describe_response =
        kafka_consumer_group_describe_response_frame(
            0,
            1,
            &[ConsumerGroupDescribeGroupFixture {
                error_code: 30,
                error_message: Some("describe secret denied"),
                group_id: "alpha.secret",
                group_state: "dead.secret",
                assignor_name: "range.secret",
                members: &[],
            }],
        );
    truncated_consumer_group_describe_response.truncate(18);
    assert_eq!(
        parse_kafka_consumer_group_describe_response(
            &truncated_consumer_group_describe_response,
            1,
            &config,
        )
        .unwrap_err(),
        KafkaExtraction::MalformedFrame
    );

    let mut truncated_get_telemetry_subscriptions_response =
        kafka_get_telemetry_subscriptions_response_frame(
            0,
            35,
            [23_u8; 16],
            &[1],
            &["secret.metric"],
        );
    truncated_get_telemetry_subscriptions_response.truncate(20);
    assert_eq!(
        parse_kafka_get_telemetry_subscriptions_response(
            &truncated_get_telemetry_subscriptions_response,
            0,
            &config,
        )
        .unwrap_err(),
        KafkaExtraction::MalformedFrame
    );

    let mut truncated_push_telemetry_response = kafka_push_telemetry_response_frame(0, 35);
    truncated_push_telemetry_response.truncate(8);
    assert_eq!(
        parse_kafka_push_telemetry_response(&truncated_push_telemetry_response, 0, &config)
            .unwrap_err(),
        KafkaExtraction::MalformedFrame
    );

    let mut truncated_list_config_resources_response =
        kafka_list_config_resources_response_frame(0, 1, 35, &[("secret.config", 2)]);
    truncated_list_config_resources_response.truncate(12);
    assert_eq!(
        parse_kafka_list_config_resources_response(
            &truncated_list_config_resources_response,
            1,
            &config,
        )
        .unwrap_err(),
        KafkaExtraction::MalformedFrame
    );

    let mut truncated_describe_topic_partitions_response =
        kafka_describe_topic_partitions_response_frame(
            0,
            &[DescribeTopicPartitionsTopicFixture {
                error_code: 35,
                name: Some("orders.secret"),
                topic_id: [31_u8; 16],
                partitions: &[],
            }],
            None,
        );
    truncated_describe_topic_partitions_response.truncate(18);
    assert_eq!(
        parse_kafka_describe_topic_partitions_response(
            &truncated_describe_topic_partitions_response,
            0,
            &config,
        )
        .unwrap_err(),
        KafkaExtraction::MalformedFrame
    );

    let mut truncated_add_raft_voter_response =
        kafka_add_raft_voter_response_frame(0, 35, Some("secret message"));
    truncated_add_raft_voter_response.truncate(10);
    assert_eq!(
        parse_kafka_add_raft_voter_response(&truncated_add_raft_voter_response, 0, &config)
            .unwrap_err(),
        KafkaExtraction::MalformedFrame
    );

    let mut truncated_remove_raft_voter_response =
        kafka_remove_raft_voter_response_frame(0, 35, Some("secret message"));
    truncated_remove_raft_voter_response.truncate(10);
    assert_eq!(
        parse_kafka_remove_raft_voter_response(&truncated_remove_raft_voter_response, 0, &config)
            .unwrap_err(),
        KafkaExtraction::MalformedFrame
    );

    let mut truncated_update_raft_voter_response = kafka_update_raft_voter_response_frame(
        0,
        35,
        Some(UpdateRaftVoterLeaderFixture {
            leader_id: 7,
            leader_epoch: 8,
            host: "leader.secret.internal",
            port: 9092,
        }),
    );
    truncated_update_raft_voter_response.truncate(10);
    assert_eq!(
        parse_kafka_update_raft_voter_response(&truncated_update_raft_voter_response, 0, &config)
            .unwrap_err(),
        KafkaExtraction::MalformedFrame
    );

    let mut truncated_initialize_share_group_state_response =
        kafka_initialize_share_group_state_response_frame(
            0,
            &[InitializeShareGroupStateResultTopicFixture {
                topic_id: [29_u8; 16],
                partitions: &[InitializeShareGroupStateResultPartitionFixture {
                    partition: 1,
                    error_code: 35,
                    error_message: Some("secret message"),
                }],
            }],
        );
    truncated_initialize_share_group_state_response.truncate(18);
    assert_eq!(
        parse_kafka_initialize_share_group_state_response(
            &truncated_initialize_share_group_state_response,
            0,
            &config,
        )
        .unwrap_err(),
        KafkaExtraction::MalformedFrame
    );

    let mut truncated_read_share_group_state_response = kafka_read_share_group_state_response_frame(
        0,
        &[ReadShareGroupStateResultTopicFixture {
            topic_id: [29_u8; 16],
            partitions: &[ReadShareGroupStateResultPartitionFixture {
                partition: 1,
                error_code: 35,
                error_message: Some("secret message"),
                state_epoch: 5,
                start_offset: 100,
                state_batches: &[],
            }],
        }],
    );
    truncated_read_share_group_state_response.truncate(18);
    assert_eq!(
        parse_kafka_read_share_group_state_response(
            &truncated_read_share_group_state_response,
            0,
            &config,
        )
        .unwrap_err(),
        KafkaExtraction::MalformedFrame
    );

    let mut truncated_write_share_group_state_response =
        kafka_write_share_group_state_response_frame(
            0,
            &[WriteShareGroupStateResultTopicFixture {
                topic_id: [29_u8; 16],
                partitions: &[WriteShareGroupStateResultPartitionFixture {
                    partition: 1,
                    error_code: 35,
                    error_message: Some("secret message"),
                }],
            }],
        );
    truncated_write_share_group_state_response.truncate(18);
    assert_eq!(
        parse_kafka_write_share_group_state_response(
            &truncated_write_share_group_state_response,
            1,
            &config,
        )
        .unwrap_err(),
        KafkaExtraction::MalformedFrame
    );

    let mut truncated_delete_share_group_state_response =
        kafka_delete_share_group_state_response_frame(
            0,
            &[DeleteShareGroupStateResultTopicFixture {
                topic_id: [29_u8; 16],
                partitions: &[DeleteShareGroupStateResultPartitionFixture {
                    partition: 1,
                    error_code: 35,
                    error_message: Some("secret message"),
                }],
            }],
        );
    truncated_delete_share_group_state_response.truncate(18);
    assert_eq!(
        parse_kafka_delete_share_group_state_response(
            &truncated_delete_share_group_state_response,
            0,
            &config,
        )
        .unwrap_err(),
        KafkaExtraction::MalformedFrame
    );

    let mut truncated_read_share_group_state_summary_response =
        kafka_read_share_group_state_summary_response_frame(
            0,
            &[ReadShareGroupStateSummaryResultTopicFixture {
                topic_id: [29_u8; 16],
                partitions: &[ReadShareGroupStateSummaryResultPartitionFixture {
                    partition: 1,
                    error_code: 35,
                    error_message: Some("secret message"),
                    state_epoch: 5,
                    leader_epoch: 2,
                    start_offset: 100,
                    delivery_complete_count: Some(200),
                }],
            }],
            1,
        );
    truncated_read_share_group_state_summary_response.truncate(18);
    assert_eq!(
        parse_kafka_read_share_group_state_summary_response(
            &truncated_read_share_group_state_summary_response,
            1,
            &config,
        )
        .unwrap_err(),
        KafkaExtraction::MalformedFrame
    );

    let mut truncated_delete_share_group_offsets_response =
        kafka_delete_share_group_offsets_response_frame(
            0,
            0,
            None,
            &[("orders.secret", [29_u8; 16], 6, Some("secret message"))],
        );
    truncated_delete_share_group_offsets_response.truncate(18);
    assert_eq!(
        parse_kafka_delete_share_group_offsets_response(
            &truncated_delete_share_group_offsets_response,
            0,
            &config,
        )
        .unwrap_err(),
        KafkaExtraction::MalformedFrame
    );
    assert_eq!(
        parse_kafka_delete_share_group_offsets_response(
            &kafka_delete_share_group_offsets_response_frame(0, 6, Some("secret message"), &[],),
            0,
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
        parse_kafka_delete_share_group_offsets_response(
            &kafka_delete_share_group_offsets_response_with_topic_count_frame(1025),
            0,
            &config,
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );

    let describe_share_group_offsets_error_partitions: &[DescribeShareGroupOffsetsResponsePartitionFixture<'_>] =
        &[(3, -1, -1, 6, Some("secret message"))];
    let describe_share_group_offsets_error_topics: &[DescribeShareGroupOffsetsResponseTopicFixture<'_>] =
        &[(
            "orders.secret",
            [29_u8; 16],
            describe_share_group_offsets_error_partitions,
        )];
    let describe_share_group_offsets_error_groups: &[DescribeShareGroupOffsetsResponseGroupFixture<'_>] =
        &[(
            "group.secret",
            describe_share_group_offsets_error_topics,
            0,
            None,
        )];
    let mut truncated_describe_share_group_offsets_response =
        kafka_describe_share_group_offsets_response_frame(
            0,
            0,
            describe_share_group_offsets_error_groups,
        );
    truncated_describe_share_group_offsets_response.truncate(18);
    assert_eq!(
        parse_kafka_describe_share_group_offsets_response(
            &truncated_describe_share_group_offsets_response,
            0,
            &config,
        )
        .unwrap_err(),
        KafkaExtraction::MalformedFrame
    );
    assert_eq!(
        parse_kafka_describe_share_group_offsets_response(
            &kafka_describe_share_group_offsets_response_frame(
                0,
                0,
                describe_share_group_offsets_error_groups,
            ),
            0,
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
        parse_kafka_describe_share_group_offsets_response(
            &kafka_describe_share_group_offsets_response_with_group_count_frame(1025),
            0,
            &config,
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );

    let mut truncated_join_group_response =
        kafka_join_group_response_frame(0, 2, 25, &[("member", b"metadata")]);
    truncated_join_group_response.truncate(14);
    assert_eq!(
        parse_kafka_join_group_response(&truncated_join_group_response, 2, &config).unwrap_err(),
        KafkaExtraction::MalformedFrame
    );

    let mut truncated_find_coordinator_response =
        kafka_find_coordinator_response_frame(0, 2, 15, Some("coordinator"));
    truncated_find_coordinator_response.truncate(16);
    assert_eq!(
        parse_kafka_find_coordinator_response(&truncated_find_coordinator_response, 2, &config)
            .unwrap_err(),
        KafkaExtraction::MalformedFrame
    );

    let mut truncated_heartbeat_response = kafka_heartbeat_response_frame(0, 3, 27);
    truncated_heartbeat_response.truncate(8);
    assert_eq!(
        parse_kafka_heartbeat_response(&truncated_heartbeat_response, 3, &config).unwrap_err(),
        KafkaExtraction::MalformedFrame
    );

    let mut truncated_leave_group_response =
        kafka_leave_group_response_frame(0, 3, 0, &[("member", None, 25)]);
    truncated_leave_group_response.truncate(12);
    assert_eq!(
        parse_kafka_leave_group_response(&truncated_leave_group_response, 3, &config).unwrap_err(),
        KafkaExtraction::MalformedFrame
    );

    let mut truncated_sync_group_response = kafka_sync_group_response_frame(0, 3, 25, b"data");
    truncated_sync_group_response.truncate(12);
    assert_eq!(
        parse_kafka_sync_group_response(&truncated_sync_group_response, 3, &config).unwrap_err(),
        KafkaExtraction::MalformedFrame
    );

    let mut truncated_describe_groups_response =
        kafka_describe_groups_response_frame(0, 4, &[("group", 30, 0)]);
    truncated_describe_groups_response.truncate(20);
    assert_eq!(
        parse_kafka_describe_groups_response(&truncated_describe_groups_response, 4, &config)
            .unwrap_err(),
        KafkaExtraction::MalformedFrame
    );

    let mut truncated_list_groups_response =
        kafka_list_groups_response_frame(0, 3, 0, &[("group", "consumer")]);
    truncated_list_groups_response.truncate(12);
    assert_eq!(
        parse_kafka_list_groups_response(&truncated_list_groups_response, 3, &config).unwrap_err(),
        KafkaExtraction::MalformedFrame
    );

    let mut truncated_delete_groups_response =
        kafka_delete_groups_response_frame(0, &[("group", 30)]);
    truncated_delete_groups_response.truncate(12);
    assert_eq!(
        parse_kafka_delete_groups_response(&truncated_delete_groups_response, 1, &config)
            .unwrap_err(),
        KafkaExtraction::MalformedFrame
    );

    let mut truncated_sasl_handshake_response =
        kafka_sasl_handshake_response_frame(0, 33, &["PLAIN"]);
    truncated_sasl_handshake_response.truncate(10);
    assert_eq!(
        parse_kafka_sasl_handshake_response(&truncated_sasl_handshake_response, 1, &config)
            .unwrap_err(),
        KafkaExtraction::MalformedFrame
    );

    let mut truncated_sasl_authenticate_response =
        kafka_sasl_authenticate_response_frame(0, 1, 58, Some("denied"), b"blob");
    truncated_sasl_authenticate_response.truncate(12);
    assert_eq!(
        parse_kafka_sasl_authenticate_response(&truncated_sasl_authenticate_response, 1, &config)
            .unwrap_err(),
        KafkaExtraction::MalformedFrame
    );

    let mut truncated_init_producer_id_response = kafka_init_producer_id_response_frame(0, 1, 49);
    truncated_init_producer_id_response.truncate(12);
    assert_eq!(
        parse_kafka_init_producer_id_response(&truncated_init_producer_id_response, 1, &config)
            .unwrap_err(),
        KafkaExtraction::MalformedFrame
    );

    let mut truncated_add_partitions_to_txn_response =
        kafka_add_partitions_to_txn_response_frame(0, &[("orders", 53)]);
    truncated_add_partitions_to_txn_response.truncate(16);
    assert_eq!(
        parse_kafka_add_partitions_to_txn_response(
            &truncated_add_partitions_to_txn_response,
            1,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::MalformedFrame
    );

    let mut truncated_add_offsets_to_txn_response = kafka_throttled_error_response_frame(0, 49);
    truncated_add_offsets_to_txn_response.truncate(10);
    assert_eq!(
        parse_kafka_add_offsets_to_txn_response(&truncated_add_offsets_to_txn_response, 1, &config)
            .unwrap_err(),
        KafkaExtraction::MalformedFrame
    );

    let mut truncated_end_txn_response = kafka_throttled_error_response_frame(0, 48);
    truncated_end_txn_response.truncate(10);
    assert_eq!(
        parse_kafka_end_txn_response(&truncated_end_txn_response, 1, &config).unwrap_err(),
        KafkaExtraction::MalformedFrame
    );

    let mut truncated_write_txn_markers_response =
        kafka_write_txn_markers_response_frame(&[("orders", &[(0, 48)])]);
    truncated_write_txn_markers_response.truncate(16);
    assert_eq!(
        parse_kafka_write_txn_markers_response(&truncated_write_txn_markers_response, 1, &config)
            .unwrap_err(),
        KafkaExtraction::MalformedFrame
    );

    let mut truncated_txn_offset_commit_response =
        kafka_txn_offset_commit_response_frame(0, &[("orders", &[(0, 27)])]);
    truncated_txn_offset_commit_response.truncate(16);
    assert_eq!(
        parse_kafka_txn_offset_commit_response(&truncated_txn_offset_commit_response, 1, &config)
            .unwrap_err(),
        KafkaExtraction::MalformedFrame
    );

    let mut truncated_metadata_response = kafka_metadata_response_frame(0, 8, &[("orders", 6, 0)]);
    truncated_metadata_response.truncate(24);
    assert_eq!(
        parse_kafka_metadata_response(&truncated_metadata_response, 8, &config).unwrap_err(),
        KafkaExtraction::MalformedFrame
    );

    assert_eq!(
        parse_kafka_request(&kafka_request_frame(3, 9, Some(b"bad-\xff"), b""), &config)
            .unwrap_err(),
        KafkaExtraction::InvalidUtf8
    );
}
