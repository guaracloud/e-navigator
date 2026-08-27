#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    reason = "integration tests use panic-oriented assertions for failed contracts"
)]

use e_navigator_protocol::{
    ProtocolExtractionConfig,
    grpc::{GrpcExtraction, parse_grpc_request_headers, parse_grpc_response_trailers},
    http::{HttpExtraction, parse_http_request, parse_http_response},
    kafka::{
        KafkaExtraction, parse_kafka_add_offsets_to_txn_response,
        parse_kafka_add_partitions_to_txn_response, parse_kafka_add_raft_voter_response,
        parse_kafka_allocate_producer_ids_response, parse_kafka_alter_client_quotas_response,
        parse_kafka_alter_configs_response, parse_kafka_alter_partition_reassignments_response,
        parse_kafka_alter_replica_log_dirs_response,
        parse_kafka_alter_user_scram_credentials_response, parse_kafka_api_versions_response,
        parse_kafka_broker_heartbeat_response, parse_kafka_consumer_group_describe_response,
        parse_kafka_consumer_group_heartbeat_response,
        parse_kafka_controller_registration_response, parse_kafka_create_acls_response,
        parse_kafka_create_delegation_token_response, parse_kafka_create_partitions_response,
        parse_kafka_create_topics_response, parse_kafka_delete_acls_response,
        parse_kafka_delete_groups_response, parse_kafka_delete_records_response,
        parse_kafka_delete_share_group_offsets_response,
        parse_kafka_delete_share_group_state_response, parse_kafka_delete_topics_response,
        parse_kafka_describe_acls_response, parse_kafka_describe_client_quotas_response,
        parse_kafka_describe_cluster_response, parse_kafka_describe_configs_response,
        parse_kafka_describe_delegation_token_response, parse_kafka_describe_groups_response,
        parse_kafka_describe_log_dirs_response, parse_kafka_describe_producers_response,
        parse_kafka_describe_quorum_response, parse_kafka_describe_share_group_offsets_response,
        parse_kafka_describe_topic_partitions_response, parse_kafka_describe_transactions_response,
        parse_kafka_describe_user_scram_credentials_response, parse_kafka_elect_leaders_response,
        parse_kafka_end_txn_response, parse_kafka_expire_delegation_token_response,
        parse_kafka_fetch_response, parse_kafka_find_coordinator_response,
        parse_kafka_get_telemetry_subscriptions_response, parse_kafka_heartbeat_response,
        parse_kafka_incremental_alter_configs_response, parse_kafka_init_producer_id_response,
        parse_kafka_initialize_share_group_state_response, parse_kafka_join_group_response,
        parse_kafka_leave_group_response, parse_kafka_list_config_resources_response,
        parse_kafka_list_groups_response, parse_kafka_list_offsets_response,
        parse_kafka_list_partition_reassignments_response, parse_kafka_list_transactions_response,
        parse_kafka_metadata_response, parse_kafka_offset_commit_response,
        parse_kafka_offset_delete_response, parse_kafka_offset_fetch_response,
        parse_kafka_offset_for_leader_epoch_response, parse_kafka_produce_response,
        parse_kafka_push_telemetry_response, parse_kafka_read_share_group_state_response,
        parse_kafka_read_share_group_state_summary_response,
        parse_kafka_remove_raft_voter_response, parse_kafka_renew_delegation_token_response,
        parse_kafka_request, parse_kafka_request_correlation_id,
        parse_kafka_response_correlation_id, parse_kafka_response_for_api_key,
        parse_kafka_sasl_authenticate_response, parse_kafka_sasl_handshake_response,
        parse_kafka_share_group_heartbeat_response, parse_kafka_sync_group_response,
        parse_kafka_txn_offset_commit_response, parse_kafka_unregister_broker_response,
        parse_kafka_update_features_response, parse_kafka_update_raft_voter_response,
        parse_kafka_write_share_group_state_response, parse_kafka_write_txn_markers_response,
    },
    mongodb::{
        MongodbExtraction, MongodbResponseLifecycle, MongodbResponseProgress,
        parse_mongodb_message, parse_mongodb_response,
    },
    mysql::{
        MYSQL_MAX_PHYSICAL_PAYLOAD_BYTES, MysqlClientPacketProgress, MysqlCompressionAlgorithm,
        MysqlCompressionExtraction, MysqlExtraction, MysqlLogicalPacketProgress,
        MysqlResponseLifecycle, MysqlResponseProgress, decode_mysql_compressed_packet,
        negotiate_mysql_compression, parse_mysql_client_handshake_response, parse_mysql_command,
        parse_mysql_command_prefix, parse_mysql_error_response, parse_mysql_response,
        parse_mysql_server_greeting,
    },
    nats::{NatsExtraction, parse_nats_command, parse_nats_response},
    postgres::{
        PostgresExtraction, PostgresRequestLifecycle, PostgresRequestProgress,
        PostgresSimpleQueryLifecycle, PostgresSimpleQueryProgress, PostgresStartupKind,
        PostgresStartupLifecycle, PostgresStartupProgress, parse_postgres_error_response,
        parse_postgres_message, parse_postgres_response, parse_postgres_startup_message,
    },
    redis::{
        RedisExtraction, RedisResponseRole, RedisSubscriptionState, parse_redis_command,
        parse_redis_response, redis_connection_response_role, redis_response_role,
    },
    trace_context::{TraceContextError, parse_traceparent},
};
use e_navigator_signals::ProtocolKind;
use flate2::{Compression, write::ZlibEncoder};
use proptest::prelude::*;
use std::io::Write as _;

const VALID_TRACEPARENT: &str = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn valid_lowercase_traceparents_parse(
        version in lower_hex_string(2).prop_filter("reserved version is invalid", |value| value != "ff"),
        trace_id in non_zero_lower_hex_string(32),
        span_id in non_zero_lower_hex_string(16),
        flags in lower_hex_string(2),
    ) {
        let value = format!("{version}-{trace_id}-{span_id}-{flags}");

        let parsed = parse_traceparent(&value).expect("valid lowercase traceparent parses");

        prop_assert_eq!(parsed.version, version);
        prop_assert_eq!(parsed.trace_id, trace_id);
        prop_assert_eq!(parsed.span_id, span_id);
        prop_assert_eq!(parsed.flags, flags);
    }

    #[test]
    fn malformed_traceparent_lengths_reject(
        trace_id in lower_hex_string(0..40).prop_filter("exclude valid trace id length", |value| value.len() != 32),
        span_id in lower_hex_string(0..24).prop_filter("exclude valid span id length", |value| value.len() != 16),
        flags in lower_hex_string(0..6).prop_filter("exclude valid flags length", |value| value.len() != 2),
    ) {
        prop_assert_eq!(
            parse_traceparent(&format!("00-{trace_id}-00f067aa0ba902b7-01")).unwrap_err(),
            TraceContextError::Malformed
        );
        prop_assert_eq!(
            parse_traceparent(&format!("00-4bf92f3577b34da6a3ce929d0e0e4736-{span_id}-01")).unwrap_err(),
            TraceContextError::Malformed
        );
        prop_assert_eq!(
            parse_traceparent(&format!("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-{flags}")).unwrap_err(),
            TraceContextError::Malformed
        );
    }

    #[test]
    fn uppercase_traceparent_hex_rejects(
        trace_id in uppercase_hex_string(32),
        span_id in uppercase_hex_string(16),
        flags in uppercase_hex_string(2),
    ) {
        prop_assume!(trace_id.bytes().any(|byte| byte.is_ascii_uppercase()));
        prop_assume!(span_id.bytes().any(|byte| byte.is_ascii_uppercase()));
        prop_assume!(flags.bytes().any(|byte| byte.is_ascii_uppercase()));

        prop_assert_eq!(
            parse_traceparent(&format!("00-{trace_id}-00f067aa0ba902b7-01")).unwrap_err(),
            TraceContextError::InvalidHex
        );
        prop_assert_eq!(
            parse_traceparent(&format!("00-4bf92f3577b34da6a3ce929d0e0e4736-{span_id}-01")).unwrap_err(),
            TraceContextError::InvalidHex
        );
        prop_assert_eq!(
            parse_traceparent(&format!("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-{flags}")).unwrap_err(),
            TraceContextError::InvalidHex
        );
    }

    #[test]
    fn wrong_traceparent_separators_reject(separator in "[/:_| ]") {
        let value = format!(
            "00{separator}4bf92f3577b34da6a3ce929d0e0e4736{separator}00f067aa0ba902b7{separator}01"
        );

        prop_assert_eq!(parse_traceparent(&value).unwrap_err(), TraceContextError::Malformed);
    }

    #[test]
    fn arbitrary_http_fixture_bytes_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..=512)) {
        let config = ProtocolExtractionConfig {
            max_header_bytes: 256,
            max_request_line_bytes: 64,
            max_attributes: 2,
            max_tracestate_bytes: 32,
        };

        let _ = parse_http_request(&bytes, &config);
    }

    #[test]
    fn arbitrary_http_response_bytes_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..=512)) {
        let config = ProtocolExtractionConfig {
            max_header_bytes: 256,
            max_request_line_bytes: 64,
            max_attributes: 2,
            max_tracestate_bytes: 32,
        };

        let _ = parse_http_response(&bytes, &config);
    }

    #[test]
    fn arbitrary_grpc_header_bytes_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..=512)) {
        let config = ProtocolExtractionConfig {
            max_header_bytes: 256,
            max_request_line_bytes: 64,
            max_attributes: 3,
            max_tracestate_bytes: 32,
        };

        let _ = parse_grpc_request_headers(&bytes, &config);
    }

    #[test]
    fn arbitrary_grpc_trailer_bytes_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..=512)) {
        let config = ProtocolExtractionConfig {
            max_header_bytes: 256,
            max_request_line_bytes: 64,
            max_attributes: 2,
            max_tracestate_bytes: 32,
        };

        let _ = parse_grpc_response_trailers(&bytes, &config);
    }

    #[test]
    fn http_fixture_limits_are_respected(
        path in "[A-Za-z0-9/_-]{0,40}",
        tracestate in "[a-z0-9=,._-]{0,80}",
    ) {
        let bytes = format!(
            "GET /{path} HTTP/1.1\r\nTraceparent: {VALID_TRACEPARENT}\r\nTracestate: {tracestate}\r\nAuthorization: Bearer secret\r\nCookie: session=secret\r\n\r\n"
        );
        let config = ProtocolExtractionConfig {
            max_header_bytes: 256,
            max_request_line_bytes: 64,
            max_attributes: 1,
            max_tracestate_bytes: 16,
        };

        let parsed = parse_http_request(bytes.as_bytes(), &config);
        if let Ok(parsed) = parsed {
            prop_assert!(parsed.attributes.len() <= config.max_attributes);
            prop_assert!(parsed
                .tracestate
                .as_ref()
                .is_none_or(|value| value.len() <= config.max_tracestate_bytes));
            prop_assert!(!parsed
                .attributes
                .iter()
                .any(|attribute| attribute.value.contains("secret")));
        }
    }

    #[test]
    fn http_response_limits_are_respected(
        status in 100u16..=599,
        reason in "[A-Za-z0-9_.=/%+-]{0,80}",
    ) {
        let bytes = format!(
            "HTTP/1.1 {status} {reason}\r\nSet-Cookie: session=secret\r\nX-Error-Detail: {reason}\r\n\r\nbody"
        );
        let config = ProtocolExtractionConfig {
            max_header_bytes: 256,
            max_request_line_bytes: 128,
            max_attributes: 1,
            max_tracestate_bytes: 32,
        };

        let parsed = parse_http_response(bytes.as_bytes(), &config)
            .expect("bounded http response parses");
        prop_assert_eq!(parsed.status_code, status);
        prop_assert!(parsed.attributes.len() <= config.max_attributes);
        prop_assert!(!parsed
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("secret")));
    }

    #[test]
    fn arbitrary_redis_fixture_bytes_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..=512)) {
        let config = ProtocolExtractionConfig {
            max_header_bytes: 256,
            max_request_line_bytes: 64,
            max_attributes: 4,
            max_tracestate_bytes: 32,
        };

        let _ = parse_redis_command(&bytes, &config);
    }

    #[test]
    fn arbitrary_redis_response_bytes_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..=512)) {
        let config = ProtocolExtractionConfig {
            max_header_bytes: 256,
            max_request_line_bytes: 64,
            max_attributes: 4,
            max_tracestate_bytes: 32,
        };

        let _ = parse_redis_response(&bytes, &config);
    }

    #[test]
    fn redis_response_limits_are_respected(
        status in "[A-Za-z0-9_-]{1,64}",
        message in "[A-Za-z0-9_.=/%+-]{0,80}",
    ) {
        let bytes = format!("-{status} {message} secret-detail\r\n");
        let config = ProtocolExtractionConfig {
            max_header_bytes: 256,
            max_request_line_bytes: 64,
            max_attributes: 2,
            max_tracestate_bytes: 32,
        };

        let parsed = parse_redis_response(bytes.as_bytes(), &config)
            .expect("bounded redis error parses");
        let expected_status = status.to_ascii_uppercase();
        prop_assert_eq!(parsed.status_code.as_deref(), Some(expected_status.as_str()));
        prop_assert!(parsed.error_type.is_some());
        prop_assert!(parsed.attributes.len() <= config.max_attributes);
        prop_assert!(!parsed
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("secret")));
    }

    #[test]
    fn arbitrary_kafka_fixture_bytes_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..=512)) {
        let config = ProtocolExtractionConfig {
            max_header_bytes: 256,
            max_request_line_bytes: 64,
            max_attributes: 4,
            max_tracestate_bytes: 32,
        };

        let _ = parse_kafka_request(&bytes, &config);
    }

    #[test]
    fn arbitrary_kafka_response_bytes_never_panic(
        bytes in prop::collection::vec(any::<u8>(), 0..=512),
        api_version in 0i16..=4,
    ) {
        let config = ProtocolExtractionConfig {
            max_header_bytes: 256,
            max_request_line_bytes: 64,
            max_attributes: 4,
            max_tracestate_bytes: 32,
        };

        let _ = parse_kafka_api_versions_response(&bytes, api_version, &config);
        let _ = parse_kafka_create_topics_response(&bytes, api_version.clamp(2, 4), &config);
        let _ = parse_kafka_create_partitions_response(&bytes, api_version.min(1), &config);
        let _ = parse_kafka_create_acls_response(&bytes, 1, &config);
        let _ = parse_kafka_describe_acls_response(&bytes, 1, &config);
        let _ = parse_kafka_delete_acls_response(&bytes, 1, &config);
        let _ = parse_kafka_describe_configs_response(&bytes, api_version.clamp(1, 3), &config);
        let _ = parse_kafka_alter_configs_response(&bytes, api_version.min(1), &config);
        let _ = parse_kafka_alter_replica_log_dirs_response(&bytes, 1, &config);
        let _ = parse_kafka_describe_log_dirs_response(&bytes, 1, &config);
        let _ = parse_kafka_create_delegation_token_response(&bytes, 1, &config);
        let _ = parse_kafka_renew_delegation_token_response(&bytes, 1, &config);
        let _ = parse_kafka_expire_delegation_token_response(&bytes, 1, &config);
        let _ = parse_kafka_describe_delegation_token_response(&bytes, 1, &config);
        let _ = parse_kafka_elect_leaders_response(&bytes, api_version.min(1), &config);
        let _ = parse_kafka_incremental_alter_configs_response(&bytes, api_version.min(1), &config);
        let _ = parse_kafka_alter_partition_reassignments_response(&bytes, api_version.min(1), &config);
        let _ = parse_kafka_list_partition_reassignments_response(&bytes, 0, &config);
        let _ = parse_kafka_describe_client_quotas_response(&bytes, api_version.min(1), &config);
        let _ = parse_kafka_alter_client_quotas_response(&bytes, api_version.min(1), &config);
        let _ = parse_kafka_describe_user_scram_credentials_response(&bytes, 0, &config);
        let _ = parse_kafka_alter_user_scram_credentials_response(&bytes, 0, &config);
        let _ = parse_kafka_describe_quorum_response(&bytes, api_version.min(2), &config);
        let _ = parse_kafka_update_features_response(&bytes, api_version.min(2), &config);
        let _ = parse_kafka_describe_cluster_response(&bytes, api_version.min(2), &config);
        let _ = parse_kafka_describe_producers_response(&bytes, 0, &config);
        let _ = parse_kafka_broker_heartbeat_response(&bytes, api_version.min(2), &config);
        let _ = parse_kafka_unregister_broker_response(&bytes, 0, &config);
        let _ = parse_kafka_describe_transactions_response(&bytes, 0, &config);
        let _ = parse_kafka_list_transactions_response(&bytes, api_version.min(2), &config);
        let _ = parse_kafka_allocate_producer_ids_response(&bytes, 0, &config);
        let _ = parse_kafka_consumer_group_heartbeat_response(&bytes, api_version.min(1), &config);
        let _ = parse_kafka_consumer_group_describe_response(&bytes, api_version.min(1), &config);
        let _ = parse_kafka_controller_registration_response(&bytes, 0, &config);
        let _ = parse_kafka_get_telemetry_subscriptions_response(&bytes, 0, &config);
        let _ = parse_kafka_push_telemetry_response(&bytes, 0, &config);
        let _ = parse_kafka_list_config_resources_response(&bytes, api_version.min(1), &config);
        let _ = parse_kafka_describe_topic_partitions_response(&bytes, 0, &config);
        let _ = parse_kafka_share_group_heartbeat_response(&bytes, 1, &config);
        let _ = parse_kafka_add_raft_voter_response(&bytes, api_version.min(1), &config);
        let _ = parse_kafka_remove_raft_voter_response(&bytes, 0, &config);
        let _ = parse_kafka_update_raft_voter_response(&bytes, 0, &config);
        let _ = parse_kafka_initialize_share_group_state_response(&bytes, 0, &config);
        let _ = parse_kafka_read_share_group_state_response(&bytes, 0, &config);
        let _ = parse_kafka_write_share_group_state_response(&bytes, api_version.min(1), &config);
        let _ = parse_kafka_delete_share_group_state_response(&bytes, 0, &config);
        let _ = parse_kafka_read_share_group_state_summary_response(
            &bytes,
            api_version.min(1),
            &config,
        );
        let _ = parse_kafka_delete_share_group_offsets_response(&bytes, 0, &config);
        let _ = parse_kafka_describe_share_group_offsets_response(&bytes, api_version.min(1), &config);
        let _ = parse_kafka_produce_response(&bytes, api_version.min(4), &config);
        let _ = parse_kafka_fetch_response(&bytes, api_version.min(5), &config);
        let _ = parse_kafka_offset_commit_response(&bytes, api_version.clamp(2, 7), &config);
        let _ = parse_kafka_list_offsets_response(&bytes, api_version.clamp(1, 5), &config);
        let _ = parse_kafka_delete_records_response(&bytes, api_version.min(1), &config);
        let _ = parse_kafka_delete_topics_response(&bytes, api_version.clamp(1, 3), &config);
        let _ = parse_kafka_offset_delete_response(&bytes, 0, &config);
        let _ = parse_kafka_offset_for_leader_epoch_response(
            &bytes,
            api_version.clamp(2, 4),
            &config,
        );
        let _ = parse_kafka_find_coordinator_response(&bytes, api_version.min(2), &config);
        let _ = parse_kafka_join_group_response(&bytes, api_version.clamp(0, 5), &config);
        let _ = parse_kafka_heartbeat_response(&bytes, api_version.min(3), &config);
        let _ = parse_kafka_leave_group_response(&bytes, api_version.min(3), &config);
        let _ = parse_kafka_sync_group_response(&bytes, api_version.min(3), &config);
        let _ = parse_kafka_describe_groups_response(&bytes, api_version.min(4), &config);
        let _ = parse_kafka_list_groups_response(&bytes, api_version.min(3), &config);
        let _ = parse_kafka_sasl_handshake_response(&bytes, api_version.min(1), &config);
        let _ = parse_kafka_add_offsets_to_txn_response(&bytes, api_version.min(2), &config);
        let _ = parse_kafka_add_partitions_to_txn_response(&bytes, api_version.min(2), &config);
        let _ = parse_kafka_end_txn_response(&bytes, api_version.min(2), &config);
        let _ = parse_kafka_write_txn_markers_response(&bytes, api_version.clamp(1, 2), &config);
        let _ = parse_kafka_txn_offset_commit_response(&bytes, api_version.min(2), &config);
        let _ = parse_kafka_sasl_authenticate_response(&bytes, api_version.min(1), &config);
        let _ = parse_kafka_metadata_response(&bytes, api_version.min(8), &config);
    }

    #[test]
    fn kafka_api_versions_response_limits_are_respected(
        error_code in 1i16..=1000,
    ) {
        let bytes = kafka_api_versions_response_frame(0, error_code, b"secret-broker-data");
        let config = ProtocolExtractionConfig {
            max_header_bytes: 256,
            max_request_line_bytes: 64,
            max_attributes: 3,
            max_tracestate_bytes: 32,
        };

        let parsed = parse_kafka_api_versions_response(&bytes, 0, &config)
            .expect("bounded kafka api versions response parses");
        let expected_status = error_code.to_string();
        prop_assert_eq!(parsed.status_code.as_str(), expected_status.as_str());
        prop_assert_eq!(parsed.error_type.as_deref(), Some(expected_status.as_str()));
        prop_assert!(parsed.attributes.len() <= config.max_attributes);
        prop_assert!(!parsed
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("secret")));
    }

    #[test]
    fn arbitrary_postgres_fixture_bytes_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..=512)) {
        let config = ProtocolExtractionConfig {
            max_header_bytes: 256,
            max_request_line_bytes: 64,
            max_attributes: 4,
            max_tracestate_bytes: 32,
        };

        let _ = parse_postgres_message(&bytes, &config);
    }

    #[test]
    fn arbitrary_postgres_startup_bytes_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..=512)) {
        let config = ProtocolExtractionConfig {
            max_header_bytes: 512,
            max_request_line_bytes: 128,
            max_attributes: 16,
            ..ProtocolExtractionConfig::default()
        };
        let _ = parse_postgres_startup_message(&bytes, &config);
    }

    #[test]
    fn arbitrary_postgres_response_bytes_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..=512)) {
        let config = ProtocolExtractionConfig {
            max_header_bytes: 256,
            max_request_line_bytes: 64,
            max_attributes: 4,
            max_tracestate_bytes: 32,
        };

        let _ = parse_postgres_response(&bytes, &config);
        let _ = parse_postgres_error_response(&bytes, &config);
    }

    #[test]
    fn arbitrary_postgres_simple_query_lifecycle_bytes_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..=512)) {
        let config = ProtocolExtractionConfig {
            max_header_bytes: 256,
            max_request_line_bytes: 64,
            max_attributes: 4,
            max_tracestate_bytes: 32,
        };
        let request = postgres_frame(b'Q', b"SELECT 1\0");
        let mut lifecycle = PostgresSimpleQueryLifecycle::from_request(&request, &config)
            .expect("bounded Query fixture parses");

        let _ = lifecycle.observe_response(&bytes, &config);
    }

    #[test]
    fn arbitrary_postgres_request_lifecycle_bytes_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..=512)) {
        let config = ProtocolExtractionConfig {
            max_header_bytes: 256,
            max_request_line_bytes: 64,
            max_attributes: 4,
            max_tracestate_bytes: 32,
        };
        let request = postgres_frame(b'E', &[0; 5]);
        let mut lifecycle = PostgresRequestLifecycle::from_request(&request, &config)
            .expect("bounded Execute fixture parses");

        let _ = lifecycle.observe_response(&bytes, &config);
    }

    #[test]
    fn postgres_error_response_limits_are_respected(
        sqlstate in "[A-Z0-9]{5}",
        message in "[A-Za-z0-9_.=/%+-]{0,80}",
    ) {
        let bytes = postgres_error_response_frame(sqlstate.as_bytes(), message.as_bytes());
        let config = ProtocolExtractionConfig {
            max_header_bytes: 256,
            max_request_line_bytes: 64,
            max_attributes: 2,
            max_tracestate_bytes: 32,
        };

        let parsed = parse_postgres_error_response(&bytes, &config)
            .expect("bounded postgres error parses");
        prop_assert_eq!(parsed.status_code.as_str(), sqlstate.as_str());
        prop_assert_eq!(parsed.error_type.as_deref(), Some(parsed.status_code.as_str()));
        prop_assert!(parsed.attributes.len() <= config.max_attributes);
        prop_assert!(!parsed
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("secret")));
    }

    #[test]
    fn arbitrary_mysql_fixture_bytes_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..=512)) {
        let config = ProtocolExtractionConfig {
            max_header_bytes: 256,
            max_request_line_bytes: 64,
            max_attributes: 4,
            max_tracestate_bytes: 32,
        };

        let _ = parse_mysql_command(&bytes, &config);
    }

    #[test]
    fn arbitrary_mysql_response_bytes_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..=512)) {
        let config = ProtocolExtractionConfig {
            max_header_bytes: 256,
            max_request_line_bytes: 64,
            max_attributes: 4,
            max_tracestate_bytes: 32,
        };

        let _ = parse_mysql_response(&bytes, &config);
        let _ = parse_mysql_error_response(&bytes, &config);
    }

    #[test]
    fn arbitrary_mysql_handshake_and_compression_bytes_never_panic(
        bytes in prop::collection::vec(any::<u8>(), 0..=512),
        max_payload_bytes in 0usize..=512,
    ) {
        let _ = parse_mysql_server_greeting(&bytes, max_payload_bytes);
        let _ = parse_mysql_client_handshake_response(&bytes, max_payload_bytes);
        let _ = decode_mysql_compressed_packet(&bytes, max_payload_bytes);
    }

    #[test]
    fn arbitrary_mysql_lifecycle_packet_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..=512)) {
        let config = ProtocolExtractionConfig {
            max_header_bytes: 256,
            max_request_line_bytes: 64,
            max_attributes: 4,
            max_tracestate_bytes: 32,
        };
        let mut lifecycle = MysqlResponseLifecycle::from_request(
            &[1, 0, 0, 0, 0x0e],
            &config,
        )
        .expect("bounded PING request starts a lifecycle");

        let _ = lifecycle.observe_packet(&bytes, &config);
    }

    #[test]
    fn arbitrary_mysql_local_infile_client_packet_never_panics(
        bytes in prop::collection::vec(any::<u8>(), 0..=512),
        declared_total_len in any::<u64>(),
    ) {
        let config = ProtocolExtractionConfig::default();
        let request = mysql_packet(0x03, b"LOAD DATA LOCAL INFILE 'fixture'");
        let mut lifecycle = MysqlResponseLifecycle::from_request(&request, &config)
            .expect("fixture query starts lifecycle");
        lifecycle
            .observe_packet(
                &mysql_packet_with_sequence(1, b"\xfbfixture"),
                &config,
            )
            .expect("fixture enters upload state");

        let _ = lifecycle.observe_client_packet(&bytes, declared_total_len);
    }

    #[test]
    fn arbitrary_mysql_logical_packet_prefix_never_panics(
        bytes in prop::collection::vec(any::<u8>(), 0..=512),
        declared_total_len in any::<u64>(),
    ) {
        let config = ProtocolExtractionConfig::default();
        let _ = parse_mysql_command_prefix(&bytes, declared_total_len, &config);

        let first_prefix = [0xff, 0xff, 0xff, 0, 0x03, b'S', b'E', b'L', b'E', b'C', b'T'];
        let mut lifecycle = MysqlResponseLifecycle::from_request_prefix(
            &first_prefix,
            (MYSQL_MAX_PHYSICAL_PAYLOAD_BYTES + 4) as u64,
            &config,
        )
        .expect("bounded large query fixture starts a lifecycle");
        let _ = lifecycle.observe_request_continuation(&bytes, declared_total_len);

        let mut response_lifecycle = MysqlResponseLifecycle::from_request(
            &mysql_packet(0x03, b"SELECT 1"),
            &config,
        )
        .expect("bounded query fixture starts a response lifecycle");
        let _ = response_lifecycle.observe_response_prefix(&bytes, declared_total_len);
    }

    #[test]
    fn mysql_error_response_limits_are_respected(
        vendor_code in 1u16..=65535,
        sqlstate in "[A-Z0-9]{5}",
        message in "[A-Za-z0-9_.=/%+-]{0,80}",
    ) {
        let bytes = mysql_error_packet(vendor_code, Some(sqlstate.as_bytes()), message.as_bytes());
        let config = ProtocolExtractionConfig {
            max_header_bytes: 256,
            max_request_line_bytes: 64,
            max_attributes: 2,
            max_tracestate_bytes: 32,
        };

        let parsed = parse_mysql_error_response(&bytes, &config)
            .expect("bounded mysql error parses");
        let expected_status = format!("{sqlstate}/{vendor_code}");
        prop_assert_eq!(parsed.status_code.as_str(), expected_status.as_str());
        prop_assert_eq!(parsed.error_type.as_deref(), Some(parsed.status_code.as_str()));
        prop_assert!(parsed.attributes.len() <= config.max_attributes);
        prop_assert!(!parsed
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("secret")));
    }

    #[test]
    fn arbitrary_mongodb_fixture_bytes_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..=512)) {
        let config = ProtocolExtractionConfig {
            max_header_bytes: 256,
            max_request_line_bytes: 64,
            max_attributes: 4,
            max_tracestate_bytes: 32,
        };

        let _ = parse_mongodb_message(&bytes, &config);
    }

    #[test]
    fn arbitrary_mongodb_response_bytes_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..=512)) {
        let config = ProtocolExtractionConfig {
            max_header_bytes: 256,
            max_request_line_bytes: 64,
            max_attributes: 4,
            max_tracestate_bytes: 32,
        };

        let _ = parse_mongodb_response(&bytes, &config);
    }

    #[test]
    fn mongodb_response_limits_are_respected(
        code in 1i32..=65535,
        message in "[A-Za-z0-9_.=/%+-]{0,40}",
    ) {
        let bytes = mongodb_op_msg(&bson_mongodb_error_document(code, message.as_bytes()));
        let config = ProtocolExtractionConfig {
            max_header_bytes: 256,
            max_request_line_bytes: 128,
            max_attributes: 2,
            max_tracestate_bytes: 32,
        };

        let parsed = parse_mongodb_response(&bytes, &config)
            .expect("bounded mongodb error parses");
        let expected_status = code.to_string();
        prop_assert_eq!(parsed.status_code.as_str(), expected_status.as_str());
        prop_assert_eq!(parsed.error_type.as_deref(), Some(expected_status.as_str()));
        prop_assert!(parsed.attributes.len() <= config.max_attributes);
        prop_assert!(!parsed
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("secret")));
    }

    #[test]
    fn arbitrary_nats_fixture_bytes_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..=512)) {
        let config = ProtocolExtractionConfig {
            max_header_bytes: 256,
            max_request_line_bytes: 64,
            max_attributes: 4,
            max_tracestate_bytes: 32,
        };

        let _ = parse_nats_command(&bytes, &config);
    }

    #[test]
    fn arbitrary_nats_response_bytes_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..=512)) {
        let config = ProtocolExtractionConfig {
            max_header_bytes: 256,
            max_request_line_bytes: 64,
            max_attributes: 4,
            max_tracestate_bytes: 32,
        };

        let _ = parse_nats_response(&bytes, &config);
    }

    #[test]
    fn nats_response_limits_are_respected(
        message in "[A-Za-z0-9_.=/%+-]{0,40}",
    ) {
        let bytes = format!("-ERR {message} secret-detail\r\n");
        let config = ProtocolExtractionConfig {
            max_header_bytes: 256,
            max_request_line_bytes: 96,
            max_attributes: 2,
            max_tracestate_bytes: 32,
        };

        let parsed = parse_nats_response(bytes.as_bytes(), &config)
            .expect("bounded nats error parses");
        prop_assert_eq!(parsed.status_code.as_str(), "ERR");
        prop_assert_eq!(parsed.error_type.as_deref(), Some("nats_error"));
        prop_assert!(parsed.attributes.len() <= config.max_attributes);
        prop_assert!(!parsed
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("secret")));
    }

    #[test]
    fn grpc_fixture_limits_are_respected(
        service in "[A-Za-z0-9_.-]{1,40}",
        method in "[A-Za-z0-9_.-]{1,40}",
        tracestate in "[a-z0-9=,._-]{0,80}",
    ) {
        let bytes = format!(
            ":method: POST\n:path: /{service}/{method}\n:authority: checkout.example.com:443\ncontent-type: application/grpc\ntraceparent: {VALID_TRACEPARENT}\ntracestate: {tracestate}\nauthorization: Bearer secret\n\n"
        );
        let config = ProtocolExtractionConfig {
            max_header_bytes: 512,
            max_request_line_bytes: 64,
            max_attributes: 3,
            max_tracestate_bytes: 16,
        };

        let parsed = parse_grpc_request_headers(bytes.as_bytes(), &config)
            .expect("bounded grpc headers parse");
        prop_assert!(parsed.attributes.len() <= config.max_attributes);
        prop_assert!(parsed
            .tracestate
            .as_ref()
            .is_none_or(|value| value.len() <= config.max_tracestate_bytes));
        prop_assert!(!parsed
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("secret")));
    }

    #[test]
    fn grpc_trailer_limits_are_respected(
        status in 0u8..=16,
        message in "[A-Za-z0-9_.=/%+-]{0,80}",
    ) {
        let bytes = format!(
            "grpc-status: {status}\ngrpc-message: {message}\ngrpc-status-details-bin: c2VjcmV0\n\n"
        );
        let config = ProtocolExtractionConfig {
            max_header_bytes: 256,
            max_request_line_bytes: 64,
            max_attributes: 1,
            max_tracestate_bytes: 32,
        };

        let parsed = parse_grpc_response_trailers(bytes.as_bytes(), &config)
            .expect("bounded grpc trailers parse");
        prop_assert_eq!(parsed.status_code, u16::from(status));
        prop_assert!(parsed.attributes.len() <= config.max_attributes);
        prop_assert!(!parsed
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("secret")));
    }
}

#[test]
fn parses_valid_w3c_traceparent_strictly() {
    let context = parse_traceparent(VALID_TRACEPARENT).expect("traceparent parses");

    assert_eq!(context.version, "00");
    assert_eq!(context.trace_id, "4bf92f3577b34da6a3ce929d0e0e4736");
    assert_eq!(context.span_id, "00f067aa0ba902b7");
    assert_eq!(context.flags, "01");
}

#[test]
fn rejects_malformed_traceparents_and_all_zero_ids() {
    assert_eq!(
        parse_traceparent("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7").unwrap_err(),
        TraceContextError::Malformed
    );
    assert_eq!(
        parse_traceparent("00-zzzz2f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01").unwrap_err(),
        TraceContextError::InvalidHex
    );
    assert_eq!(
        parse_traceparent("00-4BF92F3577B34DA6A3CE929D0E0E4736-00f067aa0ba902b7-01").unwrap_err(),
        TraceContextError::InvalidHex
    );
    assert_eq!(
        parse_traceparent("ff-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01").unwrap_err(),
        TraceContextError::ReservedVersion
    );
    assert_eq!(
        parse_traceparent("00-00000000000000000000000000000000-00f067aa0ba902b7-01").unwrap_err(),
        TraceContextError::AllZeroTraceId
    );
    assert_eq!(
        parse_traceparent("00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01").unwrap_err(),
        TraceContextError::AllZeroSpanId
    );
}

#[test]
fn rejects_traceparent_length_and_separator_variants() {
    for value in [
        "",
        "00",
        "00-4bf92f3577b34da6a3ce929d0e0e473-00f067aa0ba902b7-01",
        "00-4bf92f3577b34da6a3ce929d0e0e473600-00f067aa0ba902b7-01",
        "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902-01",
        "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b700-01",
        "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-0",
        "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-011",
        "00:4bf92f3577b34da6a3ce929d0e0e4736:00f067aa0ba902b7:01",
        " 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
        "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01 ",
    ] {
        assert_eq!(
            parse_traceparent(value).unwrap_err(),
            TraceContextError::Malformed,
            "{value:?}"
        );
    }
}

#[test]
fn extracts_http_request_trace_context_from_bounded_fixture() {
    let bytes = b"GET /checkout/123 HTTP/1.1\r\nHost: api.example.com\r\nTraceparent: 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01\r\nTracestate: vendor=value\r\nAuthorization: Bearer secret\r\n\r\n";

    let extraction = parse_http_request(bytes, &ProtocolExtractionConfig::default())
        .expect("http request parses");

    assert_eq!(extraction.protocol, ProtocolKind::Http);
    assert_eq!(extraction.method.as_deref(), Some("GET"));
    assert_eq!(
        extraction.trace_context.as_ref().unwrap().trace_id,
        "4bf92f3577b34da6a3ce929d0e0e4736"
    );
    assert_eq!(
        extraction.trace_context.as_ref().unwrap().span_id,
        "00f067aa0ba902b7"
    );
    assert_eq!(extraction.tracestate.as_deref(), Some("vendor=value"));
    assert!(
        extraction.attributes.iter().any(|attribute| {
            attribute.key == "http.request.method" && attribute.value == "GET"
        })
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| { attribute.key == "url.path" && attribute.value == "/checkout/123" })
    );
}

#[test]
fn extracts_grpc_request_trace_context_from_decoded_http2_headers() {
    let bytes = b":method: POST\n:path: /checkout.v1.CheckoutService/GetCart\n:authority: checkout.example.com:8443\ncontent-type: application/grpc+proto\ntraceparent: 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01\ntracestate: vendor=value\nauthorization: Bearer secret\n\n";

    let extraction = parse_grpc_request_headers(bytes, &ProtocolExtractionConfig::default())
        .expect("grpc request headers parse");

    assert_eq!(extraction.protocol, ProtocolKind::Grpc);
    assert_eq!(extraction.method.as_deref(), Some("GetCart"));
    assert_eq!(
        extraction.trace_context.as_ref().unwrap().trace_id,
        "4bf92f3577b34da6a3ce929d0e0e4736"
    );
    assert_eq!(
        extraction.trace_context.as_ref().unwrap().span_id,
        "00f067aa0ba902b7"
    );
    assert_eq!(extraction.tracestate.as_deref(), Some("vendor=value"));
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "rpc.system" && attribute.value == "grpc")
    );
    assert!(extraction.attributes.iter().any(|attribute| {
        attribute.key == "rpc.service" && attribute.value == "checkout.v1.CheckoutService"
    }));
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "rpc.method" && attribute.value == "GetCart")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "server.address"
                && attribute.value == "checkout.example.com")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "server.port" && attribute.value == "8443")
    );
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("secret"))
    );
}

#[test]
fn extracts_grpc_status_from_decoded_http2_trailers() {
    let bytes = b"grpc-status: 13\ngrpc-message: internal%20database%20detail\ngrpc-status-details-bin: c2VjcmV0\n\n";

    let extraction = parse_grpc_response_trailers(bytes, &ProtocolExtractionConfig::default())
        .expect("grpc response trailers parse");

    assert_eq!(extraction.protocol, ProtocolKind::Grpc);
    assert_eq!(extraction.status_code, 13);
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| { attribute.key == "rpc.system" && attribute.value == "grpc" })
    );
    assert!(
        extraction.attributes.iter().any(|attribute| {
            attribute.key == "rpc.grpc.status_code" && attribute.value == "13"
        })
    );
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("database")
                || attribute.value.contains("c2VjcmV0"))
    );
}

#[test]
fn drops_malformed_grpc_authority_attributes() {
    for authority in [
        "checkout.example.com:70000",
        "checkout.example.com:notaport",
        "[2001:db8::1]invalid",
        "user@checkout.example.com",
        "checkout example.com",
        "checkout.example.com/path",
        "checkout\\example.com",
    ] {
        let bytes = format!(
            ":method: POST\n:path: /checkout.v1.CheckoutService/GetCart\n:authority: {authority}\ncontent-type: application/grpc\n\n"
        );
        let extraction =
            parse_grpc_request_headers(bytes.as_bytes(), &ProtocolExtractionConfig::default())
                .expect("grpc request headers parse without authority attributes");

        assert!(
            !extraction.attributes.iter().any(
                |attribute| attribute.key == "server.address" || attribute.key == "server.port"
            ),
            "{authority:?}"
        );
    }
}

#[test]
fn rejects_non_grpc_decoded_http2_headers() {
    for content_type in [
        "application/json",
        "application/grpc+",
        "application/grpc+proto; charset=utf-8",
    ] {
        let bytes = format!(":method: POST\n:path: /checkout\ncontent-type: {content_type}\n\n");

        assert_eq!(
            parse_grpc_request_headers(bytes.as_bytes(), &ProtocolExtractionConfig::default())
                .unwrap_err(),
            GrpcExtraction::MissingGrpcContentType,
            "{content_type:?}"
        );
    }
}

#[test]
fn rejects_grpc_headers_without_post_method() {
    for bytes in [
        b":path: /checkout.v1.CheckoutService/GetCart\ncontent-type: application/grpc\n\n"
            .as_slice(),
        b":method: GET\n:path: /checkout.v1.CheckoutService/GetCart\ncontent-type: application/grpc\n\n"
            .as_slice(),
    ] {
        assert_eq!(
            parse_grpc_request_headers(bytes, &ProtocolExtractionConfig::default()).unwrap_err(),
            GrpcExtraction::MissingGrpcMethod
        );
    }
}

#[test]
fn rejects_malformed_grpc_response_trailers() {
    let missing = b"grpc-message: no-status\n\n";
    let invalid = b"grpc-status: 17\n\n";
    let non_numeric = b"grpc-status: unavailable\n\n";

    assert_eq!(
        parse_grpc_response_trailers(missing, &ProtocolExtractionConfig::default()).unwrap_err(),
        GrpcExtraction::MissingGrpcStatus
    );
    assert_eq!(
        parse_grpc_response_trailers(invalid, &ProtocolExtractionConfig::default()).unwrap_err(),
        GrpcExtraction::InvalidGrpcStatus
    );
    assert_eq!(
        parse_grpc_response_trailers(non_numeric, &ProtocolExtractionConfig::default())
            .unwrap_err(),
        GrpcExtraction::InvalidGrpcStatus
    );
}

#[test]
fn reports_grpc_trace_context_warnings_without_inventing_ids() {
    let missing = b":method: POST\n:path: /checkout.v1.CheckoutService/GetCart\ncontent-type: application/grpc\n\n";
    let malformed = b":method: POST\n:path: /checkout.v1.CheckoutService/GetCart\ncontent-type: application/grpc\ntraceparent: 00-bad\n\n";

    let missing = parse_grpc_request_headers(missing, &ProtocolExtractionConfig::default())
        .expect("missing trace context still parses");
    let malformed = parse_grpc_request_headers(malformed, &ProtocolExtractionConfig::default())
        .expect("malformed trace context still parses");

    assert_eq!(missing.warning.as_deref(), Some("missing_trace_context"));
    assert!(missing.trace_context.is_none());
    assert_eq!(
        malformed.warning.as_deref(),
        Some("malformed_trace_context")
    );
    assert!(malformed.trace_context.is_none());
}

#[test]
fn extracts_http_request_path_without_query_or_fragment() {
    let bytes = b"GET /checkout/123?token=secret#frag HTTP/1.1\r\nHost: api.example.com\r\nTraceparent: 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01\r\n\r\n";

    let extraction = parse_http_request(bytes, &ProtocolExtractionConfig::default())
        .expect("http request parses");

    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| { attribute.key == "url.path" && attribute.value == "/checkout/123" })
    );
    assert!(!extraction
        .attributes
        .iter()
        .any(|attribute| attribute.value.contains("secret") || attribute.value.contains("frag")));
}

#[test]
fn extracts_http_response_status_without_reason_or_headers() {
    let bytes = b"HTTP/1.1 503 Service Unavailable\r\nSet-Cookie: session=secret\r\nX-Error-Detail: database offline\r\n\r\nbody";

    let extraction = parse_http_response(bytes, &ProtocolExtractionConfig::default())
        .expect("http response parses");

    assert_eq!(extraction.protocol, ProtocolKind::Http);
    assert_eq!(extraction.status_code, 503);
    assert!(extraction.attributes.iter().any(|attribute| {
        attribute.key == "http.response.status_code" && attribute.value == "503"
    }));
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("Service")
                || attribute.value.contains("database")
                || attribute.value.contains("secret"))
    );
}

#[test]
fn rejects_malformed_http_response_status_lines() {
    let missing = b"HTTP/1.1\r\n\r\n";
    let malformed_version = b"HTTP/x 200 OK\r\n\r\n";
    let non_numeric = b"HTTP/1.1 OK\r\n\r\n";
    let out_of_range = b"HTTP/1.1 700 custom\r\n\r\n";
    let request = b"GET /checkout HTTP/1.1\r\n\r\n";

    assert_eq!(
        parse_http_response(missing, &ProtocolExtractionConfig::default()).unwrap_err(),
        HttpExtraction::MalformedResponseLine
    );
    assert_eq!(
        parse_http_response(malformed_version, &ProtocolExtractionConfig::default()).unwrap_err(),
        HttpExtraction::MalformedResponseLine
    );
    assert_eq!(
        parse_http_response(non_numeric, &ProtocolExtractionConfig::default()).unwrap_err(),
        HttpExtraction::InvalidStatusCode
    );
    assert_eq!(
        parse_http_response(out_of_range, &ProtocolExtractionConfig::default()).unwrap_err(),
        HttpExtraction::InvalidStatusCode
    );
    assert_eq!(
        parse_http_response(request, &ProtocolExtractionConfig::default()).unwrap_err(),
        HttpExtraction::MalformedResponseLine
    );
}

#[test]
fn extracts_bounded_http_request_id_without_secret_headers() {
    let bytes = b"GET /checkout/123 HTTP/1.1\r\nHost: api.example.com\r\nTraceparent: 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01\r\nX-Request-ID: req-12345\r\nAuthorization: Bearer secret\r\nCookie: session=secret\r\n\r\n";

    let extraction = parse_http_request(bytes, &ProtocolExtractionConfig::default())
        .expect("http request parses");

    assert!(
        extraction.attributes.iter().any(|attribute| {
            attribute.key == "http.request.id" && attribute.value == "req-12345"
        })
    );
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("secret"))
    );
}

#[test]
fn drops_oversized_http_request_id_attribute() {
    let request_id = "r".repeat(129);
    let bytes = format!(
        "GET /checkout/123 HTTP/1.1\r\nTraceparent: {VALID_TRACEPARENT}\r\nX-Request-ID: {request_id}\r\n\r\n"
    );

    let extraction = parse_http_request(bytes.as_bytes(), &ProtocolExtractionConfig::default())
        .expect("http request parses");

    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "http.request.id")
    );
}

#[test]
fn extracts_bounded_http_host_authority_without_secret_headers() {
    let bytes = b"GET /checkout/123 HTTP/1.1\r\nHost: checkout.example.com:8443\r\nTraceparent: 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01\r\nAuthorization: Bearer secret\r\nCookie: session=secret\r\n\r\n";

    let extraction = parse_http_request(bytes, &ProtocolExtractionConfig::default())
        .expect("http request parses");

    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "server.address"
                && attribute.value == "checkout.example.com")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "server.port" && attribute.value == "8443")
    );
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("secret"))
    );
}

#[test]
fn extracts_http_connect_authority_form_without_header_values() {
    let bytes = b"CONNECT checkout.example.com:443 HTTP/1.1\r\nTraceparent: 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01\r\nAuthorization: Bearer secret\r\n\r\n";

    let extraction = parse_http_request(bytes, &ProtocolExtractionConfig::default())
        .expect("http connect parses");

    assert_eq!(extraction.method.as_deref(), Some("CONNECT"));
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "server.address"
                && attribute.value == "checkout.example.com")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "server.port" && attribute.value == "443")
    );
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "url.path" || attribute.value.contains("secret"))
    );
}

#[test]
fn extracts_absolute_form_http_target_path_and_authority_without_secrets() {
    let bytes = b"GET https://checkout.example.com:8443/orders/123?token=secret#frag HTTP/1.1\r\nTraceparent: 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01\r\nAuthorization: Bearer secret\r\nCookie: session=secret\r\n\r\n";

    let extraction = parse_http_request(bytes, &ProtocolExtractionConfig::default())
        .expect("http request parses");

    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| { attribute.key == "url.path" && attribute.value == "/orders/123" })
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "server.address"
                && attribute.value == "checkout.example.com")
    );
    assert!(
        extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "server.port" && attribute.value == "8443")
    );
    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.value.contains("secret") || attribute.value.contains("frag"))
    );
}

#[test]
fn drops_malformed_and_oversized_http_host_authority_attributes() {
    for host in [
        "user:pass@checkout.example.com",
        "checkout.example.com:not-a-port",
        "checkout.example.com:70000",
    ] {
        let bytes = format!(
            "GET /checkout/123 HTTP/1.1\r\nHost: {host}\r\nTraceparent: {VALID_TRACEPARENT}\r\n\r\n"
        );

        let extraction = parse_http_request(bytes.as_bytes(), &ProtocolExtractionConfig::default())
            .expect("http request parses");

        assert!(
            !extraction.attributes.iter().any(
                |attribute| attribute.key == "server.address" || attribute.key == "server.port"
            ),
            "{host:?}"
        );
    }

    let oversized_host = "h".repeat(254);
    let bytes = format!(
        "GET /checkout/123 HTTP/1.1\r\nHost: {oversized_host}\r\nTraceparent: {VALID_TRACEPARENT}\r\n\r\n"
    );

    let extraction = parse_http_request(bytes.as_bytes(), &ProtocolExtractionConfig::default())
        .expect("http request parses");

    assert!(
        !extraction
            .attributes
            .iter()
            .any(|attribute| attribute.key == "server.address" || attribute.key == "server.port")
    );
}

#[test]
fn drops_malformed_absolute_form_http_target_authority_attributes() {
    for target in [
        "ftp://checkout.example.com/orders/123",
        "https://user:pass@checkout.example.com/orders/123",
        "https://checkout.example.com:not-a-port/orders/123",
        "https://checkout.example.com:70000/orders/123",
    ] {
        let bytes = format!("GET {target} HTTP/1.1\r\nTraceparent: {VALID_TRACEPARENT}\r\n\r\n");

        let extraction = parse_http_request(bytes.as_bytes(), &ProtocolExtractionConfig::default())
            .expect("http request parses");

        assert!(
            !extraction
                .attributes
                .iter()
                .any(|attribute| attribute.key == "url.path"
                    || attribute.key == "server.address"
                    || attribute.key == "server.port"),
            "{target:?}"
        );
    }

    let oversized_host = "h".repeat(254);
    let target = format!("https://{oversized_host}/orders/123");
    let bytes = format!("GET {target} HTTP/1.1\r\nTraceparent: {VALID_TRACEPARENT}\r\n\r\n");

    let extraction = parse_http_request(bytes.as_bytes(), &ProtocolExtractionConfig::default())
        .expect("http request parses");

    assert!(!extraction.attributes.iter().any(|attribute| {
        attribute.key == "url.path"
            || attribute.key == "server.address"
            || attribute.key == "server.port"
    }));
}

#[test]
fn drops_malformed_http_connect_authority_attributes() {
    for target in [
        "user:pass@checkout.example.com:443",
        "checkout.example.com:not-a-port",
        "checkout.example.com:70000",
        "/not-authority-form",
    ] {
        let bytes =
            format!("CONNECT {target} HTTP/1.1\r\nTraceparent: {VALID_TRACEPARENT}\r\n\r\n");

        let extraction = parse_http_request(bytes.as_bytes(), &ProtocolExtractionConfig::default())
            .expect("http connect parses");

        assert!(
            !extraction.attributes.iter().any(
                |attribute| attribute.key == "server.address" || attribute.key == "server.port"
            ),
            "{target:?}"
        );
    }
}

#[test]
fn reports_missing_and_invalid_trace_context_without_inventing_ids() {
    let missing = parse_http_request(
        b"POST /orders HTTP/1.1\r\nHost: api.example.com\r\n\r\n",
        &ProtocolExtractionConfig::default(),
    )
    .expect("request without trace context parses");
    assert_eq!(missing.trace_context, None);
    assert_eq!(missing.warning.as_deref(), Some("missing_trace_context"));

    let malformed = parse_http_request(
        b"GET / HTTP/1.1\r\nTraceparent: 00-bad\r\n\r\n",
        &ProtocolExtractionConfig::default(),
    )
    .expect("request with malformed trace context still parses");
    assert_eq!(malformed.trace_context, None);
    assert_eq!(
        malformed.warning.as_deref(),
        Some("malformed_trace_context")
    );
}

#[test]
fn rejects_adversarial_http_header_fixtures_without_panicking() {
    let config = ProtocolExtractionConfig::default();

    assert_eq!(
        parse_http_request(b"\xff\xfe\xfd\r\n\r\n", &config).unwrap_err(),
        HttpExtraction::InvalidUtf8
    );
    assert_eq!(
        parse_http_request(b"GET\r\nHost: api.example.com\r\n\r\n", &config).unwrap_err(),
        HttpExtraction::MalformedRequestLine
    );
    assert_eq!(
        parse_http_request(b"GET / HTTP/x\r\nHost: api.example.com\r\n\r\n", &config).unwrap_err(),
        HttpExtraction::MalformedRequestLine
    );
    assert_eq!(
        parse_http_request(
            b"GET / HTTP/1.1 unexpected\r\nHost: api.example.com\r\n\r\n",
            &config
        )
        .unwrap_err(),
        HttpExtraction::MalformedRequestLine
    );
    assert_eq!(
        parse_http_request(b"GET / HTTP/1.1\nHost: api.example.com\n\n", &config).unwrap_err(),
        HttpExtraction::HeadersTooLong
    );

    let lowercase_method = parse_http_request(
        b"get / HTTP/1.1\r\nTraceparent: 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01\r\n\r\n",
        &config,
    )
    .expect("lowercase method is parsed without inventing normalized method context");
    assert_eq!(lowercase_method.method, None);
    assert!(lowercase_method.attributes.is_empty());
}

#[test]
fn enforces_fixed_header_request_line_tracestate_and_attribute_bounds() {
    let config = ProtocolExtractionConfig {
        max_header_bytes: 64,
        max_request_line_bytes: 16,
        max_attributes: 1,
        max_tracestate_bytes: 8,
    };

    assert_eq!(
        parse_http_request(
            b"GET /very-long-path HTTP/1.1\r\nHost: api.example.com\r\n\r\n",
            &config
        )
        .unwrap_err(),
        HttpExtraction::RequestLineTooLong
    );
    assert_eq!(
        parse_http_request(
            b"GET / HTTP/1.1\r\nHost: api.example.com\r\nX-A: 1\r\nX-B: 2\r\nX-C: 3\r\n\r\n",
            &config
        )
        .unwrap_err(),
        HttpExtraction::HeadersTooLong
    );

    let extraction = parse_http_request(
        b"GET / HTTP/1.1\r\nTraceparent: 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01\r\nTracestate: too-long-value\r\n\r\n",
        &ProtocolExtractionConfig {
            max_header_bytes: 256,
            max_request_line_bytes: 64,
            max_attributes: 1,
            max_tracestate_bytes: 8,
        },
    )
    .expect("bounded truncation parses deterministically");
    assert_eq!(extraction.tracestate, None);
    assert_eq!(extraction.attributes.len(), 1);
}

#[path = "protocol_extraction/kafka/mod.rs"]
mod kafka;
#[path = "protocol_extraction/mongodb.rs"]
mod mongodb;
#[path = "protocol_extraction/mysql.rs"]
mod mysql;
#[path = "protocol_extraction/nats.rs"]
mod nats;
#[path = "protocol_extraction/postgres.rs"]
mod postgres;
#[path = "protocol_extraction/redis.rs"]
mod redis;

use kafka::kafka_api_versions_response_frame;
use mongodb::{bson_mongodb_error_document, mongodb_op_msg};
use mysql::{mysql_error_packet, mysql_packet, mysql_packet_with_sequence};
use postgres::{postgres_error_response_frame, postgres_frame};

fn lower_hex_string(
    len: impl Into<proptest::collection::SizeRange>,
) -> impl Strategy<Value = String> {
    prop::collection::vec(prop_oneof![Just(b'0'), b'1'..=b'9', b'a'..=b'f'], len)
        .prop_map(|bytes| String::from_utf8(bytes).expect("ascii hex"))
}

fn non_zero_lower_hex_string(len: usize) -> impl Strategy<Value = String> {
    lower_hex_string(len).prop_filter("all-zero ids are invalid", |value| {
        value.bytes().any(|byte| byte != b'0')
    })
}

fn uppercase_hex_string(len: usize) -> impl Strategy<Value = String> {
    prop::collection::vec(prop_oneof![Just(b'0'), b'1'..=b'9', b'A'..=b'F'], len)
        .prop_map(|bytes| String::from_utf8(bytes).expect("ascii hex"))
}
