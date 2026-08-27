use super::*;

#[test]
fn rejects_malformed_classic_kafka_frames() {
    let config = ProtocolExtractionConfig::default();

    assert_eq!(
        parse_kafka_request(&[], &config).unwrap_err(),
        KafkaExtraction::MalformedFrame
    );
    assert_eq!(
        parse_kafka_request(&0_i32.to_be_bytes(), &config).unwrap_err(),
        KafkaExtraction::MalformedFrame
    );
    assert_eq!(
        parse_kafka_request(&kafka_request_frame(99, 0, None, b""), &config).unwrap_err(),
        KafkaExtraction::UnsupportedApiKey
    );
    assert_eq!(
        parse_kafka_request(&kafka_request_frame(18, 0, None, b"trailing"), &config).unwrap_err(),
        KafkaExtraction::MalformedFrame
    );
    assert_eq!(
        parse_kafka_request(&kafka_request_frame(0, 2, None, b"\0\x01"), &config).unwrap_err(),
        KafkaExtraction::MalformedFrame
    );
    assert_eq!(
        parse_kafka_request(&kafka_request_frame(1, 6, None, b""), &config).unwrap_err(),
        KafkaExtraction::UnsupportedApiVersion
    );
    assert_eq!(
        parse_kafka_request(&kafka_request_frame(1, 5, None, b"\0\x01"), &config).unwrap_err(),
        KafkaExtraction::MalformedFrame
    );
    assert_eq!(
        parse_kafka_request(&kafka_request_frame(2, 0, None, b""), &config).unwrap_err(),
        KafkaExtraction::UnsupportedApiVersion
    );
    assert_eq!(
        parse_kafka_request(&kafka_request_frame(2, 5, None, b"\0\x01"), &config).unwrap_err(),
        KafkaExtraction::MalformedFrame
    );
    let mut too_many_list_offsets_topics = Vec::new();
    too_many_list_offsets_topics.extend_from_slice(&(-1_i32).to_be_bytes());
    too_many_list_offsets_topics.push(0);
    too_many_list_offsets_topics.extend_from_slice(&1025_i32.to_be_bytes());
    assert_eq!(
        parse_kafka_request(
            &kafka_request_frame(2, 5, None, &too_many_list_offsets_topics),
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );
    let body = kafka_list_offsets_request_body(5, &[("topic.secret.name", &[0])]);
    assert_eq!(
        parse_kafka_request(
            &kafka_request_frame(2, 5, None, &body),
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
        parse_kafka_request(&kafka_request_frame(20, 0, None, b""), &config).unwrap_err(),
        KafkaExtraction::UnsupportedApiVersion
    );
    assert_eq!(
        parse_kafka_request(&kafka_request_frame(20, 3, None, b"\0\x01"), &config).unwrap_err(),
        KafkaExtraction::MalformedFrame
    );
    let mut too_many_delete_topics = Vec::new();
    too_many_delete_topics.extend_from_slice(&1025_i32.to_be_bytes());
    assert_eq!(
        parse_kafka_request(
            &kafka_request_frame(20, 3, None, &too_many_delete_topics),
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );
    let body = kafka_delete_topics_request_body(&["topic.secret.name"]);
    assert_eq!(
        parse_kafka_request(
            &kafka_request_frame(20, 3, None, &body),
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
        parse_kafka_request(&kafka_request_frame(47, 1, None, b""), &config).unwrap_err(),
        KafkaExtraction::UnsupportedApiVersion
    );
    assert_eq!(
        parse_kafka_request(&kafka_request_frame(47, 0, None, b"\0\x01"), &config).unwrap_err(),
        KafkaExtraction::MalformedFrame
    );
    let mut too_many_offset_delete_topics = Vec::new();
    push_kafka_string(&mut too_many_offset_delete_topics, "group");
    too_many_offset_delete_topics.extend_from_slice(&1025_i32.to_be_bytes());
    assert_eq!(
        parse_kafka_request(
            &kafka_request_frame(47, 0, None, &too_many_offset_delete_topics),
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );
    let body = kafka_offset_delete_request_body(&[("topic.secret.name", &[0])]);
    assert_eq!(
        parse_kafka_request(
            &kafka_request_frame(47, 0, None, &body),
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
        parse_kafka_request(&kafka_request_frame(21, -1, None, b""), &config).unwrap_err(),
        KafkaExtraction::UnsupportedApiVersion
    );
    assert_eq!(
        parse_kafka_request(&kafka_request_frame(21, 1, None, b"\0\x01"), &config).unwrap_err(),
        KafkaExtraction::MalformedFrame
    );
    let mut too_many_delete_records_topics = Vec::new();
    too_many_delete_records_topics.extend_from_slice(&1025_i32.to_be_bytes());
    assert_eq!(
        parse_kafka_request(
            &kafka_request_frame(21, 1, None, &too_many_delete_records_topics),
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );
    let body = kafka_delete_records_request_body(&[("topic.secret.name", &[0])]);
    assert_eq!(
        parse_kafka_request(
            &kafka_request_frame(21, 1, None, &body),
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
        parse_kafka_request(&kafka_request_frame(8, 1, None, b""), &config).unwrap_err(),
        KafkaExtraction::UnsupportedApiVersion
    );
    assert_eq!(
        parse_kafka_request(&kafka_request_frame(8, 7, None, b"\0\x01"), &config).unwrap_err(),
        KafkaExtraction::MalformedFrame
    );
    let body = kafka_offset_commit_request_body(7, &[("topic.secret.name", &[0])]);
    assert_eq!(
        parse_kafka_request(
            &kafka_request_frame(8, 7, None, &body),
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
        parse_kafka_request(&kafka_request_frame(9, 0, None, b""), &config).unwrap_err(),
        KafkaExtraction::UnsupportedApiVersion
    );
    assert_eq!(
        parse_kafka_request(&kafka_request_frame(9, 5, None, b"\0\x01"), &config).unwrap_err(),
        KafkaExtraction::MalformedFrame
    );
    let mut too_many_offset_fetch_topics = Vec::new();
    push_kafka_string(&mut too_many_offset_fetch_topics, "group");
    too_many_offset_fetch_topics.extend_from_slice(&1025_i32.to_be_bytes());
    assert_eq!(
        parse_kafka_request(
            &kafka_request_frame(9, 5, None, &too_many_offset_fetch_topics),
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );
    let body = kafka_offset_fetch_request_body(5, Some(&[("topic.secret.name", &[0])]));
    assert_eq!(
        parse_kafka_request(
            &kafka_request_frame(9, 5, None, &body),
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
        parse_kafka_request(&kafka_request_frame(24, -1, None, b""), &config).unwrap_err(),
        KafkaExtraction::UnsupportedApiVersion
    );
    assert_eq!(
        parse_kafka_request(&kafka_request_frame(24, 2, None, b"\0\x01"), &config).unwrap_err(),
        KafkaExtraction::MalformedFrame
    );
    let mut too_many_add_partitions_topics = Vec::new();
    push_kafka_string(&mut too_many_add_partitions_topics, "transaction");
    too_many_add_partitions_topics.extend_from_slice(&42_i64.to_be_bytes());
    too_many_add_partitions_topics.extend_from_slice(&1_i16.to_be_bytes());
    too_many_add_partitions_topics.extend_from_slice(&1025_i32.to_be_bytes());
    assert_eq!(
        parse_kafka_request(
            &kafka_request_frame(24, 2, None, &too_many_add_partitions_topics),
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );
    let body = kafka_add_partitions_to_txn_request_body(&[("topic.secret.name", &[0])]);
    assert_eq!(
        parse_kafka_request(
            &kafka_request_frame(24, 2, None, &body),
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
        parse_kafka_request(&kafka_request_frame(25, -1, None, b""), &config).unwrap_err(),
        KafkaExtraction::UnsupportedApiVersion
    );
    assert_eq!(
        parse_kafka_request(&kafka_request_frame(25, 2, None, b"\0\x01"), &config).unwrap_err(),
        KafkaExtraction::MalformedFrame
    );
    let body = kafka_add_offsets_to_txn_request_body();
    assert_eq!(
        parse_kafka_request(
            &kafka_request_frame(25, 2, None, &body),
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
        parse_kafka_request(&kafka_request_frame(26, -1, None, b""), &config).unwrap_err(),
        KafkaExtraction::UnsupportedApiVersion
    );
    assert_eq!(
        parse_kafka_request(&kafka_request_frame(26, 2, None, b"\0\x01"), &config).unwrap_err(),
        KafkaExtraction::MalformedFrame
    );
    let body = kafka_end_txn_request_body();
    assert_eq!(
        parse_kafka_request(
            &kafka_request_frame(26, 2, None, &body),
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
        parse_kafka_request(&kafka_flexible_request_frame(27, 0, None, b""), &config).unwrap_err(),
        KafkaExtraction::UnsupportedApiVersion
    );
    assert_eq!(
        parse_kafka_request(
            &kafka_flexible_request_frame(27, 1, None, b"\0\x01"),
            &config
        )
        .unwrap_err(),
        KafkaExtraction::MalformedFrame
    );
    let mut too_many_write_txn_markers = Vec::new();
    push_unsigned_varint(&mut too_many_write_txn_markers, 1026);
    assert_eq!(
        parse_kafka_request(
            &kafka_flexible_request_frame(27, 1, None, &too_many_write_txn_markers),
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );
    let body = kafka_write_txn_markers_request_body(1, &[("topic.secret.name", &[0])]);
    assert_eq!(
        parse_kafka_request(
            &kafka_flexible_request_frame(27, 1, None, &body),
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
        parse_kafka_request(&kafka_request_frame(28, -1, None, b""), &config).unwrap_err(),
        KafkaExtraction::UnsupportedApiVersion
    );
    assert_eq!(
        parse_kafka_request(&kafka_request_frame(28, 2, None, b"\0\x01"), &config).unwrap_err(),
        KafkaExtraction::MalformedFrame
    );
    let mut too_many_txn_offset_commit_topics = Vec::new();
    push_kafka_string(&mut too_many_txn_offset_commit_topics, "transaction");
    push_kafka_string(&mut too_many_txn_offset_commit_topics, "group");
    too_many_txn_offset_commit_topics.extend_from_slice(&42_i64.to_be_bytes());
    too_many_txn_offset_commit_topics.extend_from_slice(&3_i16.to_be_bytes());
    too_many_txn_offset_commit_topics.extend_from_slice(&1025_i32.to_be_bytes());
    assert_eq!(
        parse_kafka_request(
            &kafka_request_frame(28, 2, None, &too_many_txn_offset_commit_topics),
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );
    let body = kafka_txn_offset_commit_request_body(2, &[("topic.secret.name", &[0])]);
    assert_eq!(
        parse_kafka_request(
            &kafka_request_frame(28, 2, None, &body),
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
        parse_kafka_request(&kafka_request_frame(10, -1, None, b""), &config).unwrap_err(),
        KafkaExtraction::UnsupportedApiVersion
    );
    assert_eq!(
        parse_kafka_request(&kafka_request_frame(10, 2, None, b"\0\x01"), &config).unwrap_err(),
        KafkaExtraction::MalformedFrame
    );
    let body = kafka_find_coordinator_request_body(2, "group.secret");
    assert_eq!(
        parse_kafka_request(
            &kafka_request_frame(10, 2, None, &body),
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
        parse_kafka_request(&kafka_request_frame(11, -1, None, b""), &config).unwrap_err(),
        KafkaExtraction::UnsupportedApiVersion
    );
    assert_eq!(
        parse_kafka_request(&kafka_request_frame(11, 5, None, b"\0\x01"), &config).unwrap_err(),
        KafkaExtraction::MalformedFrame
    );
    let mut too_many_join_group_protocols = Vec::new();
    push_kafka_string(&mut too_many_join_group_protocols, "group");
    too_many_join_group_protocols.extend_from_slice(&60_000_i32.to_be_bytes());
    too_many_join_group_protocols.extend_from_slice(&60_000_i32.to_be_bytes());
    push_kafka_string(&mut too_many_join_group_protocols, "member");
    push_kafka_nullable_string(&mut too_many_join_group_protocols, None);
    push_kafka_string(&mut too_many_join_group_protocols, "consumer");
    too_many_join_group_protocols.extend_from_slice(&1025_i32.to_be_bytes());
    assert_eq!(
        parse_kafka_request(
            &kafka_request_frame(11, 5, None, &too_many_join_group_protocols),
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );
    let body = kafka_join_group_request_body(
        5,
        &[("range.secret", b"secret-protocol-metadata".as_slice())],
    );
    assert_eq!(
        parse_kafka_request(
            &kafka_request_frame(11, 5, None, &body),
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
    assert_eq!(
        parse_kafka_request(&kafka_request_frame(12, -1, None, b""), &config).unwrap_err(),
        KafkaExtraction::UnsupportedApiVersion
    );
    assert_eq!(
        parse_kafka_request(&kafka_request_frame(12, 3, None, b"\0\x01"), &config).unwrap_err(),
        KafkaExtraction::MalformedFrame
    );
    let body = kafka_heartbeat_request_body(3, Some("instance.secret"));
    assert_eq!(
        parse_kafka_request(
            &kafka_request_frame(12, 3, None, &body),
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
        parse_kafka_request(&kafka_request_frame(13, -1, None, b""), &config).unwrap_err(),
        KafkaExtraction::UnsupportedApiVersion
    );
    assert_eq!(
        parse_kafka_request(&kafka_request_frame(13, 3, None, b"\0\x01"), &config).unwrap_err(),
        KafkaExtraction::MalformedFrame
    );
    let body = kafka_leave_group_request_body(3);
    assert_eq!(
        parse_kafka_request(
            &kafka_request_frame(13, 3, None, &body),
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
        parse_kafka_request(&kafka_request_frame(14, -1, None, b""), &config).unwrap_err(),
        KafkaExtraction::UnsupportedApiVersion
    );
    assert_eq!(
        parse_kafka_request(&kafka_request_frame(14, 3, None, b"\0\x01"), &config).unwrap_err(),
        KafkaExtraction::MalformedFrame
    );
    let body = kafka_sync_group_request_body(3, b"secret-assignment");
    assert_eq!(
        parse_kafka_request(
            &kafka_request_frame(14, 3, None, &body),
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
        parse_kafka_request(&kafka_request_frame(15, -1, None, b""), &config).unwrap_err(),
        KafkaExtraction::UnsupportedApiVersion
    );
    assert_eq!(
        parse_kafka_request(&kafka_request_frame(15, 4, None, b"\0\x01"), &config).unwrap_err(),
        KafkaExtraction::MalformedFrame
    );
    let body = kafka_describe_groups_request_body(4, &["group.secret"]);
    assert_eq!(
        parse_kafka_request(
            &kafka_request_frame(15, 4, None, &body),
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
        parse_kafka_request(&kafka_request_frame(16, -1, None, b""), &config).unwrap_err(),
        KafkaExtraction::UnsupportedApiVersion
    );
    assert_eq!(
        parse_kafka_request(&kafka_request_frame(16, 3, None, b"trailing"), &config).unwrap_err(),
        KafkaExtraction::MalformedFrame
    );
    assert_eq!(
        parse_kafka_request(&kafka_request_frame(17, -1, None, b""), &config).unwrap_err(),
        KafkaExtraction::UnsupportedApiVersion
    );
    assert_eq!(
        parse_kafka_request(&kafka_request_frame(17, 2, None, b""), &config).unwrap_err(),
        KafkaExtraction::UnsupportedApiVersion
    );
    assert_eq!(
        parse_kafka_request(&kafka_request_frame(17, 1, None, b"\0\x01"), &config).unwrap_err(),
        KafkaExtraction::MalformedFrame
    );
    let body = kafka_sasl_handshake_request_body("PLAIN.secret");
    assert_eq!(
        parse_kafka_request(
            &kafka_request_frame(17, 1, None, &body),
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
        parse_kafka_request(&kafka_request_frame(36, -1, None, b""), &config).unwrap_err(),
        KafkaExtraction::UnsupportedApiVersion
    );
    assert_eq!(
        parse_kafka_request(&kafka_request_frame(36, 1, None, b"\0\x01"), &config).unwrap_err(),
        KafkaExtraction::MalformedFrame
    );
    let mut oversized_sasl_auth = Vec::new();
    oversized_sasl_auth.extend_from_slice(&129_i32.to_be_bytes());
    oversized_sasl_auth.extend_from_slice(&[0_u8; 129]);
    assert_eq!(
        parse_kafka_request(
            &kafka_request_frame(36, 1, None, &oversized_sasl_auth),
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
    assert_eq!(
        parse_kafka_request(&kafka_request_frame(3, -1, None, b""), &config).unwrap_err(),
        KafkaExtraction::UnsupportedApiVersion
    );
    assert_eq!(
        parse_kafka_request(&kafka_request_frame(3, 8, None, b"\0\x01"), &config).unwrap_err(),
        KafkaExtraction::MalformedFrame
    );
    assert_eq!(
        parse_kafka_request(
            &kafka_request_frame(3, 0, None, &(-1_i32).to_be_bytes()),
            &config
        )
        .unwrap_err(),
        KafkaExtraction::MalformedFrame
    );
    let mut too_many_metadata_topics = Vec::new();
    too_many_metadata_topics.extend_from_slice(&1025_i32.to_be_bytes());
    assert_eq!(
        parse_kafka_request(
            &kafka_request_frame(3, 8, None, &too_many_metadata_topics),
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );
    let body = kafka_metadata_request_body(8, Some(&["topic.secret.name"]));
    assert_eq!(
        parse_kafka_request(
            &kafka_request_frame(3, 8, None, &body),
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
    let mut too_many_fetch_topics = Vec::new();
    too_many_fetch_topics.extend_from_slice(&(-1_i32).to_be_bytes());
    too_many_fetch_topics.extend_from_slice(&500_i32.to_be_bytes());
    too_many_fetch_topics.extend_from_slice(&1_i32.to_be_bytes());
    too_many_fetch_topics.extend_from_slice(&1_000_i32.to_be_bytes());
    too_many_fetch_topics.extend_from_slice(&0_i8.to_be_bytes());
    too_many_fetch_topics.extend_from_slice(&1025_i32.to_be_bytes());
    assert_eq!(
        parse_kafka_request(
            &kafka_request_frame(1, 5, None, &too_many_fetch_topics),
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );
    let body = kafka_fetch_request_body(5, &[("topic.secret.name", &[0])]);
    assert_eq!(
        parse_kafka_request(
            &kafka_request_frame(1, 5, None, &body),
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
    let mut too_many_produce_topics = Vec::new();
    too_many_produce_topics.extend_from_slice(&1_i16.to_be_bytes());
    too_many_produce_topics.extend_from_slice(&1_000_i32.to_be_bytes());
    too_many_produce_topics.extend_from_slice(&1025_i32.to_be_bytes());
    assert_eq!(
        parse_kafka_request(
            &kafka_request_frame(0, 2, None, &too_many_produce_topics),
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );
    let body = kafka_produce_request_body(&[("topic.secret.name", 0, b"value")]);
    assert_eq!(
        parse_kafka_request(
            &kafka_request_frame(0, 2, None, &body),
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
            &kafka_flexible_request_frame(18, 3, None, b"\0\x01\0"),
            &config
        )
        .unwrap_err(),
        KafkaExtraction::MalformedFrame
    );
    assert_eq!(
        parse_kafka_request(
            &kafka_flexible_request_frame(18, 3, None, b"\x0bsecret-app\x01\0"),
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
        parse_kafka_request(&kafka_request_frame(19, 1, None, b""), &config).unwrap_err(),
        KafkaExtraction::UnsupportedApiVersion
    );
    assert_eq!(
        parse_kafka_request(&kafka_request_frame(19, 4, None, b"\0\x01"), &config).unwrap_err(),
        KafkaExtraction::MalformedFrame
    );
    let mut too_many_create_topics = Vec::new();
    too_many_create_topics.extend_from_slice(&1025_i32.to_be_bytes());
    assert_eq!(
        parse_kafka_request(
            &kafka_request_frame(19, 4, None, &too_many_create_topics),
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );
    let body = kafka_create_topics_request_body(
        "topic.secret.name",
        "retention.ms.secret",
        Some("token-secret"),
    );
    assert_eq!(
        parse_kafka_request(
            &kafka_request_frame(19, 4, None, &body),
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
        parse_kafka_request(&kafka_request_frame(37, -1, None, b""), &config).unwrap_err(),
        KafkaExtraction::UnsupportedApiVersion
    );
    assert_eq!(
        parse_kafka_request(&kafka_request_frame(37, 1, None, b"\0\x01"), &config).unwrap_err(),
        KafkaExtraction::MalformedFrame
    );
    let mut too_many_create_partitions_topics = Vec::new();
    too_many_create_partitions_topics.extend_from_slice(&1025_i32.to_be_bytes());
    assert_eq!(
        parse_kafka_request(
            &kafka_request_frame(37, 1, None, &too_many_create_partitions_topics),
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );
    let body = kafka_create_partitions_request_body("topic.secret.name", Some(&[&[1, 2]]));
    assert_eq!(
        parse_kafka_request(
            &kafka_request_frame(37, 1, None, &body),
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
        parse_kafka_request(&kafka_request_frame(30, 0, None, b""), &config).unwrap_err(),
        KafkaExtraction::UnsupportedApiVersion
    );
    assert_eq!(
        parse_kafka_request(&kafka_request_frame(30, 1, None, b"\0\x01"), &config).unwrap_err(),
        KafkaExtraction::MalformedFrame
    );
    let mut too_many_create_acls = Vec::new();
    too_many_create_acls.extend_from_slice(&1025_i32.to_be_bytes());
    assert_eq!(
        parse_kafka_request(
            &kafka_request_frame(30, 1, None, &too_many_create_acls),
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );
    let body = kafka_create_acls_request_body("topic.secret.name", "User:secret", "host.secret");
    assert_eq!(
        parse_kafka_request(
            &kafka_request_frame(30, 1, None, &body),
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
        parse_kafka_request(&kafka_request_frame(29, 0, None, b""), &config).unwrap_err(),
        KafkaExtraction::UnsupportedApiVersion
    );
    assert_eq!(
        parse_kafka_request(&kafka_request_frame(29, 1, None, b"\x02"), &config).unwrap_err(),
        KafkaExtraction::MalformedFrame
    );
    let body = kafka_describe_acls_request_body(
        Some("topic.secret.name"),
        Some("User:secret"),
        Some("host.secret"),
    );
    assert_eq!(
        parse_kafka_request(
            &kafka_request_frame(29, 1, None, &body),
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
        parse_kafka_request(&kafka_request_frame(31, 0, None, b""), &config).unwrap_err(),
        KafkaExtraction::UnsupportedApiVersion
    );
    assert_eq!(
        parse_kafka_request(&kafka_request_frame(31, 1, None, b"\0\x01"), &config).unwrap_err(),
        KafkaExtraction::MalformedFrame
    );
    let mut too_many_delete_acl_filters = Vec::new();
    too_many_delete_acl_filters.extend_from_slice(&1025_i32.to_be_bytes());
    assert_eq!(
        parse_kafka_request(
            &kafka_request_frame(31, 1, None, &too_many_delete_acl_filters),
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );
    let body = kafka_delete_acls_request_body(
        Some("topic.secret.name"),
        Some("User:secret"),
        Some("host.secret"),
    );
    assert_eq!(
        parse_kafka_request(
            &kafka_request_frame(31, 1, None, &body),
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
        parse_kafka_request(&kafka_request_frame(32, 0, None, b""), &config).unwrap_err(),
        KafkaExtraction::UnsupportedApiVersion
    );
    assert_eq!(
        parse_kafka_request(&kafka_request_frame(32, 1, None, b"\0\x01"), &config).unwrap_err(),
        KafkaExtraction::MalformedFrame
    );
    let mut too_many_describe_config_resources = Vec::new();
    too_many_describe_config_resources.extend_from_slice(&1025_i32.to_be_bytes());
    assert_eq!(
        parse_kafka_request(
            &kafka_request_frame(32, 1, None, &too_many_describe_config_resources),
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );
    let body =
        kafka_describe_configs_request_body(3, "topic.secret.name", Some(&["retention.secret.ms"]));
    assert_eq!(
        parse_kafka_request(
            &kafka_request_frame(32, 3, None, &body),
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
        parse_kafka_request(&kafka_request_frame(33, -1, None, b""), &config).unwrap_err(),
        KafkaExtraction::UnsupportedApiVersion
    );
    assert_eq!(
        parse_kafka_request(&kafka_request_frame(33, 1, None, b"\0\x01"), &config).unwrap_err(),
        KafkaExtraction::MalformedFrame
    );
    let mut too_many_alter_config_resources = Vec::new();
    too_many_alter_config_resources.extend_from_slice(&1025_i32.to_be_bytes());
    assert_eq!(
        parse_kafka_request(
            &kafka_request_frame(33, 1, None, &too_many_alter_config_resources),
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );
    let body = kafka_alter_configs_request_body(
        "topic.secret.name",
        &[("retention.secret.ms", Some("token-secret"))],
    );
    assert_eq!(
        parse_kafka_request(
            &kafka_request_frame(33, 1, None, &body),
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
        parse_kafka_request(&kafka_request_frame(34, 2, None, b""), &config).unwrap_err(),
        KafkaExtraction::UnsupportedApiVersion
    );
    let mut too_many_alter_replica_dirs = Vec::new();
    too_many_alter_replica_dirs.extend_from_slice(&1025_i32.to_be_bytes());
    assert_eq!(
        parse_kafka_request(
            &kafka_request_frame(34, 1, None, &too_many_alter_replica_dirs),
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );
    let body = kafka_alter_replica_log_dirs_request_body(
        "/var/lib/kafka/secret-dir",
        &[("orders.secret", &[0])],
    );
    assert_eq!(
        parse_kafka_request(
            &kafka_request_frame(34, 1, None, &body),
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
        parse_kafka_request(&kafka_request_frame(35, 2, None, b""), &config).unwrap_err(),
        KafkaExtraction::UnsupportedApiVersion
    );
    let mut too_many_describe_log_dirs_topics = Vec::new();
    too_many_describe_log_dirs_topics.extend_from_slice(&1025_i32.to_be_bytes());
    assert_eq!(
        parse_kafka_request(
            &kafka_request_frame(35, 1, None, &too_many_describe_log_dirs_topics),
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );
    let body = kafka_describe_log_dirs_request_body(Some(&[("orders.secret", &[0])]));
    assert_eq!(
        parse_kafka_request(
            &kafka_request_frame(35, 1, None, &body),
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
        parse_kafka_request(&kafka_request_frame(38, 2, None, b""), &config).unwrap_err(),
        KafkaExtraction::UnsupportedApiVersion
    );
    let mut too_many_create_delegation_token_renewers = Vec::new();
    too_many_create_delegation_token_renewers.extend_from_slice(&1025_i32.to_be_bytes());
    assert_eq!(
        parse_kafka_request(
            &kafka_request_frame(38, 1, None, &too_many_create_delegation_token_renewers),
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );
    let body = kafka_create_delegation_token_request_body(&[("User", "alice.secret")]);
    assert_eq!(
        parse_kafka_request(
            &kafka_request_frame(38, 1, None, &body),
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
        parse_kafka_request(&kafka_request_frame(39, 2, None, b""), &config).unwrap_err(),
        KafkaExtraction::UnsupportedApiVersion
    );
    let body = kafka_renew_delegation_token_request_body(&[0_u8; 129]);
    assert_eq!(
        parse_kafka_request(
            &kafka_request_frame(39, 1, None, &body),
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
    assert_eq!(
        parse_kafka_request(&kafka_request_frame(40, 2, None, b""), &config).unwrap_err(),
        KafkaExtraction::UnsupportedApiVersion
    );
    let body = kafka_expire_delegation_token_request_body(&[0_u8; 129]);
    assert_eq!(
        parse_kafka_request(
            &kafka_request_frame(40, 1, None, &body),
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
    assert_eq!(
        parse_kafka_request(&kafka_request_frame(41, 2, None, b""), &config).unwrap_err(),
        KafkaExtraction::UnsupportedApiVersion
    );
    let mut too_many_describe_delegation_token_owners = Vec::new();
    too_many_describe_delegation_token_owners.extend_from_slice(&1025_i32.to_be_bytes());
    assert_eq!(
        parse_kafka_request(
            &kafka_request_frame(41, 1, None, &too_many_describe_delegation_token_owners),
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );
    let body = kafka_describe_delegation_token_request_body(Some(&[("User", "alice.secret")]));
    assert_eq!(
        parse_kafka_request(
            &kafka_request_frame(41, 1, None, &body),
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
        parse_kafka_api_versions_response(&[], 0, &config).unwrap_err(),
        KafkaExtraction::MalformedFrame
    );
    assert_eq!(
        parse_kafka_api_versions_response(&kafka_frame(&0_i32.to_be_bytes()), 0, &config)
            .unwrap_err(),
        KafkaExtraction::MalformedFrame
    );
    assert_eq!(
        parse_kafka_api_versions_response(
            &kafka_flexible_api_versions_response_with_tags_frame(35, 17, b"secret"),
            3,
            &ProtocolExtractionConfig {
                max_header_bytes: 128,
                max_request_line_bytes: 4,
                max_attributes: 4,
                max_tracestate_bytes: 32,
            },
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );
    assert_eq!(
        parse_kafka_api_versions_response(
            &kafka_api_versions_response_frame(0, 35, b""),
            -1,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::UnsupportedApiVersion
    );
    assert_eq!(
        parse_kafka_produce_response(
            &kafka_produce_response_frame(0, 8, &[("orders", 0)]),
            8,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::UnsupportedApiVersion
    );
    assert_eq!(
        parse_kafka_offset_commit_response(
            &kafka_offset_commit_response_frame(0, 8, &[("orders", 0)]),
            8,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::UnsupportedApiVersion
    );
    assert_eq!(
        parse_kafka_offset_fetch_response(
            &kafka_offset_fetch_response_frame(0, 6, 0, &[("orders", 0)]),
            6,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::UnsupportedApiVersion
    );
    assert_eq!(
        parse_kafka_offset_delete_response(
            &kafka_offset_delete_response_frame(0, 0, &[("orders", 0)]),
            1,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::UnsupportedApiVersion
    );
    assert_eq!(
        parse_kafka_produce_response(
            &kafka_produce_response_with_topic_count_frame(1025),
            1,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );
    assert_eq!(
        parse_kafka_produce_response(
            &kafka_produce_response_with_partition_count_frame(1025),
            1,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );
    assert_eq!(
        parse_kafka_fetch_response(
            &kafka_fetch_response_frame(0, 6, &[("orders", 0, b"")]),
            6,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::UnsupportedApiVersion
    );
    assert_eq!(
        parse_kafka_list_offsets_response(
            &kafka_list_offsets_response_frame(0, 6, &[("orders", 0)]),
            6,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::UnsupportedApiVersion
    );
    assert_eq!(
        parse_kafka_delete_records_response(
            &kafka_delete_records_response_frame(0, &[("orders", 0)]),
            2,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::UnsupportedApiVersion
    );
    assert_eq!(
        parse_kafka_delete_topics_response(
            &kafka_delete_topics_response_frame(0, &[("orders", 0)]),
            4,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::UnsupportedApiVersion
    );
    assert_eq!(
        parse_kafka_create_topics_response(
            &kafka_create_topics_response_frame(0, &[("orders", 0, None)]),
            1,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::UnsupportedApiVersion
    );
    assert_eq!(
        parse_kafka_create_partitions_response(
            &kafka_create_partitions_response_frame(0, &[("orders", 0, None)]),
            2,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::UnsupportedApiVersion
    );
    assert_eq!(
        parse_kafka_create_acls_response(
            &kafka_create_acls_response_frame(0, &[(0, None)]),
            2,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::UnsupportedApiVersion
    );
    assert_eq!(
        parse_kafka_describe_acls_response(
            &kafka_describe_acls_response_frame(0, 0, None, &[]),
            2,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::UnsupportedApiVersion
    );
    assert_eq!(
        parse_kafka_delete_acls_response(&kafka_delete_acls_response_frame(0, &[]), 2, &config)
            .unwrap_err(),
        KafkaExtraction::UnsupportedApiVersion
    );
    assert_eq!(
        parse_kafka_describe_configs_response(
            &kafka_describe_configs_response_frame(0, 1, &[]),
            4,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::UnsupportedApiVersion
    );
    assert_eq!(
        parse_kafka_alter_configs_response(
            &kafka_alter_configs_response_frame(0, &[(0, None, "orders")]),
            2,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::UnsupportedApiVersion
    );
    assert_eq!(
        parse_kafka_alter_replica_log_dirs_response(
            &kafka_alter_replica_log_dirs_response_frame(0, &[("orders", &[(0, 0)])]),
            2,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::UnsupportedApiVersion
    );
    assert_eq!(
        parse_kafka_describe_log_dirs_response(
            &kafka_describe_log_dirs_response_frame(0, &[(0, "/tmp/kafka", &[("orders", &[0])])]),
            2,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::UnsupportedApiVersion
    );
    assert_eq!(
        parse_kafka_create_delegation_token_response(
            &kafka_create_delegation_token_response_frame(0, 0, "User", "alice", "token", b"hmac",),
            2,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::UnsupportedApiVersion
    );
    assert_eq!(
        parse_kafka_renew_delegation_token_response(
            &kafka_renew_delegation_token_response_frame(0, 0),
            2,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::UnsupportedApiVersion
    );
    assert_eq!(
        parse_kafka_expire_delegation_token_response(
            &kafka_expire_delegation_token_response_frame(0, 0),
            2,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::UnsupportedApiVersion
    );
    assert_eq!(
        parse_kafka_describe_delegation_token_response(
            &kafka_describe_delegation_token_response_frame(0, 0, &[]),
            2,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::UnsupportedApiVersion
    );
    assert_eq!(
        parse_kafka_join_group_response(
            &kafka_join_group_response_frame(0, 5, 0, &[("member", b"metadata")]),
            6,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::UnsupportedApiVersion
    );
    assert_eq!(
        parse_kafka_find_coordinator_response(
            &kafka_find_coordinator_response_frame(0, 3, 0, None),
            3,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::UnsupportedApiVersion
    );
    assert_eq!(
        parse_kafka_heartbeat_response(&kafka_heartbeat_response_frame(0, 4, 0), 4, &config)
            .unwrap_err(),
        KafkaExtraction::UnsupportedApiVersion
    );
    assert_eq!(
        parse_kafka_leave_group_response(
            &kafka_leave_group_response_frame(0, 4, 0, &[]),
            4,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::UnsupportedApiVersion
    );
    assert_eq!(
        parse_kafka_sync_group_response(&kafka_sync_group_response_frame(0, 4, 0, b""), 4, &config)
            .unwrap_err(),
        KafkaExtraction::UnsupportedApiVersion
    );
    assert_eq!(
        parse_kafka_describe_groups_response(
            &kafka_describe_groups_response_frame(0, 5, &[("group", 0, 0)]),
            5,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::UnsupportedApiVersion
    );
    assert_eq!(
        parse_kafka_list_groups_response(
            &kafka_list_groups_response_frame(0, 4, 0, &[]),
            4,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::UnsupportedApiVersion
    );
    assert_eq!(
        parse_kafka_delete_groups_response(
            &kafka_delete_groups_response_frame(0, &[("group", 0)]),
            2,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::UnsupportedApiVersion
    );
    assert_eq!(
        parse_kafka_elect_leaders_response(
            &kafka_elect_leaders_response_frame(0, 1, 0, &[]),
            2,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::UnsupportedApiVersion
    );
    assert_eq!(
        parse_kafka_incremental_alter_configs_response(
            &kafka_incremental_alter_configs_response_frame(0, 1, &[]),
            2,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::UnsupportedApiVersion
    );
    assert_eq!(
        parse_kafka_alter_partition_reassignments_response(
            &kafka_alter_partition_reassignments_response_frame(0, 1, 0, None, &[]),
            2,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::UnsupportedApiVersion
    );
    assert_eq!(
        parse_kafka_list_partition_reassignments_response(
            &kafka_list_partition_reassignments_response_frame(0, 0, None, &[]),
            1,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::UnsupportedApiVersion
    );
    assert_eq!(
        parse_kafka_describe_client_quotas_response(
            &kafka_describe_client_quotas_response_frame(0, 1, 0, None, None),
            2,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::UnsupportedApiVersion
    );
    assert_eq!(
        parse_kafka_alter_client_quotas_response(
            &kafka_alter_client_quotas_response_frame(0, 1, &[]),
            2,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::UnsupportedApiVersion
    );
    assert_eq!(
        parse_kafka_describe_user_scram_credentials_response(
            &kafka_describe_user_scram_credentials_response_frame(0, 0, None, &[]),
            1,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::UnsupportedApiVersion
    );
    assert_eq!(
        parse_kafka_alter_user_scram_credentials_response(
            &kafka_alter_user_scram_credentials_response_frame(0, &[]),
            1,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::UnsupportedApiVersion
    );
    assert_eq!(
        parse_kafka_describe_quorum_response(
            &kafka_describe_quorum_response_frame(0, 2, 0, None, &[], &[]),
            3,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::UnsupportedApiVersion
    );
    assert_eq!(
        parse_kafka_update_features_response(
            &kafka_update_features_response_frame(0, 2, 0, None, &[]),
            3,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::UnsupportedApiVersion
    );
    assert_eq!(
        parse_kafka_describe_cluster_response(
            &kafka_describe_cluster_response_frame(0, 2, 0, None, "cluster", &[]),
            3,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::UnsupportedApiVersion
    );
    assert_eq!(
        parse_kafka_describe_producers_response(
            &kafka_describe_producers_response_frame(0, &[("orders.secret", &[])]),
            1,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::UnsupportedApiVersion
    );
    assert_eq!(
        parse_kafka_unregister_broker_response(
            &kafka_unregister_broker_response_frame(0, 0, None),
            1,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::UnsupportedApiVersion
    );
    assert_eq!(
        parse_kafka_describe_transactions_response(
            &kafka_describe_transactions_response_frame(0, &[]),
            1,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::UnsupportedApiVersion
    );
    assert_eq!(
        parse_kafka_list_transactions_response(
            &kafka_list_transactions_response_frame(0, 0, &[], &[]),
            3,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::UnsupportedApiVersion
    );
    assert_eq!(
        parse_kafka_consumer_group_heartbeat_response(
            &kafka_consumer_group_heartbeat_response_frame(0, 0, None, None, None),
            2,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::UnsupportedApiVersion
    );
    assert_eq!(
        parse_kafka_consumer_group_describe_response(
            &kafka_consumer_group_describe_response_frame(0, 0, &[]),
            2,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::UnsupportedApiVersion
    );
    assert_eq!(
        parse_kafka_get_telemetry_subscriptions_response(
            &kafka_get_telemetry_subscriptions_response_frame(0, 0, [0_u8; 16], &[], &[]),
            1,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::UnsupportedApiVersion
    );
    assert_eq!(
        parse_kafka_push_telemetry_response(&kafka_push_telemetry_response_frame(0, 0), 1, &config)
            .unwrap_err(),
        KafkaExtraction::UnsupportedApiVersion
    );
    assert_eq!(
        parse_kafka_list_config_resources_response(
            &kafka_list_config_resources_response_frame(0, 1, 0, &[]),
            2,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::UnsupportedApiVersion
    );
    assert_eq!(
        parse_kafka_describe_topic_partitions_response(
            &kafka_describe_topic_partitions_response_frame(0, &[], None),
            1,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::UnsupportedApiVersion
    );
    assert_eq!(
        parse_kafka_add_raft_voter_response(
            &kafka_add_raft_voter_response_frame(0, 0, None),
            2,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::UnsupportedApiVersion
    );
    assert_eq!(
        parse_kafka_remove_raft_voter_response(
            &kafka_remove_raft_voter_response_frame(0, 0, None),
            1,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::UnsupportedApiVersion
    );
    assert_eq!(
        parse_kafka_update_raft_voter_response(
            &kafka_update_raft_voter_response_frame(0, 0, None),
            1,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::UnsupportedApiVersion
    );
    assert_eq!(
        parse_kafka_initialize_share_group_state_response(
            &kafka_initialize_share_group_state_response_frame(0, &[]),
            1,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::UnsupportedApiVersion
    );
    assert_eq!(
        parse_kafka_read_share_group_state_response(
            &kafka_read_share_group_state_response_frame(0, &[]),
            1,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::UnsupportedApiVersion
    );
    assert_eq!(
        parse_kafka_write_share_group_state_response(
            &kafka_write_share_group_state_response_frame(0, &[]),
            2,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::UnsupportedApiVersion
    );
    assert_eq!(
        parse_kafka_delete_share_group_state_response(
            &kafka_delete_share_group_state_response_frame(0, &[]),
            1,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::UnsupportedApiVersion
    );
    assert_eq!(
        parse_kafka_read_share_group_state_summary_response(
            &kafka_read_share_group_state_summary_response_frame(0, &[], 1),
            2,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::UnsupportedApiVersion
    );
    assert_eq!(
        parse_kafka_delete_share_group_offsets_response(
            &kafka_delete_share_group_offsets_response_frame(0, 0, None, &[]),
            1,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::UnsupportedApiVersion
    );
    assert_eq!(
        parse_kafka_describe_share_group_offsets_response(
            &kafka_describe_share_group_offsets_response_frame(0, 0, &[]),
            2,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::UnsupportedApiVersion
    );
    assert_eq!(
        parse_kafka_sasl_handshake_response(
            &kafka_sasl_handshake_response_frame(0, 0, &["PLAIN"]),
            2,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::UnsupportedApiVersion
    );
    assert_eq!(
        parse_kafka_sasl_authenticate_response(
            &kafka_sasl_authenticate_response_frame(0, 1, 0, None, b""),
            2,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::UnsupportedApiVersion
    );
    assert_eq!(
        parse_kafka_init_producer_id_response(
            &kafka_init_producer_id_response_frame(0, 2, 0),
            2,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::UnsupportedApiVersion
    );
    assert_eq!(
        parse_kafka_add_partitions_to_txn_response(
            &kafka_add_partitions_to_txn_response_frame(0, &[("orders", 0)]),
            3,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::UnsupportedApiVersion
    );
    assert_eq!(
        parse_kafka_add_offsets_to_txn_response(
            &kafka_throttled_error_response_frame(0, 0),
            3,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::UnsupportedApiVersion
    );
    assert_eq!(
        parse_kafka_end_txn_response(&kafka_throttled_error_response_frame(0, 0), 3, &config)
            .unwrap_err(),
        KafkaExtraction::UnsupportedApiVersion
    );
    assert_eq!(
        parse_kafka_write_txn_markers_response(
            &kafka_write_txn_markers_response_frame(&[("orders", &[(0, 0)])]),
            0,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::UnsupportedApiVersion
    );
    assert_eq!(
        parse_kafka_txn_offset_commit_response(
            &kafka_txn_offset_commit_response_frame(0, &[("orders", &[(0, 0)])]),
            3,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::UnsupportedApiVersion
    );
    assert_eq!(
        parse_kafka_metadata_response(
            &kafka_metadata_response_frame(0, 9, &[("orders", 0, 0)]),
            9,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::UnsupportedApiVersion
    );
    assert_eq!(
        parse_kafka_fetch_response(
            &kafka_fetch_response_with_topic_count_frame(1025),
            1,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );
    assert_eq!(
        parse_kafka_fetch_response(
            &kafka_fetch_response_with_partition_count_frame(1025),
            1,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );
    assert_eq!(
        parse_kafka_fetch_response(
            &kafka_fetch_response_with_record_len_frame(129),
            1,
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
    assert_eq!(
        parse_kafka_offset_commit_response(
            &kafka_offset_commit_response_with_topic_count_frame(1025),
            3,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );
    assert_eq!(
        parse_kafka_offset_fetch_response(
            &kafka_offset_fetch_response_with_topic_count_frame(1025),
            3,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );
    assert_eq!(
        parse_kafka_offset_fetch_response(
            &kafka_offset_fetch_response_with_partition_count_frame(1025),
            3,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );
    assert_eq!(
        parse_kafka_offset_delete_response(
            &kafka_offset_delete_response_with_topic_count_frame(1025),
            0,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );
    assert_eq!(
        parse_kafka_offset_delete_response(
            &kafka_offset_delete_response_with_partition_count_frame(1025),
            0,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );
    assert_eq!(
        parse_kafka_list_offsets_response(
            &kafka_list_offsets_response_with_topic_count_frame(1025),
            2,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );
    assert_eq!(
        parse_kafka_list_offsets_response(
            &kafka_list_offsets_response_with_partition_count_frame(1025),
            2,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );
    assert_eq!(
        parse_kafka_delete_records_response(
            &kafka_delete_records_response_with_topic_count_frame(1025),
            1,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );
    assert_eq!(
        parse_kafka_delete_records_response(
            &kafka_delete_records_response_with_partition_count_frame(1025),
            1,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );
    assert_eq!(
        parse_kafka_delete_topics_response(
            &kafka_delete_topics_response_with_topic_count_frame(1025),
            1,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );
    assert_eq!(
        parse_kafka_create_topics_response(
            &kafka_create_topics_response_with_topic_count_frame(1025),
            2,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );
    assert_eq!(
        parse_kafka_create_partitions_response(
            &kafka_create_partitions_response_with_topic_count_frame(1025),
            0,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );
    assert_eq!(
        parse_kafka_create_acls_response(
            &kafka_create_acls_response_with_result_count_frame(1025),
            1,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );
    assert_eq!(
        parse_kafka_describe_acls_response(
            &kafka_describe_acls_response_with_resource_count_frame(1025),
            1,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );
    assert_eq!(
        parse_kafka_describe_acls_response(
            &kafka_describe_acls_response_with_acl_count_frame(1025),
            1,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );
    assert_eq!(
        parse_kafka_delete_acls_response(
            &kafka_delete_acls_response_with_filter_count_frame(1025),
            1,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );
    assert_eq!(
        parse_kafka_delete_acls_response(
            &kafka_delete_acls_response_with_acl_count_frame(1025),
            1,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );
    assert_eq!(
        parse_kafka_describe_configs_response(
            &kafka_describe_configs_response_with_result_count_frame(1025),
            1,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );
    assert_eq!(
        parse_kafka_describe_configs_response(
            &kafka_describe_configs_response_with_config_count_frame(1025),
            1,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );
    assert_eq!(
        parse_kafka_describe_configs_response(
            &kafka_describe_configs_response_with_synonym_count_frame(1025),
            1,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );
    assert_eq!(
        parse_kafka_alter_configs_response(
            &kafka_alter_configs_response_with_response_count_frame(1025),
            1,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );
    assert_eq!(
        parse_kafka_alter_replica_log_dirs_response(
            &kafka_alter_replica_log_dirs_response_with_topic_count_frame(1025),
            1,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );
    assert_eq!(
        parse_kafka_alter_replica_log_dirs_response(
            &kafka_alter_replica_log_dirs_response_with_partition_count_frame(1025),
            1,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );
    assert_eq!(
        parse_kafka_describe_log_dirs_response(
            &kafka_describe_log_dirs_response_with_result_count_frame(1025),
            1,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );
    assert_eq!(
        parse_kafka_describe_log_dirs_response(
            &kafka_describe_log_dirs_response_with_topic_count_frame(1025),
            1,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );
    assert_eq!(
        parse_kafka_describe_log_dirs_response(
            &kafka_describe_log_dirs_response_with_partition_count_frame(1025),
            1,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );
    assert_eq!(
        parse_kafka_create_delegation_token_response(
            &kafka_create_delegation_token_response_frame(
                0,
                0,
                "User",
                "alice.secret",
                "token.secret.id",
                &[0_u8; 129],
            ),
            1,
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
    assert_eq!(
        parse_kafka_describe_delegation_token_response(
            &kafka_describe_delegation_token_response_with_token_count_frame(1025),
            1,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );
    assert_eq!(
        parse_kafka_describe_delegation_token_response(
            &kafka_describe_delegation_token_response_with_renewer_count_frame(1025),
            1,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );
    assert_eq!(
        parse_kafka_describe_delegation_token_response(
            &kafka_describe_delegation_token_response_frame(
                0,
                0,
                &[DescribeDelegationTokenFixture {
                    principal_type: "User",
                    principal_name: "alice.secret",
                    token_id: "token.secret.id",
                    hmac: &[0_u8; 129],
                    renewers: &[],
                }],
            ),
            1,
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
    assert_eq!(
        parse_kafka_add_partitions_to_txn_response(
            &kafka_add_partitions_to_txn_response_with_topic_count_frame(1025),
            1,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );
    assert_eq!(
        parse_kafka_add_partitions_to_txn_response(
            &kafka_add_partitions_to_txn_response_with_partition_count_frame(1025),
            1,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );
    assert_eq!(
        parse_kafka_write_txn_markers_response(
            &kafka_write_txn_markers_response_with_marker_count_frame(1025),
            1,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );
    assert_eq!(
        parse_kafka_write_txn_markers_response(
            &kafka_write_txn_markers_response_with_partition_count_frame(1025),
            1,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );
    assert_eq!(
        parse_kafka_txn_offset_commit_response(
            &kafka_txn_offset_commit_response_with_topic_count_frame(1025),
            1,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );
    assert_eq!(
        parse_kafka_txn_offset_commit_response(
            &kafka_txn_offset_commit_response_with_partition_count_frame(1025),
            1,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );
    assert_eq!(
        parse_kafka_sasl_handshake_response(
            &kafka_sasl_handshake_response_with_mechanism_count_frame(1025),
            1,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );
    assert_eq!(
        parse_kafka_sasl_handshake_response(
            &kafka_sasl_handshake_response_frame(0, 0, &["PLAIN.secret"]),
            1,
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
        parse_kafka_sasl_authenticate_response(
            &kafka_sasl_authenticate_response_frame(0, 1, 58, Some("denied"), b"blob"),
            1,
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
        parse_kafka_join_group_response(
            &kafka_join_group_response_with_member_count_frame(1025),
            5,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );
    assert_eq!(
        parse_kafka_find_coordinator_response(
            &kafka_find_coordinator_response_frame(0, 2, 15, Some("coordinator.secret")),
            2,
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
        parse_kafka_leave_group_response(
            &kafka_leave_group_response_with_member_count_frame(1025),
            3,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );
    assert_eq!(
        parse_kafka_sync_group_response(
            &kafka_sync_group_response_with_assignment_len_frame(129),
            1,
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
    assert_eq!(
        parse_kafka_describe_groups_response(
            &kafka_describe_groups_response_with_group_count_frame(1025),
            4,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );
    assert_eq!(
        parse_kafka_list_groups_response(
            &kafka_list_groups_response_with_group_count_frame(1025),
            3,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );
    assert_eq!(
        parse_kafka_delete_groups_response(
            &kafka_delete_groups_response_with_group_count_frame(1025),
            1,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );
    assert_eq!(
        parse_kafka_elect_leaders_response(
            &kafka_elect_leaders_response_with_topic_count_frame(1025),
            1,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );
    assert_eq!(
        parse_kafka_elect_leaders_response(
            &kafka_elect_leaders_response_with_partition_count_frame(1025),
            1,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );
    assert_eq!(
        parse_kafka_incremental_alter_configs_response(
            &kafka_incremental_alter_configs_response_with_response_count_frame(0, 1025),
            0,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );
    assert_eq!(
        parse_kafka_incremental_alter_configs_response(
            &kafka_incremental_alter_configs_response_with_response_count_frame(1, 1025),
            1,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );
    assert_eq!(
        parse_kafka_alter_partition_reassignments_response(
            &kafka_alter_partition_reassignments_response_with_topic_count_frame(1025),
            1,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );
    assert_eq!(
        parse_kafka_alter_partition_reassignments_response(
            &kafka_alter_partition_reassignments_response_with_partition_count_frame(1025),
            1,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );
    assert_eq!(
        parse_kafka_list_partition_reassignments_response(
            &kafka_list_partition_reassignments_response_with_topic_count_frame(1025),
            0,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );
    assert_eq!(
        parse_kafka_list_partition_reassignments_response(
            &kafka_list_partition_reassignments_response_with_partition_count_frame(1025),
            0,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );
    assert_eq!(
        parse_kafka_describe_client_quotas_response(
            &kafka_describe_client_quotas_response_with_entry_count_frame(1, 1025),
            1,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );
    assert_eq!(
        parse_kafka_describe_client_quotas_response(
            &kafka_describe_client_quotas_response_with_entity_count_frame(1, 1025),
            1,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );
    assert_eq!(
        parse_kafka_alter_client_quotas_response(
            &kafka_alter_client_quotas_response_with_entry_count_frame(1, 1025),
            1,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );
    assert_eq!(
        parse_kafka_alter_client_quotas_response(
            &kafka_alter_client_quotas_response_with_entity_count_frame(1, 1025),
            1,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );
    assert_eq!(
        parse_kafka_describe_user_scram_credentials_response(
            &kafka_describe_user_scram_credentials_response_with_result_count_frame(1025),
            0,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );
    assert_eq!(
        parse_kafka_describe_user_scram_credentials_response(
            &kafka_describe_user_scram_credentials_response_with_credential_count_frame(1025),
            0,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );
    assert_eq!(
        parse_kafka_alter_user_scram_credentials_response(
            &kafka_alter_user_scram_credentials_response_with_result_count_frame(1025),
            0,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );
    assert_eq!(
        parse_kafka_describe_quorum_response(
            &kafka_describe_quorum_response_with_topic_count_frame(1025),
            2,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );
    assert_eq!(
        parse_kafka_describe_quorum_response(
            &kafka_describe_quorum_response_with_partition_count_frame(1025),
            2,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );
    assert_eq!(
        parse_kafka_update_features_response(
            &kafka_update_features_response_with_result_count_frame(1025),
            1,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );
    assert_eq!(
        parse_kafka_describe_cluster_response(
            &kafka_describe_cluster_response_with_broker_count_frame(1025),
            2,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );
    assert_eq!(
        parse_kafka_describe_producers_response(
            &kafka_describe_producers_response_with_topic_count_frame(1025),
            0,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );
    assert_eq!(
        parse_kafka_describe_producers_response(
            &kafka_describe_producers_response_with_partition_count_frame(1025),
            0,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );
    assert_eq!(
        parse_kafka_describe_transactions_response(
            &kafka_describe_transactions_response_with_state_count_frame(1025),
            0,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );
    assert_eq!(
        parse_kafka_describe_transactions_response(
            &kafka_describe_transactions_response_with_topic_count_frame(1025),
            0,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );
    assert_eq!(
        parse_kafka_list_transactions_response(
            &kafka_list_transactions_response_with_unknown_state_count_frame(1025),
            2,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );
    assert_eq!(
        parse_kafka_list_transactions_response(
            &kafka_list_transactions_response_with_state_count_frame(1025),
            2,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );
    assert_eq!(
        parse_kafka_consumer_group_heartbeat_response(
            &kafka_consumer_group_heartbeat_response_with_assignment_count_frame(1025),
            1,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );
    assert_eq!(
        parse_kafka_consumer_group_describe_response(
            &kafka_consumer_group_describe_response_with_group_count_frame(1025),
            1,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );
    assert_eq!(
        parse_kafka_get_telemetry_subscriptions_response(
            &kafka_get_telemetry_subscriptions_response_with_compression_type_count_frame(1025),
            0,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );
    assert_eq!(
        parse_kafka_get_telemetry_subscriptions_response(
            &kafka_get_telemetry_subscriptions_response_with_requested_metric_count_frame(1025),
            0,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );
    assert_eq!(
        parse_kafka_list_config_resources_response(
            &kafka_list_config_resources_response_with_resource_count_frame(1025),
            1,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );
    assert_eq!(
        parse_kafka_describe_topic_partitions_response(
            &kafka_describe_topic_partitions_response_with_topic_count_frame(1025),
            0,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );
    assert_eq!(
        parse_kafka_describe_topic_partitions_response(
            &kafka_describe_topic_partitions_response_with_partition_count_frame(1025),
            0,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );
    assert_eq!(
        parse_kafka_add_raft_voter_response(
            &kafka_add_raft_voter_response_frame(0, 0, Some("secret message")),
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
        parse_kafka_add_raft_voter_response(
            &kafka_add_raft_voter_response_frame(0, 35, Some("secret message")),
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
        parse_kafka_remove_raft_voter_response(
            &kafka_remove_raft_voter_response_frame(0, 0, Some("secret message")),
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
        parse_kafka_remove_raft_voter_response(
            &kafka_remove_raft_voter_response_frame(0, 35, Some("secret message")),
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
        parse_kafka_update_raft_voter_response(
            &kafka_update_raft_voter_response_frame(
                0,
                0,
                Some(UpdateRaftVoterLeaderFixture {
                    leader_id: 7,
                    leader_epoch: 8,
                    host: "leader.secret.internal",
                    port: 9092,
                }),
            ),
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
        parse_kafka_update_raft_voter_response(
            &kafka_update_raft_voter_response_with_tag_len_frame(65),
            0,
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
    assert_eq!(
        parse_kafka_initialize_share_group_state_response(
            &kafka_initialize_share_group_state_response_with_topic_count_frame(1025),
            0,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );
    assert_eq!(
        parse_kafka_initialize_share_group_state_response(
            &kafka_initialize_share_group_state_response_with_partition_count_frame(1025),
            0,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );
    assert_eq!(
        parse_kafka_initialize_share_group_state_response(
            &kafka_initialize_share_group_state_response_frame(
                0,
                &[InitializeShareGroupStateResultTopicFixture {
                    topic_id: [29_u8; 16],
                    partitions: &[InitializeShareGroupStateResultPartitionFixture {
                        partition: 1,
                        error_code: 35,
                        error_message: Some("secret message"),
                    }],
                }],
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
        parse_kafka_read_share_group_state_response(
            &kafka_read_share_group_state_response_with_topic_count_frame(1025),
            0,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );
    assert_eq!(
        parse_kafka_read_share_group_state_response(
            &kafka_read_share_group_state_response_with_partition_count_frame(1025),
            0,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );
    assert_eq!(
        parse_kafka_read_share_group_state_response(
            &kafka_read_share_group_state_response_with_batch_count_frame(1025),
            0,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );
    assert_eq!(
        parse_kafka_read_share_group_state_response(
            &kafka_read_share_group_state_response_frame(
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
        parse_kafka_write_share_group_state_response(
            &kafka_write_share_group_state_response_with_topic_count_frame(1025),
            1,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );
    assert_eq!(
        parse_kafka_write_share_group_state_response(
            &kafka_write_share_group_state_response_with_partition_count_frame(1025),
            1,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );
    assert_eq!(
        parse_kafka_write_share_group_state_response(
            &kafka_write_share_group_state_response_frame(
                0,
                &[WriteShareGroupStateResultTopicFixture {
                    topic_id: [29_u8; 16],
                    partitions: &[WriteShareGroupStateResultPartitionFixture {
                        partition: 1,
                        error_code: 35,
                        error_message: Some("secret message"),
                    }],
                }],
            ),
            1,
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
        parse_kafka_delete_share_group_state_response(
            &kafka_delete_share_group_state_response_with_topic_count_frame(1025),
            0,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );
    assert_eq!(
        parse_kafka_delete_share_group_state_response(
            &kafka_delete_share_group_state_response_with_partition_count_frame(1025),
            0,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );
    assert_eq!(
        parse_kafka_delete_share_group_state_response(
            &kafka_delete_share_group_state_response_frame(
                0,
                &[DeleteShareGroupStateResultTopicFixture {
                    topic_id: [29_u8; 16],
                    partitions: &[DeleteShareGroupStateResultPartitionFixture {
                        partition: 1,
                        error_code: 35,
                        error_message: Some("secret message"),
                    }],
                }],
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
        parse_kafka_read_share_group_state_summary_response(
            &kafka_read_share_group_state_summary_response_with_topic_count_frame(1025),
            1,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );
    assert_eq!(
        parse_kafka_read_share_group_state_summary_response(
            &kafka_read_share_group_state_summary_response_with_partition_count_frame(1025),
            1,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );
    assert_eq!(
        parse_kafka_read_share_group_state_summary_response(
            &kafka_read_share_group_state_summary_response_frame(
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
            ),
            1,
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
        parse_kafka_describe_cluster_response(
            &kafka_describe_cluster_response_frame(
                0,
                2,
                0,
                None,
                "cluster",
                &[(1, "broker.secret.internal", 9092, None, false)],
            ),
            2,
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
        parse_kafka_unregister_broker_response(
            &kafka_unregister_broker_response_frame(0, 35, Some("broker secret denied")),
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
        parse_kafka_describe_transactions_response(
            &kafka_describe_transactions_response_frame(
                0,
                &[(0, "txn.secret", "ongoing.secret", 1001, &[])],
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
        parse_kafka_list_transactions_response(
            &kafka_list_transactions_response_frame(
                0,
                0,
                &["unknown.secret"],
                &[("txn.secret", 1001, "ongoing.secret")],
            ),
            2,
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
        parse_kafka_consumer_group_heartbeat_response(
            &kafka_consumer_group_heartbeat_response_frame(
                0,
                35,
                Some("heartbeat secret denied"),
                Some("member.secret"),
                None,
            ),
            1,
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
        parse_kafka_consumer_group_describe_response(
            &kafka_consumer_group_describe_response_frame(
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
            ),
            1,
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
        parse_kafka_get_telemetry_subscriptions_response(
            &kafka_get_telemetry_subscriptions_response_frame(
                0,
                0,
                [23_u8; 16],
                &[1],
                &["secret.metric"],
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
        parse_kafka_list_config_resources_response(
            &kafka_list_config_resources_response_frame(0, 1, 0, &[("secret.config", 2)]),
            1,
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
        parse_kafka_describe_topic_partitions_response(
            &kafka_describe_topic_partitions_response_frame(
                0,
                &[DescribeTopicPartitionsTopicFixture {
                    error_code: 0,
                    name: Some("orders.secret"),
                    topic_id: [31_u8; 16],
                    partitions: &[],
                }],
                None,
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
        parse_kafka_metadata_response(
            &kafka_metadata_response_with_topic_count_frame(1025),
            8,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );
    assert_eq!(
        parse_kafka_metadata_response(
            &kafka_metadata_response_with_partition_count_frame(1025),
            8,
            &config
        )
        .unwrap_err(),
        KafkaExtraction::FrameTooLong
    );
}
