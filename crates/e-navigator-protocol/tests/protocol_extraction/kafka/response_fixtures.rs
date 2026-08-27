#[test]
fn kafka_response_dispatcher_matches_direct_parser() {
    let bytes = kafka_api_versions_response_frame(42, 7, b"");
    let config = ProtocolExtractionConfig::default();

    let direct = parse_kafka_api_versions_response(&bytes, 0, &config)
        .expect("api versions response parses directly");
    let dispatched = parse_kafka_response_for_api_key(18, 0, &bytes, &config)
        .expect("api versions response parses through the dispatcher");
    assert_eq!(direct, dispatched);

    let unknown = parse_kafka_response_for_api_key(9999, 0, &bytes, &config);
    assert!(unknown.is_err());
}

pub(super) fn kafka_api_versions_response_frame(
    correlation_id: i32,
    error_code: i16,
    body: &[u8],
) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&correlation_id.to_be_bytes());
    response.extend_from_slice(&error_code.to_be_bytes());
    response.extend_from_slice(body);
    kafka_frame(&response)
}

fn kafka_flexible_api_versions_response_frame(error_code: i16, body: &[u8]) -> Vec<u8> {
    kafka_flexible_api_versions_response_with_tags_frame(error_code, 0, body)
}

fn kafka_flexible_api_versions_response_with_tags_frame(
    error_code: i16,
    tag_value_len: usize,
    body: &[u8],
) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&42_i32.to_be_bytes());
    if tag_value_len == 0 {
        push_unsigned_varint(&mut response, 0);
    } else {
        push_unsigned_varint(&mut response, 1);
        push_unsigned_varint(&mut response, 0);
        push_unsigned_varint(&mut response, tag_value_len);
        response.extend(std::iter::repeat_n(0, tag_value_len));
    }
    response.extend_from_slice(&error_code.to_be_bytes());
    response.extend_from_slice(body);
    kafka_frame(&response)
}

fn kafka_produce_response_frame(
    correlation_id: i32,
    api_version: i16,
    topics: &[(&str, i16)],
) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&correlation_id.to_be_bytes());
    response.extend_from_slice(&(topics.len() as i32).to_be_bytes());
    for (topic, error_code) in topics {
        response.extend_from_slice(&(topic.len() as i16).to_be_bytes());
        response.extend_from_slice(topic.as_bytes());
        response.extend_from_slice(&1_i32.to_be_bytes());
        response.extend_from_slice(&0_i32.to_be_bytes());
        response.extend_from_slice(&error_code.to_be_bytes());
        response.extend_from_slice(&42_i64.to_be_bytes());
        if api_version >= 2 {
            response.extend_from_slice(&1_700_000_000_i64.to_be_bytes());
        }
        if api_version >= 5 {
            response.extend_from_slice(&7_i64.to_be_bytes());
        }
    }
    if api_version >= 1 {
        response.extend_from_slice(&0_i32.to_be_bytes());
    }
    kafka_frame(&response)
}

fn kafka_produce_response_with_topic_count_frame(topic_count: i32) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&topic_count.to_be_bytes());
    kafka_frame(&response)
}

fn kafka_produce_response_with_partition_count_frame(partition_count: i32) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&1_i32.to_be_bytes());
    response.extend_from_slice(&6_i16.to_be_bytes());
    response.extend_from_slice(b"orders");
    response.extend_from_slice(&partition_count.to_be_bytes());
    kafka_frame(&response)
}

fn kafka_fetch_response_frame(
    correlation_id: i32,
    api_version: i16,
    topics: &[(&str, i16, &[u8])],
) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&correlation_id.to_be_bytes());
    if api_version >= 1 {
        response.extend_from_slice(&0_i32.to_be_bytes());
    }
    response.extend_from_slice(&(topics.len() as i32).to_be_bytes());
    for (topic, error_code, records) in topics {
        response.extend_from_slice(&(topic.len() as i16).to_be_bytes());
        response.extend_from_slice(topic.as_bytes());
        response.extend_from_slice(&1_i32.to_be_bytes());
        response.extend_from_slice(&0_i32.to_be_bytes());
        response.extend_from_slice(&error_code.to_be_bytes());
        response.extend_from_slice(&42_i64.to_be_bytes());
        if api_version >= 4 {
            response.extend_from_slice(&40_i64.to_be_bytes());
        }
        if api_version >= 5 {
            response.extend_from_slice(&1_i64.to_be_bytes());
        }
        if api_version >= 4 {
            response.extend_from_slice(&0_i32.to_be_bytes());
        }
        response.extend_from_slice(&(records.len() as i32).to_be_bytes());
        response.extend_from_slice(records);
    }
    kafka_frame(&response)
}

fn kafka_fetch_response_with_topic_count_frame(topic_count: i32) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&topic_count.to_be_bytes());
    kafka_frame(&response)
}

fn kafka_fetch_response_with_partition_count_frame(partition_count: i32) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&1_i32.to_be_bytes());
    response.extend_from_slice(&6_i16.to_be_bytes());
    response.extend_from_slice(b"orders");
    response.extend_from_slice(&partition_count.to_be_bytes());
    kafka_frame(&response)
}

fn kafka_fetch_response_with_record_len_frame(record_len: i32) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&1_i32.to_be_bytes());
    response.extend_from_slice(&6_i16.to_be_bytes());
    response.extend_from_slice(b"orders");
    response.extend_from_slice(&1_i32.to_be_bytes());
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&0_i16.to_be_bytes());
    response.extend_from_slice(&42_i64.to_be_bytes());
    response.extend_from_slice(&record_len.to_be_bytes());
    kafka_frame(&response)
}

fn kafka_offset_commit_response_frame(
    correlation_id: i32,
    api_version: i16,
    topics: &[(&str, i16)],
) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&correlation_id.to_be_bytes());
    if api_version >= 3 {
        response.extend_from_slice(&0_i32.to_be_bytes());
    }
    response.extend_from_slice(&(topics.len() as i32).to_be_bytes());
    for (topic, error_code) in topics {
        push_kafka_string(&mut response, topic);
        response.extend_from_slice(&1_i32.to_be_bytes());
        response.extend_from_slice(&0_i32.to_be_bytes());
        response.extend_from_slice(&error_code.to_be_bytes());
    }
    kafka_frame(&response)
}

fn kafka_offset_commit_response_with_topic_count_frame(topic_count: i32) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&topic_count.to_be_bytes());
    kafka_frame(&response)
}

fn kafka_offset_fetch_response_frame(
    correlation_id: i32,
    api_version: i16,
    top_level_error_code: i16,
    topics: &[(&str, i16)],
) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&correlation_id.to_be_bytes());
    if api_version >= 3 {
        response.extend_from_slice(&0_i32.to_be_bytes());
    }
    response.extend_from_slice(&(topics.len() as i32).to_be_bytes());
    for (topic, error_code) in topics {
        push_kafka_string(&mut response, topic);
        response.extend_from_slice(&1_i32.to_be_bytes());
        response.extend_from_slice(&0_i32.to_be_bytes());
        response.extend_from_slice(&42_i64.to_be_bytes());
        if api_version >= 5 {
            response.extend_from_slice(&3_i32.to_be_bytes());
        }
        push_kafka_nullable_string(&mut response, Some("metadata.secret"));
        response.extend_from_slice(&error_code.to_be_bytes());
    }
    if api_version >= 2 {
        response.extend_from_slice(&top_level_error_code.to_be_bytes());
    }
    kafka_frame(&response)
}

fn kafka_offset_fetch_response_with_topic_count_frame(topic_count: i32) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&topic_count.to_be_bytes());
    kafka_frame(&response)
}

fn kafka_offset_fetch_response_with_partition_count_frame(partition_count: i32) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&1_i32.to_be_bytes());
    response.extend_from_slice(&6_i16.to_be_bytes());
    response.extend_from_slice(b"orders");
    response.extend_from_slice(&partition_count.to_be_bytes());
    kafka_frame(&response)
}

fn kafka_offset_delete_response_frame(
    correlation_id: i32,
    top_level_error_code: i16,
    topics: &[(&str, i16)],
) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&correlation_id.to_be_bytes());
    response.extend_from_slice(&top_level_error_code.to_be_bytes());
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&(topics.len() as i32).to_be_bytes());
    for (topic, error_code) in topics {
        push_kafka_string(&mut response, topic);
        response.extend_from_slice(&1_i32.to_be_bytes());
        response.extend_from_slice(&0_i32.to_be_bytes());
        response.extend_from_slice(&error_code.to_be_bytes());
    }
    kafka_frame(&response)
}

fn kafka_offset_delete_response_with_topic_count_frame(topic_count: i32) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&0_i16.to_be_bytes());
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&topic_count.to_be_bytes());
    kafka_frame(&response)
}

fn kafka_offset_delete_response_with_partition_count_frame(partition_count: i32) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&0_i16.to_be_bytes());
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&1_i32.to_be_bytes());
    response.extend_from_slice(&6_i16.to_be_bytes());
    response.extend_from_slice(b"orders");
    response.extend_from_slice(&partition_count.to_be_bytes());
    kafka_frame(&response)
}

type OffsetForLeaderEpochResponsePartitionFixture = (i16, i32, i32, i64);
type OffsetForLeaderEpochResponseTopicFixture<'a> =
    (&'a str, &'a [OffsetForLeaderEpochResponsePartitionFixture]);

fn kafka_offset_for_leader_epoch_response_frame(
    correlation_id: i32,
    api_version: i16,
    topics: &[OffsetForLeaderEpochResponseTopicFixture<'_>],
) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&correlation_id.to_be_bytes());
    if api_version >= 4 {
        push_unsigned_varint(&mut response, 0);
    }
    response.extend_from_slice(&0_i32.to_be_bytes());
    if api_version >= 4 {
        push_unsigned_varint(&mut response, topics.len() + 1);
        for (topic, partitions) in topics {
            push_compact_string(&mut response, topic);
            push_unsigned_varint(&mut response, partitions.len() + 1);
            for (error_code, partition, leader_epoch, end_offset) in *partitions {
                response.extend_from_slice(&error_code.to_be_bytes());
                response.extend_from_slice(&partition.to_be_bytes());
                response.extend_from_slice(&leader_epoch.to_be_bytes());
                response.extend_from_slice(&end_offset.to_be_bytes());
                push_unsigned_varint(&mut response, 0);
            }
            push_unsigned_varint(&mut response, 0);
        }
        push_unsigned_varint(&mut response, 0);
    } else {
        response.extend_from_slice(&(topics.len() as i32).to_be_bytes());
        for (topic, partitions) in topics {
            push_kafka_string(&mut response, topic);
            response.extend_from_slice(&(partitions.len() as i32).to_be_bytes());
            for (error_code, partition, leader_epoch, end_offset) in *partitions {
                response.extend_from_slice(&error_code.to_be_bytes());
                response.extend_from_slice(&partition.to_be_bytes());
                response.extend_from_slice(&leader_epoch.to_be_bytes());
                response.extend_from_slice(&end_offset.to_be_bytes());
            }
        }
    }
    kafka_frame(&response)
}

fn kafka_offset_for_leader_epoch_response_with_topic_count_frame(
    api_version: i16,
    topic_count: usize,
) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&0_i32.to_be_bytes());
    if api_version >= 4 {
        push_unsigned_varint(&mut response, 0);
    }
    response.extend_from_slice(&0_i32.to_be_bytes());
    if api_version >= 4 {
        push_unsigned_varint(&mut response, topic_count + 1);
    } else {
        response.extend_from_slice(&(topic_count as i32).to_be_bytes());
    }
    kafka_frame(&response)
}

fn kafka_list_offsets_response_frame(
    correlation_id: i32,
    api_version: i16,
    topics: &[(&str, i16)],
) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&correlation_id.to_be_bytes());
    if api_version >= 2 {
        response.extend_from_slice(&0_i32.to_be_bytes());
    }
    response.extend_from_slice(&(topics.len() as i32).to_be_bytes());
    for (topic, error_code) in topics {
        push_kafka_string(&mut response, topic);
        response.extend_from_slice(&1_i32.to_be_bytes());
        response.extend_from_slice(&0_i32.to_be_bytes());
        response.extend_from_slice(&error_code.to_be_bytes());
        response.extend_from_slice(&42_i64.to_be_bytes());
        response.extend_from_slice(&1024_i64.to_be_bytes());
        if api_version >= 4 {
            response.extend_from_slice(&3_i32.to_be_bytes());
        }
    }
    kafka_frame(&response)
}

fn kafka_list_offsets_response_with_topic_count_frame(topic_count: i32) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&topic_count.to_be_bytes());
    kafka_frame(&response)
}

fn kafka_list_offsets_response_with_partition_count_frame(partition_count: i32) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&1_i32.to_be_bytes());
    response.extend_from_slice(&6_i16.to_be_bytes());
    response.extend_from_slice(b"orders");
    response.extend_from_slice(&partition_count.to_be_bytes());
    kafka_frame(&response)
}

fn kafka_delete_records_response_frame(correlation_id: i32, topics: &[(&str, i16)]) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&correlation_id.to_be_bytes());
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&(topics.len() as i32).to_be_bytes());
    for (topic, error_code) in topics {
        push_kafka_string(&mut response, topic);
        response.extend_from_slice(&1_i32.to_be_bytes());
        response.extend_from_slice(&0_i32.to_be_bytes());
        response.extend_from_slice(&42_i64.to_be_bytes());
        response.extend_from_slice(&error_code.to_be_bytes());
    }
    kafka_frame(&response)
}

fn kafka_delete_records_response_with_topic_count_frame(topic_count: i32) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&topic_count.to_be_bytes());
    kafka_frame(&response)
}

fn kafka_delete_records_response_with_partition_count_frame(partition_count: i32) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&1_i32.to_be_bytes());
    response.extend_from_slice(&6_i16.to_be_bytes());
    response.extend_from_slice(b"orders");
    response.extend_from_slice(&partition_count.to_be_bytes());
    kafka_frame(&response)
}

fn kafka_delete_topics_response_frame(correlation_id: i32, topics: &[(&str, i16)]) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&correlation_id.to_be_bytes());
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&(topics.len() as i32).to_be_bytes());
    for (topic, error_code) in topics {
        push_kafka_string(&mut response, topic);
        response.extend_from_slice(&error_code.to_be_bytes());
    }
    kafka_frame(&response)
}

fn kafka_create_topics_response_frame(
    correlation_id: i32,
    topics: &[(&str, i16, Option<&str>)],
) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&correlation_id.to_be_bytes());
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&(topics.len() as i32).to_be_bytes());
    for (topic, error_code, error_message) in topics {
        push_kafka_string(&mut response, topic);
        response.extend_from_slice(&error_code.to_be_bytes());
        push_kafka_nullable_string(&mut response, *error_message);
    }
    kafka_frame(&response)
}

fn kafka_create_topics_response_with_topic_count_frame(topic_count: i32) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&topic_count.to_be_bytes());
    kafka_frame(&response)
}

fn kafka_create_partitions_response_frame(
    correlation_id: i32,
    topics: &[(&str, i16, Option<&str>)],
) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&correlation_id.to_be_bytes());
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&(topics.len() as i32).to_be_bytes());
    for (topic, error_code, error_message) in topics {
        push_kafka_string(&mut response, topic);
        response.extend_from_slice(&error_code.to_be_bytes());
        push_kafka_nullable_string(&mut response, *error_message);
    }
    kafka_frame(&response)
}

fn kafka_create_partitions_response_with_topic_count_frame(topic_count: i32) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&topic_count.to_be_bytes());
    kafka_frame(&response)
}

fn kafka_create_acls_response_frame(
    correlation_id: i32,
    results: &[(i16, Option<&str>)],
) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&correlation_id.to_be_bytes());
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&(results.len() as i32).to_be_bytes());
    for (error_code, error_message) in results {
        response.extend_from_slice(&error_code.to_be_bytes());
        push_kafka_nullable_string(&mut response, *error_message);
    }
    kafka_frame(&response)
}

fn kafka_create_acls_response_with_result_count_frame(result_count: i32) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&result_count.to_be_bytes());
    kafka_frame(&response)
}

fn kafka_describe_acls_response_frame(
    correlation_id: i32,
    error_code: i16,
    error_message: Option<&str>,
    resources: &[(&str, &[(&str, &str)])],
) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&correlation_id.to_be_bytes());
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&error_code.to_be_bytes());
    push_kafka_nullable_string(&mut response, error_message);
    response.extend_from_slice(&(resources.len() as i32).to_be_bytes());
    for (resource_name, acls) in resources {
        response.push(2);
        push_kafka_string(&mut response, resource_name);
        response.push(3);
        response.extend_from_slice(&(acls.len() as i32).to_be_bytes());
        for (principal, host) in *acls {
            push_kafka_string(&mut response, principal);
            push_kafka_string(&mut response, host);
            response.push(3);
            response.push(3);
        }
    }
    kafka_frame(&response)
}

fn kafka_describe_acls_response_with_resource_count_frame(resource_count: i32) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&0_i16.to_be_bytes());
    push_kafka_nullable_string(&mut response, None);
    response.extend_from_slice(&resource_count.to_be_bytes());
    kafka_frame(&response)
}

fn kafka_describe_acls_response_with_acl_count_frame(acl_count: i32) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&0_i16.to_be_bytes());
    push_kafka_nullable_string(&mut response, None);
    response.extend_from_slice(&1_i32.to_be_bytes());
    response.push(2);
    push_kafka_string(&mut response, "orders");
    response.push(3);
    response.extend_from_slice(&acl_count.to_be_bytes());
    kafka_frame(&response)
}

type DeleteAclResult<'a> = (i16, Option<&'a str>, &'a str, &'a str, &'a str);

fn kafka_delete_acls_response_frame(
    correlation_id: i32,
    filter_results: &[(i16, Option<&str>, &[DeleteAclResult<'_>])],
) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&correlation_id.to_be_bytes());
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&(filter_results.len() as i32).to_be_bytes());
    for (filter_error_code, filter_error_message, matching_acls) in filter_results {
        response.extend_from_slice(&filter_error_code.to_be_bytes());
        push_kafka_nullable_string(&mut response, *filter_error_message);
        response.extend_from_slice(&(matching_acls.len() as i32).to_be_bytes());
        for (acl_error_code, acl_error_message, resource_name, principal, host) in *matching_acls {
            response.extend_from_slice(&acl_error_code.to_be_bytes());
            push_kafka_nullable_string(&mut response, *acl_error_message);
            response.push(2);
            push_kafka_string(&mut response, resource_name);
            response.push(3);
            push_kafka_string(&mut response, principal);
            push_kafka_string(&mut response, host);
            response.push(3);
            response.push(3);
        }
    }
    kafka_frame(&response)
}

fn kafka_delete_acls_response_with_filter_count_frame(filter_count: i32) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&filter_count.to_be_bytes());
    kafka_frame(&response)
}

fn kafka_delete_acls_response_with_acl_count_frame(acl_count: i32) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&1_i32.to_be_bytes());
    response.extend_from_slice(&0_i16.to_be_bytes());
    push_kafka_nullable_string(&mut response, None);
    response.extend_from_slice(&acl_count.to_be_bytes());
    kafka_frame(&response)
}

type DescribeConfigSynonym<'a> = (&'a str, Option<&'a str>);
type DescribeConfigEntry<'a> = (
    &'a str,
    Option<&'a str>,
    &'a [DescribeConfigSynonym<'a>],
    Option<&'a str>,
);
type DescribeConfigResult<'a> = (i16, Option<&'a str>, &'a str, &'a [DescribeConfigEntry<'a>]);

fn kafka_describe_configs_response_frame(
    correlation_id: i32,
    api_version: i16,
    results: &[DescribeConfigResult<'_>],
) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&correlation_id.to_be_bytes());
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&(results.len() as i32).to_be_bytes());
    for (error_code, error_message, resource_name, configs) in results {
        response.extend_from_slice(&error_code.to_be_bytes());
        push_kafka_nullable_string(&mut response, *error_message);
        response.push(2);
        push_kafka_string(&mut response, resource_name);
        response.extend_from_slice(&(configs.len() as i32).to_be_bytes());
        for (name, value, synonyms, documentation) in *configs {
            push_kafka_string(&mut response, name);
            push_kafka_nullable_string(&mut response, *value);
            response.push(0);
            response.push(1);
            response.push(1);
            response.extend_from_slice(&(synonyms.len() as i32).to_be_bytes());
            for (synonym_name, synonym_value) in *synonyms {
                push_kafka_string(&mut response, synonym_name);
                push_kafka_nullable_string(&mut response, *synonym_value);
                response.push(1);
            }
            if api_version >= 3 {
                response.push(2);
                push_kafka_nullable_string(&mut response, *documentation);
            }
        }
    }
    kafka_frame(&response)
}

fn kafka_describe_configs_response_with_result_count_frame(result_count: i32) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&result_count.to_be_bytes());
    kafka_frame(&response)
}

fn kafka_describe_configs_response_with_config_count_frame(config_count: i32) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&1_i32.to_be_bytes());
    response.extend_from_slice(&0_i16.to_be_bytes());
    push_kafka_nullable_string(&mut response, None);
    response.push(2);
    push_kafka_string(&mut response, "orders");
    response.extend_from_slice(&config_count.to_be_bytes());
    kafka_frame(&response)
}

fn kafka_describe_configs_response_with_synonym_count_frame(synonym_count: i32) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&1_i32.to_be_bytes());
    response.extend_from_slice(&0_i16.to_be_bytes());
    push_kafka_nullable_string(&mut response, None);
    response.push(2);
    push_kafka_string(&mut response, "orders");
    response.extend_from_slice(&1_i32.to_be_bytes());
    push_kafka_string(&mut response, "retention.ms");
    push_kafka_nullable_string(&mut response, Some("60000"));
    response.push(0);
    response.push(1);
    response.push(0);
    response.extend_from_slice(&synonym_count.to_be_bytes());
    kafka_frame(&response)
}

fn kafka_alter_configs_response_frame(
    correlation_id: i32,
    responses: &[(i16, Option<&str>, &str)],
) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&correlation_id.to_be_bytes());
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&(responses.len() as i32).to_be_bytes());
    for (error_code, error_message, resource_name) in responses {
        response.extend_from_slice(&error_code.to_be_bytes());
        push_kafka_nullable_string(&mut response, *error_message);
        response.push(2);
        push_kafka_string(&mut response, resource_name);
    }
    kafka_frame(&response)
}

fn kafka_alter_configs_response_with_response_count_frame(response_count: i32) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&response_count.to_be_bytes());
    kafka_frame(&response)
}

fn kafka_alter_replica_log_dirs_response_frame(
    correlation_id: i32,
    topics: &[(&str, &[(i32, i16)])],
) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&correlation_id.to_be_bytes());
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&(topics.len() as i32).to_be_bytes());
    for (topic, partitions) in topics {
        push_kafka_string(&mut response, topic);
        response.extend_from_slice(&(partitions.len() as i32).to_be_bytes());
        for (partition, error_code) in *partitions {
            response.extend_from_slice(&partition.to_be_bytes());
            response.extend_from_slice(&error_code.to_be_bytes());
        }
    }
    kafka_frame(&response)
}

fn kafka_alter_replica_log_dirs_response_with_topic_count_frame(topic_count: i32) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&topic_count.to_be_bytes());
    kafka_frame(&response)
}

fn kafka_alter_replica_log_dirs_response_with_partition_count_frame(
    partition_count: i32,
) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&1_i32.to_be_bytes());
    push_kafka_string(&mut response, "orders");
    response.extend_from_slice(&partition_count.to_be_bytes());
    kafka_frame(&response)
}

type DescribeLogDirsTopic<'a> = (&'a str, &'a [i32]);
type DescribeLogDirsResult<'a> = (i16, &'a str, &'a [DescribeLogDirsTopic<'a>]);

fn kafka_describe_log_dirs_response_frame(
    correlation_id: i32,
    results: &[DescribeLogDirsResult<'_>],
) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&correlation_id.to_be_bytes());
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&(results.len() as i32).to_be_bytes());
    for (error_code, log_dir, topics) in results {
        response.extend_from_slice(&error_code.to_be_bytes());
        push_kafka_string(&mut response, log_dir);
        response.extend_from_slice(&(topics.len() as i32).to_be_bytes());
        for (topic, partitions) in *topics {
            push_kafka_string(&mut response, topic);
            response.extend_from_slice(&(partitions.len() as i32).to_be_bytes());
            for partition in *partitions {
                response.extend_from_slice(&partition.to_be_bytes());
                response.extend_from_slice(&4096_i64.to_be_bytes());
                response.extend_from_slice(&0_i64.to_be_bytes());
                response.push(0);
            }
        }
    }
    kafka_frame(&response)
}

fn kafka_describe_log_dirs_response_with_result_count_frame(result_count: i32) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&result_count.to_be_bytes());
    kafka_frame(&response)
}

fn kafka_describe_log_dirs_response_with_topic_count_frame(topic_count: i32) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&1_i32.to_be_bytes());
    response.extend_from_slice(&0_i16.to_be_bytes());
    push_kafka_string(&mut response, "/tmp/kafka");
    response.extend_from_slice(&topic_count.to_be_bytes());
    kafka_frame(&response)
}

fn kafka_describe_log_dirs_response_with_partition_count_frame(partition_count: i32) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&1_i32.to_be_bytes());
    response.extend_from_slice(&0_i16.to_be_bytes());
    push_kafka_string(&mut response, "/tmp/kafka");
    response.extend_from_slice(&1_i32.to_be_bytes());
    push_kafka_string(&mut response, "orders");
    response.extend_from_slice(&partition_count.to_be_bytes());
    kafka_frame(&response)
}

fn kafka_create_delegation_token_response_frame(
    correlation_id: i32,
    error_code: i16,
    principal_type: &str,
    principal_name: &str,
    token_id: &str,
    hmac: &[u8],
) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&correlation_id.to_be_bytes());
    response.extend_from_slice(&error_code.to_be_bytes());
    push_kafka_string(&mut response, principal_type);
    push_kafka_string(&mut response, principal_name);
    response.extend_from_slice(&1_700_000_000_000_i64.to_be_bytes());
    response.extend_from_slice(&1_700_003_600_000_i64.to_be_bytes());
    response.extend_from_slice(&1_700_007_200_000_i64.to_be_bytes());
    push_kafka_string(&mut response, token_id);
    push_kafka_bytes(&mut response, hmac);
    response.extend_from_slice(&0_i32.to_be_bytes());
    kafka_frame(&response)
}

fn kafka_renew_delegation_token_response_frame(correlation_id: i32, error_code: i16) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&correlation_id.to_be_bytes());
    response.extend_from_slice(&error_code.to_be_bytes());
    response.extend_from_slice(&1_700_003_600_000_i64.to_be_bytes());
    response.extend_from_slice(&0_i32.to_be_bytes());
    kafka_frame(&response)
}

fn kafka_expire_delegation_token_response_frame(correlation_id: i32, error_code: i16) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&correlation_id.to_be_bytes());
    response.extend_from_slice(&error_code.to_be_bytes());
    response.extend_from_slice(&1_700_000_000_000_i64.to_be_bytes());
    response.extend_from_slice(&0_i32.to_be_bytes());
    kafka_frame(&response)
}

struct DescribeDelegationTokenFixture<'a> {
    principal_type: &'a str,
    principal_name: &'a str,
    token_id: &'a str,
    hmac: &'a [u8],
    renewers: &'a [(&'a str, &'a str)],
}

fn kafka_describe_delegation_token_response_frame(
    correlation_id: i32,
    error_code: i16,
    tokens: &[DescribeDelegationTokenFixture<'_>],
) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&correlation_id.to_be_bytes());
    response.extend_from_slice(&error_code.to_be_bytes());
    response.extend_from_slice(&(tokens.len() as i32).to_be_bytes());
    for token in tokens {
        push_kafka_string(&mut response, token.principal_type);
        push_kafka_string(&mut response, token.principal_name);
        response.extend_from_slice(&1_700_000_000_000_i64.to_be_bytes());
        response.extend_from_slice(&1_700_003_600_000_i64.to_be_bytes());
        response.extend_from_slice(&1_700_007_200_000_i64.to_be_bytes());
        push_kafka_string(&mut response, token.token_id);
        push_kafka_bytes(&mut response, token.hmac);
        response.extend_from_slice(&(token.renewers.len() as i32).to_be_bytes());
        for (principal_type, principal_name) in token.renewers {
            push_kafka_string(&mut response, principal_type);
            push_kafka_string(&mut response, principal_name);
        }
    }
    response.extend_from_slice(&0_i32.to_be_bytes());
    kafka_frame(&response)
}

fn kafka_describe_delegation_token_response_with_token_count_frame(token_count: i32) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&0_i16.to_be_bytes());
    response.extend_from_slice(&token_count.to_be_bytes());
    kafka_frame(&response)
}

fn kafka_describe_delegation_token_response_with_renewer_count_frame(
    renewer_count: i32,
) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&0_i16.to_be_bytes());
    response.extend_from_slice(&1_i32.to_be_bytes());
    push_kafka_string(&mut response, "User");
    push_kafka_string(&mut response, "alice");
    response.extend_from_slice(&1_700_000_000_000_i64.to_be_bytes());
    response.extend_from_slice(&1_700_003_600_000_i64.to_be_bytes());
    response.extend_from_slice(&1_700_007_200_000_i64.to_be_bytes());
    push_kafka_string(&mut response, "token");
    push_kafka_bytes(&mut response, b"hmac");
    response.extend_from_slice(&renewer_count.to_be_bytes());
    kafka_frame(&response)
}

fn kafka_delete_topics_response_with_topic_count_frame(topic_count: i32) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&topic_count.to_be_bytes());
    kafka_frame(&response)
}

fn kafka_add_partitions_to_txn_response_frame(
    correlation_id: i32,
    topics: &[(&str, i16)],
) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&correlation_id.to_be_bytes());
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&(topics.len() as i32).to_be_bytes());
    for (topic, error_code) in topics {
        push_kafka_string(&mut response, topic);
        response.extend_from_slice(&1_i32.to_be_bytes());
        response.extend_from_slice(&0_i32.to_be_bytes());
        response.extend_from_slice(&error_code.to_be_bytes());
    }
    kafka_frame(&response)
}

fn kafka_add_partitions_to_txn_response_with_topic_count_frame(topic_count: i32) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&topic_count.to_be_bytes());
    kafka_frame(&response)
}

fn kafka_add_partitions_to_txn_response_with_partition_count_frame(
    partition_count: i32,
) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&1_i32.to_be_bytes());
    response.extend_from_slice(&6_i16.to_be_bytes());
    response.extend_from_slice(b"orders");
    response.extend_from_slice(&partition_count.to_be_bytes());
    kafka_frame(&response)
}

fn kafka_write_txn_markers_response_frame(topics: &[(&str, &[(i32, i16)])]) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&0_i32.to_be_bytes());
    push_unsigned_varint(&mut response, 0);
    push_unsigned_varint(&mut response, 2);
    response.extend_from_slice(&42_i64.to_be_bytes());
    push_unsigned_varint(&mut response, topics.len() + 1);
    for (topic, partitions) in topics {
        push_compact_string(&mut response, topic);
        push_unsigned_varint(&mut response, partitions.len() + 1);
        for (partition, error_code) in *partitions {
            response.extend_from_slice(&partition.to_be_bytes());
            response.extend_from_slice(&error_code.to_be_bytes());
            push_unsigned_varint(&mut response, 0);
        }
        push_unsigned_varint(&mut response, 0);
    }
    push_unsigned_varint(&mut response, 0);
    push_unsigned_varint(&mut response, 0);
    kafka_frame(&response)
}

fn kafka_write_txn_markers_response_with_marker_count_frame(marker_count: usize) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&0_i32.to_be_bytes());
    push_unsigned_varint(&mut response, 0);
    push_unsigned_varint(&mut response, marker_count + 1);
    kafka_frame(&response)
}

fn kafka_write_txn_markers_response_with_partition_count_frame(partition_count: usize) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&0_i32.to_be_bytes());
    push_unsigned_varint(&mut response, 0);
    push_unsigned_varint(&mut response, 2);
    response.extend_from_slice(&42_i64.to_be_bytes());
    push_unsigned_varint(&mut response, 2);
    push_compact_string(&mut response, "orders");
    push_unsigned_varint(&mut response, partition_count + 1);
    kafka_frame(&response)
}

fn kafka_txn_offset_commit_response_frame(
    correlation_id: i32,
    topics: &[(&str, &[(i32, i16)])],
) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&correlation_id.to_be_bytes());
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&(topics.len() as i32).to_be_bytes());
    for (topic, partitions) in topics {
        push_kafka_string(&mut response, topic);
        response.extend_from_slice(&(partitions.len() as i32).to_be_bytes());
        for (partition, error_code) in *partitions {
            response.extend_from_slice(&partition.to_be_bytes());
            response.extend_from_slice(&error_code.to_be_bytes());
        }
    }
    kafka_frame(&response)
}

fn kafka_txn_offset_commit_response_with_topic_count_frame(topic_count: i32) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&topic_count.to_be_bytes());
    kafka_frame(&response)
}

fn kafka_txn_offset_commit_response_with_partition_count_frame(partition_count: i32) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&1_i32.to_be_bytes());
    response.extend_from_slice(&6_i16.to_be_bytes());
    response.extend_from_slice(b"orders");
    response.extend_from_slice(&partition_count.to_be_bytes());
    kafka_frame(&response)
}

fn kafka_join_group_response_frame(
    correlation_id: i32,
    api_version: i16,
    error_code: i16,
    members: &[(&str, &[u8])],
) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&correlation_id.to_be_bytes());
    if api_version >= 2 {
        response.extend_from_slice(&0_i32.to_be_bytes());
    }
    response.extend_from_slice(&error_code.to_be_bytes());
    response.extend_from_slice(&3_i32.to_be_bytes());
    push_kafka_string(&mut response, "range.secret");
    push_kafka_string(&mut response, "leader.secret");
    push_kafka_string(&mut response, "member.secret");
    response.extend_from_slice(&(members.len() as i32).to_be_bytes());
    for (member_id, metadata) in members {
        push_kafka_string(&mut response, member_id);
        push_kafka_bytes(&mut response, metadata);
    }
    kafka_frame(&response)
}

fn kafka_join_group_response_with_member_count_frame(member_count: i32) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&0_i16.to_be_bytes());
    response.extend_from_slice(&3_i32.to_be_bytes());
    push_kafka_string(&mut response, "range");
    push_kafka_string(&mut response, "leader");
    push_kafka_string(&mut response, "member");
    response.extend_from_slice(&member_count.to_be_bytes());
    kafka_frame(&response)
}

fn kafka_find_coordinator_response_frame(
    correlation_id: i32,
    api_version: i16,
    error_code: i16,
    error_message: Option<&str>,
) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&correlation_id.to_be_bytes());
    if api_version >= 1 {
        response.extend_from_slice(&0_i32.to_be_bytes());
    }
    response.extend_from_slice(&error_code.to_be_bytes());
    if api_version >= 1 {
        push_kafka_nullable_string(&mut response, error_message);
    }
    response.extend_from_slice(&7_i32.to_be_bytes());
    push_kafka_string(&mut response, "broker.secret.local");
    response.extend_from_slice(&9092_i32.to_be_bytes());
    kafka_frame(&response)
}

fn kafka_heartbeat_response_frame(
    correlation_id: i32,
    api_version: i16,
    error_code: i16,
) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&correlation_id.to_be_bytes());
    if api_version >= 1 {
        response.extend_from_slice(&0_i32.to_be_bytes());
    }
    response.extend_from_slice(&error_code.to_be_bytes());
    kafka_frame(&response)
}

fn kafka_leave_group_response_frame(
    correlation_id: i32,
    api_version: i16,
    error_code: i16,
    members: &[(&str, Option<&str>, i16)],
) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&correlation_id.to_be_bytes());
    if api_version >= 1 {
        response.extend_from_slice(&0_i32.to_be_bytes());
    }
    response.extend_from_slice(&error_code.to_be_bytes());
    if api_version >= 3 {
        response.extend_from_slice(&(members.len() as i32).to_be_bytes());
        for (member_id, group_instance_id, member_error_code) in members {
            push_kafka_string(&mut response, member_id);
            push_kafka_nullable_string(&mut response, *group_instance_id);
            response.extend_from_slice(&member_error_code.to_be_bytes());
        }
    }
    kafka_frame(&response)
}

fn kafka_leave_group_response_with_member_count_frame(member_count: i32) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&0_i16.to_be_bytes());
    response.extend_from_slice(&member_count.to_be_bytes());
    kafka_frame(&response)
}

fn kafka_sync_group_response_frame(
    correlation_id: i32,
    api_version: i16,
    error_code: i16,
    assignment: &[u8],
) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&correlation_id.to_be_bytes());
    if api_version >= 1 {
        response.extend_from_slice(&0_i32.to_be_bytes());
    }
    response.extend_from_slice(&error_code.to_be_bytes());
    response.extend_from_slice(&(assignment.len() as i32).to_be_bytes());
    response.extend_from_slice(assignment);
    kafka_frame(&response)
}

fn kafka_sync_group_response_with_assignment_len_frame(assignment_len: i32) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&0_i16.to_be_bytes());
    response.extend_from_slice(&assignment_len.to_be_bytes());
    kafka_frame(&response)
}

fn kafka_describe_groups_response_frame(
    correlation_id: i32,
    api_version: i16,
    groups: &[(&str, i16, i16)],
) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&correlation_id.to_be_bytes());
    if api_version >= 1 {
        response.extend_from_slice(&0_i32.to_be_bytes());
    }
    response.extend_from_slice(&(groups.len() as i32).to_be_bytes());
    for (group_id, group_error_code, _member_error_code) in groups {
        response.extend_from_slice(&group_error_code.to_be_bytes());
        push_kafka_string(&mut response, group_id);
        push_kafka_string(&mut response, "stable.secret");
        push_kafka_string(&mut response, "consumer.secret");
        push_kafka_string(&mut response, "range.secret");
        response.extend_from_slice(&1_i32.to_be_bytes());
        push_kafka_string(&mut response, "member.secret");
        if api_version >= 4 {
            push_kafka_nullable_string(&mut response, Some("instance.secret"));
        }
        push_kafka_string(&mut response, "client.secret");
        push_kafka_string(&mut response, "host.secret");
        response.extend_from_slice(&15_i32.to_be_bytes());
        response.extend_from_slice(b"secret-metadata");
        response.extend_from_slice(&17_i32.to_be_bytes());
        response.extend_from_slice(b"secret-assignment");
        if api_version >= 3 {
            response.extend_from_slice(&0_i32.to_be_bytes());
        }
    }
    kafka_frame(&response)
}

fn kafka_describe_groups_response_with_group_count_frame(group_count: i32) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&group_count.to_be_bytes());
    kafka_frame(&response)
}

fn kafka_list_groups_response_frame(
    correlation_id: i32,
    api_version: i16,
    error_code: i16,
    groups: &[(&str, &str)],
) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&correlation_id.to_be_bytes());
    if api_version >= 1 {
        response.extend_from_slice(&0_i32.to_be_bytes());
    }
    response.extend_from_slice(&error_code.to_be_bytes());
    response.extend_from_slice(&(groups.len() as i32).to_be_bytes());
    for (group_id, protocol_type) in groups {
        push_kafka_string(&mut response, group_id);
        push_kafka_string(&mut response, protocol_type);
        if api_version >= 3 {
            push_kafka_string(&mut response, "stable.secret");
        }
    }
    kafka_frame(&response)
}

fn kafka_list_groups_response_with_group_count_frame(group_count: i32) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&0_i16.to_be_bytes());
    response.extend_from_slice(&group_count.to_be_bytes());
    kafka_frame(&response)
}

fn kafka_delete_groups_response_frame(correlation_id: i32, groups: &[(&str, i16)]) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&correlation_id.to_be_bytes());
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&(groups.len() as i32).to_be_bytes());
    for (group_id, error_code) in groups {
        push_kafka_string(&mut response, group_id);
        response.extend_from_slice(&error_code.to_be_bytes());
    }
    kafka_frame(&response)
}

fn kafka_delete_groups_response_with_group_count_frame(group_count: i32) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&group_count.to_be_bytes());
    kafka_frame(&response)
}

type ElectLeadersPartitionResult<'a> = (i32, i16, Option<&'a str>);
type ElectLeadersTopicResult<'a> = (&'a str, &'a [ElectLeadersPartitionResult<'a>]);

fn kafka_elect_leaders_response_frame(
    correlation_id: i32,
    api_version: i16,
    top_level_error_code: i16,
    topics: &[ElectLeadersTopicResult<'_>],
) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&correlation_id.to_be_bytes());
    response.extend_from_slice(&0_i32.to_be_bytes());
    if api_version >= 1 {
        response.extend_from_slice(&top_level_error_code.to_be_bytes());
    }
    response.extend_from_slice(&(topics.len() as i32).to_be_bytes());
    for (topic, partitions) in topics {
        push_kafka_string(&mut response, topic);
        response.extend_from_slice(&(partitions.len() as i32).to_be_bytes());
        for (partition, error_code, error_message) in *partitions {
            response.extend_from_slice(&partition.to_be_bytes());
            response.extend_from_slice(&error_code.to_be_bytes());
            push_kafka_nullable_string(&mut response, *error_message);
        }
    }
    kafka_frame(&response)
}

fn kafka_elect_leaders_response_with_topic_count_frame(topic_count: i32) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&0_i16.to_be_bytes());
    response.extend_from_slice(&topic_count.to_be_bytes());
    kafka_frame(&response)
}

fn kafka_elect_leaders_response_with_partition_count_frame(partition_count: i32) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&0_i16.to_be_bytes());
    response.extend_from_slice(&1_i32.to_be_bytes());
    push_kafka_string(&mut response, "orders");
    response.extend_from_slice(&partition_count.to_be_bytes());
    kafka_frame(&response)
}

type IncrementalAlterConfigsResponseFixture<'a> = (i16, Option<&'a str>, i8, &'a str);

fn kafka_incremental_alter_configs_response_frame(
    correlation_id: i32,
    api_version: i16,
    responses: &[IncrementalAlterConfigsResponseFixture<'_>],
) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&correlation_id.to_be_bytes());
    if api_version >= 1 {
        push_unsigned_varint(&mut response, 0);
    }
    response.extend_from_slice(&0_i32.to_be_bytes());
    if api_version == 0 {
        response.extend_from_slice(&(responses.len() as i32).to_be_bytes());
        for (error_code, error_message, resource_type, resource_name) in responses {
            response.extend_from_slice(&error_code.to_be_bytes());
            push_kafka_nullable_string(&mut response, *error_message);
            response.push(*resource_type as u8);
            push_kafka_string(&mut response, resource_name);
        }
    } else {
        push_unsigned_varint(&mut response, responses.len() + 1);
        for (error_code, error_message, resource_type, resource_name) in responses {
            response.extend_from_slice(&error_code.to_be_bytes());
            push_compact_nullable_string(&mut response, *error_message);
            response.push(*resource_type as u8);
            push_compact_string(&mut response, resource_name);
            push_unsigned_varint(&mut response, 0);
        }
        push_unsigned_varint(&mut response, 0);
    }
    kafka_frame(&response)
}

fn kafka_incremental_alter_configs_response_with_response_count_frame(
    api_version: i16,
    response_count: usize,
) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&0_i32.to_be_bytes());
    if api_version >= 1 {
        push_unsigned_varint(&mut response, 0);
    }
    response.extend_from_slice(&0_i32.to_be_bytes());
    if api_version == 0 {
        response.extend_from_slice(&(response_count as i32).to_be_bytes());
    } else {
        push_unsigned_varint(&mut response, response_count + 1);
    }
    kafka_frame(&response)
}

type AlterPartitionReassignmentResultFixture<'a> = (i32, i16, Option<&'a str>);
type AlterPartitionReassignmentTopicResultFixture<'a> =
    (&'a str, &'a [AlterPartitionReassignmentResultFixture<'a>]);

fn kafka_alter_partition_reassignments_response_frame(
    correlation_id: i32,
    api_version: i16,
    top_level_error_code: i16,
    top_level_error_message: Option<&str>,
    topics: &[AlterPartitionReassignmentTopicResultFixture<'_>],
) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&correlation_id.to_be_bytes());
    push_unsigned_varint(&mut response, 0);
    response.extend_from_slice(&0_i32.to_be_bytes());
    if api_version >= 1 {
        response.push(1);
    }
    response.extend_from_slice(&top_level_error_code.to_be_bytes());
    push_compact_nullable_string(&mut response, top_level_error_message);
    push_unsigned_varint(&mut response, topics.len() + 1);
    for (topic, partitions) in topics {
        push_compact_string(&mut response, topic);
        push_unsigned_varint(&mut response, partitions.len() + 1);
        for (partition, error_code, error_message) in *partitions {
            response.extend_from_slice(&partition.to_be_bytes());
            response.extend_from_slice(&error_code.to_be_bytes());
            push_compact_nullable_string(&mut response, *error_message);
            push_unsigned_varint(&mut response, 0);
        }
        push_unsigned_varint(&mut response, 0);
    }
    push_unsigned_varint(&mut response, 0);
    kafka_frame(&response)
}

fn kafka_alter_partition_reassignments_response_with_topic_count_frame(
    topic_count: usize,
) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&0_i32.to_be_bytes());
    push_unsigned_varint(&mut response, 0);
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.push(1);
    response.extend_from_slice(&0_i16.to_be_bytes());
    push_compact_nullable_string(&mut response, None);
    push_unsigned_varint(&mut response, topic_count + 1);
    kafka_frame(&response)
}

fn kafka_alter_partition_reassignments_response_with_partition_count_frame(
    partition_count: usize,
) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&0_i32.to_be_bytes());
    push_unsigned_varint(&mut response, 0);
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.push(1);
    response.extend_from_slice(&0_i16.to_be_bytes());
    push_compact_nullable_string(&mut response, None);
    push_unsigned_varint(&mut response, 2);
    push_compact_string(&mut response, "orders");
    push_unsigned_varint(&mut response, partition_count + 1);
    kafka_frame(&response)
}

type ListPartitionReassignmentResultFixture<'a> = (i32, &'a [i32], &'a [i32], &'a [i32]);
type ListPartitionReassignmentTopicResultFixture<'a> =
    (&'a str, &'a [ListPartitionReassignmentResultFixture<'a>]);

fn kafka_list_partition_reassignments_response_frame(
    correlation_id: i32,
    error_code: i16,
    error_message: Option<&str>,
    topics: &[ListPartitionReassignmentTopicResultFixture<'_>],
) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&correlation_id.to_be_bytes());
    push_unsigned_varint(&mut response, 0);
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&error_code.to_be_bytes());
    push_compact_nullable_string(&mut response, error_message);
    push_unsigned_varint(&mut response, topics.len() + 1);
    for (topic, partitions) in topics {
        push_compact_string(&mut response, topic);
        push_unsigned_varint(&mut response, partitions.len() + 1);
        for (partition, replicas, adding_replicas, removing_replicas) in *partitions {
            response.extend_from_slice(&partition.to_be_bytes());
            push_compact_int32_array(&mut response, replicas);
            push_compact_int32_array(&mut response, adding_replicas);
            push_compact_int32_array(&mut response, removing_replicas);
            push_unsigned_varint(&mut response, 0);
        }
        push_unsigned_varint(&mut response, 0);
    }
    push_unsigned_varint(&mut response, 0);
    kafka_frame(&response)
}

fn kafka_list_partition_reassignments_response_with_topic_count_frame(
    topic_count: usize,
) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&0_i32.to_be_bytes());
    push_unsigned_varint(&mut response, 0);
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&0_i16.to_be_bytes());
    push_compact_nullable_string(&mut response, None);
    push_unsigned_varint(&mut response, topic_count + 1);
    kafka_frame(&response)
}

fn kafka_list_partition_reassignments_response_with_partition_count_frame(
    partition_count: usize,
) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&0_i32.to_be_bytes());
    push_unsigned_varint(&mut response, 0);
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&0_i16.to_be_bytes());
    push_compact_nullable_string(&mut response, None);
    push_unsigned_varint(&mut response, 2);
    push_compact_string(&mut response, "orders");
    push_unsigned_varint(&mut response, partition_count + 1);
    kafka_frame(&response)
}

type DescribeClientQuotasEntityFixture<'a> = (&'a str, Option<&'a str>);
type DescribeClientQuotasValueFixture<'a> = (&'a str, f64);
type DescribeClientQuotasEntryFixture<'a> = (
    &'a [DescribeClientQuotasEntityFixture<'a>],
    &'a [DescribeClientQuotasValueFixture<'a>],
);

fn kafka_describe_client_quotas_response_frame(
    correlation_id: i32,
    api_version: i16,
    error_code: i16,
    error_message: Option<&str>,
    entries: Option<&[DescribeClientQuotasEntryFixture<'_>]>,
) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&correlation_id.to_be_bytes());
    if api_version >= 1 {
        push_unsigned_varint(&mut response, 0);
    }
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&error_code.to_be_bytes());
    if api_version == 0 {
        push_kafka_nullable_string(&mut response, error_message);
        if let Some(entries) = entries {
            response.extend_from_slice(&(entries.len() as i32).to_be_bytes());
            for (entities, values) in entries {
                response.extend_from_slice(&(entities.len() as i32).to_be_bytes());
                for (entity_type, entity_name) in *entities {
                    push_kafka_string(&mut response, entity_type);
                    push_kafka_nullable_string(&mut response, *entity_name);
                }
                response.extend_from_slice(&(values.len() as i32).to_be_bytes());
                for (key, value) in *values {
                    push_kafka_string(&mut response, key);
                    response.extend_from_slice(&value.to_be_bytes());
                }
            }
        } else {
            response.extend_from_slice(&(-1_i32).to_be_bytes());
        }
    } else {
        push_compact_nullable_string(&mut response, error_message);
        if let Some(entries) = entries {
            push_unsigned_varint(&mut response, entries.len() + 1);
            for (entities, values) in entries {
                push_unsigned_varint(&mut response, entities.len() + 1);
                for (entity_type, entity_name) in *entities {
                    push_compact_string(&mut response, entity_type);
                    push_compact_nullable_string(&mut response, *entity_name);
                    push_unsigned_varint(&mut response, 0);
                }
                push_unsigned_varint(&mut response, values.len() + 1);
                for (key, value) in *values {
                    push_compact_string(&mut response, key);
                    response.extend_from_slice(&value.to_be_bytes());
                    push_unsigned_varint(&mut response, 0);
                }
                push_unsigned_varint(&mut response, 0);
            }
        } else {
            push_unsigned_varint(&mut response, 0);
        }
        push_unsigned_varint(&mut response, 0);
    }
    kafka_frame(&response)
}

fn kafka_describe_client_quotas_response_with_entry_count_frame(
    api_version: i16,
    entry_count: usize,
) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&0_i32.to_be_bytes());
    if api_version >= 1 {
        push_unsigned_varint(&mut response, 0);
    }
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&0_i16.to_be_bytes());
    if api_version == 0 {
        push_kafka_nullable_string(&mut response, None);
        response.extend_from_slice(&(entry_count as i32).to_be_bytes());
    } else {
        push_compact_nullable_string(&mut response, None);
        push_unsigned_varint(&mut response, entry_count + 1);
    }
    kafka_frame(&response)
}

fn kafka_describe_client_quotas_response_with_entity_count_frame(
    api_version: i16,
    entity_count: usize,
) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&0_i32.to_be_bytes());
    if api_version >= 1 {
        push_unsigned_varint(&mut response, 0);
    }
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&0_i16.to_be_bytes());
    if api_version == 0 {
        push_kafka_nullable_string(&mut response, None);
        response.extend_from_slice(&1_i32.to_be_bytes());
        response.extend_from_slice(&(entity_count as i32).to_be_bytes());
    } else {
        push_compact_nullable_string(&mut response, None);
        push_unsigned_varint(&mut response, 2);
        push_unsigned_varint(&mut response, entity_count + 1);
    }
    kafka_frame(&response)
}

type AlterClientQuotaResultFixture<'a> = (i16, Option<&'a str>, &'a [ClientQuotaEntityFixture<'a>]);

fn kafka_alter_client_quotas_response_frame(
    correlation_id: i32,
    api_version: i16,
    entries: &[AlterClientQuotaResultFixture<'_>],
) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&correlation_id.to_be_bytes());
    if api_version >= 1 {
        push_unsigned_varint(&mut response, 0);
    }
    response.extend_from_slice(&0_i32.to_be_bytes());
    if api_version == 0 {
        response.extend_from_slice(&(entries.len() as i32).to_be_bytes());
        for (error_code, error_message, entities) in entries {
            response.extend_from_slice(&error_code.to_be_bytes());
            push_kafka_nullable_string(&mut response, *error_message);
            response.extend_from_slice(&(entities.len() as i32).to_be_bytes());
            for (entity_type, entity_name) in *entities {
                push_kafka_string(&mut response, entity_type);
                push_kafka_nullable_string(&mut response, *entity_name);
            }
        }
    } else {
        push_unsigned_varint(&mut response, entries.len() + 1);
        for (error_code, error_message, entities) in entries {
            response.extend_from_slice(&error_code.to_be_bytes());
            push_compact_nullable_string(&mut response, *error_message);
            push_unsigned_varint(&mut response, entities.len() + 1);
            for (entity_type, entity_name) in *entities {
                push_compact_string(&mut response, entity_type);
                push_compact_nullable_string(&mut response, *entity_name);
                push_unsigned_varint(&mut response, 0);
            }
            push_unsigned_varint(&mut response, 0);
        }
        push_unsigned_varint(&mut response, 0);
    }
    kafka_frame(&response)
}

fn kafka_alter_client_quotas_response_with_entry_count_frame(
    api_version: i16,
    entry_count: usize,
) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&0_i32.to_be_bytes());
    if api_version >= 1 {
        push_unsigned_varint(&mut response, 0);
    }
    response.extend_from_slice(&0_i32.to_be_bytes());
    if api_version == 0 {
        response.extend_from_slice(&(entry_count as i32).to_be_bytes());
    } else {
        push_unsigned_varint(&mut response, entry_count + 1);
    }
    kafka_frame(&response)
}

fn kafka_alter_client_quotas_response_with_entity_count_frame(
    api_version: i16,
    entity_count: usize,
) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&0_i32.to_be_bytes());
    if api_version >= 1 {
        push_unsigned_varint(&mut response, 0);
    }
    response.extend_from_slice(&0_i32.to_be_bytes());
    if api_version == 0 {
        response.extend_from_slice(&1_i32.to_be_bytes());
        response.extend_from_slice(&0_i16.to_be_bytes());
        push_kafka_nullable_string(&mut response, None);
        response.extend_from_slice(&(entity_count as i32).to_be_bytes());
    } else {
        push_unsigned_varint(&mut response, 2);
        response.extend_from_slice(&0_i16.to_be_bytes());
        push_compact_nullable_string(&mut response, None);
        push_unsigned_varint(&mut response, entity_count + 1);
    }
    kafka_frame(&response)
}

type UserScramCredentialInfoFixture = (i8, i32);
type DescribeUserScramCredentialsResultFixture<'a> = (
    &'a str,
    i16,
    Option<&'a str>,
    &'a [UserScramCredentialInfoFixture],
);

fn kafka_describe_user_scram_credentials_response_frame(
    correlation_id: i32,
    top_level_error_code: i16,
    top_level_error_message: Option<&str>,
    results: &[DescribeUserScramCredentialsResultFixture<'_>],
) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&correlation_id.to_be_bytes());
    push_unsigned_varint(&mut response, 0);
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&top_level_error_code.to_be_bytes());
    push_compact_nullable_string(&mut response, top_level_error_message);
    push_unsigned_varint(&mut response, results.len() + 1);
    for (user, error_code, error_message, credentials) in results {
        push_compact_string(&mut response, user);
        response.extend_from_slice(&error_code.to_be_bytes());
        push_compact_nullable_string(&mut response, *error_message);
        push_unsigned_varint(&mut response, credentials.len() + 1);
        for (mechanism, iterations) in *credentials {
            response.push(*mechanism as u8);
            response.extend_from_slice(&iterations.to_be_bytes());
            push_unsigned_varint(&mut response, 0);
        }
        push_unsigned_varint(&mut response, 0);
    }
    push_unsigned_varint(&mut response, 0);
    kafka_frame(&response)
}

fn kafka_describe_user_scram_credentials_response_with_result_count_frame(
    result_count: usize,
) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&0_i32.to_be_bytes());
    push_unsigned_varint(&mut response, 0);
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&0_i16.to_be_bytes());
    push_compact_nullable_string(&mut response, None);
    push_unsigned_varint(&mut response, result_count + 1);
    kafka_frame(&response)
}

fn kafka_describe_user_scram_credentials_response_with_credential_count_frame(
    credential_count: usize,
) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&0_i32.to_be_bytes());
    push_unsigned_varint(&mut response, 0);
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&0_i16.to_be_bytes());
    push_compact_nullable_string(&mut response, None);
    push_unsigned_varint(&mut response, 2);
    push_compact_string(&mut response, "alice");
    response.extend_from_slice(&0_i16.to_be_bytes());
    push_compact_nullable_string(&mut response, None);
    push_unsigned_varint(&mut response, credential_count + 1);
    kafka_frame(&response)
}

type AlterUserScramCredentialsResultFixture<'a> = (&'a str, i16, Option<&'a str>);

fn kafka_alter_user_scram_credentials_response_frame(
    correlation_id: i32,
    results: &[AlterUserScramCredentialsResultFixture<'_>],
) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&correlation_id.to_be_bytes());
    push_unsigned_varint(&mut response, 0);
    response.extend_from_slice(&0_i32.to_be_bytes());
    push_unsigned_varint(&mut response, results.len() + 1);
    for (user, error_code, error_message) in results {
        push_compact_string(&mut response, user);
        response.extend_from_slice(&error_code.to_be_bytes());
        push_compact_nullable_string(&mut response, *error_message);
        push_unsigned_varint(&mut response, 0);
    }
    push_unsigned_varint(&mut response, 0);
    kafka_frame(&response)
}

fn kafka_alter_user_scram_credentials_response_with_result_count_frame(
    result_count: usize,
) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&0_i32.to_be_bytes());
    push_unsigned_varint(&mut response, 0);
    response.extend_from_slice(&0_i32.to_be_bytes());
    push_unsigned_varint(&mut response, result_count + 1);
    kafka_frame(&response)
}

type DescribeQuorumPartitionFixture<'a> = (i32, i16, Option<&'a str>);
type DescribeQuorumTopicFixture<'a> = (&'a str, &'a [DescribeQuorumPartitionFixture<'a>]);
type DescribeQuorumListenerFixture<'a> = (&'a str, &'a str, u16);
type DescribeQuorumNodeFixture<'a> = (i32, &'a [DescribeQuorumListenerFixture<'a>]);

fn kafka_describe_quorum_response_frame(
    correlation_id: i32,
    api_version: i16,
    top_level_error_code: i16,
    top_level_error_message: Option<&str>,
    topics: &[DescribeQuorumTopicFixture<'_>],
    nodes: &[DescribeQuorumNodeFixture<'_>],
) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&correlation_id.to_be_bytes());
    push_unsigned_varint(&mut response, 0);
    response.extend_from_slice(&top_level_error_code.to_be_bytes());
    if api_version >= 2 {
        push_compact_nullable_string(&mut response, top_level_error_message);
    }
    push_unsigned_varint(&mut response, topics.len() + 1);
    for (topic, partitions) in topics {
        push_compact_string(&mut response, topic);
        push_unsigned_varint(&mut response, partitions.len() + 1);
        for (partition, error_code, error_message) in *partitions {
            response.extend_from_slice(&partition.to_be_bytes());
            response.extend_from_slice(&error_code.to_be_bytes());
            if api_version >= 2 {
                push_compact_nullable_string(&mut response, *error_message);
            }
            response.extend_from_slice(&1_i32.to_be_bytes());
            response.extend_from_slice(&2_i32.to_be_bytes());
            response.extend_from_slice(&42_i64.to_be_bytes());
            push_describe_quorum_replica_states(&mut response, api_version);
            push_describe_quorum_replica_states(&mut response, api_version);
            push_unsigned_varint(&mut response, 0);
        }
        push_unsigned_varint(&mut response, 0);
    }
    if api_version >= 2 {
        push_unsigned_varint(&mut response, nodes.len() + 1);
        for (node_id, listeners) in nodes {
            response.extend_from_slice(&node_id.to_be_bytes());
            push_unsigned_varint(&mut response, listeners.len() + 1);
            for (name, host, port) in *listeners {
                push_compact_string(&mut response, name);
                push_compact_string(&mut response, host);
                response.extend_from_slice(&port.to_be_bytes());
                push_unsigned_varint(&mut response, 0);
            }
            push_unsigned_varint(&mut response, 0);
        }
    }
    push_unsigned_varint(&mut response, 0);
    kafka_frame(&response)
}

fn push_describe_quorum_replica_states(response: &mut Vec<u8>, api_version: i16) {
    push_unsigned_varint(response, 2);
    response.extend_from_slice(&1_i32.to_be_bytes());
    if api_version >= 2 {
        response.extend_from_slice(&[0x11; 16]);
    }
    response.extend_from_slice(&42_i64.to_be_bytes());
    if api_version >= 1 {
        response.extend_from_slice(&1_000_i64.to_be_bytes());
        response.extend_from_slice(&2_000_i64.to_be_bytes());
    }
    push_unsigned_varint(response, 0);
}

fn kafka_describe_quorum_response_with_topic_count_frame(topic_count: usize) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&0_i32.to_be_bytes());
    push_unsigned_varint(&mut response, 0);
    response.extend_from_slice(&0_i16.to_be_bytes());
    push_compact_nullable_string(&mut response, None);
    push_unsigned_varint(&mut response, topic_count + 1);
    kafka_frame(&response)
}

fn kafka_describe_quorum_response_with_partition_count_frame(partition_count: usize) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&0_i32.to_be_bytes());
    push_unsigned_varint(&mut response, 0);
    response.extend_from_slice(&0_i16.to_be_bytes());
    push_compact_nullable_string(&mut response, None);
    push_unsigned_varint(&mut response, 2);
    push_compact_string(&mut response, "orders");
    push_unsigned_varint(&mut response, partition_count + 1);
    kafka_frame(&response)
}

type UpdateFeaturesResultFixture<'a> = (&'a str, i16, Option<&'a str>);

fn kafka_update_features_response_frame(
    correlation_id: i32,
    api_version: i16,
    top_level_error_code: i16,
    top_level_error_message: Option<&str>,
    results: &[UpdateFeaturesResultFixture<'_>],
) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&correlation_id.to_be_bytes());
    push_unsigned_varint(&mut response, 0);
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&top_level_error_code.to_be_bytes());
    push_compact_nullable_string(&mut response, top_level_error_message);
    if api_version <= 1 {
        push_unsigned_varint(&mut response, results.len() + 1);
        for (feature, error_code, error_message) in results {
            push_compact_string(&mut response, feature);
            response.extend_from_slice(&error_code.to_be_bytes());
            push_compact_nullable_string(&mut response, *error_message);
            push_unsigned_varint(&mut response, 0);
        }
    }
    push_unsigned_varint(&mut response, 0);
    kafka_frame(&response)
}

fn kafka_update_features_response_with_result_count_frame(result_count: usize) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&0_i32.to_be_bytes());
    push_unsigned_varint(&mut response, 0);
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&0_i16.to_be_bytes());
    push_compact_nullable_string(&mut response, None);
    push_unsigned_varint(&mut response, result_count + 1);
    kafka_frame(&response)
}

type DescribeClusterBrokerFixture<'a> = (i32, &'a str, i32, Option<&'a str>, bool);

fn kafka_describe_cluster_response_frame(
    correlation_id: i32,
    api_version: i16,
    error_code: i16,
    error_message: Option<&str>,
    cluster_id: &str,
    brokers: &[DescribeClusterBrokerFixture<'_>],
) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&correlation_id.to_be_bytes());
    push_unsigned_varint(&mut response, 0);
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&error_code.to_be_bytes());
    push_compact_nullable_string(&mut response, error_message);
    if api_version >= 1 {
        response.push(2);
    }
    push_compact_string(&mut response, cluster_id);
    response.extend_from_slice(&1_i32.to_be_bytes());
    push_unsigned_varint(&mut response, brokers.len() + 1);
    for (broker_id, host, port, rack, is_fenced) in brokers {
        response.extend_from_slice(&broker_id.to_be_bytes());
        push_compact_string(&mut response, host);
        response.extend_from_slice(&port.to_be_bytes());
        push_compact_nullable_string(&mut response, *rack);
        if api_version >= 2 {
            response.push(u8::from(*is_fenced));
        }
        push_unsigned_varint(&mut response, 0);
    }
    response.extend_from_slice(&0_i32.to_be_bytes());
    push_unsigned_varint(&mut response, 0);
    kafka_frame(&response)
}

fn kafka_describe_cluster_response_with_broker_count_frame(broker_count: usize) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&0_i32.to_be_bytes());
    push_unsigned_varint(&mut response, 0);
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&0_i16.to_be_bytes());
    push_compact_nullable_string(&mut response, None);
    response.push(2);
    push_compact_string(&mut response, "cluster");
    response.extend_from_slice(&1_i32.to_be_bytes());
    push_unsigned_varint(&mut response, broker_count + 1);
    kafka_frame(&response)
}

type DescribeProducersPartitionFixture<'a> = (i32, i16, Option<&'a str>, usize);
type DescribeProducersTopicFixture<'a> = (&'a str, &'a [DescribeProducersPartitionFixture<'a>]);

fn kafka_describe_producers_response_frame(
    correlation_id: i32,
    topics: &[DescribeProducersTopicFixture<'_>],
) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&correlation_id.to_be_bytes());
    push_unsigned_varint(&mut response, 0);
    response.extend_from_slice(&0_i32.to_be_bytes());
    push_unsigned_varint(&mut response, topics.len() + 1);
    for (topic, partitions) in topics {
        push_compact_string(&mut response, topic);
        push_unsigned_varint(&mut response, partitions.len() + 1);
        for (partition_index, error_code, error_message, producer_count) in *partitions {
            response.extend_from_slice(&partition_index.to_be_bytes());
            response.extend_from_slice(&error_code.to_be_bytes());
            push_compact_nullable_string(&mut response, *error_message);
            push_unsigned_varint(&mut response, producer_count + 1);
            for producer_index in 0..*producer_count {
                response.extend_from_slice(&(1001_i64 + producer_index as i64).to_be_bytes());
                response.extend_from_slice(&(producer_index as i32).to_be_bytes());
                response.extend_from_slice(&(producer_index as i32).to_be_bytes());
                response.extend_from_slice(&(123456_i64 + producer_index as i64).to_be_bytes());
                response.extend_from_slice(&(producer_index as i32).to_be_bytes());
                response.extend_from_slice(&(42_i64 + producer_index as i64).to_be_bytes());
                push_unsigned_varint(&mut response, 0);
            }
            push_unsigned_varint(&mut response, 0);
        }
        push_unsigned_varint(&mut response, 0);
    }
    push_unsigned_varint(&mut response, 0);
    kafka_frame(&response)
}

fn kafka_describe_producers_response_with_topic_count_frame(topic_count: usize) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&0_i32.to_be_bytes());
    push_unsigned_varint(&mut response, 0);
    response.extend_from_slice(&0_i32.to_be_bytes());
    push_unsigned_varint(&mut response, topic_count + 1);
    kafka_frame(&response)
}

fn kafka_describe_producers_response_with_partition_count_frame(partition_count: usize) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&0_i32.to_be_bytes());
    push_unsigned_varint(&mut response, 0);
    response.extend_from_slice(&0_i32.to_be_bytes());
    push_unsigned_varint(&mut response, 2);
    push_compact_string(&mut response, "orders");
    push_unsigned_varint(&mut response, partition_count + 1);
    kafka_frame(&response)
}

fn kafka_broker_heartbeat_response_frame(
    correlation_id: i32,
    error_code: i16,
    is_caught_up: bool,
    is_fenced: bool,
    should_shutdown: bool,
) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&correlation_id.to_be_bytes());
    push_unsigned_varint(&mut response, 0);
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&error_code.to_be_bytes());
    response.push(u8::from(is_caught_up));
    response.push(u8::from(is_fenced));
    response.push(u8::from(should_shutdown));
    push_unsigned_varint(&mut response, 0);
    kafka_frame(&response)
}

fn kafka_broker_heartbeat_response_with_tag_value_len_frame(tag_value_len: usize) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&0_i32.to_be_bytes());
    push_unsigned_varint(&mut response, 0);
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&0_i16.to_be_bytes());
    response.push(1);
    response.push(0);
    response.push(0);
    push_unsigned_varint(&mut response, 1);
    push_unsigned_varint(&mut response, 0);
    push_unsigned_varint(&mut response, tag_value_len);
    response.resize(response.len() + tag_value_len, 0);
    kafka_frame(&response)
}

fn kafka_unregister_broker_response_frame(
    correlation_id: i32,
    error_code: i16,
    error_message: Option<&str>,
) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&correlation_id.to_be_bytes());
    push_unsigned_varint(&mut response, 0);
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&error_code.to_be_bytes());
    push_compact_nullable_string(&mut response, error_message);
    push_unsigned_varint(&mut response, 0);
    kafka_frame(&response)
}

type DescribeTransactionsTopicFixture<'a> = (&'a str, &'a [i32]);
type DescribeTransactionsStateFixture<'a> = (
    i16,
    &'a str,
    &'a str,
    i64,
    &'a [DescribeTransactionsTopicFixture<'a>],
);

fn kafka_describe_transactions_response_frame(
    correlation_id: i32,
    states: &[DescribeTransactionsStateFixture<'_>],
) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&correlation_id.to_be_bytes());
    push_unsigned_varint(&mut response, 0);
    response.extend_from_slice(&0_i32.to_be_bytes());
    push_unsigned_varint(&mut response, states.len() + 1);
    for (error_code, transactional_id, transaction_state, producer_id, topics) in states {
        response.extend_from_slice(&error_code.to_be_bytes());
        push_compact_string(&mut response, transactional_id);
        push_compact_string(&mut response, transaction_state);
        response.extend_from_slice(&60_000_i32.to_be_bytes());
        response.extend_from_slice(&123456_i64.to_be_bytes());
        response.extend_from_slice(&producer_id.to_be_bytes());
        response.extend_from_slice(&1_i16.to_be_bytes());
        push_unsigned_varint(&mut response, topics.len() + 1);
        for (topic, partitions) in *topics {
            push_compact_string(&mut response, topic);
            push_compact_int32_array(&mut response, partitions);
            push_unsigned_varint(&mut response, 0);
        }
        push_unsigned_varint(&mut response, 0);
    }
    push_unsigned_varint(&mut response, 0);
    kafka_frame(&response)
}

fn kafka_describe_transactions_response_with_state_count_frame(state_count: usize) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&0_i32.to_be_bytes());
    push_unsigned_varint(&mut response, 0);
    response.extend_from_slice(&0_i32.to_be_bytes());
    push_unsigned_varint(&mut response, state_count + 1);
    kafka_frame(&response)
}

fn kafka_describe_transactions_response_with_topic_count_frame(topic_count: usize) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&0_i32.to_be_bytes());
    push_unsigned_varint(&mut response, 0);
    response.extend_from_slice(&0_i32.to_be_bytes());
    push_unsigned_varint(&mut response, 2);
    response.extend_from_slice(&0_i16.to_be_bytes());
    push_compact_string(&mut response, "txn");
    push_compact_string(&mut response, "ongoing");
    response.extend_from_slice(&60_000_i32.to_be_bytes());
    response.extend_from_slice(&123456_i64.to_be_bytes());
    response.extend_from_slice(&1001_i64.to_be_bytes());
    response.extend_from_slice(&1_i16.to_be_bytes());
    push_unsigned_varint(&mut response, topic_count + 1);
    kafka_frame(&response)
}

type ListTransactionsStateFixture<'a> = (&'a str, i64, &'a str);

fn kafka_list_transactions_response_frame(
    correlation_id: i32,
    error_code: i16,
    unknown_state_filters: &[&str],
    states: &[ListTransactionsStateFixture<'_>],
) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&correlation_id.to_be_bytes());
    push_unsigned_varint(&mut response, 0);
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&error_code.to_be_bytes());
    push_unsigned_varint(&mut response, unknown_state_filters.len() + 1);
    for state_filter in unknown_state_filters {
        push_compact_string(&mut response, state_filter);
    }
    push_unsigned_varint(&mut response, states.len() + 1);
    for (transactional_id, producer_id, transaction_state) in states {
        push_compact_string(&mut response, transactional_id);
        response.extend_from_slice(&producer_id.to_be_bytes());
        push_compact_string(&mut response, transaction_state);
        push_unsigned_varint(&mut response, 0);
    }
    push_unsigned_varint(&mut response, 0);
    kafka_frame(&response)
}

fn kafka_list_transactions_response_with_unknown_state_count_frame(
    unknown_state_count: usize,
) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&0_i32.to_be_bytes());
    push_unsigned_varint(&mut response, 0);
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&0_i16.to_be_bytes());
    push_unsigned_varint(&mut response, unknown_state_count + 1);
    kafka_frame(&response)
}

fn kafka_list_transactions_response_with_state_count_frame(state_count: usize) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&0_i32.to_be_bytes());
    push_unsigned_varint(&mut response, 0);
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&0_i16.to_be_bytes());
    push_unsigned_varint(&mut response, 1);
    push_unsigned_varint(&mut response, state_count + 1);
    kafka_frame(&response)
}

fn kafka_allocate_producer_ids_response_frame(
    correlation_id: i32,
    error_code: i16,
    producer_id_start: i64,
    producer_id_len: i32,
) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&correlation_id.to_be_bytes());
    push_unsigned_varint(&mut response, 0);
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&error_code.to_be_bytes());
    response.extend_from_slice(&producer_id_start.to_be_bytes());
    response.extend_from_slice(&producer_id_len.to_be_bytes());
    push_unsigned_varint(&mut response, 0);
    kafka_frame(&response)
}

fn kafka_consumer_group_heartbeat_response_frame(
    correlation_id: i32,
    error_code: i16,
    error_message: Option<&str>,
    member_id: Option<&str>,
    assignment: Option<&[ConsumerGroupHeartbeatTopicPartitionsFixture<'_>]>,
) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&correlation_id.to_be_bytes());
    push_unsigned_varint(&mut response, 0);
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&error_code.to_be_bytes());
    push_compact_nullable_string(&mut response, error_message);
    push_compact_nullable_string(&mut response, member_id);
    response.extend_from_slice(&1_i32.to_be_bytes());
    response.extend_from_slice(&3_000_i32.to_be_bytes());
    push_nullable_topic_partition_assignment(&mut response, assignment);
    push_unsigned_varint(&mut response, 0);
    kafka_frame(&response)
}

fn kafka_consumer_group_heartbeat_response_with_assignment_count_frame(
    assignment_count: usize,
) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&0_i32.to_be_bytes());
    push_unsigned_varint(&mut response, 0);
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&0_i16.to_be_bytes());
    push_compact_nullable_string(&mut response, None);
    push_compact_nullable_string(&mut response, None);
    response.extend_from_slice(&1_i32.to_be_bytes());
    response.extend_from_slice(&3_000_i32.to_be_bytes());
    response.push(1);
    push_unsigned_varint(&mut response, assignment_count + 1);
    kafka_frame(&response)
}

fn kafka_share_group_heartbeat_response_frame(
    correlation_id: i32,
    error_code: i16,
    error_message: Option<&str>,
    member_id: Option<&str>,
    assignment: Option<&[ConsumerGroupHeartbeatTopicPartitionsFixture<'_>]>,
) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&correlation_id.to_be_bytes());
    push_unsigned_varint(&mut response, 0);
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&error_code.to_be_bytes());
    push_compact_nullable_string(&mut response, error_message);
    push_compact_nullable_string(&mut response, member_id);
    response.extend_from_slice(&1_i32.to_be_bytes());
    response.extend_from_slice(&3_000_i32.to_be_bytes());
    push_nullable_topic_partition_assignment(&mut response, assignment);
    push_unsigned_varint(&mut response, 0);
    kafka_frame(&response)
}

fn kafka_share_group_heartbeat_response_with_assignment_count_frame(
    assignment_count: usize,
) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&0_i32.to_be_bytes());
    push_unsigned_varint(&mut response, 0);
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&0_i16.to_be_bytes());
    push_compact_nullable_string(&mut response, None);
    push_compact_nullable_string(&mut response, None);
    response.extend_from_slice(&1_i32.to_be_bytes());
    response.extend_from_slice(&3_000_i32.to_be_bytes());
    response.push(1);
    push_unsigned_varint(&mut response, assignment_count + 1);
    kafka_frame(&response)
}

fn kafka_share_group_heartbeat_response_with_partition_count_frame(
    partition_count: usize,
) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&0_i32.to_be_bytes());
    push_unsigned_varint(&mut response, 0);
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&0_i16.to_be_bytes());
    push_compact_nullable_string(&mut response, None);
    push_compact_nullable_string(&mut response, None);
    response.extend_from_slice(&1_i32.to_be_bytes());
    response.extend_from_slice(&3_000_i32.to_be_bytes());
    response.push(1);
    push_unsigned_varint(&mut response, 2);
    response.extend_from_slice(&[7_u8; 16]);
    push_unsigned_varint(&mut response, partition_count + 1);
    kafka_frame(&response)
}

fn kafka_controller_registration_response_frame(
    correlation_id: i32,
    error_code: i16,
    error_message: Option<&str>,
) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&correlation_id.to_be_bytes());
    push_unsigned_varint(&mut response, 0);
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&error_code.to_be_bytes());
    push_compact_nullable_string(&mut response, error_message);
    push_unsigned_varint(&mut response, 0);
    kafka_frame(&response)
}

fn kafka_controller_registration_response_with_tag_value_len_frame(
    tag_value_len: usize,
) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&0_i32.to_be_bytes());
    push_unsigned_varint(&mut response, 0);
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&0_i16.to_be_bytes());
    push_compact_nullable_string(&mut response, None);
    push_unsigned_varint(&mut response, 1);
    push_unsigned_varint(&mut response, 0);
    push_unsigned_varint(&mut response, tag_value_len);
    response.resize(response.len() + tag_value_len, 0);
    kafka_frame(&response)
}

type ConsumerGroupDescribeTopicPartitionsFixture<'a> = ([u8; 16], &'a str, &'a [i32]);

struct ConsumerGroupDescribeMemberFixture<'a> {
    member_id: &'a str,
    instance_id: Option<&'a str>,
    rack_id: Option<&'a str>,
    client_id: &'a str,
    client_host: &'a str,
    subscribed_topic_names: &'a [&'a str],
    subscribed_topic_regex: Option<&'a str>,
    assignment: &'a [ConsumerGroupDescribeTopicPartitionsFixture<'a>],
    target_assignment: &'a [ConsumerGroupDescribeTopicPartitionsFixture<'a>],
}

struct ConsumerGroupDescribeGroupFixture<'a> {
    error_code: i16,
    error_message: Option<&'a str>,
    group_id: &'a str,
    group_state: &'a str,
    assignor_name: &'a str,
    members: &'a [ConsumerGroupDescribeMemberFixture<'a>],
}

fn kafka_consumer_group_describe_response_frame(
    correlation_id: i32,
    api_version: i16,
    groups: &[ConsumerGroupDescribeGroupFixture<'_>],
) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&correlation_id.to_be_bytes());
    push_unsigned_varint(&mut response, 0);
    response.extend_from_slice(&0_i32.to_be_bytes());
    push_unsigned_varint(&mut response, groups.len() + 1);
    for group in groups {
        response.extend_from_slice(&group.error_code.to_be_bytes());
        push_compact_nullable_string(&mut response, group.error_message);
        push_compact_string(&mut response, group.group_id);
        push_compact_string(&mut response, group.group_state);
        response.extend_from_slice(&1_i32.to_be_bytes());
        response.extend_from_slice(&1_i32.to_be_bytes());
        push_compact_string(&mut response, group.assignor_name);
        push_unsigned_varint(&mut response, group.members.len() + 1);
        for member in group.members {
            push_compact_string(&mut response, member.member_id);
            push_compact_nullable_string(&mut response, member.instance_id);
            push_compact_nullable_string(&mut response, member.rack_id);
            response.extend_from_slice(&1_i32.to_be_bytes());
            push_compact_string(&mut response, member.client_id);
            push_compact_string(&mut response, member.client_host);
            push_compact_string_array(&mut response, member.subscribed_topic_names);
            push_compact_nullable_string(&mut response, member.subscribed_topic_regex);
            push_topic_partition_assignment_with_names(&mut response, member.assignment);
            push_topic_partition_assignment_with_names(&mut response, member.target_assignment);
            if api_version >= 1 {
                response.push(1);
            }
            push_unsigned_varint(&mut response, 0);
        }
        response.extend_from_slice(&0_i32.to_be_bytes());
        push_unsigned_varint(&mut response, 0);
    }
    push_unsigned_varint(&mut response, 0);
    kafka_frame(&response)
}

fn kafka_consumer_group_describe_response_with_group_count_frame(group_count: usize) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&0_i32.to_be_bytes());
    push_unsigned_varint(&mut response, 0);
    response.extend_from_slice(&0_i32.to_be_bytes());
    push_unsigned_varint(&mut response, group_count + 1);
    kafka_frame(&response)
}

fn kafka_get_telemetry_subscriptions_response_frame(
    correlation_id: i32,
    error_code: i16,
    client_instance_id: [u8; 16],
    accepted_compression_types: &[i8],
    requested_metrics: &[&str],
) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&correlation_id.to_be_bytes());
    push_unsigned_varint(&mut response, 0);
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&error_code.to_be_bytes());
    response.extend_from_slice(&client_instance_id);
    response.extend_from_slice(&7_i32.to_be_bytes());
    push_compact_int8_array(&mut response, accepted_compression_types);
    response.extend_from_slice(&30_000_i32.to_be_bytes());
    response.extend_from_slice(&1_048_576_i32.to_be_bytes());
    response.push(1);
    push_compact_string_array(&mut response, requested_metrics);
    push_unsigned_varint(&mut response, 0);
    kafka_frame(&response)
}

fn kafka_get_telemetry_subscriptions_response_with_compression_type_count_frame(
    compression_type_count: usize,
) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&0_i32.to_be_bytes());
    push_unsigned_varint(&mut response, 0);
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&0_i16.to_be_bytes());
    response.extend_from_slice(&[0_u8; 16]);
    response.extend_from_slice(&7_i32.to_be_bytes());
    push_unsigned_varint(&mut response, compression_type_count + 1);
    kafka_frame(&response)
}

fn kafka_get_telemetry_subscriptions_response_with_requested_metric_count_frame(
    requested_metric_count: usize,
) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&0_i32.to_be_bytes());
    push_unsigned_varint(&mut response, 0);
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&0_i16.to_be_bytes());
    response.extend_from_slice(&[0_u8; 16]);
    response.extend_from_slice(&7_i32.to_be_bytes());
    push_unsigned_varint(&mut response, 1);
    response.extend_from_slice(&30_000_i32.to_be_bytes());
    response.extend_from_slice(&1_048_576_i32.to_be_bytes());
    response.push(1);
    push_unsigned_varint(&mut response, requested_metric_count + 1);
    kafka_frame(&response)
}

fn kafka_push_telemetry_response_frame(correlation_id: i32, error_code: i16) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&correlation_id.to_be_bytes());
    push_unsigned_varint(&mut response, 0);
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&error_code.to_be_bytes());
    push_unsigned_varint(&mut response, 0);
    kafka_frame(&response)
}

fn kafka_list_config_resources_response_frame(
    correlation_id: i32,
    api_version: i16,
    error_code: i16,
    resources: &[(&str, i8)],
) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&correlation_id.to_be_bytes());
    push_unsigned_varint(&mut response, 0);
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&error_code.to_be_bytes());
    push_unsigned_varint(&mut response, resources.len() + 1);
    for (resource_name, resource_type) in resources {
        push_compact_string(&mut response, resource_name);
        if api_version >= 1 {
            response.push(*resource_type as u8);
        }
        push_unsigned_varint(&mut response, 0);
    }
    push_unsigned_varint(&mut response, 0);
    kafka_frame(&response)
}

fn kafka_list_config_resources_response_with_resource_count_frame(
    resource_count: usize,
) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&0_i32.to_be_bytes());
    push_unsigned_varint(&mut response, 0);
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&0_i16.to_be_bytes());
    push_unsigned_varint(&mut response, resource_count + 1);
    kafka_frame(&response)
}

struct DescribeTopicPartitionsPartitionFixture<'a> {
    error_code: i16,
    partition_index: i32,
    replica_nodes: &'a [i32],
    isr_nodes: &'a [i32],
    eligible_leader_replicas: Option<&'a [i32]>,
    last_known_elr: Option<&'a [i32]>,
    offline_replicas: &'a [i32],
}

struct DescribeTopicPartitionsTopicFixture<'a> {
    error_code: i16,
    name: Option<&'a str>,
    topic_id: [u8; 16],
    partitions: &'a [DescribeTopicPartitionsPartitionFixture<'a>],
}

fn kafka_describe_topic_partitions_response_frame(
    correlation_id: i32,
    topics: &[DescribeTopicPartitionsTopicFixture<'_>],
    next_cursor: Option<(&str, i32)>,
) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&correlation_id.to_be_bytes());
    push_unsigned_varint(&mut response, 0);
    response.extend_from_slice(&0_i32.to_be_bytes());
    push_unsigned_varint(&mut response, topics.len() + 1);
    for topic in topics {
        response.extend_from_slice(&topic.error_code.to_be_bytes());
        push_compact_nullable_string(&mut response, topic.name);
        response.extend_from_slice(&topic.topic_id);
        response.push(0);
        push_unsigned_varint(&mut response, topic.partitions.len() + 1);
        for partition in topic.partitions {
            response.extend_from_slice(&partition.error_code.to_be_bytes());
            response.extend_from_slice(&partition.partition_index.to_be_bytes());
            response.extend_from_slice(&1_i32.to_be_bytes());
            response.extend_from_slice(&1_i32.to_be_bytes());
            push_compact_int32_array(&mut response, partition.replica_nodes);
            push_compact_int32_array(&mut response, partition.isr_nodes);
            push_compact_nullable_int32_array(&mut response, partition.eligible_leader_replicas);
            push_compact_nullable_int32_array(&mut response, partition.last_known_elr);
            push_compact_int32_array(&mut response, partition.offline_replicas);
            push_unsigned_varint(&mut response, 0);
        }
        response.extend_from_slice(&0_i32.to_be_bytes());
        push_unsigned_varint(&mut response, 0);
    }
    push_nullable_topic_partition_cursor(&mut response, next_cursor);
    push_unsigned_varint(&mut response, 0);
    kafka_frame(&response)
}

fn kafka_describe_topic_partitions_response_with_topic_count_frame(topic_count: usize) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&0_i32.to_be_bytes());
    push_unsigned_varint(&mut response, 0);
    response.extend_from_slice(&0_i32.to_be_bytes());
    push_unsigned_varint(&mut response, topic_count + 1);
    kafka_frame(&response)
}

fn kafka_describe_topic_partitions_response_with_partition_count_frame(
    partition_count: usize,
) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&0_i32.to_be_bytes());
    push_unsigned_varint(&mut response, 0);
    response.extend_from_slice(&0_i32.to_be_bytes());
    push_unsigned_varint(&mut response, 2);
    response.extend_from_slice(&0_i16.to_be_bytes());
    push_compact_nullable_string(&mut response, Some("orders.secret"));
    response.extend_from_slice(&[31_u8; 16]);
    response.push(0);
    push_unsigned_varint(&mut response, partition_count + 1);
    kafka_frame(&response)
}

fn kafka_add_raft_voter_response_frame(
    correlation_id: i32,
    error_code: i16,
    error_message: Option<&str>,
) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&correlation_id.to_be_bytes());
    push_unsigned_varint(&mut response, 0);
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&error_code.to_be_bytes());
    push_compact_nullable_string(&mut response, error_message);
    push_unsigned_varint(&mut response, 0);
    kafka_frame(&response)
}

fn kafka_remove_raft_voter_response_frame(
    correlation_id: i32,
    error_code: i16,
    error_message: Option<&str>,
) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&correlation_id.to_be_bytes());
    push_unsigned_varint(&mut response, 0);
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&error_code.to_be_bytes());
    push_compact_nullable_string(&mut response, error_message);
    push_unsigned_varint(&mut response, 0);
    kafka_frame(&response)
}

struct UpdateRaftVoterLeaderFixture<'a> {
    leader_id: i32,
    leader_epoch: i32,
    host: &'a str,
    port: i32,
}

fn kafka_update_raft_voter_response_frame(
    correlation_id: i32,
    error_code: i16,
    current_leader: Option<UpdateRaftVoterLeaderFixture<'_>>,
) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&correlation_id.to_be_bytes());
    push_unsigned_varint(&mut response, 0);
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&error_code.to_be_bytes());
    if let Some(current_leader) = current_leader {
        push_unsigned_varint(&mut response, 1);
        push_unsigned_varint(&mut response, 0);
        let mut tag = Vec::new();
        tag.extend_from_slice(&current_leader.leader_id.to_be_bytes());
        tag.extend_from_slice(&current_leader.leader_epoch.to_be_bytes());
        push_compact_string(&mut tag, current_leader.host);
        tag.extend_from_slice(&current_leader.port.to_be_bytes());
        push_unsigned_varint(&mut tag, 0);
        push_unsigned_varint(&mut response, tag.len());
        response.extend_from_slice(&tag);
    } else {
        push_unsigned_varint(&mut response, 0);
    }
    kafka_frame(&response)
}

fn kafka_update_raft_voter_response_with_tag_len_frame(tag_len: usize) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&0_i32.to_be_bytes());
    push_unsigned_varint(&mut response, 0);
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&0_i16.to_be_bytes());
    push_unsigned_varint(&mut response, 1);
    push_unsigned_varint(&mut response, 0);
    push_unsigned_varint(&mut response, tag_len);
    response.resize(response.len() + tag_len, 0);
    kafka_frame(&response)
}

struct InitializeShareGroupStateResultPartitionFixture<'a> {
    partition: i32,
    error_code: i16,
    error_message: Option<&'a str>,
}

struct InitializeShareGroupStateResultTopicFixture<'a> {
    topic_id: [u8; 16],
    partitions: &'a [InitializeShareGroupStateResultPartitionFixture<'a>],
}

fn kafka_initialize_share_group_state_response_frame(
    correlation_id: i32,
    topics: &[InitializeShareGroupStateResultTopicFixture<'_>],
) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&correlation_id.to_be_bytes());
    push_unsigned_varint(&mut response, 0);
    push_unsigned_varint(&mut response, topics.len() + 1);
    for topic in topics {
        response.extend_from_slice(&topic.topic_id);
        push_unsigned_varint(&mut response, topic.partitions.len() + 1);
        for partition in topic.partitions {
            response.extend_from_slice(&partition.partition.to_be_bytes());
            response.extend_from_slice(&partition.error_code.to_be_bytes());
            push_compact_nullable_string(&mut response, partition.error_message);
            push_unsigned_varint(&mut response, 0);
        }
        push_unsigned_varint(&mut response, 0);
    }
    push_unsigned_varint(&mut response, 0);
    kafka_frame(&response)
}

fn kafka_initialize_share_group_state_response_with_topic_count_frame(
    topic_count: usize,
) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&0_i32.to_be_bytes());
    push_unsigned_varint(&mut response, 0);
    push_unsigned_varint(&mut response, topic_count + 1);
    kafka_frame(&response)
}

fn kafka_initialize_share_group_state_response_with_partition_count_frame(
    partition_count: usize,
) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&0_i32.to_be_bytes());
    push_unsigned_varint(&mut response, 0);
    push_unsigned_varint(&mut response, 2);
    response.extend_from_slice(&[29_u8; 16]);
    push_unsigned_varint(&mut response, partition_count + 1);
    kafka_frame(&response)
}

struct ReadShareGroupStateBatchFixture {
    first_offset: i64,
    last_offset: i64,
    delivery_state: i8,
    delivery_count: i16,
}

struct ReadShareGroupStateResultPartitionFixture<'a> {
    partition: i32,
    error_code: i16,
    error_message: Option<&'a str>,
    state_epoch: i32,
    start_offset: i64,
    state_batches: &'a [ReadShareGroupStateBatchFixture],
}

struct ReadShareGroupStateResultTopicFixture<'a> {
    topic_id: [u8; 16],
    partitions: &'a [ReadShareGroupStateResultPartitionFixture<'a>],
}

fn kafka_read_share_group_state_response_frame(
    correlation_id: i32,
    topics: &[ReadShareGroupStateResultTopicFixture<'_>],
) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&correlation_id.to_be_bytes());
    push_unsigned_varint(&mut response, 0);
    push_unsigned_varint(&mut response, topics.len() + 1);
    for topic in topics {
        response.extend_from_slice(&topic.topic_id);
        push_unsigned_varint(&mut response, topic.partitions.len() + 1);
        for partition in topic.partitions {
            response.extend_from_slice(&partition.partition.to_be_bytes());
            response.extend_from_slice(&partition.error_code.to_be_bytes());
            push_compact_nullable_string(&mut response, partition.error_message);
            response.extend_from_slice(&partition.state_epoch.to_be_bytes());
            response.extend_from_slice(&partition.start_offset.to_be_bytes());
            push_unsigned_varint(&mut response, partition.state_batches.len() + 1);
            for batch in partition.state_batches {
                response.extend_from_slice(&batch.first_offset.to_be_bytes());
                response.extend_from_slice(&batch.last_offset.to_be_bytes());
                response.push(batch.delivery_state as u8);
                response.extend_from_slice(&batch.delivery_count.to_be_bytes());
                push_unsigned_varint(&mut response, 0);
            }
            push_unsigned_varint(&mut response, 0);
        }
        push_unsigned_varint(&mut response, 0);
    }
    push_unsigned_varint(&mut response, 0);
    kafka_frame(&response)
}

fn kafka_read_share_group_state_response_with_topic_count_frame(topic_count: usize) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&0_i32.to_be_bytes());
    push_unsigned_varint(&mut response, 0);
    push_unsigned_varint(&mut response, topic_count + 1);
    kafka_frame(&response)
}

fn kafka_read_share_group_state_response_with_partition_count_frame(
    partition_count: usize,
) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&0_i32.to_be_bytes());
    push_unsigned_varint(&mut response, 0);
    push_unsigned_varint(&mut response, 2);
    response.extend_from_slice(&[29_u8; 16]);
    push_unsigned_varint(&mut response, partition_count + 1);
    kafka_frame(&response)
}

fn kafka_read_share_group_state_response_with_batch_count_frame(batch_count: usize) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&0_i32.to_be_bytes());
    push_unsigned_varint(&mut response, 0);
    push_unsigned_varint(&mut response, 2);
    response.extend_from_slice(&[29_u8; 16]);
    push_unsigned_varint(&mut response, 2);
    response.extend_from_slice(&1_i32.to_be_bytes());
    response.extend_from_slice(&0_i16.to_be_bytes());
    push_compact_nullable_string(&mut response, None);
    response.extend_from_slice(&5_i32.to_be_bytes());
    response.extend_from_slice(&100_i64.to_be_bytes());
    push_unsigned_varint(&mut response, batch_count + 1);
    kafka_frame(&response)
}

struct WriteShareGroupStateResultPartitionFixture<'a> {
    partition: i32,
    error_code: i16,
    error_message: Option<&'a str>,
}

struct WriteShareGroupStateResultTopicFixture<'a> {
    topic_id: [u8; 16],
    partitions: &'a [WriteShareGroupStateResultPartitionFixture<'a>],
}

fn kafka_write_share_group_state_response_frame(
    correlation_id: i32,
    topics: &[WriteShareGroupStateResultTopicFixture<'_>],
) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&correlation_id.to_be_bytes());
    push_unsigned_varint(&mut response, 0);
    push_unsigned_varint(&mut response, topics.len() + 1);
    for topic in topics {
        response.extend_from_slice(&topic.topic_id);
        push_unsigned_varint(&mut response, topic.partitions.len() + 1);
        for partition in topic.partitions {
            response.extend_from_slice(&partition.partition.to_be_bytes());
            response.extend_from_slice(&partition.error_code.to_be_bytes());
            push_compact_nullable_string(&mut response, partition.error_message);
            push_unsigned_varint(&mut response, 0);
        }
        push_unsigned_varint(&mut response, 0);
    }
    push_unsigned_varint(&mut response, 0);
    kafka_frame(&response)
}

fn kafka_write_share_group_state_response_with_topic_count_frame(topic_count: usize) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&0_i32.to_be_bytes());
    push_unsigned_varint(&mut response, 0);
    push_unsigned_varint(&mut response, topic_count + 1);
    kafka_frame(&response)
}

fn kafka_write_share_group_state_response_with_partition_count_frame(
    partition_count: usize,
) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&0_i32.to_be_bytes());
    push_unsigned_varint(&mut response, 0);
    push_unsigned_varint(&mut response, 2);
    response.extend_from_slice(&[29_u8; 16]);
    push_unsigned_varint(&mut response, partition_count + 1);
    kafka_frame(&response)
}

struct DeleteShareGroupStateResultPartitionFixture<'a> {
    partition: i32,
    error_code: i16,
    error_message: Option<&'a str>,
}

struct DeleteShareGroupStateResultTopicFixture<'a> {
    topic_id: [u8; 16],
    partitions: &'a [DeleteShareGroupStateResultPartitionFixture<'a>],
}

fn kafka_delete_share_group_state_response_frame(
    correlation_id: i32,
    topics: &[DeleteShareGroupStateResultTopicFixture<'_>],
) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&correlation_id.to_be_bytes());
    push_unsigned_varint(&mut response, 0);
    push_unsigned_varint(&mut response, topics.len() + 1);
    for topic in topics {
        response.extend_from_slice(&topic.topic_id);
        push_unsigned_varint(&mut response, topic.partitions.len() + 1);
        for partition in topic.partitions {
            response.extend_from_slice(&partition.partition.to_be_bytes());
            response.extend_from_slice(&partition.error_code.to_be_bytes());
            push_compact_nullable_string(&mut response, partition.error_message);
            push_unsigned_varint(&mut response, 0);
        }
        push_unsigned_varint(&mut response, 0);
    }
    push_unsigned_varint(&mut response, 0);
    kafka_frame(&response)
}

fn kafka_delete_share_group_state_response_with_topic_count_frame(topic_count: usize) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&0_i32.to_be_bytes());
    push_unsigned_varint(&mut response, 0);
    push_unsigned_varint(&mut response, topic_count + 1);
    kafka_frame(&response)
}

fn kafka_delete_share_group_state_response_with_partition_count_frame(
    partition_count: usize,
) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&0_i32.to_be_bytes());
    push_unsigned_varint(&mut response, 0);
    push_unsigned_varint(&mut response, 2);
    response.extend_from_slice(&[29_u8; 16]);
    push_unsigned_varint(&mut response, partition_count + 1);
    kafka_frame(&response)
}

struct ReadShareGroupStateSummaryResultPartitionFixture<'a> {
    partition: i32,
    error_code: i16,
    error_message: Option<&'a str>,
    state_epoch: i32,
    leader_epoch: i32,
    start_offset: i64,
    delivery_complete_count: Option<i32>,
}

struct ReadShareGroupStateSummaryResultTopicFixture<'a> {
    topic_id: [u8; 16],
    partitions: &'a [ReadShareGroupStateSummaryResultPartitionFixture<'a>],
}

fn kafka_read_share_group_state_summary_response_frame(
    correlation_id: i32,
    topics: &[ReadShareGroupStateSummaryResultTopicFixture<'_>],
    api_version: i16,
) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&correlation_id.to_be_bytes());
    push_unsigned_varint(&mut response, 0);
    push_unsigned_varint(&mut response, topics.len() + 1);
    for topic in topics {
        response.extend_from_slice(&topic.topic_id);
        push_unsigned_varint(&mut response, topic.partitions.len() + 1);
        for partition in topic.partitions {
            response.extend_from_slice(&partition.partition.to_be_bytes());
            response.extend_from_slice(&partition.error_code.to_be_bytes());
            push_compact_nullable_string(&mut response, partition.error_message);
            response.extend_from_slice(&partition.state_epoch.to_be_bytes());
            response.extend_from_slice(&partition.leader_epoch.to_be_bytes());
            response.extend_from_slice(&partition.start_offset.to_be_bytes());
            if api_version >= 1 {
                response.extend_from_slice(
                    &partition
                        .delivery_complete_count
                        .unwrap_or(-1)
                        .to_be_bytes(),
                );
            }
            push_unsigned_varint(&mut response, 0);
        }
        push_unsigned_varint(&mut response, 0);
    }
    push_unsigned_varint(&mut response, 0);
    kafka_frame(&response)
}

fn kafka_read_share_group_state_summary_response_with_topic_count_frame(
    topic_count: usize,
) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&0_i32.to_be_bytes());
    push_unsigned_varint(&mut response, 0);
    push_unsigned_varint(&mut response, topic_count + 1);
    kafka_frame(&response)
}

fn kafka_read_share_group_state_summary_response_with_partition_count_frame(
    partition_count: usize,
) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&0_i32.to_be_bytes());
    push_unsigned_varint(&mut response, 0);
    push_unsigned_varint(&mut response, 2);
    response.extend_from_slice(&[29_u8; 16]);
    push_unsigned_varint(&mut response, partition_count + 1);
    kafka_frame(&response)
}

type DeleteShareGroupOffsetsResponseTopicFixture<'a> = (&'a str, [u8; 16], i16, Option<&'a str>);

fn kafka_delete_share_group_offsets_response_frame(
    correlation_id: i32,
    top_level_error_code: i16,
    top_level_error_message: Option<&str>,
    topics: &[DeleteShareGroupOffsetsResponseTopicFixture<'_>],
) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&correlation_id.to_be_bytes());
    push_unsigned_varint(&mut response, 0);
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&top_level_error_code.to_be_bytes());
    push_compact_nullable_string(&mut response, top_level_error_message);
    push_unsigned_varint(&mut response, topics.len() + 1);
    for (topic, topic_id, error_code, error_message) in topics {
        push_compact_string(&mut response, topic);
        response.extend_from_slice(topic_id);
        response.extend_from_slice(&error_code.to_be_bytes());
        push_compact_nullable_string(&mut response, *error_message);
        push_unsigned_varint(&mut response, 0);
    }
    push_unsigned_varint(&mut response, 0);
    kafka_frame(&response)
}

fn kafka_delete_share_group_offsets_response_with_topic_count_frame(topic_count: usize) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&0_i32.to_be_bytes());
    push_unsigned_varint(&mut response, 0);
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&0_i16.to_be_bytes());
    push_compact_nullable_string(&mut response, None);
    push_unsigned_varint(&mut response, topic_count + 1);
    kafka_frame(&response)
}

type DescribeShareGroupOffsetsResponsePartitionFixture<'a> = (i32, i64, i32, i16, Option<&'a str>);
type DescribeShareGroupOffsetsResponseTopicFixture<'a> = (
    &'a str,
    [u8; 16],
    &'a [DescribeShareGroupOffsetsResponsePartitionFixture<'a>],
);
type DescribeShareGroupOffsetsResponseGroupFixture<'a> = (
    &'a str,
    &'a [DescribeShareGroupOffsetsResponseTopicFixture<'a>],
    i16,
    Option<&'a str>,
);

fn kafka_describe_share_group_offsets_response_frame(
    correlation_id: i32,
    api_version: i16,
    groups: &[DescribeShareGroupOffsetsResponseGroupFixture<'_>],
) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&correlation_id.to_be_bytes());
    push_unsigned_varint(&mut response, 0);
    response.extend_from_slice(&0_i32.to_be_bytes());
    push_unsigned_varint(&mut response, groups.len() + 1);
    for (group_id, topics, group_error_code, group_error_message) in groups {
        push_compact_string(&mut response, group_id);
        push_unsigned_varint(&mut response, topics.len() + 1);
        for (topic, topic_id, partitions) in topics.iter() {
            push_compact_string(&mut response, topic);
            response.extend_from_slice(topic_id);
            push_unsigned_varint(&mut response, partitions.len() + 1);
            for (partition_index, start_offset, leader_epoch, error_code, error_message) in
                partitions.iter()
            {
                response.extend_from_slice(&partition_index.to_be_bytes());
                response.extend_from_slice(&start_offset.to_be_bytes());
                response.extend_from_slice(&leader_epoch.to_be_bytes());
                if api_version >= 1 {
                    response.extend_from_slice(&(-1_i64).to_be_bytes());
                }
                response.extend_from_slice(&error_code.to_be_bytes());
                push_compact_nullable_string(&mut response, *error_message);
                push_unsigned_varint(&mut response, 0);
            }
            push_unsigned_varint(&mut response, 0);
        }
        response.extend_from_slice(&group_error_code.to_be_bytes());
        push_compact_nullable_string(&mut response, *group_error_message);
        push_unsigned_varint(&mut response, 0);
    }
    push_unsigned_varint(&mut response, 0);
    kafka_frame(&response)
}

fn kafka_describe_share_group_offsets_response_with_group_count_frame(
    group_count: usize,
) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&0_i32.to_be_bytes());
    push_unsigned_varint(&mut response, 0);
    response.extend_from_slice(&0_i32.to_be_bytes());
    push_unsigned_varint(&mut response, group_count + 1);
    kafka_frame(&response)
}

fn kafka_sasl_handshake_response_frame(
    correlation_id: i32,
    error_code: i16,
    mechanisms: &[&str],
) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&correlation_id.to_be_bytes());
    response.extend_from_slice(&error_code.to_be_bytes());
    response.extend_from_slice(&(mechanisms.len() as i32).to_be_bytes());
    for mechanism in mechanisms {
        push_kafka_string(&mut response, mechanism);
    }
    kafka_frame(&response)
}

fn kafka_sasl_handshake_response_with_mechanism_count_frame(mechanism_count: i32) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&0_i16.to_be_bytes());
    response.extend_from_slice(&mechanism_count.to_be_bytes());
    kafka_frame(&response)
}

fn kafka_sasl_authenticate_response_frame(
    correlation_id: i32,
    api_version: i16,
    error_code: i16,
    error_message: Option<&str>,
    auth_bytes: &[u8],
) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&correlation_id.to_be_bytes());
    response.extend_from_slice(&error_code.to_be_bytes());
    push_kafka_nullable_string(&mut response, error_message);
    push_kafka_bytes(&mut response, auth_bytes);
    if api_version >= 1 {
        response.extend_from_slice(&60_000_i64.to_be_bytes());
    }
    kafka_frame(&response)
}

fn kafka_init_producer_id_response_frame(
    correlation_id: i32,
    api_version: i16,
    error_code: i16,
) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&correlation_id.to_be_bytes());
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&error_code.to_be_bytes());
    response.extend_from_slice(&42_i64.to_be_bytes());
    response.extend_from_slice(&3_i16.to_be_bytes());
    if api_version >= 2 {
        response.push(0);
    }
    kafka_frame(&response)
}

fn kafka_throttled_error_response_frame(correlation_id: i32, error_code: i16) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&correlation_id.to_be_bytes());
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&error_code.to_be_bytes());
    kafka_frame(&response)
}

fn kafka_metadata_response_frame(
    correlation_id: i32,
    api_version: i16,
    topics: &[(&str, i16, i16)],
) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&correlation_id.to_be_bytes());
    if api_version >= 3 {
        response.extend_from_slice(&0_i32.to_be_bytes());
    }
    response.extend_from_slice(&1_i32.to_be_bytes());
    response.extend_from_slice(&7_i32.to_be_bytes());
    push_kafka_string(&mut response, "broker.secret.local");
    response.extend_from_slice(&9092_i32.to_be_bytes());
    if api_version >= 1 {
        response.extend_from_slice(&(-1_i16).to_be_bytes());
    }
    if api_version >= 2 {
        push_kafka_nullable_string(&mut response, Some("cluster.secret"));
    }
    if api_version >= 1 {
        response.extend_from_slice(&7_i32.to_be_bytes());
    }
    response.extend_from_slice(&(topics.len() as i32).to_be_bytes());
    for (topic, topic_error_code, partition_error_code) in topics {
        response.extend_from_slice(&topic_error_code.to_be_bytes());
        push_kafka_string(&mut response, topic);
        if api_version >= 1 {
            response.push(0);
        }
        response.extend_from_slice(&1_i32.to_be_bytes());
        response.extend_from_slice(&partition_error_code.to_be_bytes());
        response.extend_from_slice(&0_i32.to_be_bytes());
        response.extend_from_slice(&7_i32.to_be_bytes());
        if api_version >= 7 {
            response.extend_from_slice(&3_i32.to_be_bytes());
        }
        push_int32_array(&mut response, &[7]);
        push_int32_array(&mut response, &[7]);
        if api_version >= 5 {
            push_int32_array(&mut response, &[]);
        }
        if api_version >= 8 {
            response.extend_from_slice(&0_i32.to_be_bytes());
        }
    }
    if api_version >= 8 {
        response.extend_from_slice(&0_i32.to_be_bytes());
    }
    kafka_frame(&response)
}

fn kafka_metadata_response_with_topic_count_frame(topic_count: i32) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&(-1_i16).to_be_bytes());
    response.extend_from_slice(&7_i32.to_be_bytes());
    response.extend_from_slice(&topic_count.to_be_bytes());
    kafka_frame(&response)
}

fn kafka_metadata_response_with_partition_count_frame(partition_count: i32) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&0_i32.to_be_bytes());
    response.extend_from_slice(&(-1_i16).to_be_bytes());
    response.extend_from_slice(&7_i32.to_be_bytes());
    response.extend_from_slice(&1_i32.to_be_bytes());
    response.extend_from_slice(&0_i16.to_be_bytes());
    response.extend_from_slice(&6_i16.to_be_bytes());
    response.extend_from_slice(b"orders");
    response.push(0);
    response.extend_from_slice(&partition_count.to_be_bytes());
    kafka_frame(&response)
}

fn push_kafka_string(bytes: &mut Vec<u8>, value: &str) {
    bytes.extend_from_slice(&(value.len() as i16).to_be_bytes());
    bytes.extend_from_slice(value.as_bytes());
}

fn push_kafka_nullable_string(bytes: &mut Vec<u8>, value: Option<&str>) {
    if let Some(value) = value {
        push_kafka_string(bytes, value);
    } else {
        bytes.extend_from_slice(&(-1_i16).to_be_bytes());
    }
}

fn push_compact_string(bytes: &mut Vec<u8>, value: &str) {
    push_unsigned_varint(bytes, value.len() + 1);
    bytes.extend_from_slice(value.as_bytes());
}

fn push_compact_nullable_string(bytes: &mut Vec<u8>, value: Option<&str>) {
    if let Some(value) = value {
        push_compact_string(bytes, value);
    } else {
        push_unsigned_varint(bytes, 0);
    }
}

fn push_compact_nullable_string_array(bytes: &mut Vec<u8>, values: Option<&[&str]>) {
    if let Some(values) = values {
        push_unsigned_varint(bytes, values.len() + 1);
        for value in values {
            push_compact_string(bytes, value);
        }
    } else {
        push_unsigned_varint(bytes, 0);
    }
}

fn push_compact_string_array(bytes: &mut Vec<u8>, values: &[&str]) {
    push_unsigned_varint(bytes, values.len() + 1);
    for value in values {
        push_compact_string(bytes, value);
    }
}

fn push_compact_int8_array(bytes: &mut Vec<u8>, values: &[i8]) {
    push_unsigned_varint(bytes, values.len() + 1);
    for value in values {
        bytes.push(*value as u8);
    }
}

fn push_compact_nullable_topic_partitions(
    bytes: &mut Vec<u8>,
    values: Option<&[ConsumerGroupHeartbeatTopicPartitionsFixture<'_>]>,
) {
    if let Some(values) = values {
        push_unsigned_varint(bytes, values.len() + 1);
        for (topic_id, partitions) in values {
            bytes.extend_from_slice(topic_id);
            push_compact_int32_array(bytes, partitions);
            push_unsigned_varint(bytes, 0);
        }
    } else {
        push_unsigned_varint(bytes, 0);
    }
}

fn push_topic_partition_assignment_with_names(
    bytes: &mut Vec<u8>,
    values: &[ConsumerGroupDescribeTopicPartitionsFixture<'_>],
) {
    push_unsigned_varint(bytes, values.len() + 1);
    for (topic_id, topic_name, partitions) in values {
        bytes.extend_from_slice(topic_id);
        push_compact_string(bytes, topic_name);
        push_compact_int32_array(bytes, partitions);
        push_unsigned_varint(bytes, 0);
    }
    push_unsigned_varint(bytes, 0);
}

fn push_nullable_topic_partition_cursor(bytes: &mut Vec<u8>, cursor: Option<(&str, i32)>) {
    if let Some((topic_name, partition_index)) = cursor {
        push_compact_string(bytes, topic_name);
        bytes.extend_from_slice(&partition_index.to_be_bytes());
        push_unsigned_varint(bytes, 0);
    } else {
        bytes.push(0xff);
    }
}

fn push_nullable_topic_partition_assignment(
    bytes: &mut Vec<u8>,
    values: Option<&[ConsumerGroupHeartbeatTopicPartitionsFixture<'_>]>,
) {
    if let Some(values) = values {
        bytes.push(1);
        push_unsigned_varint(bytes, values.len() + 1);
        for (topic_id, partitions) in values {
            bytes.extend_from_slice(topic_id);
            push_compact_int32_array(bytes, partitions);
            push_unsigned_varint(bytes, 0);
        }
        push_unsigned_varint(bytes, 0);
    } else {
        bytes.push(0xff);
    }
}

fn push_compact_bytes(bytes: &mut Vec<u8>, value: &[u8]) {
    push_unsigned_varint(bytes, value.len() + 1);
    bytes.extend_from_slice(value);
}

fn push_kafka_bytes(bytes: &mut Vec<u8>, value: &[u8]) {
    bytes.extend_from_slice(&(value.len() as i32).to_be_bytes());
    bytes.extend_from_slice(value);
}

fn push_int32_array(bytes: &mut Vec<u8>, values: &[i32]) {
    bytes.extend_from_slice(&(values.len() as i32).to_be_bytes());
    for value in values {
        bytes.extend_from_slice(&value.to_be_bytes());
    }
}

fn push_compact_int32_array(bytes: &mut Vec<u8>, values: &[i32]) {
    push_unsigned_varint(bytes, values.len() + 1);
    for value in values {
        bytes.extend_from_slice(&value.to_be_bytes());
    }
}

fn push_compact_nullable_int32_array(bytes: &mut Vec<u8>, values: Option<&[i32]>) {
    if let Some(values) = values {
        push_unsigned_varint(bytes, values.len() + 1);
        for value in values {
            bytes.extend_from_slice(&value.to_be_bytes());
        }
    } else {
        push_unsigned_varint(bytes, 0);
    }
}

fn push_unsigned_varint(bytes: &mut Vec<u8>, mut value: usize) {
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        bytes.push(byte);
        if value == 0 {
            return;
        }
    }
}
