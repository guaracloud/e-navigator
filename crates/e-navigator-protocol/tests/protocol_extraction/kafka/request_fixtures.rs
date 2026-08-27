fn kafka_request_frame(
    api_key: i16,
    api_version: i16,
    client_id: Option<&[u8]>,
    body: &[u8],
) -> Vec<u8> {
    let mut request = Vec::new();
    request.extend_from_slice(&api_key.to_be_bytes());
    request.extend_from_slice(&api_version.to_be_bytes());
    request.extend_from_slice(&42_i32.to_be_bytes());
    if let Some(client_id) = client_id {
        request.extend_from_slice(&(client_id.len() as i16).to_be_bytes());
        request.extend_from_slice(client_id);
    } else {
        request.extend_from_slice(&(-1_i16).to_be_bytes());
    }
    request.extend_from_slice(body);
    kafka_frame(&request)
}

fn kafka_produce_request_body(topics: &[(&str, i32, &[u8])]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&1_i16.to_be_bytes());
    body.extend_from_slice(&1_000_i32.to_be_bytes());
    body.extend_from_slice(&(topics.len() as i32).to_be_bytes());
    for (topic, partition, records) in topics {
        body.extend_from_slice(&(topic.len() as i16).to_be_bytes());
        body.extend_from_slice(topic.as_bytes());
        body.extend_from_slice(&1_i32.to_be_bytes());
        body.extend_from_slice(&partition.to_be_bytes());
        body.extend_from_slice(&(records.len() as i32).to_be_bytes());
        body.extend_from_slice(records);
    }
    body
}

fn kafka_fetch_request_body(api_version: i16, topics: &[(&str, &[i32])]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&(-1_i32).to_be_bytes());
    body.extend_from_slice(&500_i32.to_be_bytes());
    body.extend_from_slice(&1_i32.to_be_bytes());
    if api_version >= 3 {
        body.extend_from_slice(&1_000_i32.to_be_bytes());
    }
    if api_version >= 4 {
        body.push(0);
    }
    body.extend_from_slice(&(topics.len() as i32).to_be_bytes());
    for (topic, partitions) in topics {
        body.extend_from_slice(&(topic.len() as i16).to_be_bytes());
        body.extend_from_slice(topic.as_bytes());
        body.extend_from_slice(&(partitions.len() as i32).to_be_bytes());
        for partition in *partitions {
            body.extend_from_slice(&partition.to_be_bytes());
            body.extend_from_slice(&42_i64.to_be_bytes());
            if api_version >= 5 {
                body.extend_from_slice(&40_i64.to_be_bytes());
            }
            body.extend_from_slice(&1024_i32.to_be_bytes());
        }
    }
    body
}

fn kafka_offset_commit_request_body(api_version: i16, topics: &[(&str, &[i32])]) -> Vec<u8> {
    let mut body = Vec::new();
    push_kafka_string(&mut body, "group.secret");
    body.extend_from_slice(&3_i32.to_be_bytes());
    push_kafka_string(&mut body, "member.secret");
    if api_version >= 7 {
        push_kafka_nullable_string(&mut body, Some("instance.secret"));
    }
    if api_version <= 4 {
        body.extend_from_slice(&60_000_i64.to_be_bytes());
    }
    body.extend_from_slice(&(topics.len() as i32).to_be_bytes());
    for (topic, partitions) in topics {
        push_kafka_string(&mut body, topic);
        body.extend_from_slice(&(partitions.len() as i32).to_be_bytes());
        for partition in *partitions {
            body.extend_from_slice(&partition.to_be_bytes());
            body.extend_from_slice(&42_i64.to_be_bytes());
            if api_version >= 6 {
                body.extend_from_slice(&3_i32.to_be_bytes());
            }
            push_kafka_nullable_string(&mut body, Some("metadata.secret"));
        }
    }
    body
}

fn kafka_offset_fetch_request_body(api_version: i16, topics: Option<&[(&str, &[i32])]>) -> Vec<u8> {
    let mut body = Vec::new();
    push_kafka_string(&mut body, "group.secret");
    if let Some(topics) = topics {
        body.extend_from_slice(&(topics.len() as i32).to_be_bytes());
        for (topic, partitions) in topics {
            push_kafka_string(&mut body, topic);
            body.extend_from_slice(&(partitions.len() as i32).to_be_bytes());
            for partition in *partitions {
                body.extend_from_slice(&partition.to_be_bytes());
            }
        }
    } else {
        assert!(api_version >= 2);
        body.extend_from_slice(&(-1_i32).to_be_bytes());
    }
    body
}

fn kafka_offset_delete_request_body(topics: &[(&str, &[i32])]) -> Vec<u8> {
    let mut body = Vec::new();
    push_kafka_string(&mut body, "group.secret");
    body.extend_from_slice(&(topics.len() as i32).to_be_bytes());
    for (topic, partitions) in topics {
        push_kafka_string(&mut body, topic);
        body.extend_from_slice(&(partitions.len() as i32).to_be_bytes());
        for partition in *partitions {
            body.extend_from_slice(&partition.to_be_bytes());
        }
    }
    body
}

type OffsetForLeaderEpochRequestPartitionFixture = (i32, i32, i32);
type OffsetForLeaderEpochRequestTopicFixture<'a> =
    (&'a str, &'a [OffsetForLeaderEpochRequestPartitionFixture]);

fn kafka_offset_for_leader_epoch_request_body(
    api_version: i16,
    topics: &[OffsetForLeaderEpochRequestTopicFixture<'_>],
) -> Vec<u8> {
    let mut body = Vec::new();
    if api_version >= 3 {
        body.extend_from_slice(&(-2_i32).to_be_bytes());
    }
    if api_version >= 4 {
        push_unsigned_varint(&mut body, topics.len() + 1);
        for (topic, partitions) in topics {
            push_compact_string(&mut body, topic);
            push_unsigned_varint(&mut body, partitions.len() + 1);
            for (partition, current_leader_epoch, leader_epoch) in *partitions {
                body.extend_from_slice(&partition.to_be_bytes());
                body.extend_from_slice(&current_leader_epoch.to_be_bytes());
                body.extend_from_slice(&leader_epoch.to_be_bytes());
                push_unsigned_varint(&mut body, 0);
            }
            push_unsigned_varint(&mut body, 0);
        }
        push_unsigned_varint(&mut body, 0);
    } else {
        body.extend_from_slice(&(topics.len() as i32).to_be_bytes());
        for (topic, partitions) in topics {
            push_kafka_string(&mut body, topic);
            body.extend_from_slice(&(partitions.len() as i32).to_be_bytes());
            for (partition, current_leader_epoch, leader_epoch) in *partitions {
                body.extend_from_slice(&partition.to_be_bytes());
                body.extend_from_slice(&current_leader_epoch.to_be_bytes());
                body.extend_from_slice(&leader_epoch.to_be_bytes());
            }
        }
    }
    body
}

fn kafka_offset_for_leader_epoch_request_with_topic_count_body(topic_count: i32) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&topic_count.to_be_bytes());
    body
}

fn kafka_offset_for_leader_epoch_flexible_request_with_partition_count_body(
    partition_count: usize,
) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&(-2_i32).to_be_bytes());
    push_unsigned_varint(&mut body, 2);
    push_compact_string(&mut body, "orders");
    push_unsigned_varint(&mut body, partition_count + 1);
    body
}

fn kafka_list_offsets_request_body(api_version: i16, topics: &[(&str, &[i32])]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&(-1_i32).to_be_bytes());
    if api_version >= 2 {
        body.push(0);
    }
    body.extend_from_slice(&(topics.len() as i32).to_be_bytes());
    for (topic, partitions) in topics {
        body.extend_from_slice(&(topic.len() as i16).to_be_bytes());
        body.extend_from_slice(topic.as_bytes());
        body.extend_from_slice(&(partitions.len() as i32).to_be_bytes());
        for partition in *partitions {
            body.extend_from_slice(&partition.to_be_bytes());
            if api_version >= 4 {
                body.extend_from_slice(&3_i32.to_be_bytes());
            }
            body.extend_from_slice(&42_i64.to_be_bytes());
        }
    }
    body
}

fn kafka_delete_records_request_body(topics: &[(&str, &[i32])]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&(topics.len() as i32).to_be_bytes());
    for (topic, partitions) in topics {
        push_kafka_string(&mut body, topic);
        body.extend_from_slice(&(partitions.len() as i32).to_be_bytes());
        for partition in *partitions {
            body.extend_from_slice(&partition.to_be_bytes());
            body.extend_from_slice(&42_i64.to_be_bytes());
        }
    }
    body.extend_from_slice(&60_000_i32.to_be_bytes());
    body
}

fn kafka_delete_topics_request_body(topics: &[&str]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&(topics.len() as i32).to_be_bytes());
    for topic in topics {
        push_kafka_string(&mut body, topic);
    }
    body.extend_from_slice(&60_000_i32.to_be_bytes());
    body
}

fn kafka_create_topics_request_body(
    topic: &str,
    config_name: &str,
    config_value: Option<&str>,
) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&1_i32.to_be_bytes());
    push_kafka_string(&mut body, topic);
    body.extend_from_slice(&1_i32.to_be_bytes());
    body.extend_from_slice(&1_i16.to_be_bytes());
    body.extend_from_slice(&1_i32.to_be_bytes());
    body.extend_from_slice(&0_i32.to_be_bytes());
    push_int32_array(&mut body, &[1]);
    body.extend_from_slice(&1_i32.to_be_bytes());
    push_kafka_string(&mut body, config_name);
    push_kafka_nullable_string(&mut body, config_value);
    body.extend_from_slice(&60_000_i32.to_be_bytes());
    body.push(1);
    body
}

fn kafka_create_partitions_request_body(topic: &str, assignments: Option<&[&[i32]]>) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&1_i32.to_be_bytes());
    push_kafka_string(&mut body, topic);
    body.extend_from_slice(&3_i32.to_be_bytes());
    if let Some(assignments) = assignments {
        body.extend_from_slice(&(assignments.len() as i32).to_be_bytes());
        for brokers in assignments {
            push_int32_array(&mut body, brokers);
        }
    } else {
        body.extend_from_slice(&(-1_i32).to_be_bytes());
    }
    body.extend_from_slice(&60_000_i32.to_be_bytes());
    body.push(1);
    body
}

fn kafka_create_acls_request_body(resource_name: &str, principal: &str, host: &str) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&1_i32.to_be_bytes());
    body.push(2);
    push_kafka_string(&mut body, resource_name);
    body.push(3);
    push_kafka_string(&mut body, principal);
    push_kafka_string(&mut body, host);
    body.push(3);
    body.push(3);
    body
}

fn kafka_describe_acls_request_body(
    resource_name: Option<&str>,
    principal: Option<&str>,
    host: Option<&str>,
) -> Vec<u8> {
    let mut body = Vec::new();
    body.push(2);
    push_kafka_nullable_string(&mut body, resource_name);
    body.push(3);
    push_kafka_nullable_string(&mut body, principal);
    push_kafka_nullable_string(&mut body, host);
    body.push(3);
    body.push(3);
    body
}

fn kafka_delete_acls_request_body(
    resource_name: Option<&str>,
    principal: Option<&str>,
    host: Option<&str>,
) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&1_i32.to_be_bytes());
    body.push(2);
    push_kafka_nullable_string(&mut body, resource_name);
    body.push(3);
    push_kafka_nullable_string(&mut body, principal);
    push_kafka_nullable_string(&mut body, host);
    body.push(3);
    body.push(3);
    body
}

fn kafka_describe_configs_request_body(
    api_version: i16,
    resource_name: &str,
    keys: Option<&[&str]>,
) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&1_i32.to_be_bytes());
    body.push(2);
    push_kafka_string(&mut body, resource_name);
    if let Some(keys) = keys {
        body.extend_from_slice(&(keys.len() as i32).to_be_bytes());
        for key in keys {
            push_kafka_string(&mut body, key);
        }
    } else {
        body.extend_from_slice(&(-1_i32).to_be_bytes());
    }
    body.push(1);
    if api_version >= 3 {
        body.push(1);
    }
    body
}

fn kafka_alter_configs_request_body(
    resource_name: &str,
    configs: &[(&str, Option<&str>)],
) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&1_i32.to_be_bytes());
    body.push(2);
    push_kafka_string(&mut body, resource_name);
    body.extend_from_slice(&(configs.len() as i32).to_be_bytes());
    for (name, value) in configs {
        push_kafka_string(&mut body, name);
        push_kafka_nullable_string(&mut body, *value);
    }
    body.push(1);
    body
}

type IncrementalAlterConfigFixture<'a> = (&'a str, i8, Option<&'a str>);
type IncrementalAlterConfigsResourceFixture<'a> =
    (i8, &'a str, &'a [IncrementalAlterConfigFixture<'a>]);

fn kafka_incremental_alter_configs_request_body(
    api_version: i16,
    resources: &[IncrementalAlterConfigsResourceFixture<'_>],
) -> Vec<u8> {
    let mut body = Vec::new();
    if api_version == 0 {
        body.extend_from_slice(&(resources.len() as i32).to_be_bytes());
        for (resource_type, resource_name, configs) in resources {
            body.push(*resource_type as u8);
            push_kafka_string(&mut body, resource_name);
            body.extend_from_slice(&(configs.len() as i32).to_be_bytes());
            for (name, operation, value) in *configs {
                push_kafka_string(&mut body, name);
                body.push(*operation as u8);
                push_kafka_nullable_string(&mut body, *value);
            }
        }
    } else {
        push_unsigned_varint(&mut body, resources.len() + 1);
        for (resource_type, resource_name, configs) in resources {
            body.push(*resource_type as u8);
            push_compact_string(&mut body, resource_name);
            push_unsigned_varint(&mut body, configs.len() + 1);
            for (name, operation, value) in *configs {
                push_compact_string(&mut body, name);
                body.push(*operation as u8);
                push_compact_nullable_string(&mut body, *value);
                push_unsigned_varint(&mut body, 0);
            }
            push_unsigned_varint(&mut body, 0);
        }
    }
    body.push(1);
    if api_version >= 1 {
        push_unsigned_varint(&mut body, 0);
    }
    body
}

type AlterPartitionReassignmentFixture<'a> = (i32, Option<&'a [i32]>);
type AlterPartitionReassignmentsTopicFixture<'a> =
    (&'a str, &'a [AlterPartitionReassignmentFixture<'a>]);

fn kafka_alter_partition_reassignments_request_body(
    api_version: i16,
    topics: &[AlterPartitionReassignmentsTopicFixture<'_>],
) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&60_000_i32.to_be_bytes());
    if api_version >= 1 {
        body.push(1);
    }
    push_unsigned_varint(&mut body, topics.len() + 1);
    for (topic, partitions) in topics {
        push_compact_string(&mut body, topic);
        push_unsigned_varint(&mut body, partitions.len() + 1);
        for (partition, replicas) in *partitions {
            body.extend_from_slice(&partition.to_be_bytes());
            push_compact_nullable_int32_array(&mut body, *replicas);
            push_unsigned_varint(&mut body, 0);
        }
        push_unsigned_varint(&mut body, 0);
    }
    push_unsigned_varint(&mut body, 0);
    body
}

type ListPartitionReassignmentsRequestTopicFixture<'a> = (&'a str, &'a [i32]);

fn kafka_list_partition_reassignments_request_body(
    topics: Option<&[ListPartitionReassignmentsRequestTopicFixture<'_>]>,
) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&60_000_i32.to_be_bytes());
    if let Some(topics) = topics {
        push_unsigned_varint(&mut body, topics.len() + 1);
        for (topic, partitions) in topics {
            push_compact_string(&mut body, topic);
            push_compact_int32_array(&mut body, partitions);
            push_unsigned_varint(&mut body, 0);
        }
    } else {
        push_unsigned_varint(&mut body, 0);
    }
    push_unsigned_varint(&mut body, 0);
    body
}

type DescribeClientQuotasComponentFixture<'a> = (&'a str, i8, Option<&'a str>);
type ClientQuotaEntityFixture<'a> = (&'a str, Option<&'a str>);
type AlterClientQuotaOpFixture<'a> = (&'a str, f64, bool);
type AlterClientQuotaEntryFixture<'a> = (
    &'a [ClientQuotaEntityFixture<'a>],
    &'a [AlterClientQuotaOpFixture<'a>],
);

fn kafka_describe_client_quotas_request_body(
    api_version: i16,
    components: &[DescribeClientQuotasComponentFixture<'_>],
) -> Vec<u8> {
    let mut body = Vec::new();
    if api_version == 0 {
        body.extend_from_slice(&(components.len() as i32).to_be_bytes());
        for (entity_type, match_type, match_value) in components {
            push_kafka_string(&mut body, entity_type);
            body.push(*match_type as u8);
            push_kafka_nullable_string(&mut body, *match_value);
        }
        body.push(1);
    } else {
        push_unsigned_varint(&mut body, components.len() + 1);
        for (entity_type, match_type, match_value) in components {
            push_compact_string(&mut body, entity_type);
            body.push(*match_type as u8);
            push_compact_nullable_string(&mut body, *match_value);
            push_unsigned_varint(&mut body, 0);
        }
        body.push(1);
        push_unsigned_varint(&mut body, 0);
    }
    body
}

fn kafka_alter_client_quotas_request_body(
    api_version: i16,
    entries: &[AlterClientQuotaEntryFixture<'_>],
) -> Vec<u8> {
    let mut body = Vec::new();
    if api_version == 0 {
        body.extend_from_slice(&(entries.len() as i32).to_be_bytes());
        for (entities, ops) in entries {
            body.extend_from_slice(&(entities.len() as i32).to_be_bytes());
            for (entity_type, entity_name) in *entities {
                push_kafka_string(&mut body, entity_type);
                push_kafka_nullable_string(&mut body, *entity_name);
            }
            body.extend_from_slice(&(ops.len() as i32).to_be_bytes());
            for (key, value, remove) in *ops {
                push_kafka_string(&mut body, key);
                body.extend_from_slice(&value.to_be_bytes());
                body.push(u8::from(*remove));
            }
        }
        body.push(1);
    } else {
        push_unsigned_varint(&mut body, entries.len() + 1);
        for (entities, ops) in entries {
            push_unsigned_varint(&mut body, entities.len() + 1);
            for (entity_type, entity_name) in *entities {
                push_compact_string(&mut body, entity_type);
                push_compact_nullable_string(&mut body, *entity_name);
                push_unsigned_varint(&mut body, 0);
            }
            push_unsigned_varint(&mut body, ops.len() + 1);
            for (key, value, remove) in *ops {
                push_compact_string(&mut body, key);
                body.extend_from_slice(&value.to_be_bytes());
                body.push(u8::from(*remove));
                push_unsigned_varint(&mut body, 0);
            }
            push_unsigned_varint(&mut body, 0);
        }
        body.push(1);
        push_unsigned_varint(&mut body, 0);
    }
    body
}

fn kafka_describe_user_scram_credentials_request_body(users: Option<&[&str]>) -> Vec<u8> {
    let mut body = Vec::new();
    if let Some(users) = users {
        push_unsigned_varint(&mut body, users.len() + 1);
        for user in users {
            push_compact_string(&mut body, user);
            push_unsigned_varint(&mut body, 0);
        }
    } else {
        push_unsigned_varint(&mut body, 0);
    }
    push_unsigned_varint(&mut body, 0);
    body
}

type AlterUserScramCredentialDeletionFixture<'a> = (&'a str, i8);
type AlterUserScramCredentialUpsertionFixture<'a> = (&'a str, i8, i32, &'a [u8], &'a [u8]);

fn kafka_alter_user_scram_credentials_request_body(
    deletions: &[AlterUserScramCredentialDeletionFixture<'_>],
    upsertions: &[AlterUserScramCredentialUpsertionFixture<'_>],
) -> Vec<u8> {
    let mut body = Vec::new();
    push_unsigned_varint(&mut body, deletions.len() + 1);
    for (name, mechanism) in deletions {
        push_compact_string(&mut body, name);
        body.push(*mechanism as u8);
        push_unsigned_varint(&mut body, 0);
    }
    push_unsigned_varint(&mut body, upsertions.len() + 1);
    for (name, mechanism, iterations, salt, salted_password) in upsertions {
        push_compact_string(&mut body, name);
        body.push(*mechanism as u8);
        body.extend_from_slice(&iterations.to_be_bytes());
        push_compact_bytes(&mut body, salt);
        push_compact_bytes(&mut body, salted_password);
        push_unsigned_varint(&mut body, 0);
    }
    push_unsigned_varint(&mut body, 0);
    body
}

fn kafka_describe_quorum_request_body(topics: &[(&str, &[i32])]) -> Vec<u8> {
    let mut body = Vec::new();
    push_unsigned_varint(&mut body, topics.len() + 1);
    for (topic, partitions) in topics {
        push_compact_string(&mut body, topic);
        push_unsigned_varint(&mut body, partitions.len() + 1);
        for partition in *partitions {
            body.extend_from_slice(&partition.to_be_bytes());
            push_unsigned_varint(&mut body, 0);
        }
        push_unsigned_varint(&mut body, 0);
    }
    push_unsigned_varint(&mut body, 0);
    body
}

type UpdateFeaturesRequestFixture<'a> = (&'a str, i16, i8);

fn kafka_update_features_request_body(
    api_version: i16,
    updates: &[UpdateFeaturesRequestFixture<'_>],
    validate_only: bool,
) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&60_000_i32.to_be_bytes());
    push_unsigned_varint(&mut body, updates.len() + 1);
    for (feature, max_version_level, update_type) in updates {
        push_compact_string(&mut body, feature);
        body.extend_from_slice(&max_version_level.to_be_bytes());
        body.push(*update_type as u8);
        push_unsigned_varint(&mut body, 0);
    }
    if api_version >= 1 {
        body.push(u8::from(validate_only));
    }
    push_unsigned_varint(&mut body, 0);
    body
}

fn kafka_describe_cluster_request_body(api_version: i16) -> Vec<u8> {
    let mut body = Vec::new();
    body.push(1);
    if api_version >= 1 {
        body.push(2);
    }
    if api_version >= 2 {
        body.push(1);
    }
    push_unsigned_varint(&mut body, 0);
    body
}

type DescribeProducersRequestTopicFixture<'a> = (&'a str, &'a [i32]);

fn kafka_describe_producers_request_body(
    topics: &[DescribeProducersRequestTopicFixture<'_>],
) -> Vec<u8> {
    let mut body = Vec::new();
    push_unsigned_varint(&mut body, topics.len() + 1);
    for (topic, partitions) in topics {
        push_compact_string(&mut body, topic);
        push_compact_int32_array(&mut body, partitions);
        push_unsigned_varint(&mut body, 0);
    }
    push_unsigned_varint(&mut body, 0);
    body
}

fn kafka_broker_heartbeat_request_body(
    api_version: i16,
    broker_id: i32,
    broker_epoch: i64,
    metadata_offset: i64,
    want_fence: bool,
    want_shutdown: bool,
) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&broker_id.to_be_bytes());
    body.extend_from_slice(&broker_epoch.to_be_bytes());
    body.extend_from_slice(&metadata_offset.to_be_bytes());
    body.push(u8::from(want_fence));
    body.push(u8::from(want_shutdown));
    if api_version == 0 {
        push_unsigned_varint(&mut body, 0);
    } else {
        push_unsigned_varint(&mut body, if api_version >= 2 { 2 } else { 1 });
        push_unsigned_varint(&mut body, 0);
        let mut offline_log_dirs = Vec::new();
        push_unsigned_varint(&mut offline_log_dirs, 2);
        offline_log_dirs.extend_from_slice(&[7_u8; 16]);
        push_unsigned_varint(&mut body, offline_log_dirs.len());
        body.extend_from_slice(&offline_log_dirs);
        if api_version >= 2 {
            push_unsigned_varint(&mut body, 1);
            let mut cordoned_log_dirs = Vec::new();
            push_unsigned_varint(&mut cordoned_log_dirs, 0);
            push_unsigned_varint(&mut body, cordoned_log_dirs.len());
            body.extend_from_slice(&cordoned_log_dirs);
        }
    }
    body
}

fn kafka_broker_heartbeat_request_body_with_tag_value_len(tag_value_len: usize) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&42_i32.to_be_bytes());
    body.extend_from_slice(&9_876_i64.to_be_bytes());
    body.extend_from_slice(&123_456_i64.to_be_bytes());
    body.push(1);
    body.push(0);
    push_unsigned_varint(&mut body, 1);
    push_unsigned_varint(&mut body, 0);
    push_unsigned_varint(&mut body, tag_value_len);
    body.resize(body.len() + tag_value_len, 0);
    body
}

fn kafka_unregister_broker_request_body(broker_id: i32) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&broker_id.to_be_bytes());
    push_unsigned_varint(&mut body, 0);
    body
}

fn kafka_describe_transactions_request_body(transactional_ids: &[&str]) -> Vec<u8> {
    let mut body = Vec::new();
    push_unsigned_varint(&mut body, transactional_ids.len() + 1);
    for transactional_id in transactional_ids {
        push_compact_string(&mut body, transactional_id);
    }
    push_unsigned_varint(&mut body, 0);
    body
}

fn kafka_list_transactions_request_body(
    api_version: i16,
    state_filters: &[&str],
    producer_id_filters: &[i64],
    transactional_id_pattern: Option<&str>,
) -> Vec<u8> {
    let mut body = Vec::new();
    push_unsigned_varint(&mut body, state_filters.len() + 1);
    for state_filter in state_filters {
        push_compact_string(&mut body, state_filter);
    }
    push_unsigned_varint(&mut body, producer_id_filters.len() + 1);
    for producer_id in producer_id_filters {
        body.extend_from_slice(&producer_id.to_be_bytes());
    }
    if api_version >= 1 {
        body.extend_from_slice(&123456_i64.to_be_bytes());
    }
    if api_version >= 2 {
        push_compact_nullable_string(&mut body, transactional_id_pattern);
    }
    push_unsigned_varint(&mut body, 0);
    body
}

fn kafka_allocate_producer_ids_request_body(broker_id: i32, broker_epoch: i64) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&broker_id.to_be_bytes());
    body.extend_from_slice(&broker_epoch.to_be_bytes());
    push_unsigned_varint(&mut body, 0);
    body
}

type ConsumerGroupHeartbeatTopicPartitionsFixture<'a> = ([u8; 16], &'a [i32]);

struct ConsumerGroupHeartbeatRequestFixture<'a> {
    api_version: i16,
    group_id: &'a str,
    member_id: &'a str,
    instance_id: Option<&'a str>,
    rack_id: Option<&'a str>,
    subscribed_topic_names: Option<&'a [&'a str]>,
    subscribed_topic_regex: Option<&'a str>,
    server_assignor: Option<&'a str>,
    topic_partitions: Option<&'a [ConsumerGroupHeartbeatTopicPartitionsFixture<'a>]>,
}

struct ShareGroupHeartbeatRequestFixture<'a> {
    group_id: &'a str,
    member_id: &'a str,
    rack_id: Option<&'a str>,
    subscribed_topic_names: Option<&'a [&'a str]>,
}

fn kafka_consumer_group_heartbeat_prefix_body(
    group_id: &str,
    member_id: &str,
    instance_id: Option<&str>,
    rack_id: Option<&str>,
) -> Vec<u8> {
    let mut body = Vec::new();
    push_compact_string(&mut body, group_id);
    push_compact_string(&mut body, member_id);
    body.extend_from_slice(&1_i32.to_be_bytes());
    push_compact_nullable_string(&mut body, instance_id);
    push_compact_nullable_string(&mut body, rack_id);
    body.extend_from_slice(&30_000_i32.to_be_bytes());
    body
}

fn kafka_consumer_group_heartbeat_request_body(
    fixture: &ConsumerGroupHeartbeatRequestFixture<'_>,
) -> Vec<u8> {
    let mut body = kafka_consumer_group_heartbeat_prefix_body(
        fixture.group_id,
        fixture.member_id,
        fixture.instance_id,
        fixture.rack_id,
    );
    push_compact_nullable_string_array(&mut body, fixture.subscribed_topic_names);
    if fixture.api_version >= 1 {
        push_compact_nullable_string(&mut body, fixture.subscribed_topic_regex);
    }
    push_compact_nullable_string(&mut body, fixture.server_assignor);
    push_compact_nullable_topic_partitions(&mut body, fixture.topic_partitions);
    push_unsigned_varint(&mut body, 0);
    body
}

fn kafka_share_group_heartbeat_request_body(
    fixture: &ShareGroupHeartbeatRequestFixture<'_>,
) -> Vec<u8> {
    let mut body = Vec::new();
    push_compact_string(&mut body, fixture.group_id);
    push_compact_string(&mut body, fixture.member_id);
    body.extend_from_slice(&1_i32.to_be_bytes());
    push_compact_nullable_string(&mut body, fixture.rack_id);
    push_compact_nullable_string_array(&mut body, fixture.subscribed_topic_names);
    push_unsigned_varint(&mut body, 0);
    body
}

type ControllerRegistrationListenerFixture<'a> = (&'a str, &'a str, u16, i16);
type ControllerRegistrationFeatureFixture<'a> = (&'a str, i16, i16);

fn kafka_controller_registration_request_body(
    controller_id: i32,
    incarnation_id: [u8; 16],
    listeners: &[ControllerRegistrationListenerFixture<'_>],
    features: &[ControllerRegistrationFeatureFixture<'_>],
) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&controller_id.to_be_bytes());
    body.extend_from_slice(&incarnation_id);
    body.push(1);
    push_unsigned_varint(&mut body, listeners.len() + 1);
    for (name, host, port, security_protocol) in listeners {
        push_compact_string(&mut body, name);
        push_compact_string(&mut body, host);
        body.extend_from_slice(&port.to_be_bytes());
        body.extend_from_slice(&security_protocol.to_be_bytes());
        push_unsigned_varint(&mut body, 0);
    }
    push_unsigned_varint(&mut body, features.len() + 1);
    for (name, min_version, max_version) in features {
        push_compact_string(&mut body, name);
        body.extend_from_slice(&min_version.to_be_bytes());
        body.extend_from_slice(&max_version.to_be_bytes());
        push_unsigned_varint(&mut body, 0);
    }
    push_unsigned_varint(&mut body, 0);
    body
}

fn kafka_consumer_group_describe_request_body(_api_version: i16, group_ids: &[&str]) -> Vec<u8> {
    let mut body = Vec::new();
    push_unsigned_varint(&mut body, group_ids.len() + 1);
    for group_id in group_ids {
        push_compact_string(&mut body, group_id);
    }
    body.push(1);
    push_unsigned_varint(&mut body, 0);
    body
}

fn kafka_get_telemetry_subscriptions_request_body(client_instance_id: [u8; 16]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&client_instance_id);
    push_unsigned_varint(&mut body, 0);
    body
}

fn kafka_push_telemetry_request_body(client_instance_id: [u8; 16], metrics: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&client_instance_id);
    body.extend_from_slice(&7_i32.to_be_bytes());
    body.push(1);
    body.push(0);
    push_compact_bytes(&mut body, metrics);
    push_unsigned_varint(&mut body, 0);
    body
}

fn kafka_list_config_resources_request_body(resource_types: &[i8]) -> Vec<u8> {
    let mut body = Vec::new();
    push_compact_int8_array(&mut body, resource_types);
    push_unsigned_varint(&mut body, 0);
    body
}

fn kafka_describe_topic_partitions_request_body(
    topics: &[&str],
    cursor: Option<(&str, i32)>,
) -> Vec<u8> {
    let mut body = Vec::new();
    push_unsigned_varint(&mut body, topics.len() + 1);
    for topic in topics {
        push_compact_string(&mut body, topic);
        push_unsigned_varint(&mut body, 0);
    }
    body.extend_from_slice(&100_i32.to_be_bytes());
    push_nullable_topic_partition_cursor(&mut body, cursor);
    push_unsigned_varint(&mut body, 0);
    body
}

fn kafka_add_raft_voter_request_body(
    api_version: i16,
    cluster_id: Option<&str>,
    listeners: &[(&str, &str, u16)],
) -> Vec<u8> {
    let mut body = Vec::new();
    push_compact_nullable_string(&mut body, cluster_id);
    body.extend_from_slice(&100_i32.to_be_bytes());
    body.extend_from_slice(&1_i32.to_be_bytes());
    body.extend_from_slice(&[29_u8; 16]);
    push_unsigned_varint(&mut body, listeners.len() + 1);
    for (name, host, port) in listeners {
        push_compact_string(&mut body, name);
        push_compact_string(&mut body, host);
        body.extend_from_slice(&port.to_be_bytes());
        push_unsigned_varint(&mut body, 0);
    }
    if api_version >= 1 {
        body.push(1);
    }
    push_unsigned_varint(&mut body, 0);
    body
}

fn kafka_remove_raft_voter_request_body(cluster_id: Option<&str>) -> Vec<u8> {
    let mut body = Vec::new();
    push_compact_nullable_string(&mut body, cluster_id);
    body.extend_from_slice(&1_i32.to_be_bytes());
    body.extend_from_slice(&[29_u8; 16]);
    push_unsigned_varint(&mut body, 0);
    body
}

fn kafka_update_raft_voter_request_body(
    cluster_id: Option<&str>,
    listeners: &[(&str, &str, u16)],
) -> Vec<u8> {
    let mut body = Vec::new();
    push_compact_nullable_string(&mut body, cluster_id);
    body.extend_from_slice(&100_i32.to_be_bytes());
    body.extend_from_slice(&1_i32.to_be_bytes());
    body.extend_from_slice(&[29_u8; 16]);
    push_unsigned_varint(&mut body, listeners.len() + 1);
    for (name, host, port) in listeners {
        push_compact_string(&mut body, name);
        push_compact_string(&mut body, host);
        body.extend_from_slice(&port.to_be_bytes());
        push_unsigned_varint(&mut body, 0);
    }
    body.extend_from_slice(&1_i16.to_be_bytes());
    body.extend_from_slice(&2_i16.to_be_bytes());
    push_unsigned_varint(&mut body, 0);
    body
}

struct InitializeShareGroupStatePartitionFixture {
    partition: i32,
    state_epoch: i32,
    start_offset: i64,
}

struct InitializeShareGroupStateTopicFixture<'a> {
    topic_id: [u8; 16],
    partitions: &'a [InitializeShareGroupStatePartitionFixture],
}

fn kafka_initialize_share_group_state_request_body(
    group_id: &str,
    topics: &[InitializeShareGroupStateTopicFixture<'_>],
) -> Vec<u8> {
    let mut body = Vec::new();
    push_compact_string(&mut body, group_id);
    push_unsigned_varint(&mut body, topics.len() + 1);
    for topic in topics {
        body.extend_from_slice(&topic.topic_id);
        push_unsigned_varint(&mut body, topic.partitions.len() + 1);
        for partition in topic.partitions {
            body.extend_from_slice(&partition.partition.to_be_bytes());
            body.extend_from_slice(&partition.state_epoch.to_be_bytes());
            body.extend_from_slice(&partition.start_offset.to_be_bytes());
            push_unsigned_varint(&mut body, 0);
        }
        push_unsigned_varint(&mut body, 0);
    }
    push_unsigned_varint(&mut body, 0);
    body
}

struct ReadShareGroupStatePartitionFixture {
    partition: i32,
    leader_epoch: i32,
}

struct ReadShareGroupStateTopicFixture<'a> {
    topic_id: [u8; 16],
    partitions: &'a [ReadShareGroupStatePartitionFixture],
}

fn kafka_read_share_group_state_request_body(
    group_id: &str,
    topics: &[ReadShareGroupStateTopicFixture<'_>],
) -> Vec<u8> {
    let mut body = Vec::new();
    push_compact_string(&mut body, group_id);
    push_unsigned_varint(&mut body, topics.len() + 1);
    for topic in topics {
        body.extend_from_slice(&topic.topic_id);
        push_unsigned_varint(&mut body, topic.partitions.len() + 1);
        for partition in topic.partitions {
            body.extend_from_slice(&partition.partition.to_be_bytes());
            body.extend_from_slice(&partition.leader_epoch.to_be_bytes());
            push_unsigned_varint(&mut body, 0);
        }
        push_unsigned_varint(&mut body, 0);
    }
    push_unsigned_varint(&mut body, 0);
    body
}

struct WriteShareGroupStateBatchFixture {
    first_offset: i64,
    last_offset: i64,
    delivery_state: i8,
    delivery_count: i16,
}

struct WriteShareGroupStatePartitionFixture<'a> {
    partition: i32,
    state_epoch: i32,
    leader_epoch: i32,
    start_offset: i64,
    delivery_complete_count: Option<i32>,
    state_batches: &'a [WriteShareGroupStateBatchFixture],
}

struct WriteShareGroupStateTopicFixture<'a> {
    topic_id: [u8; 16],
    partitions: &'a [WriteShareGroupStatePartitionFixture<'a>],
}

fn kafka_write_share_group_state_request_body(
    group_id: &str,
    topics: &[WriteShareGroupStateTopicFixture<'_>],
    api_version: i16,
) -> Vec<u8> {
    let mut body = Vec::new();
    push_compact_string(&mut body, group_id);
    push_unsigned_varint(&mut body, topics.len() + 1);
    for topic in topics {
        body.extend_from_slice(&topic.topic_id);
        push_unsigned_varint(&mut body, topic.partitions.len() + 1);
        for partition in topic.partitions {
            body.extend_from_slice(&partition.partition.to_be_bytes());
            body.extend_from_slice(&partition.state_epoch.to_be_bytes());
            body.extend_from_slice(&partition.leader_epoch.to_be_bytes());
            body.extend_from_slice(&partition.start_offset.to_be_bytes());
            if api_version >= 1 {
                body.extend_from_slice(
                    &partition
                        .delivery_complete_count
                        .unwrap_or(-1)
                        .to_be_bytes(),
                );
            }
            push_unsigned_varint(&mut body, partition.state_batches.len() + 1);
            for batch in partition.state_batches {
                body.extend_from_slice(&batch.first_offset.to_be_bytes());
                body.extend_from_slice(&batch.last_offset.to_be_bytes());
                body.push(batch.delivery_state as u8);
                body.extend_from_slice(&batch.delivery_count.to_be_bytes());
                push_unsigned_varint(&mut body, 0);
            }
            push_unsigned_varint(&mut body, 0);
        }
        push_unsigned_varint(&mut body, 0);
    }
    push_unsigned_varint(&mut body, 0);
    body
}

struct DeleteShareGroupStatePartitionFixture {
    partition: i32,
}

struct DeleteShareGroupStateTopicFixture<'a> {
    topic_id: [u8; 16],
    partitions: &'a [DeleteShareGroupStatePartitionFixture],
}

fn kafka_delete_share_group_state_request_body(
    group_id: &str,
    topics: &[DeleteShareGroupStateTopicFixture<'_>],
) -> Vec<u8> {
    let mut body = Vec::new();
    push_compact_string(&mut body, group_id);
    push_unsigned_varint(&mut body, topics.len() + 1);
    for topic in topics {
        body.extend_from_slice(&topic.topic_id);
        push_unsigned_varint(&mut body, topic.partitions.len() + 1);
        for partition in topic.partitions {
            body.extend_from_slice(&partition.partition.to_be_bytes());
            push_unsigned_varint(&mut body, 0);
        }
        push_unsigned_varint(&mut body, 0);
    }
    push_unsigned_varint(&mut body, 0);
    body
}

struct ReadShareGroupStateSummaryPartitionFixture {
    partition: i32,
    leader_epoch: i32,
}

struct ReadShareGroupStateSummaryTopicFixture<'a> {
    topic_id: [u8; 16],
    partitions: &'a [ReadShareGroupStateSummaryPartitionFixture],
}

fn kafka_read_share_group_state_summary_request_body(
    group_id: &str,
    topics: &[ReadShareGroupStateSummaryTopicFixture<'_>],
) -> Vec<u8> {
    let mut body = Vec::new();
    push_compact_string(&mut body, group_id);
    push_unsigned_varint(&mut body, topics.len() + 1);
    for topic in topics {
        body.extend_from_slice(&topic.topic_id);
        push_unsigned_varint(&mut body, topic.partitions.len() + 1);
        for partition in topic.partitions {
            body.extend_from_slice(&partition.partition.to_be_bytes());
            body.extend_from_slice(&partition.leader_epoch.to_be_bytes());
            push_unsigned_varint(&mut body, 0);
        }
        push_unsigned_varint(&mut body, 0);
    }
    push_unsigned_varint(&mut body, 0);
    body
}

type DescribeShareGroupOffsetsRequestTopicFixture<'a> = (&'a str, &'a [i32]);
type DescribeShareGroupOffsetsRequestGroupFixture<'a> = (
    &'a str,
    Option<&'a [DescribeShareGroupOffsetsRequestTopicFixture<'a>]>,
);

fn kafka_describe_share_group_offsets_request_body(
    groups: &[DescribeShareGroupOffsetsRequestGroupFixture<'_>],
) -> Vec<u8> {
    let mut body = Vec::new();
    push_unsigned_varint(&mut body, groups.len() + 1);
    for (group_id, topics) in groups {
        push_compact_string(&mut body, group_id);
        match topics {
            Some(topics) => {
                push_unsigned_varint(&mut body, topics.len() + 1);
                for (topic, partitions) in topics.iter() {
                    push_compact_string(&mut body, topic);
                    push_unsigned_varint(&mut body, partitions.len() + 1);
                    for partition in partitions.iter() {
                        body.extend_from_slice(&partition.to_be_bytes());
                    }
                    push_unsigned_varint(&mut body, 0);
                }
            }
            None => push_unsigned_varint(&mut body, 0),
        }
        push_unsigned_varint(&mut body, 0);
    }
    push_unsigned_varint(&mut body, 0);
    body
}

fn kafka_delete_share_group_offsets_request_body(group_id: &str, topics: &[&str]) -> Vec<u8> {
    let mut body = Vec::new();
    push_compact_string(&mut body, group_id);
    push_unsigned_varint(&mut body, topics.len() + 1);
    for topic in topics {
        push_compact_string(&mut body, topic);
        push_unsigned_varint(&mut body, 0);
    }
    push_unsigned_varint(&mut body, 0);
    body
}

fn kafka_alter_replica_log_dirs_request_body(log_dir: &str, topics: &[(&str, &[i32])]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&1_i32.to_be_bytes());
    push_kafka_string(&mut body, log_dir);
    body.extend_from_slice(&(topics.len() as i32).to_be_bytes());
    for (topic, partitions) in topics {
        push_kafka_string(&mut body, topic);
        push_int32_array(&mut body, partitions);
    }
    body
}

fn kafka_describe_log_dirs_request_body(topics: Option<&[(&str, &[i32])]>) -> Vec<u8> {
    let mut body = Vec::new();
    if let Some(topics) = topics {
        body.extend_from_slice(&(topics.len() as i32).to_be_bytes());
        for (topic, partitions) in topics {
            push_kafka_string(&mut body, topic);
            push_int32_array(&mut body, partitions);
        }
    } else {
        body.extend_from_slice(&(-1_i32).to_be_bytes());
    }
    body
}

fn kafka_create_delegation_token_request_body(renewers: &[(&str, &str)]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&(renewers.len() as i32).to_be_bytes());
    for (principal_type, principal_name) in renewers {
        push_kafka_string(&mut body, principal_type);
        push_kafka_string(&mut body, principal_name);
    }
    body.extend_from_slice(&3_600_000_i64.to_be_bytes());
    body
}

fn kafka_renew_delegation_token_request_body(hmac: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    push_kafka_bytes(&mut body, hmac);
    body.extend_from_slice(&3_600_000_i64.to_be_bytes());
    body
}

fn kafka_expire_delegation_token_request_body(hmac: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    push_kafka_bytes(&mut body, hmac);
    body.extend_from_slice(&3_600_000_i64.to_be_bytes());
    body
}

fn kafka_describe_delegation_token_request_body(owners: Option<&[(&str, &str)]>) -> Vec<u8> {
    let mut body = Vec::new();
    if let Some(owners) = owners {
        body.extend_from_slice(&(owners.len() as i32).to_be_bytes());
        for (principal_type, principal_name) in owners {
            push_kafka_string(&mut body, principal_type);
            push_kafka_string(&mut body, principal_name);
        }
    } else {
        body.extend_from_slice(&(-1_i32).to_be_bytes());
    }
    body
}

fn kafka_join_group_request_body(api_version: i16, protocols: &[(&str, &[u8])]) -> Vec<u8> {
    let mut body = Vec::new();
    push_kafka_string(&mut body, "group.secret");
    body.extend_from_slice(&60_000_i32.to_be_bytes());
    if api_version >= 1 {
        body.extend_from_slice(&60_000_i32.to_be_bytes());
    }
    push_kafka_string(&mut body, "member.secret");
    if api_version >= 5 {
        push_kafka_nullable_string(&mut body, Some("instance.secret"));
    }
    push_kafka_string(&mut body, "consumer.secret");
    body.extend_from_slice(&(protocols.len() as i32).to_be_bytes());
    for (protocol, metadata) in protocols {
        push_kafka_string(&mut body, protocol);
        push_kafka_bytes(&mut body, metadata);
    }
    body
}

fn kafka_find_coordinator_request_body(api_version: i16, key: &str) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&(key.len() as i16).to_be_bytes());
    body.extend_from_slice(key.as_bytes());
    if api_version >= 1 {
        body.push(0);
    }
    body
}

fn kafka_heartbeat_request_body(api_version: i16, group_instance_id: Option<&str>) -> Vec<u8> {
    let mut body = Vec::new();
    push_kafka_string(&mut body, "group.secret");
    body.extend_from_slice(&3_i32.to_be_bytes());
    push_kafka_string(&mut body, "member.secret");
    if api_version >= 3 {
        push_kafka_nullable_string(&mut body, group_instance_id);
    }
    body
}

fn kafka_leave_group_request_body(api_version: i16) -> Vec<u8> {
    let mut body = Vec::new();
    push_kafka_string(&mut body, "group.secret");
    if api_version <= 2 {
        push_kafka_string(&mut body, "member.secret");
    } else {
        body.extend_from_slice(&1_i32.to_be_bytes());
        push_kafka_string(&mut body, "member.secret");
        push_kafka_nullable_string(&mut body, Some("instance.secret"));
    }
    body
}

fn kafka_sync_group_request_body(api_version: i16, assignment: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    push_kafka_string(&mut body, "group.secret");
    body.extend_from_slice(&3_i32.to_be_bytes());
    push_kafka_string(&mut body, "member.secret");
    if api_version >= 3 {
        push_kafka_nullable_string(&mut body, Some("instance.secret"));
    }
    body.extend_from_slice(&1_i32.to_be_bytes());
    push_kafka_string(&mut body, "member.secret");
    body.extend_from_slice(&(assignment.len() as i32).to_be_bytes());
    body.extend_from_slice(assignment);
    body
}

fn kafka_describe_groups_request_body(api_version: i16, groups: &[&str]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&(groups.len() as i32).to_be_bytes());
    for group in groups {
        push_kafka_string(&mut body, group);
    }
    if api_version >= 3 {
        body.push(1);
    }
    body
}

fn kafka_delete_groups_request_body(groups: &[&str]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&(groups.len() as i32).to_be_bytes());
    for group in groups {
        push_kafka_string(&mut body, group);
    }
    body
}

fn kafka_elect_leaders_request_body(
    api_version: i16,
    topic_partitions: Option<&[(&str, &[i32])]>,
) -> Vec<u8> {
    let mut body = Vec::new();
    if api_version >= 1 {
        body.push(0);
    }
    if let Some(topic_partitions) = topic_partitions {
        body.extend_from_slice(&(topic_partitions.len() as i32).to_be_bytes());
        for (topic, partitions) in topic_partitions {
            push_kafka_string(&mut body, topic);
            push_int32_array(&mut body, partitions);
        }
    } else {
        body.extend_from_slice(&(-1_i32).to_be_bytes());
    }
    body.extend_from_slice(&60_000_i32.to_be_bytes());
    body
}

fn kafka_sasl_handshake_request_body(mechanism: &str) -> Vec<u8> {
    let mut body = Vec::new();
    push_kafka_string(&mut body, mechanism);
    body
}

fn kafka_sasl_authenticate_request_body(auth_bytes: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    push_kafka_bytes(&mut body, auth_bytes);
    body
}

fn kafka_init_producer_id_request_body(transactional_id: Option<&str>) -> Vec<u8> {
    let mut body = Vec::new();
    push_kafka_nullable_string(&mut body, transactional_id);
    body.extend_from_slice(&60_000_i32.to_be_bytes());
    body
}

fn kafka_add_partitions_to_txn_request_body(topics: &[(&str, &[i32])]) -> Vec<u8> {
    let mut body = Vec::new();
    push_kafka_string(&mut body, "transaction.secret");
    body.extend_from_slice(&42_i64.to_be_bytes());
    body.extend_from_slice(&3_i16.to_be_bytes());
    body.extend_from_slice(&(topics.len() as i32).to_be_bytes());
    for (topic, partitions) in topics {
        push_kafka_string(&mut body, topic);
        push_int32_array(&mut body, partitions);
    }
    body
}

fn kafka_add_offsets_to_txn_request_body() -> Vec<u8> {
    let mut body = Vec::new();
    push_kafka_string(&mut body, "transaction.secret");
    body.extend_from_slice(&42_i64.to_be_bytes());
    body.extend_from_slice(&3_i16.to_be_bytes());
    push_kafka_string(&mut body, "group.secret");
    body
}

fn kafka_end_txn_request_body() -> Vec<u8> {
    let mut body = Vec::new();
    push_kafka_string(&mut body, "transaction.secret");
    body.extend_from_slice(&42_i64.to_be_bytes());
    body.extend_from_slice(&3_i16.to_be_bytes());
    body.push(1);
    body
}

fn kafka_write_txn_markers_request_body(api_version: i16, topics: &[(&str, &[i32])]) -> Vec<u8> {
    let mut body = Vec::new();
    push_unsigned_varint(&mut body, 2);
    body.extend_from_slice(&42_i64.to_be_bytes());
    body.extend_from_slice(&3_i16.to_be_bytes());
    body.push(1);
    push_unsigned_varint(&mut body, topics.len() + 1);
    for (topic, partitions) in topics {
        push_compact_string(&mut body, topic);
        push_unsigned_varint(&mut body, partitions.len() + 1);
        for partition in *partitions {
            body.extend_from_slice(&partition.to_be_bytes());
        }
        push_unsigned_varint(&mut body, 0);
    }
    body.extend_from_slice(&7_i32.to_be_bytes());
    if api_version >= 2 {
        body.push(2);
    }
    push_unsigned_varint(&mut body, 0);
    push_unsigned_varint(&mut body, 0);
    body
}

fn kafka_txn_offset_commit_request_body(api_version: i16, topics: &[(&str, &[i32])]) -> Vec<u8> {
    let mut body = Vec::new();
    push_kafka_string(&mut body, "transaction.secret");
    push_kafka_string(&mut body, "group.secret");
    body.extend_from_slice(&42_i64.to_be_bytes());
    body.extend_from_slice(&3_i16.to_be_bytes());
    body.extend_from_slice(&(topics.len() as i32).to_be_bytes());
    for (topic, partitions) in topics {
        push_kafka_string(&mut body, topic);
        body.extend_from_slice(&(partitions.len() as i32).to_be_bytes());
        for partition in *partitions {
            body.extend_from_slice(&partition.to_be_bytes());
            body.extend_from_slice(&42_i64.to_be_bytes());
            if api_version >= 2 {
                body.extend_from_slice(&3_i32.to_be_bytes());
            }
            push_kafka_nullable_string(&mut body, Some("metadata.secret"));
        }
    }
    body
}

fn kafka_metadata_request_body(api_version: i16, topics: Option<&[&str]>) -> Vec<u8> {
    let mut body = Vec::new();
    if let Some(topics) = topics {
        body.extend_from_slice(&(topics.len() as i32).to_be_bytes());
        for topic in topics {
            body.extend_from_slice(&(topic.len() as i16).to_be_bytes());
            body.extend_from_slice(topic.as_bytes());
        }
    } else {
        body.extend_from_slice(&(-1_i32).to_be_bytes());
    }
    if api_version >= 4 {
        body.push(1);
    }
    if api_version >= 8 {
        body.push(0);
        body.push(0);
    }
    body
}

fn kafka_flexible_request_frame(
    api_key: i16,
    api_version: i16,
    client_id: Option<&[u8]>,
    body: &[u8],
) -> Vec<u8> {
    let mut request = Vec::new();
    request.extend_from_slice(&api_key.to_be_bytes());
    request.extend_from_slice(&api_version.to_be_bytes());
    request.extend_from_slice(&42_i32.to_be_bytes());
    if let Some(client_id) = client_id {
        push_unsigned_varint(&mut request, client_id.len() + 1);
        request.extend_from_slice(client_id);
    } else {
        push_unsigned_varint(&mut request, 0);
    }
    push_unsigned_varint(&mut request, 0);
    request.extend_from_slice(body);
    kafka_frame(&request)
}

fn kafka_frame(request: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(request.len() + 4);
    frame.extend_from_slice(&(request.len() as i32).to_be_bytes());
    frame.extend_from_slice(request);
    frame
}
