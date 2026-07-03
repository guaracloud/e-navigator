#![no_main]

use e_navigator_protocol::{
    ProtocolExtractionConfig,
    kafka::{
        parse_kafka_add_offsets_to_txn_response, parse_kafka_api_versions_response,
        parse_kafka_describe_groups_response, parse_kafka_delete_groups_response,
        parse_kafka_fetch_response, parse_kafka_find_coordinator_response,
        parse_kafka_heartbeat_response, parse_kafka_init_producer_id_response,
        parse_kafka_leave_group_response, parse_kafka_list_groups_response,
        parse_kafka_list_offsets_response, parse_kafka_metadata_response,
        parse_kafka_offset_commit_response, parse_kafka_offset_fetch_response,
        parse_kafka_produce_response, parse_kafka_request, parse_kafka_sync_group_response,
    },
};
use libfuzzer_sys::fuzz_target;

const MAX_INPUT_BYTES: usize = 2048;

fuzz_target!(|data: &[u8]| {
    let data = &data[..data.len().min(MAX_INPUT_BYTES)];
    let config = ProtocolExtractionConfig {
        max_header_bytes: 512,
        max_request_line_bytes: 128,
        max_attributes: 4,
        max_tracestate_bytes: 128,
    };

    let _ = parse_kafka_request(data, &config);
    let _ = parse_kafka_api_versions_response(data, 0, &config);
    let _ = parse_kafka_api_versions_response(data, 3, &config);
    let _ = parse_kafka_produce_response(data, 0, &config);
    let _ = parse_kafka_produce_response(data, 7, &config);
    let _ = parse_kafka_fetch_response(data, 0, &config);
    let _ = parse_kafka_fetch_response(data, 5, &config);
    let _ = parse_kafka_offset_commit_response(data, 2, &config);
    let _ = parse_kafka_offset_commit_response(data, 7, &config);
    let _ = parse_kafka_offset_fetch_response(data, 1, &config);
    let _ = parse_kafka_offset_fetch_response(data, 5, &config);
    let _ = parse_kafka_list_offsets_response(data, 1, &config);
    let _ = parse_kafka_list_offsets_response(data, 5, &config);
    let _ = parse_kafka_find_coordinator_response(data, 0, &config);
    let _ = parse_kafka_find_coordinator_response(data, 2, &config);
    let _ = parse_kafka_heartbeat_response(data, 0, &config);
    let _ = parse_kafka_heartbeat_response(data, 3, &config);
    let _ = parse_kafka_leave_group_response(data, 0, &config);
    let _ = parse_kafka_leave_group_response(data, 3, &config);
    let _ = parse_kafka_sync_group_response(data, 0, &config);
    let _ = parse_kafka_sync_group_response(data, 3, &config);
    let _ = parse_kafka_describe_groups_response(data, 0, &config);
    let _ = parse_kafka_describe_groups_response(data, 4, &config);
    let _ = parse_kafka_list_groups_response(data, 0, &config);
    let _ = parse_kafka_list_groups_response(data, 3, &config);
    let _ = parse_kafka_delete_groups_response(data, 0, &config);
    let _ = parse_kafka_delete_groups_response(data, 1, &config);
    let _ = parse_kafka_init_producer_id_response(data, 0, &config);
    let _ = parse_kafka_init_producer_id_response(data, 1, &config);
    let _ = parse_kafka_add_offsets_to_txn_response(data, 0, &config);
    let _ = parse_kafka_add_offsets_to_txn_response(data, 2, &config);
    let _ = parse_kafka_metadata_response(data, 0, &config);
    let _ = parse_kafka_metadata_response(data, 8, &config);
});
