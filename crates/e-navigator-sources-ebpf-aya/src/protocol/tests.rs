use super::*;
use crate::perf_sample::InlineSample;
use e_navigator_signals::SignalPayload;
use flate2::{Compression, write::ZlibEncoder};
use std::io::Write as _;

fn fixed_command(name: &str) -> [u8; 16] {
    let mut command = [0_u8; 16];
    let bytes = name.as_bytes();
    command[..bytes.len().min(16)].copy_from_slice(&bytes[..bytes.len().min(16)]);
    command
}

fn raw_event(remote_port: u16, payload: &[u8], total_len: u32) -> RawProtocolDataEvent {
    let mut event = RawProtocolDataEvent {
        pid: 4242,
        uid: 1000,
        cgroup_id: 77,
        fd: 9,
        direction: RAW_PROTOCOL_DIRECTION_WRITE,
        role: RAW_PROTOCOL_ROLE_CLIENT,
        family: RAW_PROTOCOL_AF_INET,
        remote_port_be: remote_port.to_be(),
        local_port_be: 43210_u16.to_be(),
        remote_addr_v4: u32::from_ne_bytes([10, 0, 0, 5]),
        local_addr_v4: u32::from_ne_bytes([10, 0, 0, 9]),
        remote_addr_v6: [0; 16],
        local_addr_v6: [0; 16],
        timestamp_unix_nanos: 1_000,
        connection_started_at_nanos: 100,
        payload_len: payload.len() as u32,
        payload_total_len: total_len,
        payload_offset: 0,
        payload_captured_len: payload.len() as u32,
        command: fixed_command("client"),
        payload: [0; RAW_PROTOCOL_DATA_BYTES],
    };
    event.payload[..payload.len()].copy_from_slice(payload);
    event
}

fn raw_as_bytes(event: &RawProtocolDataEvent) -> &[u8] {
    unsafe {
        core::slice::from_raw_parts(
            (event as *const RawProtocolDataEvent).cast::<u8>(),
            core::mem::size_of::<RawProtocolDataEvent>(),
        )
    }
}

fn inline_sample(event: &RawProtocolDataEvent) -> InlineSample {
    InlineSample::from_perf(raw_as_bytes(event), &[]).expect("raw protocol event fits inline")
}

fn registry() -> ProtocolStreamRegistry {
    ProtocolStreamRegistry::new(
        Some("test-host".to_string()),
        std::path::PathBuf::from("__e_navigator_test_no_procfs__"),
        &ProtocolSourceConfig::default(),
    )
}

fn http_registry(port: u16) -> ProtocolStreamRegistry {
    let config = ProtocolSourceConfig {
        http1_ports: vec![port],
        ..ProtocolSourceConfig::default()
    };
    ProtocolStreamRegistry::new(
        Some("test-host".to_string()),
        std::path::PathBuf::from("__e_navigator_test_no_procfs__"),
        &config,
    )
}

fn discovery_registry() -> ProtocolStreamRegistry {
    let config = ProtocolSourceConfig {
        discovery_enabled: true,
        ..ProtocolSourceConfig::default()
    };
    ProtocolStreamRegistry::new(
        Some("test-host".to_string()),
        std::path::PathBuf::from("__e_navigator_test_no_procfs__"),
        &config,
    )
}

fn handle(
    registry: &mut ProtocolStreamRegistry,
    event: &RawProtocolDataEvent,
) -> Vec<SignalEnvelope> {
    handle_at(registry, event, 5_000)
}

fn handle_at(
    registry: &mut ProtocolStreamRegistry,
    event: &RawProtocolDataEvent,
    observed_unix_nanos: u64,
) -> Vec<SignalEnvelope> {
    let mut signals = Vec::new();
    registry
        .handle_event(raw_as_bytes(event), observed_unix_nanos, &mut signals)
        .expect("valid event decodes");
    signals
}

fn response_event(remote_port: u16, payload: &[u8]) -> RawProtocolDataEvent {
    let mut event = raw_event(remote_port, payload, payload.len() as u32);
    event.direction = RAW_PROTOCOL_DIRECTION_READ;
    event
}

fn response_event_with_total(
    remote_port: u16,
    payload: &[u8],
    total_len: u32,
) -> RawProtocolDataEvent {
    let mut event = raw_event(remote_port, payload, total_len);
    event.direction = RAW_PROTOCOL_DIRECTION_READ;
    event
}

fn postgres_frame(message_type: u8, body: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(body.len() + 5);
    frame.push(message_type);
    frame.extend_from_slice(&((body.len() + 4) as u32).to_be_bytes());
    frame.extend_from_slice(body);
    frame
}

fn postgres_startup(parameters: &[u8]) -> Vec<u8> {
    let mut body = 196_608_u32.to_be_bytes().to_vec();
    body.extend_from_slice(parameters);
    let mut frame = ((body.len() + 4) as u32).to_be_bytes().to_vec();
    frame.extend_from_slice(&body);
    frame
}

fn postgres_error(sqlstate: &[u8], message: &[u8]) -> Vec<u8> {
    let mut body = b"SERROR\0C".to_vec();
    body.extend_from_slice(sqlstate);
    body.push(0);
    body.push(b'M');
    body.extend_from_slice(message);
    body.extend_from_slice(&[0, 0]);
    postgres_frame(b'E', &body)
}

fn mysql_column_definition_packet(sequence: u8) -> Vec<u8> {
    let mut payload = Vec::new();
    for value in [b"def".as_slice(), b"", b"", b"", b"value", b""] {
        payload.push(value.len() as u8);
        payload.extend_from_slice(value);
    }
    payload.push(0x0c);
    payload.extend_from_slice(&0x0021_u16.to_le_bytes());
    payload.extend_from_slice(&11_u32.to_le_bytes());
    payload.push(0x03);
    payload.extend_from_slice(&0_u16.to_le_bytes());
    payload.push(0);
    payload.extend_from_slice(&[0, 0]);

    let mut packet = Vec::with_capacity(payload.len() + 4);
    packet.push((payload.len() & 0xff) as u8);
    packet.push(((payload.len() >> 8) & 0xff) as u8);
    packet.push(((payload.len() >> 16) & 0xff) as u8);
    packet.push(sequence);
    packet.extend_from_slice(&payload);
    packet
}

fn mysql_wire_packet(sequence: u8, payload: &[u8]) -> Vec<u8> {
    let payload_len = payload.len();
    let mut packet = Vec::with_capacity(payload_len + 4);
    packet.push((payload_len & 0xff) as u8);
    packet.push(((payload_len >> 8) & 0xff) as u8);
    packet.push(((payload_len >> 16) & 0xff) as u8);
    packet.push(sequence);
    packet.extend_from_slice(payload);
    packet
}

fn mysql_server_greeting(capabilities: u32) -> Vec<u8> {
    let mut payload = vec![0x0a];
    payload.extend_from_slice(b"8.0.36\0");
    payload.extend_from_slice(&42_u32.to_le_bytes());
    payload.extend_from_slice(b"12345678");
    payload.push(0);
    payload.extend_from_slice(&(capabilities as u16).to_le_bytes());
    payload.push(0x21);
    payload.extend_from_slice(&2_u16.to_le_bytes());
    payload.extend_from_slice(&((capabilities >> 16) as u16).to_le_bytes());
    payload.push(21);
    payload.extend_from_slice(&[0; 10]);
    payload.extend_from_slice(b"abcdefghijkl\0");
    mysql_wire_packet(0, &payload)
}

fn mysql_client_handshake_response(sequence: u8, capabilities: u32) -> Vec<u8> {
    let mut payload = capabilities.to_le_bytes().to_vec();
    payload.extend_from_slice(&16_777_216_u32.to_le_bytes());
    payload.push(0x21);
    payload.extend_from_slice(&[0; 23]);
    payload.extend_from_slice(b"fixture-user\0");
    payload.push(0);
    mysql_wire_packet(sequence, &payload)
}

fn mysql_compressed_packet(sequence: u8, payload: &[u8], compress: bool) -> Vec<u8> {
    let (body, uncompressed_len) = if compress {
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::fast());
        encoder
            .write_all(payload)
            .expect("fixture zlib write succeeds");
        let body = encoder.finish().expect("fixture zlib finish succeeds");
        (body, payload.len())
    } else {
        (payload.to_vec(), 0)
    };
    let body_len = u32::try_from(body.len()).expect("fixture length fits u32");
    let uncompressed_len = u32::try_from(uncompressed_len).expect("fixture length fits u32");
    let mut packet = Vec::with_capacity(body.len() + 7);
    packet.extend_from_slice(&body_len.to_le_bytes()[..3]);
    packet.push(sequence);
    packet.extend_from_slice(&uncompressed_len.to_le_bytes()[..3]);
    packet.extend_from_slice(&body);
    packet
}

fn kafka_api_versions_request(correlation_id: i32) -> Vec<u8> {
    let mut body = vec![0, 18, 0, 0];
    body.extend_from_slice(&correlation_id.to_be_bytes());
    body.extend_from_slice(&[0xff, 0xff]);
    let mut frame = (body.len() as i32).to_be_bytes().to_vec();
    frame.extend_from_slice(&body);
    frame
}

fn kafka_api_versions_response(correlation_id: i32) -> Vec<u8> {
    let mut body = correlation_id.to_be_bytes().to_vec();
    body.extend_from_slice(&[0, 0]);
    let mut frame = (body.len() as i32).to_be_bytes().to_vec();
    frame.extend_from_slice(&body);
    frame
}

fn mongodb_op_msg(request_id: i32, response_to: i32, document: &[u8]) -> Vec<u8> {
    mongodb_op_msg_with_flags(request_id, response_to, 0, document)
}

fn mongodb_op_msg_with_flags(
    request_id: i32,
    response_to: i32,
    flags: u32,
    document: &[u8],
) -> Vec<u8> {
    let message_len = 16 + 4 + 1 + document.len();
    let mut frame = Vec::with_capacity(message_len);
    frame.extend_from_slice(&(message_len as i32).to_le_bytes());
    frame.extend_from_slice(&request_id.to_le_bytes());
    frame.extend_from_slice(&response_to.to_le_bytes());
    frame.extend_from_slice(&2013_i32.to_le_bytes());
    frame.extend_from_slice(&flags.to_le_bytes());
    frame.push(0);
    frame.extend_from_slice(document);
    frame
}

fn mongodb_find_document(collection: &str) -> Vec<u8> {
    let value_len = collection.len() + 1;
    let document_len = 4 + 1 + 5 + 4 + value_len + 1;
    let mut document = Vec::with_capacity(document_len);
    document.extend_from_slice(&(document_len as i32).to_le_bytes());
    document.push(0x02);
    document.extend_from_slice(b"find\0");
    document.extend_from_slice(&(value_len as i32).to_le_bytes());
    document.extend_from_slice(collection.as_bytes());
    document.push(0);
    document.push(0);
    document
}

fn mongodb_ok_document() -> Vec<u8> {
    let mut document = 10_i32.to_le_bytes().to_vec();
    document.extend_from_slice(&[0x08, b'o', b'k', 0, 1, 0]);
    document
}

#[test]
fn protocol_perf_watermarks_merge_cross_cpu_samples_by_kernel_time() {
    let mut later = raw_event(6379, b"later", 5);
    later.timestamp_unix_nanos = 300;
    let mut earlier = raw_event(6379, b"earlier", 7);
    earlier.timestamp_unix_nanos = 100;
    let mut order = ProtocolSampleOrder::new(2, 8);

    // Reader 1 delivers first, but reader 0 has not completed its poll,
    // so the later event must remain buffered.
    assert!(order.push_sample(inline_sample(&later)).is_none());
    order.update_watermark(1, 400);
    assert!(order.pop_ready().is_none());

    assert!(order.push_sample(inline_sample(&earlier)).is_none());
    order.update_watermark(0, 400);
    assert_eq!(
        protocol_sample_timestamp(&order.pop_ready().expect("earlier sample")),
        Some(100)
    );
    assert_eq!(
        protocol_sample_timestamp(&order.pop_ready().expect("later sample")),
        Some(300)
    );
    assert!(order.pop_ready().is_none());
}

#[test]
fn protocol_perf_merge_bound_flushes_without_dropping() {
    let mut later = raw_event(6379, b"later", 5);
    later.timestamp_unix_nanos = 300;
    let mut earlier = raw_event(6379, b"earlier", 7);
    earlier.timestamp_unix_nanos = 100;
    let mut order = ProtocolSampleOrder::new(2, 1);

    assert!(order.push_sample(inline_sample(&later)).is_none());
    let forced = order
        .push_sample(inline_sample(&earlier))
        .expect("bound flushes oldest sample");
    assert_eq!(protocol_sample_timestamp(&forced), Some(100));
    assert_eq!(
        protocol_sample_timestamp(&order.pop_oldest().expect("remaining sample")),
        Some(300)
    );
}

fn observation(signal: &SignalEnvelope) -> &ProtocolRequestObservation {
    match &signal.payload {
        SignalPayload::ProtocolRequestObservation(observation) => observation,
        other => panic!("expected protocol request observation, got {other:?}"),
    }
}

#[test]
fn redis_command_matches_response_with_latency() {
    let mut registry = registry();
    let payload = b"*2\r\n$3\r\nGET\r\n$10\r\nsecret-key\r\n";
    let event = raw_event(6379, payload, payload.len() as u32);
    assert!(handle_at(&mut registry, &event, 5_000).is_empty());

    let response = response_event(6379, b"$5\r\nhello\r\n");
    let signals = handle_at(&mut registry, &response, 7_500);

    assert_eq!(signals.len(), 1);
    let observation = observation(&signals[0]);
    assert_eq!(observation.protocol, ProtocolKind::Redis);
    assert_eq!(observation.method.as_deref(), Some("GET"));
    assert_eq!(observation.confidence, TraceConfidence::High);
    assert_eq!(observation.start_unix_nanos, 5_000);
    assert_eq!(observation.end_unix_nanos, Some(7_500));
    assert_eq!(observation.duration_nanos, Some(2_500));
    let process = observation.process.as_ref().expect("process identity");
    assert_eq!(process.pid, 4242);
    assert_eq!(process.command, "client");
    let peer = observation.peer.as_ref().expect("peer context");
    assert_eq!(peer.address.as_deref(), Some("10.0.0.5"));
    assert_eq!(peer.port, Some(6379));
    assert_eq!(registry.counters().matched_responses, 1);

    // Neither the key nor the response value may appear in the signal.
    let serialized = serde_json::to_string(&signals[0]).expect("signal serializes");
    assert!(!serialized.contains("secret-key"));
    assert!(!serialized.contains("hello"));
}

#[test]
fn fragmented_request_latency_starts_at_the_first_observed_byte() {
    let mut registry = registry();
    let first = b"*2\r\n$3\r\nGET\r\n";
    let second = b"$10\r\nsecret-key\r\n";
    assert!(
        handle_at(
            &mut registry,
            &raw_event(6379, first, first.len() as u32),
            5_000,
        )
        .is_empty()
    );
    assert!(
        handle_at(
            &mut registry,
            &raw_event(6379, second, second.len() as u32),
            5_500,
        )
        .is_empty()
    );

    let signals = handle_at(
        &mut registry,
        &response_event(6379, b"$5\r\nhello\r\n"),
        9_000,
    );
    assert_eq!(signals.len(), 1);
    let observation = observation(&signals[0]);
    assert_eq!(observation.start_unix_nanos, 5_000);
    assert_eq!(observation.duration_nanos, Some(4_000));
}

#[test]
fn redis_resp3_push_does_not_consume_the_command_reply() {
    let mut registry = registry();
    let request = b"*2\r\n$3\r\nGET\r\n$10\r\nsecret-key\r\n";
    assert!(
        handle_at(
            &mut registry,
            &raw_event(6379, request, request.len() as u32),
            5_000,
        )
        .is_empty()
    );

    let response = b">2\r\n+invalidate\r\n$10\r\nsecret-key\r\n$5\r\nhello\r\n";
    let signals = handle_at(&mut registry, &response_event(6379, response), 7_500);

    assert_eq!(signals.len(), 1);
    let observation = observation(&signals[0]);
    assert_eq!(observation.method.as_deref(), Some("GET"));
    assert_eq!(observation.duration_nanos, Some(2_500));
    assert_eq!(registry.counters().matched_responses, 1);
    assert_eq!(registry.counters().response_continuations, 1);
    assert_eq!(registry.counters().orphan_responses, 0);
    let serialized = serde_json::to_string(&signals).expect("signals serialize");
    assert!(!serialized.contains("secret-key"));
    assert!(!serialized.contains("hello"));
}

#[test]
fn redis_resp3_subscription_pushes_complete_only_the_subscribe_command() {
    let mut registry = registry();
    let requests =
        b"*3\r\n$9\r\nSUBSCRIBE\r\n$10\r\nsecret-one\r\n$10\r\nsecret-two\r\n*1\r\n$4\r\nPING\r\n";
    assert!(
        handle_at(
            &mut registry,
            &raw_event(6379, requests, requests.len() as u32),
            5_000,
        )
        .is_empty()
    );

    let first_confirmation = b">3\r\n$9\r\nsubscribe\r\n$10\r\nsecret-one\r\n:1\r\n";
    assert!(
        handle_at(
            &mut registry,
            &response_event(6379, first_confirmation),
            7_000,
        )
        .is_empty(),
        "one confirmation must not complete a two-channel subscription"
    );

    let second_confirmation = b">3\r\n$9\r\nsubscribe\r\n$10\r\nsecret-two\r\n:2\r\n";
    let signals = handle_at(
        &mut registry,
        &response_event(6379, second_confirmation),
        8_000,
    );
    assert_eq!(signals.len(), 1);
    assert_eq!(
        observation(&signals[0]).method.as_deref(),
        Some("SUBSCRIBE")
    );
    assert_eq!(observation(&signals[0]).duration_nanos, Some(3_000));

    let signals = handle_at(&mut registry, &response_event(6379, b"+PONG\r\n"), 9_000);
    assert_eq!(signals.len(), 1);
    assert_eq!(observation(&signals[0]).method.as_deref(), Some("PING"));
    assert_eq!(registry.counters().matched_responses, 2);
    let serialized = serde_json::to_string(&signals).expect("signals serialize");
    assert!(!serialized.contains("secret-one"));
    assert!(!serialized.contains("secret-two"));
}

#[test]
fn redis_resp2_pubsub_delivery_does_not_consume_an_interleaved_reply() {
    let mut registry = registry();
    let requests = b"*2\r\n$9\r\nSUBSCRIBE\r\n$7\r\nchannel\r\n*1\r\n$4\r\nPING\r\n";
    assert!(
        handle_at(
            &mut registry,
            &raw_event(6379, requests, requests.len() as u32),
            5_000,
        )
        .is_empty()
    );

    let confirmation = b"*3\r\n$9\r\nsubscribe\r\n$7\r\nchannel\r\n:1\r\n";
    let signals = handle_at(&mut registry, &response_event(6379, confirmation), 6_000);
    assert_eq!(signals.len(), 1);
    assert_eq!(
        observation(&signals[0]).method.as_deref(),
        Some("SUBSCRIBE")
    );

    let delivery = b"*3\r\n$7\r\nmessage\r\n$7\r\nchannel\r\n$14\r\nsecret-payload\r\n";
    assert!(
        handle_at(&mut registry, &response_event(6379, delivery), 7_000,).is_empty(),
        "an out-of-band delivery must not complete PING"
    );

    let signals = handle_at(&mut registry, &response_event(6379, b"+PONG\r\n"), 8_000);
    assert_eq!(signals.len(), 1);
    assert_eq!(observation(&signals[0]).method.as_deref(), Some("PING"));
    assert_eq!(observation(&signals[0]).duration_nanos, Some(3_000));
    assert_eq!(registry.counters().matched_responses, 2);
    assert_eq!(registry.counters().response_continuations, 1);
    let serialized = serde_json::to_string(&signals).expect("signals serialize");
    assert!(!serialized.contains("secret-payload"));
    assert!(!serialized.contains("channel"));
}

#[test]
fn redis_mismatched_subscription_confirmation_does_not_change_connection_state() {
    let mut registry = registry();
    let request = b"*2\r\n$9\r\nSUBSCRIBE\r\n$1\r\na\r\n";
    assert!(
        handle_at(
            &mut registry,
            &raw_event(6379, request, request.len() as u32),
            5_000,
        )
        .is_empty()
    );

    let mismatched = b"*3\r\n$10\r\npsubscribe\r\n$1\r\na\r\n:1\r\n";
    assert!(handle_at(&mut registry, &response_event(6379, mismatched), 6_000).is_empty());
    let stream = registry
        .connections
        .values()
        .next()
        .expect("redis connection remains tracked");
    assert_eq!(stream.redis_subscription, RedisSubscriptionState::None);

    let matched = b"*3\r\n$9\r\nsubscribe\r\n$1\r\na\r\n:1\r\n";
    let signals = handle_at(&mut registry, &response_event(6379, matched), 7_000);
    assert_eq!(signals.len(), 1);
    assert_eq!(
        observation(&signals[0]).method.as_deref(),
        Some("SUBSCRIBE")
    );
}

#[test]
fn redis_malformed_subscribe_confirmations_do_not_change_connection_state() {
    let mut registry = registry();
    let request = b"*2\r\n$9\r\nSUBSCRIBE\r\n$1\r\na\r\n";
    assert!(
        handle_at(
            &mut registry,
            &raw_event(6379, request, request.len() as u32),
            5_000,
        )
        .is_empty()
    );

    for (observed_at, malformed) in [
        (
            6_000,
            b"*3\r\n$9\r\nsubscribe\r\n$1\r\na\r\n:0\r\n".as_slice(),
        ),
        (7_000, b"*3\r\n$9\r\nsubscribe\r\n$-1\r\n:1\r\n".as_slice()),
    ] {
        assert!(
            handle_at(&mut registry, &response_event(6379, malformed), observed_at,).is_empty()
        );
        let stream = registry
            .connections
            .values()
            .next()
            .expect("redis connection remains tracked");
        assert_eq!(stream.redis_subscription, RedisSubscriptionState::None);
        assert_eq!(stream.in_flight.len(), 1);
    }
    assert_eq!(registry.counters().unparsed_responses, 2);

    let valid = b"*3\r\n$9\r\nsubscribe\r\n$1\r\na\r\n:1\r\n";
    let signals = handle_at(&mut registry, &response_event(6379, valid), 8_000);
    assert_eq!(signals.len(), 1);
    assert_eq!(
        observation(&signals[0]).method.as_deref(),
        Some("SUBSCRIBE")
    );
    let stream = registry
        .connections
        .values()
        .next()
        .expect("redis connection remains tracked");
    assert_eq!(stream.redis_subscription, RedisSubscriptionState::Resp2);
}

#[test]
fn redis_zero_argument_unsubscribe_fails_ambiguous_connection_state_closed() {
    let mut registry = registry();
    let subscriptions =
        b"*2\r\n$9\r\nSUBSCRIBE\r\n$1\r\na\r\n*2\r\n$10\r\nPSUBSCRIBE\r\n$2\r\np*\r\n";
    assert!(
        handle_at(
            &mut registry,
            &raw_event(6379, subscriptions, subscriptions.len() as u32),
            5_000,
        )
        .is_empty()
    );
    let subscribe_confirmation = b"*3\r\n$9\r\nsubscribe\r\n$1\r\na\r\n:1\r\n";
    assert_eq!(
        handle_at(
            &mut registry,
            &response_event(6379, subscribe_confirmation),
            6_000,
        )
        .len(),
        1
    );
    let pattern_confirmation = b"*3\r\n$10\r\npsubscribe\r\n$2\r\np*\r\n:2\r\n";
    assert_eq!(
        handle_at(
            &mut registry,
            &response_event(6379, pattern_confirmation),
            7_000,
        )
        .len(),
        1
    );

    let get = b"*2\r\n$3\r\nGET\r\n$3\r\nkey\r\n";
    assert!(
        handle_at(
            &mut registry,
            &raw_event(6379, get, get.len() as u32),
            8_000,
        )
        .is_empty()
    );

    let unsubscribe = b"*1\r\n$11\r\nUNSUBSCRIBE\r\n";
    let signals = handle_at(
        &mut registry,
        &raw_event(6379, unsubscribe, unsubscribe.len() as u32),
        9_000,
    );
    assert_eq!(
        signals.len(),
        2,
        "the earlier GET and ambiguous control are emitted without correlation"
    );
    assert!(
        signals
            .iter()
            .all(|signal| observation(signal).confidence == TraceConfidence::Low)
    );
    assert!(
        signals
            .iter()
            .all(|signal| observation(signal).duration_nanos.is_none())
    );

    let ambiguous_confirmation = b"*3\r\n$11\r\nunsubscribe\r\n$1\r\na\r\n:1\r\n";
    assert!(
        handle_at(
            &mut registry,
            &response_event(6379, ambiguous_confirmation),
            10_000,
        )
        .is_empty()
    );
    let stream = registry
        .connections
        .values()
        .next()
        .expect("redis connection remains tracked");
    assert!(stream.redis_transport_opaque);
    assert!(stream.in_flight.is_empty());
    assert_eq!(registry.counters().redis_ambiguous_state_transitions, 1);

    let explicit_unsubscribe = b"*2\r\n$11\r\nUNSUBSCRIBE\r\n$1\r\na\r\n";
    let signals = handle_at(
        &mut registry,
        &raw_event(
            6379,
            explicit_unsubscribe,
            explicit_unsubscribe.len() as u32,
        ),
        11_000,
    );
    assert_eq!(signals.len(), 1);
    assert_eq!(observation(&signals[0]).confidence, TraceConfidence::Low);
    assert!(
        handle_at(
            &mut registry,
            &response_event(6379, ambiguous_confirmation),
            12_000,
        )
        .is_empty()
    );
}

#[test]
fn redis_ambiguous_subscription_opacity_clears_only_for_a_new_connection() {
    let mut registry = registry();
    let ambiguous = b"*1\r\n$12\r\nPUNSUBSCRIBE\r\n";
    let signals = handle_at(
        &mut registry,
        &raw_event(6379, ambiguous, ambiguous.len() as u32),
        5_000,
    );
    assert_eq!(signals.len(), 1);
    assert!(observation(&signals[0]).duration_nanos.is_none());
    assert!(
        registry
            .connections
            .values()
            .next()
            .expect("opaque redis connection remains tracked")
            .redis_transport_opaque
    );

    let ping = b"*1\r\n$4\r\nPING\r\n";
    let same_connection = handle_at(
        &mut registry,
        &raw_event(6379, ping, ping.len() as u32),
        6_000,
    );
    assert_eq!(same_connection.len(), 1);
    assert!(observation(&same_connection[0]).duration_nanos.is_none());

    let mut new_connection = raw_event(6379, ping, ping.len() as u32);
    new_connection.local_port_be = 43211_u16.to_be();
    assert!(handle_at(&mut registry, &new_connection, 7_000).is_empty());
    let mut pong = response_event(6379, b"+PONG\r\n");
    pong.local_port_be = 43211_u16.to_be();
    let signals = handle_at(&mut registry, &pong, 8_000);
    assert_eq!(signals.len(), 1);
    assert_eq!(observation(&signals[0]).method.as_deref(), Some("PING"));
    assert_eq!(observation(&signals[0]).duration_nanos, Some(1_000));
}

#[test]
fn redis_message_shaped_array_is_a_reply_before_subscription() {
    let mut registry = registry();
    let request = b"*2\r\n$3\r\nGET\r\n$3\r\nkey\r\n";
    assert!(
        handle_at(
            &mut registry,
            &raw_event(6379, request, request.len() as u32),
            5_000,
        )
        .is_empty()
    );

    let response = b"*3\r\n$7\r\nmessage\r\n$1\r\nx\r\n$1\r\ny\r\n";
    let signals = handle_at(&mut registry, &response_event(6379, response), 7_000);

    assert_eq!(signals.len(), 1);
    assert_eq!(observation(&signals[0]).method.as_deref(), Some("GET"));
    assert_eq!(observation(&signals[0]).duration_nanos, Some(2_000));
}

#[test]
fn redis_confirmation_shaped_array_does_not_change_standard_connection_state() {
    let mut registry = registry();
    let first_request = b"*2\r\n$3\r\nGET\r\n$3\r\nkey\r\n";
    assert!(
        handle_at(
            &mut registry,
            &raw_event(6379, first_request, first_request.len() as u32),
            5_000,
        )
        .is_empty()
    );

    let confirmation_shaped = b"*3\r\n$9\r\nsubscribe\r\n$7\r\nchannel\r\n:1\r\n";
    let signals = handle_at(
        &mut registry,
        &response_event(6379, confirmation_shaped),
        6_000,
    );
    assert_eq!(signals.len(), 1);
    assert_eq!(observation(&signals[0]).method.as_deref(), Some("GET"));

    let second_request = b"*2\r\n$3\r\nGET\r\n$4\r\nnext\r\n";
    assert!(
        handle_at(
            &mut registry,
            &raw_event(6379, second_request, second_request.len() as u32),
            7_000,
        )
        .is_empty()
    );
    let message_shaped = b"*3\r\n$7\r\nmessage\r\n$1\r\nx\r\n$1\r\ny\r\n";
    let signals = handle_at(&mut registry, &response_event(6379, message_shaped), 8_000);
    assert_eq!(signals.len(), 1);
    assert_eq!(observation(&signals[0]).method.as_deref(), Some("GET"));
}

#[test]
fn redis_reset_confirmation_exits_subscriber_mode() {
    let mut registry = registry();
    let subscribe = b"*2\r\n$9\r\nSUBSCRIBE\r\n$1\r\na\r\n";
    assert!(
        handle_at(
            &mut registry,
            &raw_event(6379, subscribe, subscribe.len() as u32),
            5_000,
        )
        .is_empty()
    );
    let confirmation = b"*3\r\n$9\r\nsubscribe\r\n$1\r\na\r\n:1\r\n";
    assert_eq!(
        handle_at(&mut registry, &response_event(6379, confirmation), 6_000).len(),
        1
    );

    let reset = b"*1\r\n$5\r\nRESET\r\n";
    assert!(
        handle_at(
            &mut registry,
            &raw_event(6379, reset, reset.len() as u32),
            7_000,
        )
        .is_empty()
    );
    let signals = handle_at(&mut registry, &response_event(6379, b"+RESET\r\n"), 8_000);
    assert_eq!(signals.len(), 1);
    assert_eq!(observation(&signals[0]).method.as_deref(), Some("RESET"));
    let stream = registry
        .connections
        .values()
        .next()
        .expect("redis connection remains tracked");
    assert_eq!(stream.redis_subscription, RedisSubscriptionState::None);

    let get = b"*2\r\n$3\r\nGET\r\n$4\r\nnext\r\n";
    assert!(
        handle_at(
            &mut registry,
            &raw_event(6379, get, get.len() as u32),
            9_000,
        )
        .is_empty()
    );
    let message_shaped = b"*3\r\n$7\r\nmessage\r\n$1\r\nx\r\n$1\r\ny\r\n";
    let signals = handle_at(&mut registry, &response_event(6379, message_shaped), 10_000);
    assert_eq!(signals.len(), 1);
    assert_eq!(observation(&signals[0]).method.as_deref(), Some("GET"));
}

#[test]
fn redis_failed_reset_preserves_subscriber_mode() {
    let mut registry = registry();
    let subscribe = b"*2\r\n$9\r\nSUBSCRIBE\r\n$1\r\na\r\n";
    assert!(
        handle_at(
            &mut registry,
            &raw_event(6379, subscribe, subscribe.len() as u32),
            5_000,
        )
        .is_empty()
    );
    let confirmation = b"*3\r\n$9\r\nsubscribe\r\n$1\r\na\r\n:1\r\n";
    assert_eq!(
        handle_at(&mut registry, &response_event(6379, confirmation), 6_000).len(),
        1
    );

    let reset = b"*1\r\n$5\r\nRESET\r\n";
    assert!(
        handle_at(
            &mut registry,
            &raw_event(6379, reset, reset.len() as u32),
            7_000,
        )
        .is_empty()
    );
    let signals = handle_at(
        &mut registry,
        &response_event(6379, b"-ERR reset rejected\r\n"),
        8_000,
    );
    assert_eq!(signals.len(), 1);
    assert_eq!(observation(&signals[0]).method.as_deref(), Some("RESET"));
    assert!(
        observation(&signals[0])
            .attributes
            .iter()
            .any(|attribute| attribute.key == "error.type")
    );
    let stream = registry
        .connections
        .values()
        .next()
        .expect("redis connection remains tracked");
    assert_eq!(stream.redis_subscription, RedisSubscriptionState::Resp2);

    let delivery = b"*3\r\n$7\r\nmessage\r\n$1\r\na\r\n$6\r\nsecret\r\n";
    assert!(
        handle_at(&mut registry, &response_event(6379, delivery), 9_000).is_empty(),
        "subscriber delivery remains out of band after RESET fails"
    );
}

#[test]
fn redis_message_shaped_array_remains_a_reply_in_resp3_subscriber_mode() {
    let mut registry = registry();
    let requests = b"*2\r\n$9\r\nSUBSCRIBE\r\n$7\r\nchannel\r\n*2\r\n$3\r\nGET\r\n$3\r\nkey\r\n";
    assert!(
        handle_at(
            &mut registry,
            &raw_event(6379, requests, requests.len() as u32),
            5_000,
        )
        .is_empty()
    );

    let confirmation = b">3\r\n$9\r\nsubscribe\r\n$7\r\nchannel\r\n:1\r\n";
    let signals = handle_at(&mut registry, &response_event(6379, confirmation), 6_000);
    assert_eq!(signals.len(), 1);
    assert_eq!(
        observation(&signals[0]).method.as_deref(),
        Some("SUBSCRIBE")
    );

    let response = b"*3\r\n$7\r\nmessage\r\n$1\r\nx\r\n$1\r\ny\r\n";
    let signals = handle_at(&mut registry, &response_event(6379, response), 7_000);
    assert_eq!(signals.len(), 1);
    assert_eq!(observation(&signals[0]).method.as_deref(), Some("GET"));
}

#[test]
fn redis_resp3_attributes_do_not_consume_the_decorated_reply() {
    let mut registry = registry();
    let request = b"*2\r\n$3\r\nGET\r\n$10\r\nsecret-key\r\n";
    assert!(
        handle_at(
            &mut registry,
            &raw_event(6379, request, request.len() as u32),
            5_000,
        )
        .is_empty()
    );

    let response = b"|1\r\n+ttl\r\n:10\r\n$5\r\nhello\r\n";
    let signals = handle_at(&mut registry, &response_event(6379, response), 7_500);

    assert_eq!(signals.len(), 1);
    let observation = observation(&signals[0]);
    assert_eq!(observation.method.as_deref(), Some("GET"));
    assert_eq!(observation.duration_nanos, Some(2_500));
    assert_eq!(registry.counters().matched_responses, 1);
    assert_eq!(registry.counters().response_continuations, 1);
    assert_eq!(registry.counters().orphan_responses, 0);
    let serialized = serde_json::to_string(&signals).expect("signals serialize");
    assert!(!serialized.contains("secret-key"));
    assert!(!serialized.contains("hello"));
    assert!(!serialized.contains("ttl"));
}

#[test]
fn websocket_upgrade_and_coalesced_frames_emit_metadata_only() {
    let mut registry = http_registry(8080);
    let request = b"GET /chat HTTP/1.1\r\nHost: example.test\r\nUpgrade: websocket\r\nConnection: keep-alive, Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
    assert!(
        handle_at(
            &mut registry,
            &raw_event(8080, request, request.len() as u32),
            5_000,
        )
        .is_empty()
    );

    let response = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n";
    let server_frame = [0x81, 0x06, b's', b'e', b'c', b'r', b'e', b't'];
    let mut response_and_frame = response.to_vec();
    response_and_frame.extend_from_slice(&server_frame);
    let signals = handle_at(
        &mut registry,
        &response_event(8080, &response_and_frame),
        7_000,
    );

    assert_eq!(signals.len(), 2);
    let handshake = observation(&signals[0]);
    assert_eq!(handshake.protocol, ProtocolKind::Websocket);
    assert_eq!(handshake.method.as_deref(), Some("handshake"));
    assert_eq!(handshake.status_code, Some(101));
    let frame = observation(&signals[1]);
    assert_eq!(frame.protocol, ProtocolKind::Websocket);
    assert_eq!(frame.method.as_deref(), Some("text"));
    assert!(frame.attributes.iter().any(|attribute| {
        attribute.key == "websocket.frame.payload_length" && attribute.value == "6"
    }));
    let serialized = serde_json::to_string(&signals).expect("signals serialize");
    assert!(!serialized.contains("secret"));
    assert_eq!(registry.counters().websocket_upgrades, 1);
    assert_eq!(registry.counters().websocket_frames, 1);

    let masked_client_frame = [0x89, 0x80, 1, 2, 3, 4];
    let client_signals = handle_at(
        &mut registry,
        &raw_event(8080, &masked_client_frame, masked_client_frame.len() as u32),
        8_000,
    );
    assert_eq!(client_signals.len(), 1);
    assert_eq!(
        observation(&client_signals[0]).method.as_deref(),
        Some("ping")
    );
    assert_eq!(registry.counters().websocket_frames, 2);
}

#[test]
fn grpc_web_binary_request_matches_text_response_status() {
    use base64::{Engine as _, engine::general_purpose::STANDARD};

    let mut registry = http_registry(8081);
    let message = [
        0, 0, 0, 0, 11, b's', b'e', b'c', b'r', b'e', b't', b'-', b'b', b'o', b'd', b'y',
    ];
    let mut request = format!(
            "POST /demo.Echo/Call HTTP/1.1\r\nHost: example.test\r\nContent-Type: application/grpc-web+proto\r\nContent-Length: {}\r\n\r\n",
            message.len()
        )
        .into_bytes();
    request.extend_from_slice(&message);
    assert!(
        handle_at(
            &mut registry,
            &raw_event(8081, &request, request.len() as u32),
            10_000,
        )
        .is_empty()
    );

    let trailer_payload = b"grpc-status: 0\r\n";
    let mut response_body = vec![0, 0, 0, 0, 2, b'o', b'k', 0x80];
    response_body.extend_from_slice(&(trailer_payload.len() as u32).to_be_bytes());
    response_body.extend_from_slice(trailer_payload);
    let encoded = STANDARD.encode(response_body);
    let mut response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/grpc-web-text+proto\r\nContent-Length: {}\r\n\r\n",
            encoded.len()
        )
        .into_bytes();
    response.extend_from_slice(encoded.as_bytes());
    let signals = handle_at(&mut registry, &response_event(8081, &response), 12_500);

    assert_eq!(signals.len(), 1);
    let rpc = observation(&signals[0]);
    assert_eq!(rpc.protocol, ProtocolKind::Grpc);
    assert_eq!(rpc.method.as_deref(), Some("Call"));
    assert_eq!(rpc.status_code, Some(0));
    assert_eq!(rpc.duration_nanos, Some(2_500));
    assert!(rpc.attributes.iter().any(|attribute| {
        attribute.key == "rpc.grpc.transport" && attribute.value == "grpc_web"
    }));
    let serialized = serde_json::to_string(&signals).expect("signals serialize");
    assert!(!serialized.contains("secret-body"));
    assert_eq!(registry.counters().grpc_web_requests, 1);
}

#[test]
fn connection_generation_prevents_websocket_state_leaking_across_fd_reuse() {
    use base64::{Engine as _, engine::general_purpose::STANDARD};

    let mut registry = http_registry(8082);
    let websocket_request = b"GET /websocket-proof HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
    assert!(
        handle_at(
            &mut registry,
            &raw_event(8082, websocket_request, websocket_request.len() as u32),
            1_000,
        )
        .is_empty()
    );
    let websocket_response = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n";
    assert_eq!(
        handle_at(
            &mut registry,
            &response_event(8082, websocket_response),
            2_000,
        )
        .len(),
        1
    );

    let message = b"\x00\x00\x00\x00\x12client-secret-blue";
    let mut request = format!(
            "POST /proof.Echo/Call HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/grpc-web+proto\r\nContent-Length: {}\r\n\r\n",
            message.len()
        )
        .into_bytes();
    request.extend_from_slice(message);
    let mut request_event = raw_event(8082, &request, request.len() as u32);
    request_event.connection_started_at_nanos = 200;
    assert!(handle_at(&mut registry, &request_event, 3_000).is_empty());

    let trailer = b"grpc-status: 0\r\n";
    let mut body = vec![0, 0, 0, 0, 2, b'o', b'k', 0x80];
    body.extend_from_slice(&(trailer.len() as u32).to_be_bytes());
    body.extend_from_slice(trailer);
    let encoded = STANDARD.encode(body);
    let mut response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/grpc-web-text+proto\r\nContent-Length: {}\r\n\r\n",
            encoded.len()
        )
        .into_bytes();
    response.extend_from_slice(encoded.as_bytes());
    let mut response_event = response_event(8082, &response);
    response_event.connection_started_at_nanos = 200;
    let signals = handle_at(&mut registry, &response_event, 4_000);

    assert_eq!(signals.len(), 1);
    assert_eq!(observation(&signals[0]).protocol, ProtocolKind::Grpc);
    assert_eq!(observation(&signals[0]).status_code, Some(0));
    assert_eq!(registry.counters().evicted_connections, 1);
    assert_eq!(registry.counters().grpc_web_requests, 1);
}

#[test]
fn connection_reuses_source_time_container_attribution() {
    const CONTAINER_ID: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let procfs_root = std::env::temp_dir().join(format!(
        "e-navigator-protocol-container-cache-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&procfs_root);
    let cgroup_path = procfs_root.join("4242/cgroup");
    std::fs::create_dir_all(cgroup_path.parent().expect("cgroup parent"))
        .expect("create procfs fixture");
    std::fs::write(
        &cgroup_path,
        format!("0::/kubepods.slice/cri-containerd-{CONTAINER_ID}.scope\n"),
    )
    .expect("write cgroup fixture");
    let mut registry = ProtocolStreamRegistry::new(
        Some("test-host".to_string()),
        procfs_root.clone(),
        &ProtocolSourceConfig::default(),
    );
    let reads_before = crate::procfs::container_cgroup_read_count();

    let request = raw_event(6379, b"*1\r\n$4\r\nPING\r\n", 14);
    assert!(handle_at(&mut registry, &request, 5_000).is_empty());
    std::fs::remove_file(&cgroup_path).expect("remove cgroup fixture after connection start");

    let response = response_event(6379, b"+PONG\r\n");
    let signals = handle_at(&mut registry, &response, 6_000);

    assert_eq!(
        crate::procfs::container_cgroup_read_count() - reads_before,
        1,
        "an established connection must not reopen its procfs cgroup file"
    );
    let container = observation(&signals[0])
        .container
        .as_ref()
        .expect("connection keeps its source-time container");
    assert_eq!(container.container_id, CONTAINER_ID);
    assert_eq!(container.runtime.as_deref(), Some("containerd"));
    std::fs::remove_dir_all(procfs_root).expect("cleanup procfs fixture");
}

#[test]
fn reused_fd_with_a_new_socket_tuple_resets_stream_state() {
    let mut registry = registry();
    let first = raw_event(6379, b"*2\r\n$3\r\nGET\r\n$3\r\nkey\r\n", 22);
    assert!(handle_at(&mut registry, &first, 5_000).is_empty());

    let mut reused = raw_event(6379, b"*1\r\n$4\r\nPING\r\n", 14);
    reused.local_port_be = 43211_u16.to_be();
    let evicted = handle_at(&mut registry, &reused, 6_000);

    assert_eq!(evicted.len(), 1);
    assert_eq!(observation(&evicted[0]).method.as_deref(), Some("GET"));
    assert_eq!(observation(&evicted[0]).end_unix_nanos, None);
    assert_eq!(registry.counters().evicted_connections, 1);
    assert_eq!(registry.counters().unmatched_evicted, 1);

    let mut response = response_event(6379, b"+PONG\r\n");
    response.local_port_be = 43211_u16.to_be();
    let matched = handle_at(&mut registry, &response, 7_000);

    assert_eq!(matched.len(), 1);
    assert_eq!(observation(&matched[0]).method.as_deref(), Some("PING"));
    assert_eq!(observation(&matched[0]).duration_nanos, Some(1_000));
}

#[test]
fn redis_error_response_attaches_error_attributes() {
    let mut registry = registry();
    let request = raw_event(6379, b"*1\r\n$4\r\nPING\r\n", 14);
    assert!(handle_at(&mut registry, &request, 5_000).is_empty());

    let response = response_event(6379, b"-ERR unknown command\r\n");
    let signals = handle_at(&mut registry, &response, 6_000);

    assert_eq!(signals.len(), 1);
    let observation = observation(&signals[0]);
    assert_eq!(observation.duration_nanos, Some(1_000));
    assert!(
        observation
            .attributes
            .iter()
            .any(|attribute| attribute.key == "error.type" || attribute.key.contains("status")),
        "expected response status attributes, got {:?}",
        observation.attributes,
    );
}

#[test]
fn kafka_request_reassembles_and_matches_response() {
    let mut registry = registry();
    // api_key=18 (api_versions), api_version=0, correlation_id=7,
    // client_id len=-1.
    let body = [0, 18, 0, 0, 0, 0, 0, 7, 0xff, 0xff];
    let mut frame = (body.len() as i32).to_be_bytes().to_vec();
    frame.extend_from_slice(&body);

    let first = raw_event(9092, &frame[..6], 6);
    assert!(handle_at(&mut registry, &first, 5_000).is_empty());
    let second = raw_event(9092, &frame[6..], (frame.len() - 6) as u32);
    assert!(handle_at(&mut registry, &second, 5_100).is_empty());

    // ApiVersions v0 response: correlation id + error code 0.
    let response_body = [0, 0, 0, 7, 0, 0];
    let mut response_frame = (response_body.len() as i32).to_be_bytes().to_vec();
    response_frame.extend_from_slice(&response_body);
    let response = response_event(9092, &response_frame);
    let signals = handle_at(&mut registry, &response, 9_100);

    assert_eq!(signals.len(), 1);
    let observation = observation(&signals[0]);
    assert_eq!(observation.protocol, ProtocolKind::Kafka);
    assert_eq!(observation.method.as_deref(), Some("api_versions"));
    assert_eq!(observation.start_unix_nanos, 5_000);
    assert_eq!(observation.duration_nanos, Some(4_100));
    assert_eq!(registry.counters().matched_responses, 1);
}

#[test]
fn kafka_response_correlation_id_prevents_destructive_fifo_mismatch() {
    let mut registry = registry();
    let frame = kafka_api_versions_request(7);
    assert!(
        handle_at(
            &mut registry,
            &raw_event(9092, &frame, frame.len() as u32),
            5_000
        )
        .is_empty()
    );

    let mismatched_frame = kafka_api_versions_response(6);
    let mismatched = response_event(9092, &mismatched_frame);
    assert!(handle_at(&mut registry, &mismatched, 6_000).is_empty());
    assert_eq!(registry.counters().matched_responses, 0);
    assert_eq!(registry.counters().kafka_correlation_mismatches, 1);

    let matched_frame = kafka_api_versions_response(7);
    let matched = response_event(9092, &matched_frame);
    let signals = handle_at(&mut registry, &matched, 7_000);
    assert_eq!(signals.len(), 1);
    assert_eq!(registry.counters().matched_responses, 1);
}

#[test]
fn kafka_response_correlation_id_matches_out_of_order_requests() {
    let mut registry = registry();
    for (correlation_id, observed_at) in [(7, 5_000), (8, 6_000)] {
        let request = kafka_api_versions_request(correlation_id);
        assert!(
            handle_at(
                &mut registry,
                &raw_event(9092, &request, request.len() as u32),
                observed_at,
            )
            .is_empty()
        );
    }

    let response_eight = kafka_api_versions_response(8);
    let signals = handle_at(&mut registry, &response_event(9092, &response_eight), 7_000);
    assert_eq!(signals.len(), 1);
    assert_eq!(observation(&signals[0]).duration_nanos, Some(1_000));

    let response_seven = kafka_api_versions_response(7);
    let signals = handle_at(&mut registry, &response_event(9092, &response_seven), 8_000);
    assert_eq!(signals.len(), 1);
    assert_eq!(observation(&signals[0]).duration_nanos, Some(3_000));
    assert_eq!(registry.counters().matched_responses, 2);
    assert_eq!(registry.counters().kafka_correlation_mismatches, 0);
}

#[test]
fn mongodb_response_to_matches_out_of_order_requests() {
    let mut registry = registry();
    for (request_id, collection, observed_at) in [(7, "customers", 5_000), (8, "orders", 6_000)] {
        let request = mongodb_op_msg(request_id, 0, &mongodb_find_document(collection));
        assert!(
            handle_at(
                &mut registry,
                &raw_event(27017, &request, request.len() as u32),
                observed_at,
            )
            .is_empty()
        );
    }

    let response_eight = mongodb_op_msg(80, 8, &mongodb_ok_document());
    let signals = handle_at(
        &mut registry,
        &response_event(27017, &response_eight),
        7_000,
    );
    assert_eq!(signals.len(), 1);
    assert_eq!(observation(&signals[0]).duration_nanos, Some(1_000));
    assert!(
        observation(&signals[0]).attributes.iter().any(|attribute| {
            attribute.key == "db.collection.name" && attribute.value == "orders"
        })
    );

    let response_seven = mongodb_op_msg(70, 7, &mongodb_ok_document());
    let signals = handle_at(
        &mut registry,
        &response_event(27017, &response_seven),
        8_000,
    );
    assert_eq!(signals.len(), 1);
    assert_eq!(observation(&signals[0]).duration_nanos, Some(3_000));
    assert!(observation(&signals[0]).attributes.iter().any(|attribute| {
        attribute.key == "db.collection.name" && attribute.value == "customers"
    }));
    assert_eq!(registry.counters().matched_responses, 2);
    assert_eq!(registry.counters().mongodb_correlation_mismatches, 0);
}

#[test]
fn mongodb_response_to_mismatch_retains_the_request() {
    let mut registry = registry();
    let request = mongodb_op_msg(7, 0, &mongodb_find_document("customers"));
    assert!(
        handle_at(
            &mut registry,
            &raw_event(27017, &request, request.len() as u32),
            5_000,
        )
        .is_empty()
    );

    let mismatched_response = mongodb_op_msg(60, 6, &mongodb_ok_document());
    assert!(
        handle_at(
            &mut registry,
            &response_event(27017, &mismatched_response),
            6_000,
        )
        .is_empty()
    );
    assert_eq!(registry.counters().matched_responses, 0);
    assert_eq!(registry.counters().mongodb_correlation_mismatches, 1);

    let matched_response = mongodb_op_msg(70, 7, &mongodb_ok_document());
    let signals = handle_at(
        &mut registry,
        &response_event(27017, &matched_response),
        7_000,
    );
    assert_eq!(signals.len(), 1);
    assert_eq!(observation(&signals[0]).duration_nanos, Some(2_000));
    assert_eq!(registry.counters().matched_responses, 1);
}

#[test]
fn mongodb_fire_and_forget_request_emits_without_waiting_for_a_response() {
    let mut registry = registry();
    let request = mongodb_op_msg_with_flags(7, 0, 0x02, &mongodb_find_document("customers"));

    let signals = handle_at(
        &mut registry,
        &raw_event(27017, &request, request.len() as u32),
        5_000,
    );

    assert_eq!(signals.len(), 1);
    assert_eq!(observation(&signals[0]).duration_nanos, None);
    assert_eq!(registry.counters().mongodb_fire_and_forget_requests, 1);
}

#[test]
fn mongodb_exhaust_request_is_retained_until_the_final_response() {
    let mut registry = registry();
    let request = mongodb_op_msg_with_flags(7, 0, 0x0001_0000, &mongodb_find_document("customers"));
    assert!(
        handle_at(
            &mut registry,
            &raw_event(27017, &request, request.len() as u32),
            5_000,
        )
        .is_empty()
    );

    let continued = mongodb_op_msg_with_flags(70, 7, 0x02, &mongodb_ok_document());
    assert!(handle_at(&mut registry, &response_event(27017, &continued), 6_000,).is_empty());
    assert_eq!(registry.counters().mongodb_response_continuations, 1);

    let final_response = mongodb_op_msg(71, 7, &mongodb_ok_document());
    let signals = handle_at(
        &mut registry,
        &response_event(27017, &final_response),
        8_000,
    );
    assert_eq!(signals.len(), 1);
    assert_eq!(observation(&signals[0]).duration_nanos, Some(3_000));
    assert_eq!(registry.counters().matched_responses, 1);
}

#[test]
fn mongodb_unexpected_continuation_fails_closed_and_retains_request() {
    let mut registry = registry();
    let request = mongodb_op_msg(7, 0, &mongodb_find_document("customers"));
    assert!(
        handle_at(
            &mut registry,
            &raw_event(27017, &request, request.len() as u32),
            5_000,
        )
        .is_empty()
    );

    let unexpected = mongodb_op_msg_with_flags(70, 7, 0x02, &mongodb_ok_document());
    assert!(handle_at(&mut registry, &response_event(27017, &unexpected), 6_000,).is_empty());
    assert_eq!(registry.counters().mongodb_lifecycle_failures, 1);

    let final_response = mongodb_op_msg(71, 7, &mongodb_ok_document());
    let signals = handle_at(
        &mut registry,
        &response_event(27017, &final_response),
        8_000,
    );
    assert_eq!(signals.len(), 1);
    assert_eq!(observation(&signals[0]).duration_nanos, Some(3_000));
}

#[test]
fn dynamic_discovery_matches_redis_on_an_unconfigured_port() {
    let mut registry = discovery_registry();
    let request = raw_event(16_379, b"*1\r\n$4\r\nPING\r\n", 14);
    assert!(handle_at(&mut registry, &request, 5_000).is_empty());

    let response = response_event(16_379, b"+OK\r\n");
    let signals = handle_at(&mut registry, &response, 7_000);
    assert_eq!(signals.len(), 1);
    assert_eq!(observation(&signals[0]).protocol, ProtocolKind::Redis);
    assert_eq!(observation(&signals[0]).duration_nanos, Some(2_000));
    assert_eq!(registry.counters().discovered_connections, 1);
}

#[test]
fn dynamic_discovery_does_not_guess_an_ambiguous_prefix() {
    let mut registry = discovery_registry();
    let request = raw_event(16_379, b"PING\r\n", 6);

    assert!(handle_at(&mut registry, &request, 5_000).is_empty());
    assert_eq!(registry.tracked_connections(), 0);
    assert_eq!(registry.counters().discovery_unclassified_events, 1);
}

#[test]
fn dynamic_discovery_reassembles_a_request_across_syscalls() {
    let mut registry = discovery_registry();
    let first = raw_event(16_379, b"*1\r\n", 4);
    assert!(handle_at(&mut registry, &first, 5_000).is_empty());

    let mut second = raw_event(16_379, b"$4\r\nPING\r\n", 10);
    second.timestamp_unix_nanos = 2_000;
    assert!(handle_at(&mut registry, &second, 6_000).is_empty());

    let response = response_event(16_379, b"+OK\r\n");
    let signals = handle_at(&mut registry, &response, 7_000);
    assert_eq!(signals.len(), 1);
    assert_eq!(observation(&signals[0]).protocol, ProtocolKind::Redis);
    assert_eq!(observation(&signals[0]).duration_nanos, Some(2_000));
    assert_eq!(registry.counters().discovered_connections, 1);
}

#[test]
fn configured_port_precedes_dynamic_discovery() {
    let config = ProtocolSourceConfig {
        discovery_enabled: true,
        nats_ports: vec![16_379],
        ..ProtocolSourceConfig::default()
    };
    let mut registry = ProtocolStreamRegistry::new(
        Some("test-host".to_string()),
        std::path::PathBuf::from("__e_navigator_test_no_procfs__"),
        &config,
    );

    let signals = handle_at(&mut registry, &raw_event(16_379, b"PING\r\n", 6), 5_000);
    assert_eq!(signals.len(), 1);
    assert_eq!(observation(&signals[0]).protocol, ProtocolKind::Nats);
    assert_eq!(registry.counters().discovered_connections, 0);
    assert_eq!(registry.counters().discovery_unclassified_events, 0);
}

#[test]
fn dynamic_discovery_candidate_count_is_bounded() {
    let config = ProtocolSourceConfig {
        discovery_enabled: true,
        max_tracked_connections: 1,
        ..ProtocolSourceConfig::default()
    };
    let mut registry = ProtocolStreamRegistry::new(
        Some("test-host".to_string()),
        std::path::PathBuf::from("__e_navigator_test_no_procfs__"),
        &config,
    );
    assert!(handle_at(&mut registry, &raw_event(16_379, b"PING\r\n", 6), 5_000,).is_empty());
    let mut second = raw_event(16_380, b"PING\r\n", 6);
    second.fd = 10;
    assert!(handle_at(&mut registry, &second, 6_000).is_empty());

    assert_eq!(registry.discovery_candidates.len(), 1);
    assert_eq!(registry.counters().discovery_candidate_evictions, 1);
}

#[test]
fn kafka_duplicate_in_flight_correlation_id_is_non_destructive() {
    let mut registry = registry();
    let request = kafka_api_versions_request(7);
    for observed_at in [5_000, 6_000] {
        assert!(
            handle_at(
                &mut registry,
                &raw_event(9092, &request, request.len() as u32),
                observed_at,
            )
            .is_empty()
        );
    }

    let response = kafka_api_versions_response(7);
    for expected_mismatches in [1, 2] {
        assert!(handle_at(&mut registry, &response_event(9092, &response), 7_000,).is_empty());
        assert_eq!(
            registry.counters().kafka_correlation_mismatches,
            expected_mismatches
        );
    }
    assert_eq!(registry.counters().matched_responses, 0);
}

#[test]
fn truncated_frame_is_counted_not_emitted() {
    let mut registry = registry();
    let mut frame = 4096_i32.to_be_bytes().to_vec();
    frame.extend_from_slice(&[0; 64]);
    let event = raw_event(9092, &frame, 4100);
    let signals = handle(&mut registry, &event);

    assert!(signals.is_empty());
    assert_eq!(registry.counters().truncated_frames, 1);
}

#[test]
fn nats_read_direction_is_ignored() {
    let mut registry = registry();
    let event = response_event(4222, b"MSG updates 1 5\r\nhello\r\n");
    let signals = handle(&mut registry, &event);

    assert!(signals.is_empty());
    assert_eq!(registry.counters().ignored_read_events, 1);
}

#[test]
fn orphan_responses_are_counted_not_matched() {
    let mut registry = registry();
    let event = response_event(6379, b"+OK\r\n");
    let signals = handle(&mut registry, &event);

    assert!(signals.is_empty());
    assert_eq!(registry.counters().orphan_responses, 1);
}

#[test]
fn unmapped_port_is_an_explicit_filter() {
    let mut registry = registry();
    let payload = b"PING\r\n";
    let event = raw_event(8080, payload, payload.len() as u32);
    let mut signals = Vec::new();
    let err = registry
        .handle_event(raw_as_bytes(&event), 5_000, &mut signals)
        .expect_err("unmapped port is rejected");
    assert_eq!(err.reason_name(), "unmapped_port");
    assert!(err.is_filtered_sample());
}

#[test]
fn unresolved_server_port_remains_invalid() {
    let mut registry = registry();
    let payload = b"PING\r\n";
    let mut event = raw_event(0, payload, payload.len() as u32);
    event.local_port_be = 0;
    event.role = RAW_PROTOCOL_ROLE_SERVER;
    event.direction = RAW_PROTOCOL_DIRECTION_READ;
    let mut signals = Vec::new();
    let err = registry
        .handle_event(raw_as_bytes(&event), 5_000, &mut signals)
        .expect_err("unresolved server port is rejected");
    assert_eq!(err.reason_name(), "unresolved_server_port");
    assert!(!err.is_filtered_sample());
}

#[test]
fn short_sample_is_rejected() {
    let mut registry = registry();
    let mut signals = Vec::new();
    let err = registry
        .handle_event(&[0_u8; 16], 5_000, &mut signals)
        .expect_err("short sample is rejected");
    assert_eq!(err.reason_name(), "raw_sample_too_short");
}

#[test]
fn invalid_payload_length_is_rejected() {
    let mut registry = registry();
    let payload = b"PING\r\n";
    let mut event = raw_event(6379, payload, payload.len() as u32);
    event.payload_len = (RAW_PROTOCOL_DATA_BYTES + 1) as u32;
    let mut signals = Vec::new();
    let err = registry
        .handle_event(raw_as_bytes(&event), 5_000, &mut signals)
        .expect_err("oversized payload length is rejected");
    assert_eq!(err.reason_name(), "invalid_payload_length");
}

/// Splits one syscall payload into eBPF-shaped segment events.
fn segmented_events(remote_port: u16, payload: &[u8]) -> Vec<RawProtocolDataEvent> {
    payload
        .chunks(RAW_PROTOCOL_DATA_BYTES)
        .enumerate()
        .map(|(index, chunk)| {
            let mut event = raw_event(remote_port, chunk, payload.len() as u32);
            event.payload_offset = (index * RAW_PROTOCOL_DATA_BYTES) as u32;
            event.payload_captured_len = payload.len() as u32;
            event
        })
        .collect()
}

#[test]
fn multi_segment_syscall_reassembles_complete_frame() {
    let mut registry = registry();
    let value = "x".repeat(560);
    let mut command = format!(
        "*3\r\n$3\r\nSET\r\n$10\r\nsecret-key\r\n${}\r\n",
        value.len()
    )
    .into_bytes();
    command.extend_from_slice(value.as_bytes());
    command.extend_from_slice(b"\r\n");
    assert!(command.len() > 2 * RAW_PROTOCOL_DATA_BYTES);

    for event in segmented_events(6379, &command) {
        assert!(handle_at(&mut registry, &event, 5_000).is_empty());
    }

    let response = response_event(6379, b"+OK\r\n");
    let signals = handle_at(&mut registry, &response, 6_000);
    assert_eq!(signals.len(), 1);
    let observation = observation(&signals[0]);
    assert_eq!(observation.method.as_deref(), Some("SET"));
    assert_eq!(observation.confidence, TraceConfidence::High);
    assert_eq!(registry.counters().segment_gaps, 0);
    assert_eq!(registry.counters().truncated_frames, 0);

    let serialized = serde_json::to_string(&signals[0]).expect("signal serializes");
    assert!(!serialized.contains("xxxx"));
    assert!(!serialized.contains("secret-key"));
}

#[test]
fn lost_final_segment_becomes_accounted_gap() {
    let mut registry = registry();
    let value = "x".repeat(560);
    let mut command = format!(
        "*3\r\n$3\r\nSET\r\n$10\r\nsecret-key\r\n${}\r\n",
        value.len()
    )
    .into_bytes();
    command.extend_from_slice(value.as_bytes());
    command.extend_from_slice(b"\r\n");

    let segments = segmented_events(6379, &command);
    assert!(segments.len() >= 2);
    // Only the first segment arrives; the rest are lost.
    assert!(handle_at(&mut registry, &segments[0], 5_000).is_empty());

    // The next syscall flushes the missing tail as a gap; its own
    // command still parses cleanly at the next frame boundary.
    let ping = raw_event(6379, b"*1\r\n$4\r\nPING\r\n", 14);
    assert!(handle_at(&mut registry, &ping, 5_100).is_empty());
    assert_eq!(registry.counters().segment_gaps, 1);
    assert_eq!(registry.counters().truncated_frames, 1);

    let response = response_event(6379, b"+PONG\r\n+PONG\r\n");
    let signals = handle_at(&mut registry, &response, 6_000);
    assert_eq!(signals.len(), 2);
    assert_eq!(observation(&signals[1]).method.as_deref(), Some("PING"));
}

#[test]
fn lost_leading_segments_become_accounted_gap() {
    let mut registry = registry();
    // A mid-syscall segment arrives with no preceding offset-0 segment.
    // Its bytes cannot start a valid frame, so the decoder resyncs.
    let mut orphan = raw_event(6379, &[b'*'; 200], 456);
    orphan.payload_offset = 256;
    orphan.payload_captured_len = 456;
    assert!(handle_at(&mut registry, &orphan, 5_000).is_empty());
    assert_eq!(registry.counters().segment_gaps, 1);

    // The stream recovers at the next clean frame boundary.
    let ping = raw_event(6379, b"*1\r\n$4\r\nPING\r\n", 14);
    assert!(handle_at(&mut registry, &ping, 5_100).is_empty());
    let response = response_event(6379, b"+PONG\r\n");
    let signals = handle_at(&mut registry, &response, 6_000);
    assert_eq!(signals.len(), 1);
    assert_eq!(observation(&signals[0]).method.as_deref(), Some("PING"));
}

#[test]
fn segment_exceeding_captured_len_is_rejected() {
    let mut registry = registry();
    let payload = b"PING\r\n";
    let mut event = raw_event(6379, payload, payload.len() as u32);
    event.payload_offset = 8;
    let mut signals = Vec::new();
    let err = registry
        .handle_event(raw_as_bytes(&event), 5_000, &mut signals)
        .expect_err("segment past captured length is rejected");
    assert_eq!(err.reason_name(), "invalid_payload_length");
}

#[test]
fn captured_len_exceeding_total_len_is_rejected() {
    let mut registry = registry();
    let payload = b"PING\r\n";
    let mut event = raw_event(6379, payload, payload.len() as u32);
    event.payload_captured_len = event.payload_total_len + 1;
    let mut signals = Vec::new();
    let err = registry
        .handle_event(raw_as_bytes(&event), 5_000, &mut signals)
        .expect_err("captured length past total length is rejected");
    assert_eq!(err.reason_name(), "invalid_payload_length");
}

#[test]
fn unparsed_request_frames_hold_queue_position() {
    let mut registry = registry();
    // A valid MySQL packet header carrying an unknown command byte: it
    // cannot be parsed, but its response slot must stay aligned.
    let packet = [1, 0, 0, 0, 0xfb];
    let event = raw_event(3306, &packet, packet.len() as u32);
    assert!(handle_at(&mut registry, &event, 5_000).is_empty());
    assert_eq!(registry.counters().unparsed_frames, 1);

    let response = response_event(3306, &[7, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0]);
    let signals = handle_at(&mut registry, &response, 6_000);
    assert_eq!(signals.len(), 1);
    let observation = observation(&signals[0]);
    assert_eq!(observation.method, None);
    assert_eq!(observation.confidence, TraceConfidence::Low);
    assert_eq!(observation.duration_nanos, Some(1_000));
}

#[test]
fn connection_cap_evicts_oldest_stream() {
    let config = ProtocolSourceConfig {
        max_tracked_connections: 2,
        ..ProtocolSourceConfig::default()
    };
    let mut registry = ProtocolStreamRegistry::new(
        None,
        std::path::PathBuf::from("__e_navigator_test_no_procfs__"),
        &config,
    );

    let payload = b"PING\r\n";
    for fd in 0..3 {
        let mut event = raw_event(6379, payload, payload.len() as u32);
        event.fd = fd;
        let mut signals = Vec::new();
        registry
            .handle_event(raw_as_bytes(&event), 5_000 + fd as u64, &mut signals)
            .expect("valid event decodes");
    }

    assert_eq!(registry.tracked_connections(), 2);
    assert_eq!(registry.counters().evicted_connections, 1);
}

fn http2_frame(frame_type: u8, flags: u8, stream_id: u32, payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::new();
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes()[1..]);
    frame.push(frame_type);
    frame.push(flags);
    frame.extend_from_slice(&stream_id.to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

#[test]
fn http2_request_matches_stream_response() {
    let config = ProtocolSourceConfig {
        http2_ports: vec![50051],
        ..ProtocolSourceConfig::default()
    };
    let mut registry = ProtocolStreamRegistry::new(
        None,
        std::path::PathBuf::from("__e_navigator_test_no_procfs__"),
        &config,
    );

    // Preface, then HEADERS for stream 1: :method GET (0x82), :path / (0x84).
    let mut request_payload = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
    request_payload.extend_from_slice(&http2_frame(1, 0x4, 1, &[0x82, 0x84]));
    let request = raw_event(50051, &request_payload, request_payload.len() as u32);
    assert!(handle_at(&mut registry, &request, 5_000).is_empty());

    // Response HEADERS with :status 200 (0x88) and END_STREAM|END_HEADERS.
    let response_payload = http2_frame(1, 0x4 | 0x1, 1, &[0x88]);
    let mut response = raw_event(50051, &response_payload, response_payload.len() as u32);
    response.direction = RAW_PROTOCOL_DIRECTION_READ;
    let signals = handle_at(&mut registry, &response, 6_200);

    assert_eq!(signals.len(), 1);
    let observation = observation(&signals[0]);
    assert_eq!(observation.protocol, ProtocolKind::Http);
    assert_eq!(observation.method.as_deref(), Some("GET"));
    assert_eq!(observation.duration_nanos, Some(1_200));
    assert!(
        observation
            .attributes
            .iter()
            .any(|attribute| attribute.key == "http.response.status_code"
                && attribute.value == "200"),
    );
}

#[test]
fn http2_request_continuation_reassembles_before_matching() {
    let config = ProtocolSourceConfig {
        http2_ports: vec![50051],
        ..ProtocolSourceConfig::default()
    };
    let mut registry = ProtocolStreamRegistry::new(
        None,
        std::path::PathBuf::from("__e_navigator_test_no_procfs__"),
        &config,
    );

    let mut request_payload = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
    request_payload.extend_from_slice(&http2_frame(HTTP2_FRAME_TYPE_HEADERS, 0, 1, &[0x82]));
    let request = raw_event(50051, &request_payload, request_payload.len() as u32);
    assert!(handle_at(&mut registry, &request, 5_000).is_empty());

    let continuation = http2_frame(HTTP2_FRAME_TYPE_CONTINUATION, 0x4, 1, &[0x84]);
    let request = raw_event(50051, &continuation, continuation.len() as u32);
    assert!(handle_at(&mut registry, &request, 5_100).is_empty());

    let response_payload = http2_frame(HTTP2_FRAME_TYPE_HEADERS, 0x4 | 0x1, 1, &[0x88]);
    let mut response = raw_event(50051, &response_payload, response_payload.len() as u32);
    response.direction = RAW_PROTOCOL_DIRECTION_READ;
    let signals = handle_at(&mut registry, &response, 6_200);

    assert_eq!(signals.len(), 1);
    let observation = observation(&signals[0]);
    assert_eq!(observation.method.as_deref(), Some("GET"));
    assert_eq!(observation.duration_nanos, Some(1_200));
    assert_eq!(registry.counters().unparsed_frames, 0);
    assert_eq!(registry.counters().unparsed_responses, 0);
}

#[test]
fn http2_response_continuation_preserves_initial_end_stream() {
    let config = ProtocolSourceConfig {
        http2_ports: vec![50051],
        ..ProtocolSourceConfig::default()
    };
    let mut registry = ProtocolStreamRegistry::new(
        None,
        std::path::PathBuf::from("__e_navigator_test_no_procfs__"),
        &config,
    );

    let mut request_payload = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
    request_payload.extend_from_slice(&http2_frame(
        HTTP2_FRAME_TYPE_HEADERS,
        0x4,
        1,
        &[0x82, 0x84],
    ));
    let request = raw_event(50051, &request_payload, request_payload.len() as u32);
    assert!(handle_at(&mut registry, &request, 5_000).is_empty());

    let response_headers = http2_frame(HTTP2_FRAME_TYPE_HEADERS, 0x1, 1, &[]);
    let mut response = raw_event(50051, &response_headers, response_headers.len() as u32);
    response.direction = RAW_PROTOCOL_DIRECTION_READ;
    assert!(handle_at(&mut registry, &response, 5_500).is_empty());

    let response_continuation = http2_frame(HTTP2_FRAME_TYPE_CONTINUATION, 0x4, 1, &[0x88]);
    let mut response = raw_event(
        50051,
        &response_continuation,
        response_continuation.len() as u32,
    );
    response.direction = RAW_PROTOCOL_DIRECTION_READ;
    let signals = handle_at(&mut registry, &response, 6_000);

    assert_eq!(signals.len(), 1);
    let observation = observation(&signals[0]);
    assert_eq!(observation.duration_nanos, Some(1_000));
    assert!(
        observation
            .attributes
            .iter()
            .any(|attribute| attribute.key == "http.response.status_code"
                && attribute.value == "200"),
    );
    assert_eq!(registry.counters().unparsed_frames, 0);
    assert_eq!(registry.counters().unparsed_responses, 0);
}

#[test]
fn http2_multiplexed_streams_match_out_of_order() {
    let config = ProtocolSourceConfig {
        http2_ports: vec![50051],
        ..ProtocolSourceConfig::default()
    };
    let mut registry = ProtocolStreamRegistry::new(
        None,
        std::path::PathBuf::from("__e_navigator_test_no_procfs__"),
        &config,
    );

    let mut request_payload = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
    request_payload.extend_from_slice(&http2_frame(1, 0x4, 1, &[0x82, 0x84]));
    request_payload.extend_from_slice(&http2_frame(1, 0x4, 3, &[0x83, 0x84]));
    let request = raw_event(50051, &request_payload, request_payload.len() as u32);
    assert!(handle_at(&mut registry, &request, 5_000).is_empty());

    // Stream 3 responds before stream 1.
    let mut response_payload = http2_frame(1, 0x4 | 0x1, 3, &[0x88]);
    response_payload.extend_from_slice(&http2_frame(1, 0x4 | 0x1, 1, &[0x88]));
    let mut response = raw_event(50051, &response_payload, response_payload.len() as u32);
    response.direction = RAW_PROTOCOL_DIRECTION_READ;
    let signals = handle_at(&mut registry, &response, 6_000);

    assert_eq!(signals.len(), 2);
    assert_eq!(observation(&signals[0]).method.as_deref(), Some("POST"));
    assert_eq!(observation(&signals[1]).method.as_deref(), Some("GET"));
}

#[test]
fn http2_grpc_trailers_complete_the_stream() {
    let config = ProtocolSourceConfig {
        http2_ports: vec![50051],
        ..ProtocolSourceConfig::default()
    };
    let mut registry = ProtocolStreamRegistry::new(
        None,
        std::path::PathBuf::from("__e_navigator_test_no_procfs__"),
        &config,
    );

    // gRPC request: :method POST, :path /pkg.Svc/Do, content-type
    // application/grpc (all literal without indexing where needed).
    let mut block = vec![0x83, 0x04];
    let path = b"/pkg.Svc/Do";
    block.push(path.len() as u8);
    block.extend_from_slice(path);
    block.push(0x0f);
    block.push(31 - 15);
    let content_type = b"application/grpc";
    block.push(content_type.len() as u8);
    block.extend_from_slice(content_type);
    let mut request_payload = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
    request_payload.extend_from_slice(&http2_frame(1, 0x4, 1, &block));
    let request = raw_event(50051, &request_payload, request_payload.len() as u32);
    assert!(handle_at(&mut registry, &request, 5_000).is_empty());

    // Response headers without END_STREAM, then trailers with grpc-status.
    let headers = http2_frame(1, 0x4, 1, &[0x88]);
    let mut response = raw_event(50051, &headers, headers.len() as u32);
    response.direction = RAW_PROTOCOL_DIRECTION_READ;
    assert!(handle_at(&mut registry, &response, 5_500).is_empty());

    let mut trailer_block = vec![0x00];
    let name = b"grpc-status";
    trailer_block.push(name.len() as u8);
    trailer_block.extend_from_slice(name);
    trailer_block.push(1);
    trailer_block.push(b'0');
    let trailers = http2_frame(1, 0x4 | 0x1, 1, &trailer_block);
    let mut response = raw_event(50051, &trailers, trailers.len() as u32);
    response.direction = RAW_PROTOCOL_DIRECTION_READ;
    let signals = handle_at(&mut registry, &response, 6_000);

    assert_eq!(signals.len(), 1);
    let observation = observation(&signals[0]);
    assert_eq!(observation.protocol, ProtocolKind::Grpc);
    assert_eq!(observation.duration_nanos, Some(1_000));
    assert!(
        observation
            .attributes
            .iter()
            .any(|attribute| attribute.key == "rpc.service" && attribute.value == "pkg.Svc"),
    );
    assert!(
        observation
            .attributes
            .iter()
            .any(|attribute| attribute.key == "rpc.grpc.status_code" && attribute.value == "0"),
    );
}

#[test]
fn http1_request_matches_response_with_status() {
    let config = ProtocolSourceConfig {
        http1_ports: vec![8443],
        ..ProtocolSourceConfig::default()
    };
    let mut registry = ProtocolStreamRegistry::new(
        None,
        std::path::PathBuf::from("__e_navigator_test_no_procfs__"),
        &config,
    );

    let request = b"GET /orders/42 HTTP/1.1\r\nHost: api.test\r\n\r\n";
    let event = raw_event(8443, request, request.len() as u32);
    assert!(handle_at(&mut registry, &event, 5_000).is_empty());

    let response = response_event(
        8443,
        b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n",
    );
    let signals = handle_at(&mut registry, &response, 6_000);

    assert_eq!(signals.len(), 1);
    let observation = observation(&signals[0]);
    assert_eq!(observation.protocol, ProtocolKind::Http);
    assert_eq!(observation.method.as_deref(), Some("GET"));
    assert_eq!(observation.duration_nanos, Some(1_000));
    assert!(
        observation
            .attributes
            .iter()
            .any(|attribute| attribute.key == "http.response.status_code"
                && attribute.value == "503"),
    );
    // The request target path must not leak as a high-cardinality value.
    let serialized = serde_json::to_string(&signals[0]).expect("signal serializes");
    assert!(serialized.contains("url.path"));
}

#[test]
fn registry_preserves_tls_source_provenance() {
    let config = ProtocolSourceConfig {
        http1_ports: vec![8443],
        ..ProtocolSourceConfig::default()
    };
    let mut registry = ProtocolStreamRegistry::new_with_source(
        None,
        std::path::PathBuf::from("__e_navigator_test_no_procfs__"),
        &config,
        "source.aya_tls",
    );
    let request = b"GET / HTTP/1.1\r\nHost: api.test\r\n\r\n";
    let event = raw_event(8443, request, request.len() as u32);
    assert!(handle_at(&mut registry, &event, 5_000).is_empty());
    let response = response_event(8443, b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
    let signals = handle_at(&mut registry, &response, 6_000);

    assert_eq!(signals.len(), 1);
    assert_eq!(signals[0].source, "source.aya_tls");
}

#[test]
fn server_role_uses_local_port_and_read_as_request_direction() {
    let config = ProtocolSourceConfig {
        http1_ports: vec![8443],
        ..ProtocolSourceConfig::default()
    };
    let mut registry = ProtocolStreamRegistry::new(
        None,
        std::path::PathBuf::from("__e_navigator_test_no_procfs__"),
        &config,
    );

    let request = b"GET /inbound HTTP/1.1\r\nHost: api.test\r\n\r\n";
    let mut event = raw_event(51_000, request, request.len() as u32);
    event.local_port_be = 8443_u16.to_be();
    event.role = RAW_PROTOCOL_ROLE_SERVER;
    event.direction = RAW_PROTOCOL_DIRECTION_READ;
    assert!(handle_at(&mut registry, &event, 5_000).is_empty());

    let response = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
    let mut event = raw_event(51_000, response, response.len() as u32);
    event.local_port_be = 8443_u16.to_be();
    event.role = RAW_PROTOCOL_ROLE_SERVER;
    event.direction = RAW_PROTOCOL_DIRECTION_WRITE;
    let signals = handle_at(&mut registry, &event, 6_000);

    assert_eq!(signals.len(), 1);
    let observation = observation(&signals[0]);
    assert_eq!(observation.role, Some(ProtocolCaptureRole::Server));
    assert_eq!(observation.method.as_deref(), Some("GET"));
    assert_eq!(observation.duration_nanos, Some(1_000));
}

#[cfg(unix)]
#[test]
fn server_role_resolves_preexisting_listener_port_from_bounded_procfs() {
    use std::os::unix::fs::symlink;

    let fixture_root = std::env::temp_dir().join(format!(
        "e-navigator-protocol-procfs-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos(),
    ));
    let pid = 4_242_u32;
    let fd = 17_i32;
    let fd_root = fixture_root.join(pid.to_string()).join("fd");
    let net_root = fixture_root.join(pid.to_string()).join("net");
    std::fs::create_dir_all(&fd_root).expect("fixture fd directory");
    std::fs::create_dir_all(&net_root).expect("fixture net directory");
    symlink("socket:[12345]", fd_root.join(fd.to_string())).expect("fixture socket link");
    std::fs::write(
            net_root.join("tcp"),
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
               0: 00000000:20FB 00000000:0000 0A 00000000:00000000 00:00000000 00000000 1000 0 12345\n",
        )
        .expect("fixture tcp table");

    let listeners = discover_existing_listener_endpoints(&fixture_root);
    assert_eq!(listeners.len(), 1);
    assert_eq!(listeners[0].pid, pid);
    assert_eq!(listeners[0].fd, fd);
    assert_eq!(listeners[0].family, RAW_PROTOCOL_AF_INET);
    assert_eq!(u16::from_be(listeners[0].local_port_be), 8_443);

    let config = ProtocolSourceConfig {
        inbound_enabled: true,
        http1_ports: vec![8_443],
        ..ProtocolSourceConfig::default()
    };
    let mut registry = ProtocolStreamRegistry::new(None, fixture_root.clone(), &config);

    let request = b"GET /inbound HTTP/1.1\r\nHost: api.test\r\n\r\n";
    let mut event = raw_event(51_000, request, request.len() as u32);
    event.pid = pid;
    event.fd = fd;
    event.local_port_be = 0;
    event.role = RAW_PROTOCOL_ROLE_SERVER;
    event.direction = RAW_PROTOCOL_DIRECTION_READ;
    assert!(handle_at(&mut registry, &event, 5_000).is_empty());

    // The resolved endpoint is connection-scoped; later frames do not
    // depend on the procfs entry remaining readable.
    std::fs::remove_file(fd_root.join(fd.to_string())).expect("remove fixture link");
    let response = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
    let mut event = raw_event(51_000, response, response.len() as u32);
    event.pid = pid;
    event.fd = fd;
    event.local_port_be = 0;
    event.role = RAW_PROTOCOL_ROLE_SERVER;
    event.direction = RAW_PROTOCOL_DIRECTION_WRITE;
    let signals = handle_at(&mut registry, &event, 6_000);

    assert_eq!(signals.len(), 1);
    let observation = observation(&signals[0]);
    assert_eq!(observation.role, Some(ProtocolCaptureRole::Server));
    assert_eq!(observation.method.as_deref(), Some("GET"));
    std::fs::remove_dir_all(&fixture_root).expect("remove fixture procfs");
}

#[test]
fn server_grpc_capture_preserves_hpack_trace_context() {
    let config = ProtocolSourceConfig {
        http2_ports: vec![50051],
        ..ProtocolSourceConfig::default()
    };
    let mut registry = ProtocolStreamRegistry::new(
        None,
        std::path::PathBuf::from("__e_navigator_test_no_procfs__"),
        &config,
    );

    let mut block = vec![0x83]; // :method POST
    append_hpack_literal(&mut block, ":path", "/pkg.Svc/Call");
    append_hpack_literal(&mut block, "content-type", "application/grpc");
    append_hpack_literal(
        &mut block,
        "traceparent",
        "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
    );
    append_hpack_literal(&mut block, "tracestate", "vendor=opaque");
    let mut request_payload = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
    request_payload.extend_from_slice(&http2_frame(1, 0x4, 1, &block));
    let mut request = raw_event(51_000, &request_payload, request_payload.len() as u32);
    request.local_port_be = 50051_u16.to_be();
    request.role = RAW_PROTOCOL_ROLE_SERVER;
    request.direction = RAW_PROTOCOL_DIRECTION_READ;
    assert!(handle_at(&mut registry, &request, 5_000).is_empty());

    let response_payload = http2_frame(1, 0x4 | 0x1, 1, &[0x88]);
    let mut response = raw_event(51_000, &response_payload, response_payload.len() as u32);
    response.local_port_be = 50051_u16.to_be();
    response.role = RAW_PROTOCOL_ROLE_SERVER;
    response.direction = RAW_PROTOCOL_DIRECTION_WRITE;
    let signals = handle_at(&mut registry, &response, 6_000);

    assert_eq!(signals.len(), 1);
    let observation = observation(&signals[0]);
    assert_eq!(observation.protocol, ProtocolKind::Grpc);
    assert_eq!(observation.role, Some(ProtocolCaptureRole::Server));
    assert_eq!(
        observation.trace_id.as_deref(),
        Some("4bf92f3577b34da6a3ce929d0e0e4736")
    );
    assert_eq!(observation.span_id.as_deref(), Some("00f067aa0ba902b7"));
    assert!(observation.attributes.iter().any(|attribute| {
        attribute.key == "e.navigator.trace.tracestate" && attribute.value == "validated_discarded"
    }));
}

#[test]
fn server_grpc_cross_cpu_arrival_is_decoded_in_kernel_time_order() {
    let config = ProtocolSourceConfig {
        http2_ports: vec![50051],
        ..ProtocolSourceConfig::default()
    };
    let mut registry = ProtocolStreamRegistry::new(
        None,
        std::path::PathBuf::from("__e_navigator_test_no_procfs__"),
        &config,
    );

    let mut preface_and_settings = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
    preface_and_settings.extend_from_slice(&http2_frame(4, 0, 0, &[0; 36]));
    preface_and_settings.extend_from_slice(&http2_frame(8, 0, 0, &[0, 0, 0, 1]));
    let mut preface = raw_event(
        51_000,
        &preface_and_settings,
        preface_and_settings.len() as u32,
    );
    preface.local_port_be = 50051_u16.to_be();
    preface.role = RAW_PROTOCOL_ROLE_SERVER;
    preface.direction = RAW_PROTOCOL_DIRECTION_READ;
    preface.timestamp_unix_nanos = 100;

    let settings_ack_payload = http2_frame(4, 0x1, 0, &[]);
    let mut settings_ack = raw_event(
        51_000,
        &settings_ack_payload,
        settings_ack_payload.len() as u32,
    );
    settings_ack.local_port_be = 50051_u16.to_be();
    settings_ack.role = RAW_PROTOCOL_ROLE_SERVER;
    settings_ack.direction = RAW_PROTOCOL_DIRECTION_READ;
    settings_ack.timestamp_unix_nanos = 200;

    let mut block = vec![0x83]; // :method POST
    append_hpack_literal(&mut block, ":path", "/acceptance.Echo/Unary");
    append_hpack_literal(&mut block, "content-type", "application/grpc");
    append_hpack_literal(
        &mut block,
        "traceparent",
        "00-d60e3b12000000000000000000000001-face000000000001-01",
    );
    append_hpack_literal(&mut block, "user-agent", &"x".repeat(100));
    let mut request_payload = http2_frame(1, 0x4, 1, &block);
    request_payload.extend_from_slice(&http2_frame(0, 0x1, 1, &[0; 32]));
    assert!(request_payload.len() > RAW_PROTOCOL_DATA_BYTES);
    let mut request_segments = segmented_events(51_000, &request_payload);
    for segment in &mut request_segments {
        segment.local_port_be = 50051_u16.to_be();
        segment.role = RAW_PROTOCOL_ROLE_SERVER;
        segment.direction = RAW_PROTOCOL_DIRECTION_READ;
        segment.timestamp_unix_nanos = 300;
    }

    let response_payload = http2_frame(1, 0x4 | 0x1, 1, &[0x88]);
    let mut response = raw_event(51_000, &response_payload, response_payload.len() as u32);
    response.local_port_be = 50051_u16.to_be();
    response.role = RAW_PROTOCOL_ROLE_SERVER;
    response.direction = RAW_PROTOCOL_DIRECTION_WRITE;
    response.timestamp_unix_nanos = 400;

    let mut order = ProtocolSampleOrder::new(2, 16);
    // Model the observed grpcio scheduling: a worker CPU's HEADERS and
    // response arrive at userspace before another CPU's connection
    // preface and SETTINGS samples.
    for segment in &request_segments {
        assert!(order.push_sample(inline_sample(segment)).is_none());
    }
    assert!(order.push_sample(inline_sample(&response)).is_none());
    assert!(order.push_sample(inline_sample(&preface)).is_none());
    assert!(order.push_sample(inline_sample(&settings_ack)).is_none());
    order.update_watermark(0, 500);
    assert!(order.pop_ready().is_none());
    order.update_watermark(1, 500);

    let mut signals = Vec::new();
    while let Some(sample) = order.pop_ready() {
        let observed_unix_nanos =
            10_000 + protocol_sample_timestamp(&sample).expect("kernel timestamp");
        registry
            .handle_event(sample.as_bytes(), observed_unix_nanos, &mut signals)
            .expect("ordered raw event decodes");
    }

    assert_eq!(signals.len(), 1);
    let observation = observation(&signals[0]);
    assert_eq!(observation.protocol, ProtocolKind::Grpc);
    assert_eq!(observation.method.as_deref(), Some("POST"));
    assert!(observation.attributes.iter().any(|attribute| {
        attribute.key == "rpc.service" && attribute.value == "acceptance.Echo"
    }));
    assert!(
        observation
            .attributes
            .iter()
            .any(|attribute| { attribute.key == "rpc.method" && attribute.value == "Unary" })
    );
    assert_eq!(
        observation.trace_id.as_deref(),
        Some("d60e3b12000000000000000000000001")
    );
    assert_eq!(observation.span_id.as_deref(), Some("face000000000001"));
    assert_eq!(registry.counters().segment_gaps, 0);
    assert_eq!(registry.counters().unparsed_frames, 0);
}

fn append_hpack_literal(block: &mut Vec<u8>, name: &str, value: &str) {
    assert!(name.len() < 127);
    assert!(value.len() < 127);
    block.push(0x00);
    block.push(name.len() as u8);
    block.extend_from_slice(name.as_bytes());
    block.push(value.len() as u8);
    block.extend_from_slice(value.as_bytes());
}

#[test]
fn postgres_query_matches_ready_for_query() {
    let mut registry = registry();
    let statement = b"SELECT 1\0";
    let mut frame = vec![b'Q'];
    frame.extend_from_slice(&((statement.len() + 4) as u32).to_be_bytes());
    frame.extend_from_slice(statement);
    let event = raw_event(5432, &frame, frame.len() as u32);
    assert!(handle_at(&mut registry, &event, 5_000).is_empty());

    // CommandComplete is response payload; ReadyForQuery closes the batch.
    let mut response_payload = Vec::new();
    response_payload.push(b'C');
    response_payload.extend_from_slice(&13_u32.to_be_bytes());
    response_payload.extend_from_slice(b"SELECT 1\0");
    response_payload.push(b'Z');
    response_payload.extend_from_slice(&5_u32.to_be_bytes());
    response_payload.push(b'I');
    let response = response_event(5432, &response_payload);
    let signals = handle_at(&mut registry, &response, 8_000);

    assert_eq!(signals.len(), 1);
    let observation = observation(&signals[0]);
    assert_eq!(observation.protocol, ProtocolKind::Postgresql);
    assert_eq!(observation.method.as_deref(), Some("SELECT"));
    assert_eq!(observation.duration_nanos, Some(3_000));
    assert_eq!(registry.counters().response_continuations, 1);
    let serialized = serde_json::to_string(&signals[0]).expect("signal serializes");
    assert!(!serialized.contains("SELECT 1"));
}

#[test]
fn postgres_startup_owns_authentication_and_emits_one_private_connect_span() {
    let mut registry = registry();
    let startup = postgres_startup(b"user\0secret-user\0database\0secret-db\0\0");
    assert!(
        handle_at(
            &mut registry,
            &raw_event(5432, &startup, startup.len() as u32),
            5_000,
        )
        .is_empty()
    );

    let authentication_sasl = postgres_frame(
        b'R',
        &[
            0, 0, 0, 10, b'S', b'C', b'R', b'A', b'M', b'-', b'S', b'H', b'A', b'-', b'2', b'5',
            b'6', 0, 0,
        ],
    );
    assert!(
        handle_at(
            &mut registry,
            &response_event(5432, &authentication_sasl),
            6_000,
        )
        .is_empty()
    );

    // SASL responses are opaque bytes, not necessarily C strings. The
    // startup lifecycle owns them and must never emit their contents.
    let sasl_response = postgres_frame(b'p', b"secret-client-proof");
    assert!(
        handle_at(
            &mut registry,
            &raw_event(5432, &sasl_response, sasl_response.len() as u32),
            7_000,
        )
        .is_empty()
    );

    for response in [
        postgres_frame(b'R', &[0, 0, 0, 0]),
        postgres_frame(b'S', b"server_version\x0017.11\0"),
        postgres_frame(b'K', &[0xaa; 8]),
    ] {
        assert!(handle_at(&mut registry, &response_event(5432, &response), 8_000,).is_empty());
    }

    let ready = postgres_frame(b'Z', b"I");
    let signals = handle_at(&mut registry, &response_event(5432, &ready), 10_000);
    assert_eq!(signals.len(), 1);
    let observation = observation(&signals[0]);
    assert_eq!(observation.method.as_deref(), Some("CONNECT"));
    assert_eq!(observation.duration_nanos, Some(5_000));
    assert_eq!(registry.counters().matched_responses, 1);
    assert_eq!(registry.counters().unparsed_frames, 0);
    assert!(
        registry
            .connections
            .values()
            .next()
            .expect("postgres connection is tracked")
            .in_flight
            .is_empty()
    );
    let serialized = serde_json::to_string(&signals).expect("signals serialize");
    for secret in ["secret-user", "secret-db", "secret-client-proof"] {
        assert!(!serialized.contains(secret));
    }
}

#[test]
fn postgres_ssl_rejection_keeps_cleartext_startup_aligned() {
    let mut registry = registry();
    let mut ssl_request = 8_u32.to_be_bytes().to_vec();
    ssl_request.extend_from_slice(&80_877_103_u32.to_be_bytes());
    assert!(
        handle_at(
            &mut registry,
            &raw_event(5432, &ssl_request, ssl_request.len() as u32),
            5_000,
        )
        .is_empty()
    );
    assert!(handle_at(&mut registry, &response_event(5432, b"N"), 6_000).is_empty());

    let startup = postgres_startup(b"user\0secret-user\0\0");
    assert!(
        handle_at(
            &mut registry,
            &raw_event(5432, &startup, startup.len() as u32),
            7_000,
        )
        .is_empty()
    );
    let ready = postgres_frame(b'Z', b"I");
    let signals = handle_at(&mut registry, &response_event(5432, &ready), 9_000);
    assert_eq!(signals.len(), 1);
    assert_eq!(observation(&signals[0]).method.as_deref(), Some("CONNECT"));
    assert_eq!(
        registry.counters().postgres_encryption_negotiation_rejected,
        1
    );
    assert_eq!(registry.counters().unparsed_frames, 0);
    assert_eq!(registry.counters().unparsed_responses, 0);
}

#[test]
fn postgres_accepted_ssl_marks_raw_transport_opaque() {
    let mut registry = registry();
    let mut ssl_request = 8_u32.to_be_bytes().to_vec();
    ssl_request.extend_from_slice(&80_877_103_u32.to_be_bytes());
    assert!(
        handle_at(
            &mut registry,
            &raw_event(5432, &ssl_request, ssl_request.len() as u32),
            5_000,
        )
        .is_empty()
    );
    assert!(handle_at(&mut registry, &response_event(5432, b"S"), 6_000).is_empty());

    let tls_record = [0x16, 0x03, 0x03, 0, 8, 0xaa, 0xbb, 0xcc];
    assert!(
        handle_at(
            &mut registry,
            &raw_event(5432, &tls_record, tls_record.len() as u32),
            7_000,
        )
        .is_empty()
    );
    assert_eq!(
        registry.counters().postgres_encryption_negotiation_accepted,
        1
    );
    assert_eq!(registry.counters().postgres_encrypted_transport_events, 1);
    assert_eq!(registry.counters().unparsed_frames, 0);
}

#[test]
fn postgres_ssl_buffer_stuffing_fails_closed_with_diagnostic() {
    let mut registry = registry();
    let mut ssl_request = 8_u32.to_be_bytes().to_vec();
    ssl_request.extend_from_slice(&80_877_103_u32.to_be_bytes());
    assert!(
        handle_at(
            &mut registry,
            &raw_event(5432, &ssl_request, ssl_request.len() as u32),
            5_000,
        )
        .is_empty()
    );

    // PostgreSQL requires exactly one negotiation byte before the TLS
    // library takes ownership. Extra bytes are ambiguous and must not be
    // parsed as either backend messages or ciphertext.
    let stuffed = [b'S', 0x16, 0x03, 0x03];
    assert!(handle_at(&mut registry, &response_event(5432, &stuffed), 6_000,).is_empty());
    assert_eq!(registry.counters().postgres_negotiation_failures, 1);
    assert_eq!(
        registry.counters().postgres_encryption_negotiation_accepted,
        0
    );
    assert_eq!(registry.counters().unparsed_responses, 0);

    let ciphertext = [0x16, 0x03, 0x03, 0, 1, 0];
    assert!(
        handle_at(
            &mut registry,
            &raw_event(5432, &ciphertext, ciphertext.len() as u32),
            7_000,
        )
        .is_empty()
    );
    assert_eq!(registry.counters().postgres_encrypted_transport_events, 1);
}

#[test]
fn postgres_query_retains_error_until_ready_for_query() {
    let mut registry = registry();
    let request = postgres_frame(
        b'Q',
        b"INSERT INTO accounts VALUES (1); SELECT secret_value\0",
    );
    assert!(
        handle_at(
            &mut registry,
            &raw_event(5432, &request, request.len() as u32),
            5_000,
        )
        .is_empty()
    );

    let error = postgres_error(b"23505", b"secret constraint detail");
    assert!(
        handle_at(&mut registry, &response_event(5432, &error), 7_000).is_empty(),
        "ErrorResponse is not the simple-query cycle terminator"
    );

    let ready = postgres_frame(b'Z', b"E");
    let signals = handle_at(&mut registry, &response_event(5432, &ready), 9_000);

    assert_eq!(signals.len(), 1);
    let observation = observation(&signals[0]);
    assert_eq!(observation.method.as_deref(), Some("INSERT"));
    assert_eq!(observation.duration_nanos, Some(4_000));
    assert!(observation.attributes.iter().any(|attribute| {
        attribute.key == "db.response.status_code" && attribute.value == "23505"
    }));
    assert!(
        observation
            .attributes
            .iter()
            .any(|attribute| { attribute.key == "error.type" && attribute.value == "23505" })
    );
    assert!(observation.attributes.iter().any(|attribute| {
        attribute.key == "db.postgresql.transaction.status"
            && attribute.value == "failed_transaction"
    }));
    assert_eq!(registry.counters().matched_responses, 1);
    assert_eq!(registry.counters().orphan_responses, 0);
    let serialized = serde_json::to_string(&signals).expect("signals serialize");
    assert!(!serialized.contains("secret"));
    assert!(!serialized.contains("constraint"));
    assert!(!serialized.contains("accounts"));
}

#[test]
fn postgres_extended_pipeline_matches_each_protocol_terminal() {
    let mut registry = registry();
    let requests = [
        postgres_frame(b'P', b"\0SELECT secret_value\0\0\0"),
        postgres_frame(b'B', &[0; 8]),
        postgres_frame(b'D', b"S\0"),
        postgres_frame(b'E', &[0; 5]),
        postgres_frame(b'S', b""),
    ];
    for (index, request) in requests.iter().enumerate() {
        assert!(
            handle_at(
                &mut registry,
                &raw_event(5432, request, request.len() as u32),
                5_000 + index as u64,
            )
            .is_empty()
        );
    }
    let stream = registry
        .connections
        .values()
        .next()
        .expect("postgres connection is tracked");
    assert_eq!(stream.in_flight.len(), requests.len());
    assert!(
        stream
            .in_flight
            .front()
            .is_some_and(|entry| entry.postgres_request_response.is_some())
    );

    for (response, expected_method) in [
        (postgres_frame(b'1', b""), "SELECT"),
        (postgres_frame(b'2', b""), "BIND"),
    ] {
        let signals = handle_at(&mut registry, &response_event(5432, &response), 8_000);
        assert_eq!(signals.len(), 1, "counters: {:?}", registry.counters());
        assert_eq!(
            observation(&signals[0]).method.as_deref(),
            Some(expected_method)
        );
    }

    let parameter_description = postgres_frame(b't', &[0, 0]);
    assert!(
        handle_at(
            &mut registry,
            &response_event(5432, &parameter_description),
            8_000,
        )
        .is_empty()
    );
    let no_data = postgres_frame(b'n', b"");
    let signals = handle_at(&mut registry, &response_event(5432, &no_data), 8_000);
    assert_eq!(signals.len(), 1);
    assert_eq!(observation(&signals[0]).method.as_deref(), Some("DESCRIBE"));

    let command_complete = postgres_frame(b'C', b"SELECT 1\0");
    let signals = handle_at(
        &mut registry,
        &response_event(5432, &command_complete),
        8_000,
    );
    assert_eq!(signals.len(), 1);
    assert_eq!(observation(&signals[0]).method.as_deref(), Some("EXECUTE"));

    let ready = postgres_frame(b'Z', b"I");
    let signals = handle_at(&mut registry, &response_event(5432, &ready), 8_000);
    assert_eq!(signals.len(), 1);
    let observation = observation(&signals[0]);
    assert_eq!(observation.method.as_deref(), Some("SYNC"));
    assert!(observation.attributes.iter().any(|attribute| {
        attribute.key == "db.postgresql.transaction.status" && attribute.value == "idle"
    }));
    assert_eq!(registry.counters().matched_responses, 5);
    let serialized = serde_json::to_string(&signals).expect("signals serialize");
    assert!(!serialized.contains("secret_value"));
}

#[test]
fn postgres_extended_error_discards_pipeline_until_sync() {
    let mut registry = registry();
    let requests = [
        postgres_frame(b'P', b"\0SELECT secret_value\0\0\0"),
        postgres_frame(b'B', &[0; 8]),
        postgres_frame(b'E', &[0; 5]),
        postgres_frame(b'S', b""),
        postgres_frame(b'P', b"\0SELECT another_secret\0\0\0"),
    ];
    for (index, request) in requests.iter().enumerate() {
        assert!(
            handle_at(
                &mut registry,
                &raw_event(5432, request, request.len() as u32),
                5_000 + index as u64,
            )
            .is_empty()
        );
    }

    let error = postgres_error(b"23505", b"secret constraint detail");
    let signals = handle_at(&mut registry, &response_event(5432, &error), 8_000);
    assert_eq!(signals.len(), 3);
    let parse = observation(&signals[0]);
    assert_eq!(parse.method.as_deref(), Some("SELECT"));
    assert_eq!(parse.duration_nanos, Some(3_000));
    assert!(
        parse
            .attributes
            .iter()
            .any(|attribute| { attribute.key == "error.type" && attribute.value == "23505" })
    );
    for skipped in &signals[1..] {
        let skipped = observation(skipped);
        assert_eq!(skipped.duration_nanos, None);
        assert_eq!(skipped.confidence, TraceConfidence::Low);
    }
    assert_eq!(registry.counters().postgres_skipped_requests, 2);
    let ready = postgres_frame(b'Z', b"I");
    let signals = handle_at(&mut registry, &response_event(5432, &ready), 9_000);
    assert_eq!(signals.len(), 1);
    assert_eq!(observation(&signals[0]).method.as_deref(), Some("SYNC"));

    let parse_complete = postgres_frame(b'1', b"");
    let signals = handle_at(
        &mut registry,
        &response_event(5432, &parse_complete),
        11_000,
    );
    assert_eq!(signals.len(), 1);
    assert_eq!(observation(&signals[0]).method.as_deref(), Some("SELECT"));
    let serialized = serde_json::to_string(&signals).expect("signals serialize");
    assert!(!serialized.contains("secret"));
}

#[test]
fn postgres_copy_control_frames_do_not_displace_the_initiating_query() {
    let mut registry = registry();
    let query = postgres_frame(b'Q', b"COPY secret_table FROM STDIN\0");
    assert!(
        handle_at(
            &mut registry,
            &raw_event(5432, &query, query.len() as u32),
            5_000,
        )
        .is_empty()
    );

    let copy_in = postgres_frame(b'G', &[0, 0, 0]);
    assert!(handle_at(&mut registry, &response_event(5432, &copy_in), 6_000,).is_empty());
    for (request, method) in [
        (postgres_frame(b'd', b"secret-copy-row"), "COPY_DATA"),
        (postgres_frame(b'c', b""), "COPY_DONE"),
    ] {
        let signals = handle_at(
            &mut registry,
            &raw_event(5432, &request, request.len() as u32),
            7_000,
        );
        assert_eq!(signals.len(), 1);
        let observation = observation(&signals[0]);
        assert_eq!(observation.method.as_deref(), Some(method));
        assert_eq!(observation.duration_nanos, None);
        let serialized = serde_json::to_string(&signals).expect("signals serialize");
        assert!(!serialized.contains("secret-copy-row"));
    }
    assert_eq!(
        registry
            .connections
            .values()
            .next()
            .expect("postgres connection is tracked")
            .in_flight
            .len(),
        1
    );

    let command_complete = postgres_frame(b'C', b"COPY 1\0");
    assert!(
        handle_at(
            &mut registry,
            &response_event(5432, &command_complete),
            8_000,
        )
        .is_empty()
    );
    let ready = postgres_frame(b'Z', b"I");
    let signals = handle_at(&mut registry, &response_event(5432, &ready), 9_000);
    assert_eq!(signals.len(), 1);
    assert_eq!(observation(&signals[0]).method.as_deref(), Some("COPY"));
    assert_eq!(observation(&signals[0]).duration_nanos, Some(4_000));
    assert!(
        registry
            .connections
            .values()
            .next()
            .expect("postgres connection is tracked")
            .in_flight
            .is_empty()
    );
}

#[test]
fn postgres_copy_in_ignores_prequeued_and_in_mode_sync_without_displacing_query() {
    let mut registry = registry();
    let query = postgres_frame(b'Q', b"COPY secret_table FROM STDIN\0");
    let sync = postgres_frame(b'S', b"");
    for (timestamp, request) in [(5_000, &query), (5_100, &sync)] {
        assert!(
            handle_at(
                &mut registry,
                &raw_event(5432, request, request.len() as u32),
                timestamp,
            )
            .is_empty()
        );
    }
    assert_eq!(
        registry
            .connections
            .values()
            .next()
            .expect("postgres connection is tracked")
            .in_flight
            .len(),
        2
    );

    let copy_in = postgres_frame(b'G', &[0, 0, 0]);
    assert!(handle_at(&mut registry, &response_event(5432, &copy_in), 6_000).is_empty());
    assert_eq!(
        registry
            .connections
            .values()
            .next()
            .expect("postgres connection is tracked")
            .in_flight
            .len(),
        1
    );

    // Sync and Flush received during copy-in are protocol-defined no-ops.
    for request in [postgres_frame(b'S', b""), postgres_frame(b'H', b"")] {
        assert!(
            handle_at(
                &mut registry,
                &raw_event(5432, &request, request.len() as u32),
                6_500,
            )
            .is_empty()
        );
    }
    assert_eq!(registry.counters().postgres_copy_ignored_controls, 3);

    for request in [
        postgres_frame(b'd', b"secret-copy-row"),
        postgres_frame(b'c', b""),
    ] {
        let signals = handle_at(
            &mut registry,
            &raw_event(5432, &request, request.len() as u32),
            7_000,
        );
        assert_eq!(signals.len(), 1);
    }
    let command_complete = postgres_frame(b'C', b"COPY 1\0");
    assert!(
        handle_at(
            &mut registry,
            &response_event(5432, &command_complete),
            8_000,
        )
        .is_empty()
    );
    let ready = postgres_frame(b'Z', b"I");
    let signals = handle_at(&mut registry, &response_event(5432, &ready), 9_000);
    assert_eq!(signals.len(), 1);
    assert_eq!(observation(&signals[0]).method.as_deref(), Some("COPY"));
    assert!(
        registry
            .connections
            .values()
            .next()
            .expect("postgres connection is tracked")
            .in_flight
            .is_empty()
    );
}

#[test]
fn postgres_late_pipeline_requests_resume_immediately_after_sync_is_sent() {
    let mut registry = registry();
    let parse = postgres_frame(b'P', b"\0SELECT secret_value\0\0\0");
    assert!(
        handle_at(
            &mut registry,
            &raw_event(5432, &parse, parse.len() as u32),
            5_000,
        )
        .is_empty()
    );
    let error = postgres_error(b"23505", b"secret constraint detail");
    let signals = handle_at(&mut registry, &response_event(5432, &error), 6_000);
    assert_eq!(signals.len(), 1);

    let skipped_bind = postgres_frame(b'B', &[0; 8]);
    let signals = handle_at(
        &mut registry,
        &raw_event(5432, &skipped_bind, skipped_bind.len() as u32),
        7_000,
    );
    assert_eq!(signals.len(), 1);
    assert_eq!(observation(&signals[0]).method.as_deref(), Some("BIND"));
    assert_eq!(observation(&signals[0]).confidence, TraceConfidence::Low);
    assert_eq!(observation(&signals[0]).duration_nanos, None);

    let sync = postgres_frame(b'S', b"");
    assert!(
        handle_at(
            &mut registry,
            &raw_event(5432, &sync, sync.len() as u32),
            8_000,
        )
        .is_empty()
    );
    let next_parse = postgres_frame(b'P', b"\0SELECT another_secret\0\0\0");
    assert!(
        handle_at(
            &mut registry,
            &raw_event(5432, &next_parse, next_parse.len() as u32),
            9_000,
        )
        .is_empty(),
        "messages after the observed Sync belong to the next pipeline segment"
    );

    let ready = postgres_frame(b'Z', b"I");
    let signals = handle_at(&mut registry, &response_event(5432, &ready), 10_000);
    assert_eq!(signals.len(), 1);
    assert_eq!(observation(&signals[0]).method.as_deref(), Some("SYNC"));
    let parse_complete = postgres_frame(b'1', b"");
    let signals = handle_at(
        &mut registry,
        &response_event(5432, &parse_complete),
        11_000,
    );
    assert_eq!(signals.len(), 1);
    assert_eq!(observation(&signals[0]).method.as_deref(), Some("SELECT"));
    assert_eq!(registry.counters().postgres_skipped_requests, 1);
}

#[test]
fn mysql_result_set_completes_only_at_the_terminal_packet() {
    let mut registry = registry();
    let request = [7, 0, 0, 0, 3, b's', b'e', b'l', b'e', b'c', b't'];
    let event = raw_event(3306, &request, request.len() as u32);
    assert!(handle_at(&mut registry, &event, 5_000).is_empty());
    let column_definition = mysql_column_definition_packet(2);

    // One column, its definition, the metadata terminator, and one text
    // row are all continuations of the same command lifecycle.
    for packet in [
        &[1, 0, 0, 1, 1][..],
        column_definition.as_slice(),
        &[5, 0, 0, 3, 0xfe, 0, 0, 2, 0][..],
        &[2, 0, 0, 4, 1, b'x'][..],
    ] {
        assert!(
            handle_at(&mut registry, &response_event(3306, packet), 6_000).is_empty(),
            "intermediate result-set packet completed the request"
        );
    }

    let terminal = [5, 0, 0, 5, 0xfe, 0, 0, 2, 0];
    let signals = handle_at(&mut registry, &response_event(3306, &terminal), 9_000);

    assert_eq!(signals.len(), 1);
    let observation = observation(&signals[0]);
    assert_eq!(observation.protocol, ProtocolKind::Mysql);
    assert_eq!(observation.method.as_deref(), Some("SELECT"));
    assert_eq!(observation.duration_nanos, Some(4_000));
    assert!(observation.attributes.iter().any(|attribute| {
        attribute.key == "db.response.status_code" && attribute.value == "EOF"
    }));
    assert_eq!(registry.counters().response_continuations, 4);
    assert_eq!(registry.counters().orphan_responses, 0);
}

#[test]
fn mysql_zlib_handshake_activates_only_after_auth_ok_and_correlates_frames() {
    let mut registry = registry();
    let capabilities = (1 << 9) | (1 << 5);
    let greeting = mysql_server_greeting(capabilities);
    assert!(handle_at(&mut registry, &response_event(3306, &greeting), 1_000).is_empty());
    let handshake = mysql_client_handshake_response(1, capabilities);
    assert!(
        handle_at(
            &mut registry,
            &raw_event(3306, &handshake, handshake.len() as u32),
            2_000,
        )
        .is_empty()
    );
    let auth_ok = mysql_wire_packet(2, &[0, 0, 0, 2, 0, 0, 0]);
    assert!(handle_at(&mut registry, &response_event(3306, &auth_ok), 3_000).is_empty());

    let query = mysql_wire_packet(0, b"\x03SELECT secret FROM private_table");
    let request = mysql_compressed_packet(0, &query, true);
    assert!(
        handle_at(
            &mut registry,
            &raw_event(3306, &request, request.len() as u32),
            5_000,
        )
        .is_empty()
    );
    let ok = mysql_wire_packet(1, &[0, 0, 0, 2, 0, 0, 0]);
    let response = mysql_compressed_packet(1, &ok, false);
    let signals = handle_at(&mut registry, &response_event(3306, &response), 9_000);

    assert_eq!(signals.len(), 1);
    let observation = observation(&signals[0]);
    assert_eq!(observation.protocol, ProtocolKind::Mysql);
    assert_eq!(observation.method.as_deref(), Some("SELECT"));
    assert_eq!(observation.duration_nanos, Some(4_000));
    assert_eq!(registry.counters().mysql_server_greetings, 1);
    assert_eq!(registry.counters().mysql_client_handshakes, 1);
    assert_eq!(registry.counters().mysql_compression_zlib_connections, 1);
    assert_eq!(registry.counters().mysql_compressed_packets, 2);
    assert_eq!(registry.counters().mysql_compression_failures, 0);
    assert_eq!(registry.counters().orphan_responses, 0);
    assert_eq!(registry.counters().unparsed_frames, 0);
    let serialized = serde_json::to_string(&signals).expect("signals serialize");
    assert!(!serialized.contains("secret"));
    assert!(!serialized.contains("private_table"));
}

#[test]
fn mysql_zlib_auth_switch_split_packets_and_sequence_reset_remain_correlated() {
    let mut registry = registry();
    let capabilities = (1 << 9) | (1 << 5);
    let greeting = mysql_server_greeting(capabilities);
    assert!(handle(&mut registry, &response_event(3306, &greeting)).is_empty());
    let handshake = mysql_client_handshake_response(1, capabilities);
    assert!(
        handle(
            &mut registry,
            &raw_event(3306, &handshake, handshake.len() as u32),
        )
        .is_empty()
    );
    let auth_switch = mysql_wire_packet(2, b"\xfecaching_sha2_password\0salt\0");
    assert!(handle(&mut registry, &response_event(3306, &auth_switch)).is_empty());
    let auth_reply = mysql_wire_packet(3, b"private-auth-response");
    assert!(
        handle(
            &mut registry,
            &raw_event(3306, &auth_reply, auth_reply.len() as u32),
        )
        .is_empty()
    );
    let auth_ok = mysql_wire_packet(4, &[0, 0, 0, 2, 0, 0, 0]);
    assert!(handle(&mut registry, &response_event(3306, &auth_ok)).is_empty());

    let query = mysql_wire_packet(0, b"\x03SELECT secret FROM private_table");
    let split_at = 9;
    let first = mysql_compressed_packet(0, &query[..split_at], false);
    let second = mysql_compressed_packet(1, &query[split_at..], true);
    assert!(
        handle_at(
            &mut registry,
            &raw_event(3306, &first, first.len() as u32),
            5_000,
        )
        .is_empty()
    );
    assert!(
        handle_at(
            &mut registry,
            &raw_event(3306, &second, second.len() as u32),
            5_500,
        )
        .is_empty()
    );

    let resultset = [
        mysql_wire_packet(1, &[1]),
        mysql_column_definition_packet(2),
        mysql_wire_packet(3, &[0xfe, 0, 0, 2, 0]),
        mysql_wire_packet(4, &[1, b'x']),
        mysql_wire_packet(5, &[0xfe, 0, 0, 2, 0]),
    ]
    .concat();
    let response = mysql_compressed_packet(2, &resultset, true);
    let signals = handle_at(&mut registry, &response_event(3306, &response), 9_000);
    assert_eq!(signals.len(), 1);
    assert_eq!(observation(&signals[0]).method.as_deref(), Some("SELECT"));
    assert_eq!(observation(&signals[0]).duration_nanos, Some(4_000));

    let ping = mysql_wire_packet(0, &[0x0e]);
    let ping = mysql_compressed_packet(0, &ping, false);
    assert!(
        handle_at(
            &mut registry,
            &raw_event(3306, &ping, ping.len() as u32),
            10_000,
        )
        .is_empty()
    );
    let pong = mysql_wire_packet(1, &[0, 0, 0, 2, 0, 0, 0]);
    let pong = mysql_compressed_packet(1, &pong, false);
    let signals = handle_at(&mut registry, &response_event(3306, &pong), 11_000);
    assert_eq!(signals.len(), 1);
    assert_eq!(observation(&signals[0]).method.as_deref(), Some("PING"));
    assert_eq!(registry.counters().mysql_auth_packets, 3);
    assert_eq!(registry.counters().mysql_compressed_packets, 5);
    assert_eq!(registry.counters().mysql_compression_failures, 0);
    assert_eq!(registry.counters().mysql_handshake_failures, 0);
    let serialized = serde_json::to_string(&signals).expect("signals serialize");
    assert!(!serialized.contains("private"));
}

#[test]
fn mysql_compression_without_a_server_greeting_fails_closed() {
    let mut registry = registry();
    let capabilities = (1 << 9) | (1 << 5);
    let handshake = mysql_client_handshake_response(2, capabilities);
    assert!(
        handle(
            &mut registry,
            &raw_event(3306, &handshake, handshake.len() as u32),
        )
        .is_empty()
    );
    let auth_ok = mysql_wire_packet(3, &[0, 0, 0, 2, 0, 0, 0]);
    assert!(handle(&mut registry, &response_event(3306, &auth_ok)).is_empty());

    let ping = mysql_compressed_packet(0, &mysql_wire_packet(0, &[0x0e]), false);
    assert!(handle(&mut registry, &raw_event(3306, &ping, ping.len() as u32),).is_empty());
    let pong = mysql_compressed_packet(1, &mysql_wire_packet(1, &[0, 0, 0, 2, 0, 0, 0]), false);
    let signals = handle(&mut registry, &response_event(3306, &pong));
    assert!(signals.is_empty());
    assert_eq!(registry.counters().mysql_server_greetings, 0);
    assert_eq!(registry.counters().mysql_compression_zlib_connections, 0);
    assert_eq!(
        registry.counters().mysql_compression_unverified_rejections,
        1
    );
}

#[test]
fn mysql_compression_negotiation_falls_back_or_fails_closed_explicitly() {
    let mut fallback = registry();
    let protocol_41 = 1 << 9;
    let greeting = mysql_server_greeting(protocol_41);
    assert!(handle(&mut fallback, &response_event(3306, &greeting)).is_empty());
    let handshake = mysql_client_handshake_response(1, protocol_41 | (1 << 5));
    assert!(
        handle(
            &mut fallback,
            &raw_event(3306, &handshake, handshake.len() as u32),
        )
        .is_empty()
    );
    let auth_ok = mysql_wire_packet(2, &[0, 0, 0, 2, 0, 0, 0]);
    assert!(handle(&mut fallback, &response_event(3306, &auth_ok)).is_empty());
    let ping = mysql_wire_packet(0, &[0x0e]);
    assert!(handle(&mut fallback, &raw_event(3306, &ping, ping.len() as u32),).is_empty());
    let pong = mysql_wire_packet(1, &[0, 0, 0, 2, 0, 0, 0]);
    assert_eq!(handle(&mut fallback, &response_event(3306, &pong)).len(), 1);
    assert_eq!(fallback.counters().mysql_compression_zlib_connections, 0);

    let mut zstd = registry();
    let zstd_capabilities = protocol_41 | (1 << 26);
    let greeting = mysql_server_greeting(zstd_capabilities);
    assert!(handle(&mut zstd, &response_event(3306, &greeting)).is_empty());
    let handshake = mysql_client_handshake_response(1, zstd_capabilities);
    assert!(
        handle(
            &mut zstd,
            &raw_event(3306, &handshake, handshake.len() as u32),
        )
        .is_empty()
    );
    let auth_ok = mysql_wire_packet(2, &[0, 0, 0, 2, 0, 0, 0]);
    assert!(handle(&mut zstd, &response_event(3306, &auth_ok)).is_empty());
    assert_eq!(zstd.counters().mysql_compression_zstd_rejections, 1);
    let opaque = mysql_compressed_packet(0, &mysql_wire_packet(0, &[0x0e]), false);
    assert!(handle(&mut zstd, &raw_event(3306, &opaque, opaque.len() as u32),).is_empty());
    assert_eq!(zstd.counters().mysql_compression_opaque_events, 1);
    assert_eq!(zstd.counters().unparsed_frames, 0);
}

#[test]
fn mysql_compressed_sequence_mismatch_makes_transport_opaque() {
    let mut registry = registry();
    let capabilities = (1 << 9) | (1 << 5);
    let greeting = mysql_server_greeting(capabilities);
    assert!(handle(&mut registry, &response_event(3306, &greeting)).is_empty());
    let handshake = mysql_client_handshake_response(1, capabilities);
    assert!(
        handle(
            &mut registry,
            &raw_event(3306, &handshake, handshake.len() as u32),
        )
        .is_empty()
    );
    let auth_ok = mysql_wire_packet(2, &[0, 0, 0, 2, 0, 0, 0]);
    assert!(handle(&mut registry, &response_event(3306, &auth_ok)).is_empty());

    let wrong_sequence = mysql_compressed_packet(1, &mysql_wire_packet(0, &[0x0e]), false);
    assert!(
        handle(
            &mut registry,
            &raw_event(3306, &wrong_sequence, wrong_sequence.len() as u32),
        )
        .is_empty()
    );
    assert_eq!(registry.counters().mysql_compression_failures, 1);
    let valid = mysql_compressed_packet(0, &mysql_wire_packet(0, &[0x0e]), false);
    assert!(handle(&mut registry, &raw_event(3306, &valid, valid.len() as u32),).is_empty());
    assert_eq!(registry.counters().mysql_compression_opaque_events, 1);
    assert!(
        registry
            .connections
            .values()
            .next()
            .expect("mysql connection remains diagnosed")
            .in_flight
            .is_empty()
    );
}

#[test]
fn mysql_local_infile_upload_remains_owned_by_the_original_query() {
    let mut registry = registry();
    let request = mysql_wire_packet(
        0,
        b"\x03LOAD DATA LOCAL INFILE 'secret.csv' INTO TABLE private_table",
    );
    assert!(
        handle_at(
            &mut registry,
            &raw_event(3306, &request, request.len() as u32),
            5_000,
        )
        .is_empty()
    );

    let local_infile = mysql_wire_packet(1, b"\xfbsecret-server-path.csv");
    assert!(handle_at(&mut registry, &response_event(3306, &local_infile), 6_000,).is_empty());

    // Only a bounded prefix is captured from a 1024-byte file packet.
    // The lifecycle needs its header and sequence, never the file body.
    let mut large_prefix = vec![0, 4, 0, 2];
    large_prefix.extend_from_slice(b"secret-file-prefix");
    assert!(handle_at(&mut registry, &raw_event(3306, &large_prefix, 1_028), 7_000,).is_empty());
    let terminator = mysql_wire_packet(3, b"");
    assert!(
        handle_at(
            &mut registry,
            &raw_event(3306, &terminator, terminator.len() as u32),
            8_000,
        )
        .is_empty()
    );

    let ok = mysql_wire_packet(4, &[0, 0, 0, 2, 0, 0, 0]);
    let signals = handle_at(&mut registry, &response_event(3306, &ok), 10_000);
    assert_eq!(signals.len(), 1);
    let observation = observation(&signals[0]);
    assert_eq!(observation.method.as_deref(), Some("LOAD"));
    assert_eq!(observation.duration_nanos, Some(5_000));
    assert_eq!(registry.counters().mysql_local_infile_packets, 2);
    assert_eq!(registry.counters().mysql_local_infile_bytes, 1_024);
    assert_eq!(registry.counters().unparsed_frames, 0);
    assert!(
        registry
            .connections
            .values()
            .next()
            .expect("mysql connection is tracked")
            .in_flight
            .is_empty()
    );
    let serialized = serde_json::to_string(&signals).expect("signals serialize");
    for secret in [
        "secret.csv",
        "private_table",
        "secret-server-path",
        "secret-file-prefix",
    ] {
        assert!(!serialized.contains(secret));
    }
}

#[test]
fn mysql_large_logical_request_is_correlated_once_from_its_bounded_prefix() {
    let mut registry = registry();
    let declared_len = 0x00ff_ffff_u32 + 4;
    let first_prefix = [
        0xff, 0xff, 0xff, 0, 0x03, b'S', b'E', b'L', b'E', b'C', b'T', b' ', b's', b'e', b'c',
        b'r', b'e', b't',
    ];
    assert!(
        handle_at(
            &mut registry,
            &raw_event(3306, &first_prefix, declared_len),
            5_000,
        )
        .is_empty()
    );

    let final_packet = mysql_wire_packet(1, b"private-tail");
    assert!(
        handle_at(
            &mut registry,
            &raw_event(3306, &final_packet, final_packet.len() as u32),
            6_000,
        )
        .is_empty()
    );

    let ok = mysql_wire_packet(2, &[0, 0, 0, 2, 0, 0, 0]);
    let signals = handle_at(&mut registry, &response_event(3306, &ok), 9_000);
    assert_eq!(signals.len(), 1);
    let observation = observation(&signals[0]);
    assert_eq!(observation.method.as_deref(), Some("SELECT"));
    assert_eq!(observation.duration_nanos, Some(4_000));
    assert_eq!(registry.counters().mysql_logical_request_continuations, 1);
    assert_eq!(registry.counters().mysql_logical_sequence_failures, 0);
    assert_eq!(registry.counters().unmatched_overflow, 0);
    let serialized = serde_json::to_string(&signals).expect("signals serialize");
    assert!(!serialized.contains("secret"));
    assert!(!serialized.contains("private-tail"));
}

#[test]
fn mysql_large_result_row_does_not_complete_or_displace_the_query() {
    let mut registry = registry();
    let request = mysql_wire_packet(0, b"\x03SELECT secret FROM private_table");
    assert!(
        handle_at(
            &mut registry,
            &raw_event(3306, &request, request.len() as u32),
            5_000,
        )
        .is_empty()
    );
    for packet in [
        mysql_wire_packet(1, &[1]),
        mysql_column_definition_packet(2),
        mysql_wire_packet(3, &[0xfe, 0, 0, 2, 0]),
    ] {
        assert!(handle_at(&mut registry, &response_event(3306, &packet), 6_000).is_empty());
    }

    let declared_len = 0x00ff_ffff_u32 + 4;
    let row_prefix = [
        0xff, 0xff, 0xff, 4, 0x03, b's', b'e', b'c', b'r', b'e', b't',
    ];
    assert!(
        handle_at(
            &mut registry,
            &response_event_with_total(3306, &row_prefix, declared_len),
            7_000,
        )
        .is_empty()
    );
    let final_row_packet = mysql_wire_packet(5, b"private-tail");
    assert!(
        handle_at(
            &mut registry,
            &response_event(3306, &final_row_packet),
            8_000,
        )
        .is_empty()
    );

    let terminal = mysql_wire_packet(6, &[0xfe, 0, 0, 2, 0]);
    let signals = handle_at(&mut registry, &response_event(3306, &terminal), 9_000);
    assert_eq!(signals.len(), 1);
    assert_eq!(observation(&signals[0]).method.as_deref(), Some("SELECT"));
    assert_eq!(registry.counters().mysql_logical_response_continuations, 1);
    assert_eq!(registry.counters().mysql_logical_sequence_failures, 0);
    assert_eq!(registry.counters().unparsed_responses, 0);
    let serialized = serde_json::to_string(&signals).expect("signals serialize");
    assert!(!serialized.contains("secret"));
    assert!(!serialized.contains("private-tail"));
}

#[test]
fn mysql_result_set_accepts_deprecated_eof_ok_terminator() {
    let mut registry = registry();
    let request = [7, 0, 0, 0, 3, b's', b'e', b'l', b'e', b'c', b't'];
    assert!(
        handle_at(
            &mut registry,
            &raw_event(3306, &request, request.len() as u32),
            5_000,
        )
        .is_empty()
    );
    let column_definition = mysql_column_definition_packet(2);

    for packet in [
        &[1, 0, 0, 1, 1][..],
        column_definition.as_slice(),
        &[2, 0, 0, 3, 1, b'x'][..],
    ] {
        assert!(handle_at(&mut registry, &response_event(3306, packet), 6_000).is_empty());
    }

    // Header 0xfe with a nine-byte payload is an OK packet, not the
    // legacy short EOF packet. The two trailing bytes model bounded info.
    let terminal = [9, 0, 0, 4, 0xfe, 0, 0, 2, 0, 0, 0, 0, 0];
    let signals = handle_at(&mut registry, &response_event(3306, &terminal), 8_000);

    assert_eq!(signals.len(), 1);
    let observation = observation(&signals[0]);
    assert_eq!(observation.duration_nanos, Some(3_000));
    assert!(observation.attributes.iter().any(|attribute| {
        attribute.key == "db.response.status_code" && attribute.value == "OK"
    }));
}

#[test]
fn mysql_prepare_completes_after_parameter_and_column_metadata() {
    let mut registry = registry();
    let request = [
        9, 0, 0, 0, 0x16, b'S', b'E', b'L', b'E', b'C', b'T', b' ', b'?',
    ];
    assert!(
        handle_at(
            &mut registry,
            &raw_event(3306, &request, request.len() as u32),
            5_000,
        )
        .is_empty()
    );

    let prepare_ok = [12, 0, 0, 1, 0, 7, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0];
    let parameter_definition = mysql_column_definition_packet(2);
    let column_definition = mysql_column_definition_packet(4);
    for packet in [
        &prepare_ok[..],
        parameter_definition.as_slice(),
        &[5, 0, 0, 3, 0xfe, 0, 0, 2, 0][..],
        column_definition.as_slice(),
    ] {
        assert!(
            handle_at(&mut registry, &response_event(3306, packet), 6_000).is_empty(),
            "prepared statement completed before all metadata arrived"
        );
    }

    let terminal = [5, 0, 0, 5, 0xfe, 0, 0, 2, 0];
    let signals = handle_at(&mut registry, &response_event(3306, &terminal), 8_000);

    assert_eq!(signals.len(), 1);
    let observation = observation(&signals[0]);
    assert_eq!(observation.method.as_deref(), Some("SELECT"));
    assert_eq!(observation.duration_nanos, Some(3_000));
    assert_eq!(registry.counters().response_continuations, 4);
}

#[test]
fn mysql_statement_execute_does_not_treat_binary_row_as_ok() {
    let mut registry = registry();
    let request = [10, 0, 0, 0, 0x17, 7, 0, 0, 0, 0, 1, 0, 0, 0];
    assert!(
        handle_at(
            &mut registry,
            &raw_event(3306, &request, request.len() as u32),
            5_000,
        )
        .is_empty()
    );
    let column_definition = mysql_column_definition_packet(2);

    for packet in [
        &[1, 0, 0, 1, 1][..],
        column_definition.as_slice(),
        &[5, 0, 0, 3, 0xfe, 0, 0, 2, 0][..],
        &[8, 0, 0, 4, 0, 0, 6, b'f', b'o', b'o', b'b', b'a'][..],
    ] {
        assert!(
            handle_at(&mut registry, &response_event(3306, packet), 6_000).is_empty(),
            "binary row completed the prepared execution"
        );
    }

    let terminal = [5, 0, 0, 5, 0xfe, 0, 0, 2, 0];
    let signals = handle_at(&mut registry, &response_event(3306, &terminal), 8_000);

    assert_eq!(signals.len(), 1);
    let observation = observation(&signals[0]);
    assert_eq!(observation.method.as_deref(), Some("EXECUTE"));
    assert_eq!(observation.duration_nanos, Some(3_000));
}

#[test]
fn mysql_no_response_command_never_enters_the_correlation_queue() {
    let mut registry = registry();
    let request = [5, 0, 0, 0, 0x19, 7, 0, 0, 0];
    let signals = handle_at(
        &mut registry,
        &raw_event(3306, &request, request.len() as u32),
        5_000,
    );

    assert_eq!(signals.len(), 1);
    let observation = observation(&signals[0]);
    assert_eq!(observation.method.as_deref(), Some("CLOSE"));
    assert_eq!(observation.end_unix_nanos, None);
    assert_eq!(registry.counters().matched_responses, 0);

    let orphan = [7, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0];
    assert!(handle_at(&mut registry, &response_event(3306, &orphan), 6_000).is_empty());
    assert_eq!(registry.counters().orphan_responses, 1);
}

#[test]
fn mysql_statement_fetch_waits_for_terminal_packet_after_binary_rows() {
    let mut registry = registry();
    let request = [9, 0, 0, 0, 0x1c, 7, 0, 0, 0, 1, 0, 0, 0];
    assert!(
        handle_at(
            &mut registry,
            &raw_event(3306, &request, request.len() as u32),
            5_000,
        )
        .is_empty()
    );

    let row = [8, 0, 0, 1, 0, 0, 6, b'f', b'o', b'o', b'b', b'a'];
    assert!(
        handle_at(&mut registry, &response_event(3306, &row), 6_000).is_empty(),
        "binary fetch row completed the request"
    );

    let terminal = [5, 0, 0, 2, 0xfe, 0, 0, 2, 0];
    let signals = handle_at(&mut registry, &response_event(3306, &terminal), 8_000);

    assert_eq!(signals.len(), 1);
    let observation = observation(&signals[0]);
    assert_eq!(observation.method.as_deref(), Some("FETCH"));
    assert_eq!(observation.duration_nanos, Some(3_000));
}

#[test]
fn mysql_more_results_flag_keeps_the_command_in_flight() {
    let mut registry = registry();
    let request = [7, 0, 0, 0, 3, b's', b'e', b'l', b'e', b'c', b't'];
    assert!(
        handle_at(
            &mut registry,
            &raw_event(3306, &request, request.len() as u32),
            5_000,
        )
        .is_empty()
    );

    let more_results = [7, 0, 0, 1, 0, 0, 0, 0x0a, 0, 0, 0];
    assert!(handle_at(&mut registry, &response_event(3306, &more_results), 6_000,).is_empty());

    let terminal = [7, 0, 0, 2, 0, 0, 0, 2, 0, 0, 0];
    let signals = handle_at(&mut registry, &response_event(3306, &terminal), 8_000);
    assert_eq!(signals.len(), 1);
    assert_eq!(observation(&signals[0]).duration_nanos, Some(3_000));
    assert_eq!(registry.counters().response_continuations, 1);
}

#[test]
fn mysql_sequence_gap_is_non_destructive() {
    let mut registry = registry();
    let request = [1, 0, 0, 0, 0x0e];
    assert!(
        handle_at(
            &mut registry,
            &raw_event(3306, &request, request.len() as u32),
            5_000,
        )
        .is_empty()
    );

    let wrong_sequence = [7, 0, 0, 2, 0, 0, 0, 2, 0, 0, 0];
    assert!(handle_at(&mut registry, &response_event(3306, &wrong_sequence), 6_000,).is_empty());
    assert_eq!(registry.counters().unparsed_responses, 1);

    let terminal = [7, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0];
    let signals = handle_at(&mut registry, &response_event(3306, &terminal), 7_000);
    assert_eq!(signals.len(), 1);
    assert_eq!(observation(&signals[0]).method.as_deref(), Some("PING"));
    assert_eq!(observation(&signals[0]).duration_nanos, Some(2_000));
}

#[test]
fn nats_publish_produces_observation() {
    let mut registry = registry();
    let payload = b"PUB orders.created 5\r\nhello\r\n";
    let event = raw_event(4222, payload, payload.len() as u32);
    let signals = handle(&mut registry, &event);

    assert_eq!(signals.len(), 1);
    let observation = observation(&signals[0]);
    assert_eq!(observation.protocol, ProtocolKind::Nats);
    assert_eq!(observation.method.as_deref(), Some("pub"));
    let serialized = serde_json::to_string(&signals[0]).expect("signal serializes");
    assert!(!serialized.contains("orders.created"));
}

#[test]
fn pipelined_commands_match_pipelined_responses() {
    let mut registry = registry();
    let payload = b"*1\r\n$4\r\nPING\r\n*1\r\n$4\r\nPING\r\n";
    let event = raw_event(6379, payload, payload.len() as u32);
    assert!(handle_at(&mut registry, &event, 5_000).is_empty());

    let response = response_event(6379, b"+PONG\r\n+PONG\r\n");
    let signals = handle_at(&mut registry, &response, 5_400);

    assert_eq!(signals.len(), 2);
    for signal in &signals {
        assert_eq!(observation(signal).duration_nanos, Some(400));
    }
}

#[test]
fn in_flight_overflow_emits_unmatched_observation() {
    let mut registry = registry();
    let payload = b"*1\r\n$4\r\nPING\r\n";
    let mut emitted = Vec::new();
    for index in 0..(MAX_IN_FLIGHT_REQUESTS + 1) {
        let event = raw_event(6379, payload, payload.len() as u32);
        emitted.extend(handle_at(&mut registry, &event, 5_000 + index as u64));
    }

    assert_eq!(emitted.len(), 1);
    let observation = observation(&emitted[0]);
    assert_eq!(observation.end_unix_nanos, None);
    assert_eq!(observation.duration_nanos, None);
    assert_eq!(registry.counters().unmatched_overflow, 1);
}

#[test]
fn stale_in_flight_requests_expire_unmatched() {
    let mut registry = registry();
    let payload = b"*1\r\n$4\r\nPING\r\n";
    let event = raw_event(6379, payload, payload.len() as u32);
    assert!(handle_at(&mut registry, &event, 5_000).is_empty());

    let later = 5_000 + REQUEST_MATCH_TIMEOUT_NANOS + 1;
    let signals = handle_at(&mut registry, &event, later);

    assert_eq!(signals.len(), 1);
    assert_eq!(observation(&signals[0]).duration_nanos, None);
    assert_eq!(registry.counters().unmatched_expired, 1);
}
