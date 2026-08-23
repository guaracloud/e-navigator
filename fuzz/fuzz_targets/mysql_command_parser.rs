#![no_main]

use e_navigator_protocol::{
    ProtocolExtractionConfig,
    mysql::{
        MysqlResponseLifecycle, parse_mysql_command, parse_mysql_error_response,
        parse_mysql_response,
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

    let _ = parse_mysql_command(data, &config);
    let _ = parse_mysql_response(data, &config);
    let _ = parse_mysql_error_response(data, &config);

    if let Ok(mut lifecycle) = MysqlResponseLifecycle::from_request(data, &config) {
        let _ = lifecycle.observe_packet(data, &config);
    }

    let Some(selector) = data.first().copied() else {
        return;
    };
    let command = [0x03, 0x16, 0x17, 0x1c, 0x0e][usize::from(selector) % 5];
    let request = mysql_packet(0, &[command]);
    let Ok(mut lifecycle) = MysqlResponseLifecycle::from_request(&request, &config) else {
        return;
    };
    for (index, selector) in data.iter().copied().skip(1).take(255).enumerate() {
        let packet = mysql_packet((index + 1) as u8, &mysql_response_payload(selector));
        let _ = lifecycle.observe_packet(&packet, &config);
    }
});

fn mysql_packet(sequence: u8, payload: &[u8]) -> Vec<u8> {
    let mut packet = Vec::with_capacity(payload.len() + 4);
    packet.push((payload.len() & 0xff) as u8);
    packet.push(((payload.len() >> 8) & 0xff) as u8);
    packet.push(((payload.len() >> 16) & 0xff) as u8);
    packet.push(sequence);
    packet.extend_from_slice(payload);
    packet
}

fn mysql_response_payload(selector: u8) -> Vec<u8> {
    match selector % 8 {
        0 => vec![0x00, 0, 0, 2, 0, 0, 0],
        1 => vec![0xff, 0x28, 0x04],
        2 => vec![1],
        3 => mysql_column_definition(),
        4 => vec![0xfe, 0, 0, 2, 0],
        5 => vec![1, b'x'],
        6 => vec![0, 0],
        _ => vec![0x00, 7, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0],
    }
}

fn mysql_column_definition() -> Vec<u8> {
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
    payload
}
