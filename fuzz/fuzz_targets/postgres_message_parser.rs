#![no_main]

use e_navigator_protocol::{
    ProtocolExtractionConfig,
    postgres::{
        PostgresRequestLifecycle, PostgresSimpleQueryLifecycle, PostgresStartupLifecycle,
        parse_postgres_error_response, parse_postgres_message, parse_postgres_response,
        parse_postgres_startup_message,
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

    let _ = parse_postgres_message(data, &config);
    let _ = parse_postgres_response(data, &config);
    let _ = parse_postgres_error_response(data, &config);
    let _ = parse_postgres_startup_message(data, &config);

    if let Ok(mut lifecycle) = PostgresSimpleQueryLifecycle::from_request(data, &config) {
        let _ = lifecycle.observe_response(data, &config);
    }
    if let Ok(mut lifecycle) = PostgresRequestLifecycle::from_request(data, &config) {
        let _ = lifecycle.observe_response(data, &config);
    }
    if let Ok(mut lifecycle) = PostgresStartupLifecycle::from_request(data, &config) {
        let _ = lifecycle.observe_response(data, &config);
    }

    let Some(selector) = data.first().copied() else {
        return;
    };
    let request = postgres_request(selector);
    if let Ok(mut lifecycle) = PostgresSimpleQueryLifecycle::from_request(&request, &config) {
        for selector in data.iter().copied().skip(1) {
            let _ = lifecycle.observe_response(&postgres_response(selector), &config);
        }
    } else if let Ok(mut lifecycle) = PostgresRequestLifecycle::from_request(&request, &config) {
        for selector in data.iter().copied().skip(1) {
            let _ = lifecycle.observe_response(&postgres_response(selector), &config);
        }
    }
});

fn postgres_request(selector: u8) -> Vec<u8> {
    match selector % 10 {
        0 => postgres_frame(b'Q', b"SELECT 1\0"),
        1 => postgres_frame(b'P', b"\0SELECT 1\0\0\0"),
        2 => postgres_frame(b'B', &[0; 8]),
        3 => postgres_frame(b'D', b"S\0"),
        4 => postgres_frame(b'D', b"P\0"),
        5 => postgres_frame(b'C', b"P\0"),
        6 => postgres_frame(b'E', &[0; 5]),
        7 => postgres_frame(b'F', &[0; 10]),
        8 => postgres_frame(b'p', b"secret\0"),
        _ => postgres_frame(b'S', b""),
    }
}

fn postgres_response(selector: u8) -> Vec<u8> {
    match selector % 13 {
        0 => postgres_frame(b'1', b""),
        1 => postgres_frame(b'2', b""),
        2 => postgres_frame(b'3', b""),
        3 => postgres_frame(b't', &[0, 0]),
        4 => postgres_frame(b'T', &[0, 0]),
        5 => postgres_frame(b'n', b""),
        6 => postgres_frame(b'C', b"SELECT 1\0"),
        7 => postgres_error(),
        8 => postgres_frame(b'Z', b"I"),
        9 => postgres_frame(b'R', &[0, 0, 0, 0]),
        10 => postgres_frame(b'V', &(-1_i32).to_be_bytes()),
        11 => postgres_frame(b'D', &[0, 0]),
        _ => postgres_frame(b's', b""),
    }
}

fn postgres_error() -> Vec<u8> {
    postgres_frame(b'E', b"SERROR\0C23505\0Msecret\0\0")
}

fn postgres_frame(message_type: u8, body: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(body.len() + 5);
    frame.push(message_type);
    frame.extend_from_slice(&((body.len() + 4) as u32).to_be_bytes());
    frame.extend_from_slice(body);
    frame
}
