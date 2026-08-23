#![no_main]

use e_navigator_protocol::{
    ProtocolExtractionConfig,
    redis::{RedisResponseLifecycle, parse_redis_command, parse_redis_response},
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

    let _ = parse_redis_command(data, &config);
    let _ = parse_redis_response(data, &config);

    if let Ok(mut lifecycle) = RedisResponseLifecycle::from_request(data, &config) {
        let _ = lifecycle.observe_response(data, &config);
    }

    let Some(selector) = data.first().copied() else {
        return;
    };
    let request = redis_request(selector);
    let Ok(mut lifecycle) = RedisResponseLifecycle::from_request(request, &config) else {
        return;
    };
    for selector in data.iter().copied().skip(1) {
        let _ = lifecycle.observe_response(redis_response(selector), &config);
    }
});

fn redis_request(selector: u8) -> &'static [u8] {
    match selector % 5 {
        0 => b"*2\r\n$3\r\nGET\r\n$3\r\nkey\r\n",
        1 => b"*3\r\n$9\r\nSUBSCRIBE\r\n$1\r\na\r\n$1\r\nb\r\n",
        2 => b"*2\r\n$11\r\nUNSUBSCRIBE\r\n$1\r\na\r\n",
        3 => b"*1\r\n$11\r\nUNSUBSCRIBE\r\n",
        _ => b"*1\r\n$4\r\nPING\r\n",
    }
}

fn redis_response(selector: u8) -> &'static [u8] {
    match selector % 8 {
        0 => b"+OK\r\n",
        1 => b"-ERR secret\r\n",
        2 => b">2\r\n+invalidate\r\n$3\r\nkey\r\n",
        3 => b"|1\r\n+ttl\r\n:10\r\n",
        4 => b">3\r\n$9\r\nsubscribe\r\n$1\r\na\r\n:1\r\n",
        5 => b">3\r\n$11\r\nunsubscribe\r\n$1\r\na\r\n:0\r\n",
        6 => b">3\r\n$7\r\nmessage\r\n$1\r\na\r\n$6\r\nsecret\r\n",
        _ => b"*3\r\n$9\r\nsubscribe\r\n$1\r\na\r\n:1\r\n",
    }
}
