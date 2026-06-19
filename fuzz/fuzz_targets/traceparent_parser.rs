#![no_main]

use e_navigator_protocol::trace_context::parse_traceparent;
use libfuzzer_sys::fuzz_target;

const MAX_INPUT_BYTES: usize = 256;

fuzz_target!(|data: &[u8]| {
    let data = &data[..data.len().min(MAX_INPUT_BYTES)];
    let Ok(value) = std::str::from_utf8(data) else {
        return;
    };

    let _ = parse_traceparent(value);
});
