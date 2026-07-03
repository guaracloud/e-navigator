#![no_main]

use e_navigator_protocol::{
    ProtocolExtractionConfig,
    grpc::{parse_grpc_request_headers, parse_grpc_response_trailers},
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

    let _ = parse_grpc_request_headers(data, &config);
    let _ = parse_grpc_response_trailers(data, &config);
});
