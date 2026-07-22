#![no_main]

use e_navigator_protocol::grpc_web::{GrpcWebWireMode, parse_grpc_web_envelopes};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mode = if data.first().is_some_and(|byte| byte & 1 == 1) {
        GrpcWebWireMode::Text
    } else {
        GrpcWebWireMode::Binary
    };
    let require_status = data.get(1).is_some_and(|byte| byte & 1 == 1);
    let _ = parse_grpc_web_envelopes(data, mode, 64 * 1024, require_status);
});
