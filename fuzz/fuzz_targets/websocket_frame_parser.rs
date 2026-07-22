#![no_main]

use e_navigator_protocol::websocket::{
    WebSocketDirection, is_websocket_upgrade_request, is_websocket_upgrade_response,
    parse_websocket_frame, websocket_frame_boundary,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let direction = if data.first().is_some_and(|byte| byte & 1 == 1) {
        WebSocketDirection::ClientToServer
    } else {
        WebSocketDirection::ServerToClient
    };
    let _ = websocket_frame_boundary(data, direction, 64 * 1024 * 1024);
    let _ = parse_websocket_frame(data, direction, 64 * 1024 * 1024, false);
    let _ = is_websocket_upgrade_request(data, 64 * 1024);
    let _ = is_websocket_upgrade_response(data, 64 * 1024);
});
