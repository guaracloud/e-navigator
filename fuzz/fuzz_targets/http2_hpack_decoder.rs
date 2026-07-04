#![no_main]

use e_navigator_protocol::{
    ProtocolExtractionConfig,
    http2::{
        HTTP2_FLAG_END_HEADERS, HTTP2_FRAME_TYPE_HEADERS, HpackDecoder, Http2FrameHeader,
        parse_http2_frame_header, parse_http2_request_headers_frame,
        parse_http2_response_headers_frame,
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

    let _ = parse_http2_frame_header(data);

    let mut decoder = HpackDecoder::new();
    let _ = decoder.decode_header_block(data);
    // Feed a second block into the same decoder to exercise dynamic-table
    // and poisoning state.
    let _ = decoder.decode_header_block(data);

    let flags = data.first().copied().unwrap_or(HTTP2_FLAG_END_HEADERS);
    let header = Http2FrameHeader {
        length: data.len(),
        frame_type: HTTP2_FRAME_TYPE_HEADERS,
        flags,
        stream_id: 1,
    };
    let mut decoder = HpackDecoder::new();
    let _ = parse_http2_request_headers_frame(&mut decoder, &header, data, &config);
    let mut decoder = HpackDecoder::new();
    let _ = parse_http2_response_headers_frame(&mut decoder, &header, data, &config);
});
