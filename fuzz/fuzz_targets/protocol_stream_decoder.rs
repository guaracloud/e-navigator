#![no_main]

use e_navigator_protocol::stream::{
    ProtocolStreamDecoder, StreamDecodeLimits, StreamDirection, StreamProtocol, frame_boundary,
};
use libfuzzer_sys::fuzz_target;

const MAX_INPUT_BYTES: usize = 2048;

const PROTOCOLS: [StreamProtocol; 8] = [
    StreamProtocol::Http1,
    StreamProtocol::Http2,
    StreamProtocol::Kafka,
    StreamProtocol::Mongodb,
    StreamProtocol::Mysql,
    StreamProtocol::Nats,
    StreamProtocol::Postgresql,
    StreamProtocol::Redis,
];

fuzz_target!(|data: &[u8]| {
    let data = &data[..data.len().min(MAX_INPUT_BYTES)];
    let limits = StreamDecodeLimits {
        max_buffered_bytes: 512,
        max_frame_bytes: 1024,
        max_frames_per_chunk: 16,
    };

    for protocol in PROTOCOLS {
        for direction in [StreamDirection::Request, StreamDirection::Response] {
            let _ = frame_boundary(protocol, direction, data, limits.max_frame_bytes);
        }

        let mut decoder = ProtocolStreamDecoder::new(protocol, StreamDirection::Request, limits);
        let mut response_decoder =
            ProtocolStreamDecoder::new(protocol, StreamDirection::Response, limits);
        let mut frames = Vec::new();
        response_decoder.push_chunk(data, data.len() as u64, &mut frames);
        // Feed the same input as several chunk shapes: contiguous, split,
        // and with an uncaptured tail beyond the captured length.
        decoder.push_chunk(data, data.len() as u64, &mut frames);
        let midpoint = data.len() / 2;
        decoder.push_chunk(&data[..midpoint], data.len() as u64, &mut frames);
        decoder.push_chunk(&data[midpoint..], data.len() as u64, &mut frames);
    }
});
