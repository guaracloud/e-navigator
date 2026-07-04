#![no_main]

use e_navigator_protocol::stream::{
    RequestStreamDecoder, StreamDecodeLimits, StreamProtocol, request_frame_boundary,
};
use libfuzzer_sys::fuzz_target;

const MAX_INPUT_BYTES: usize = 2048;

const PROTOCOLS: [StreamProtocol; 6] = [
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
        let _ = request_frame_boundary(protocol, data, limits.max_frame_bytes);

        let mut decoder = RequestStreamDecoder::new(protocol, limits);
        let mut frames = Vec::new();
        // Feed the same input as several chunk shapes: contiguous, split,
        // and with an uncaptured tail beyond the captured length.
        decoder.push_chunk(data, data.len() as u64, &mut frames);
        let midpoint = data.len() / 2;
        decoder.push_chunk(&data[..midpoint], data.len() as u64, &mut frames);
        decoder.push_chunk(&data[midpoint..], data.len() as u64, &mut frames);
    }
});
