#![no_main]

use e_navigator_signals::SignalEnvelope;
use libfuzzer_sys::fuzz_target;

const MAX_INPUT_BYTES: usize = 64 * 1024;

fuzz_target!(|data: &[u8]| {
    let data = &data[..data.len().min(MAX_INPUT_BYTES)];
    let Ok(signal) = serde_json::from_slice::<SignalEnvelope>(data) else {
        return;
    };
    let encoded = match serde_json::to_vec(&signal) {
        Ok(encoded) => encoded,
        Err(error) => panic!("deserialized signal envelope must serialize: {error}"),
    };
    let Ok(round_trip) = serde_json::from_slice::<SignalEnvelope>(&encoded) else {
        panic!("serialized signal envelope must deserialize");
    };

    assert_eq!(round_trip, signal);
});
