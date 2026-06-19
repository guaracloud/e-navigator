#![no_main]

use e_navigator_profiling::model::{NormalizationLimits, parse_profile_fixture};
use libfuzzer_sys::fuzz_target;

const MAX_INPUT_BYTES: usize = 4096;

fuzz_target!(|data: &[u8]| {
    let data = &data[..data.len().min(MAX_INPUT_BYTES)];
    let Ok(fixture) = std::str::from_utf8(data) else {
        return;
    };
    let limits = NormalizationLimits {
        max_fixture_bytes: MAX_INPUT_BYTES,
        max_frames_per_stack: 16,
        max_attributes: 8,
        max_symbol_bytes: 128,
        max_module_bytes: 128,
        max_file_bytes: 128,
        max_attribute_key_bytes: 64,
        max_attribute_value_bytes: 128,
        ..NormalizationLimits::default()
    };

    let _ = parse_profile_fixture(fixture, &limits);
});
