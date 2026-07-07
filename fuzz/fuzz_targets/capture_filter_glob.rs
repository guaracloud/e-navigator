#![no_main]

use e_navigator_core::glob_match;
use libfuzzer_sys::fuzz_target;

const MAX_INPUT_BYTES: usize = 512;

// The glob matcher runs bytewise over untrusted namespace strings; it must
// never panic, loop unboundedly, or misbehave on arbitrary bytes. Split the
// input into a pattern and a value at the first NUL (or midpoint) and match.
fuzz_target!(|data: &[u8]| {
    let data = &data[..data.len().min(MAX_INPUT_BYTES)];
    let split = data.iter().position(|&byte| byte == 0).unwrap_or(data.len() / 2);
    let (pattern, value) = data.split_at(split.min(data.len()));
    let pattern = String::from_utf8_lossy(pattern);
    let value = String::from_utf8_lossy(value.strip_prefix(&[0]).unwrap_or(value));

    let _ = glob_match(&pattern, &value);
    // A pattern of all wildcards must always match; a sanity invariant that
    // would fail loudly if the matcher regressed into rejecting everything.
    if !pattern.is_empty() && pattern.bytes().all(|byte| byte == b'*') {
        assert!(glob_match(&pattern, &value));
    }
});
