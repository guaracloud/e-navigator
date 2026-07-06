#![no_main]

use e_navigator_profiling::unwind::{ElfUnwindTable, parse_load_segments};
use libfuzzer_sys::fuzz_target;

const MAX_INPUT_BYTES: usize = 1 << 16;

fuzz_target!(|data: &[u8]| {
    let data = &data[..data.len().min(MAX_INPUT_BYTES)];

    let table = ElfUnwindTable::parse(data);
    let _ = table.lookup(0);
    let probe = u64::from_le_bytes(
        <[u8; 8]>::try_from(&data[..data.len().min(8)]).unwrap_or([0; 8]),
    );
    let _ = table.lookup(probe);

    let _ = parse_load_segments(data);
});
