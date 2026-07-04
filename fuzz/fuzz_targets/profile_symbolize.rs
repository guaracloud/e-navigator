#![no_main]

use e_navigator_profiling::symbolize::{ElfSymbolTable, ProcessModuleMap};
use libfuzzer_sys::fuzz_target;

const MAX_INPUT_BYTES: usize = 4096;

fuzz_target!(|data: &[u8]| {
    let data = &data[..data.len().min(MAX_INPUT_BYTES)];

    // Treat the input as ELF image bytes.
    let table = ElfSymbolTable::parse(data);
    let _ = table.resolve(0);
    let _ = table.resolve(u64::from_le_bytes(
        <[u8; 8]>::try_from(&data[..data.len().min(8)])
            .unwrap_or([0; 8]),
    ));

    // And, separately, as /proc/<pid>/maps text.
    if let Ok(text) = std::str::from_utf8(data) {
        let map = ProcessModuleMap::parse_maps(text);
        for mapping in map.mappings() {
            let _ = map.resolve(mapping.start);
            let _ = map.resolve(mapping.end);
        }
        let _ = map.resolve(0);
    }
});
