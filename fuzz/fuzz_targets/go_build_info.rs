#![no_main]

use e_navigator_sources_ebpf_aya::fuzz_parse_go_build_info;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = fuzz_parse_go_build_info(data);
});
