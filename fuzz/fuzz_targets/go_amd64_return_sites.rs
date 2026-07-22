#![no_main]

use e_navigator_sources_ebpf_aya::fuzz_decode_go_amd64_returns;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = fuzz_decode_go_amd64_returns(data);
});
