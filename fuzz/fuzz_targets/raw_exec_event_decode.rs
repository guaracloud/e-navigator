#![no_main]

use e_navigator_sources_ebpf_aya::exec::fuzz_decode_raw_exec_event;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = fuzz_decode_raw_exec_event(data);
});
