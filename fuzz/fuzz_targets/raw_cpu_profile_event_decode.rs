#![no_main]

use e_navigator_sources_ebpf_aya::cpu_profile::fuzz_decode_raw_cpu_profile_event;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = fuzz_decode_raw_cpu_profile_event(data);
});
