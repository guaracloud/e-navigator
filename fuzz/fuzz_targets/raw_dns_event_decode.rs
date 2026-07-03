#![no_main]

use e_navigator_sources_ebpf_aya::dns::fuzz_decode_raw_dns_event;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = fuzz_decode_raw_dns_event(data);
});
