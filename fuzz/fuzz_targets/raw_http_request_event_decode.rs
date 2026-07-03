#![no_main]

use e_navigator_sources_ebpf_aya::http::fuzz_decode_raw_http_request_event;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = fuzz_decode_raw_http_request_event(data);
});
