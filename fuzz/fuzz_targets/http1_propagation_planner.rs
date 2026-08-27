#![no_main]

use e_navigator_context_propagation::{
    MAX_TRACESTATE_BYTES, copy_tracestate, extract_traceparent, plan_http1_prefix_propagation,
    plan_http1_propagation, validate_tracestate,
};
use libfuzzer_sys::fuzz_target;

const MAX_INPUT_BYTES: usize = 2048;

fuzz_target!(|data: &[u8]| {
    let data = &data[..data.len().min(MAX_INPUT_BYTES)];
    let mut tracestate = [0_u8; MAX_TRACESTATE_BYTES];

    let _ = plan_http1_propagation(data);
    let _ = extract_traceparent(data);
    let _ = copy_tracestate(data, &mut tracestate);
    let _ = validate_tracestate(data);

    // Exercise both consistent bounded prefixes and deliberately inconsistent
    // total lengths. The planner must classify either shape without panicking.
    let midpoint = data.len() / 2;
    let prefix = &data[..midpoint];
    let _ = plan_http1_prefix_propagation(prefix, data.len());
    let _ = plan_http1_prefix_propagation(data, midpoint);
});
