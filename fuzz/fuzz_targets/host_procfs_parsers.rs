#![no_main]

use e_navigator_sources_host::{
    parse_cpu_stat, parse_diskstats, parse_loadavg, parse_meminfo, parse_process_stat,
};
use libfuzzer_sys::fuzz_target;

const MAX_INPUT_BYTES: usize = 4096;

fuzz_target!(|data: &[u8]| {
    let data = &data[..data.len().min(MAX_INPUT_BYTES)];
    let contents = String::from_utf8_lossy(data);

    let _ = parse_cpu_stat(&contents, 100, 1_000, 2_000);
    let _ = parse_loadavg(&contents, 1_000, 2_000);
    let _ = parse_meminfo(&contents, 1_000, 2_000);
    let _ = parse_diskstats(&contents, 1_000, 2_000);
    let _ = parse_process_stat(1, &contents, Some(&contents), 100, 4096, 0, 0, 1_000, 2_000);
});
