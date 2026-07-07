#![no_main]

use e_navigator_core::capture_filter::{
    parse_container_id_from_cgroup_path, parse_pod_uid_from_cgroup_path,
};
use libfuzzer_sys::fuzz_target;

const MAX_INPUT_BYTES: usize = 1024;

// Both cgroup-path parsers run over untrusted, arbitrarily-structured paths
// (cross-runtime, cross-driver, possibly hostile). They must never panic and
// must respect their documented output invariants.
fuzz_target!(|data: &[u8]| {
    let data = &data[..data.len().min(MAX_INPUT_BYTES)];
    let path = String::from_utf8_lossy(data);

    if let Some(container_id) = parse_container_id_from_cgroup_path(&path) {
        assert_eq!(container_id.len(), 64);
        assert!(container_id.bytes().all(|byte| byte.is_ascii_hexdigit()));
    }

    if let Some(pod_uid) = parse_pod_uid_from_cgroup_path(&path) {
        assert!((8..=64).contains(&pod_uid.len()));
        assert!(pod_uid.bytes().all(|byte| byte.is_ascii_hexdigit() || byte == b'-'));
    }
});
