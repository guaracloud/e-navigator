use super::*;
use e_navigator_core::CapturePosture;
use std::collections::BTreeMap;

const CID: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const UID: &str = "1234abcd-5678-90ab-cdef-1234567890ab";

#[test]
fn control_word_encodes_posture() {
    let disabled = CaptureFilterConfig::default();
    assert_eq!(control_word(&disabled), CONTROL_DISABLED);

    let denylist = CaptureFilterConfig {
        enabled: true,
        unknown_cgroup: CapturePosture::Allow,
        ..Default::default()
    };
    assert_eq!(control_word(&denylist), CONTROL_UNKNOWN_CAPTURE);

    let allowlist = CaptureFilterConfig {
        enabled: true,
        unknown_cgroup: CapturePosture::Deny,
        ..Default::default()
    };
    assert_eq!(control_word(&allowlist), CONTROL_UNKNOWN_DROP);
}

#[test]
fn parse_raw_pods_extracts_bare_container_ids_unscoped() {
    let body = format!(
        r#"{{
            "items": [
                {{
                    "metadata": {{
                        "namespace": "payments",
                        "uid": "{UID}",
                        "labels": {{ "team": "payments", "tier": "prod" }}
                    }},
                    "status": {{
                        "containerStatuses": [
                            {{ "containerID": "containerd://{CID}" }},
                            {{ "containerID": null }}
                        ]
                    }}
                }},
                {{
                    "metadata": {{ "namespace": "kube-system", "uid": "no-containers" }}
                }}
            ]
        }}"#
    );
    let pods = parse_raw_pods(&body, 1024, 64).expect("valid pod list");
    assert_eq!(pods.len(), 2);

    let payments = &pods[0];
    assert_eq!(payments.namespace, "payments");
    assert_eq!(payments.pod_uid.as_deref(), Some(UID));
    assert_eq!(payments.container_ids, vec![CID.to_string()]);
    assert_eq!(
        payments.labels.get("team").map(String::as_str),
        Some("payments")
    );

    // Pod with no status/containers still parses (namespace-only exclusion).
    assert_eq!(pods[1].namespace, "kube-system");
    assert!(pods[1].container_ids.is_empty());
}

#[test]
fn parse_raw_pods_bounds_pods_and_labels() {
    let body = r#"{
        "items": [
            { "metadata": { "namespace": "a", "labels": { "x": "1", "y": "2", "z": "3" } } },
            { "metadata": { "namespace": "b" } }
        ]
    }"#;
    let pods = parse_raw_pods(body, 1, 2).expect("valid");
    assert_eq!(pods.len(), 1);
    assert!(pods[0].labels.len() <= 2);
}

#[test]
fn parse_raw_pods_rejects_malformed_json() {
    assert!(parse_raw_pods("not json", 16, 16).is_err());
}

#[test]
fn parse_raw_pods_tolerates_empty_list() {
    let pods = parse_raw_pods(r#"{"items":[]}"#, 16, 16).expect("valid");
    assert!(pods.is_empty());
}

#[test]
fn scan_cgroups_discovers_pod_and_container_tokens() {
    let root = std::env::temp_dir().join(format!("e-nav-cf-scan-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let uid_underscored = UID.replace('-', "_");
    let leaf = root
        .join("kubepods.slice")
        .join("kubepods-besteffort.slice")
        .join(format!("kubepods-besteffort-pod{uid_underscored}.slice"))
        .join(format!("cri-containerd-{CID}.scope"));
    std::fs::create_dir_all(&leaf).expect("fixture cgroup tree");
    // A host cgroup that must not resolve to any pod.
    std::fs::create_dir_all(root.join("system.slice").join("sshd.service")).expect("host cgroup");

    let observations = scan_cgroups_blocking(&root, &root.join("proc"));

    // The scan emits an observation per cgroup level; the container-scope leaf
    // carries both the pod UID and container id (both resolve to the same pod).
    let leaf = observations
        .iter()
        .find(|obs| obs.container_id.as_deref() == Some(CID))
        .expect("container cgroup discovered");
    assert_eq!(leaf.pod_uid.as_deref(), Some(UID));
    assert!(
        observations
            .iter()
            .all(|obs| obs.pod_uid.is_some() || obs.container_id.is_some()),
        "host-only cgroups must be excluded from observations"
    );

    std::fs::remove_dir_all(&root).expect("cleanup");
}

#[test]
fn has_unresolved_is_true_without_index_and_false_when_resolved() {
    let observation = CgroupObservation {
        cgroup_id: 1,
        container_id: Some(CID.to_string()),
        pod_uid: Some(UID.to_string()),
        process_names: Vec::new(),
    };
    // No index yet -> eager fetch warranted.
    assert!(has_unresolved(
        std::slice::from_ref(&observation),
        &RawNodePodIndex::default(),
        false
    ));

    let index = RawNodePodIndex::from_pods(
        vec![RawPod {
            namespace: "payments".to_string(),
            pod_uid: Some(UID.to_string()),
            container_ids: vec![CID.to_string()],
            labels: BTreeMap::new(),
        }],
        1024,
    );
    assert!(!has_unresolved(
        std::slice::from_ref(&observation),
        &index,
        true
    ));
}

#[test]
fn controller_publish_increments_generation() {
    let controller = CaptureFilterController::new(CONTROL_UNKNOWN_DROP);
    let (generation0, _) = controller.current();
    controller.publish(DesiredFilterMap::default());
    let (generation1, _) = controller.current();
    assert_ne!(generation0, generation1);
    assert_eq!(controller.control_word(), CONTROL_UNKNOWN_DROP);
}

#[test]
fn scan_cgroups_reads_bounded_process_names_from_host_procfs() {
    let fixture =
        std::env::temp_dir().join(format!("e-nav-cf-process-scan-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&fixture);
    let cgroup_root = fixture.join("cgroup");
    let procfs_root = fixture.join("proc");
    let leaf = cgroup_root.join(format!("cri-containerd-{CID}.scope"));
    std::fs::create_dir_all(&leaf).expect("fixture cgroup");
    std::fs::create_dir_all(procfs_root.join("123")).expect("fixture proc pid");
    std::fs::write(leaf.join("cgroup.procs"), "123\nnot-a-pid\n").expect("fixture cgroup.procs");
    std::fs::write(procfs_root.join("123").join("comm"), "postgres-exporter\n")
        .expect("fixture comm");

    let observations = scan_cgroups_blocking(&cgroup_root, &procfs_root);
    let container = observations
        .iter()
        .find(|observation| observation.container_id.as_deref() == Some(CID))
        .expect("container observation");

    assert_eq!(container.process_names, vec!["postgres-exporter"]);
    std::fs::remove_dir_all(&fixture).expect("cleanup");
}
