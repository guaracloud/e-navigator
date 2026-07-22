use super::*;
use e_navigator_core::CapturePosture;
use proptest::prelude::*;
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
fn cgroup_hierarchy_probe_distinguishes_v2_v1_hybrid_and_unavailable() {
    let fixture = std::env::temp_dir().join(format!(
        "e-nav-cgroup-mode-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos())
    ));
    let unified = fixture.join("unified");
    let legacy = fixture.join("legacy");
    let hybrid = fixture.join("hybrid");
    std::fs::create_dir_all(&unified).expect("unified fixture");
    std::fs::write(unified.join("cgroup.controllers"), "cpu memory\n").expect("v2 marker");
    assert_eq!(
        detect_cgroup_hierarchy(&unified),
        CgroupHierarchyMode::UnifiedV2
    );

    let legacy_cpu = legacy.join("cpu");
    std::fs::create_dir_all(&legacy_cpu).expect("legacy fixture");
    std::fs::write(legacy_cpu.join("tasks"), "").expect("v1 marker");
    assert_eq!(
        detect_cgroup_hierarchy(&legacy),
        CgroupHierarchyMode::LegacyV1
    );

    let hybrid_cpu = hybrid.join("cpu");
    std::fs::create_dir_all(&hybrid_cpu).expect("hybrid fixture");
    std::fs::write(hybrid.join("cgroup.controllers"), "memory\n").expect("v2 marker");
    std::fs::write(hybrid_cpu.join("tasks"), "").expect("v1 marker");
    assert_eq!(
        detect_cgroup_hierarchy(&hybrid),
        CgroupHierarchyMode::Hybrid
    );
    assert_eq!(
        detect_cgroup_hierarchy(&fixture.join("missing")),
        CgroupHierarchyMode::Unavailable
    );

    let bounded = fixture.join("bounded");
    std::fs::create_dir_all(&bounded).expect("bounded fixture");
    std::fs::write(bounded.join("cgroup.controllers"), "cpu memory\n").expect("bounded v2 marker");
    for index in 0..MAX_CGROUP_HIERARCHY_CHILDREN {
        std::fs::create_dir(bounded.join(format!("child-{index}"))).expect("bounded child");
    }
    assert_eq!(
        detect_cgroup_hierarchy(&bounded),
        CgroupHierarchyMode::Unavailable,
        "an oversized startup probe must fail closed instead of classifying a partial tree"
    );

    std::fs::remove_dir_all(&fixture).expect("cleanup hierarchy fixtures");
}

#[test]
fn unsupported_cgroup_hierarchies_override_allow_to_fail_closed() {
    let config = CaptureFilterConfig {
        enabled: true,
        unknown_cgroup: CapturePosture::Allow,
        ..Default::default()
    };
    for mode in [
        CgroupHierarchyMode::LegacyV1,
        CgroupHierarchyMode::Hybrid,
        CgroupHierarchyMode::Unavailable,
    ] {
        assert_eq!(
            effective_control_word(&config, mode),
            (CONTROL_UNKNOWN_DROP, true)
        );
    }
    assert_eq!(
        effective_control_word(&config, CgroupHierarchyMode::UnifiedV2),
        (CONTROL_UNKNOWN_CAPTURE, false)
    );

    let controller = CaptureFilterController::new(
        CONTROL_UNKNOWN_DROP,
        CgroupHierarchyMode::LegacyV1,
        true,
        CgroupDiscoveryMode::EventDriven,
    );
    let telemetry = controller.telemetry();
    assert_eq!(
        telemetry.cgroup_hierarchy_mode,
        CgroupHierarchyMode::LegacyV1
    );
    assert_eq!(telemetry.capture_filter_fail_closed_total, 1);
}

#[test]
fn parse_raw_pods_extracts_bare_container_ids_unscoped() {
    let body = format!(
        r#"{{
            "items": [
                {{
                    "metadata": {{
                        "namespace": "payments",
                        "name": "payments-api-abc",
                        "uid": "{UID}",
                        "labels": {{ "team": "payments", "tier": "prod" }}
                    }},
                    "spec": {{ "nodeName": "node-a" }},
                    "status": {{
                        "podIP": "10.42.0.10",
                        "containerStatuses": [
                            {{ "name": "api", "containerID": "containerd://{CID}" }},
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
    assert_eq!(payments.pod_name, "payments-api-abc");
    assert_eq!(payments.node_name.as_deref(), Some("node-a"));
    assert_eq!(payments.pod_ip.as_deref(), Some("10.42.0.10"));
    assert_eq!(payments.container_ids, vec![CID.to_string()]);
    assert_eq!(
        payments.container_names.get(CID).map(String::as_str),
        Some("api")
    );
    assert_eq!(
        payments.labels.get("team").map(String::as_str),
        Some("payments")
    );

    // Pod with no status/containers still parses (namespace-only exclusion).
    assert_eq!(pods[1].namespace, "kube-system");
    assert!(pods[1].container_ids.is_empty());
}

#[test]
fn cluster_wide_snapshot_prioritizes_local_pods_and_derives_deployment_owner() {
    let body = r#"{
        "metadata": {"resourceVersion": "91"},
        "items": [
            {
                "metadata": {"namespace": "a", "name": "remote", "uid": "remote"},
                "spec": {"nodeName": "node-b"}
            },
            {
                "metadata": {
                    "namespace": "z",
                    "name": "api-7d9f8d6c5b-abcd",
                    "uid": "local",
                    "labels": {"pod-template-hash": "7d9f8d6c5b"},
                    "ownerReferences": [{
                        "kind": "ReplicaSet",
                        "name": "api-7d9f8d6c5b",
                        "controller": true
                    }]
                },
                "spec": {"nodeName": "node-a"}
            }
        ]
    }"#;

    let snapshot = in_cluster::parse_raw_pod_snapshot_for_node(body, 1, 64, Some("node-a"))
        .expect("cluster snapshot");

    assert_eq!(snapshot.pods.len(), 1);
    assert_eq!(snapshot.pods[0].pod_uid.as_deref(), Some("local"));
    assert_eq!(snapshot.pods[0].workload_name.as_deref(), Some("api"));
    assert_eq!(
        snapshot.pods[0].workload_type.as_deref(),
        Some("deployment")
    );
}

#[test]
fn parses_service_cluster_ips_and_ready_endpoint_slice_addresses() {
    let services = in_cluster::parse_raw_services(
        r#"{"items":[{"metadata":{"namespace":"proj","name":"redis","uid":"svc-1"},"spec":{"clusterIP":"10.43.0.9","clusterIPs":["10.43.0.9"]}}]}"#,
        16,
    )
    .expect("service list");
    assert_eq!(services.len(), 1);
    assert_eq!(services[0].cluster_ips, vec!["10.43.0.9"]);

    let slices = in_cluster::parse_raw_endpoint_slices(
        r#"{"items":[{"metadata":{"namespace":"proj","labels":{"kubernetes.io/service-name":"redis"}},"endpoints":[{"addresses":["10.42.1.20"],"conditions":{"ready":true}},{"addresses":["10.42.1.21"],"conditions":{"ready":false}}]}]}"#,
        16,
    )
    .expect("endpoint slices");
    assert_eq!(slices.len(), 1);
    assert_eq!(slices[0].addresses, vec!["10.42.1.20"]);

    let nullable = in_cluster::parse_raw_endpoint_slices(
        r#"{"items":[{"metadata":{"namespace":"proj","labels":{"kubernetes.io/service-name":"empty"}},"endpoints":null},{"metadata":{"namespace":"proj","labels":{"kubernetes.io/service-name":"nullable-address"}},"endpoints":[{"addresses":null,"conditions":{"ready":true}}]}]}"#,
        16,
    )
    .expect("nullable endpoint slice lists");
    assert_eq!(nullable.len(), 2);
    assert!(nullable.iter().all(|slice| slice.addresses.is_empty()));
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
fn pod_snapshot_preserves_list_resource_version() {
    let snapshot = parse_raw_pod_snapshot(
        r#"{
          "metadata": {"resourceVersion": "41"},
          "items": []
        }"#,
        16,
        16,
    )
    .expect("valid snapshot");

    assert_eq!(snapshot.resource_version, "41");
    assert!(snapshot.pods.is_empty());
}

#[test]
fn watch_events_reconcile_add_bookmark_and_delete() {
    let mut pods = BTreeMap::new();
    let mut resource_version = "41".to_string();
    let added = format!(
        r#"{{
          "type": "ADDED",
          "object": {{
            "metadata": {{
              "namespace": "proj-payments",
              "name": "payments-api",
              "uid": "{UID}",
              "resourceVersion": "42",
              "labels": {{"guara.cloud/tier": "pro"}}
            }},
            "spec": {{"nodeName": "node-a"}},
            "status": {{
              "podIP": "10.42.0.10",
              "containerStatuses": [{{
                "name": "api",
                "containerID": "containerd://{CID}"
              }}]
            }}
          }}
        }}"#
    );
    apply_watch_line(added.as_bytes(), &mut pods, &mut resource_version, 16, 16)
        .expect("add event");
    assert_eq!(resource_version, "42");
    assert_eq!(
        pods.get(UID).and_then(|pod| pod.pod_ip.as_deref()),
        Some("10.42.0.10")
    );

    apply_watch_line(
        br#"{"type":"BOOKMARK","object":{"metadata":{"resourceVersion":"43"}}}"#,
        &mut pods,
        &mut resource_version,
        16,
        16,
    )
    .expect("bookmark");
    assert_eq!(resource_version, "43");

    let deleted = format!(
        r#"{{"type":"DELETED","object":{{"metadata":{{"namespace":"proj-payments","name":"payments-api","uid":"{UID}","resourceVersion":"44"}}}}}}"#
    );
    apply_watch_line(deleted.as_bytes(), &mut pods, &mut resource_version, 16, 16)
        .expect("delete event");
    assert_eq!(resource_version, "44");
    assert!(pods.is_empty());
}

#[test]
fn watch_expiration_requests_a_relist() {
    let mut pods = BTreeMap::new();
    let mut resource_version = "41".to_string();
    let err = apply_watch_line(
        br#"{"type":"ERROR","object":{"code":410,"reason":"Expired","message":"too old"}}"#,
        &mut pods,
        &mut resource_version,
        16,
        16,
    )
    .expect_err("expired watch fails");

    assert_eq!(err, PodWatchError::ExpiredResourceVersion);
}

#[test]
fn complete_watch_event_is_published_without_waiting_for_watch_end() {
    use std::sync::Mutex;

    let published = Arc::new(Mutex::new(Vec::new()));
    let captured = Arc::clone(&published);
    let publisher: RawPodPublisher = Arc::new(move |snapshot| {
        captured
            .lock()
            .expect("publication lock")
            .push(snapshot.clone());
    });
    let mut pods = BTreeMap::new();
    let mut resource_version = "41".to_string();
    let added = format!(
        r#"{{"type":"ADDED","object":{{"metadata":{{"namespace":"proj-payments","name":"payments-api","uid":"{UID}","resourceVersion":"42"}}}}}}"#
    );

    in_cluster::apply_and_publish_watch_line(
        added.as_bytes(),
        &mut pods,
        &mut resource_version,
        16,
        16,
        in_cluster::WatchResources {
            preferred_node: None,
            services: &[],
            endpoint_slices: &[],
        },
        &publisher,
    )
    .expect("event publication");

    let published = published.lock().expect("publication lock");
    assert_eq!(published.len(), 1);
    assert_eq!(published[0].resource_version, "42");
    assert_eq!(published[0].pods[0].pod_uid.as_deref(), Some(UID));
}

#[test]
fn local_watch_addition_evicts_remote_pod_when_cluster_bound_is_full() {
    let remote = parse_raw_pods(
        r#"{"items":[{"metadata":{"namespace":"proj","name":"remote","uid":"remote"},"spec":{"nodeName":"node-b"}}]}"#,
        1,
        16,
    )
    .expect("remote pod")
    .pop()
    .expect("one remote pod");
    let mut pods = BTreeMap::from([("remote".to_string(), remote)]);
    let mut resource_version = "41".to_string();
    let publisher: RawPodPublisher = Arc::new(|_| {});
    let local = br#"{"type":"ADDED","object":{"metadata":{"namespace":"proj","name":"local","uid":"local","resourceVersion":"42"},"spec":{"nodeName":"node-a"}}}"#;

    in_cluster::apply_and_publish_watch_line(
        local,
        &mut pods,
        &mut resource_version,
        1,
        16,
        in_cluster::WatchResources {
            preferred_node: Some("node-a"),
            services: &[],
            endpoint_slices: &[],
        },
        &publisher,
    )
    .expect("local add");

    assert_eq!(pods.len(), 1);
    assert!(pods.contains_key("local"));
    assert!(!pods.contains_key("remote"));
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

    let observations = scan_cgroups_blocking(&root, &root.join("proc"), false);

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
fn controller_publish_increments_only_for_changed_desired_state() {
    let controller = CaptureFilterController::new(
        CONTROL_UNKNOWN_DROP,
        CgroupHierarchyMode::UnifiedV2,
        false,
        CgroupDiscoveryMode::EventDriven,
    );
    let (generation0, _, _) = controller.current();

    assert!(!controller.publish(DesiredFilterMap::default(), Instant::now()));
    assert_eq!(controller.current().0, generation0);

    let policy = CaptureFilterPolicy::from_config(&CaptureFilterConfig {
        enabled: true,
        default_posture: CapturePosture::Allow,
        ..Default::default()
    });
    let index = RawNodePodIndex::from_pods(
        [RawPod {
            namespace: "proj".to_string(),
            pod_name: "api".to_string(),
            pod_uid: Some(UID.to_string()),
            node_name: Some("node-a".to_string()),
            pod_ip: None,
            workload_name: Some("api".to_string()),
            workload_type: Some("deployment".to_string()),
            container_ids: vec![CID.to_string()],
            container_names: BTreeMap::new(),
            labels: BTreeMap::new(),
        }],
        1,
    );
    let desired = build_desired_filter_map(
        &[CgroupObservation::from_cgroup_path(
            41,
            &format!(
                "/kubepods-pod{}.slice/cri-containerd-{CID}.scope",
                UID.replace('-', "_")
            ),
        )],
        &index,
        &policy,
        1,
    );

    assert!(controller.publish(desired.clone(), Instant::now()));
    let (generation1, _, _) = controller.current();
    assert_ne!(generation0, generation1);
    assert!(!controller.publish(desired, Instant::now()));
    assert_eq!(controller.current().0, generation1);
    assert_eq!(controller.control_word(), CONTROL_UNKNOWN_DROP);
}

#[test]
fn controller_publishes_raw_pods_for_shared_attribution() {
    let controller = CaptureFilterController::new(
        CONTROL_UNKNOWN_DROP,
        CgroupHierarchyMode::UnifiedV2,
        false,
        CgroupDiscoveryMode::EventDriven,
    );
    controller.mark_resource_relist_success();
    controller.publish_snapshot(RawPodSnapshot {
        resource_version: "1".to_string(),
        pods: vec![RawPod {
            namespace: "proj-payments".to_string(),
            pod_name: "payments-api".to_string(),
            pod_uid: Some(UID.to_string()),
            node_name: Some("node-a".to_string()),
            pod_ip: Some("10.42.0.10".to_string()),
            workload_name: Some("payments-api".to_string()),
            workload_type: Some("deployment".to_string()),
            container_ids: vec![CID.to_string()],
            container_names: BTreeMap::from([(CID.to_string(), "api".to_string())]),
            labels: BTreeMap::new(),
        }],
        services: Vec::new(),
        endpoint_slices: Vec::new(),
    });

    let (generation, pods) = controller.raw_pods();

    assert_eq!(generation, 1);
    assert_eq!(pods.len(), 1);
    assert_eq!(pods[0].pod_ip.as_deref(), Some("10.42.0.10"));
    let telemetry = controller.telemetry();
    assert_eq!(telemetry.reconciliations, 1);
    assert_eq!(telemetry.pod_count, 1);
    assert!(telemetry.last_success_unix_seconds > 0);
    assert!(telemetry.last_resource_relist_unix_seconds > 0);
}

#[test]
fn event_driven_refreshes_coalesce_and_polling_ignores_notifications() {
    let event_driven = CaptureFilterController::new(
        CONTROL_UNKNOWN_DROP,
        CgroupHierarchyMode::UnifiedV2,
        false,
        CgroupDiscoveryMode::EventDriven,
    );
    event_driven.enqueue_refresh();
    event_driven.enqueue_refresh();
    assert!(event_driven.take_pending_refresh().is_some());
    assert!(event_driven.take_pending_refresh().is_none());
    let telemetry = event_driven.telemetry();
    assert_eq!(telemetry.discovery_notifications_total, 2);
    assert_eq!(telemetry.discovery_coalesced_total, 1);

    let polling = CaptureFilterController::new(
        CONTROL_UNKNOWN_DROP,
        CgroupHierarchyMode::UnifiedV2,
        false,
        CgroupDiscoveryMode::Polling,
    );
    polling.enqueue_refresh();
    assert!(polling.take_pending_refresh().is_none());
    assert_eq!(polling.telemetry().discovery_notifications_total, 0);
}

#[test]
fn desired_map_publication_wakes_a_waiting_applier() {
    let controller = Arc::new(CaptureFilterController::new(
        CONTROL_UNKNOWN_DROP,
        CgroupHierarchyMode::UnifiedV2,
        false,
        CgroupDiscoveryMode::EventDriven,
    ));
    let waiting = Arc::clone(&controller);
    let waiter =
        std::thread::spawn(move || waiting.wait_for_change(Some(0), Duration::from_secs(1)));
    std::thread::sleep(Duration::from_millis(10));

    let policy = CaptureFilterPolicy::from_config(&CaptureFilterConfig {
        enabled: true,
        default_posture: CapturePosture::Allow,
        ..Default::default()
    });
    let index = RawNodePodIndex::from_pods(
        [RawPod {
            namespace: "proj".to_string(),
            pod_name: "api".to_string(),
            pod_uid: Some(UID.to_string()),
            node_name: None,
            pod_ip: None,
            workload_name: None,
            workload_type: None,
            container_ids: Vec::new(),
            container_names: BTreeMap::new(),
            labels: BTreeMap::new(),
        }],
        1,
    );
    let desired = build_desired_filter_map(
        &[CgroupObservation::from_cgroup_path(
            41,
            &format!("/kubepods-pod{}.slice", UID.replace('-', "_")),
        )],
        &index,
        &policy,
        1,
    );
    let started_at = Instant::now();
    assert!(controller.publish(desired, started_at));

    let (generation, _desired, published_started_at) = waiter.join().expect("waiter joins");
    assert_eq!(generation, 1);
    assert_eq!(published_started_at, Some(started_at));
}

#[test]
fn scan_cgroups_reads_bounded_process_names_from_host_procfs() {
    use std::os::unix::fs::symlink;

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
    symlink(
        "/usr/local/bin/redis_exporter",
        procfs_root.join("123").join("exe"),
    )
    .expect("fixture exe symlink");

    let observations = scan_cgroups_blocking(&cgroup_root, &procfs_root, true);
    let container = observations
        .iter()
        .find(|observation| observation.container_id.as_deref() == Some(CID))
        .expect("container observation");

    assert_eq!(
        container.process_names,
        vec![
            "redis_exporter",
            "/usr/local/bin/redis_exporter",
            "postgres-exporter"
        ]
    );
    std::fs::remove_dir_all(&fixture).expect("cleanup");
}

#[test]
fn scan_cgroups_skips_process_procfs_without_process_rules() {
    let fixture = std::env::temp_dir().join(format!(
        "e-nav-cf-process-scan-disabled-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&fixture);
    let cgroup_root = fixture.join("cgroup");
    let procfs_root = fixture.join("proc");
    let leaf = cgroup_root.join(format!("cri-containerd-{CID}.scope"));
    std::fs::create_dir_all(&leaf).expect("fixture cgroup");
    std::fs::write(leaf.join("cgroup.procs"), "123\n").expect("fixture cgroup.procs");

    let observations = scan_cgroups_blocking(&cgroup_root, &procfs_root, false);
    let container = observations
        .iter()
        .find(|observation| observation.container_id.as_deref() == Some(CID))
        .expect("container observation");

    assert!(container.process_names.is_empty());
    std::fs::remove_dir_all(&fixture).expect("cleanup");
}

proptest! {
    #[test]
    fn refresh_gate_matches_a_one_slot_queue(operations in prop::collection::vec(any::<bool>(), 0..1_024)) {
        let pending = AtomicBool::new(false);
        let mut model_pending = false;

        for offer in operations {
            if offer {
                prop_assert_eq!(mark_refresh_pending(&pending), model_pending);
                model_pending = true;
            } else {
                prop_assert_eq!(take_refresh_pending(&pending), model_pending);
                model_pending = false;
            }
        }
    }
}
