use e_navigator_signals::{
    ContainerContext, KubernetesContext, MetricAggregationWindow, NetworkProcessIdentity,
    ProfileSampleObservation, ProfilingAttribute, ProfilingConfidence, ProfilingCorrelationKind,
    ProfilingFrame, ProfilingKind, ProfilingSessionObservation, SignalEnvelope,
};
use e_navigator_sinks::{PYROSCOPE_CPU_PROFILE_IDENTITY, format_profile_record};
use std::collections::BTreeMap;

#[test]
fn formats_profile_session_boundary_record() {
    let signal = SignalEnvelope::profiling_session_observation(
        "generator.profiling",
        Some("node-a".to_string()),
        ProfilingSessionObservation {
            window: MetricAggregationWindow {
                start_unix_nanos: 1,
                end_unix_nanos: 2,
            },
            profiling_kind: ProfilingKind::Cpu,
            correlation_kind: ProfilingCorrelationKind::Synthetic,
            confidence: ProfilingConfidence::Medium,
            profile_id: "profile:abc".to_string(),
            observed_sample_count: 3,
            dropped_sample_count: 0,
            distinct_stack_count: 2,
            sampling_period_nanos: Some(10_000_000),
            process: None,
            container: None,
            kubernetes: None,
            source: "source.synthetic_profile".to_string(),
            attributes: vec![ProfilingAttribute {
                key: "profiling.synthetic.fixture".to_string(),
                value: "cpu_sample".to_string(),
            }],
        },
    );

    let record = format_profile_record(&signal).expect("profile record formats");

    assert_eq!(record.schema, "e-navigator.profile.internal.v1");
    assert_eq!(record.profile_id, "profile:abc");
    assert_eq!(record.profile_kind, "cpu");
    assert_eq!(
        record.profile_metric_name.as_deref(),
        Some(PYROSCOPE_CPU_PROFILE_IDENTITY)
    );
    assert_eq!(record.sample_count, 3);
    assert_eq!(record.resource["host.name"], "node-a");
    assert_eq!(
        record.attributes["profiling.synthetic.fixture"],
        "cpu_sample"
    );
}

#[test]
fn formats_profile_sample_without_raw_stack_attribute_labels() {
    let signal = SignalEnvelope::profile_sample_observation(
        "source.synthetic_profile",
        Some("node-a".to_string()),
        ProfileSampleObservation {
            timestamp_unix_nanos: 1,
            profiling_kind: ProfilingKind::Cpu,
            correlation_kind: ProfilingCorrelationKind::Synthetic,
            confidence: ProfilingConfidence::High,
            sample_count: 1,
            sampling_period_nanos: Some(10_000_000),
            stack_id: "stack:abc".to_string(),
            stack_frames: vec![ProfilingFrame {
                symbol: Some("checkout::handler".to_string()),
                module: Some("checkout".to_string()),
                file: Some("/src/checkout.rs".to_string()),
                line: Some(42),
            }],
            process: None,
            container: None,
            kubernetes: None,
            thread_id: None,
            thread_name: None,
            attributes: vec![],
        },
    );

    let record = format_profile_record(&signal).expect("profile record formats");

    assert_eq!(record.stack_id.as_deref(), Some("stack:abc"));
    assert_eq!(record.frame_count, Some(1));
    assert!(!record.attributes.contains_key("stack"));
    assert!(!record.attributes.contains_key("file"));
}

#[test]
fn sample_profile_ids_include_host_and_workload_identity() {
    let mut left = profile_sample_signal(Some("node-a"), Some("container-a"), Some("pod-a"));
    let right = profile_sample_signal(Some("node-b"), Some("container-b"), Some("pod-b"));
    let left_record = format_profile_record(&left).expect("left formats");
    let right_record = format_profile_record(&right).expect("right formats");
    assert_ne!(left_record.profile_id, right_record.profile_id);

    if let e_navigator_signals::SignalPayload::ProfileSampleObservation(sample) = &mut left.payload
    {
        sample.container = Some(container("container-c"));
    }
    let changed_record = format_profile_record(&left).expect("changed formats");
    assert_ne!(left_record.profile_id, changed_record.profile_id);
}

#[test]
fn profile_resource_mapping_preserves_pod_uid() {
    let record = format_profile_record(&profile_sample_signal(
        Some("node-a"),
        Some("container-a"),
        Some("pod-a"),
    ))
    .expect("record formats");

    assert_eq!(record.resource["k8s.pod.uid"], "pod-a");
}

#[test]
fn profile_resource_mapping_adds_pyroscope_compatible_labels() {
    let mut signal = profile_sample_signal(Some("node-a"), Some("container-a"), Some("pod-a"));
    if let e_navigator_signals::SignalPayload::ProfileSampleObservation(sample) =
        &mut signal.payload
        && let Some(kubernetes) = &mut sample.kubernetes
    {
        kubernetes.namespace = "proj-paid".to_string();
        kubernetes.labels.insert(
            "app.kubernetes.io/name".to_string(),
            "checkout-api".to_string(),
        );
        kubernetes
            .labels
            .insert("guara.cloud/catalog-slug".to_string(), "".to_string());
    }

    let record = format_profile_record(&signal).expect("record formats");

    assert_eq!(record.resource["namespace"], "proj-paid");
    assert_eq!(record.resource["service_name"], "checkout-api");
    assert_eq!(record.resource["catalog_slug"], "");
    assert_eq!(record.resource["pod"], "checkout-123");
    assert_eq!(record.resource["container"], "checkout");
    assert_eq!(record.resource["node"], "node-a");
    assert_eq!(record.resource["source"], "e-navigator");
}

#[test]
fn bounds_attributes_and_filters_sensitive_keys() {
    let signal = SignalEnvelope::profiling_session_observation(
        "generator.profiling",
        None,
        ProfilingSessionObservation {
            window: MetricAggregationWindow {
                start_unix_nanos: 1,
                end_unix_nanos: 2,
            },
            profiling_kind: ProfilingKind::Cpu,
            correlation_kind: ProfilingCorrelationKind::Synthetic,
            confidence: ProfilingConfidence::Medium,
            profile_id: "profile:abc".to_string(),
            observed_sample_count: 3,
            dropped_sample_count: 0,
            distinct_stack_count: 2,
            sampling_period_nanos: None,
            process: None,
            container: None,
            kubernetes: None,
            source: "source.synthetic_profile".to_string(),
            attributes: vec![
                attr("authorization", "Bearer token"),
                attr("x-api-key", "secret"),
                attr("private_key", "secret"),
                attr("jwt", "secret"),
                attr("alpha", "one"),
                attr("beta", "two"),
                attr("cookie", "session=secret"),
                attr("gamma", "three"),
            ],
        },
    );

    let record = format_profile_record(&signal).expect("profile record formats");

    assert_eq!(record.attributes.len(), 3);
    assert_eq!(record.attributes["alpha"], "one");
    assert!(!record.attributes.contains_key("authorization"));
    assert!(!record.attributes.contains_key("cookie"));
    assert!(!record.attributes.contains_key("x-api-key"));
    assert!(!record.attributes.contains_key("private_key"));
    assert!(!record.attributes.contains_key("jwt"));
}

#[test]
fn attribute_scan_is_bounded_even_with_duplicate_keys() {
    let mut attributes = (0..32)
        .map(|index| attr("same-key", &format!("value-{index}")))
        .collect::<Vec<_>>();
    attributes.push(attr("late-key", "must-not-be-scanned"));
    let signal = SignalEnvelope::profiling_session_observation(
        "generator.profiling",
        None,
        ProfilingSessionObservation {
            window: MetricAggregationWindow {
                start_unix_nanos: 1,
                end_unix_nanos: 2,
            },
            profiling_kind: ProfilingKind::Cpu,
            correlation_kind: ProfilingCorrelationKind::Synthetic,
            confidence: ProfilingConfidence::Medium,
            profile_id: "profile:abc".to_string(),
            observed_sample_count: 3,
            dropped_sample_count: 0,
            distinct_stack_count: 2,
            sampling_period_nanos: None,
            process: None,
            container: None,
            kubernetes: None,
            source: "source.synthetic_profile".to_string(),
            attributes,
        },
    );

    let record = format_profile_record(&signal).expect("profile record formats");

    assert!(record.attributes.contains_key("same-key"));
    assert!(!record.attributes.contains_key("late-key"));
}

#[test]
fn canonical_fields_cannot_be_overwritten_by_attributes() {
    let signal = SignalEnvelope::profiling_session_observation(
        "generator.profiling",
        None,
        ProfilingSessionObservation {
            window: MetricAggregationWindow {
                start_unix_nanos: 1,
                end_unix_nanos: 2,
            },
            profiling_kind: ProfilingKind::Cpu,
            correlation_kind: ProfilingCorrelationKind::Synthetic,
            confidence: ProfilingConfidence::Medium,
            profile_id: "profile:abc".to_string(),
            observed_sample_count: 3,
            dropped_sample_count: 0,
            distinct_stack_count: 2,
            sampling_period_nanos: None,
            process: None,
            container: None,
            kubernetes: None,
            source: "source.synthetic_profile".to_string(),
            attributes: vec![attr("profile_id", "evil"), attr("profile_kind", "memory")],
        },
    );

    let record = format_profile_record(&signal).expect("profile record formats");

    assert_eq!(record.profile_id, "profile:abc");
    assert_eq!(record.profile_kind, "cpu");
    assert!(record.attributes.is_empty());
}

fn attr(key: &str, value: &str) -> ProfilingAttribute {
    ProfilingAttribute {
        key: key.to_string(),
        value: value.to_string(),
    }
}

fn profile_sample_signal(
    host: Option<&str>,
    container_id: Option<&str>,
    pod_uid: Option<&str>,
) -> SignalEnvelope {
    SignalEnvelope::profile_sample_observation(
        "source.synthetic_exec",
        host.map(ToString::to_string),
        ProfileSampleObservation {
            timestamp_unix_nanos: 1,
            profiling_kind: ProfilingKind::Cpu,
            correlation_kind: ProfilingCorrelationKind::Synthetic,
            confidence: ProfilingConfidence::High,
            sample_count: 1,
            sampling_period_nanos: Some(10_000_000),
            stack_id: "stack:abc".to_string(),
            stack_frames: vec![],
            process: Some(NetworkProcessIdentity {
                pid: 42,
                ppid: Some(1),
                uid: Some(1000),
                command: "checkout-api".to_string(),
                executable: Some("/app/checkout-api".to_string()),
                cgroup_id: None,
            }),
            container: container_id.map(container),
            kubernetes: pod_uid.map(kubernetes),
            thread_id: None,
            thread_name: None,
            attributes: vec![],
        },
    )
}

fn container(container_id: &str) -> ContainerContext {
    ContainerContext {
        container_id: container_id.to_string(),
        runtime: Some("containerd".to_string()),
    }
}

fn kubernetes(pod_uid: &str) -> KubernetesContext {
    KubernetesContext {
        namespace: "default".to_string(),
        pod_name: "checkout-123".to_string(),
        pod_uid: Some(pod_uid.to_string()),
        container_name: Some("checkout".to_string()),
        node_name: Some("node-a".to_string()),
        labels: BTreeMap::new(),
    }
}
