use e_navigator_signals::{
    ContainerContext, KubernetesContext, MetricAggregationWindow, NetworkProcessIdentity,
    ProfileSampleObservation, ProfilingAttribute, ProfilingConfidence, ProfilingCorrelationKind,
    ProfilingFrame, ProfilingKind, ProfilingSessionObservation, SignalEnvelope,
};
use e_navigator_sinks::{
    E_NAVIGATOR_CPU_PROFILE_METRIC_NAME, format_otel_profile_record, format_pprof_profile,
    format_profile_record,
};
use prost::Message;
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
        Some(E_NAVIGATOR_CPU_PROFILE_METRIC_NAME)
    );
    assert_eq!(record.sample_count, 3);
    assert_eq!(record.resource["host.name"], "node-a");
    assert_eq!(
        record.attributes["profiling.synthetic.fixture"],
        "cpu_sample"
    );
}

#[test]
fn formats_otel_profile_session_with_dropped_samples_and_safe_attributes() {
    let signal = SignalEnvelope::profiling_session_observation(
        "generator.profiling",
        Some("node-a".to_string()),
        ProfilingSessionObservation {
            window: MetricAggregationWindow {
                start_unix_nanos: 1_000,
                end_unix_nanos: 3_000,
            },
            profiling_kind: ProfilingKind::Cpu,
            correlation_kind: ProfilingCorrelationKind::ObservedProfileSample,
            confidence: ProfilingConfidence::Medium,
            profile_id: "profile:abc".to_string(),
            observed_sample_count: 24,
            dropped_sample_count: 76,
            distinct_stack_count: 5,
            sampling_period_nanos: Some(10_000_000),
            process: Some(NetworkProcessIdentity {
                pid: 42,
                ppid: Some(1),
                uid: Some(1000),
                command: "checkout-api".to_string(),
                executable: Some("/app/checkout-api".to_string()),
                cgroup_id: None,
            }),
            container: None,
            kubernetes: None,
            source: "source.aya_cpu_profile".to_string(),
            attributes: vec![
                attr("profiling.synthetic.fixture", "cpu_sample"),
                attr("authorization", "Bearer token"),
                attr("profile_id", "evil"),
            ],
        },
    );

    let record = format_otel_profile_record(&signal).expect("OTLP profile record formats");

    assert_eq!(record.profile_id, "profile:abc");
    assert_eq!(record.profile_kind, "cpu");
    assert_eq!(record.sample_count, 24);
    assert_eq!(record.dropped_sample_count, 76);
    assert_eq!(record.timestamp_unix_nanos, 3_000);
    assert_eq!(record.duration_nanos, 2_000);
    assert_eq!(record.sampling_period_nanos, Some(10_000_000));
    assert_eq!(record.resource["host.name"], "node-a");
    assert_eq!(record.resource["process.pid"], 42);
    assert_eq!(record.attributes["profile.distinct_stack_count"], 5);
    assert_eq!(record.attributes["profile.dropped_sample_count"], 76);
    assert_eq!(
        record.attributes["profile.source"],
        "source.aya_cpu_profile"
    );
    assert_eq!(
        record.attributes["profiling.synthetic.fixture"],
        "cpu_sample"
    );
    assert!(!record.attributes.contains_key("authorization"));
    assert!(!record.attributes.contains_key("profile_id"));
    assert!(record.stack_frames.is_empty());
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
fn profile_record_bounds_identifier_fields() {
    const MAX_VALUE_BYTES: usize = 256;

    let long_value = "i".repeat(MAX_VALUE_BYTES + 64);
    let session = SignalEnvelope::profiling_session_observation(
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
            profile_id: long_value.clone(),
            observed_sample_count: 3,
            dropped_sample_count: 0,
            distinct_stack_count: 2,
            sampling_period_nanos: None,
            process: None,
            container: None,
            kubernetes: None,
            source: "source.synthetic_profile".to_string(),
            attributes: Vec::new(),
        },
    );
    let session_record = format_profile_record(&session).expect("session formats");
    assert_eq!(session_record.profile_id.len(), MAX_VALUE_BYTES);

    let mut sample = profile_sample_signal(Some("node-a"), None, None);
    if let e_navigator_signals::SignalPayload::ProfileSampleObservation(observation) =
        &mut sample.payload
    {
        observation.stack_id = long_value;
    }
    let sample_record = format_profile_record(&sample).expect("sample formats");
    assert_eq!(
        sample_record.stack_id.as_deref().map(str::len),
        Some(MAX_VALUE_BYTES)
    );
}

#[test]
fn sample_profile_ids_include_host_and_workload_identity() {
    let mut left = profile_sample_signal(Some("node-a"), Some("container-a"), Some("pod-a"));
    let right = profile_sample_signal(Some("node-b"), Some("container-b"), Some("pod-b"));
    let left_record = format_profile_record(&left).expect("left formats");
    let right_record = format_profile_record(&right).expect("right formats");
    assert_eq!(left_record.profile_id, "profile-sample:d41180ea1f8882c9");
    assert_ne!(left_record.profile_id, right_record.profile_id);

    if let e_navigator_signals::SignalPayload::ProfileSampleObservation(sample) = &mut left.payload
    {
        sample.container = Some(container("container-c"));
    }
    let changed_record = format_profile_record(&left).expect("changed formats");
    assert_ne!(left_record.profile_id, changed_record.profile_id);
}

#[test]
fn otlp_profile_sample_ids_include_host_and_workload_identity() {
    let mut left = profile_sample_signal(Some("node-a"), Some("container-a"), Some("pod-a"));
    let right = profile_sample_signal(Some("node-b"), Some("container-b"), Some("pod-b"));
    let left_record = format_otel_profile_record(&left).expect("left formats");
    let right_record = format_otel_profile_record(&right).expect("right formats");
    assert_eq!(left_record.profile_id, "profile-sample:d41180ea1f8882c9");
    assert_ne!(left_record.profile_id, right_record.profile_id);

    if let e_navigator_signals::SignalPayload::ProfileSampleObservation(sample) = &mut left.payload
    {
        sample.container = Some(container("container-c"));
    }
    let changed_record = format_otel_profile_record(&left).expect("changed formats");
    assert_ne!(left_record.profile_id, changed_record.profile_id);
}

#[test]
fn otlp_profile_bounds_sample_attributes_and_stack_frames() {
    const MAX_VALUE_BYTES: usize = 256;
    const MAX_STACK_FRAMES: usize = 256;

    let long_value = "v".repeat(MAX_VALUE_BYTES + 64);
    let mut signal = profile_sample_signal(Some("node-a"), Some("container-a"), Some("pod-a"));
    if let e_navigator_signals::SignalPayload::ProfileSampleObservation(sample) =
        &mut signal.payload
    {
        sample.stack_id = long_value.clone();
        sample.thread_name = Some(long_value.clone());
        sample.stack_frames = (0..MAX_STACK_FRAMES + 64)
            .map(|index| ProfilingFrame {
                symbol: Some(long_value.clone()),
                module: Some(long_value.clone()),
                file: Some(long_value.clone()),
                line: Some(index as u32),
            })
            .collect();
    }

    let record = format_otel_profile_record(&signal).expect("record formats");

    assert_eq!(
        record.attributes["profile.stack.id"].as_str().map(str::len),
        Some(MAX_VALUE_BYTES)
    );
    assert_eq!(
        record.attributes["thread.name"].as_str().map(str::len),
        Some(MAX_VALUE_BYTES)
    );
    assert_eq!(record.stack_frames.len(), MAX_STACK_FRAMES);
    let frame = record.stack_frames.first().expect("stack frame formats");
    assert_eq!(frame.symbol.as_deref().map(str::len), Some(MAX_VALUE_BYTES));
    assert_eq!(frame.module.as_deref().map(str::len), Some(MAX_VALUE_BYTES));
    assert_eq!(frame.file.as_deref().map(str::len), Some(MAX_VALUE_BYTES));
}

#[test]
fn otlp_profile_bounds_session_source_attribute() {
    const MAX_VALUE_BYTES: usize = 256;

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
            sampling_period_nanos: Some(10_000_000),
            process: None,
            container: None,
            kubernetes: None,
            source: "s".repeat(MAX_VALUE_BYTES + 64),
            attributes: Vec::new(),
        },
    );

    let record = format_otel_profile_record(&signal).expect("record formats");

    assert_eq!(
        record.attributes["profile.source"].as_str().map(str::len),
        Some(MAX_VALUE_BYTES)
    );
}

#[test]
fn otlp_profile_sample_attribute_cap_includes_canonical_fields() {
    const MAX_OTLP_ATTRIBUTES: usize = 16;

    let mut signal = profile_sample_signal(Some("node-a"), Some("container-a"), Some("pod-a"));
    if let e_navigator_signals::SignalPayload::ProfileSampleObservation(sample) =
        &mut signal.payload
    {
        sample.thread_id = Some(7);
        sample.thread_name = Some("worker-7".to_string());
        sample.attributes = vec![attr("profile.stack.id", "evil")];
        sample
            .attributes
            .extend((0..32).map(|index| attr(&format!("profiling.extra.{index:02}"), "value")));
    }

    let record = format_otel_profile_record(&signal).expect("record formats");

    assert_eq!(record.attributes.len(), MAX_OTLP_ATTRIBUTES);
    assert_eq!(record.attributes["profile.stack.id"], "stack:abc");
    assert_eq!(record.attributes["thread.id"].as_u64(), Some(7));
    assert_eq!(record.attributes["thread.name"], "worker-7");
    assert!(record.attributes.contains_key("profiling.extra.12"));
    assert!(!record.attributes.contains_key("profiling.extra.13"));
}

#[test]
fn otlp_profile_session_attribute_cap_includes_canonical_fields() {
    const MAX_OTLP_ATTRIBUTES: usize = 16;

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
            dropped_sample_count: 1,
            distinct_stack_count: 2,
            sampling_period_nanos: Some(10_000_000),
            process: None,
            container: None,
            kubernetes: None,
            source: "source.synthetic_profile".to_string(),
            attributes: {
                let mut attributes = vec![attr("profile.source", "evil")];
                attributes.extend(
                    (0..32).map(|index| attr(&format!("profiling.extra.{index:02}"), "value")),
                );
                attributes
            },
        },
    );

    let record = format_otel_profile_record(&signal).expect("record formats");

    assert_eq!(record.attributes.len(), MAX_OTLP_ATTRIBUTES);
    assert_eq!(record.attributes["profile.distinct_stack_count"], 2);
    assert_eq!(record.attributes["profile.dropped_sample_count"], 1);
    assert_eq!(
        record.attributes["profile.source"],
        "source.synthetic_profile"
    );
    assert!(record.attributes.contains_key("profiling.extra.12"));
    assert!(!record.attributes.contains_key("profiling.extra.13"));
}

#[test]
fn profile_record_bounds_resource_values() {
    const MAX_VALUE_BYTES: usize = 256;

    let signal = profile_sample_with_long_resource_values(MAX_VALUE_BYTES);
    let record = format_profile_record(&signal).expect("record formats");

    for key in [
        "host.name",
        "process.command",
        "container.id",
        "container.runtime",
        "k8s.namespace.name",
        "namespace",
        "k8s.pod.name",
        "pod",
        "k8s.pod.uid",
        "k8s.container.name",
        "container",
        "k8s.node.name",
        "node",
        "service_name",
    ] {
        assert_eq!(record.resource[key].len(), MAX_VALUE_BYTES);
    }
}

#[test]
fn otlp_profile_bounds_resource_values() {
    const MAX_VALUE_BYTES: usize = 256;

    let signal = profile_sample_with_long_resource_values(MAX_VALUE_BYTES);
    let record = format_otel_profile_record(&signal).expect("record formats");

    for key in [
        "host.name",
        "process.command",
        "container.id",
        "container.runtime",
        "k8s.namespace.name",
        "namespace",
        "k8s.pod.name",
        "pod",
        "k8s.pod.uid",
        "k8s.container.name",
        "container",
        "k8s.node.name",
        "node",
        "service.name",
        "service_name",
    ] {
        assert_eq!(
            record.resource[key].as_str().map(str::len),
            Some(MAX_VALUE_BYTES)
        );
    }
}

#[test]
fn pprof_profile_sample_encodes_stack_values_and_safe_labels() {
    let mut signal = SignalEnvelope::profile_sample_observation(
        "source.aya_cpu_profile",
        Some("node-a".to_string()),
        ProfileSampleObservation {
            timestamp_unix_nanos: 1_000,
            profiling_kind: ProfilingKind::Cpu,
            correlation_kind: ProfilingCorrelationKind::ObservedProfileSample,
            confidence: ProfilingConfidence::High,
            sample_count: 2,
            sampling_period_nanos: Some(10_000_000),
            stack_id: "stack:abc".to_string(),
            stack_frames: vec![
                ProfilingFrame {
                    symbol: Some("checkout::handler".to_string()),
                    module: Some("checkout".to_string()),
                    file: Some("/src/checkout.rs".to_string()),
                    line: Some(42),
                },
                ProfilingFrame {
                    symbol: Some("tokio::runtime".to_string()),
                    module: Some("tokio".to_string()),
                    file: None,
                    line: None,
                },
            ],
            process: Some(NetworkProcessIdentity {
                pid: 42,
                ppid: Some(1),
                uid: Some(1000),
                command: "checkout-api".to_string(),
                executable: Some("/app/checkout-api".to_string()),
                cgroup_id: None,
            }),
            container: Some(container("container-a")),
            kubernetes: Some(kubernetes("pod-a")),
            thread_id: Some(7),
            thread_name: Some("worker".to_string()),
            attributes: vec![
                attr("profiling.source", "fixture"),
                attr("authorization", "Bearer token"),
                attr("schema", "evil"),
                attr("profile_id", "evil"),
                attr("correlation_kind", "evil"),
                attr("confidence", "evil"),
            ],
        },
    );
    if let e_navigator_signals::SignalPayload::ProfileSampleObservation(sample) =
        &mut signal.payload
        && let Some(kubernetes) = &mut sample.kubernetes
    {
        kubernetes
            .labels
            .insert("app".to_string(), "checkout-api".to_string());
    }

    let bytes = format_pprof_profile(&signal).expect("pprof profile formats");
    let profile = pprof::Profile::decode(bytes.as_slice()).expect("pprof decodes");

    assert_eq!(profile.string_table.first().map(String::as_str), Some(""));
    assert!(profile.string_table.contains(&"cpu".to_string()));
    assert!(profile.string_table.contains(&"nanoseconds".to_string()));
    assert!(
        profile
            .string_table
            .contains(&"checkout::handler".to_string())
    );
    assert!(profile.string_table.contains(&"tokio::runtime".to_string()));
    assert_eq!(profile.sample.len(), 1);
    assert_eq!(profile.sample[0].value, vec![20_000_000]);
    assert_eq!(profile.sample[0].location_id, vec![1, 2]);
    assert_eq!(profile.location.len(), 2);
    assert_eq!(profile.location[0].line[0].line, 42);
    assert_eq!(profile.function.len(), 2);
    assert_eq!(profile.time_nanos, 1_000);
    assert_eq!(profile.period, 10_000_000);
    assert_eq!(label_value(&profile, "service.name"), Some("checkout-api"));
    assert_eq!(label_value(&profile, "thread.name"), Some("worker"));
    assert_eq!(label_value(&profile, "profiling.source"), Some("fixture"));
    assert_eq!(label_value(&profile, "authorization"), None);
    assert_eq!(label_value(&profile, "schema"), None);
    assert_eq!(label_value(&profile, "profile_id"), None);
    assert_eq!(label_value(&profile, "correlation_kind"), None);
    assert_eq!(label_value(&profile, "confidence"), None);
}

#[test]
fn pprof_profile_bounds_canonical_label_values() {
    const MAX_LABEL_BYTES: usize = 256;

    let long_value = "v".repeat(MAX_LABEL_BYTES + 64);
    let mut signal = profile_sample_signal(Some(&long_value), Some(&long_value), Some(&long_value));

    if let e_navigator_signals::SignalPayload::ProfileSampleObservation(sample) =
        &mut signal.payload
    {
        sample.stack_id = long_value.clone();
        sample.stack_frames = vec![ProfilingFrame {
            symbol: Some("checkout::handler".to_string()),
            module: Some("checkout".to_string()),
            file: Some("/src/checkout.rs".to_string()),
            line: Some(42),
        }];
        sample.thread_name = Some(long_value.clone());
        if let Some(process) = &mut sample.process {
            process.command = long_value.clone();
        }
        if let Some(kubernetes) = &mut sample.kubernetes {
            kubernetes.namespace = long_value.clone();
            kubernetes.pod_name = long_value.clone();
            kubernetes.container_name = Some(long_value.clone());
            kubernetes.node_name = Some(long_value.clone());
            kubernetes
                .labels
                .insert("app".to_string(), long_value.clone());
        }
    }

    let bytes = format_pprof_profile(&signal).expect("pprof profile formats");
    let profile = pprof::Profile::decode(bytes.as_slice()).expect("pprof decodes");

    for key in [
        "host.name",
        "profile.stack.id",
        "thread.name",
        "process.command",
        "container.id",
        "k8s.namespace.name",
        "k8s.pod.name",
        "k8s.pod.uid",
        "k8s.container.name",
        "k8s.node.name",
        "service.name",
    ] {
        assert_eq!(
            label_value(&profile, key).map(str::len),
            Some(MAX_LABEL_BYTES)
        );
    }
}

#[test]
fn pprof_profile_attributes_cannot_overwrite_canonical_labels() {
    let mut signal = profile_sample_signal(Some("node-a"), Some("container-a"), Some("pod-a"));

    if let e_navigator_signals::SignalPayload::ProfileSampleObservation(sample) =
        &mut signal.payload
    {
        sample.stack_frames = vec![ProfilingFrame {
            symbol: Some("checkout::handler".to_string()),
            module: Some("checkout".to_string()),
            file: Some("/src/checkout.rs".to_string()),
            line: Some(42),
        }];
        sample.thread_id = Some(7);
        sample.thread_name = Some("worker".to_string());
        if let Some(kubernetes) = &mut sample.kubernetes {
            kubernetes
                .labels
                .insert("app".to_string(), "checkout-api".to_string());
        }
        sample.attributes = vec![
            attr("profile.stack.id", "evil-stack"),
            attr("thread.name", "evil-thread"),
            attr("process.command", "evil-process"),
            attr("service.name", "evil-service"),
            attr("profiling.source", "fixture"),
        ];
    }

    let bytes = format_pprof_profile(&signal).expect("pprof profile formats");
    let profile = pprof::Profile::decode(bytes.as_slice()).expect("pprof decodes");

    assert_eq!(label_value(&profile, "profile.stack.id"), Some("stack:abc"));
    assert_eq!(label_value(&profile, "thread.name"), Some("worker"));
    assert_eq!(
        label_value(&profile, "process.command"),
        Some("checkout-api")
    );
    assert_eq!(label_value(&profile, "service.name"), Some("checkout-api"));
    assert_eq!(label_value(&profile, "profiling.source"), Some("fixture"));
}

#[test]
fn pprof_profile_bounds_frame_string_values() {
    const MAX_FRAME_BYTES: usize = 256;

    let long_value = "f".repeat(MAX_FRAME_BYTES + 64);
    let signal = SignalEnvelope::profile_sample_observation(
        "source.aya_cpu_profile",
        Some("node-a".to_string()),
        ProfileSampleObservation {
            timestamp_unix_nanos: 1_000,
            profiling_kind: ProfilingKind::Cpu,
            correlation_kind: ProfilingCorrelationKind::ObservedProfileSample,
            confidence: ProfilingConfidence::High,
            sample_count: 1,
            sampling_period_nanos: Some(10_000_000),
            stack_id: "stack:abc".to_string(),
            stack_frames: vec![ProfilingFrame {
                symbol: Some(long_value.clone()),
                module: Some("checkout".to_string()),
                file: Some(long_value),
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

    let bytes = format_pprof_profile(&signal).expect("pprof profile formats");
    let profile = pprof::Profile::decode(bytes.as_slice()).expect("pprof decodes");
    let function = profile.function.first().expect("function formats");

    assert_eq!(
        string_table_value(&profile, function.name).map(str::len),
        Some(MAX_FRAME_BYTES)
    );
    assert_eq!(
        string_table_value(&profile, function.system_name).map(str::len),
        Some(MAX_FRAME_BYTES)
    );
    assert_eq!(
        string_table_value(&profile, function.filename).map(str::len),
        Some(MAX_FRAME_BYTES)
    );
}

#[test]
fn pprof_profile_bounds_stack_frame_count() {
    const MAX_STACK_FRAMES: usize = 256;

    let stack_frames = (0..MAX_STACK_FRAMES + 64)
        .map(|index| ProfilingFrame {
            symbol: Some(format!("frame_{index}")),
            module: Some("checkout".to_string()),
            file: Some(format!("/src/frame_{index}.rs")),
            line: Some(index as u32),
        })
        .collect();
    let signal = SignalEnvelope::profile_sample_observation(
        "source.aya_cpu_profile",
        Some("node-a".to_string()),
        ProfileSampleObservation {
            timestamp_unix_nanos: 1_000,
            profiling_kind: ProfilingKind::Cpu,
            correlation_kind: ProfilingCorrelationKind::ObservedProfileSample,
            confidence: ProfilingConfidence::High,
            sample_count: 1,
            sampling_period_nanos: Some(10_000_000),
            stack_id: "stack:abc".to_string(),
            stack_frames,
            process: None,
            container: None,
            kubernetes: None,
            thread_id: None,
            thread_name: None,
            attributes: vec![],
        },
    );

    let bytes = format_pprof_profile(&signal).expect("pprof profile formats");
    let profile = pprof::Profile::decode(bytes.as_slice()).expect("pprof decodes");

    assert_eq!(profile.location.len(), MAX_STACK_FRAMES);
    assert_eq!(profile.function.len(), MAX_STACK_FRAMES);
    assert_eq!(profile.sample[0].location_id.len(), MAX_STACK_FRAMES);
}

#[test]
fn pprof_profile_ignores_sessions_and_empty_stacks() {
    let session = SignalEnvelope::profiling_session_observation(
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
            attributes: Vec::new(),
        },
    );
    let empty_stack = profile_sample_signal(Some("node-a"), Some("container-a"), Some("pod-a"));

    assert_eq!(format_pprof_profile(&session), None);
    assert_eq!(format_pprof_profile(&empty_stack), None);
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
fn profile_resource_mapping_adds_native_workload_labels() {
    let mut signal = profile_sample_signal(Some("node-a"), Some("container-a"), Some("pod-a"));
    if let e_navigator_signals::SignalPayload::ProfileSampleObservation(sample) =
        &mut signal.payload
        && let Some(kubernetes) = &mut sample.kubernetes
    {
        kubernetes.namespace = "e-navigator-bench".to_string();
        kubernetes.labels.insert(
            "app.kubernetes.io/name".to_string(),
            "checkout-api".to_string(),
        );
    }

    let record = format_profile_record(&signal).expect("record formats");

    assert_eq!(record.resource["namespace"], "e-navigator-bench");
    assert_eq!(record.resource["service_name"], "checkout-api");
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
                attr("Authorization", "Bearer token"),
                attr("x-api-key", "secret"),
                attr("X-API-Key", "secret"),
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
    assert!(!record.attributes.contains_key("Authorization"));
    assert!(!record.attributes.contains_key("cookie"));
    assert!(!record.attributes.contains_key("x-api-key"));
    assert!(!record.attributes.contains_key("X-API-Key"));
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

fn profile_sample_with_long_resource_values(max_value_bytes: usize) -> SignalEnvelope {
    let long_value = "r".repeat(max_value_bytes + 64);
    let mut signal = profile_sample_signal(Some(&long_value), Some(&long_value), Some(&long_value));

    if let e_navigator_signals::SignalPayload::ProfileSampleObservation(sample) =
        &mut signal.payload
    {
        if let Some(process) = &mut sample.process {
            process.command = long_value.clone();
        }
        if let Some(container) = &mut sample.container {
            container.runtime = Some(long_value.clone());
        }
        if let Some(kubernetes) = &mut sample.kubernetes {
            kubernetes.namespace = long_value.clone();
            kubernetes.pod_name = long_value.clone();
            kubernetes.container_name = Some(long_value.clone());
            kubernetes.node_name = Some(long_value.clone());
            kubernetes.labels.insert("app".to_string(), long_value);
        }
    }

    signal
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

fn label_value<'a>(profile: &'a pprof::Profile, key: &str) -> Option<&'a str> {
    let sample = profile.sample.first()?;
    sample.label.iter().find_map(|label| {
        let label_key = string_table_value(profile, label.key)?;
        if label_key == key {
            string_table_value(profile, label.str)
        } else {
            None
        }
    })
}

fn string_table_value(profile: &pprof::Profile, index: i64) -> Option<&str> {
    profile
        .string_table
        .get(usize::try_from(index).ok()?)
        .map(String::as_str)
}

mod pprof {
    use prost::Message;

    #[derive(Clone, PartialEq, Message)]
    pub(super) struct Profile {
        #[prost(message, repeated, tag = "1")]
        pub(super) sample_type: Vec<ValueType>,
        #[prost(message, repeated, tag = "2")]
        pub(super) sample: Vec<Sample>,
        #[prost(message, repeated, tag = "3")]
        pub(super) mapping: Vec<Mapping>,
        #[prost(message, repeated, tag = "4")]
        pub(super) location: Vec<Location>,
        #[prost(message, repeated, tag = "5")]
        pub(super) function: Vec<Function>,
        #[prost(string, repeated, tag = "6")]
        pub(super) string_table: Vec<String>,
        #[prost(int64, tag = "7")]
        pub(super) drop_frames: i64,
        #[prost(int64, tag = "8")]
        pub(super) keep_frames: i64,
        #[prost(int64, tag = "9")]
        pub(super) time_nanos: i64,
        #[prost(int64, tag = "10")]
        pub(super) duration_nanos: i64,
        #[prost(message, optional, tag = "11")]
        pub(super) period_type: Option<ValueType>,
        #[prost(int64, tag = "12")]
        pub(super) period: i64,
        #[prost(int64, repeated, tag = "13")]
        pub(super) comment: Vec<i64>,
        #[prost(int64, tag = "14")]
        pub(super) default_sample_type: i64,
    }

    #[derive(Clone, PartialEq, Message)]
    pub(super) struct ValueType {
        #[prost(int64, tag = "1")]
        pub(super) r#type: i64,
        #[prost(int64, tag = "2")]
        pub(super) unit: i64,
    }

    #[derive(Clone, PartialEq, Message)]
    pub(super) struct Sample {
        #[prost(uint64, repeated, tag = "1")]
        pub(super) location_id: Vec<u64>,
        #[prost(int64, repeated, tag = "2")]
        pub(super) value: Vec<i64>,
        #[prost(message, repeated, tag = "3")]
        pub(super) label: Vec<Label>,
    }

    #[derive(Clone, PartialEq, Message)]
    pub(super) struct Label {
        #[prost(int64, tag = "1")]
        pub(super) key: i64,
        #[prost(int64, tag = "2")]
        pub(super) str: i64,
        #[prost(int64, tag = "3")]
        pub(super) num: i64,
        #[prost(int64, tag = "4")]
        pub(super) num_unit: i64,
    }

    #[derive(Clone, PartialEq, Message)]
    pub(super) struct Mapping {
        #[prost(uint64, tag = "1")]
        pub(super) id: u64,
    }

    #[derive(Clone, PartialEq, Message)]
    pub(super) struct Location {
        #[prost(uint64, tag = "1")]
        pub(super) id: u64,
        #[prost(uint64, tag = "2")]
        pub(super) mapping_id: u64,
        #[prost(uint64, tag = "3")]
        pub(super) address: u64,
        #[prost(message, repeated, tag = "4")]
        pub(super) line: Vec<Line>,
        #[prost(bool, tag = "5")]
        pub(super) is_folded: bool,
    }

    #[derive(Clone, PartialEq, Message)]
    pub(super) struct Line {
        #[prost(uint64, tag = "1")]
        pub(super) function_id: u64,
        #[prost(int64, tag = "2")]
        pub(super) line: i64,
    }

    #[derive(Clone, PartialEq, Message)]
    pub(super) struct Function {
        #[prost(uint64, tag = "1")]
        pub(super) id: u64,
        #[prost(int64, tag = "2")]
        pub(super) name: i64,
        #[prost(int64, tag = "3")]
        pub(super) system_name: i64,
        #[prost(int64, tag = "4")]
        pub(super) filename: i64,
        #[prost(int64, tag = "5")]
        pub(super) start_line: i64,
    }
}
