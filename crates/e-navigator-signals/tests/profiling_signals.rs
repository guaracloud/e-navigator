use e_navigator_core::Signal;
use e_navigator_signals::{
    ContainerContext, KubernetesContext, MetricAggregationWindow, NetworkProcessIdentity,
    ProfilingAttribute, ProfilingConfidence, ProfilingCorrelationKind, ProfilingFrame,
    ProfilingKind, ProfilingSessionObservation, ProfilingStackTraceObservation,
    ProfilingWarningObservation, SignalEnvelope, SignalPayload,
};
use proptest::prelude::*;
use std::collections::BTreeMap;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    #[test]
    fn constructed_profile_envelopes_round_trip_without_changing_identity(
        source in "[a-z_\\.]{1,32}",
        host in prop::option::of("[a-z0-9.-]{1,32}"),
        sample_count in 1u64..1024,
    ) {
        let signal = SignalEnvelope::profile_sample_observation(
            source.clone(),
            host.clone(),
            e_navigator_signals::ProfileSampleObservation {
                timestamp_unix_nanos: 1_000,
                profiling_kind: ProfilingKind::Cpu,
                correlation_kind: ProfilingCorrelationKind::Synthetic,
                confidence: ProfilingConfidence::High,
                sample_count,
                sampling_period_nanos: Some(10_000_000),
                stack_id: "stack:0123456789abcdef".to_string(),
                stack_frames: vec![ProfilingFrame {
                    symbol: Some("checkout::handler".to_string()),
                    module: Some("checkout".to_string()),
                    file: None,
                    line: None,
                }],
                process: Some(process()),
                container: Some(container()),
                kubernetes: Some(kubernetes()),
                thread_id: None,
                thread_name: None,
                attributes: vec![],
            },
        );

        let json = serde_json::to_value(&signal).expect("serializes");
        let decoded: SignalEnvelope = serde_json::from_value(json).expect("deserializes");

        prop_assert_eq!(decoded.schema_version, signal.schema_version);
        prop_assert_eq!(decoded.kind(), signal.kind());
        prop_assert_eq!(decoded.source, source);
        prop_assert_eq!(decoded.host, host);
        prop_assert!(matches!(decoded.payload, SignalPayload::ProfileSampleObservation(_)));
    }
}

#[test]
fn serializes_cpu_profile_sample_with_bounded_stack_and_context() {
    let signal = SignalEnvelope::profile_sample_observation(
        "source.synthetic_profile",
        Some("node-a".to_string()),
        e_navigator_signals::ProfileSampleObservation {
            timestamp_unix_nanos: 1_000,
            profiling_kind: ProfilingKind::Cpu,
            correlation_kind: ProfilingCorrelationKind::Synthetic,
            confidence: ProfilingConfidence::High,
            sample_count: 3,
            sampling_period_nanos: Some(10_000_000),
            stack_id: "stack:0123456789abcdef".to_string(),
            stack_frames: vec![ProfilingFrame {
                symbol: Some("checkout::handler".to_string()),
                module: Some("checkout".to_string()),
                file: None,
                line: None,
            }],
            process: Some(process()),
            container: Some(container()),
            kubernetes: Some(kubernetes()),
            thread_id: Some(7),
            thread_name: Some("tokio-runtime-worker".to_string()),
            attributes: vec![ProfilingAttribute {
                key: "profiling.synthetic.fixture".to_string(),
                value: "cpu_sample".to_string(),
            }],
        },
    );

    let json = serde_json::to_value(&signal).expect("signal serializes");
    let decoded: SignalEnvelope = serde_json::from_value(json.clone()).expect("round trips");

    assert_eq!(json["schema_version"], 1);
    assert_eq!(json["kind"], "profile_sample_observation");
    assert_eq!(json["payload"]["profiling_kind"], "cpu");
    assert_eq!(json["payload"]["correlation_kind"], "synthetic");
    assert_eq!(json["payload"]["confidence"], "high");
    assert_eq!(json["payload"]["sample_count"], 3);
    assert_eq!(json["payload"]["sampling_period_nanos"], 10_000_000);
    assert_eq!(
        json["payload"]["stack_frames"][0]["symbol"],
        "checkout::handler"
    );
    assert_eq!(json["payload"]["process"]["pid"], 42);
    assert_eq!(json["payload"]["thread_id"], 7);
    assert!(matches!(
        decoded.payload,
        SignalPayload::ProfileSampleObservation(_)
    ));
}

#[test]
fn profile_sample_constructor_filters_sensitive_attributes_before_json_stdout() {
    let signal = SignalEnvelope::profile_sample_observation(
        "source.synthetic_profile",
        Some("node-a".to_string()),
        e_navigator_signals::ProfileSampleObservation {
            timestamp_unix_nanos: 1_000,
            profiling_kind: ProfilingKind::Cpu,
            correlation_kind: ProfilingCorrelationKind::Synthetic,
            confidence: ProfilingConfidence::High,
            sample_count: 1,
            sampling_period_nanos: Some(10_000_000),
            stack_id: "stack:0123456789abcdef".to_string(),
            stack_frames: vec![],
            process: None,
            container: None,
            kubernetes: None,
            thread_id: None,
            thread_name: None,
            attributes: vec![
                ProfilingAttribute {
                    key: "authorization".to_string(),
                    value: "bearer token".to_string(),
                },
                ProfilingAttribute {
                    key: "api_key".to_string(),
                    value: "secret".to_string(),
                },
                ProfilingAttribute {
                    key: "profiling.synthetic.fixture".to_string(),
                    value: "cpu_sample".to_string(),
                },
            ],
        },
    );

    let json = serde_json::to_value(&signal).expect("signal serializes");
    let attributes = json["payload"]["attributes"]
        .as_array()
        .expect("attributes are serialized");

    assert_eq!(attributes.len(), 1);
    assert_eq!(attributes[0]["key"], "profiling.synthetic.fixture");
}

#[test]
fn profile_sample_constructor_bounds_attributes_before_json_stdout() {
    let mut attributes = vec![ProfilingAttribute {
        key: "k".repeat(96),
        value: "v".repeat(320),
    }];
    attributes.extend((0..20).map(|index| ProfilingAttribute {
        key: format!("profiling.attribute.{index}"),
        value: "value".to_string(),
    }));

    let signal = SignalEnvelope::profile_sample_observation(
        "source.synthetic_profile",
        Some("node-a".to_string()),
        e_navigator_signals::ProfileSampleObservation {
            timestamp_unix_nanos: 1_000,
            profiling_kind: ProfilingKind::Cpu,
            correlation_kind: ProfilingCorrelationKind::Synthetic,
            confidence: ProfilingConfidence::High,
            sample_count: 1,
            sampling_period_nanos: Some(10_000_000),
            stack_id: "stack:0123456789abcdef".to_string(),
            stack_frames: vec![],
            process: None,
            container: None,
            kubernetes: None,
            thread_id: None,
            thread_name: None,
            attributes,
        },
    );

    let json = serde_json::to_value(&signal).expect("signal serializes");
    let attributes = json["payload"]["attributes"]
        .as_array()
        .expect("attributes are serialized");

    assert_eq!(attributes.len(), 16);
    assert_eq!(attributes[0]["key"].as_str().map(str::len), Some(64));
    assert_eq!(attributes[0]["value"].as_str().map(str::len), Some(256));
    assert_eq!(attributes[15]["key"], "profiling.attribute.14");
}

#[test]
fn profile_sample_constructor_bounds_stack_frames_before_json_stdout() {
    let frames = (0..300)
        .map(|index| ProfilingFrame {
            symbol: Some(format!("frame-{index}-{}", "s".repeat(320))),
            module: Some("m".repeat(320)),
            file: Some("f".repeat(320)),
            line: Some(index),
        })
        .collect();

    let signal = SignalEnvelope::profile_sample_observation(
        "source.synthetic_profile",
        Some("node-a".to_string()),
        e_navigator_signals::ProfileSampleObservation {
            timestamp_unix_nanos: 1_000,
            profiling_kind: ProfilingKind::Cpu,
            correlation_kind: ProfilingCorrelationKind::Synthetic,
            confidence: ProfilingConfidence::High,
            sample_count: 1,
            sampling_period_nanos: Some(10_000_000),
            stack_id: "stack:0123456789abcdef".to_string(),
            stack_frames: frames,
            process: None,
            container: None,
            kubernetes: None,
            thread_id: None,
            thread_name: None,
            attributes: vec![],
        },
    );

    let json = serde_json::to_value(&signal).expect("signal serializes");
    let frames = json["payload"]["stack_frames"]
        .as_array()
        .expect("stack frames are serialized");

    assert_eq!(frames.len(), 256);
    assert_eq!(frames[0]["symbol"].as_str().map(str::len), Some(256));
    assert_eq!(frames[0]["module"].as_str().map(str::len), Some(256));
    assert_eq!(frames[0]["file"].as_str().map(str::len), Some(256));
    assert_eq!(frames[255]["line"], 255);
}

#[test]
fn serializes_stack_trace_observation_with_optional_missing_symbols() {
    let signal = SignalEnvelope::profiling_stack_trace_observation(
        "source.synthetic_profile",
        Some("node-a".to_string()),
        ProfilingStackTraceObservation {
            timestamp_unix_nanos: 1_100,
            profiling_kind: ProfilingKind::Cpu,
            correlation_kind: ProfilingCorrelationKind::Synthetic,
            confidence: ProfilingConfidence::Medium,
            stack_id: "stack:missing".to_string(),
            stack_frames: vec![ProfilingFrame {
                symbol: None,
                module: Some("libunknown.so".to_string()),
                file: None,
                line: None,
            }],
            process: Some(process()),
            container: Some(container()),
            kubernetes: Some(kubernetes()),
            attributes: vec![],
        },
    );

    let json = serde_json::to_value(&signal).expect("signal serializes");
    let decoded: SignalEnvelope = serde_json::from_value(json.clone()).expect("round trips");

    assert_eq!(json["kind"], "profiling_stack_trace_observation");
    assert_eq!(
        json["payload"]["stack_frames"][0]["symbol"],
        serde_json::Value::Null
    );
    assert_eq!(
        json["payload"]["stack_frames"][0]["module"],
        "libunknown.so"
    );
    assert!(matches!(
        decoded.payload,
        SignalPayload::ProfilingStackTraceObservation(_)
    ));
}

#[test]
fn serializes_profiling_session_window_observation() {
    let signal = SignalEnvelope::profiling_session_observation(
        "generator.profiling",
        Some("node-a".to_string()),
        ProfilingSessionObservation {
            window: MetricAggregationWindow {
                start_unix_nanos: 1_000,
                end_unix_nanos: 2_000,
            },
            profiling_kind: ProfilingKind::Cpu,
            correlation_kind: ProfilingCorrelationKind::Synthetic,
            confidence: ProfilingConfidence::Medium,
            profile_id: "profile:0123456789abcdef".to_string(),
            observed_sample_count: 5,
            dropped_sample_count: 0,
            distinct_stack_count: 2,
            sampling_period_nanos: Some(10_000_000),
            process: Some(process()),
            container: Some(container()),
            kubernetes: Some(kubernetes()),
            source: "source.synthetic_profile".to_string(),
            attributes: vec![],
        },
    );

    let json = serde_json::to_value(&signal).expect("signal serializes");
    let decoded: SignalEnvelope = serde_json::from_value(json.clone()).expect("round trips");

    assert_eq!(json["kind"], "profiling_session_observation");
    assert_eq!(json["payload"]["profile_id"], "profile:0123456789abcdef");
    assert_eq!(json["payload"]["observed_sample_count"], 5);
    assert_eq!(json["payload"]["source"], "source.synthetic_profile");
    assert!(matches!(
        decoded.payload,
        SignalPayload::ProfilingSessionObservation(_)
    ));
}

#[test]
fn serializes_profiling_warning_observation() {
    let signal = SignalEnvelope::profiling_warning_observation(
        "generator.profiling",
        Some("node-a".to_string()),
        ProfilingWarningObservation {
            warning_type: "missing_attribution".to_string(),
            message: "profile sample has no container or Kubernetes context".to_string(),
            timestamp_unix_nanos: 1_500,
            source_signal_kind: "profile_sample_observation".to_string(),
            source_module: "source.synthetic_profile".to_string(),
            profiling_kind: ProfilingKind::Cpu,
            correlation_kind: ProfilingCorrelationKind::Synthetic,
            confidence: ProfilingConfidence::Low,
            process: Some(process()),
            container: None,
            kubernetes: None,
            attributes: vec![],
        },
    );

    let json = serde_json::to_value(&signal).expect("signal serializes");
    let decoded: SignalEnvelope = serde_json::from_value(json.clone()).expect("round trips");

    assert_eq!(json["kind"], "profiling_warning_observation");
    assert_eq!(json["payload"]["warning_type"], "missing_attribution");
    assert_eq!(json["payload"]["profiling_kind"], "cpu");
    assert!(matches!(
        decoded.payload,
        SignalPayload::ProfilingWarningObservation(_)
    ));
}

#[test]
fn direct_payload_deserialization_keeps_profile_payloads_unambiguous() {
    let sample_payload = serde_json::json!({
        "timestamp_unix_nanos": 1,
        "profiling_kind": "cpu",
        "correlation_kind": "synthetic",
        "confidence": "high",
        "sample_count": 1,
        "sampling_period_nanos": 1000,
        "stack_id": "stack:a",
        "stack_frames": [],
        "process": null,
        "container": null,
        "kubernetes": null,
        "thread_id": null,
        "thread_name": null,
        "attributes": []
    });
    let session_payload = serde_json::json!({
        "window": {"start_unix_nanos": 1, "end_unix_nanos": 2},
        "profiling_kind": "cpu",
        "correlation_kind": "synthetic",
        "confidence": "medium",
        "profile_id": "profile:a",
        "observed_sample_count": 1,
        "dropped_sample_count": 0,
        "distinct_stack_count": 1,
        "sampling_period_nanos": 1000,
        "process": null,
        "container": null,
        "kubernetes": null,
        "source": "source.synthetic_profile",
        "attributes": []
    });

    let sample: SignalPayload =
        serde_json::from_value(sample_payload).expect("sample payload deserializes");
    let session: SignalPayload =
        serde_json::from_value(session_payload).expect("session payload deserializes");

    assert!(matches!(sample, SignalPayload::ProfileSampleObservation(_)));
    assert!(matches!(
        session,
        SignalPayload::ProfilingSessionObservation(_)
    ));
}

#[test]
fn rejects_stack_trace_kind_with_profile_sample_payload_fields() {
    let json = serde_json::json!({
        "schema_version": 1,
        "kind": "profiling_stack_trace_observation",
        "source": "source.synthetic_profile",
        "host": null,
        "payload": {
            "timestamp_unix_nanos": 1,
            "profiling_kind": "cpu",
            "correlation_kind": "synthetic",
            "confidence": "high",
            "sample_count": 1,
            "sampling_period_nanos": 1000,
            "stack_id": "stack:a",
            "stack_frames": [],
            "process": null,
            "container": null,
            "kubernetes": null,
            "thread_id": null,
            "thread_name": null,
            "attributes": []
        }
    });

    let err = serde_json::from_value::<SignalEnvelope>(json)
        .expect_err("sample-only fields must not be accepted as stack trace payloads");

    assert!(
        err.to_string()
            .contains("profiling_stack_trace_observation")
    );
}

fn process() -> NetworkProcessIdentity {
    NetworkProcessIdentity {
        pid: 42,
        ppid: Some(1),
        uid: Some(1000),
        command: "checkout-api".to_string(),
        executable: Some("/app/checkout-api".to_string()),
        cgroup_id: None,
    }
}

fn container() -> ContainerContext {
    ContainerContext {
        container_id: "0123456789abcdef".to_string(),
        runtime: Some("containerd".to_string()),
    }
}

fn kubernetes() -> KubernetesContext {
    KubernetesContext {
        namespace: "default".to_string(),
        pod_name: "checkout-123".to_string(),
        pod_uid: Some("pod-uid".to_string()),
        container_name: Some("checkout".to_string()),
        node_name: Some("node-a".to_string()),
        labels: BTreeMap::from([("app".to_string(), "checkout".to_string())]),
    }
}
