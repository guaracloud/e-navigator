use e_navigator_signals::{
    MetricAggregationWindow, ProfileSampleObservation, ProfilingAttribute, ProfilingConfidence,
    ProfilingCorrelationKind, ProfilingFrame, ProfilingKind, ProfilingSessionObservation,
    SignalEnvelope,
};
use e_navigator_sinks::format_profile_record;

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
