use e_navigator_profiling::model::{
    NormalizationLimits, RawProfileFrame, RawProfileSample, parse_profile_fixture,
};
use e_navigator_signals::{ProfilingConfidence, ProfilingCorrelationKind, ProfilingKind};

#[test]
fn bounded_stack_truncation_limits_frame_count() {
    let sample = raw_sample(
        (0..6)
            .map(|index| frame(Some(format!("fn{index}"))))
            .collect(),
    );
    let normalized = sample
        .normalize(&NormalizationLimits {
            max_frames_per_stack: 3,
            ..NormalizationLimits::default()
        })
        .expect("sample normalizes");

    assert_eq!(normalized.stack_frames.len(), 3);
    assert_eq!(normalized.attributes[0].key, "profiling.stack.truncated");
    assert_eq!(normalized.attributes[0].value, "true");
}

#[test]
fn oversized_symbols_modules_and_files_are_truncated_on_char_boundaries() {
    let sample = raw_sample(vec![RawProfileFrame {
        symbol: Some("abcdef".to_string()),
        module: Some("moduleabcdef".to_string()),
        file: Some("src/checkout/mod.rs".to_string()),
        line: Some(12),
    }]);

    let normalized = sample
        .normalize(&NormalizationLimits {
            max_symbol_bytes: 4,
            max_module_bytes: 6,
            max_file_bytes: 7,
            ..NormalizationLimits::default()
        })
        .expect("sample normalizes");

    let frame = &normalized.stack_frames[0];
    assert_eq!(frame.symbol.as_deref(), Some("abcd"));
    assert_eq!(frame.module.as_deref(), Some("module"));
    assert_eq!(frame.file.as_deref(), Some("src/che"));
}

#[test]
fn oversized_attribute_keys_and_values_are_truncated() {
    let normalized = raw_sample(vec![frame(Some("checkout::handler".to_string()))])
        .with_attributes(vec![e_navigator_signals::ProfilingAttribute {
            key: "very-long-attribute-key".to_string(),
            value: "very-long-attribute-value".to_string(),
        }])
        .normalize(&NormalizationLimits {
            max_attribute_key_bytes: 8,
            max_attribute_value_bytes: 9,
            ..NormalizationLimits::default()
        })
        .expect("sample normalizes");

    assert_eq!(normalized.attributes[0].key, "very-lon");
    assert_eq!(normalized.attributes[0].value, "very-long");
}

#[test]
fn sensitive_profile_attributes_are_filtered_during_normalization() {
    let normalized = raw_sample(vec![frame(Some("checkout::handler".to_string()))])
        .with_attributes(vec![
            e_navigator_signals::ProfilingAttribute {
                key: "authorization".to_string(),
                value: "bearer token".to_string(),
            },
            e_navigator_signals::ProfilingAttribute {
                key: "x-api-key".to_string(),
                value: "secret".to_string(),
            },
            e_navigator_signals::ProfilingAttribute {
                key: "profiling.synthetic.fixture".to_string(),
                value: "cpu_sample".to_string(),
            },
        ])
        .normalize(&NormalizationLimits::default())
        .expect("sample normalizes");

    assert_eq!(normalized.attributes.len(), 1);
    assert_eq!(normalized.attributes[0].key, "profiling.synthetic.fixture");
}

#[test]
fn missing_symbols_remain_missing_without_inventing_frames() {
    let sample = raw_sample(vec![RawProfileFrame {
        symbol: None,
        module: Some("libunknown.so".to_string()),
        file: None,
        line: None,
    }]);
    let normalized = sample
        .normalize(&NormalizationLimits::default())
        .expect("sample normalizes");

    assert_eq!(normalized.stack_frames[0].symbol, None);
    assert_eq!(
        normalized.stack_frames[0].module.as_deref(),
        Some("libunknown.so")
    );
}

#[test]
fn deterministic_stack_ids_are_stable_for_same_normalized_frames() {
    let sample = raw_sample(vec![
        frame(Some("checkout::handler".to_string())),
        frame(Some("tokio::runtime".to_string())),
    ]);

    let first = sample
        .clone()
        .normalize(&NormalizationLimits::default())
        .expect("sample normalizes");
    let second = sample
        .normalize(&NormalizationLimits::default())
        .expect("sample normalizes");

    assert_eq!(first.stack_id, second.stack_id);
    assert!(first.stack_id.starts_with("stack:"));
}

#[test]
fn deterministic_stack_ids_distinguish_missing_from_empty_fields() {
    let missing = raw_sample(vec![RawProfileFrame {
        symbol: None,
        module: Some("checkout".to_string()),
        file: None,
        line: None,
    }])
    .normalize(&NormalizationLimits::default())
    .expect("missing sample normalizes");
    let empty = raw_sample(vec![RawProfileFrame {
        symbol: Some(String::new()),
        module: Some("checkout".to_string()),
        file: None,
        line: None,
    }])
    .normalize(&NormalizationLimits::default())
    .expect("empty sample normalizes");

    assert_ne!(missing.stack_id, empty.stack_id);
}

#[test]
fn stack_truncation_marker_is_retained_when_attribute_capacity_is_full() {
    let normalized = raw_sample(
        (0..6)
            .map(|index| frame(Some(format!("fn{index}"))))
            .collect(),
    )
    .with_attributes(vec![e_navigator_signals::ProfilingAttribute {
        key: "zeta".to_string(),
        value: "kept-unless-marker-needs-space".to_string(),
    }])
    .normalize(&NormalizationLimits {
        max_frames_per_stack: 3,
        max_attributes: 1,
        ..NormalizationLimits::default()
    })
    .expect("sample normalizes");

    assert_eq!(normalized.attributes.len(), 1);
    assert_eq!(normalized.attributes[0].key, "profiling.stack.truncated");
    assert_eq!(normalized.attributes[0].value, "true");
}

#[test]
fn synthetic_profile_sample_normalization_sets_profile_fields() {
    let normalized = raw_sample(vec![frame(Some("checkout::handler".to_string()))])
        .normalize(&NormalizationLimits::default())
        .expect("sample normalizes");

    assert_eq!(normalized.profiling_kind, ProfilingKind::Cpu);
    assert_eq!(
        normalized.correlation_kind,
        ProfilingCorrelationKind::Synthetic
    );
    assert_eq!(normalized.confidence, ProfilingConfidence::High);
    assert_eq!(normalized.sample_count, 2);
    assert_eq!(normalized.sampling_period_nanos, Some(10_000_000));
}

#[test]
fn malformed_fixture_is_rejected() {
    let err = parse_profile_fixture(
        r#"{"timestamp_unix_nanos":1,"profiling_kind":"cpu","correlation_kind":"synthetic"}"#,
        &NormalizationLimits::default(),
    )
    .expect_err("fixture is malformed");

    assert!(err.contains("sample_count"));
}

#[test]
fn oversized_fixture_input_is_rejected_before_normalization() {
    let err = parse_profile_fixture(
        r#"{"timestamp_unix_nanos":1,"profiling_kind":"cpu","correlation_kind":"synthetic","confidence":"low","sample_count":1,"stack_frames":[]}"#,
        &NormalizationLimits {
            max_fixture_bytes: 16,
            ..NormalizationLimits::default()
        },
    )
    .expect_err("fixture is too large");

    assert!(err.contains("profile fixture exceeds"));
}

#[test]
fn extreme_fixture_arrays_are_rejected_before_normalization() {
    let frames = (0..80)
        .map(|index| format!(r#"{{"symbol":"fn{index}","module":null,"file":null,"line":null}}"#))
        .collect::<Vec<_>>()
        .join(",");
    let fixture = format!(
        r#"{{"timestamp_unix_nanos":1,"profiling_kind":"cpu","correlation_kind":"synthetic","confidence":"low","sample_count":1,"stack_frames":[{frames}]}}"#
    );
    let err = parse_profile_fixture(
        &fixture,
        &NormalizationLimits {
            max_frames_per_stack: 4,
            ..NormalizationLimits::default()
        },
    )
    .expect_err("fixture has too many frames");

    assert!(err.contains("stack_frames exceeds fixture preflight limit"));
}

#[test]
fn deterministic_output_orders_attributes_and_applies_limits() {
    let fixture = r#"{
      "timestamp_unix_nanos": 1,
      "profiling_kind": "cpu",
      "correlation_kind": "synthetic",
      "confidence": "high",
      "sample_count": 2,
      "sampling_period_nanos": 10000000,
      "stack_frames": [{"symbol":"checkout::handler","module":"checkout","file":null,"line":42}],
      "attributes": [
        {"key":"zeta","value":"last"},
        {"key":"alpha","value":"first"},
        {"key":"beta","value":"second"}
      ]
    }"#;

    let normalized = parse_profile_fixture(
        fixture,
        &NormalizationLimits {
            max_attributes: 2,
            ..NormalizationLimits::default()
        },
    )
    .expect("fixture normalizes");

    assert_eq!(normalized.attributes[0].key, "alpha");
    assert_eq!(normalized.attributes[1].key, "beta");
    assert_eq!(normalized.attributes.len(), 2);
}

fn raw_sample(stack_frames: Vec<RawProfileFrame>) -> RawProfileSample {
    RawProfileSample {
        timestamp_unix_nanos: 1,
        profiling_kind: ProfilingKind::Cpu,
        correlation_kind: ProfilingCorrelationKind::Synthetic,
        confidence: ProfilingConfidence::High,
        sample_count: 2,
        sampling_period_nanos: Some(10_000_000),
        stack_frames,
        process: None,
        container: None,
        kubernetes: None,
        thread_id: None,
        thread_name: None,
        attributes: vec![],
    }
}

trait RawProfileSampleExt {
    fn with_attributes(
        self,
        attributes: Vec<e_navigator_signals::ProfilingAttribute>,
    ) -> RawProfileSample;
}

impl RawProfileSampleExt for RawProfileSample {
    fn with_attributes(
        mut self,
        attributes: Vec<e_navigator_signals::ProfilingAttribute>,
    ) -> RawProfileSample {
        self.attributes = attributes;
        self
    }
}

fn frame(symbol: Option<String>) -> RawProfileFrame {
    RawProfileFrame {
        symbol,
        module: Some("checkout".to_string()),
        file: None,
        line: None,
    }
}
