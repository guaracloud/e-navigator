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

fn frame(symbol: Option<String>) -> RawProfileFrame {
    RawProfileFrame {
        symbol,
        module: Some("checkout".to_string()),
        file: None,
        line: None,
    }
}
