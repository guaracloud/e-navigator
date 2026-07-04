use e_navigator_profiling::model::{
    NormalizationLimits, RawProfileFrame, RawProfileSample, parse_profile_fixture,
};
use e_navigator_signals::{
    ContainerContext, KubernetesContext, ProfilingAttribute, ProfilingConfidence,
    ProfilingCorrelationKind, ProfilingKind, SignalEnvelope,
};

pub(super) fn signals(
    host: Option<String>,
    container: ContainerContext,
    kubernetes: KubernetesContext,
    started: u64,
) -> Vec<SignalEnvelope> {
    let limits = NormalizationLimits {
        max_frames_per_stack: 4,
        max_symbol_bytes: 64,
        max_module_bytes: 64,
        max_file_bytes: 64,
        max_attributes: 8,
        max_attribute_key_bytes: 64,
        max_attribute_value_bytes: 256,
        max_samples_per_window: 128,
        max_fixture_bytes: 1024 * 1024,
    };
    let process = super::process_identity();
    let mut signals = Vec::new();
    for sample in [
        RawProfileSample {
            timestamp_unix_nanos: started,
            profiling_kind: ProfilingKind::Cpu,
            correlation_kind: ProfilingCorrelationKind::Synthetic,
            confidence: ProfilingConfidence::High,
            sample_count: 2,
            sampling_period_nanos: Some(10_000_000),
            stack_frames: vec![
                raw_profile_frame(
                    Some("synthetic_api::checkout_handler"),
                    Some("synthetic-api"),
                ),
                raw_profile_frame(Some("tokio::runtime::park"), Some("tokio")),
            ],
            process: Some(process.clone()),
            container: Some(container.clone()),
            kubernetes: Some(kubernetes.clone()),
            thread_id: Some(7),
            thread_name: Some("synthetic-profile-worker".to_string()),
            attributes: vec![ProfilingAttribute {
                key: "profiling.synthetic.fixture".to_string(),
                value: "cpu_sample".to_string(),
            }],
        },
        RawProfileSample {
            timestamp_unix_nanos: started.saturating_add(1),
            profiling_kind: ProfilingKind::Cpu,
            correlation_kind: ProfilingCorrelationKind::Synthetic,
            confidence: ProfilingConfidence::Medium,
            sample_count: 1,
            sampling_period_nanos: Some(10_000_000),
            stack_frames: vec![RawProfileFrame {
                symbol: None,
                module: Some("libunknown.so".to_string()),
                file: None,
                line: None,
                module_offset: None,
            }],
            process: Some(process.clone()),
            container: Some(container.clone()),
            kubernetes: Some(kubernetes.clone()),
            thread_id: None,
            thread_name: None,
            attributes: vec![ProfilingAttribute {
                key: "profiling.synthetic.fixture".to_string(),
                value: "missing_symbols".to_string(),
            }],
        },
        RawProfileSample {
            timestamp_unix_nanos: started.saturating_add(2),
            profiling_kind: ProfilingKind::Cpu,
            correlation_kind: ProfilingCorrelationKind::Synthetic,
            confidence: ProfilingConfidence::Medium,
            sample_count: 1,
            sampling_period_nanos: Some(10_000_000),
            stack_frames: (0..8)
                .map(|index| {
                    raw_profile_frame(
                        Some(&format!("synthetic_api::deep_frame_{index}")),
                        Some("synthetic-api"),
                    )
                })
                .collect(),
            process: Some(process.clone()),
            container: Some(container.clone()),
            kubernetes: Some(kubernetes.clone()),
            thread_id: None,
            thread_name: None,
            attributes: vec![ProfilingAttribute {
                key: "profiling.synthetic.fixture".to_string(),
                value: "oversized_stack".to_string(),
            }],
        },
    ] {
        if let Ok(sample) = sample.normalize(&limits) {
            signals.push(SignalEnvelope::profile_sample_observation(
                super::source_name(),
                host.clone(),
                sample,
            ));
        }
    }

    if let Err(err) = parse_profile_fixture(
        r#"{"timestamp_unix_nanos":1,"profiling_kind":"cpu","correlation_kind":"synthetic"}"#,
        &limits,
    ) {
        signals.push(SignalEnvelope::profiling_warning_observation(
            super::source_name(),
            host,
            e_navigator_signals::ProfilingWarningObservation {
                warning_type: "malformed_profile_fixture".to_string(),
                message: format!("synthetic profile fixture rejected: {err}"),
                timestamp_unix_nanos: started.saturating_add(3),
                source_signal_kind: "profile_sample_observation".to_string(),
                source_module: super::source_name().to_string(),
                profiling_kind: ProfilingKind::Unknown,
                correlation_kind: ProfilingCorrelationKind::Synthetic,
                confidence: ProfilingConfidence::Low,
                process: Some(process),
                container: Some(container),
                kubernetes: Some(kubernetes),
                attributes: vec![ProfilingAttribute {
                    key: "profiling.synthetic.fixture".to_string(),
                    value: "malformed_low_confidence".to_string(),
                }],
            },
        ));
    }

    signals
}

fn raw_profile_frame(symbol: Option<&str>, module: Option<&str>) -> RawProfileFrame {
    RawProfileFrame {
        symbol: symbol.map(ToString::to_string),
        module: module.map(ToString::to_string),
        file: None,
        line: None,
        module_offset: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use e_navigator_signals::SignalPayload;

    #[test]
    fn synthetic_profile_fixtures_cover_phase9_foundation_cases() {
        let (container, kubernetes) = crate::synthetic::synthetic_attribution();
        let signals = signals(Some("node-a".to_string()), container, kubernetes, 1_000);

        assert!(signals.iter().any(|signal| {
            matches!(
                &signal.payload,
                SignalPayload::ProfileSampleObservation(sample)
                    if signal.source == "source.synthetic_exec"
                        && sample.profiling_kind == e_navigator_signals::ProfilingKind::Cpu
                        && sample.attributes.iter().any(|attribute| attribute.key == "profiling.synthetic.fixture"
                            && attribute.value == "cpu_sample")
                        && !sample.stack_frames.is_empty()
                        && sample.stack_frames.iter().all(|frame| frame.symbol.is_some())
            )
        }));
        assert!(signals.iter().any(|signal| {
            matches!(
                &signal.payload,
                SignalPayload::ProfileSampleObservation(sample)
                    if sample.attributes.iter().any(|attribute| attribute.key == "profiling.synthetic.fixture"
                        && attribute.value == "missing_symbols")
                        && sample.stack_frames.iter().any(|frame| frame.symbol.is_none())
            )
        }));
        assert!(signals.iter().any(|signal| {
            matches!(
                &signal.payload,
                SignalPayload::ProfileSampleObservation(sample)
                    if sample.attributes.iter().any(|attribute| attribute.key == "profiling.synthetic.fixture"
                        && attribute.value == "oversized_stack")
                        && sample.stack_frames.len() == 4
                        && sample.attributes.iter().any(|attribute| attribute.key == "profiling.stack.truncated")
            )
        }));
        assert!(signals.iter().any(|signal| {
            matches!(
                &signal.payload,
                SignalPayload::ProfilingWarningObservation(warning)
                    if warning.warning_type == "malformed_profile_fixture"
            )
        }));
    }
}
