use e_navigator_core::{Generator, Signal};
use e_navigator_generators::ProfilingGenerator;
use e_navigator_signals::{
    ContainerContext, KubernetesContext, MetricAggregationWindow, NetworkProcessIdentity,
    NodeCpuObservation, ProfileSampleObservation, ProfilingAttribute, ProfilingConfidence,
    ProfilingCorrelationKind, ProfilingFrame, ProfilingKind, SignalEnvelope, SignalPayload,
};
use std::collections::BTreeMap;
use tokio::sync::mpsc;

#[tokio::test]
async fn synthetic_cpu_sample_generates_profiling_window() {
    let generator = ProfilingGenerator::with_limits(8, 16, 8, 1_000_000_000);
    let outputs = observe(&generator, &sample_signal(1_500_000_000, Some(context()))).await;

    assert_eq!(outputs.len(), 1);
    assert_eq!(outputs[0].kind(), "profiling_session_observation");
    let SignalPayload::ProfilingSessionObservation(window) = &outputs[0].payload else {
        panic!("expected profiling session");
    };
    assert_eq!(window.profiling_kind, ProfilingKind::Cpu);
    assert_eq!(window.correlation_kind, ProfilingCorrelationKind::Synthetic);
    assert_eq!(window.confidence, ProfilingConfidence::High);
    assert_eq!(window.observed_sample_count, 2);
    assert_eq!(window.distinct_stack_count, 1);
    assert_eq!(window.window.start_unix_nanos, 1_000_000_000);
    assert_eq!(window.window.end_unix_nanos, 2_000_000_000);
    assert_eq!(window.source, "source.synthetic_profile");
    assert_eq!(window.process.as_ref().expect("process").pid, 42);
    assert_eq!(
        window
            .kubernetes
            .as_ref()
            .expect("kubernetes")
            .container_name
            .as_deref(),
        Some("checkout")
    );
}

#[tokio::test]
async fn missing_attribution_emits_structured_warning() {
    let generator = ProfilingGenerator::with_limits(8, 16, 8, 1_000_000_000);
    let outputs = observe(&generator, &sample_signal(1_500_000_000, None)).await;

    assert!(outputs.iter().any(|signal| {
        matches!(
            &signal.payload,
            SignalPayload::ProfilingWarningObservation(warning)
                if warning.warning_type == "missing_attribution"
        )
    }));
}

#[tokio::test]
async fn raw_resource_cpu_metric_does_not_create_profiling_output() {
    let generator = ProfilingGenerator::default();
    let signal = SignalEnvelope::node_cpu_observation(
        "source.host_resource",
        Some("node-a".to_string()),
        NodeCpuObservation {
            metric_name: "system.cpu.time".to_string(),
            unit: "ns".to_string(),
            timestamp_unix_nanos: 2,
            window: MetricAggregationWindow {
                start_unix_nanos: 1,
                end_unix_nanos: 2,
            },
            user_nanos: 10,
            system_nanos: 10,
            idle_nanos: 80,
            iowait_nanos: 0,
            steal_nanos: 0,
            runnable_tasks: Some(1),
            blocked_tasks: Some(0),
        },
    );

    assert!(observe(&generator, &signal).await.is_empty());
}

#[tokio::test]
async fn duplicate_samples_are_suppressed() {
    let generator = ProfilingGenerator::with_limits(8, 16, 8, 1_000_000_000);
    let signal = sample_signal(1_500_000_000, Some(context()));

    assert_eq!(observe(&generator, &signal).await.len(), 1);
    assert!(observe(&generator, &signal).await.is_empty());
}

#[tokio::test]
async fn aggregation_is_deterministic() {
    let generator = ProfilingGenerator::with_limits(8, 16, 8, 1_000_000_000);
    let first = observe(
        &generator,
        &sample_signal_with_stack(1_500_000_000, "stack:a", Some(context())),
    )
    .await;
    let second = observe(
        &generator,
        &sample_signal_with_stack(1_600_000_000, "stack:b", Some(context())),
    )
    .await;

    let SignalPayload::ProfilingSessionObservation(first_window) = &first[0].payload else {
        panic!("expected first profiling session");
    };
    let SignalPayload::ProfilingSessionObservation(second_window) = &second[0].payload else {
        panic!("expected second profiling session");
    };

    assert_eq!(first_window.profile_id, second_window.profile_id);
    assert_eq!(second_window.observed_sample_count, 4);
    assert_eq!(second_window.distinct_stack_count, 2);
}

#[tokio::test]
async fn bounded_state_evicts_old_windows_after_limit() {
    let generator = ProfilingGenerator::with_limits(1, 16, 8, 1_000_000_000);

    assert_eq!(
        observe(
            &generator,
            &sample_signal_with_stack(1_500_000_000, "stack:a", Some(context())),
        )
        .await
        .len(),
        1
    );
    assert_eq!(
        observe(
            &generator,
            &sample_signal_with_stack(2_500_000_000, "stack:b", Some(context())),
        )
        .await
        .len(),
        1
    );
    let recreated = observe(
        &generator,
        &sample_signal_with_stack(1_600_000_000, "stack:c", Some(context())),
    )
    .await;
    let SignalPayload::ProfilingSessionObservation(window) = &recreated[0].payload else {
        panic!("expected recreated profiling session");
    };
    assert_eq!(window.observed_sample_count, 2);
    assert_eq!(window.distinct_stack_count, 1);
}

#[tokio::test]
async fn preserves_attribution_from_original_sample() {
    let generator = ProfilingGenerator::with_limits(8, 16, 8, 1_000_000_000);
    let outputs = observe(&generator, &sample_signal(1_500_000_000, Some(context()))).await;
    let SignalPayload::ProfilingSessionObservation(window) = &outputs[0].payload else {
        panic!("expected profiling session");
    };

    assert_eq!(outputs[0].host.as_deref(), Some("node-a"));
    assert_eq!(
        window
            .container
            .as_ref()
            .expect("container")
            .runtime
            .as_deref(),
        Some("containerd")
    );
    assert_eq!(
        window.process.as_ref().expect("process").command,
        "checkout-api"
    );
}

#[tokio::test]
async fn later_attributed_samples_do_not_merge_with_unattributed_windows() {
    let generator = ProfilingGenerator::with_limits(8, 16, 8, 1_000_000_000);

    let first = observe(
        &generator,
        &sample_signal_with_stack(1_500_000_000, "stack:a", None),
    )
    .await;
    let second = observe(
        &generator,
        &sample_signal_with_stack(1_600_000_000, "stack:b", Some(context())),
    )
    .await;

    let SignalPayload::ProfilingSessionObservation(first_window) = &first[0].payload else {
        panic!("expected first profiling session");
    };
    let SignalPayload::ProfilingSessionObservation(second_window) = &second[0].payload else {
        panic!("expected second profiling session");
    };
    assert!(first_window.container.is_none());
    assert_eq!(
        second_window
            .container
            .as_ref()
            .expect("container")
            .container_id,
        "0123456789abcdef"
    );
    assert_ne!(first_window.profile_id, second_window.profile_id);
    assert_eq!(second_window.observed_sample_count, 2);
    assert_eq!(second_window.distinct_stack_count, 1);
}

#[tokio::test]
async fn workload_identity_separates_processless_profile_windows() {
    let generator = ProfilingGenerator::with_limits(8, 16, 8, 1_000_000_000);
    let first_context = context();
    let mut second_context = context();
    second_context.0.container_id = "fedcba9876543210".to_string();
    second_context.1.namespace = "payments".to_string();
    second_context.1.pod_uid = Some("pod-uid-b".to_string());
    second_context.1.container_name = Some("payments".to_string());

    let mut first_signal = sample_signal_with_stack(1_500_000_000, "stack:a", Some(first_context));
    let mut second_signal =
        sample_signal_with_stack(1_600_000_000, "stack:b", Some(second_context));
    clear_process(&mut first_signal);
    clear_process(&mut second_signal);

    let first = observe(&generator, &first_signal).await;
    let second = observe(&generator, &second_signal).await;

    let SignalPayload::ProfilingSessionObservation(first_window) = &first[0].payload else {
        panic!("expected first profiling session");
    };
    let SignalPayload::ProfilingSessionObservation(second_window) = &second[0].payload else {
        panic!("expected second profiling session");
    };
    assert_ne!(first_window.profile_id, second_window.profile_id);
    assert_eq!(first_window.observed_sample_count, 2);
    assert_eq!(second_window.observed_sample_count, 2);
}

#[tokio::test]
async fn profile_id_distinguishes_missing_pid_from_pid_zero() {
    let generator = ProfilingGenerator::with_limits(8, 16, 8, 1_000_000_000);
    let mut processless = sample_signal_with_stack(1_500_000_000, "stack:a", None);
    let mut pid_zero = sample_signal_with_stack(1_600_000_000, "stack:b", None);
    clear_process(&mut processless);
    set_pid(&mut pid_zero, 0);

    let first = observe(&generator, &processless).await;
    let second = observe(&generator, &pid_zero).await;

    let SignalPayload::ProfilingSessionObservation(first_window) = &first[0].payload else {
        panic!("expected first profiling session");
    };
    let SignalPayload::ProfilingSessionObservation(second_window) = &second[0].payload else {
        panic!("expected second profiling session");
    };
    assert_ne!(first_window.profile_id, second_window.profile_id);
}

#[tokio::test]
async fn per_window_stack_and_sample_counts_are_bounded() {
    let generator = ProfilingGenerator::with_limits(8, 16, 8, 1_000_000_000);

    let mut last = Vec::new();
    for index in 0..70 {
        last = observe(
            &generator,
            &sample_signal_with_stack(
                1_500_000_000 + index,
                &format!("stack:{index:016x}"),
                Some(context()),
            ),
        )
        .await;
    }

    let SignalPayload::ProfilingSessionObservation(window) = &last[0].payload else {
        panic!("expected profiling session");
    };
    assert_eq!(window.distinct_stack_count, 64);
    assert_eq!(window.observed_sample_count, 64);
    assert_eq!(window.dropped_sample_count, 76);
}

#[tokio::test]
async fn duplicate_suppression_distinguishes_thread_and_sample_count() {
    let generator = ProfilingGenerator::with_limits(8, 16, 8, 1_000_000_000);
    let first = sample_signal_with_stack(1_500_000_000, "stack:a", Some(context()));
    let mut second = sample_signal_with_stack(1_500_000_000, "stack:a", Some(context()));
    if let SignalPayload::ProfileSampleObservation(sample) = &mut second.payload {
        sample.thread_id = Some(99);
        sample.sample_count = 3;
    }

    assert_eq!(observe(&generator, &first).await.len(), 1);
    let outputs = observe(&generator, &second).await;
    let SignalPayload::ProfilingSessionObservation(window) = &outputs[0].payload else {
        panic!("expected profiling session");
    };
    assert_eq!(window.observed_sample_count, 5);
}

async fn observe(generator: &ProfilingGenerator, signal: &SignalEnvelope) -> Vec<SignalEnvelope> {
    let (tx, mut rx) = mpsc::channel(8);
    generator
        .observe(signal, &tx)
        .await
        .expect("generator observes");
    drop(tx);
    let mut outputs = Vec::new();
    while let Some(output) = rx.recv().await {
        outputs.push(output);
    }
    outputs
}

fn sample_signal(
    timestamp_unix_nanos: u64,
    attribution: Option<(ContainerContext, KubernetesContext)>,
) -> SignalEnvelope {
    sample_signal_with_stack(timestamp_unix_nanos, "stack:0123456789abcdef", attribution)
}

fn sample_signal_with_stack(
    timestamp_unix_nanos: u64,
    stack_id: &str,
    attribution: Option<(ContainerContext, KubernetesContext)>,
) -> SignalEnvelope {
    let (container, kubernetes) = attribution
        .map(|(container, kubernetes)| (Some(container), Some(kubernetes)))
        .unwrap_or((None, None));
    SignalEnvelope::profile_sample_observation(
        "source.synthetic_profile",
        Some("node-a".to_string()),
        ProfileSampleObservation {
            timestamp_unix_nanos,
            profiling_kind: ProfilingKind::Cpu,
            correlation_kind: ProfilingCorrelationKind::Synthetic,
            confidence: ProfilingConfidence::High,
            sample_count: 2,
            sampling_period_nanos: Some(10_000_000),
            stack_id: stack_id.to_string(),
            stack_frames: vec![ProfilingFrame {
                symbol: Some("checkout::handler".to_string()),
                module: Some("checkout".to_string()),
                file: None,
                line: None,
            }],
            process: Some(NetworkProcessIdentity {
                pid: 42,
                ppid: Some(1),
                uid: Some(1000),
                command: "checkout-api".to_string(),
                executable: Some("/app/checkout-api".to_string()),
            }),
            container,
            kubernetes,
            thread_id: None,
            thread_name: None,
            attributes: vec![ProfilingAttribute {
                key: "profiling.synthetic.fixture".to_string(),
                value: "cpu_sample".to_string(),
            }],
        },
    )
}

fn clear_process(signal: &mut SignalEnvelope) {
    let SignalPayload::ProfileSampleObservation(sample) = &mut signal.payload else {
        panic!("expected profile sample");
    };
    sample.process = None;
}

fn set_pid(signal: &mut SignalEnvelope, pid: u32) {
    let SignalPayload::ProfileSampleObservation(sample) = &mut signal.payload else {
        panic!("expected profile sample");
    };
    sample.process.as_mut().expect("process").pid = pid;
}

fn context() -> (ContainerContext, KubernetesContext) {
    (
        ContainerContext {
            container_id: "0123456789abcdef".to_string(),
            runtime: Some("containerd".to_string()),
        },
        KubernetesContext {
            namespace: "default".to_string(),
            pod_name: "checkout-123".to_string(),
            pod_uid: Some("pod-uid".to_string()),
            container_name: Some("checkout".to_string()),
            node_name: Some("node-a".to_string()),
            labels: BTreeMap::from([("app".to_string(), "checkout".to_string())]),
        },
    )
}
