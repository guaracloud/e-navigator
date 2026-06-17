use e_navigator_core::{CoreError, Generator, Signal};
use e_navigator_signals::{
    CgroupCpuObservation, CgroupFileDescriptorObservation, CgroupMemoryObservation,
    CgroupPidsObservation, CgroupResourceContext, ContainerContext, ExecEvent, KubernetesContext,
    MetricAggregationWindow, NodeCpuObservation, NodeDiskIoObservation, NodeFilesystemObservation,
    NodeLoadObservation, NodeMemoryObservation, ProcessResourceContext, ProcessResourceObservation,
    ResourceCounterMetric, ResourceGaugeMetric, SignalEnvelope, SignalPayload,
};
use std::collections::BTreeMap;
use tokio::sync::mpsc;

use crate::ResourceMetricsGenerator;

#[tokio::test]
async fn handles_cpu_counter_deltas_and_saturation_gauges() {
    let generator = ResourceMetricsGenerator::with_limits(64);
    let first = node_cpu(1_000, 10, 5, 100);
    let second = node_cpu(2_000, 13, 7, 102);

    let first_metrics = collect(&generator, &first).await;
    assert_metric_gauge(&first_metrics, "system.cpu.saturation.runnable", 3);
    assert_metric_gauge(&first_metrics, "system.cpu.saturation.blocked", 1);
    let metrics = collect(&generator, &second).await;

    assert_metric_counter(&metrics, "system.cpu.time", "user", 30_000_000);
    assert_metric_counter(&metrics, "system.cpu.time", "system", 20_000_000);
    assert_metric_counter(&metrics, "system.cpu.time", "idle", 20_000_000);
    let counter = metrics
        .iter()
        .find_map(resource_counter)
        .expect("counter metric");
    assert_eq!(counter.window.start_unix_nanos, 1_000);
    assert_eq!(counter.window.end_unix_nanos, 2_000);
}

#[tokio::test]
async fn emits_milli_load_gauges_with_explicit_scale() {
    let generator = ResourceMetricsGenerator::with_limits(64);
    let signal = SignalEnvelope::node_load_observation(
        "source.host_resource",
        Some("node-a".to_string()),
        NodeLoadObservation {
            metric_name: "system.cpu.load_average.1m".to_string(),
            unit: "1".to_string(),
            timestamp_unix_nanos: 2_000,
            window: window(1_000, 2_000),
            load1: 0.25,
            load5: 1.5,
            load15: 2.75,
            runnable_tasks: Some(2),
            total_tasks: Some(200),
        },
    );

    let metrics = collect(&generator, &signal).await;

    assert_metric_gauge(&metrics, "system.cpu.load_average.milli", 250);
    assert_metric_gauge(&metrics, "system.cpu.load_average.milli", 1_500);
    let gauge = metrics.iter().find_map(resource_gauge).expect("load gauge");
    assert_eq!(gauge.unit, "m1");
    assert!(gauge.attributes.iter().any(|attribute| {
        attribute.key == "window" && ["1m", "5m", "15m"].contains(&attribute.value.as_str())
    }));
}

#[tokio::test]
async fn emits_memory_and_filesystem_gauges() {
    let generator = ResourceMetricsGenerator::with_limits(64);
    let memory = SignalEnvelope::node_memory_observation(
        "source.host_resource",
        Some("node-a".to_string()),
        NodeMemoryObservation {
            metric_name: "system.memory.usage".to_string(),
            unit: "By".to_string(),
            timestamp_unix_nanos: 2_000,
            window: window(1_000, 2_000),
            mem_total_bytes: 8_192,
            mem_available_bytes: Some(4_096),
            mem_free_bytes: Some(2_048),
            swap_total_bytes: Some(1_024),
            swap_free_bytes: Some(512),
        },
    );
    let filesystem = SignalEnvelope::node_filesystem_observation(
        "source.host_resource",
        Some("node-a".to_string()),
        NodeFilesystemObservation {
            metric_name: "system.filesystem.usage".to_string(),
            unit: "By".to_string(),
            timestamp_unix_nanos: 2_000,
            window: window(1_000, 2_000),
            mount_point: "/var/lib/kubelet".to_string(),
            filesystem_type: Some("ext4".to_string()),
            total_bytes: 1_000,
            available_bytes: 250,
        },
    );

    let mut metrics = collect(&generator, &memory).await;
    metrics.extend(collect(&generator, &filesystem).await);

    assert_metric_gauge(&metrics, "system.memory.limit", 8_192);
    assert_metric_gauge(&metrics, "system.memory.available", 4_096);
    assert_metric_gauge(&metrics, "system.filesystem.usage", 750);
    assert_metric_gauge(&metrics, "system.filesystem.available", 250);
}

#[tokio::test]
async fn emits_disk_io_counter_deltas() {
    let generator = ResourceMetricsGenerator::with_limits(64);
    let first = disk_io(1_000, 10, 20, 4_096, 8_192);
    let second = disk_io(2_000, 14, 25, 8_192, 16_384);

    assert!(collect(&generator, &first).await.is_empty());
    let metrics = collect(&generator, &second).await;

    assert_metric_counter(&metrics, "system.disk.io", "read", 4_096);
    assert_metric_counter(&metrics, "system.disk.io", "write", 8_192);
    assert_metric_counter(&metrics, "system.disk.operations", "read", 4);
    assert_metric_counter(&metrics, "system.disk.operations", "write", 5);
}

#[tokio::test]
async fn emits_cgroup_cpu_delta_and_memory_metrics_with_context() {
    let generator = ResourceMetricsGenerator::with_limits(64);
    let cgroup = CgroupResourceContext {
        cgroup_path: "/kubepods.slice/pod123/container.scope".to_string(),
        container: None,
        kubernetes: None,
    };
    let first = cgroup_cpu(cgroup.clone(), 1_000, 100);
    let second = cgroup_cpu(cgroup.clone(), 2_000, 160);
    let memory = SignalEnvelope::cgroup_memory_observation(
        "source.host_resource",
        Some("node-a".to_string()),
        CgroupMemoryObservation {
            metric_name: "container.memory.usage".to_string(),
            unit: "By".to_string(),
            timestamp_unix_nanos: 2_000,
            window: window(1_000, 2_000),
            cgroup,
            current_bytes: Some(12_000),
            peak_bytes: Some(18_000),
            max_bytes: Some(64_000),
        },
    );

    assert!(collect(&generator, &first).await.is_empty());
    let mut metrics = collect(&generator, &second).await;
    metrics.extend(collect(&generator, &memory).await);

    assert_metric_counter(&metrics, "container.cpu.time", "total", 60_000);
    assert_metric_counter(&metrics, "container.cpu.throttling.periods", "throttled", 6);
    assert_metric_gauge(&metrics, "container.memory.usage", 12_000);
    assert_metric_gauge(&metrics, "container.memory.limit", 64_000);
}

#[tokio::test]
async fn emits_cgroup_pids_and_fd_gauges() {
    let generator = ResourceMetricsGenerator::with_limits(64);
    let cgroup = CgroupResourceContext {
        cgroup_path: "/kubepods.slice/pod123/container.scope".to_string(),
        container: None,
        kubernetes: None,
    };
    let pids = SignalEnvelope::cgroup_pids_observation(
        "source.host_resource",
        Some("node-a".to_string()),
        CgroupPidsObservation {
            metric_name: "container.process.count".to_string(),
            unit: "{process}".to_string(),
            timestamp_unix_nanos: 2_000,
            window: window(1_000, 2_000),
            cgroup: cgroup.clone(),
            process_count: Some(3),
            thread_count: Some(9),
            max_processes: Some(128),
        },
    );
    let fds = SignalEnvelope::cgroup_file_descriptor_observation(
        "source.host_resource",
        Some("node-a".to_string()),
        CgroupFileDescriptorObservation {
            metric_name: "container.file_descriptor.count".to_string(),
            unit: "{file_descriptor}".to_string(),
            timestamp_unix_nanos: 2_000,
            window: window(1_000, 2_000),
            cgroup,
            open_fds: Some(64),
            socket_count: Some(12),
        },
    );

    let mut metrics = collect(&generator, &pids).await;
    metrics.extend(collect(&generator, &fds).await);

    assert_metric_gauge(&metrics, "container.process.count", 3);
    assert_metric_gauge(&metrics, "container.thread.count", 9);
    assert_metric_gauge(&metrics, "container.process.limit", 128);
    assert_metric_gauge(&metrics, "container.file_descriptor.count", 64);
    assert_metric_gauge(&metrics, "container.socket.count", 12);
}

#[tokio::test]
async fn preserves_process_attribution_and_emits_process_cpu_deltas() {
    let generator = ResourceMetricsGenerator::with_limits(64);
    let first = process_signal(2_000, 500);
    let second = process_signal(3_000, 900);

    let first_metrics = collect(&generator, &first).await;
    assert_metric_gauge(&first_metrics, "process.memory.usage", 4_096);
    assert_metric_gauge(&first_metrics, "process.open_file_descriptor.count", 12);
    let metrics = collect(&generator, &second).await;

    assert_metric_counter(&metrics, "process.cpu.time", "total", 400);
    let Some(resource_metric) = first_metrics.iter().find_map(resource_gauge) else {
        panic!("expected process gauge");
    };
    assert_eq!(
        resource_metric
            .process
            .as_ref()
            .and_then(|process| process.container.as_ref())
            .map(|container| container.container_id.as_str()),
        Some("container-a")
    );
}

fn process_signal(timestamp: u64, cpu_time_nanos: u64) -> SignalEnvelope {
    SignalEnvelope::process_resource_observation(
        "source.host_resource",
        Some("node-a".to_string()),
        ProcessResourceObservation {
            metric_name: "process.resource".to_string(),
            unit: "1".to_string(),
            timestamp_unix_nanos: timestamp,
            window: window(timestamp.saturating_sub(1_000), timestamp),
            process: ProcessResourceContext {
                pid: 42,
                ppid: Some(1),
                uid: Some(1000),
                command: "api".to_string(),
                executable: Some("/app/api".to_string()),
                container: Some(e_navigator_signals::ContainerContext {
                    container_id: "container-a".to_string(),
                    runtime: Some("containerd".to_string()),
                }),
                kubernetes: Some(e_navigator_signals::KubernetesContext {
                    namespace: "default".to_string(),
                    pod_name: "api-123".to_string(),
                    pod_uid: Some("pod-uid".to_string()),
                    container_name: Some("api".to_string()),
                    node_name: Some("node-a".to_string()),
                    labels: Default::default(),
                }),
            },
            cpu_time_nanos: Some(cpu_time_nanos),
            memory_rss_bytes: Some(4_096),
            virtual_memory_bytes: None,
            open_fds: Some(12),
            socket_count: Some(2),
            thread_count: Some(4),
        },
    )
}

#[tokio::test]
async fn deterministic_duplicate_and_bounded_state_behavior() {
    let generator = ResourceMetricsGenerator::with_limits(2);
    let memory_a = memory_signal("node-a", 2_000, 8_192, 4_096);
    let memory_b = memory_signal("node-b", 2_000, 16_384, 8_192);

    let first = collect(&generator, &memory_a).await;
    let duplicate = collect(&generator, &memory_a).await;
    let after_evicting_stale_key = collect(&generator, &memory_b).await;

    assert!(!first.is_empty());
    assert!(duplicate.is_empty());
    assert!(!after_evicting_stale_key.is_empty());
    let names = first
        .iter()
        .map(|signal| signal.kind().to_string())
        .collect::<Vec<_>>();
    assert_eq!(
        names,
        vec!["resource_gauge_metric", "resource_gauge_metric"]
    );
}

#[tokio::test]
async fn unsupported_payloads_emit_no_resource_metrics() {
    let generator = ResourceMetricsGenerator::with_limits(64);
    let signal = SignalEnvelope::exec(
        "source.synthetic",
        Some("node-a".to_string()),
        ExecEvent {
            pid: 42,
            ppid: Some(1),
            uid: Some(1000),
            command: "bash".to_string(),
            executable: Some("/usr/bin/bash".to_string()),
            arguments: vec!["bash".to_string()],
            cgroup_id: Some(7),
            timestamp_unix_nanos: 1_000,
            container: None,
            kubernetes: None,
        },
    );

    assert!(collect(&generator, &signal).await.is_empty());
}

#[tokio::test]
async fn counter_decreases_update_state_without_emitting_delta() {
    let generator = ResourceMetricsGenerator::with_limits(64);

    assert!(
        collect(&generator, &disk_io(1_000, 10, 20, 100, 200))
            .await
            .is_empty()
    );
    assert!(
        collect(&generator, &disk_io(2_000, 9, 18, 90, 180))
            .await
            .is_empty()
    );
    let metrics = collect(&generator, &disk_io(3_000, 11, 21, 120, 220)).await;

    assert_metric_counter(&metrics, "system.disk.io", "read", 30);
    assert_metric_counter(&metrics, "system.disk.io", "write", 40);
    assert_metric_counter(&metrics, "system.disk.operations", "read", 2);
    assert_metric_counter(&metrics, "system.disk.operations", "write", 3);
    let counter = metrics
        .iter()
        .find_map(resource_counter)
        .expect("counter after reset");
    assert_eq!(counter.window.start_unix_nanos, 2_000);
    assert_eq!(counter.window.end_unix_nanos, 3_000);
}

#[tokio::test]
async fn process_metrics_keep_bounded_metric_attributes() {
    let generator = ResourceMetricsGenerator::with_limits(64);
    let metrics = collect(&generator, &process_signal(2_000, 500)).await;

    let memory = metrics
        .iter()
        .find_map(resource_gauge)
        .filter(|metric| metric.metric_name == "process.memory.usage")
        .expect("process memory metric");
    assert_eq!(attribute_pairs(memory), vec![("state", "rss")]);
    assert_eq!(
        memory
            .process
            .as_ref()
            .map(|process| process.command.as_str()),
        Some("api")
    );
}

#[tokio::test]
async fn cgroup_metrics_preserve_container_and_kubernetes_context() {
    let generator = ResourceMetricsGenerator::with_limits(64);
    let signal = SignalEnvelope::cgroup_memory_observation(
        "source.host_resource",
        Some("node-a".to_string()),
        CgroupMemoryObservation {
            metric_name: "container.memory.usage".to_string(),
            unit: "By".to_string(),
            timestamp_unix_nanos: 2_000,
            window: window(1_000, 2_000),
            cgroup: cgroup_context_with_attribution(),
            current_bytes: Some(12_000),
            peak_bytes: None,
            max_bytes: None,
        },
    );

    let metrics = collect(&generator, &signal).await;
    let memory = metrics
        .iter()
        .find_map(resource_gauge)
        .expect("cgroup memory metric");

    assert_eq!(
        memory
            .resource
            .container
            .as_ref()
            .map(|container| container.container_id.as_str()),
        Some("container-a")
    );
    assert_eq!(
        memory
            .resource
            .kubernetes
            .as_ref()
            .map(|kubernetes| kubernetes.namespace.as_str()),
        Some("default")
    );
    assert_eq!(
        memory
            .cgroup
            .as_ref()
            .and_then(|cgroup| cgroup.kubernetes.as_ref())
            .and_then(|kubernetes| kubernetes.labels.get("app"))
            .map(String::as_str),
        Some("api")
    );
}

#[tokio::test]
async fn bounded_state_eviction_order_is_deterministic() {
    let generator = ResourceMetricsGenerator::with_limits(2);

    assert_eq!(
        collect(&generator, &memory_signal("node-a", 2_000, 100, 50))
            .await
            .len(),
        2
    );
    assert_eq!(
        collect(&generator, &memory_signal("node-b", 3_000, 200, 100))
            .await
            .len(),
        2
    );
    let node_a_again = collect(&generator, &memory_signal("node-a", 4_000, 100, 51)).await;

    assert_metric_gauge(&node_a_again, "system.memory.limit", 100);
    assert_metric_gauge(&node_a_again, "system.memory.available", 51);
}

#[tokio::test]
async fn poisoned_state_lock_maps_to_module_failed_error() {
    let generator = ResourceMetricsGenerator::with_limits(64);
    let poison_target = std::panic::AssertUnwindSafe(|| {
        let _guard = generator.gauges.lock().expect("lock before poison");
        panic!("poison gauge lock");
    });
    assert!(std::panic::catch_unwind(poison_target).is_err());

    let error = collect_result(&generator, &memory_signal("node-a", 2_000, 100, 50))
        .await
        .expect_err("poisoned lock should fail");

    assert!(matches!(
        error,
        CoreError::ModuleFailed { module, message }
            if module == "generator.resource_metrics" && message == "state lock poisoned"
    ));
}

async fn collect(
    generator: &ResourceMetricsGenerator,
    signal: &SignalEnvelope,
) -> Vec<SignalEnvelope> {
    collect_result(generator, signal)
        .await
        .expect("generator observes")
}

async fn collect_result(
    generator: &ResourceMetricsGenerator,
    signal: &SignalEnvelope,
) -> Result<Vec<SignalEnvelope>, CoreError> {
    let (tx, mut rx) = mpsc::channel(16);
    generator.observe(signal, &tx).await?;
    drop(tx);
    let mut signals = Vec::new();
    while let Some(signal) = rx.recv().await {
        signals.push(signal);
    }
    Ok(signals)
}

fn node_cpu(timestamp: u64, user: u64, system: u64, idle: u64) -> SignalEnvelope {
    SignalEnvelope::node_cpu_observation(
        "source.host_resource",
        Some("node-a".to_string()),
        NodeCpuObservation {
            metric_name: "system.cpu.time".to_string(),
            unit: "ns".to_string(),
            timestamp_unix_nanos: timestamp,
            window: window(timestamp.saturating_sub(1_000), timestamp),
            user_nanos: user * 10_000_000,
            system_nanos: system * 10_000_000,
            idle_nanos: idle * 10_000_000,
            iowait_nanos: 0,
            steal_nanos: 0,
            runnable_tasks: Some(3),
            blocked_tasks: Some(1),
        },
    )
}

fn cgroup_cpu(cgroup: CgroupResourceContext, timestamp: u64, usage_micros: u64) -> SignalEnvelope {
    SignalEnvelope::cgroup_cpu_observation(
        "source.host_resource",
        Some("node-a".to_string()),
        CgroupCpuObservation {
            metric_name: "container.cpu.time".to_string(),
            unit: "ns".to_string(),
            timestamp_unix_nanos: timestamp,
            window: window(timestamp.saturating_sub(1_000), timestamp),
            cgroup,
            usage_nanos: Some(usage_micros * 1_000),
            user_nanos: None,
            system_nanos: None,
            throttled_periods: Some(usage_micros / 10),
            throttled_nanos: Some(usage_micros * 100),
        },
    )
}

fn disk_io(
    timestamp: u64,
    reads_completed: u64,
    writes_completed: u64,
    read_bytes: u64,
    written_bytes: u64,
) -> SignalEnvelope {
    SignalEnvelope::node_disk_io_observation(
        "source.host_resource",
        Some("node-a".to_string()),
        NodeDiskIoObservation {
            metric_name: "system.disk.io".to_string(),
            unit: "By".to_string(),
            timestamp_unix_nanos: timestamp,
            window: window(timestamp.saturating_sub(1_000), timestamp),
            device: "nvme0n1".to_string(),
            reads_completed,
            writes_completed,
            read_bytes,
            written_bytes,
        },
    )
}

fn memory_signal(host: &str, timestamp: u64, total: u64, available: u64) -> SignalEnvelope {
    SignalEnvelope::node_memory_observation(
        "source.host_resource",
        Some(host.to_string()),
        NodeMemoryObservation {
            metric_name: "system.memory.usage".to_string(),
            unit: "By".to_string(),
            timestamp_unix_nanos: timestamp,
            window: window(timestamp.saturating_sub(1_000), timestamp),
            mem_total_bytes: total,
            mem_available_bytes: Some(available),
            mem_free_bytes: None,
            swap_total_bytes: None,
            swap_free_bytes: None,
        },
    )
}

fn cgroup_context_with_attribution() -> CgroupResourceContext {
    let mut labels = BTreeMap::new();
    labels.insert("app".to_string(), "api".to_string());
    CgroupResourceContext {
        cgroup_path: "/kubepods.slice/pod123/container.scope".to_string(),
        container: Some(ContainerContext {
            container_id: "container-a".to_string(),
            runtime: Some("containerd".to_string()),
        }),
        kubernetes: Some(KubernetesContext {
            namespace: "default".to_string(),
            pod_name: "api-123".to_string(),
            pod_uid: Some("pod-uid".to_string()),
            container_name: Some("api".to_string()),
            node_name: Some("node-a".to_string()),
            labels,
        }),
    }
}

fn window(start_unix_nanos: u64, end_unix_nanos: u64) -> MetricAggregationWindow {
    MetricAggregationWindow {
        start_unix_nanos,
        end_unix_nanos,
    }
}

fn assert_metric_gauge(signals: &[SignalEnvelope], name: &str, value: i64) {
    assert!(
        signals.iter().any(|signal| {
            resource_gauge(signal)
                .map(|metric| metric.metric_name == name && metric.value == value)
                .unwrap_or(false)
        }),
        "missing gauge {name}={value}: {signals:#?}"
    );
}

fn assert_metric_counter(signals: &[SignalEnvelope], name: &str, state: &str, value: u64) {
    assert!(
        signals.iter().any(|signal| {
            resource_counter(signal)
                .map(|metric| {
                    metric.metric_name == name
                        && metric.value == value
                        && metric
                            .attributes
                            .iter()
                            .any(|attribute| attribute.key == "state" && attribute.value == state)
                })
                .unwrap_or(false)
        }),
        "missing counter {name}[state={state}]={value}: {signals:#?}"
    );
}

fn attribute_pairs(metric: &ResourceGaugeMetric) -> Vec<(&str, &str)> {
    metric
        .attributes
        .iter()
        .map(|attribute| (attribute.key.as_str(), attribute.value.as_str()))
        .collect()
}

fn resource_gauge(signal: &SignalEnvelope) -> Option<&ResourceGaugeMetric> {
    match &signal.payload {
        SignalPayload::ResourceGaugeMetric(metric) => Some(metric),
        _ => None,
    }
}

fn resource_counter(signal: &SignalEnvelope) -> Option<&ResourceCounterMetric> {
    match &signal.payload {
        SignalPayload::ResourceCounterMetric(metric) => Some(metric),
        _ => None,
    }
}
