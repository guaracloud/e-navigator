use super::{
    cgroup::parse_container_from_cgroup, cgroup_id::cgroup_path_id,
    kubernetes::KubernetesMetadataProvider, pid::is_expected_process_exit_race, *,
};
use async_trait::async_trait;
use e_navigator_core::{AttributionConfig, Generator, KubernetesAttributionConfig, Processor};
use e_navigator_generators::{
    DnsMetricsGenerator, NetworkMetricsGenerator, RequestCorrelationGenerator,
    ResourceMetricsGenerator, TraceCorrelationGenerator,
};
use e_navigator_signals::{
    ContainerContext, DependencyEdgeEvent, DependencyEndpoint, DnsQueryEvent, DnsQueryType,
    ExecEvent, KubernetesContext, NetworkAddressFamily, NetworkConnectionCloseEvent,
    NetworkConnectionOpenEvent, NetworkFlowDirection, NetworkFlowEndpoint, NetworkFlowSummaryEvent,
    NetworkProcessIdentity, NetworkProtocol, ProcessExitEvent, ProtocolKind,
    ProtocolRequestObservation, SignalEnvelope, SignalPayload, TraceConfidence,
    TraceCorrelationKind, TracePeerContext,
};
use std::{
    collections::{BTreeMap, VecDeque},
    fs, io,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{sync::mpsc, time::timeout};

#[derive(Debug)]
struct StaticKubernetesMetadataProvider {
    cache: KubernetesMetadataCache,
}

impl StaticKubernetesMetadataProvider {
    fn new(cache: KubernetesMetadataCache) -> Self {
        Self { cache }
    }
}

#[async_trait]
impl KubernetesMetadataProvider for StaticKubernetesMetadataProvider {
    async fn refresh(
        &self,
        _config: &e_navigator_core::KubernetesAttributionConfig,
    ) -> Result<KubernetesMetadataCache, String> {
        Ok(self.cache.clone())
    }
}

#[derive(Debug)]
struct SequencedKubernetesMetadataProvider {
    caches: Mutex<VecDeque<KubernetesMetadataCache>>,
}

impl SequencedKubernetesMetadataProvider {
    fn new(caches: impl IntoIterator<Item = KubernetesMetadataCache>) -> Self {
        Self {
            caches: Mutex::new(caches.into_iter().collect()),
        }
    }
}

#[derive(Debug)]
struct CountingKubernetesMetadataProvider {
    refreshes: Arc<Mutex<usize>>,
    cache: KubernetesMetadataCache,
}

impl CountingKubernetesMetadataProvider {
    fn new(refreshes: Arc<Mutex<usize>>, cache: KubernetesMetadataCache) -> Self {
        Self { refreshes, cache }
    }
}

#[derive(Debug)]
struct SlowKubernetesMetadataProvider {
    delay: Duration,
    cache: KubernetesMetadataCache,
}

impl SlowKubernetesMetadataProvider {
    fn new(delay: Duration, cache: KubernetesMetadataCache) -> Self {
        Self { delay, cache }
    }
}

#[async_trait]
impl KubernetesMetadataProvider for SlowKubernetesMetadataProvider {
    async fn refresh(
        &self,
        _config: &e_navigator_core::KubernetesAttributionConfig,
    ) -> Result<KubernetesMetadataCache, String> {
        tokio::time::sleep(self.delay).await;
        Ok(self.cache.clone())
    }
}

#[derive(Debug)]
struct FailingKubernetesMetadataProvider;

#[async_trait]
impl KubernetesMetadataProvider for FailingKubernetesMetadataProvider {
    async fn refresh(
        &self,
        _config: &e_navigator_core::KubernetesAttributionConfig,
    ) -> Result<KubernetesMetadataCache, String> {
        Err("api unavailable".to_string())
    }
}

#[async_trait]
impl KubernetesMetadataProvider for CountingKubernetesMetadataProvider {
    async fn refresh(
        &self,
        _config: &e_navigator_core::KubernetesAttributionConfig,
    ) -> Result<KubernetesMetadataCache, String> {
        *self.refreshes.lock().expect("refresh count lock") += 1;
        Ok(self.cache.clone())
    }
}

#[async_trait]
impl KubernetesMetadataProvider for SequencedKubernetesMetadataProvider {
    async fn refresh(
        &self,
        _config: &e_navigator_core::KubernetesAttributionConfig,
    ) -> Result<KubernetesMetadataCache, String> {
        Ok(self
            .caches
            .lock()
            .expect("cache sequence lock")
            .pop_front()
            .unwrap_or_default())
    }
}

#[tokio::test]
async fn processor_preserves_exec_event() {
    let processor = ContainerAttributionProcessor::new(Default::default());
    let signal = SignalEnvelope::exec(
        "source.test",
        None,
        ExecEvent {
            pid: 7,
            ppid: Some(1),
            uid: Some(1000),
            command: "sh".to_string(),
            executable: Some("/bin/sh".to_string()),
            arguments: vec!["sh".to_string()],
            cgroup_id: None,
            timestamp_unix_nanos: 99,
            container: None,
            kubernetes: None,
        },
    );

    let processed = processor
        .process(signal)
        .await
        .expect("processor succeeds")
        .expect("signal remains");

    assert!(matches!(
        processed.payload,
        e_navigator_signals::SignalPayload::Exec(_)
    ));
}

#[tokio::test]
async fn processor_preserves_existing_attribution_without_cgroup_id() {
    let processor = ContainerAttributionProcessor::new(Default::default());
    let signal = SignalEnvelope::exec(
        "source.test",
        Some("node-a".to_string()),
        ExecEvent {
            pid: 7,
            ppid: Some(1),
            uid: Some(1000),
            command: "sh".to_string(),
            executable: Some("/bin/sh".to_string()),
            arguments: vec!["sh".to_string()],
            cgroup_id: None,
            container: Some(ContainerContext {
                container_id: "container-a".to_string(),
                runtime: Some("containerd".to_string()),
            }),
            kubernetes: Some(KubernetesContext {
                namespace: "default".to_string(),
                pod_name: "pod-a".to_string(),
                pod_uid: Some("pod-uid-a".to_string()),
                container_name: Some("app".to_string()),
                node_name: Some("node-a".to_string()),
                labels: BTreeMap::new(),
            }),
            timestamp_unix_nanos: 99,
        },
    );

    let processed = processor
        .process(signal.clone())
        .await
        .expect("processor succeeds")
        .expect("signal remains");

    assert_eq!(processed, signal);
}

#[tokio::test]
async fn kubernetes_cache_miss_does_not_block_signal_processing() {
    let container_id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let processor = ContainerAttributionProcessor::with_cache_and_provider(
        AttributionConfig {
            kubernetes: KubernetesAttributionConfig {
                enabled: true,
                ..Default::default()
            },
            ..AttributionConfig::default()
        },
        KubernetesMetadataCache::default(),
        SlowKubernetesMetadataProvider::new(
            Duration::from_millis(150),
            KubernetesMetadataCache::from_contexts([(
                container_id.to_string(),
                kube_context("api"),
            )]),
        ),
    );

    let processed = timeout(
        Duration::from_millis(50),
        processor.process(exec_with_container(container_id)),
    )
    .await
    .expect("cache miss must not wait for refresh")
    .expect("processor succeeds")
    .expect("signal remains");

    let SignalPayload::Exec(event) = processed.payload else {
        panic!("expected exec payload");
    };
    assert!(event.kubernetes.is_none());

    tokio::time::sleep(Duration::from_millis(175)).await;
    let processed = processor
        .process(exec_with_container(container_id))
        .await
        .expect("processor succeeds")
        .expect("signal remains");
    let SignalPayload::Exec(event) = processed.payload else {
        panic!("expected exec payload");
    };
    assert_eq!(event.kubernetes.expect("kubernetes").pod_name, "api");
}

#[tokio::test]
async fn kubernetes_refresh_failure_preserves_stale_cache() {
    let container_id = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let processor = ContainerAttributionProcessor::with_cache_and_provider(
        AttributionConfig {
            kubernetes: KubernetesAttributionConfig {
                enabled: true,
                ..Default::default()
            },
            ..AttributionConfig::default()
        },
        KubernetesMetadataCache::from_contexts([(container_id.to_string(), kube_context("stale"))]),
        FailingKubernetesMetadataProvider,
    );

    let first = processor
        .process(exec_with_container(container_id))
        .await
        .expect("processor succeeds")
        .expect("signal remains");
    let SignalPayload::Exec(event) = first.payload else {
        panic!("expected exec payload");
    };
    assert_eq!(
        event.kubernetes.expect("stale kubernetes").pod_name,
        "stale"
    );

    tokio::time::sleep(Duration::from_millis(10)).await;
    let second = processor
        .process(exec_with_container(container_id))
        .await
        .expect("processor succeeds")
        .expect("signal remains");
    let SignalPayload::Exec(event) = second.payload else {
        panic!("expected exec payload");
    };
    assert_eq!(
        event.kubernetes.expect("stale kubernetes remains").pod_name,
        "stale"
    );
}

#[tokio::test]
async fn kubernetes_refresh_is_single_flight_for_concurrent_misses() {
    let refreshes = Arc::new(Mutex::new(0));
    let provider = CountingKubernetesMetadataProvider::new(
        refreshes.clone(),
        KubernetesMetadataCache::default(),
    );
    let processor = ContainerAttributionProcessor::with_cache_and_provider(
        AttributionConfig {
            kubernetes: KubernetesAttributionConfig {
                enabled: true,
                ..Default::default()
            },
            ..AttributionConfig::default()
        },
        KubernetesMetadataCache::default(),
        provider,
    );

    let first = processor.process(exec_with_container(
        "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
    ));
    let second = processor.process(exec_with_container(
        "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
    ));
    let _ = tokio::join!(first, second);
    tokio::time::sleep(Duration::from_millis(10)).await;

    assert_eq!(*refreshes.lock().expect("refresh count lock"), 1);
}

#[test]
fn parses_common_container_runtime_cgroup_patterns() {
    let docker = parse_container_from_cgroup(
        "0::/system.slice/docker-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef.scope\n",
    )
    .expect("docker id parses");
    assert_eq!(docker.runtime.as_deref(), Some("docker"));

    let containerd = parse_container_from_cgroup(
        "0::/kubepods.slice/kubepods-burstable.slice/cri-containerd-fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210.scope\n",
    )
    .expect("containerd id parses");
    assert_eq!(containerd.runtime.as_deref(), Some("containerd"));

    let crio = parse_container_from_cgroup(
        "0::/kubepods/burstable/pod123/crio-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.scope\n",
    )
    .expect("cri-o id parses");
    assert_eq!(crio.runtime.as_deref(), Some("cri-o"));
}

#[test]
fn classifies_vanished_procfs_cgroup_as_expected_exit_race() {
    let not_found = io::Error::from(io::ErrorKind::NotFound);
    let permission_denied = io::Error::from(io::ErrorKind::PermissionDenied);

    assert!(is_expected_process_exit_race(&not_found));
    assert!(!is_expected_process_exit_race(&permission_denied));
}

#[tokio::test]
async fn enriches_exec_from_procfs_cgroup_and_kubernetes_cache() {
    let root = std::env::temp_dir().join(format!(
        "e-navigator-attribution-test-{}",
        std::process::id()
    ));
    let pid_dir = root.join("42");
    fs::create_dir_all(&pid_dir).expect("pid dir is created");
    fs::write(
        pid_dir.join("cgroup"),
        "0::/kubepods.slice/cri-containerd-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef.scope\n",
    )
    .expect("cgroup fixture is written");

    let mut labels = BTreeMap::new();
    labels.insert("app".to_string(), "api".to_string());
    let cache = KubernetesMetadataCache::from_contexts([(
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
        KubernetesContext {
            namespace: "default".to_string(),
            pod_name: "api-123".to_string(),
            pod_uid: Some("pod-uid".to_string()),
            container_name: Some("api".to_string()),
            node_name: Some("node-a".to_string()),
            labels,
        },
    )]);
    let processor = ContainerAttributionProcessor::with_cache(
        AttributionConfig {
            procfs_root: root.clone(),
            cgroup_root: root.clone(),
            kubernetes: KubernetesAttributionConfig {
                enabled: false,
                ..Default::default()
            },
        },
        cache,
    );
    let signal = SignalEnvelope::exec(
        "source.test",
        None,
        ExecEvent {
            pid: 42,
            ppid: Some(1),
            uid: Some(1000),
            command: "sh".to_string(),
            executable: Some("/bin/sh".to_string()),
            arguments: vec!["sh".to_string()],
            cgroup_id: None,
            timestamp_unix_nanos: 99,
            container: None,
            kubernetes: None,
        },
    );

    let processed = processor
        .process(signal)
        .await
        .expect("processor succeeds")
        .expect("signal remains");

    let e_navigator_signals::SignalPayload::Exec(event) = processed.payload else {
        panic!("expected exec payload");
    };
    assert_eq!(
        event
            .container
            .as_ref()
            .expect("container")
            .runtime
            .as_deref(),
        Some("containerd")
    );
    assert_eq!(
        event.kubernetes.as_ref().expect("kubernetes").pod_name,
        "api-123"
    );
    assert_eq!(
        event
            .kubernetes
            .as_ref()
            .expect("kubernetes")
            .labels
            .get("app"),
        Some(&"api".to_string())
    );

    fs::remove_dir_all(root).expect("fixture cleanup succeeds");
}

#[cfg(unix)]
#[tokio::test]
async fn enriches_exec_from_cgroup_id_when_procfs_pid_has_disappeared() {
    let root = std::env::temp_dir().join(format!(
        "e-navigator-attribution-cgroup-id-test-{}",
        std::process::id()
    ));
    let proc_root = root.join("proc");
    let cgroup_root = root.join("cgroup");
    let container_id = "abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd";
    let cgroup_dir = cgroup_root.join(format!(
        "kubepods.slice/cri-containerd-{container_id}.scope"
    ));
    fs::create_dir_all(&proc_root).expect("proc root is created");
    fs::create_dir_all(&cgroup_dir).expect("cgroup dir is created");
    let cgroup_id = cgroup_path_id(&cgroup_dir).expect("fixture cgroup id");

    let cache = KubernetesMetadataCache::from_contexts([(
        container_id.to_string(),
        KubernetesContext {
            namespace: "jobs".to_string(),
            pod_name: "short-job-123".to_string(),
            pod_uid: Some("short-job-uid".to_string()),
            container_name: Some("workload".to_string()),
            node_name: Some("node-a".to_string()),
            labels: BTreeMap::new(),
        },
    )]);
    let processor = ContainerAttributionProcessor::with_cache(
        AttributionConfig {
            procfs_root: proc_root,
            cgroup_root: cgroup_root.clone(),
            kubernetes: KubernetesAttributionConfig {
                enabled: false,
                ..Default::default()
            },
        },
        cache,
    );

    let signal = SignalEnvelope::exec(
        "source.test",
        None,
        ExecEvent {
            pid: 4242,
            ppid: Some(1),
            uid: Some(1000),
            command: "wget".to_string(),
            executable: Some("/bin/wget".to_string()),
            arguments: vec!["wget".to_string()],
            cgroup_id: Some(cgroup_id),
            timestamp_unix_nanos: 99,
            container: None,
            kubernetes: None,
        },
    );

    let processed = processor
        .process(signal)
        .await
        .expect("processor succeeds")
        .expect("signal remains");

    let e_navigator_signals::SignalPayload::Exec(event) = processed.payload else {
        panic!("expected exec payload");
    };
    assert_eq!(
        event.container.as_ref().expect("container").container_id,
        container_id
    );
    assert_eq!(
        event.kubernetes.as_ref().expect("kubernetes").pod_name,
        "short-job-123"
    );

    fs::remove_dir_all(root).expect("fixture cleanup succeeds");
}

#[tokio::test]
async fn does_not_cache_missing_pid_attribution() {
    let root = std::env::temp_dir().join(format!(
        "e-navigator-attribution-missing-retry-test-{}",
        std::process::id()
    ));
    let processor = ContainerAttributionProcessor::with_cache(
        AttributionConfig {
            procfs_root: root.clone(),
            cgroup_root: root.clone(),
            kubernetes: KubernetesAttributionConfig {
                enabled: false,
                ..Default::default()
            },
        },
        KubernetesMetadataCache::default(),
    );

    let missing = SignalEnvelope::exec(
        "source.test",
        None,
        ExecEvent {
            pid: 42,
            ppid: Some(1),
            uid: Some(1000),
            command: "sh".to_string(),
            executable: Some("/bin/sh".to_string()),
            arguments: vec!["sh".to_string()],
            cgroup_id: None,
            timestamp_unix_nanos: 99,
            container: None,
            kubernetes: None,
        },
    );

    let processed = processor
        .process(missing)
        .await
        .expect("processor succeeds")
        .expect("signal remains");
    let e_navigator_signals::SignalPayload::Exec(event) = processed.payload else {
        panic!("expected exec payload");
    };
    assert!(event.container.is_none());

    let pid_dir = root.join("42");
    fs::create_dir_all(&pid_dir).expect("pid dir is created");
    fs::write(
        pid_dir.join("cgroup"),
        "0::/kubepods.slice/cri-containerd-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef.scope\n",
    )
    .expect("cgroup fixture is written");

    let retry = SignalEnvelope::exec(
        "source.test",
        None,
        ExecEvent {
            pid: 42,
            ppid: Some(1),
            uid: Some(1000),
            command: "sh".to_string(),
            executable: Some("/bin/sh".to_string()),
            arguments: vec!["sh".to_string()],
            cgroup_id: None,
            timestamp_unix_nanos: 100,
            container: None,
            kubernetes: None,
        },
    );

    let processed = processor
        .process(retry)
        .await
        .expect("processor succeeds")
        .expect("signal remains");
    let e_navigator_signals::SignalPayload::Exec(event) = processed.payload else {
        panic!("expected exec payload");
    };
    assert_eq!(
        event.container.expect("container after retry").container_id,
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    );

    fs::remove_dir_all(root).expect("fixture cleanup succeeds");
}

#[tokio::test]
async fn evicts_pid_attribution_after_process_exit() {
    let root = std::env::temp_dir().join(format!(
        "e-navigator-attribution-exit-evict-test-{}",
        std::process::id()
    ));
    let pid_dir = root.join("42");
    fs::create_dir_all(&pid_dir).expect("pid dir is created");
    fs::write(
        pid_dir.join("cgroup"),
        "0::/kubepods.slice/cri-containerd-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.scope\n",
    )
    .expect("cgroup fixture is written");
    let processor = ContainerAttributionProcessor::with_cache(
        AttributionConfig {
            procfs_root: root.clone(),
            cgroup_root: root.clone(),
            kubernetes: KubernetesAttributionConfig {
                enabled: false,
                ..Default::default()
            },
        },
        KubernetesMetadataCache::default(),
    );

    let first = SignalEnvelope::exec(
        "source.test",
        None,
        ExecEvent {
            pid: 42,
            ppid: Some(1),
            uid: Some(1000),
            command: "sh".to_string(),
            executable: Some("/bin/sh".to_string()),
            arguments: vec!["sh".to_string()],
            cgroup_id: None,
            timestamp_unix_nanos: 99,
            container: None,
            kubernetes: None,
        },
    );
    processor
        .process(first)
        .await
        .expect("processor succeeds")
        .expect("signal remains");

    let exit = SignalEnvelope::process_exit(
        "source.test",
        None,
        ProcessExitEvent {
            pid: 42,
            ppid: Some(1),
            uid: Some(1000),
            command: "sh".to_string(),
            cgroup_id: None,
            exit_code: Some(0),
            runtime_nanos: Some(1),
            timestamp_unix_nanos: 100,
            container: None,
            kubernetes: None,
        },
    );
    processor
        .process(exit)
        .await
        .expect("processor succeeds")
        .expect("signal remains");

    fs::write(
        pid_dir.join("cgroup"),
        "0::/kubepods.slice/cri-containerd-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.scope\n",
    )
    .expect("cgroup fixture is updated");
    let reused = SignalEnvelope::exec(
        "source.test",
        None,
        ExecEvent {
            pid: 42,
            ppid: Some(1),
            uid: Some(1000),
            command: "sh".to_string(),
            executable: Some("/bin/sh".to_string()),
            arguments: vec!["sh".to_string()],
            cgroup_id: None,
            timestamp_unix_nanos: 101,
            container: None,
            kubernetes: None,
        },
    );

    let processed = processor
        .process(reused)
        .await
        .expect("processor succeeds")
        .expect("signal remains");
    let e_navigator_signals::SignalPayload::Exec(event) = processed.payload else {
        panic!("expected exec payload");
    };
    assert_eq!(
        event
            .container
            .expect("container after pid reuse")
            .container_id,
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    );

    fs::remove_dir_all(root).expect("fixture cleanup succeeds");
}

#[tokio::test]
async fn enriches_network_connection_from_existing_attribution_path() {
    let root = std::env::temp_dir().join(format!(
        "e-navigator-network-attribution-test-{}",
        std::process::id()
    ));
    let pid_dir = root.join("77");
    fs::create_dir_all(&pid_dir).expect("pid dir is created");
    fs::write(
        pid_dir.join("cgroup"),
        "0::/kubepods.slice/cri-containerd-fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210.scope\n",
    )
    .expect("cgroup fixture is written");

    let mut labels = BTreeMap::new();
    labels.insert("app".to_string(), "worker".to_string());
    let cache = KubernetesMetadataCache::from_contexts([(
        "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210".to_string(),
        KubernetesContext {
            namespace: "jobs".to_string(),
            pod_name: "worker-123".to_string(),
            pod_uid: Some("worker-pod-uid".to_string()),
            container_name: Some("worker".to_string()),
            node_name: Some("node-a".to_string()),
            labels,
        },
    )]);
    let processor = ContainerAttributionProcessor::with_cache(
        AttributionConfig {
            procfs_root: root.clone(),
            cgroup_root: root.clone(),
            kubernetes: KubernetesAttributionConfig {
                enabled: false,
                ..Default::default()
            },
        },
        cache,
    );
    let signal = SignalEnvelope::network_connection_open(
        "source.test",
        Some("node-a".to_string()),
        NetworkConnectionOpenEvent {
            process: NetworkProcessIdentity {
                pid: 77,
                ppid: Some(1),
                uid: Some(1000),
                command: "worker".to_string(),
                executable: Some("/app/worker".to_string()),
                cgroup_id: None,
            },
            protocol: NetworkProtocol::Tcp,
            address_family: NetworkAddressFamily::Ipv4,
            local_address: Some("10.0.0.5".to_string()),
            local_port: Some(43512),
            remote_address: "203.0.113.10".to_string(),
            remote_port: 443,
            fd: Some(9),
            timestamp_unix_nanos: 99,
            container: None,
            kubernetes: None,
        },
    );

    let processed = processor
        .process(signal)
        .await
        .expect("processor succeeds")
        .expect("signal remains");

    let e_navigator_signals::SignalPayload::NetworkConnectionOpen(event) = processed.payload else {
        panic!("expected network open payload");
    };
    assert_eq!(
        event
            .container
            .as_ref()
            .expect("container")
            .runtime
            .as_deref(),
        Some("containerd")
    );
    assert_eq!(
        event.kubernetes.as_ref().expect("kubernetes").pod_name,
        "worker-123"
    );

    fs::remove_dir_all(root).expect("fixture cleanup succeeds");
}

#[tokio::test]
async fn network_metric_uses_processor_enriched_attribution() {
    let (processor, root) = processor_fixture(
        88,
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        KubernetesContext {
            namespace: "default".to_string(),
            pod_name: "api-123".to_string(),
            pod_uid: Some("api-pod-uid".to_string()),
            container_name: Some("api".to_string()),
            node_name: Some("node-a".to_string()),
            labels: BTreeMap::new(),
        },
    );
    let signal = SignalEnvelope::network_connection_open(
        "source.test",
        Some("node-a".to_string()),
        NetworkConnectionOpenEvent {
            process: NetworkProcessIdentity {
                pid: 88,
                ppid: Some(1),
                uid: Some(1000),
                command: "api".to_string(),
                executable: Some("/app/api".to_string()),
                cgroup_id: None,
            },
            protocol: NetworkProtocol::Tcp,
            address_family: NetworkAddressFamily::Ipv4,
            local_address: Some("10.0.0.5".to_string()),
            local_port: Some(43512),
            remote_address: "203.0.113.10".to_string(),
            remote_port: 443,
            fd: Some(9),
            timestamp_unix_nanos: 99,
            container: None,
            kubernetes: None,
        },
    );
    let processed = processor
        .process(signal)
        .await
        .expect("processor succeeds")
        .expect("signal remains");

    let outputs = observe_generator(&NetworkMetricsGenerator::default(), &processed).await;
    let metric = outputs
        .iter()
        .find_map(|signal| match &signal.payload {
            e_navigator_signals::SignalPayload::NetworkCounterMetric(metric)
                if metric.metric_name == "network.connection.open.count" =>
            {
                Some(metric)
            }
            _ => None,
        })
        .expect("network metric exists");

    assert_eq!(
        metric.kubernetes.as_ref().expect("kubernetes").pod_name,
        "api-123"
    );
    assert_eq!(
        metric.container.as_ref().expect("container").container_id,
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    );

    fs::remove_dir_all(root).expect("fixture cleanup succeeds");
}

#[tokio::test]
async fn trace_correlation_uses_processor_enriched_attribution() {
    let container_id = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
    let (processor, root) = processor_fixture(
        91,
        container_id,
        KubernetesContext {
            namespace: "default".to_string(),
            pod_name: "trace-client-123".to_string(),
            pod_uid: Some("trace-pod-uid".to_string()),
            container_name: Some("trace-client".to_string()),
            node_name: Some("node-a".to_string()),
            labels: BTreeMap::new(),
        },
    );
    let signal = SignalEnvelope::network_connection_close(
        "source.test",
        Some("node-a".to_string()),
        NetworkConnectionCloseEvent {
            process: NetworkProcessIdentity {
                pid: 91,
                ppid: Some(1),
                uid: Some(1000),
                command: "trace-client".to_string(),
                executable: Some("/app/trace-client".to_string()),
                cgroup_id: None,
            },
            protocol: NetworkProtocol::Tcp,
            address_family: NetworkAddressFamily::Ipv4,
            local_address: Some("10.0.0.5".to_string()),
            local_port: Some(43512),
            remote_address: "203.0.113.10".to_string(),
            remote_port: 443,
            fd: Some(9),
            opened_at_unix_nanos: Some(100),
            closed_at_unix_nanos: 300,
            duration_nanos: Some(200),
            bytes_sent: None,
            bytes_received: None,
            container: None,
            kubernetes: None,
        },
    );
    let processed = processor
        .process(signal)
        .await
        .expect("processor succeeds")
        .expect("signal remains");

    let outputs = observe_generator(&TraceCorrelationGenerator::default(), &processed).await;
    let span = outputs
        .iter()
        .find_map(|signal| match &signal.payload {
            e_navigator_signals::SignalPayload::ServiceInteractionSpanObservation(span) => {
                Some(span)
            }
            _ => None,
        })
        .expect("trace interaction span exists");

    assert_eq!(
        span.source.workload.as_ref().expect("kubernetes").pod_name,
        "trace-client-123"
    );
    assert_eq!(
        span.source
            .container
            .as_ref()
            .expect("container")
            .container_id,
        container_id
    );
    assert_eq!(span.process.as_ref().expect("process").pid, 91);

    fs::remove_dir_all(root).expect("fixture cleanup succeeds");
}

#[tokio::test]
async fn network_flow_summary_enriches_destination_from_pod_ip_cache() {
    let source_container_id = "abababababababababababababababababababababababababababababababab";
    let destination_container_id =
        "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd";
    let source_kubernetes = kube_context("api-pod");
    let destination_kubernetes = kube_context("redis-pod");
    let processor = ContainerAttributionProcessor::with_cache(
        AttributionConfig {
            kubernetes: KubernetesAttributionConfig {
                enabled: false,
                ..Default::default()
            },
            ..Default::default()
        },
        KubernetesMetadataCache::from_contexts_and_pod_ips(
            [
                (source_container_id.to_string(), source_kubernetes.clone()),
                (
                    destination_container_id.to_string(),
                    destination_kubernetes.clone(),
                ),
            ],
            [("10.0.0.20".to_string(), destination_kubernetes.clone())],
        ),
    );
    let signal = SignalEnvelope::network_flow_summary(
        "generator.network_metrics",
        Some("node-a".to_string()),
        NetworkFlowSummaryEvent {
            source: NetworkFlowEndpoint {
                address: Some("10.0.0.5".to_string()),
                port: Some(43512),
                owner_name: None,
                owner_type: None,
                container: Some(ContainerContext {
                    container_id: source_container_id.to_string(),
                    runtime: Some("containerd".to_string()),
                }),
                kubernetes: None,
            },
            destination: NetworkFlowEndpoint {
                address: Some("10.0.0.20".to_string()),
                port: Some(6379),
                owner_name: None,
                owner_type: None,
                container: None,
                kubernetes: None,
            },
            protocol: NetworkProtocol::Tcp,
            address_family: NetworkAddressFamily::Ipv4,
            bytes: 1536,
            packets: None,
            direction: NetworkFlowDirection::Egress,
            first_seen_unix_nanos: 100,
            last_seen_unix_nanos: 900,
        },
    );

    let processed = processor
        .process(signal)
        .await
        .expect("processor succeeds")
        .expect("signal is retained");

    let SignalPayload::NetworkFlowSummary(flow) = processed.payload else {
        panic!("expected network flow summary");
    };
    assert_eq!(flow.source.kubernetes, Some(source_kubernetes));
    assert_eq!(flow.destination.kubernetes, Some(destination_kubernetes));
}

#[tokio::test]
async fn dns_metric_uses_processor_enriched_attribution() {
    let (processor, root) = processor_fixture(
        89,
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        KubernetesContext {
            namespace: "default".to_string(),
            pod_name: "dns-client-123".to_string(),
            pod_uid: Some("dns-pod-uid".to_string()),
            container_name: Some("dns-client".to_string()),
            node_name: Some("node-a".to_string()),
            labels: BTreeMap::new(),
        },
    );
    let signal = SignalEnvelope::dns_query(
        "source.test",
        Some("node-a".to_string()),
        DnsQueryEvent {
            process: NetworkProcessIdentity {
                pid: 89,
                ppid: Some(1),
                uid: Some(1000),
                command: "api".to_string(),
                executable: Some("/app/api".to_string()),
                cgroup_id: None,
            },
            query_name: "api.example.com".to_string(),
            query_type: DnsQueryType::A,
            transport_protocol: NetworkProtocol::Udp,
            server_address: Some("10.96.0.10".to_string()),
            server_port: Some(53),
            timestamp_unix_nanos: 99,
            container: None,
            kubernetes: None,
        },
    );
    let processed = processor
        .process(signal)
        .await
        .expect("processor succeeds")
        .expect("signal remains");

    let outputs = observe_generator(&DnsMetricsGenerator::default(), &processed).await;
    let metric = outputs
        .iter()
        .find_map(|signal| match &signal.payload {
            e_navigator_signals::SignalPayload::DnsCounterMetric(metric)
                if metric.metric_name == "dns.query.count" =>
            {
                Some(metric)
            }
            _ => None,
        })
        .expect("dns metric exists");

    assert_eq!(
        metric.kubernetes.as_ref().expect("kubernetes").pod_name,
        "dns-client-123"
    );
    assert_eq!(
        metric.container.as_ref().expect("container").container_id,
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    );

    fs::remove_dir_all(root).expect("fixture cleanup succeeds");
}

#[tokio::test]
async fn resource_observations_use_processor_enriched_attribution() {
    let container_id = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    let (processor, root) = processor_fixture(
        90,
        container_id,
        KubernetesContext {
            namespace: "default".to_string(),
            pod_name: "resource-client-123".to_string(),
            pod_uid: Some("resource-pod-uid".to_string()),
            container_name: Some("resource-client".to_string()),
            node_name: Some("node-a".to_string()),
            labels: BTreeMap::new(),
        },
    );
    let signal = SignalEnvelope::process_resource_observation(
        "source.host_resource",
        Some("node-a".to_string()),
        e_navigator_signals::ProcessResourceObservation {
            metric_name: "process.resource".to_string(),
            unit: "1".to_string(),
            timestamp_unix_nanos: 99,
            window: e_navigator_signals::MetricAggregationWindow {
                start_unix_nanos: 90,
                end_unix_nanos: 99,
            },
            process: e_navigator_signals::ProcessResourceContext {
                pid: 90,
                ppid: Some(1),
                uid: Some(1000),
                command: "resource-client".to_string(),
                executable: Some("/app/resource-client".to_string()),
                container: None,
                kubernetes: None,
            },
            cpu_time_nanos: Some(100),
            memory_rss_bytes: Some(4096),
            virtual_memory_bytes: None,
            open_fds: Some(8),
            socket_count: Some(2),
            thread_count: Some(3),
        },
    );
    let processed = processor
        .process(signal)
        .await
        .expect("processor succeeds")
        .expect("signal remains");

    let outputs = observe_generator(&ResourceMetricsGenerator::default(), &processed).await;
    let metric = outputs
        .iter()
        .find_map(|signal| match &signal.payload {
            e_navigator_signals::SignalPayload::ResourceGaugeMetric(metric)
                if metric.metric_name == "process.memory.usage" =>
            {
                Some(metric)
            }
            _ => None,
        })
        .expect("resource metric exists");

    assert_eq!(
        metric
            .process
            .as_ref()
            .and_then(|process| process.kubernetes.as_ref())
            .expect("kubernetes")
            .pod_name,
        "resource-client-123"
    );
    assert_eq!(
        metric
            .process
            .as_ref()
            .and_then(|process| process.container.as_ref())
            .expect("container")
            .container_id,
        container_id
    );

    fs::remove_dir_all(root).expect("fixture cleanup succeeds");
}

#[tokio::test]
async fn cgroup_resource_observations_are_enriched_from_cgroup_path() {
    let container_id = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
    let kubernetes = KubernetesContext {
        namespace: "default".to_string(),
        pod_name: "resource-pod-456".to_string(),
        pod_uid: Some("resource-pod-uid".to_string()),
        container_name: Some("resource-client".to_string()),
        node_name: Some("node-a".to_string()),
        labels: BTreeMap::new(),
    };
    let processor = ContainerAttributionProcessor::with_cache(
        AttributionConfig {
            kubernetes: KubernetesAttributionConfig {
                enabled: false,
                ..Default::default()
            },
            ..Default::default()
        },
        KubernetesMetadataCache::from_contexts([(container_id.to_string(), kubernetes)]),
    );
    let signal = SignalEnvelope::cgroup_memory_observation(
        "source.host_resource",
        Some("node-a".to_string()),
        e_navigator_signals::CgroupMemoryObservation {
            metric_name: "container.memory.usage".to_string(),
            unit: "By".to_string(),
            timestamp_unix_nanos: 99,
            window: e_navigator_signals::MetricAggregationWindow {
                start_unix_nanos: 90,
                end_unix_nanos: 99,
            },
            cgroup: e_navigator_signals::CgroupResourceContext {
                cgroup_path: format!("/kubepods.slice/cri-containerd-{container_id}.scope"),
                container: None,
                kubernetes: None,
            },
            current_bytes: Some(4096),
            peak_bytes: None,
            max_bytes: None,
        },
    );

    let processed = processor
        .process(signal)
        .await
        .expect("processor succeeds")
        .expect("signal remains");

    let e_navigator_signals::SignalPayload::CgroupMemoryObservation(event) = processed.payload
    else {
        panic!("expected cgroup memory payload");
    };
    assert_eq!(
        event
            .cgroup
            .container
            .as_ref()
            .expect("container")
            .container_id,
        container_id
    );
    assert_eq!(
        event
            .cgroup
            .kubernetes
            .as_ref()
            .expect("kubernetes")
            .pod_name,
        "resource-pod-456"
    );
}

#[tokio::test]
async fn protocol_request_observations_reuse_existing_container_attribution() {
    let container_id = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
    let kubernetes = KubernetesContext {
        namespace: "default".to_string(),
        pod_name: "request-client-123".to_string(),
        pod_uid: Some("request-pod-uid".to_string()),
        container_name: Some("request-client".to_string()),
        node_name: Some("node-a".to_string()),
        labels: BTreeMap::new(),
    };
    let (processor, root) = processor_fixture(95, container_id, kubernetes);
    let signal = SignalEnvelope::protocol_request_observation(
        "source.protocol_fixture",
        Some("node-a".to_string()),
        ProtocolRequestObservation {
            protocol: ProtocolKind::Http,
            start_unix_nanos: 1_000,
            end_unix_nanos: Some(2_000),
            duration_nanos: Some(1_000),
            trace_id: Some("4bf92f3577b34da6a3ce929d0e0e4736".to_string()),
            span_id: Some("00f067aa0ba902b7".to_string()),
            parent_span_id: None,
            traceparent: Some(
                "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01".to_string(),
            ),
            tracestate: None,
            correlation_kind: TraceCorrelationKind::ProtocolObserved,
            confidence: TraceConfidence::Medium,
            service_name: Some("request-client".to_string()),
            method: Some("GET".to_string()),
            status_code: Some(200),
            process: Some(NetworkProcessIdentity {
                pid: 95,
                ppid: Some(1),
                uid: Some(1000),
                command: "request-client".to_string(),
                executable: Some("/app/request-client".to_string()),
                cgroup_id: None,
            }),
            container: Some(ContainerContext {
                container_id: container_id.to_string(),
                runtime: Some("containerd".to_string()),
            }),
            kubernetes: None,
            peer: Some(TracePeerContext {
                address: Some("203.0.113.10".to_string()),
                port: Some(443),
                domain: None,
                workload: None,
                container: None,
            }),
            attributes: vec![],
        },
    );

    let processed = processor
        .process(signal)
        .await
        .expect("processor succeeds")
        .expect("signal remains");
    let outputs = observe_generator(&RequestCorrelationGenerator::default(), &processed).await;
    let span = outputs
        .iter()
        .find_map(|signal| match &signal.payload {
            e_navigator_signals::SignalPayload::RequestSpanObservation(span) => Some(span),
            _ => None,
        })
        .expect("request span exists");

    assert_eq!(
        span.container.as_ref().expect("container").container_id,
        container_id
    );
    assert_eq!(
        span.kubernetes.as_ref().expect("kubernetes").pod_name,
        "request-client-123"
    );

    fs::remove_dir_all(root).expect("fixture cleanup succeeds");
}

#[tokio::test]
async fn refreshes_kubernetes_metadata_on_container_cache_miss() {
    let container_id = "1212121212121212121212121212121212121212121212121212121212121212";
    let root = std::env::temp_dir().join(format!(
        "e-navigator-attribution-refresh-test-{}",
        std::process::id()
    ));
    let pid_dir = root.join("120");
    fs::create_dir_all(&pid_dir).expect("pid dir is created");
    fs::write(
        pid_dir.join("cgroup"),
        format!("0::/kubepods.slice/cri-containerd-{container_id}.scope\n"),
    )
    .expect("cgroup fixture is written");

    let processor = ContainerAttributionProcessor::with_cache_and_provider(
        AttributionConfig {
            procfs_root: root.clone(),
            cgroup_root: root.clone(),
            kubernetes: KubernetesAttributionConfig {
                enabled: true,
                ..Default::default()
            },
        },
        KubernetesMetadataCache::default(),
        StaticKubernetesMetadataProvider::new(KubernetesMetadataCache::from_contexts([(
            container_id.to_string(),
            KubernetesContext {
                namespace: "e-navigator-test".to_string(),
                pod_name: "known-exec-network-dns".to_string(),
                pod_uid: Some("known-pod-uid".to_string()),
                container_name: Some("known".to_string()),
                node_name: Some("homelab-01".to_string()),
                labels: BTreeMap::new(),
            },
        )])),
    );
    let signal = SignalEnvelope::network_connection_open(
        "source.test",
        Some("homelab-01".to_string()),
        NetworkConnectionOpenEvent {
            process: NetworkProcessIdentity {
                pid: 120,
                ppid: Some(1),
                uid: Some(1000),
                command: "wget".to_string(),
                executable: Some("/bin/wget".to_string()),
                cgroup_id: None,
            },
            protocol: NetworkProtocol::Tcp,
            address_family: NetworkAddressFamily::Ipv4,
            local_address: Some("10.42.248.225".to_string()),
            local_port: Some(43512),
            remote_address: "10.43.0.1".to_string(),
            remote_port: 443,
            fd: Some(9),
            timestamp_unix_nanos: 99,
            container: None,
            kubernetes: None,
        },
    );

    let first = processor
        .process(signal)
        .await
        .expect("processor succeeds")
        .expect("signal remains");

    let e_navigator_signals::SignalPayload::NetworkConnectionOpen(event) = first.payload else {
        panic!("expected network open payload");
    };
    assert_eq!(
        event.container.as_ref().expect("container").container_id,
        container_id
    );
    assert!(event.kubernetes.is_none());

    tokio::time::sleep(Duration::from_millis(10)).await;
    let second = processor
        .process(SignalEnvelope::network_connection_open(
            "source.test",
            Some("homelab-01".to_string()),
            NetworkConnectionOpenEvent {
                process: NetworkProcessIdentity {
                    pid: 120,
                    ppid: Some(1),
                    uid: Some(1000),
                    command: "wget".to_string(),
                    executable: Some("/bin/wget".to_string()),
                    cgroup_id: None,
                },
                protocol: NetworkProtocol::Tcp,
                address_family: NetworkAddressFamily::Ipv4,
                local_address: Some("10.42.248.225".to_string()),
                local_port: Some(43512),
                remote_address: "10.43.0.1".to_string(),
                remote_port: 443,
                fd: Some(9),
                timestamp_unix_nanos: 100,
                container: None,
                kubernetes: None,
            },
        ))
        .await
        .expect("processor succeeds")
        .expect("signal remains");
    let e_navigator_signals::SignalPayload::NetworkConnectionOpen(event) = second.payload else {
        panic!("expected network open payload");
    };
    assert_eq!(
        event.kubernetes.as_ref().expect("kubernetes").pod_name,
        "known-exec-network-dns"
    );

    fs::remove_dir_all(root).expect("fixture cleanup succeeds");
}

#[tokio::test]
async fn does_not_refresh_kubernetes_metadata_when_attribution_is_disabled() {
    let container_id = "7878787878787878787878787878787878787878787878787878787878787878";
    let root = std::env::temp_dir().join(format!(
        "e-navigator-attribution-disabled-refresh-test-{}",
        std::process::id()
    ));
    let pid_dir = root.join("122");
    fs::create_dir_all(&pid_dir).expect("pid dir is created");
    fs::write(
        pid_dir.join("cgroup"),
        format!("0::/kubepods.slice/cri-containerd-{container_id}.scope\n"),
    )
    .expect("cgroup fixture is written");

    let refreshes = Arc::new(Mutex::new(0));
    let processor = ContainerAttributionProcessor::with_cache_and_provider(
        AttributionConfig {
            procfs_root: root.clone(),
            cgroup_root: root.clone(),
            kubernetes: KubernetesAttributionConfig {
                enabled: false,
                ..Default::default()
            },
        },
        KubernetesMetadataCache::default(),
        CountingKubernetesMetadataProvider::new(
            Arc::clone(&refreshes),
            KubernetesMetadataCache::from_contexts([(
                container_id.to_string(),
                KubernetesContext {
                    namespace: "e-navigator-test".to_string(),
                    pod_name: "disabled-refresh".to_string(),
                    pod_uid: Some("known-pod-uid".to_string()),
                    container_name: Some("known".to_string()),
                    node_name: Some("homelab-01".to_string()),
                    labels: BTreeMap::new(),
                },
            )]),
        ),
    );
    let signal = SignalEnvelope::network_connection_open(
        "source.test",
        Some("homelab-01".to_string()),
        NetworkConnectionOpenEvent {
            process: NetworkProcessIdentity {
                pid: 122,
                ppid: Some(1),
                uid: Some(1000),
                command: "wget".to_string(),
                executable: Some("/bin/wget".to_string()),
                cgroup_id: None,
            },
            protocol: NetworkProtocol::Tcp,
            address_family: NetworkAddressFamily::Ipv4,
            local_address: Some("10.42.248.245".to_string()),
            local_port: Some(43512),
            remote_address: "10.43.0.1".to_string(),
            remote_port: 443,
            fd: Some(9),
            timestamp_unix_nanos: 99,
            container: None,
            kubernetes: None,
        },
    );

    let processed = processor
        .process(signal)
        .await
        .expect("processor succeeds")
        .expect("signal remains");

    let e_navigator_signals::SignalPayload::NetworkConnectionOpen(event) = processed.payload else {
        panic!("expected network open payload");
    };
    assert_eq!(
        event.container.as_ref().expect("container").container_id,
        container_id
    );
    assert!(event.kubernetes.is_none());
    assert_eq!(*refreshes.lock().expect("refresh count lock"), 0);

    fs::remove_dir_all(root).expect("fixture cleanup succeeds");
}

#[tokio::test]
async fn retries_kubernetes_metadata_refresh_after_requested_container_miss() {
    let container_id = "5656565656565656565656565656565656565656565656565656565656565656";
    let root = std::env::temp_dir().join(format!(
        "e-navigator-attribution-fast-retry-test-{}",
        std::process::id()
    ));
    let pid_dir = root.join("121");
    fs::create_dir_all(&pid_dir).expect("pid dir is created");
    fs::write(
        pid_dir.join("cgroup"),
        format!("0::/kubepods.slice/cri-containerd-{container_id}.scope\n"),
    )
    .expect("cgroup fixture is written");

    let later_cache = KubernetesMetadataCache::from_contexts([(
        container_id.to_string(),
        KubernetesContext {
            namespace: "e-navigator-test".to_string(),
            pod_name: "known-exec-network-dns".to_string(),
            pod_uid: Some("known-pod-uid".to_string()),
            container_name: Some("known".to_string()),
            node_name: Some("homelab-01".to_string()),
            labels: BTreeMap::new(),
        },
    )]);
    let processor = ContainerAttributionProcessor::with_cache_and_provider(
        AttributionConfig {
            procfs_root: root.clone(),
            cgroup_root: root.clone(),
            kubernetes: KubernetesAttributionConfig {
                enabled: true,
                ..Default::default()
            },
        },
        KubernetesMetadataCache::default(),
        SequencedKubernetesMetadataProvider::new([KubernetesMetadataCache::default(), later_cache]),
    );
    let signal = || {
        SignalEnvelope::network_connection_open(
            "source.test",
            Some("homelab-01".to_string()),
            NetworkConnectionOpenEvent {
                process: NetworkProcessIdentity {
                    pid: 121,
                    ppid: Some(1),
                    uid: Some(1000),
                    command: "wget".to_string(),
                    executable: Some("/bin/wget".to_string()),
                    cgroup_id: None,
                },
                protocol: NetworkProtocol::Tcp,
                address_family: NetworkAddressFamily::Ipv4,
                local_address: Some("10.42.248.241".to_string()),
                local_port: Some(43512),
                remote_address: "10.255.255.1".to_string(),
                remote_port: 81,
                fd: Some(9),
                timestamp_unix_nanos: 99,
                container: None,
                kubernetes: None,
            },
        )
    };

    let first = processor
        .process(signal())
        .await
        .expect("processor succeeds")
        .expect("signal remains");
    let e_navigator_signals::SignalPayload::NetworkConnectionOpen(first_event) = first.payload
    else {
        panic!("expected network open payload");
    };
    assert_eq!(
        first_event
            .container
            .as_ref()
            .expect("container")
            .container_id,
        container_id
    );
    assert!(first_event.kubernetes.is_none());

    let second = processor
        .process(signal())
        .await
        .expect("processor succeeds")
        .expect("signal remains");
    let e_navigator_signals::SignalPayload::NetworkConnectionOpen(second_event) = second.payload
    else {
        panic!("expected network open payload");
    };
    assert!(second_event.kubernetes.is_none());

    tokio::time::sleep(Duration::from_millis(10)).await;
    let third = processor
        .process(signal())
        .await
        .expect("processor succeeds")
        .expect("signal remains");
    let e_navigator_signals::SignalPayload::NetworkConnectionOpen(third_event) = third.payload
    else {
        panic!("expected network open payload");
    };
    assert!(third_event.kubernetes.is_none());

    tokio::time::sleep(Duration::from_millis(10)).await;
    let fourth = processor
        .process(signal())
        .await
        .expect("processor succeeds")
        .expect("signal remains");
    let e_navigator_signals::SignalPayload::NetworkConnectionOpen(fourth_event) = fourth.payload
    else {
        panic!("expected network open payload");
    };
    assert_eq!(
        fourth_event
            .kubernetes
            .as_ref()
            .expect("kubernetes")
            .pod_name,
        "known-exec-network-dns"
    );

    fs::remove_dir_all(root).expect("fixture cleanup succeeds");
}

#[tokio::test]
async fn refreshes_kubernetes_metadata_for_new_container_miss_after_successful_refresh() {
    let known_container_id = "3434343434343434343434343434343434343434343434343434343434343434";
    let new_container_id = "5656565656565656565656565656565656565656565656565656565656565656";
    let root = std::env::temp_dir().join(format!(
        "e-navigator-attribution-new-container-refresh-test-{}",
        std::process::id()
    ));
    let pid_dir = root.join("123");
    fs::create_dir_all(&pid_dir).expect("pid dir is created");
    fs::write(
        pid_dir.join("cgroup"),
        format!("0::/kubepods.slice/cri-containerd-{new_container_id}.scope\n"),
    )
    .expect("cgroup fixture is written");

    let known_cache = KubernetesMetadataCache::from_contexts([(
        known_container_id.to_string(),
        kube_context("existing-workload"),
    )]);
    let refreshed_cache = KubernetesMetadataCache::from_contexts([
        (
            known_container_id.to_string(),
            kube_context("existing-workload"),
        ),
        (
            new_container_id.to_string(),
            kube_context("new-socket-client"),
        ),
    ]);
    let processor = ContainerAttributionProcessor::with_cache_and_provider(
        AttributionConfig {
            procfs_root: root.clone(),
            cgroup_root: root.clone(),
            kubernetes: KubernetesAttributionConfig {
                enabled: true,
                ..Default::default()
            },
        },
        known_cache.clone(),
        SequencedKubernetesMetadataProvider::new([known_cache, refreshed_cache]),
    );

    let primed = processor
        .process(exec_with_container(known_container_id))
        .await
        .expect("processor succeeds")
        .expect("signal remains");
    let SignalPayload::Exec(primed_event) = primed.payload else {
        panic!("expected exec payload");
    };
    assert_eq!(
        primed_event
            .kubernetes
            .as_ref()
            .expect("known container has cached kubernetes")
            .pod_name,
        "existing-workload"
    );
    tokio::time::sleep(Duration::from_millis(10)).await;

    let signal = || {
        SignalEnvelope::network_connection_close(
            "source.test",
            Some("homelab-02".to_string()),
            NetworkConnectionCloseEvent {
                process: NetworkProcessIdentity {
                    pid: 123,
                    ppid: None,
                    uid: Some(1000),
                    command: "python".to_string(),
                    executable: None,
                    cgroup_id: None,
                },
                protocol: NetworkProtocol::Tcp,
                address_family: NetworkAddressFamily::Ipv4,
                local_address: Some("10.42.134.23".to_string()),
                local_port: Some(43512),
                remote_address: "10.42.134.22".to_string(),
                remote_port: 8080,
                fd: Some(3),
                opened_at_unix_nanos: Some(100),
                closed_at_unix_nanos: 900,
                duration_nanos: Some(800),
                bytes_sent: Some(243),
                bytes_received: Some(1372),
                container: None,
                kubernetes: None,
            },
        )
    };

    let first = processor
        .process(signal())
        .await
        .expect("processor succeeds")
        .expect("signal remains");
    let SignalPayload::NetworkConnectionClose(first_event) = first.payload else {
        panic!("expected network close payload");
    };
    assert_eq!(
        first_event
            .container
            .as_ref()
            .expect("container")
            .container_id,
        new_container_id
    );
    assert!(first_event.kubernetes.is_none());

    tokio::time::sleep(Duration::from_millis(10)).await;
    let second = processor
        .process(signal())
        .await
        .expect("processor succeeds")
        .expect("signal remains");
    let SignalPayload::NetworkConnectionClose(second_event) = second.payload else {
        panic!("expected network close payload");
    };
    assert_eq!(
        second_event
            .kubernetes
            .as_ref()
            .expect("new container refreshes despite fresh previous cache")
            .pod_name,
        "new-socket-client"
    );

    fs::remove_dir_all(root).expect("fixture cleanup succeeds");
}

#[tokio::test]
async fn enriches_dependency_edge_endpoint_from_existing_container_context() {
    let container_id = "3434343434343434343434343434343434343434343434343434343434343434";
    let processor = ContainerAttributionProcessor::with_cache(
        AttributionConfig {
            kubernetes: KubernetesAttributionConfig {
                enabled: true,
                ..Default::default()
            },
            ..Default::default()
        },
        KubernetesMetadataCache::from_contexts([(
            container_id.to_string(),
            KubernetesContext {
                namespace: "e-navigator-test".to_string(),
                pod_name: "known-exec-network-dns".to_string(),
                pod_uid: Some("known-pod-uid".to_string()),
                container_name: Some("workload".to_string()),
                node_name: Some("homelab-01".to_string()),
                labels: BTreeMap::new(),
            },
        )]),
    );
    let signal = SignalEnvelope::dependency_edge(
        "generator.dependency_graph",
        Some("homelab-01".to_string()),
        DependencyEdgeEvent {
            source: DependencyEndpoint {
                workload: None,
                container: Some(ContainerContext {
                    container_id: container_id.to_string(),
                    runtime: Some("containerd".to_string()),
                }),
                address: None,
                port: None,
                domain: None,
            },
            destination: DependencyEndpoint {
                workload: None,
                container: None,
                address: Some("10.43.0.1".to_string()),
                port: Some(443),
                domain: None,
            },
            protocol: NetworkProtocol::Tcp,
            observations: 1,
            first_seen_unix_nanos: 100,
            last_seen_unix_nanos: 200,
        },
    );

    let processed = processor
        .process(signal)
        .await
        .expect("processor succeeds")
        .expect("signal remains");

    let e_navigator_signals::SignalPayload::DependencyEdge(edge) = processed.payload else {
        panic!("dependency edge remains a dependency edge");
    };
    assert_eq!(
        edge.source
            .workload
            .as_ref()
            .expect("source workload")
            .namespace,
        "e-navigator-test"
    );
    assert_eq!(
        edge.source
            .workload
            .as_ref()
            .expect("source workload")
            .pod_name,
        "known-exec-network-dns"
    );
}

#[tokio::test]
async fn profile_samples_reuse_existing_container_attribution_before_generation() {
    let container_id = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    let kubernetes = KubernetesContext {
        namespace: "default".to_string(),
        pod_name: "profile-client-123".to_string(),
        pod_uid: Some("profile-pod-uid".to_string()),
        container_name: Some("profile-client".to_string()),
        node_name: Some("node-a".to_string()),
        labels: BTreeMap::new(),
    };
    let (processor, root) = processor_fixture(101, container_id, kubernetes);
    let signal = SignalEnvelope::profile_sample_observation(
        "source.synthetic_profile",
        Some("node-a".to_string()),
        e_navigator_signals::ProfileSampleObservation {
            timestamp_unix_nanos: 1_500_000_000,
            profiling_kind: e_navigator_signals::ProfilingKind::Cpu,
            correlation_kind: e_navigator_signals::ProfilingCorrelationKind::Synthetic,
            confidence: e_navigator_signals::ProfilingConfidence::High,
            sample_count: 1,
            sampling_period_nanos: Some(10_000_000),
            stack_id: "stack:0123456789abcdef".to_string(),
            stack_frames: vec![e_navigator_signals::ProfilingFrame {
                symbol: Some("profile_client::handler".to_string()),
                module: Some("profile-client".to_string()),
                file: None,
                line: None,
            }],
            process: Some(NetworkProcessIdentity {
                pid: 101,
                ppid: Some(1),
                uid: Some(1000),
                command: "profile-client".to_string(),
                executable: Some("/app/profile-client".to_string()),
                cgroup_id: None,
            }),
            container: Some(ContainerContext {
                container_id: container_id.to_string(),
                runtime: Some("containerd".to_string()),
            }),
            kubernetes: None,
            thread_id: None,
            thread_name: None,
            attributes: vec![],
        },
    );

    let processed = processor
        .process(signal)
        .await
        .expect("processor succeeds")
        .expect("signal remains");
    let outputs = observe_generator(
        &e_navigator_generators::ProfilingGenerator::default(),
        &processed,
    )
    .await;
    let window = outputs
        .iter()
        .find_map(|signal| match &signal.payload {
            e_navigator_signals::SignalPayload::ProfilingSessionObservation(window) => Some(window),
            _ => None,
        })
        .expect("profiling session exists");

    assert_eq!(
        window.container.as_ref().expect("container").container_id,
        container_id
    );
    assert_eq!(
        window.kubernetes.as_ref().expect("kubernetes").pod_name,
        "profile-client-123"
    );

    fs::remove_dir_all(root).expect("fixture cleanup succeeds");
}

#[tokio::test]
async fn profile_samples_with_process_only_are_enriched_from_procfs_cgroup() {
    let container_id = "abababababababababababababababababababababababababababababababab";
    let kubernetes = KubernetesContext {
        namespace: "default".to_string(),
        pod_name: "profile-process-only-123".to_string(),
        pod_uid: Some("profile-process-only-uid".to_string()),
        container_name: Some("profile-client".to_string()),
        node_name: Some("node-a".to_string()),
        labels: BTreeMap::new(),
    };
    let (processor, root) = processor_fixture(102, container_id, kubernetes);
    let signal = SignalEnvelope::profile_sample_observation(
        "source.synthetic_exec",
        Some("node-a".to_string()),
        e_navigator_signals::ProfileSampleObservation {
            timestamp_unix_nanos: 1_500_000_000,
            profiling_kind: e_navigator_signals::ProfilingKind::Cpu,
            correlation_kind: e_navigator_signals::ProfilingCorrelationKind::Synthetic,
            confidence: e_navigator_signals::ProfilingConfidence::High,
            sample_count: 1,
            sampling_period_nanos: Some(10_000_000),
            stack_id: "stack:0123456789abcdef".to_string(),
            stack_frames: vec![],
            process: Some(NetworkProcessIdentity {
                pid: 102,
                ppid: Some(1),
                uid: Some(1000),
                command: "profile-client".to_string(),
                executable: Some("/app/profile-client".to_string()),
                cgroup_id: None,
            }),
            container: None,
            kubernetes: None,
            thread_id: None,
            thread_name: None,
            attributes: vec![],
        },
    );

    let processed = processor
        .process(signal)
        .await
        .expect("processor succeeds")
        .expect("signal remains");
    let e_navigator_signals::SignalPayload::ProfileSampleObservation(sample) = processed.payload
    else {
        panic!("expected profile sample payload");
    };
    assert_eq!(
        sample.container.as_ref().expect("container").container_id,
        container_id
    );
    assert_eq!(
        sample.kubernetes.as_ref().expect("kubernetes").pod_name,
        "profile-process-only-123"
    );

    fs::remove_dir_all(root).expect("fixture cleanup succeeds");
}

#[tokio::test]
async fn aya_cpu_profile_samples_keep_observed_provenance_through_attribution_and_generation() {
    let container_id = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd";
    let kubernetes = KubernetesContext {
        namespace: "default".to_string(),
        pod_name: "live-profile-client-123".to_string(),
        pod_uid: Some("live-profile-pod-uid".to_string()),
        container_name: Some("live-profile-client".to_string()),
        node_name: Some("node-a".to_string()),
        labels: BTreeMap::new(),
    };
    let (processor, root) = processor_fixture(104, container_id, kubernetes);
    let signal = SignalEnvelope::profile_sample_observation(
        "source.aya_cpu_profile",
        Some("node-a".to_string()),
        e_navigator_signals::ProfileSampleObservation {
            timestamp_unix_nanos: 1_500_000_000,
            profiling_kind: e_navigator_signals::ProfilingKind::Cpu,
            correlation_kind: e_navigator_signals::ProfilingCorrelationKind::ObservedProfileSample,
            confidence: e_navigator_signals::ProfilingConfidence::Medium,
            sample_count: 1,
            sampling_period_nanos: Some(20_408_163),
            stack_id: "stack:observed".to_string(),
            stack_frames: vec![],
            process: Some(NetworkProcessIdentity {
                pid: 104,
                ppid: None,
                uid: Some(1000),
                command: "live-profile-client".to_string(),
                executable: None,
                cgroup_id: None,
            }),
            container: None,
            kubernetes: None,
            thread_id: Some(104),
            thread_name: None,
            attributes: vec![e_navigator_signals::ProfilingAttribute {
                key: "profiling.source".to_string(),
                value: "aya_perf_event".to_string(),
            }],
        },
    );

    let processed = processor
        .process(signal)
        .await
        .expect("processor succeeds")
        .expect("signal remains");
    let outputs = observe_generator(
        &e_navigator_generators::ProfilingGenerator::default(),
        &processed,
    )
    .await;
    let window = outputs
        .iter()
        .find_map(|signal| match &signal.payload {
            e_navigator_signals::SignalPayload::ProfilingSessionObservation(window) => Some(window),
            _ => None,
        })
        .expect("profiling session exists");

    assert_eq!(window.source, "source.aya_cpu_profile");
    assert_eq!(
        window.correlation_kind,
        e_navigator_signals::ProfilingCorrelationKind::ObservedProfileSample
    );
    assert_eq!(
        window.container.as_ref().expect("container").container_id,
        container_id
    );
    assert_eq!(
        window.kubernetes.as_ref().expect("kubernetes").pod_name,
        "live-profile-client-123"
    );
    assert!(outputs.iter().all(|signal| {
        !matches!(
            signal.payload,
            e_navigator_signals::SignalPayload::ProfilingWarningObservation(_)
        )
    }));

    fs::remove_dir_all(root).expect("fixture cleanup succeeds");
}

#[tokio::test]
async fn profile_payload_variants_with_process_only_are_enriched_from_procfs_cgroup() {
    let container_id = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd";
    let kubernetes = KubernetesContext {
        namespace: "default".to_string(),
        pod_name: "profile-variant-123".to_string(),
        pod_uid: Some("profile-variant-uid".to_string()),
        container_name: Some("profile-client".to_string()),
        node_name: Some("node-a".to_string()),
        labels: BTreeMap::new(),
    };
    let (processor, root) = processor_fixture(103, container_id, kubernetes);
    let process = NetworkProcessIdentity {
        pid: 103,
        ppid: Some(1),
        uid: Some(1000),
        command: "profile-client".to_string(),
        executable: Some("/app/profile-client".to_string()),
        cgroup_id: None,
    };
    let signals = vec![
        SignalEnvelope::profiling_stack_trace_observation(
            "source.synthetic_exec",
            Some("node-a".to_string()),
            e_navigator_signals::ProfilingStackTraceObservation {
                timestamp_unix_nanos: 1_500_000_000,
                profiling_kind: e_navigator_signals::ProfilingKind::Cpu,
                correlation_kind: e_navigator_signals::ProfilingCorrelationKind::Synthetic,
                confidence: e_navigator_signals::ProfilingConfidence::High,
                stack_id: "stack:0123456789abcdef".to_string(),
                stack_frames: vec![],
                process: Some(process.clone()),
                container: None,
                kubernetes: None,
                attributes: vec![],
            },
        ),
        SignalEnvelope::profiling_session_observation(
            "generator.profiling",
            Some("node-a".to_string()),
            e_navigator_signals::ProfilingSessionObservation {
                window: e_navigator_signals::MetricAggregationWindow {
                    start_unix_nanos: 1_000_000_000,
                    end_unix_nanos: 2_000_000_000,
                },
                profiling_kind: e_navigator_signals::ProfilingKind::Cpu,
                correlation_kind: e_navigator_signals::ProfilingCorrelationKind::Synthetic,
                confidence: e_navigator_signals::ProfilingConfidence::High,
                profile_id: "profile:0123456789abcdef".to_string(),
                observed_sample_count: 1,
                dropped_sample_count: 0,
                distinct_stack_count: 1,
                sampling_period_nanos: Some(10_000_000),
                process: Some(process.clone()),
                container: None,
                kubernetes: None,
                source: "source.synthetic_exec".to_string(),
                attributes: vec![],
            },
        ),
        SignalEnvelope::profiling_warning_observation(
            "generator.profiling",
            Some("node-a".to_string()),
            e_navigator_signals::ProfilingWarningObservation {
                warning_type: "missing_attribution".to_string(),
                message: "missing attribution".to_string(),
                timestamp_unix_nanos: 1_500_000_000,
                source_signal_kind: "profile_sample_observation".to_string(),
                source_module: "source.synthetic_exec".to_string(),
                profiling_kind: e_navigator_signals::ProfilingKind::Cpu,
                correlation_kind: e_navigator_signals::ProfilingCorrelationKind::Synthetic,
                confidence: e_navigator_signals::ProfilingConfidence::Low,
                process: Some(process),
                container: None,
                kubernetes: None,
                attributes: vec![],
            },
        ),
    ];

    for signal in signals {
        let processed = processor
            .process(signal)
            .await
            .expect("processor succeeds")
            .expect("signal remains");
        let (container, kubernetes) = match processed.payload {
            e_navigator_signals::SignalPayload::ProfilingStackTraceObservation(event) => {
                (event.container, event.kubernetes)
            }
            e_navigator_signals::SignalPayload::ProfilingSessionObservation(event) => {
                (event.container, event.kubernetes)
            }
            e_navigator_signals::SignalPayload::ProfilingWarningObservation(event) => {
                (event.container, event.kubernetes)
            }
            _ => panic!("expected profiling payload"),
        };
        assert_eq!(
            container.as_ref().expect("container").container_id,
            container_id
        );
        assert_eq!(
            kubernetes.as_ref().expect("kubernetes").pod_name,
            "profile-variant-123"
        );
    }

    fs::remove_dir_all(root).expect("fixture cleanup succeeds");
}

async fn observe_generator<G>(generator: &G, signal: &SignalEnvelope) -> Vec<SignalEnvelope>
where
    G: Generator<SignalEnvelope>,
{
    let (tx, mut rx) = mpsc::channel(8);
    generator
        .observe(signal, &tx)
        .await
        .expect("generator succeeds");
    drop(tx);

    let mut outputs = Vec::new();
    while let Some(output) = rx.recv().await {
        outputs.push(output);
    }
    outputs
}

fn exec_with_container(container_id: &str) -> SignalEnvelope {
    SignalEnvelope::exec(
        "source.test",
        None,
        ExecEvent {
            pid: 7,
            ppid: Some(1),
            uid: Some(1000),
            command: "sh".to_string(),
            executable: Some("/bin/sh".to_string()),
            arguments: vec!["sh".to_string()],
            cgroup_id: None,
            timestamp_unix_nanos: 99,
            container: Some(ContainerContext {
                container_id: container_id.to_string(),
                runtime: Some("containerd".to_string()),
            }),
            kubernetes: None,
        },
    )
}

fn kube_context(pod_name: &str) -> KubernetesContext {
    KubernetesContext {
        namespace: "default".to_string(),
        pod_name: pod_name.to_string(),
        pod_uid: Some(format!("{pod_name}-uid")),
        container_name: Some("app".to_string()),
        node_name: Some("node-a".to_string()),
        labels: BTreeMap::new(),
    }
}

fn processor_fixture(
    pid: u32,
    container_id: &str,
    kubernetes: KubernetesContext,
) -> (ContainerAttributionProcessor, std::path::PathBuf) {
    let root = std::env::temp_dir().join(format!(
        "e-navigator-processor-generator-attribution-test-{}-{pid}",
        std::process::id()
    ));
    let pid_dir = root.join(pid.to_string());
    fs::create_dir_all(&pid_dir).expect("pid dir is created");
    fs::write(
        pid_dir.join("cgroup"),
        format!("0::/kubepods.slice/cri-containerd-{container_id}.scope\n"),
    )
    .expect("cgroup fixture is written");
    let processor = ContainerAttributionProcessor::with_cache(
        AttributionConfig {
            procfs_root: root.clone(),
            cgroup_root: root.clone(),
            kubernetes: KubernetesAttributionConfig {
                enabled: false,
                ..Default::default()
            },
        },
        KubernetesMetadataCache::from_contexts([(container_id.to_string(), kubernetes)]),
    );

    (processor, root)
}
