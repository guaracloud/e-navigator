use async_trait::async_trait;
use e_navigator_core::{AttributionConfig, CoreResult, ModuleKind, ModuleMetadata, Processor};
use e_navigator_signals::{ContainerContext, KubernetesContext, SignalEnvelope, SignalPayload};
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
use std::{
    collections::BTreeMap,
    fs, io,
    path::Path,
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, Instant},
};
use tracing::{debug, warn};

mod cgroup;
mod kubernetes;

use cgroup::{parse_container_from_cgroup, read_bounded_to_string};
pub use kubernetes::KubernetesMetadataCache;

const MAX_CGROUP_BYTES: u64 = 16 * 1024;
const MAX_PID_ATTRIBUTION_CACHE_ENTRIES: usize = 4096;
const MAX_CGROUP_ATTRIBUTION_CACHE_ENTRIES: usize = 4096;
const MIN_KUBERNETES_METADATA_REFRESH_INTERVAL: Duration = Duration::from_secs(30);
const MIN_KUBERNETES_METADATA_MISS_REFRESH_INTERVAL: Duration = Duration::from_secs(1);
const MIN_CGROUP_METADATA_REFRESH_INTERVAL: Duration = Duration::from_secs(1);

#[derive(Debug, Clone, Copy)]
struct KubernetesRefreshState {
    refreshed_at: Instant,
    requested_container_found: bool,
    immediate_retry_available: bool,
}

#[derive(Debug)]
pub struct ContainerAttributionProcessor {
    config: AttributionConfig,
    kubernetes_cache: Mutex<KubernetesMetadataCache>,
    kubernetes_provider: Arc<dyn KubernetesMetadataProvider>,
    last_kubernetes_refresh: Mutex<Option<KubernetesRefreshState>>,
    pid_cache: Mutex<BTreeMap<u32, Option<ContainerContext>>>,
    cgroup_id_cache: Mutex<BTreeMap<u64, ContainerContext>>,
    last_cgroup_refresh: Mutex<Option<Instant>>,
}

trait KubernetesMetadataProvider: std::fmt::Debug + Send + Sync {
    fn refresh(
        &self,
        config: &e_navigator_core::KubernetesAttributionConfig,
    ) -> Result<KubernetesMetadataCache, String>;
}

#[derive(Debug, Default)]
struct InClusterKubernetesMetadataProvider;

impl KubernetesMetadataProvider for InClusterKubernetesMetadataProvider {
    fn refresh(
        &self,
        config: &e_navigator_core::KubernetesAttributionConfig,
    ) -> Result<KubernetesMetadataCache, String> {
        KubernetesMetadataCache::from_in_cluster(config)
    }
}

impl Default for ContainerAttributionProcessor {
    fn default() -> Self {
        Self::new(AttributionConfig::default())
    }
}

impl ContainerAttributionProcessor {
    pub fn new(config: AttributionConfig) -> Self {
        let kubernetes_provider = Arc::new(InClusterKubernetesMetadataProvider);
        let kubernetes_cache = if config.kubernetes.enabled {
            kubernetes_provider
                .refresh(&config.kubernetes)
                .unwrap_or_else(|err| {
                    warn!(error = %err, "kubernetes metadata cache unavailable");
                    KubernetesMetadataCache::default()
                })
        } else {
            KubernetesMetadataCache::default()
        };

        Self {
            config,
            kubernetes_cache: Mutex::new(kubernetes_cache),
            kubernetes_provider,
            last_kubernetes_refresh: Mutex::new(None),
            pid_cache: Mutex::new(BTreeMap::new()),
            cgroup_id_cache: Mutex::new(BTreeMap::new()),
            last_cgroup_refresh: Mutex::new(None),
        }
    }

    pub fn with_cache(
        config: AttributionConfig,
        kubernetes_cache: KubernetesMetadataCache,
    ) -> Self {
        Self::with_cache_and_provider(
            config,
            kubernetes_cache,
            InClusterKubernetesMetadataProvider,
        )
    }

    fn with_cache_and_provider(
        config: AttributionConfig,
        kubernetes_cache: KubernetesMetadataCache,
        kubernetes_provider: impl KubernetesMetadataProvider + 'static,
    ) -> Self {
        Self {
            config,
            kubernetes_cache: Mutex::new(kubernetes_cache),
            kubernetes_provider: Arc::new(kubernetes_provider),
            last_kubernetes_refresh: Mutex::new(None),
            pid_cache: Mutex::new(BTreeMap::new()),
            cgroup_id_cache: Mutex::new(BTreeMap::new()),
            last_cgroup_refresh: Mutex::new(None),
        }
    }
}

#[async_trait]
impl Processor<SignalEnvelope> for ContainerAttributionProcessor {
    fn metadata(&self) -> ModuleMetadata {
        ModuleMetadata::new("processor.container_attribution", ModuleKind::Processor)
    }

    async fn process(&self, mut signal: SignalEnvelope) -> CoreResult<Option<SignalEnvelope>> {
        match &mut signal.payload {
            SignalPayload::Exec(event) => {
                if event.container.is_none() {
                    event.container = self.container_for_pid_or_cgroup(event.pid, event.cgroup_id);
                }
                if event.kubernetes.is_none() {
                    event.kubernetes = event.container.as_ref().and_then(|container| {
                        self.kubernetes_context_for_container(&container.container_id)
                    });
                }
            }
            SignalPayload::ProcessExit(event) => {
                if event.container.is_none() {
                    event.container = self.container_for_pid_or_cgroup(event.pid, event.cgroup_id);
                }
                if event.kubernetes.is_none() {
                    event.kubernetes = event.container.as_ref().and_then(|container| {
                        self.kubernetes_context_for_container(&container.container_id)
                    });
                }
                self.evict_pid_cache(event.pid);
            }
            SignalPayload::ProcessLifecycleDuration(event) => {
                if event.kubernetes.is_none() {
                    event.kubernetes = event.container.as_ref().and_then(|container| {
                        self.kubernetes_context_for_container(&container.container_id)
                    });
                }
            }
            SignalPayload::NetworkConnectionOpen(event) => {
                self.enrich_context(
                    event.process.pid,
                    event.process.cgroup_id,
                    &mut event.container,
                    &mut event.kubernetes,
                );
            }
            SignalPayload::NetworkConnectionClose(event) => {
                self.enrich_context(
                    event.process.pid,
                    event.process.cgroup_id,
                    &mut event.container,
                    &mut event.kubernetes,
                );
            }
            SignalPayload::NetworkConnectionFailure(event) => {
                self.enrich_context(
                    event.process.pid,
                    event.process.cgroup_id,
                    &mut event.container,
                    &mut event.kubernetes,
                );
            }
            SignalPayload::DnsQuery(event) => {
                self.enrich_context(
                    event.process.pid,
                    event.process.cgroup_id,
                    &mut event.container,
                    &mut event.kubernetes,
                );
            }
            SignalPayload::DnsResponse(event) => {
                self.enrich_context(
                    event.process.pid,
                    event.process.cgroup_id,
                    &mut event.container,
                    &mut event.kubernetes,
                );
            }
            SignalPayload::ProtocolRequestObservation(event) => {
                self.enrich_existing_container_context(&mut event.container, &mut event.kubernetes);
            }
            SignalPayload::ExtractedTraceContextObservation(event) => {
                self.enrich_existing_container_context(&mut event.container, &mut event.kubernetes);
            }
            SignalPayload::RequestSpanObservation(event) => {
                self.enrich_existing_container_context(&mut event.container, &mut event.kubernetes);
            }
            SignalPayload::RequestCorrelationWarning(event) => {
                self.enrich_existing_container_context(&mut event.container, &mut event.kubernetes);
            }
            SignalPayload::ProfileSampleObservation(event) => {
                self.enrich_profile_context(
                    event.process.as_ref().map(|process| process.pid),
                    event.process.as_ref().and_then(|process| process.cgroup_id),
                    &mut event.container,
                    &mut event.kubernetes,
                )
                .await;
            }
            SignalPayload::ProfilingStackTraceObservation(event) => {
                self.enrich_profile_context(
                    event.process.as_ref().map(|process| process.pid),
                    event.process.as_ref().and_then(|process| process.cgroup_id),
                    &mut event.container,
                    &mut event.kubernetes,
                )
                .await;
            }
            SignalPayload::ProfilingSessionObservation(event) => {
                self.enrich_profile_context(
                    event.process.as_ref().map(|process| process.pid),
                    event.process.as_ref().and_then(|process| process.cgroup_id),
                    &mut event.container,
                    &mut event.kubernetes,
                )
                .await;
            }
            SignalPayload::ProfilingWarningObservation(event) => {
                self.enrich_profile_context(
                    event.process.as_ref().map(|process| process.pid),
                    event.process.as_ref().and_then(|process| process.cgroup_id),
                    &mut event.container,
                    &mut event.kubernetes,
                )
                .await;
            }
            SignalPayload::ProcessResourceObservation(event) => {
                self.enrich_context(
                    event.process.pid,
                    None,
                    &mut event.process.container,
                    &mut event.process.kubernetes,
                );
            }
            SignalPayload::CgroupCpuObservation(event) => {
                self.enrich_cgroup_context(&mut event.cgroup);
            }
            SignalPayload::CgroupMemoryObservation(event) => {
                self.enrich_cgroup_context(&mut event.cgroup);
            }
            SignalPayload::CgroupPidsObservation(event) => {
                self.enrich_cgroup_context(&mut event.cgroup);
            }
            SignalPayload::CgroupFileDescriptorObservation(event) => {
                self.enrich_cgroup_context(&mut event.cgroup);
            }
            SignalPayload::ServiceInteractionSpanObservation(event) => {
                self.enrich_dependency_endpoint(&mut event.source);
                self.enrich_dependency_endpoint(&mut event.destination);
            }
            SignalPayload::TraceServicePathObservation(event) => {
                self.enrich_dependency_endpoint(&mut event.source);
                self.enrich_dependency_endpoint(&mut event.destination);
            }
            SignalPayload::DependencyEdge(event) => {
                self.enrich_dependency_endpoint(&mut event.source);
                self.enrich_dependency_endpoint(&mut event.destination);
            }
            SignalPayload::RuntimeSecurityFinding(_) => {}
            _ => {}
        }

        Ok(Some(signal))
    }
}

impl ContainerAttributionProcessor {
    fn enrich_context(
        &self,
        pid: u32,
        cgroup_id: Option<u64>,
        container: &mut Option<ContainerContext>,
        kubernetes: &mut Option<KubernetesContext>,
    ) {
        if container.is_none() {
            *container = self.container_for_pid_or_cgroup(pid, cgroup_id);
        }
        if kubernetes.is_none() {
            *kubernetes = container.as_ref().and_then(|container| {
                self.kubernetes_context_for_container(&container.container_id)
            });
        }
    }

    fn enrich_existing_container_context(
        &self,
        container: &mut Option<ContainerContext>,
        kubernetes: &mut Option<KubernetesContext>,
    ) {
        if kubernetes.is_none() {
            *kubernetes = container.as_ref().and_then(|container| {
                self.kubernetes_context_for_container(&container.container_id)
            });
        }
    }

    fn enrich_dependency_endpoint(&self, endpoint: &mut e_navigator_signals::DependencyEndpoint) {
        if endpoint.workload.is_none() {
            endpoint.workload = endpoint.container.as_ref().and_then(|container| {
                self.kubernetes_context_for_container(&container.container_id)
            });
        }
    }

    async fn enrich_profile_context(
        &self,
        pid: Option<u32>,
        cgroup_id: Option<u64>,
        container: &mut Option<ContainerContext>,
        kubernetes: &mut Option<KubernetesContext>,
    ) {
        if let Some(pid) = pid {
            if container.is_none() {
                *container = self.container_for_pid_or_cgroup_async(pid, cgroup_id).await;
            }
            if kubernetes.is_none() {
                *kubernetes = container.as_ref().and_then(|container| {
                    self.kubernetes_context_for_container(&container.container_id)
                });
            }
        } else {
            self.enrich_existing_container_context(container, kubernetes);
        }
    }

    fn enrich_cgroup_context(&self, cgroup: &mut e_navigator_signals::CgroupResourceContext) {
        if cgroup.container.is_none() {
            cgroup.container = parse_container_from_cgroup(&cgroup.cgroup_path);
        }
        self.cache_cgroup_context(cgroup);
        if cgroup.kubernetes.is_none() {
            cgroup.kubernetes = cgroup.container.as_ref().and_then(|container| {
                self.kubernetes_context_for_container(&container.container_id)
            });
        }
    }

    fn container_for_pid_or_cgroup(
        &self,
        pid: u32,
        cgroup_id: Option<u64>,
    ) -> Option<ContainerContext> {
        self.container_for_pid(pid)
            .or_else(|| cgroup_id.and_then(|cgroup_id| self.container_for_cgroup_id(cgroup_id)))
    }

    async fn container_for_pid_or_cgroup_async(
        &self,
        pid: u32,
        cgroup_id: Option<u64>,
    ) -> Option<ContainerContext> {
        match self.container_for_pid_async(pid).await {
            Some(container) => Some(container),
            None => cgroup_id.and_then(|cgroup_id| self.container_for_cgroup_id(cgroup_id)),
        }
    }

    fn kubernetes_context_for_container(&self, container_id: &str) -> Option<KubernetesContext> {
        if let Some(context) = self.cached_kubernetes_context(container_id) {
            return Some(context);
        }

        if !self.config.kubernetes.enabled || !self.should_refresh_kubernetes_cache() {
            return None;
        }

        match self.kubernetes_provider.refresh(&self.config.kubernetes) {
            Ok(cache) => {
                let cache_entries = cache.len();
                let requested_container_found = cache.contains_container(container_id);
                if let Ok(mut kubernetes_cache) = self.kubernetes_cache.lock() {
                    *kubernetes_cache = cache;
                }
                self.record_kubernetes_refresh(requested_container_found);
                debug!(
                    cache_entries,
                    requested_container_found, "kubernetes metadata cache refreshed"
                );
            }
            Err(err) => {
                self.record_kubernetes_refresh(false);
                warn!(error = %err, "kubernetes metadata cache refresh failed");
                return None;
            }
        }

        self.cached_kubernetes_context(container_id)
    }

    fn cached_kubernetes_context(&self, container_id: &str) -> Option<KubernetesContext> {
        self.kubernetes_cache
            .lock()
            .ok()
            .and_then(|cache| cache.get(container_id))
    }

    fn should_refresh_kubernetes_cache(&self) -> bool {
        let Ok(last_refresh) = self.last_kubernetes_refresh.lock() else {
            return false;
        };
        let now = Instant::now();
        let Some(last_refresh) = *last_refresh else {
            return true;
        };

        if last_refresh.requested_container_found {
            return now.duration_since(last_refresh.refreshed_at)
                >= MIN_KUBERNETES_METADATA_REFRESH_INTERVAL;
        }

        last_refresh.immediate_retry_available
            || now.duration_since(last_refresh.refreshed_at)
                >= MIN_KUBERNETES_METADATA_MISS_REFRESH_INTERVAL
    }

    fn record_kubernetes_refresh(&self, requested_container_found: bool) {
        let Ok(mut last_refresh) = self.last_kubernetes_refresh.lock() else {
            return;
        };
        let immediate_retry_available = if requested_container_found {
            false
        } else {
            !last_refresh.is_some_and(|state| {
                !state.requested_container_found && state.immediate_retry_available
            })
        };
        *last_refresh = Some(KubernetesRefreshState {
            refreshed_at: Instant::now(),
            requested_container_found,
            immediate_retry_available,
        });
    }

    fn container_for_pid(&self, pid: u32) -> Option<ContainerContext> {
        if let Some(container) = self.cached_container_for_pid(pid) {
            return container;
        }

        let path = self.config.procfs_root.join(pid.to_string()).join("cgroup");
        let container = match read_bounded_to_string(&path, MAX_CGROUP_BYTES) {
            Ok(contents) => parse_container_from_cgroup(&contents),
            Err(err) => {
                log_process_cgroup_read_error(pid, &path, &err);
                None
            }
        };
        if container.is_some() {
            self.store_cached_container_for_pid(pid, container.clone());
        }
        container
    }

    fn container_for_cgroup_id(&self, cgroup_id: u64) -> Option<ContainerContext> {
        if let Some(container) = self.cached_container_for_cgroup_id(cgroup_id) {
            return Some(container);
        }
        if self.should_refresh_cgroup_cache() {
            self.refresh_cgroup_id_cache();
        }
        self.cached_container_for_cgroup_id(cgroup_id)
    }

    fn cached_container_for_cgroup_id(&self, cgroup_id: u64) -> Option<ContainerContext> {
        self.cgroup_id_cache
            .lock()
            .ok()
            .and_then(|cache| cache.get(&cgroup_id).cloned())
    }

    fn should_refresh_cgroup_cache(&self) -> bool {
        let Ok(mut last_refresh) = self.last_cgroup_refresh.lock() else {
            return false;
        };
        let now = Instant::now();
        if last_refresh
            .is_some_and(|last| now.duration_since(last) < MIN_CGROUP_METADATA_REFRESH_INTERVAL)
        {
            return false;
        }
        *last_refresh = Some(now);
        true
    }

    fn refresh_cgroup_id_cache(&self) {
        let cache = scan_cgroup_id_cache(&self.config.cgroup_root);
        if cache.is_empty() {
            return;
        }
        if let Ok(mut cgroup_cache) = self.cgroup_id_cache.lock() {
            *cgroup_cache = cache;
        }
    }

    fn cache_cgroup_context(&self, cgroup: &e_navigator_signals::CgroupResourceContext) {
        let Some(container) = cgroup.container.clone() else {
            return;
        };
        let path = self
            .config
            .cgroup_root
            .join(cgroup.cgroup_path.trim_start_matches('/'));
        let Some(cgroup_id) = cgroup_path_id(&path) else {
            return;
        };
        if let Ok(mut cache) = self.cgroup_id_cache.lock() {
            if cache.len() >= MAX_CGROUP_ATTRIBUTION_CACHE_ENTRIES
                && !cache.contains_key(&cgroup_id)
                && let Some(oldest_id) = cache.keys().next().copied()
            {
                cache.remove(&oldest_id);
            }
            cache.insert(cgroup_id, container);
        }
    }

    async fn container_for_pid_async(&self, pid: u32) -> Option<ContainerContext> {
        if let Some(container) = self.cached_container_for_pid(pid) {
            return container;
        }

        let path = self.config.procfs_root.join(pid.to_string()).join("cgroup");
        let read_path = path.clone();
        let container = match tokio::task::spawn_blocking(move || {
            read_bounded_to_string(&read_path, MAX_CGROUP_BYTES)
                .map(|contents| parse_container_from_cgroup(&contents))
        })
        .await
        {
            Ok(Ok(container)) => container,
            Ok(Err(err)) => {
                log_process_cgroup_read_error(pid, &path, &err);
                None
            }
            Err(err) => {
                warn!(
                    pid,
                    path = %path.display(),
                    error = %err,
                    "unable to join process cgroup attribution task"
                );
                None
            }
        };
        if container.is_some() {
            self.store_cached_container_for_pid(pid, container.clone());
        }
        container
    }

    fn cached_container_for_pid(&self, pid: u32) -> Option<Option<ContainerContext>> {
        self.pid_cache()
            .ok()
            .and_then(|cache| cache.get(&pid).cloned())
    }

    fn store_cached_container_for_pid(&self, pid: u32, container: Option<ContainerContext>) {
        let Ok(mut cache) = self.pid_cache() else {
            return;
        };
        if cache.len() >= MAX_PID_ATTRIBUTION_CACHE_ENTRIES
            && !cache.contains_key(&pid)
            && let Some(oldest_pid) = cache.keys().next().copied()
        {
            cache.remove(&oldest_pid);
        }
        cache.insert(pid, container);
    }

    fn evict_pid_cache(&self, pid: u32) {
        if let Ok(mut cache) = self.pid_cache() {
            cache.remove(&pid);
        }
    }

    fn pid_cache(&self) -> Result<MutexGuard<'_, BTreeMap<u32, Option<ContainerContext>>>, String> {
        self.pid_cache.lock().map_err(|err| err.to_string())
    }
}

fn scan_cgroup_id_cache(root: &Path) -> BTreeMap<u64, ContainerContext> {
    let mut cache = BTreeMap::new();
    let mut queue = vec![root.to_path_buf()];

    while let Some(path) = queue.pop() {
        if cache.len() >= MAX_CGROUP_ATTRIBUTION_CACHE_ENTRIES {
            break;
        }
        let Some(id) = cgroup_path_id(&path) else {
            continue;
        };
        if let Ok(relative) = path.strip_prefix(root) {
            let cgroup_path = normalized_cgroup_path(relative);
            if let Some(container) = parse_container_from_cgroup(&cgroup_path) {
                cache.insert(id, container);
            }
        }
        let Ok(entries) = fs::read_dir(&path) else {
            continue;
        };
        for entry in entries.filter_map(Result::ok) {
            if queue.len().saturating_add(cache.len()) >= MAX_CGROUP_ATTRIBUTION_CACHE_ENTRIES {
                break;
            }
            if entry.file_type().is_ok_and(|file_type| file_type.is_dir()) {
                queue.push(entry.path());
            }
        }
    }

    cache
}

fn normalized_cgroup_path(path: &Path) -> String {
    let text = path.to_string_lossy();
    if text.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", text.trim_start_matches('/'))
    }
}

#[cfg(unix)]
fn cgroup_path_id(path: &Path) -> Option<u64> {
    path.metadata().ok().map(|metadata| metadata.ino())
}

#[cfg(not(unix))]
fn cgroup_path_id(_path: &Path) -> Option<u64> {
    None
}

fn log_process_cgroup_read_error(pid: u32, path: &Path, err: &io::Error) {
    if is_expected_process_exit_race(err) {
        debug!(
            pid,
            path = %path.display(),
            error = %err,
            "process cgroup disappeared before attribution"
        );
    } else {
        warn!(
            pid,
            path = %path.display(),
            error = %err,
            "unable to read process cgroup for attribution"
        );
    }
}

fn is_expected_process_exit_race(err: &io::Error) -> bool {
    err.kind() == io::ErrorKind::NotFound
}

#[cfg(test)]
mod tests {
    use super::*;
    use e_navigator_core::{Generator, KubernetesAttributionConfig};
    use e_navigator_generators::{
        DnsMetricsGenerator, NetworkMetricsGenerator, RequestCorrelationGenerator,
        ResourceMetricsGenerator, TraceCorrelationGenerator,
    };
    use e_navigator_signals::{
        ContainerContext, DependencyEdgeEvent, DependencyEndpoint, DnsQueryEvent, DnsQueryType,
        ExecEvent, KubernetesContext, NetworkAddressFamily, NetworkConnectionCloseEvent,
        NetworkConnectionOpenEvent, NetworkProcessIdentity, NetworkProtocol, ProcessExitEvent,
        ProtocolKind, ProtocolRequestObservation, TraceConfidence, TraceCorrelationKind,
        TracePeerContext,
    };
    use std::{
        collections::{BTreeMap, VecDeque},
        fs,
    };
    use tokio::sync::mpsc;

    #[derive(Debug)]
    struct StaticKubernetesMetadataProvider {
        cache: KubernetesMetadataCache,
    }

    impl StaticKubernetesMetadataProvider {
        fn new(cache: KubernetesMetadataCache) -> Self {
            Self { cache }
        }
    }

    impl KubernetesMetadataProvider for StaticKubernetesMetadataProvider {
        fn refresh(
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

    impl KubernetesMetadataProvider for SequencedKubernetesMetadataProvider {
        fn refresh(
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

        let e_navigator_signals::SignalPayload::NetworkConnectionOpen(event) = processed.payload
        else {
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

        let processed = processor
            .process(signal)
            .await
            .expect("processor succeeds")
            .expect("signal remains");

        let e_navigator_signals::SignalPayload::NetworkConnectionOpen(event) = processed.payload
        else {
            panic!("expected network open payload");
        };
        assert_eq!(
            event.container.as_ref().expect("container").container_id,
            container_id
        );
        assert_eq!(
            event.kubernetes.as_ref().expect("kubernetes").namespace,
            "e-navigator-test"
        );
        assert_eq!(
            event.kubernetes.as_ref().expect("kubernetes").pod_name,
            "known-exec-network-dns"
        );

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
            SequencedKubernetesMetadataProvider::new([
                KubernetesMetadataCache::default(),
                later_cache,
            ]),
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
        let e_navigator_signals::SignalPayload::NetworkConnectionOpen(second_event) =
            second.payload
        else {
            panic!("expected network open payload");
        };
        assert_eq!(
            second_event
                .kubernetes
                .as_ref()
                .expect("kubernetes")
                .pod_name,
            "known-exec-network-dns"
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
                e_navigator_signals::SignalPayload::ProfilingSessionObservation(window) => {
                    Some(window)
                }
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
        let e_navigator_signals::SignalPayload::ProfileSampleObservation(sample) =
            processed.payload
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
                correlation_kind:
                    e_navigator_signals::ProfilingCorrelationKind::ObservedProfileSample,
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
                e_navigator_signals::SignalPayload::ProfilingSessionObservation(window) => {
                    Some(window)
                }
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
}
