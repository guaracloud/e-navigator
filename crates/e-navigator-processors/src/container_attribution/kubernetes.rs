use async_trait::async_trait;
use e_navigator_core::{
    KubernetesAttributionConfig,
    capture_filter::{RawEndpointSlice, RawPod, RawService},
};
use e_navigator_signals::KubernetesContext;
use serde::Deserialize;
use std::{
    collections::BTreeMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
use tracing::{debug, warn};

use super::cgroup::read_bounded_to_string;

const MAX_TOKEN_BYTES: u64 = 64 * 1024;
const MIN_KUBERNETES_METADATA_REFRESH_INTERVAL: Duration = Duration::from_secs(30);
const MIN_KUBERNETES_METADATA_MISS_REFRESH_INTERVAL: Duration = Duration::from_secs(1);

#[derive(Debug, Clone, Copy)]
struct KubernetesRefreshState {
    refreshed_at: Instant,
    requested_container_found: bool,
    immediate_retry_available: bool,
    in_progress: bool,
    last_success_at: Option<Instant>,
}

#[derive(Debug)]
pub(super) struct KubernetesAttribution {
    config: KubernetesAttributionConfig,
    cache: Arc<Mutex<KubernetesMetadataCache>>,
    provider: Arc<dyn KubernetesMetadataProvider>,
    last_refresh: Arc<Mutex<Option<KubernetesRefreshState>>>,
    diagnostics: Arc<KubernetesRefreshDiagnostics>,
}

impl KubernetesAttribution {
    pub(super) fn new(config: KubernetesAttributionConfig) -> Self {
        let provider = Arc::new(InClusterKubernetesMetadataProvider);
        Self::with_cache_and_provider(config, KubernetesMetadataCache::default(), provider)
    }

    pub(super) fn with_cache(
        config: KubernetesAttributionConfig,
        cache: KubernetesMetadataCache,
    ) -> Self {
        Self::with_cache_and_provider(config, cache, Arc::new(InClusterKubernetesMetadataProvider))
    }

    pub(super) fn with_cache_and_provider(
        config: KubernetesAttributionConfig,
        cache: KubernetesMetadataCache,
        provider: Arc<dyn KubernetesMetadataProvider>,
    ) -> Self {
        Self {
            config,
            cache: Arc::new(Mutex::new(cache)),
            provider,
            last_refresh: Arc::new(Mutex::new(None)),
            diagnostics: Arc::new(KubernetesRefreshDiagnostics::default()),
        }
    }

    pub(super) fn context_for_container(&self, container_id: &str) -> Option<KubernetesContext> {
        let cached = self.cached_context(container_id);
        if cached.is_some() && self.cache_is_stale() {
            self.diagnostics
                .stale_cache_uses
                .fetch_add(1, Ordering::Relaxed);
        }

        if self.config.enabled && self.start_refresh_if_needed(container_id, cached.is_some()) {
            self.spawn_refresh(container_id.to_string());
        } else if cached.is_none() {
            self.diagnostics
                .skipped_attribution
                .fetch_add(1, Ordering::Relaxed);
        }

        cached
    }

    pub(super) fn context_for_pod_ip(&self, pod_ip: &str) -> Option<KubernetesContext> {
        self.cache
            .lock()
            .ok()
            .and_then(|cache| cache.get_by_pod_ip(pod_ip))
    }

    pub(super) fn owner_for_context(&self, context: &KubernetesContext) -> Option<WorkloadOwner> {
        self.cache
            .lock()
            .ok()
            .and_then(|cache| cache.get_owner_for_context(context))
    }

    pub(super) fn owner_for_address(&self, address: &str) -> Option<WorkloadOwner> {
        self.cache
            .lock()
            .ok()
            .and_then(|cache| cache.get_owner_for_address(address))
    }

    fn cached_context(&self, container_id: &str) -> Option<KubernetesContext> {
        self.cache
            .lock()
            .ok()
            .and_then(|cache| cache.get(container_id))
    }

    fn cache_is_stale(&self) -> bool {
        let Ok(last_refresh) = self.last_refresh.lock() else {
            return true;
        };
        let Some(last_refresh) = *last_refresh else {
            return true;
        };
        last_refresh.last_success_at.is_none_or(|success_at| {
            Instant::now().duration_since(success_at) >= MIN_KUBERNETES_METADATA_REFRESH_INTERVAL
        })
    }

    fn start_refresh_if_needed(&self, container_id: &str, cache_hit: bool) -> bool {
        let Ok(mut last_refresh) = self.last_refresh.lock() else {
            return false;
        };
        let now = Instant::now();
        let Some(state) = *last_refresh else {
            *last_refresh = Some(KubernetesRefreshState {
                refreshed_at: now,
                requested_container_found: false,
                immediate_retry_available: false,
                in_progress: true,
                last_success_at: None,
            });
            return true;
        };

        if state.in_progress {
            self.diagnostics
                .refresh_skipped
                .fetch_add(1, Ordering::Relaxed);
            return false;
        }

        let should_refresh = if cache_hit {
            state.requested_container_found
                && now.duration_since(state.refreshed_at)
                    >= MIN_KUBERNETES_METADATA_REFRESH_INTERVAL
        } else if state.requested_container_found {
            true
        } else {
            state.immediate_retry_available
                || now.duration_since(state.refreshed_at)
                    >= MIN_KUBERNETES_METADATA_MISS_REFRESH_INTERVAL
        };

        if should_refresh {
            *last_refresh = Some(KubernetesRefreshState {
                in_progress: true,
                ..state
            });
        } else {
            self.diagnostics
                .refresh_skipped
                .fetch_add(1, Ordering::Relaxed);
            debug!(container_id, "kubernetes metadata refresh skipped");
        }

        should_refresh
    }

    fn spawn_refresh(&self, requested_container_id: String) {
        self.diagnostics
            .refresh_attempts
            .fetch_add(1, Ordering::Relaxed);
        let config = self.config.clone();
        let cache = self.cache.clone();
        let last_refresh = self.last_refresh.clone();
        let provider = self.provider.clone();
        let diagnostics = self.diagnostics.clone();

        tokio::spawn(async move {
            match provider.refresh(&config).await {
                Ok(new_cache) => {
                    let cache_entries = new_cache.len();
                    let requested_container_found =
                        new_cache.contains_container(&requested_container_id);
                    if let Err(err) = install_refreshed_cache(cache.as_ref(), new_cache) {
                        diagnostics.refresh_failures.fetch_add(1, Ordering::Relaxed);
                        record_refresh_state(last_refresh.as_ref(), false, false);
                        warn!(
                            error = err,
                            cache_entries,
                            requested_container_found,
                            "kubernetes metadata cache refresh failed to install"
                        );
                        return;
                    }
                    record_refresh_state(last_refresh.as_ref(), requested_container_found, true);
                    diagnostics
                        .cache_entries
                        .store(cache_entries as u64, Ordering::Relaxed);
                    debug!(
                        cache_entries,
                        requested_container_found, "kubernetes metadata cache refreshed"
                    );
                }
                Err(err) => {
                    diagnostics.refresh_failures.fetch_add(1, Ordering::Relaxed);
                    record_refresh_state(last_refresh.as_ref(), false, false);
                    warn!(error = %err, "kubernetes metadata cache refresh failed");
                }
            }
        });
    }
}

fn install_refreshed_cache(
    cache: &Mutex<KubernetesMetadataCache>,
    new_cache: KubernetesMetadataCache,
) -> Result<(), &'static str> {
    let Ok(mut kubernetes_cache) = cache.lock() else {
        return Err("kubernetes metadata cache lock poisoned");
    };
    *kubernetes_cache = new_cache;
    Ok(())
}

fn record_refresh_state(
    last_refresh: &Mutex<Option<KubernetesRefreshState>>,
    requested_container_found: bool,
    succeeded: bool,
) {
    let Ok(mut last_refresh) = last_refresh.lock() else {
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
        in_progress: false,
        last_success_at: if succeeded {
            Some(Instant::now())
        } else {
            last_refresh.and_then(|state| state.last_success_at)
        },
    });
}

#[derive(Debug, Default)]
struct KubernetesRefreshDiagnostics {
    refresh_attempts: AtomicU64,
    refresh_failures: AtomicU64,
    refresh_skipped: AtomicU64,
    stale_cache_uses: AtomicU64,
    skipped_attribution: AtomicU64,
    cache_entries: AtomicU64,
}

#[async_trait]
pub trait KubernetesMetadataProvider: std::fmt::Debug + Send + Sync {
    async fn refresh(
        &self,
        config: &KubernetesAttributionConfig,
    ) -> Result<KubernetesMetadataCache, String>;
}

#[derive(Debug, Default)]
struct InClusterKubernetesMetadataProvider;

#[async_trait]
impl KubernetesMetadataProvider for InClusterKubernetesMetadataProvider {
    async fn refresh(
        &self,
        config: &KubernetesAttributionConfig,
    ) -> Result<KubernetesMetadataCache, String> {
        KubernetesMetadataCache::from_in_cluster(config).await
    }
}

#[derive(Debug, Clone, Default)]
pub struct KubernetesMetadataCache {
    by_container_id: BTreeMap<String, KubernetesContext>,
    by_pod_ip: BTreeMap<String, KubernetesContext>,
    owners_by_pod: BTreeMap<String, WorkloadOwner>,
    owners_by_address: BTreeMap<String, WorkloadOwner>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct WorkloadOwner {
    pub(super) name: String,
    pub(super) owner_type: String,
}

impl KubernetesMetadataCache {
    pub fn from_contexts(contexts: impl IntoIterator<Item = (String, KubernetesContext)>) -> Self {
        Self {
            by_container_id: contexts.into_iter().collect(),
            by_pod_ip: BTreeMap::new(),
            owners_by_pod: BTreeMap::new(),
            owners_by_address: BTreeMap::new(),
        }
    }

    pub fn from_contexts_and_pod_ips(
        contexts: impl IntoIterator<Item = (String, KubernetesContext)>,
        pod_ips: impl IntoIterator<Item = (String, KubernetesContext)>,
    ) -> Self {
        Self {
            by_container_id: contexts.into_iter().collect(),
            by_pod_ip: pod_ips.into_iter().collect(),
            owners_by_pod: BTreeMap::new(),
            owners_by_address: BTreeMap::new(),
        }
    }

    /// Build the scoped attribution indexes from the shared workload
    /// controller snapshot without performing Kubernetes API I/O.
    pub fn from_raw_pods(pods: &[RawPod], config: &KubernetesAttributionConfig) -> Self {
        Self::from_raw_resources(pods, &[], &[], config)
    }

    pub fn from_raw_resources(
        pods: &[RawPod],
        services: &[RawService],
        endpoint_slices: &[RawEndpointSlice],
        config: &KubernetesAttributionConfig,
    ) -> Self {
        let mut by_container_id = BTreeMap::new();
        let mut by_pod_ip = BTreeMap::new();
        let mut owners_by_pod = BTreeMap::new();
        let mut owners_by_address = BTreeMap::new();
        let mut selected_pods = 0_usize;

        for pod in pods {
            if !pod_matches_scope(
                &pod.namespace,
                pod.node_name.as_deref(),
                &pod.labels,
                config,
            ) {
                continue;
            }
            if selected_pods >= config.max_pods {
                break;
            }
            selected_pods = selected_pods.saturating_add(1);
            let labels = bounded_labels(pod.labels.clone(), config);
            let owner = raw_pod_owner(pod);
            if topology_cache_entry_count(&owners_by_pod, &owners_by_address)
                < config.max_cache_entries
            {
                owners_by_pod.insert(raw_pod_key(pod), owner.clone());
            }
            for container_id in &pod.container_ids {
                if cache_entry_count(&by_container_id, &by_pod_ip) >= config.max_cache_entries {
                    warn!(
                        max_cache_entries = config.max_cache_entries,
                        "shared Kubernetes metadata cache entry limit reached"
                    );
                    return Self {
                        by_container_id,
                        by_pod_ip,
                        owners_by_pod,
                        owners_by_address,
                    };
                }
                let context = KubernetesContext {
                    namespace: pod.namespace.clone(),
                    pod_name: pod.pod_name.clone(),
                    pod_uid: pod.pod_uid.clone(),
                    container_name: pod.container_names.get(container_id).cloned(),
                    node_name: pod.node_name.clone(),
                    labels: labels.clone(),
                };
                by_container_id.insert(container_id.clone(), context.clone());
                if let Some(pod_ip) = pod.pod_ip.as_ref().filter(|value| !value.is_empty())
                    && !by_pod_ip.contains_key(pod_ip)
                    && cache_entry_count(&by_container_id, &by_pod_ip) < config.max_cache_entries
                {
                    by_pod_ip.insert(pod_ip.clone(), context);
                    if topology_cache_entry_count(&owners_by_pod, &owners_by_address)
                        < config.max_cache_entries
                    {
                        owners_by_address.insert(pod_ip.clone(), owner.clone());
                    }
                }
            }
        }

        let service_owners = services
            .iter()
            .filter(|service| namespace_matches_scope(&service.namespace, config))
            .map(|service| {
                (
                    format!("{}/{}", service.namespace, service.service_name),
                    WorkloadOwner {
                        name: format!("{}/{}", service.namespace, service.service_name),
                        owner_type: "service".to_string(),
                    },
                    service,
                )
            })
            .collect::<Vec<_>>();
        for (_, owner, service) in &service_owners {
            for cluster_ip in &service.cluster_ips {
                if !by_pod_ip.contains_key(cluster_ip)
                    && topology_cache_entry_count(&owners_by_pod, &owners_by_address)
                        < config.max_cache_entries
                {
                    owners_by_address
                        .entry(cluster_ip.clone())
                        .or_insert_with(|| owner.clone());
                }
            }
        }
        let owners_by_service = service_owners
            .into_iter()
            .map(|(key, owner, _)| (key, owner))
            .collect::<BTreeMap<_, _>>();
        for slice in endpoint_slices {
            let service_key = format!("{}/{}", slice.namespace, slice.service_name);
            let Some(owner) = owners_by_service.get(&service_key) else {
                continue;
            };
            for address in &slice.addresses {
                if !by_pod_ip.contains_key(address)
                    && topology_cache_entry_count(&owners_by_pod, &owners_by_address)
                        < config.max_cache_entries
                {
                    owners_by_address
                        .entry(address.clone())
                        .or_insert_with(|| owner.clone());
                }
            }
        }

        Self {
            by_container_id,
            by_pod_ip,
            owners_by_pod,
            owners_by_address,
        }
    }

    pub(super) fn len(&self) -> usize {
        self.by_container_id
            .len()
            .saturating_add(self.by_pod_ip.len())
            .saturating_add(self.owners_by_pod.len())
            .saturating_add(self.owners_by_address.len())
    }

    pub(super) fn contains_container(&self, container_id: &str) -> bool {
        self.by_container_id.contains_key(container_id)
    }

    pub(super) fn get(&self, container_id: &str) -> Option<KubernetesContext> {
        self.by_container_id.get(container_id).cloned()
    }

    pub(super) fn get_by_pod_ip(&self, pod_ip: &str) -> Option<KubernetesContext> {
        self.by_pod_ip.get(pod_ip).cloned()
    }

    pub(super) fn get_owner_for_context(
        &self,
        context: &KubernetesContext,
    ) -> Option<WorkloadOwner> {
        self.owners_by_pod.get(&context_key(context)).cloned()
    }

    pub(super) fn get_owner_for_address(&self, address: &str) -> Option<WorkloadOwner> {
        self.owners_by_address.get(address).cloned()
    }

    pub(super) async fn from_in_cluster(
        config: &KubernetesAttributionConfig,
    ) -> Result<Self, String> {
        let host = std::env::var("KUBERNETES_SERVICE_HOST")
            .map_err(|_| "KUBERNETES_SERVICE_HOST is not set".to_string())?;
        let port = std::env::var("KUBERNETES_SERVICE_PORT").unwrap_or_else(|_| "443".to_string());
        let token = read_bounded_to_string(&config.token_path, MAX_TOKEN_BYTES)
            .map_err(|err| err.to_string())?;
        let ca = std::fs::read(&config.ca_cert_path).map_err(|err| err.to_string())?;
        let cert = reqwest::Certificate::from_pem(&ca).map_err(|err| err.to_string())?;
        let client = reqwest::Client::builder()
            .add_root_certificate(cert)
            .timeout(Duration::from_secs(3))
            .build()
            .map_err(|err| err.to_string())?;
        let url = pod_list_url(
            &host,
            &port,
            std::env::var("NODE_NAME").ok().as_deref(),
            config,
        )?;
        let response = client
            .get(url)
            .bearer_auth(token.trim())
            .send()
            .await
            .map_err(|err| err.to_string())?
            .error_for_status()
            .map_err(|err| err.to_string())?;
        let body = read_response_body(response, config.max_response_bytes).await?;
        Self::from_pod_list_json(&body, config)
    }

    pub fn from_pod_list_json(
        body: &str,
        config: &KubernetesAttributionConfig,
    ) -> Result<Self, String> {
        let pod_list = serde_json::from_str::<PodList>(body).map_err(|err| err.to_string())?;
        Ok(Self::from_pod_list(pod_list, config))
    }

    fn from_pod_list(pod_list: PodList, config: &KubernetesAttributionConfig) -> Self {
        let mut by_container_id = BTreeMap::new();
        let mut by_pod_ip = BTreeMap::new();
        let mut selected_pods = 0_usize;

        for pod in pod_list.items {
            let namespace = pod.metadata.namespace.unwrap_or_default();
            let pod_name = pod.metadata.name.unwrap_or_default();
            let pod_uid = pod.metadata.uid;
            let raw_labels = pod.metadata.labels.unwrap_or_default();
            let node_name = pod.spec.and_then(|spec| spec.node_name);
            if !pod_matches_scope(&namespace, node_name.as_deref(), &raw_labels, config) {
                continue;
            }
            if selected_pods >= config.max_pods {
                break;
            }
            selected_pods = selected_pods.saturating_add(1);
            let labels = bounded_labels(raw_labels, config);
            if let Some(status) = pod.status {
                let pod_ip = status.pod_ip;
                for container in status.container_statuses.unwrap_or_default() {
                    if cache_entry_count(&by_container_id, &by_pod_ip) >= config.max_cache_entries {
                        warn!(
                            max_cache_entries = config.max_cache_entries,
                            "kubernetes metadata cache entry limit reached"
                        );
                        return Self {
                            by_container_id,
                            by_pod_ip,
                            owners_by_pod: BTreeMap::new(),
                            owners_by_address: BTreeMap::new(),
                        };
                    }
                    if let Some(container_id) = container.container_id {
                        let Some((_, id)) = container_id.split_once("://") else {
                            continue;
                        };
                        let context = KubernetesContext {
                            namespace: namespace.clone(),
                            pod_name: pod_name.clone(),
                            pod_uid: pod_uid.clone(),
                            container_name: Some(container.name),
                            node_name: node_name.clone(),
                            labels: labels.clone(),
                        };
                        by_container_id.insert(id.to_string(), context.clone());
                        if let Some(pod_ip) = pod_ip.as_ref().filter(|value| !value.is_empty())
                            && !by_pod_ip.contains_key(pod_ip)
                            && cache_entry_count(&by_container_id, &by_pod_ip)
                                < config.max_cache_entries
                        {
                            by_pod_ip.insert(pod_ip.clone(), context);
                        }
                    }
                }
            }
        }

        Self {
            by_container_id,
            by_pod_ip,
            owners_by_pod: BTreeMap::new(),
            owners_by_address: BTreeMap::new(),
        }
    }
}

fn raw_pod_key(pod: &RawPod) -> String {
    format!(
        "{}/{}",
        pod.namespace,
        pod.pod_uid.as_deref().unwrap_or(&pod.pod_name)
    )
}

fn context_key(context: &KubernetesContext) -> String {
    format!(
        "{}/{}",
        context.namespace,
        context.pod_uid.as_deref().unwrap_or(&context.pod_name)
    )
}

fn raw_pod_owner(pod: &RawPod) -> WorkloadOwner {
    let name = pod
        .workload_name
        .as_deref()
        .filter(|name| !name.is_empty())
        .unwrap_or(&pod.pod_name);
    WorkloadOwner {
        name: format!("{}/{name}", pod.namespace),
        owner_type: pod
            .workload_type
            .clone()
            .filter(|owner_type| !owner_type.is_empty())
            .unwrap_or_else(|| "pod".to_string()),
    }
}

fn namespace_matches_scope(namespace: &str, config: &KubernetesAttributionConfig) -> bool {
    matches_string_selector(
        namespace,
        &config.namespace_allowlist,
        &config.namespace_denylist,
    )
}

fn cache_entry_count(
    by_container_id: &BTreeMap<String, KubernetesContext>,
    by_pod_ip: &BTreeMap<String, KubernetesContext>,
) -> usize {
    by_container_id.len().saturating_add(by_pod_ip.len())
}

fn topology_cache_entry_count(
    owners_by_pod: &BTreeMap<String, WorkloadOwner>,
    owners_by_address: &BTreeMap<String, WorkloadOwner>,
) -> usize {
    owners_by_pod.len().saturating_add(owners_by_address.len())
}

fn pod_matches_scope(
    namespace: &str,
    node_name: Option<&str>,
    labels: &BTreeMap<String, String>,
    config: &KubernetesAttributionConfig,
) -> bool {
    if !matches_string_selector(
        namespace,
        &config.namespace_allowlist,
        &config.namespace_denylist,
    ) {
        return false;
    }

    match node_name {
        Some(node_name)
            if !matches_string_selector(
                node_name,
                &config.node_name_allowlist,
                &config.node_name_denylist,
            ) =>
        {
            return false;
        }
        None if !config.node_name_allowlist.is_empty() => return false,
        _ => {}
    }

    if !config
        .pod_label_selector
        .iter()
        .all(|(key, value)| labels.get(key) == Some(value))
    {
        return false;
    }

    !config
        .pod_label_exclude_selector
        .iter()
        .any(|(key, value)| labels.get(key) == Some(value))
}

fn matches_string_selector(value: &str, allowlist: &[String], denylist: &[String]) -> bool {
    (allowlist.is_empty() || allowlist.iter().any(|allowed| allowed == value))
        && !denylist.iter().any(|denied| denied == value)
}

fn pod_list_url(
    host: &str,
    port: &str,
    node_name: Option<&str>,
    config: &KubernetesAttributionConfig,
) -> Result<String, String> {
    match node_name.filter(|node| !node.is_empty()) {
        Some(node) => {
            validate_node_name_for_field_selector(node)?;
            Ok(format!(
                "https://{host}:{port}/api/v1/pods?fieldSelector=spec.nodeName%3D{node}"
            ))
        }
        None if !config.require_node_name && config.allow_cluster_wide_pod_list => {
            warn!("kubernetes metadata refresh is listing pods without NODE_NAME scoping");
            Ok(format!("https://{host}:{port}/api/v1/pods"))
        }
        None => Err("NODE_NAME is required for Kubernetes attribution pod listing".to_string()),
    }
}

fn validate_node_name_for_field_selector(node_name: &str) -> Result<(), String> {
    if node_name.len() > KubernetesAttributionConfig::MAX_SELECTOR_VALUE_BYTES_LIMIT {
        return Err(format!(
            "NODE_NAME must be at most {} bytes for Kubernetes attribution pod listing",
            KubernetesAttributionConfig::MAX_SELECTOR_VALUE_BYTES_LIMIT
        ));
    }

    if node_name.split('.').any(|label| {
        label.is_empty()
            || label.len() > 63
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
            || !label
                .bytes()
                .next()
                .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
            || !label
                .bytes()
                .last()
                .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
    }) {
        return Err(
            "NODE_NAME must be a DNS subdomain for Kubernetes attribution pod listing".to_string(),
        );
    }

    Ok(())
}

async fn read_response_body(
    mut response: reqwest::Response,
    max_response_bytes: u64,
) -> Result<String, String> {
    if let Some(content_length) = response.content_length()
        && content_length > max_response_bytes
    {
        return Err(format!(
            "Kubernetes pod list response is {content_length} bytes, above max_response_bytes={max_response_bytes}"
        ));
    }

    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|err| err.to_string())? {
        if (body.len() as u64).saturating_add(chunk.len() as u64) > max_response_bytes {
            return Err(format!(
                "Kubernetes pod list response exceeded max_response_bytes={max_response_bytes}"
            ));
        }
        body.extend_from_slice(&chunk);
    }

    String::from_utf8(body).map_err(|err| err.to_string())
}

fn bounded_labels(
    labels: BTreeMap<String, String>,
    config: &KubernetesAttributionConfig,
) -> BTreeMap<String, String> {
    let allowed = |key: &String| {
        config.label_allowlist.is_empty()
            || config.label_allowlist.iter().any(|allowed| allowed == key)
    };
    labels
        .into_iter()
        .filter(|(key, value)| allowed(key) && safe_label(key, value))
        .take(config.max_labels_per_pod)
        .collect()
}

fn safe_label(key: &str, value: &str) -> bool {
    !key.trim().is_empty()
        && key.len() <= KubernetesAttributionConfig::MAX_SELECTOR_VALUE_BYTES_LIMIT
        && !key.bytes().any(|byte| byte.is_ascii_control())
        && !key.chars().any(char::is_whitespace)
        && !value.trim().is_empty()
        && value.len() <= KubernetesAttributionConfig::MAX_SELECTOR_VALUE_BYTES_LIMIT
        && !value.bytes().any(|byte| byte.is_ascii_control())
        && !value.chars().any(char::is_whitespace)
}

#[derive(Debug, Deserialize)]
struct PodList {
    items: Vec<Pod>,
}

#[derive(Debug, Deserialize)]
struct Pod {
    metadata: PodMetadata,
    spec: Option<PodSpec>,
    status: Option<PodStatus>,
}

#[derive(Debug, Deserialize)]
struct PodMetadata {
    name: Option<String>,
    namespace: Option<String>,
    uid: Option<String>,
    labels: Option<BTreeMap<String, String>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PodSpec {
    node_name: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PodStatus {
    #[serde(rename = "podIP")]
    pod_ip: Option<String>,
    container_statuses: Option<Vec<ContainerStatus>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ContainerStatus {
    name: String,
    #[serde(rename = "containerID")]
    container_id: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_container_index_from_kubernetes_pod_list() {
        let pod_list = PodList {
            items: vec![Pod {
                metadata: PodMetadata {
                    name: Some("known-live-loop".to_string()),
                    namespace: Some("e-navigator-test".to_string()),
                    uid: Some("pod-uid-1".to_string()),
                    labels: Some(BTreeMap::from([(
                        "e-navigator.dev/test".to_string(),
                        "true".to_string(),
                    )])),
                },
                spec: Some(PodSpec {
                    node_name: Some("homelab-01".to_string()),
                }),
                status: Some(PodStatus {
                    pod_ip: None,
                    container_statuses: Some(vec![ContainerStatus {
                        name: "known-live-loop".to_string(),
                        container_id: Some(
                            "containerd://9a0d7698a96cd5e394c21b2374f3424f69444db1e2bce4ade8b9671bf3feb9d4"
                                .to_string(),
                        ),
                    }]),
                }),
            }],
        };

        let cache = KubernetesMetadataCache::from_pod_list(
            pod_list,
            &KubernetesAttributionConfig::default(),
        );
        let context = cache
            .get("9a0d7698a96cd5e394c21b2374f3424f69444db1e2bce4ade8b9671bf3feb9d4")
            .expect("container is indexed without runtime prefix");

        assert_eq!(context.namespace, "e-navigator-test");
        assert_eq!(context.pod_name, "known-live-loop");
        assert_eq!(context.pod_uid.as_deref(), Some("pod-uid-1"));
        assert_eq!(context.container_name.as_deref(), Some("known-live-loop"));
        assert_eq!(context.node_name.as_deref(), Some("homelab-01"));
        assert_eq!(
            context
                .labels
                .get("e-navigator.dev/test")
                .map(String::as_str),
            Some("true")
        );
    }

    #[test]
    fn builds_attribution_indexes_from_shared_raw_pods() {
        let container_id = "9a0d7698a96cd5e394c21b2374f3424f69444db1e2bce4ade8b9671bf3feb9d4";
        let pods = vec![RawPod {
            namespace: "proj-payments".to_string(),
            pod_name: "payments-api-abc".to_string(),
            pod_uid: Some("pod-uid-1".to_string()),
            node_name: Some("homelab-01".to_string()),
            pod_ip: Some("10.42.0.10".to_string()),
            workload_name: Some("payments-api".to_string()),
            workload_type: Some("deployment".to_string()),
            container_ids: vec![container_id.to_string()],
            container_names: BTreeMap::from([(container_id.to_string(), "api".to_string())]),
            labels: BTreeMap::from([
                ("guara.cloud/tier".to_string(), "pro".to_string()),
                ("unsafe label".to_string(), "drop-me".to_string()),
            ]),
        }];

        let cache =
            KubernetesMetadataCache::from_raw_pods(&pods, &KubernetesAttributionConfig::default());
        let by_container = cache.get(container_id).expect("container index");
        let by_ip = cache.get_by_pod_ip("10.42.0.10").expect("pod IP index");

        assert_eq!(by_container, by_ip);
        assert_eq!(by_container.namespace, "proj-payments");
        assert_eq!(by_container.container_name.as_deref(), Some("api"));
        assert_eq!(
            by_container
                .labels
                .get("guara.cloud/tier")
                .map(String::as_str),
            Some("pro")
        );
        assert!(!by_container.labels.contains_key("unsafe label"));
    }

    #[test]
    fn shared_resources_resolve_cross_node_workloads_services_and_slice_backends() {
        let container_id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let pods = vec![RawPod {
            namespace: "proj-orders".to_string(),
            pod_name: "orders-7d9f8d6c5b-abcd".to_string(),
            pod_uid: Some("orders-pod-uid".to_string()),
            node_name: Some("homelab-02".to_string()),
            pod_ip: Some("10.42.1.20".to_string()),
            workload_name: Some("orders".to_string()),
            workload_type: Some("deployment".to_string()),
            container_ids: vec![container_id.to_string()],
            container_names: BTreeMap::from([(container_id.to_string(), "api".to_string())]),
            labels: BTreeMap::new(),
        }];
        let services = vec![RawService {
            namespace: "proj-orders".to_string(),
            service_name: "orders".to_string(),
            service_uid: Some("orders-service-uid".to_string()),
            cluster_ips: vec!["10.43.0.9".to_string()],
        }];
        let endpoint_slices = vec![RawEndpointSlice {
            namespace: "proj-orders".to_string(),
            service_name: "orders".to_string(),
            addresses: vec!["10.42.1.20".to_string(), "192.0.2.20".to_string()],
        }];

        let cache = KubernetesMetadataCache::from_raw_resources(
            &pods,
            &services,
            &endpoint_slices,
            &KubernetesAttributionConfig::default(),
        );
        let remote_pod = cache
            .get_by_pod_ip("10.42.1.20")
            .expect("cross-node pod IP");
        assert_eq!(remote_pod.node_name.as_deref(), Some("homelab-02"));
        assert_eq!(
            cache.get_owner_for_context(&remote_pod),
            Some(WorkloadOwner {
                name: "proj-orders/orders".to_string(),
                owner_type: "deployment".to_string(),
            })
        );
        let service_owner = WorkloadOwner {
            name: "proj-orders/orders".to_string(),
            owner_type: "service".to_string(),
        };
        assert_eq!(
            cache.get_owner_for_address("10.43.0.9"),
            Some(service_owner.clone())
        );
        assert_eq!(
            cache.get_owner_for_address("192.0.2.20"),
            Some(service_owner)
        );
        assert_eq!(
            cache
                .get_owner_for_address("10.42.1.20")
                .expect("pod owner wins")
                .owner_type,
            "deployment"
        );
    }

    #[test]
    fn topology_owner_indexes_respect_the_configured_cache_bound() {
        let services = vec![RawService {
            namespace: "proj".to_string(),
            service_name: "bounded".to_string(),
            service_uid: None,
            cluster_ips: vec![
                "10.43.0.1".to_string(),
                "10.43.0.2".to_string(),
                "10.43.0.3".to_string(),
            ],
        }];
        let config = KubernetesAttributionConfig {
            max_cache_entries: 2,
            ..KubernetesAttributionConfig::default()
        };

        let cache = KubernetesMetadataCache::from_raw_resources(&[], &services, &[], &config);

        assert_eq!(cache.len(), 2);
        assert!(cache.get_owner_for_address("10.43.0.1").is_some());
        assert!(cache.get_owner_for_address("10.43.0.2").is_some());
        assert!(cache.get_owner_for_address("10.43.0.3").is_none());
    }

    #[test]
    fn deserializes_kubernetes_container_id_field() {
        let cache = KubernetesMetadataCache::from_pod_list_json(
            r#"{
              "items": [
                {
                  "metadata": {
                    "name": "known-live-loop",
                    "namespace": "e-navigator-test",
                    "uid": "pod-uid-1"
                  },
                  "spec": {
                    "nodeName": "homelab-01"
                  },
                  "status": {
                    "containerStatuses": [
                      {
                        "name": "known-live-loop",
                        "containerID": "containerd://a528e7d90a827ff72201ea1cefe7d299448a2528cc5ada9ce4a7ec6d0c4a3b70"
                      }
                    ]
                  }
                }
              ]
            }"#,
            &KubernetesAttributionConfig::default(),
        )
        .expect("pod list JSON deserializes");

        assert!(cache.contains_container(
            "a528e7d90a827ff72201ea1cefe7d299448a2528cc5ada9ce4a7ec6d0c4a3b70"
        ));
    }

    #[test]
    fn missing_node_name_is_rejected_by_default() {
        let err = pod_list_url(
            "kubernetes.default.svc",
            "443",
            None,
            &KubernetesAttributionConfig::default(),
        )
        .expect_err("missing node name is rejected");

        assert!(err.contains("NODE_NAME is required"));
    }

    #[test]
    fn scoped_pod_list_url_accepts_dns_subdomain_node_name() {
        let url = pod_list_url(
            "kubernetes.default.svc",
            "443",
            Some("worker-a.zone-1"),
            &KubernetesAttributionConfig::default(),
        )
        .expect("DNS subdomain node name is valid");

        assert_eq!(
            url,
            "https://kubernetes.default.svc:443/api/v1/pods?fieldSelector=spec.nodeName%3Dworker-a.zone-1"
        );
    }

    #[test]
    fn unsafe_node_name_is_rejected_before_pod_list_url_construction() {
        for node_name in [
            "worker-a&limit=1",
            "worker-a?fieldSelector=metadata.name%3Dpod",
            "Worker-A",
            "-worker-a",
            "worker-a-",
            "worker..a",
            "worker a",
        ] {
            let err = pod_list_url(
                "kubernetes.default.svc",
                "443",
                Some(node_name),
                &KubernetesAttributionConfig::default(),
            )
            .expect_err("unsafe node name is rejected");

            assert!(
                err.contains("NODE_NAME must be a DNS subdomain"),
                "unexpected error for {node_name}: {err}"
            );
        }
    }

    #[test]
    fn cluster_wide_pod_list_requires_explicit_opt_in() {
        let config = KubernetesAttributionConfig {
            require_node_name: false,
            allow_cluster_wide_pod_list: true,
            ..KubernetesAttributionConfig::default()
        };

        let url = pod_list_url("kubernetes.default.svc", "443", None, &config)
            .expect("cluster-wide URL is explicit");

        assert_eq!(url, "https://kubernetes.default.svc:443/api/v1/pods");
    }

    #[test]
    fn pod_list_cache_entries_are_bounded_deterministically() {
        let pod_list = PodList {
            items: (0..4)
                .map(|index| Pod {
                    metadata: PodMetadata {
                        name: Some(format!("pod-{index}")),
                        namespace: Some("default".to_string()),
                        uid: Some(format!("uid-{index}")),
                        labels: None,
                    },
                    spec: Some(PodSpec {
                        node_name: Some("node-a".to_string()),
                    }),
                    status: Some(PodStatus {
                        pod_ip: None,
                        container_statuses: Some(vec![ContainerStatus {
                            name: "app".to_string(),
                            container_id: Some(format!("containerd://container-{index}")),
                        }]),
                    }),
                })
                .collect(),
        };
        let config = KubernetesAttributionConfig {
            max_cache_entries: 2,
            ..KubernetesAttributionConfig::default()
        };

        let cache = KubernetesMetadataCache::from_pod_list(pod_list, &config);

        assert_eq!(cache.len(), 2);
        assert!(cache.contains_container("container-0"));
        assert!(cache.contains_container("container-1"));
        assert!(!cache.contains_container("container-2"));
    }

    #[test]
    fn pod_ip_index_does_not_exceed_cache_entry_limit() {
        let pod_list = PodList {
            items: vec![scoped_pod(
                "api",
                "default",
                "node-a",
                "10.0.0.10",
                "container-api",
                BTreeMap::from([("app".to_string(), "api".to_string())]),
            )],
        };
        let config = KubernetesAttributionConfig {
            max_cache_entries: 1,
            ..KubernetesAttributionConfig::default()
        };

        let cache = KubernetesMetadataCache::from_pod_list(pod_list, &config);

        assert_eq!(cache.len(), 1);
        assert!(cache.contains_container("container-api"));
        assert!(cache.get_by_pod_ip("10.0.0.10").is_none());
    }

    #[test]
    fn pod_labels_are_filtered_and_capped() {
        let pod_list = PodList {
            items: vec![Pod {
                metadata: PodMetadata {
                    name: Some("api".to_string()),
                    namespace: Some("default".to_string()),
                    uid: Some("uid-api".to_string()),
                    labels: Some(BTreeMap::from([
                        ("app".to_string(), "api".to_string()),
                        ("pod-template-hash".to_string(), "abc".to_string()),
                        ("team".to_string(), "platform".to_string()),
                    ])),
                },
                spec: Some(PodSpec {
                    node_name: Some("node-a".to_string()),
                }),
                status: Some(PodStatus {
                    pod_ip: None,
                    container_statuses: Some(vec![ContainerStatus {
                        name: "api".to_string(),
                        container_id: Some("containerd://container-api".to_string()),
                    }]),
                }),
            }],
        };
        let config = KubernetesAttributionConfig {
            max_labels_per_pod: 8,
            label_allowlist: vec!["app".to_string(), "team".to_string()],
            ..KubernetesAttributionConfig::default()
        };

        let cache = KubernetesMetadataCache::from_pod_list(pod_list, &config);
        let context = cache.get("container-api").expect("container is indexed");

        assert_eq!(
            context.labels,
            BTreeMap::from([
                ("app".to_string(), "api".to_string()),
                ("team".to_string(), "platform".to_string()),
            ])
        );
    }

    #[test]
    fn unsafe_pod_labels_do_not_consume_label_limit() {
        let pod_list = PodList {
            items: vec![Pod {
                metadata: PodMetadata {
                    name: Some("api".to_string()),
                    namespace: Some("default".to_string()),
                    uid: Some("uid-api".to_string()),
                    labels: Some(BTreeMap::from([
                        ("".to_string(), "empty-key".to_string()),
                        (" app".to_string(), "whitespace-key".to_string()),
                        ("app".to_string(), "api".to_string()),
                        ("bad\nkey".to_string(), "control-key".to_string()),
                        ("empty-value".to_string(), "".to_string()),
                        ("team".to_string(), "platform".to_string()),
                    ])),
                },
                spec: Some(PodSpec {
                    node_name: Some("node-a".to_string()),
                }),
                status: Some(PodStatus {
                    pod_ip: None,
                    container_statuses: Some(vec![ContainerStatus {
                        name: "api".to_string(),
                        container_id: Some("containerd://container-api".to_string()),
                    }]),
                }),
            }],
        };
        let config = KubernetesAttributionConfig {
            max_labels_per_pod: 2,
            ..KubernetesAttributionConfig::default()
        };

        let cache = KubernetesMetadataCache::from_pod_list(pod_list, &config);
        let context = cache.get("container-api").expect("container is indexed");

        assert_eq!(
            context.labels,
            BTreeMap::from([
                ("app".to_string(), "api".to_string()),
                ("team".to_string(), "platform".to_string()),
            ])
        );
    }

    #[test]
    fn pod_scope_selectors_filter_cache_entries() {
        let pod_list = PodList {
            items: vec![
                scoped_pod(
                    "checkout",
                    "payments",
                    "node-a",
                    "10.0.0.10",
                    "container-checkout",
                    BTreeMap::from([
                        ("app".to_string(), "checkout".to_string()),
                        ("team".to_string(), "platform".to_string()),
                    ]),
                ),
                scoped_pod(
                    "orders",
                    "orders",
                    "node-a",
                    "10.0.0.11",
                    "container-orders",
                    BTreeMap::from([
                        ("app".to_string(), "orders".to_string()),
                        ("team".to_string(), "platform".to_string()),
                    ]),
                ),
                scoped_pod(
                    "checkout-canary",
                    "payments",
                    "node-b",
                    "10.0.0.12",
                    "container-canary",
                    BTreeMap::from([
                        ("app".to_string(), "checkout".to_string()),
                        ("track".to_string(), "canary".to_string()),
                    ]),
                ),
            ],
        };
        let config = KubernetesAttributionConfig {
            namespace_allowlist: vec!["payments".to_string()],
            node_name_allowlist: vec!["node-a".to_string()],
            pod_label_selector: BTreeMap::from([("app".to_string(), "checkout".to_string())]),
            pod_label_exclude_selector: BTreeMap::from([(
                "track".to_string(),
                "canary".to_string(),
            )]),
            ..KubernetesAttributionConfig::default()
        };

        let cache = KubernetesMetadataCache::from_pod_list(pod_list, &config);

        assert!(cache.contains_container("container-checkout"));
        assert!(!cache.contains_container("container-orders"));
        assert!(!cache.contains_container("container-canary"));
        assert!(cache.get_by_pod_ip("10.0.0.10").is_some());
        assert!(cache.get_by_pod_ip("10.0.0.11").is_none());
        assert!(cache.get_by_pod_ip("10.0.0.12").is_none());
    }

    #[test]
    fn denylist_selectors_filter_cache_entries_without_allowlists() {
        let pod_list = PodList {
            items: vec![
                scoped_pod(
                    "checkout",
                    "payments",
                    "node-a",
                    "10.0.0.20",
                    "container-checkout",
                    BTreeMap::from([("app".to_string(), "checkout".to_string())]),
                ),
                scoped_pod(
                    "system",
                    "kube-system",
                    "node-a",
                    "10.0.0.21",
                    "container-system",
                    BTreeMap::from([("app".to_string(), "system".to_string())]),
                ),
                scoped_pod(
                    "other-node",
                    "payments",
                    "node-b",
                    "10.0.0.22",
                    "container-other-node",
                    BTreeMap::from([("app".to_string(), "checkout".to_string())]),
                ),
                scoped_pod(
                    "debug",
                    "payments",
                    "node-a",
                    "10.0.0.23",
                    "container-debug",
                    BTreeMap::from([("observability".to_string(), "disabled".to_string())]),
                ),
            ],
        };
        let config = KubernetesAttributionConfig {
            namespace_denylist: vec!["kube-system".to_string()],
            node_name_denylist: vec!["node-b".to_string()],
            pod_label_exclude_selector: BTreeMap::from([(
                "observability".to_string(),
                "disabled".to_string(),
            )]),
            ..KubernetesAttributionConfig::default()
        };

        let cache = KubernetesMetadataCache::from_pod_list(pod_list, &config);

        assert!(cache.contains_container("container-checkout"));
        assert!(!cache.contains_container("container-system"));
        assert!(!cache.contains_container("container-other-node"));
        assert!(!cache.contains_container("container-debug"));
        assert!(cache.get_by_pod_ip("10.0.0.20").is_some());
        assert!(cache.get_by_pod_ip("10.0.0.21").is_none());
        assert!(cache.get_by_pod_ip("10.0.0.22").is_none());
        assert!(cache.get_by_pod_ip("10.0.0.23").is_none());
    }

    #[test]
    fn excluded_pods_do_not_consume_selected_pod_limit() {
        let pod_list = PodList {
            items: vec![
                scoped_pod(
                    "excluded",
                    "default",
                    "node-a",
                    "10.0.0.20",
                    "container-excluded",
                    BTreeMap::from([("app".to_string(), "excluded".to_string())]),
                ),
                scoped_pod(
                    "included",
                    "default",
                    "node-a",
                    "10.0.0.21",
                    "container-included",
                    BTreeMap::from([("app".to_string(), "included".to_string())]),
                ),
            ],
        };
        let config = KubernetesAttributionConfig {
            max_pods: 1,
            pod_label_selector: BTreeMap::from([("app".to_string(), "included".to_string())]),
            ..KubernetesAttributionConfig::default()
        };

        let cache = KubernetesMetadataCache::from_pod_list(pod_list, &config);

        assert!(cache.contains_container("container-included"));
        assert!(!cache.contains_container("container-excluded"));
    }

    #[test]
    fn pod_count_limit_bounds_parsing_before_cache_limit() {
        let pod_list = PodList {
            items: (0..3)
                .map(|index| Pod {
                    metadata: PodMetadata {
                        name: Some(format!("pod-{index}")),
                        namespace: Some("default".to_string()),
                        uid: Some(format!("uid-{index}")),
                        labels: None,
                    },
                    spec: None,
                    status: Some(PodStatus {
                        pod_ip: None,
                        container_statuses: Some(vec![ContainerStatus {
                            name: "app".to_string(),
                            container_id: Some(format!("containerd://container-{index}")),
                        }]),
                    }),
                })
                .collect(),
        };
        let config = KubernetesAttributionConfig {
            max_pods: 1,
            max_cache_entries: 8,
            ..KubernetesAttributionConfig::default()
        };

        let cache = KubernetesMetadataCache::from_pod_list(pod_list, &config);

        assert_eq!(cache.len(), 1);
        assert!(cache.contains_container("container-0"));
        assert!(!cache.contains_container("container-1"));
    }

    #[tokio::test]
    async fn response_larger_than_configured_max_is_rejected_before_json_parse() {
        use std::io::{Read, Write};

        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind test server");
        let address = listener.local_addr().expect("test server address");
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept request");
            let mut request = [0_u8; 512];
            let _ = stream.read(&mut request);
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nabcde")
                .expect("write response");
        });

        let response = reqwest::get(format!("http://{address}/pods"))
            .await
            .expect("response");
        let err = read_response_body(response, 4)
            .await
            .expect_err("oversized body is rejected");

        assert!(err.contains("above max_response_bytes=4"));
        handle.join().expect("server exits");
    }

    #[test]
    fn failed_cache_install_preserves_existing_cache() {
        let cache = Mutex::new(KubernetesMetadataCache::from_contexts([(
            "old-container".to_string(),
            kubernetes_context("old-pod"),
        )]));
        let _ = std::panic::catch_unwind(|| {
            let _guard = cache.lock().expect("cache lock acquired");
            panic!("poison cache mutex");
        });

        let err = install_refreshed_cache(
            &cache,
            KubernetesMetadataCache::from_contexts([(
                "new-container".to_string(),
                kubernetes_context("new-pod"),
            )]),
        )
        .expect_err("poisoned cache install fails");

        assert_eq!(err, "kubernetes metadata cache lock poisoned");
        let poisoned = cache.lock().expect_err("cache remains poisoned");
        assert!(poisoned.get_ref().contains_container("old-container"));
        assert!(!poisoned.get_ref().contains_container("new-container"));
    }

    #[test]
    fn failed_refresh_state_allows_retry_and_preserves_last_success() {
        let last_refresh = Mutex::new(Some(KubernetesRefreshState {
            refreshed_at: Instant::now(),
            requested_container_found: true,
            immediate_retry_available: false,
            in_progress: false,
            last_success_at: Some(Instant::now()),
        }));
        let previous_success = last_refresh
            .lock()
            .expect("state lock acquired")
            .expect("state exists")
            .last_success_at;

        record_refresh_state(&last_refresh, false, false);

        let state = last_refresh
            .lock()
            .expect("state lock acquired")
            .expect("state exists");
        assert!(!state.in_progress);
        assert!(!state.requested_container_found);
        assert!(state.immediate_retry_available);
        assert_eq!(state.last_success_at, previous_success);
    }

    fn kubernetes_context(pod_name: &str) -> KubernetesContext {
        KubernetesContext {
            namespace: "default".to_string(),
            pod_name: pod_name.to_string(),
            pod_uid: Some(format!("uid-{pod_name}")),
            container_name: Some("app".to_string()),
            node_name: Some("node-a".to_string()),
            labels: BTreeMap::new(),
        }
    }

    fn scoped_pod(
        pod_name: &str,
        namespace: &str,
        node_name: &str,
        pod_ip: &str,
        container_id: &str,
        labels: BTreeMap<String, String>,
    ) -> Pod {
        Pod {
            metadata: PodMetadata {
                name: Some(pod_name.to_string()),
                namespace: Some(namespace.to_string()),
                uid: Some(format!("uid-{pod_name}")),
                labels: Some(labels),
            },
            spec: Some(PodSpec {
                node_name: Some(node_name.to_string()),
            }),
            status: Some(PodStatus {
                pod_ip: Some(pod_ip.to_string()),
                container_statuses: Some(vec![ContainerStatus {
                    name: "app".to_string(),
                    container_id: Some(format!("containerd://{container_id}")),
                }]),
            }),
        }
    }
}
