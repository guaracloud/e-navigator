use async_trait::async_trait;
use e_navigator_core::KubernetesAttributionConfig;
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

        if self.config.enabled && self.start_refresh_if_needed(container_id) {
            self.spawn_refresh(container_id.to_string());
        } else if cached.is_none() {
            self.diagnostics
                .skipped_attribution
                .fetch_add(1, Ordering::Relaxed);
        }

        cached
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

    fn start_refresh_if_needed(&self, container_id: &str) -> bool {
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

        let should_refresh = if state.requested_container_found {
            now.duration_since(state.refreshed_at) >= MIN_KUBERNETES_METADATA_REFRESH_INTERVAL
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
                    if let Ok(mut kubernetes_cache) = cache.lock() {
                        *kubernetes_cache = new_cache;
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
pub(super) trait KubernetesMetadataProvider: std::fmt::Debug + Send + Sync {
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
}

impl KubernetesMetadataCache {
    pub fn from_contexts(contexts: impl IntoIterator<Item = (String, KubernetesContext)>) -> Self {
        Self {
            by_container_id: contexts.into_iter().collect(),
        }
    }

    pub(super) fn len(&self) -> usize {
        self.by_container_id.len()
    }

    pub(super) fn contains_container(&self, container_id: &str) -> bool {
        self.by_container_id.contains_key(container_id)
    }

    pub(super) fn get(&self, container_id: &str) -> Option<KubernetesContext> {
        self.by_container_id.get(container_id).cloned()
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
        let pod_list = serde_json::from_str::<PodList>(&body).map_err(|err| err.to_string())?;

        Ok(Self::from_pod_list(pod_list, config))
    }

    fn from_pod_list(pod_list: PodList, config: &KubernetesAttributionConfig) -> Self {
        let mut by_container_id = BTreeMap::new();

        for pod in pod_list.items.into_iter().take(config.max_pods) {
            let namespace = pod.metadata.namespace.unwrap_or_default();
            let pod_name = pod.metadata.name.unwrap_or_default();
            let pod_uid = pod.metadata.uid;
            let labels = bounded_labels(pod.metadata.labels.unwrap_or_default(), config);
            let node_name = pod.spec.and_then(|spec| spec.node_name);
            if let Some(status) = pod.status {
                for container in status.container_statuses.unwrap_or_default() {
                    if by_container_id.len() >= config.max_cache_entries {
                        warn!(
                            max_cache_entries = config.max_cache_entries,
                            "kubernetes metadata cache entry limit reached"
                        );
                        return Self { by_container_id };
                    }
                    if let Some(container_id) = container.container_id {
                        let Some((_, id)) = container_id.split_once("://") else {
                            continue;
                        };
                        by_container_id.insert(
                            id.to_string(),
                            KubernetesContext {
                                namespace: namespace.clone(),
                                pod_name: pod_name.clone(),
                                pod_uid: pod_uid.clone(),
                                container_name: Some(container.name),
                                node_name: node_name.clone(),
                                labels: labels.clone(),
                            },
                        );
                    }
                }
            }
        }

        Self { by_container_id }
    }
}

fn pod_list_url(
    host: &str,
    port: &str,
    node_name: Option<&str>,
    config: &KubernetesAttributionConfig,
) -> Result<String, String> {
    match node_name.filter(|node| !node.is_empty()) {
        Some(node) => Ok(format!(
            "https://{host}:{port}/api/v1/pods?fieldSelector=spec.nodeName%3D{node}"
        )),
        None if !config.require_node_name && config.allow_cluster_wide_pod_list => {
            warn!("kubernetes metadata refresh is listing pods without NODE_NAME scoping");
            Ok(format!("https://{host}:{port}/api/v1/pods"))
        }
        None => Err("NODE_NAME is required for Kubernetes attribution pod listing".to_string()),
    }
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
        .filter(|(key, _)| allowed(key))
        .take(config.max_labels_per_pod)
        .collect()
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
    fn deserializes_kubernetes_container_id_field() {
        let pod_list: PodList = serde_json::from_str(
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
        )
        .expect("pod list JSON deserializes");

        let cache = KubernetesMetadataCache::from_pod_list(
            pod_list,
            &KubernetesAttributionConfig::default(),
        );

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
}
