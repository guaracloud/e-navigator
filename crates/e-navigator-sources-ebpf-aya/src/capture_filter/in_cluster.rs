//! In-cluster raw node pod-list fetch and parsing for the capture filter.
//!
//! Deliberately *unscoped*: unlike the attribution enrichment fetch, this
//! returns every pod on the node so the filter can exclude a namespace even
//! when `[attribution.kubernetes]` scoping would have dropped it.

use std::collections::BTreeMap;
use std::io::Read;
use std::path::Path;
use std::time::Duration;

use async_trait::async_trait;
use e_navigator_core::KubernetesAttributionConfig;
use e_navigator_core::capture_filter::RawPod;
use serde::Deserialize;

use super::{MAX_LABELS_PER_POD, MAX_POD_LIST_RESPONSE_BYTES, MAX_TOKEN_BYTES, RawPodFetcher};

/// Reqwest-backed fetcher for the node-scoped, attribution-unscoped pod list.
#[derive(Debug)]
pub(crate) struct InClusterRawFetcher {
    client: reqwest::Client,
    url: String,
    token: String,
    max_response_bytes: u64,
    max_pods: usize,
}

impl InClusterRawFetcher {
    pub(crate) fn from_config(
        config: &KubernetesAttributionConfig,
        node_name: Option<&str>,
    ) -> Result<Self, String> {
        let host = std::env::var("KUBERNETES_SERVICE_HOST")
            .map_err(|_| "KUBERNETES_SERVICE_HOST is not set".to_string())?;
        let port = std::env::var("KUBERNETES_SERVICE_PORT").unwrap_or_else(|_| "443".to_string());
        let node = node_name
            .or(std::env::var("NODE_NAME").ok().as_deref())
            .map(str::to_string)
            .ok_or_else(|| {
                "NODE_NAME is required to scope the capture-filter pod list to this node"
                    .to_string()
            })?;
        validate_node_name(&node)?;

        let token = read_bounded(&config.token_path, MAX_TOKEN_BYTES)?;
        let ca = std::fs::read(&config.ca_cert_path).map_err(|err| err.to_string())?;
        let cert = reqwest::Certificate::from_pem(&ca).map_err(|err| err.to_string())?;
        let client = reqwest::Client::builder()
            .add_root_certificate(cert)
            .timeout(Duration::from_secs(3))
            .build()
            .map_err(|err| err.to_string())?;
        let url = format!("https://{host}:{port}/api/v1/pods?fieldSelector=spec.nodeName%3D{node}");

        Ok(Self {
            client,
            url,
            token,
            max_response_bytes: config.max_response_bytes.min(MAX_POD_LIST_RESPONSE_BYTES),
            max_pods: config.max_pods,
        })
    }
}

#[async_trait]
impl RawPodFetcher for InClusterRawFetcher {
    async fn fetch(&self) -> Result<Vec<RawPod>, String> {
        let response = self
            .client
            .get(&self.url)
            .bearer_auth(self.token.trim())
            .send()
            .await
            .map_err(|err| err.to_string())?
            .error_for_status()
            .map_err(|err| err.to_string())?;
        let body = read_response_body(response, self.max_response_bytes).await?;
        parse_raw_pods(&body, self.max_pods, MAX_LABELS_PER_POD)
    }
}

/// Parse a Kubernetes `PodList` JSON body into raw pods, bounded by `max_pods`
/// and `max_labels`. No attribution scoping is applied.
pub(crate) fn parse_raw_pods(
    body: &str,
    max_pods: usize,
    max_labels: usize,
) -> Result<Vec<RawPod>, String> {
    let pod_list: PodList = serde_json::from_str(body).map_err(|err| err.to_string())?;
    let mut pods = Vec::new();
    for pod in pod_list.items.into_iter().take(max_pods) {
        let namespace = pod.metadata.namespace.unwrap_or_default();
        let pod_name = pod.metadata.name.unwrap_or_default();
        let labels = bounded_labels(pod.metadata.labels.unwrap_or_default(), max_labels);
        let node_name = pod.spec.and_then(|spec| spec.node_name);
        let mut container_ids = Vec::new();
        let mut container_names = BTreeMap::new();
        let mut pod_ip = None;
        if let Some(status) = pod.status {
            pod_ip = status.pod_ip;
            for container in status.container_statuses.unwrap_or_default() {
                let Some(container_id) = container
                    .container_id
                    .and_then(|raw| bare_container_id(&raw))
                else {
                    continue;
                };
                if let Some(name) = container.name {
                    container_names.insert(container_id.clone(), name);
                }
                container_ids.push(container_id);
            }
        }
        pods.push(RawPod {
            namespace,
            pod_name,
            pod_uid: pod.metadata.uid,
            node_name,
            pod_ip,
            container_ids,
            container_names,
            labels,
        });
    }
    Ok(pods)
}

/// Strip the `runtime://` scheme from a Kubernetes container id, yielding the
/// bare id that matches the cgroup-path token.
fn bare_container_id(raw: &str) -> Option<String> {
    raw.split_once("://")
        .map(|(_, id)| id.to_string())
        .filter(|id| !id.is_empty())
}

fn bounded_labels(labels: BTreeMap<String, String>, max_labels: usize) -> BTreeMap<String, String> {
    labels.into_iter().take(max_labels).collect()
}

fn validate_node_name(node: &str) -> Result<(), String> {
    if node.is_empty() {
        return Err("node name must not be empty".to_string());
    }
    // DNS-subdomain characters only, so the value cannot smuggle extra query
    // parameters into the field selector.
    if !node
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.'))
    {
        return Err(format!("node name '{node}' contains invalid characters"));
    }
    Ok(())
}

fn read_bounded(path: &Path, max_bytes: u64) -> Result<String, String> {
    let mut file = std::fs::File::open(path).map_err(|err| err.to_string())?;
    let mut buffer = String::new();
    file.by_ref()
        .take(max_bytes)
        .read_to_string(&mut buffer)
        .map_err(|err| err.to_string())?;
    Ok(buffer)
}

/// Read the response body incrementally, rejecting anything past `max_bytes`
/// so a hostile or runaway API cannot exhaust memory.
async fn read_response_body(
    mut response: reqwest::Response,
    max_bytes: u64,
) -> Result<String, String> {
    let mut collected = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|err| err.to_string())? {
        if collected.len() as u64 + chunk.len() as u64 > max_bytes {
            return Err("Kubernetes pod-list response exceeds the configured limit".to_string());
        }
        collected.extend_from_slice(&chunk);
    }
    String::from_utf8(collected).map_err(|err| err.to_string())
}

#[derive(Debug, Deserialize)]
struct PodList {
    #[serde(default)]
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
    namespace: Option<String>,
    name: Option<String>,
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
struct ContainerStatus {
    name: Option<String>,
    #[serde(rename = "containerID")]
    container_id: Option<String>,
}
