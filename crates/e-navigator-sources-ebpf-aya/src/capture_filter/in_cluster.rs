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

use super::{
    MAX_LABELS_PER_POD, MAX_POD_LIST_RESPONSE_BYTES, MAX_TOKEN_BYTES, PodWatchError, RawPodFetcher,
    RawPodPublisher, RawPodSnapshot,
};

const WATCH_TIMEOUT_SECONDS: &str = "300";
const WATCH_REQUEST_TIMEOUT: Duration = Duration::from_secs(310);
const API_CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const LIST_REQUEST_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_RESOURCE_VERSION_BYTES: usize = 128;

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
            .connect_timeout(API_CONNECT_TIMEOUT)
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
    async fn list(&self) -> Result<RawPodSnapshot, String> {
        let response = self
            .client
            .get(&self.url)
            .bearer_auth(self.token.trim())
            .timeout(LIST_REQUEST_TIMEOUT)
            .send()
            .await
            .map_err(|err| err.to_string())?
            .error_for_status()
            .map_err(|err| err.to_string())?;
        let body = read_response_body(response, self.max_response_bytes).await?;
        parse_raw_pod_snapshot(&body, self.max_pods, MAX_LABELS_PER_POD)
    }

    async fn watch(
        &self,
        snapshot: RawPodSnapshot,
        publisher: RawPodPublisher,
    ) -> Result<RawPodSnapshot, PodWatchError> {
        validate_resource_version(&snapshot.resource_version).map_err(PodWatchError::Other)?;
        let mut url =
            reqwest::Url::parse(&self.url).map_err(|err| PodWatchError::Other(err.to_string()))?;
        url.query_pairs_mut()
            .append_pair("watch", "true")
            .append_pair("allowWatchBookmarks", "true")
            .append_pair("timeoutSeconds", WATCH_TIMEOUT_SECONDS)
            .append_pair("resourceVersion", &snapshot.resource_version);
        let response = self
            .client
            .get(url)
            .bearer_auth(self.token.trim())
            .timeout(WATCH_REQUEST_TIMEOUT)
            .send()
            .await
            .map_err(|err| PodWatchError::Other(err.to_string()))?;
        if response.status() == reqwest::StatusCode::GONE {
            return Err(PodWatchError::ExpiredResourceVersion);
        }
        let response = response
            .error_for_status()
            .map_err(|err| PodWatchError::Other(err.to_string()))?;
        read_watch_response(
            response,
            snapshot,
            self.max_response_bytes,
            self.max_pods,
            MAX_LABELS_PER_POD,
            publisher,
        )
        .await
    }
}

/// Parse a Kubernetes `PodList` JSON body into raw pods, bounded by `max_pods`
/// and `max_labels`. No attribution scoping is applied.
#[cfg(test)]
pub(crate) fn parse_raw_pods(
    body: &str,
    max_pods: usize,
    max_labels: usize,
) -> Result<Vec<RawPod>, String> {
    Ok(parse_raw_pod_snapshot(body, max_pods, max_labels)?.pods)
}

pub(super) fn parse_raw_pod_snapshot(
    body: &str,
    max_pods: usize,
    max_labels: usize,
) -> Result<RawPodSnapshot, String> {
    let pod_list: PodList = serde_json::from_str(body).map_err(|err| err.to_string())?;
    let mut pods = Vec::new();
    for pod in pod_list.items.into_iter().take(max_pods) {
        pods.push(raw_pod_from_pod(pod, max_labels).2);
    }
    Ok(RawPodSnapshot {
        resource_version: pod_list.metadata.resource_version.unwrap_or_default(),
        pods,
    })
}

fn raw_pod_from_pod(pod: Pod, max_labels: usize) -> (String, Option<String>, RawPod) {
    let namespace = pod.metadata.namespace.unwrap_or_default();
    let pod_name = pod.metadata.name.unwrap_or_default();
    let pod_uid = pod.metadata.uid;
    let resource_version = pod.metadata.resource_version;
    let key = pod_uid
        .clone()
        .unwrap_or_else(|| format!("{namespace}/{pod_name}"));
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
    (
        key,
        resource_version,
        RawPod {
            namespace,
            pod_name,
            pod_uid,
            node_name,
            pod_ip,
            container_ids,
            container_names,
            labels,
        },
    )
}

async fn read_watch_response(
    mut response: reqwest::Response,
    snapshot: RawPodSnapshot,
    max_line_bytes: u64,
    max_pods: usize,
    max_labels: usize,
    publisher: RawPodPublisher,
) -> Result<RawPodSnapshot, PodWatchError> {
    let mut pods = snapshot
        .pods
        .into_iter()
        .map(|pod| (raw_pod_key(&pod), pod))
        .collect::<BTreeMap<_, _>>();
    let mut resource_version = snapshot.resource_version;
    let mut pending = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|err| PodWatchError::Other(err.to_string()))?
    {
        pending.extend_from_slice(&chunk);
        while let Some(newline) = pending.iter().position(|byte| *byte == b'\n') {
            let line = pending.drain(..=newline).collect::<Vec<_>>();
            apply_and_publish_watch_line(
                trim_watch_line(&line),
                &mut pods,
                &mut resource_version,
                max_pods,
                max_labels,
                &publisher,
            )?;
        }
        if pending.len() as u64 > max_line_bytes {
            return Err(PodWatchError::Other(
                "Kubernetes watch event exceeds the configured response bound".to_string(),
            ));
        }
    }
    if !pending.is_empty() {
        apply_and_publish_watch_line(
            trim_watch_line(&pending),
            &mut pods,
            &mut resource_version,
            max_pods,
            max_labels,
            &publisher,
        )?;
    }
    Ok(RawPodSnapshot {
        resource_version,
        pods: pods.into_values().collect(),
    })
}

pub(super) fn apply_and_publish_watch_line(
    line: &[u8],
    pods: &mut BTreeMap<String, RawPod>,
    resource_version: &mut String,
    max_pods: usize,
    max_labels: usize,
    publisher: &RawPodPublisher,
) -> Result<(), PodWatchError> {
    if line.is_empty() {
        return Ok(());
    }
    apply_watch_line(line, pods, resource_version, max_pods, max_labels)?;
    publisher(&RawPodSnapshot {
        resource_version: resource_version.to_string(),
        pods: pods.values().cloned().collect(),
    });
    Ok(())
}

pub(super) fn apply_watch_line(
    line: &[u8],
    pods: &mut BTreeMap<String, RawPod>,
    resource_version: &mut String,
    max_pods: usize,
    max_labels: usize,
) -> Result<(), PodWatchError> {
    if line.is_empty() {
        return Ok(());
    }
    let event: WatchEvent =
        serde_json::from_slice(line).map_err(|err| PodWatchError::Other(err.to_string()))?;
    match event.event_type.as_str() {
        "ADDED" | "MODIFIED" => {
            let pod: Pod = serde_json::from_value(event.object)
                .map_err(|err| PodWatchError::Other(err.to_string()))?;
            let (key, version, pod) = raw_pod_from_pod(pod, max_labels);
            if pods.contains_key(&key) || pods.len() < max_pods {
                pods.insert(key, pod);
            }
            if let Some(version) = version {
                *resource_version = version;
            }
        }
        "DELETED" => {
            let pod: Pod = serde_json::from_value(event.object)
                .map_err(|err| PodWatchError::Other(err.to_string()))?;
            let (key, version, _) = raw_pod_from_pod(pod, max_labels);
            pods.remove(&key);
            if let Some(version) = version {
                *resource_version = version;
            }
        }
        "BOOKMARK" => {
            let bookmark: Bookmark = serde_json::from_value(event.object)
                .map_err(|err| PodWatchError::Other(err.to_string()))?;
            if let Some(version) = bookmark.metadata.resource_version {
                *resource_version = version;
            }
        }
        "ERROR" => {
            let status: WatchStatus = serde_json::from_value(event.object)
                .map_err(|err| PodWatchError::Other(err.to_string()))?;
            if status.code == Some(410) || status.reason.as_deref() == Some("Expired") {
                return Err(PodWatchError::ExpiredResourceVersion);
            }
            return Err(PodWatchError::Other(status.message.unwrap_or_else(|| {
                "Kubernetes pod watch returned an error".to_string()
            })));
        }
        other => {
            return Err(PodWatchError::Other(format!(
                "unsupported Kubernetes pod watch event type '{other}'"
            )));
        }
    }
    Ok(())
}

fn trim_watch_line(line: &[u8]) -> &[u8] {
    let line = line.strip_suffix(b"\n").unwrap_or(line);
    line.strip_suffix(b"\r").unwrap_or(line)
}

fn raw_pod_key(pod: &RawPod) -> String {
    pod.pod_uid
        .clone()
        .unwrap_or_else(|| format!("{}/{}", pod.namespace, pod.pod_name))
}

fn validate_resource_version(resource_version: &str) -> Result<(), String> {
    if resource_version.is_empty() || resource_version.len() > MAX_RESOURCE_VERSION_BYTES {
        return Err("Kubernetes resourceVersion is empty or exceeds 128 bytes".to_string());
    }
    if !resource_version
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err("Kubernetes resourceVersion contains invalid characters".to_string());
    }
    Ok(())
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
    metadata: ListMetadata,
    #[serde(default)]
    items: Vec<Pod>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ListMetadata {
    resource_version: Option<String>,
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
    #[serde(rename = "resourceVersion")]
    resource_version: Option<String>,
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

#[derive(Debug, Deserialize)]
struct WatchEvent {
    #[serde(rename = "type")]
    event_type: String,
    object: serde_json::Value,
}

#[derive(Debug, Deserialize)]
struct Bookmark {
    metadata: ListMetadata,
}

#[derive(Debug, Deserialize)]
struct WatchStatus {
    code: Option<u16>,
    reason: Option<String>,
    message: Option<String>,
}
