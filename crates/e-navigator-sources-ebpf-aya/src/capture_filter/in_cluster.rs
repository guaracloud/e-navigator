//! In-cluster bounded Kubernetes workload fetch and parsing.
//!
//! Pod API scoping follows `allow_cluster_wide_pod_list`; attribution selectors
//! are deliberately not applied here so capture filtering can still exclude a
//! workload that enrichment would omit. Services and EndpointSlices share the
//! same API client and reconciliation generation.

use std::collections::BTreeMap;
use std::io::Read;
use std::path::Path;
use std::time::Duration;

use async_trait::async_trait;
use e_navigator_core::KubernetesAttributionConfig;
use e_navigator_core::capture_filter::{RawEndpointSlice, RawPod, RawService};
use serde::{Deserialize, Deserializer};

use super::{
    MAX_LABELS_PER_POD, MAX_POD_LIST_RESPONSE_BYTES, MAX_TOKEN_BYTES, PodWatchError, RawPodFetcher,
    RawPodPublisher, RawPodSnapshot,
};

const WATCH_TIMEOUT_SECONDS: &str = "300";
const WATCH_REQUEST_TIMEOUT: Duration = Duration::from_secs(310);
const API_CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const LIST_REQUEST_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_RESOURCE_VERSION_BYTES: usize = 128;

/// Reqwest-backed fetcher for one bounded cluster-wide workload snapshot.
/// Local Pods are retained first when the configured bound is reached so the
/// capture filter never loses identities required by this DaemonSet member.
#[derive(Debug)]
pub(crate) struct InClusterRawFetcher {
    client: reqwest::Client,
    pods_url: String,
    services_url: String,
    endpoint_slices_url: String,
    token: String,
    max_response_bytes: u64,
    max_pods: usize,
    preferred_node: String,
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
        let base_url = format!("https://{host}:{port}");
        let pods_url = if config.allow_cluster_wide_pod_list {
            format!("{base_url}/api/v1/pods")
        } else {
            format!("{base_url}/api/v1/pods?fieldSelector=spec.nodeName%3D{node}")
        };

        Ok(Self {
            client,
            pods_url,
            services_url: format!("{base_url}/api/v1/services"),
            endpoint_slices_url: format!("{base_url}/apis/discovery.k8s.io/v1/endpointslices"),
            token,
            max_response_bytes: config.max_response_bytes.min(MAX_POD_LIST_RESPONSE_BYTES),
            max_pods: config.max_pods,
            preferred_node: node,
        })
    }

    async fn get_bounded(&self, url: &str) -> Result<String, String> {
        let response = self
            .client
            .get(url)
            .bearer_auth(self.token.trim())
            .timeout(LIST_REQUEST_TIMEOUT)
            .send()
            .await
            .map_err(|err| err.to_string())?
            .error_for_status()
            .map_err(|err| err.to_string())?;
        read_response_body(response, self.max_response_bytes).await
    }
}

#[async_trait]
impl RawPodFetcher for InClusterRawFetcher {
    async fn list(&self) -> Result<RawPodSnapshot, String> {
        let (pods_body, services_body, endpoint_slices_body) = tokio::try_join!(
            self.get_bounded(&self.pods_url),
            self.get_bounded(&self.services_url),
            self.get_bounded(&self.endpoint_slices_url),
        )?;
        let mut snapshot = parse_raw_pod_snapshot_for_node(
            &pods_body,
            self.max_pods,
            MAX_LABELS_PER_POD,
            Some(&self.preferred_node),
        )?;
        snapshot.services = parse_raw_services(&services_body, self.max_pods)?;
        snapshot.endpoint_slices = parse_raw_endpoint_slices(&endpoint_slices_body, self.max_pods)?;
        Ok(snapshot)
    }

    async fn watch(
        &self,
        snapshot: RawPodSnapshot,
        publisher: RawPodPublisher,
    ) -> Result<RawPodSnapshot, PodWatchError> {
        validate_resource_version(&snapshot.resource_version).map_err(PodWatchError::Other)?;
        let mut url = reqwest::Url::parse(&self.pods_url)
            .map_err(|err| PodWatchError::Other(err.to_string()))?;
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
            Some(&self.preferred_node),
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

#[cfg_attr(not(test), allow(dead_code))]
pub(super) fn parse_raw_pod_snapshot(
    body: &str,
    max_pods: usize,
    max_labels: usize,
) -> Result<RawPodSnapshot, String> {
    parse_raw_pod_snapshot_for_node(body, max_pods, max_labels, None)
}

pub(super) fn parse_raw_pod_snapshot_for_node(
    body: &str,
    max_pods: usize,
    max_labels: usize,
    preferred_node: Option<&str>,
) -> Result<RawPodSnapshot, String> {
    let pod_list: PodList = serde_json::from_str(body).map_err(|err| err.to_string())?;
    let mut pods = pod_list
        .items
        .into_iter()
        .map(|pod| raw_pod_from_pod(pod, max_labels).2)
        .collect::<Vec<_>>();
    if let Some(preferred_node) = preferred_node {
        pods.sort_by_key(|pod| {
            (
                pod.node_name.as_deref() != Some(preferred_node),
                pod.namespace.clone(),
                pod.pod_name.clone(),
            )
        });
    }
    pods.truncate(max_pods);
    Ok(RawPodSnapshot {
        resource_version: pod_list.metadata.resource_version.unwrap_or_default(),
        pods,
        services: Vec::new(),
        endpoint_slices: Vec::new(),
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
    let raw_labels = pod.metadata.labels.unwrap_or_default();
    let (workload_name, workload_type) = workload_owner(
        pod.metadata.owner_references.as_deref().unwrap_or_default(),
        &raw_labels,
        &pod_name,
    );
    let labels = bounded_labels(raw_labels, max_labels);
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
            workload_name,
            workload_type,
            container_ids,
            container_names,
            labels,
        },
    )
}

fn workload_owner(
    owner_references: &[OwnerReference],
    labels: &BTreeMap<String, String>,
    pod_name: &str,
) -> (Option<String>, Option<String>) {
    if let Some(owner) = owner_references
        .iter()
        .find(|owner| owner.controller == Some(true))
        .or_else(|| owner_references.first())
    {
        if owner.kind == "ReplicaSet"
            && let Some(template_hash) = labels.get("pod-template-hash")
            && owner
                .name
                .strip_suffix(template_hash)
                .and_then(|prefix| prefix.strip_suffix('-'))
                .is_some()
        {
            let deployment = owner
                .name
                .strip_suffix(template_hash)
                .and_then(|prefix| prefix.strip_suffix('-'))
                .unwrap_or(&owner.name);
            return (Some(deployment.to_string()), Some("deployment".to_string()));
        }
        return (
            Some(owner.name.clone()),
            Some(owner.kind.to_ascii_lowercase()),
        );
    }

    for label in ["app.kubernetes.io/name", "app", "k8s-app"] {
        if let Some(name) = labels.get(label).filter(|name| !name.is_empty()) {
            return (Some(name.clone()), Some("application".to_string()));
        }
    }
    (!pod_name.is_empty())
        .then(|| pod_name.to_string())
        .map_or((None, None), |name| (Some(name), Some("pod".to_string())))
}

pub(super) fn parse_raw_services(
    body: &str,
    max_services: usize,
) -> Result<Vec<RawService>, String> {
    let service_list: ServiceList = serde_json::from_str(body).map_err(|err| err.to_string())?;
    Ok(service_list
        .items
        .into_iter()
        .take(max_services)
        .filter_map(|service| {
            let namespace = service.metadata.namespace.unwrap_or_default();
            let service_name = service.metadata.name.unwrap_or_default();
            if namespace.is_empty() || service_name.is_empty() {
                return None;
            }
            let spec = service.spec?;
            let mut cluster_ips = spec.cluster_ips.unwrap_or_default();
            if let Some(cluster_ip) = spec.cluster_ip {
                cluster_ips.push(cluster_ip);
            }
            cluster_ips.retain(|address| !address.is_empty() && address != "None");
            cluster_ips.sort();
            cluster_ips.dedup();
            Some(RawService {
                namespace,
                service_name,
                service_uid: service.metadata.uid,
                cluster_ips,
            })
        })
        .collect())
}

pub(super) fn parse_raw_endpoint_slices(
    body: &str,
    max_slices: usize,
) -> Result<Vec<RawEndpointSlice>, String> {
    let slice_list: EndpointSliceList =
        serde_json::from_str(body).map_err(|err| err.to_string())?;
    Ok(slice_list
        .items
        .into_iter()
        .take(max_slices)
        .filter_map(|slice| {
            let namespace = slice.metadata.namespace.unwrap_or_default();
            let service_name = slice
                .metadata
                .labels
                .unwrap_or_default()
                .remove("kubernetes.io/service-name")?;
            if namespace.is_empty() || service_name.is_empty() {
                return None;
            }
            let mut addresses = slice
                .endpoints
                .into_iter()
                .filter(|endpoint| endpoint.conditions.ready != Some(false))
                .flat_map(|endpoint| endpoint.addresses.into_iter().take(256))
                .collect::<Vec<_>>();
            addresses.sort();
            addresses.dedup();
            Some(RawEndpointSlice {
                namespace,
                service_name,
                addresses,
            })
        })
        .collect())
}

#[derive(Clone, Copy)]
pub(super) struct WatchResources<'a> {
    pub(super) preferred_node: Option<&'a str>,
    pub(super) services: &'a [RawService],
    pub(super) endpoint_slices: &'a [RawEndpointSlice],
}

async fn read_watch_response(
    mut response: reqwest::Response,
    snapshot: RawPodSnapshot,
    max_line_bytes: u64,
    max_pods: usize,
    max_labels: usize,
    preferred_node: Option<&str>,
    publisher: RawPodPublisher,
) -> Result<RawPodSnapshot, PodWatchError> {
    let services = snapshot.services.clone();
    let endpoint_slices = snapshot.endpoint_slices.clone();
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
            let resources = WatchResources {
                preferred_node,
                services: &services,
                endpoint_slices: &endpoint_slices,
            };
            apply_and_publish_watch_line(
                trim_watch_line(&line),
                &mut pods,
                &mut resource_version,
                max_pods,
                max_labels,
                resources,
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
        let resources = WatchResources {
            preferred_node,
            services: &services,
            endpoint_slices: &endpoint_slices,
        };
        apply_and_publish_watch_line(
            trim_watch_line(&pending),
            &mut pods,
            &mut resource_version,
            max_pods,
            max_labels,
            resources,
            &publisher,
        )?;
    }
    Ok(RawPodSnapshot {
        resource_version,
        pods: pods.into_values().collect(),
        services,
        endpoint_slices,
    })
}

pub(super) fn apply_and_publish_watch_line(
    line: &[u8],
    pods: &mut BTreeMap<String, RawPod>,
    resource_version: &mut String,
    max_pods: usize,
    max_labels: usize,
    resources: WatchResources<'_>,
    publisher: &RawPodPublisher,
) -> Result<(), PodWatchError> {
    if line.is_empty() {
        return Ok(());
    }
    apply_watch_line_for_node(
        line,
        pods,
        resource_version,
        max_pods,
        max_labels,
        resources.preferred_node,
    )?;
    publisher(&RawPodSnapshot {
        resource_version: resource_version.to_string(),
        pods: pods.values().cloned().collect(),
        services: resources.services.to_vec(),
        endpoint_slices: resources.endpoint_slices.to_vec(),
    });
    Ok(())
}

#[cfg(test)]
pub(super) fn apply_watch_line(
    line: &[u8],
    pods: &mut BTreeMap<String, RawPod>,
    resource_version: &mut String,
    max_pods: usize,
    max_labels: usize,
) -> Result<(), PodWatchError> {
    apply_watch_line_for_node(line, pods, resource_version, max_pods, max_labels, None)
}

fn apply_watch_line_for_node(
    line: &[u8],
    pods: &mut BTreeMap<String, RawPod>,
    resource_version: &mut String,
    max_pods: usize,
    max_labels: usize,
    preferred_node: Option<&str>,
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
            if !pods.contains_key(&key)
                && pods.len() >= max_pods
                && preferred_node.is_some_and(|node| pod.node_name.as_deref() == Some(node))
                && let Some(remote_key) = pods.iter().find_map(|(key, pod)| {
                    preferred_node
                        .is_some_and(|node| pod.node_name.as_deref() != Some(node))
                        .then(|| key.clone())
                })
            {
                pods.remove(&remote_key);
            }
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
    #[serde(rename = "ownerReferences")]
    owner_references: Option<Vec<OwnerReference>>,
}

#[derive(Debug, Deserialize)]
struct OwnerReference {
    kind: String,
    name: String,
    controller: Option<bool>,
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
struct ServiceList {
    #[serde(default)]
    items: Vec<Service>,
}

#[derive(Debug, Deserialize)]
struct Service {
    metadata: ServiceMetadata,
    spec: Option<ServiceSpec>,
}

#[derive(Debug, Deserialize)]
struct ServiceMetadata {
    namespace: Option<String>,
    name: Option<String>,
    uid: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ServiceSpec {
    #[serde(rename = "clusterIP")]
    cluster_ip: Option<String>,
    #[serde(rename = "clusterIPs")]
    cluster_ips: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct EndpointSliceList {
    #[serde(default)]
    items: Vec<EndpointSlice>,
}

#[derive(Debug, Deserialize)]
struct EndpointSlice {
    metadata: EndpointSliceMetadata,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    endpoints: Vec<EndpointSliceEndpoint>,
}

#[derive(Debug, Deserialize)]
struct EndpointSliceMetadata {
    namespace: Option<String>,
    labels: Option<BTreeMap<String, String>>,
}

#[derive(Debug, Deserialize)]
struct EndpointSliceEndpoint {
    #[serde(default, deserialize_with = "deserialize_null_default")]
    addresses: Vec<String>,
    #[serde(default)]
    conditions: EndpointConditions,
}

#[derive(Debug, Default, Deserialize)]
struct EndpointConditions {
    ready: Option<bool>,
}

fn deserialize_null_default<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de> + Default,
{
    Ok(Option::<T>::deserialize(deserializer)?.unwrap_or_default())
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
