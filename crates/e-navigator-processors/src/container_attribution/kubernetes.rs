use e_navigator_core::KubernetesAttributionConfig;
use e_navigator_signals::KubernetesContext;
use serde::Deserialize;
use std::{collections::BTreeMap, time::Duration};

use super::cgroup::read_bounded_to_string;

const MAX_TOKEN_BYTES: u64 = 64 * 1024;

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

    pub(super) fn get(&self, container_id: &str) -> Option<KubernetesContext> {
        self.by_container_id.get(container_id).cloned()
    }

    pub(super) fn from_in_cluster(config: &KubernetesAttributionConfig) -> Result<Self, String> {
        let host = std::env::var("KUBERNETES_SERVICE_HOST")
            .map_err(|_| "KUBERNETES_SERVICE_HOST is not set".to_string())?;
        let port = std::env::var("KUBERNETES_SERVICE_PORT").unwrap_or_else(|_| "443".to_string());
        let token = read_bounded_to_string(&config.token_path, MAX_TOKEN_BYTES)?;
        let ca = std::fs::read(&config.ca_cert_path).map_err(|err| err.to_string())?;
        let cert = reqwest::Certificate::from_pem(&ca).map_err(|err| err.to_string())?;
        let client = reqwest::blocking::Client::builder()
            .add_root_certificate(cert)
            .timeout(Duration::from_secs(3))
            .build()
            .map_err(|err| err.to_string())?;
        let url = match std::env::var("NODE_NAME") {
            Ok(node) if !node.is_empty() => {
                format!("https://{host}:{port}/api/v1/pods?fieldSelector=spec.nodeName%3D{node}")
            }
            _ => format!("https://{host}:{port}/api/v1/pods"),
        };
        let body = client
            .get(url)
            .bearer_auth(token.trim())
            .send()
            .map_err(|err| err.to_string())?
            .error_for_status()
            .map_err(|err| err.to_string())?
            .text()
            .map_err(|err| err.to_string())?;
        let pod_list = serde_json::from_str::<PodList>(&body).map_err(|err| err.to_string())?;

        Ok(Self::from_pod_list(pod_list))
    }

    fn from_pod_list(pod_list: PodList) -> Self {
        let mut by_container_id = BTreeMap::new();

        for pod in pod_list.items {
            let namespace = pod.metadata.namespace.unwrap_or_default();
            let pod_name = pod.metadata.name.unwrap_or_default();
            let pod_uid = pod.metadata.uid;
            let labels = pod.metadata.labels.unwrap_or_default();
            let node_name = pod.spec.and_then(|spec| spec.node_name);
            if let Some(status) = pod.status {
                for container in status.container_statuses.unwrap_or_default() {
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
    container_id: Option<String>,
}
