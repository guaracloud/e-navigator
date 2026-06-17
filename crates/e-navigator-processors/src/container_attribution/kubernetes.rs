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

    pub(super) fn len(&self) -> usize {
        self.by_container_id.len()
    }

    pub(super) fn contains_container(&self, container_id: &str) -> bool {
        self.by_container_id.contains_key(container_id)
    }

    pub(super) fn get(&self, container_id: &str) -> Option<KubernetesContext> {
        self.by_container_id.get(container_id).cloned()
    }

    pub(super) fn from_in_cluster(config: &KubernetesAttributionConfig) -> Result<Self, String> {
        let host = std::env::var("KUBERNETES_SERVICE_HOST")
            .map_err(|_| "KUBERNETES_SERVICE_HOST is not set".to_string())?;
        let port = std::env::var("KUBERNETES_SERVICE_PORT").unwrap_or_else(|_| "443".to_string());
        let token = read_bounded_to_string(&config.token_path, MAX_TOKEN_BYTES)
            .map_err(|err| err.to_string())?;
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

        let cache = KubernetesMetadataCache::from_pod_list(pod_list);
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

        let cache = KubernetesMetadataCache::from_pod_list(pod_list);

        assert!(cache.contains_container(
            "a528e7d90a827ff72201ea1cefe7d299448a2528cc5ada9ce4a7ec6d0c4a3b70"
        ));
    }
}
