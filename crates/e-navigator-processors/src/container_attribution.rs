use async_trait::async_trait;
use e_navigator_core::{
    AttributionConfig, CoreResult, KubernetesAttributionConfig, ModuleKind, ModuleMetadata,
    Processor,
};
use e_navigator_signals::{ContainerContext, KubernetesContext, SignalEnvelope, SignalPayload};
use serde::Deserialize;
use std::{collections::BTreeMap, fs::File, io::Read, path::Path, time::Duration};
use tracing::warn;

const MAX_CGROUP_BYTES: u64 = 16 * 1024;
const MAX_TOKEN_BYTES: u64 = 64 * 1024;

#[derive(Debug)]
pub struct ContainerAttributionProcessor {
    config: AttributionConfig,
    kubernetes_cache: KubernetesMetadataCache,
}

impl Default for ContainerAttributionProcessor {
    fn default() -> Self {
        Self::new(AttributionConfig::default())
    }
}

impl ContainerAttributionProcessor {
    pub fn new(config: AttributionConfig) -> Self {
        let kubernetes_cache = if config.kubernetes.enabled {
            KubernetesMetadataCache::from_in_cluster(&config.kubernetes).unwrap_or_else(|err| {
                warn!(error = %err, "kubernetes metadata cache unavailable");
                KubernetesMetadataCache::default()
            })
        } else {
            KubernetesMetadataCache::default()
        };

        Self {
            config,
            kubernetes_cache,
        }
    }

    pub fn with_cache(
        config: AttributionConfig,
        kubernetes_cache: KubernetesMetadataCache,
    ) -> Self {
        Self {
            config,
            kubernetes_cache,
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
                    event.container = self.container_for_pid(event.pid);
                }
                if event.kubernetes.is_none() {
                    event.kubernetes = event
                        .container
                        .as_ref()
                        .and_then(|container| self.kubernetes_cache.get(&container.container_id));
                }
            }
            SignalPayload::ProcessExit(event) => {
                if event.container.is_none() {
                    event.container = self.container_for_pid(event.pid);
                }
                if event.kubernetes.is_none() {
                    event.kubernetes = event
                        .container
                        .as_ref()
                        .and_then(|container| self.kubernetes_cache.get(&container.container_id));
                }
            }
            SignalPayload::ProcessLifecycleDuration(event) => {
                if event.kubernetes.is_none() {
                    event.kubernetes = event
                        .container
                        .as_ref()
                        .and_then(|container| self.kubernetes_cache.get(&container.container_id));
                }
            }
            SignalPayload::NetworkConnectionOpen(event) => {
                self.enrich_context(
                    event.process.pid,
                    &mut event.container,
                    &mut event.kubernetes,
                );
            }
            SignalPayload::NetworkConnectionClose(event) => {
                self.enrich_context(
                    event.process.pid,
                    &mut event.container,
                    &mut event.kubernetes,
                );
            }
            SignalPayload::NetworkConnectionFailure(event) => {
                self.enrich_context(
                    event.process.pid,
                    &mut event.container,
                    &mut event.kubernetes,
                );
            }
            SignalPayload::DependencyEdge(_) => {}
            SignalPayload::RuntimeSecurityFinding(_) => {}
        }

        Ok(Some(signal))
    }
}

impl ContainerAttributionProcessor {
    fn enrich_context(
        &self,
        pid: u32,
        container: &mut Option<ContainerContext>,
        kubernetes: &mut Option<KubernetesContext>,
    ) {
        if container.is_none() {
            *container = self.container_for_pid(pid);
        }
        if kubernetes.is_none() {
            *kubernetes = container
                .as_ref()
                .and_then(|container| self.kubernetes_cache.get(&container.container_id));
        }
    }

    fn container_for_pid(&self, pid: u32) -> Option<ContainerContext> {
        let path = self.config.procfs_root.join(pid.to_string()).join("cgroup");
        match read_bounded_to_string(&path, MAX_CGROUP_BYTES) {
            Ok(contents) => parse_container_from_cgroup(&contents),
            Err(err) => {
                warn!(
                    pid,
                    path = %path.display(),
                    error = %err,
                    "unable to read process cgroup for attribution"
                );
                None
            }
        }
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

    fn get(&self, container_id: &str) -> Option<KubernetesContext> {
        self.by_container_id.get(container_id).cloned()
    }

    fn from_in_cluster(config: &KubernetesAttributionConfig) -> Result<Self, String> {
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

fn parse_container_from_cgroup(contents: &str) -> Option<ContainerContext> {
    let container_id = find_container_id(contents)?;
    let runtime = infer_runtime(contents);
    Some(ContainerContext {
        container_id,
        runtime,
    })
}

fn find_container_id(contents: &str) -> Option<String> {
    let bytes = contents.as_bytes();
    let mut index = 0;

    while index + 64 <= bytes.len() {
        if bytes[index..index + 64]
            .iter()
            .all(|byte| byte.is_ascii_hexdigit())
        {
            return Some(contents[index..index + 64].to_string());
        }
        index += 1;
    }

    None
}

fn infer_runtime(contents: &str) -> Option<String> {
    if contents.contains("cri-containerd") || contents.contains("containerd") {
        Some("containerd".to_string())
    } else if contents.contains("crio") || contents.contains("cri-o") {
        Some("cri-o".to_string())
    } else if contents.contains("docker") {
        Some("docker".to_string())
    } else {
        None
    }
}

fn read_bounded_to_string(path: &Path, max_bytes: u64) -> Result<String, String> {
    let mut file = File::open(path).map_err(|err| err.to_string())?;
    let mut buffer = String::new();
    file.by_ref()
        .take(max_bytes)
        .read_to_string(&mut buffer)
        .map_err(|err| err.to_string())?;
    Ok(buffer)
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

#[cfg(test)]
mod tests {
    use super::*;
    use e_navigator_signals::{
        ContainerContext, ExecEvent, KubernetesContext, NetworkAddressFamily,
        NetworkConnectionOpenEvent, NetworkProcessIdentity, NetworkProtocol,
    };
    use std::{collections::BTreeMap, fs};

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
}
