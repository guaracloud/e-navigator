use async_trait::async_trait;
use e_navigator_core::{CoreError, CoreResult, Generator, ModuleKind, ModuleMetadata};
use e_navigator_signals::{
    ContainerContext, DependencyEdgeEvent, DependencyEndpoint, KubernetesContext,
    NetworkConnectionCloseEvent, NetworkConnectionOpenEvent, NetworkProtocol, SignalEnvelope,
    SignalPayload,
};
use std::{
    collections::BTreeMap,
    sync::{Mutex, MutexGuard},
};
use tokio::sync::mpsc;

const DEFAULT_MAX_EDGES: usize = 4096;

#[derive(Debug)]
pub struct DependencyGraphGenerator {
    max_edges: usize,
    edges: Mutex<BTreeMap<EdgeKey, EdgeState>>,
}

impl Default for DependencyGraphGenerator {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_EDGES)
    }
}

impl DependencyGraphGenerator {
    pub fn new(max_edges: usize) -> Self {
        Self {
            max_edges,
            edges: Mutex::new(BTreeMap::new()),
        }
    }
}

#[async_trait]
impl Generator<SignalEnvelope> for DependencyGraphGenerator {
    fn metadata(&self) -> ModuleMetadata {
        ModuleMetadata::new("generator.dependency_graph", ModuleKind::Generator)
    }

    async fn observe(
        &self,
        signal: &SignalEnvelope,
        tx: &mpsc::Sender<SignalEnvelope>,
    ) -> CoreResult<()> {
        let Some(observation) = observation_from_signal(signal) else {
            return Ok(());
        };

        let edge = {
            let mut edges = self.edges()?;
            if let Some(existing) = edges.get_mut(&observation.key) {
                existing.observations = existing.observations.saturating_add(1);
                existing.last_seen_unix_nanos = observation.timestamp_unix_nanos;
                None
            } else if edges.len() >= self.max_edges {
                None
            } else {
                let state = EdgeState {
                    edge: observation.edge,
                    observations: 1,
                    first_seen_unix_nanos: observation.timestamp_unix_nanos,
                    last_seen_unix_nanos: observation.timestamp_unix_nanos,
                };
                let signal = state.to_signal(signal.host.clone());
                edges.insert(observation.key, state);
                Some(signal)
            }
        };

        if let Some(edge) = edge {
            tx.send(edge).await.map_err(|_| CoreError::PipelineClosed)?;
        }

        Ok(())
    }
}

impl DependencyGraphGenerator {
    fn edges(&self) -> CoreResult<MutexGuard<'_, BTreeMap<EdgeKey, EdgeState>>> {
        self.edges.lock().map_err(|err| CoreError::ModuleFailed {
            module: "generator.dependency_graph".to_string(),
            message: err.to_string(),
        })
    }
}

#[derive(Debug, Clone)]
struct EdgeObservation {
    key: EdgeKey,
    edge: EdgeTemplate,
    timestamp_unix_nanos: u64,
}

#[derive(Debug, Clone)]
struct EdgeState {
    edge: EdgeTemplate,
    observations: u64,
    first_seen_unix_nanos: u64,
    last_seen_unix_nanos: u64,
}

impl EdgeState {
    fn to_signal(&self, host: Option<String>) -> SignalEnvelope {
        SignalEnvelope::dependency_edge(
            "generator.dependency_graph",
            host,
            DependencyEdgeEvent {
                source: self.edge.source.clone(),
                destination: self.edge.destination.clone(),
                protocol: self.edge.protocol,
                observations: self.observations,
                first_seen_unix_nanos: self.first_seen_unix_nanos,
                last_seen_unix_nanos: self.last_seen_unix_nanos,
            },
        )
    }
}

#[derive(Debug, Clone)]
struct EdgeTemplate {
    source: DependencyEndpoint,
    destination: DependencyEndpoint,
    protocol: NetworkProtocol,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct EdgeKey {
    source_workload: Option<String>,
    source_container: Option<String>,
    destination_address: String,
    destination_port: u16,
    protocol: NetworkProtocol,
}

fn observation_from_signal(signal: &SignalEnvelope) -> Option<EdgeObservation> {
    match &signal.payload {
        SignalPayload::NetworkConnectionOpen(event) => Some(observation_from_open(event)),
        SignalPayload::NetworkConnectionClose(event) => Some(observation_from_close(event)),
        _ => None,
    }
}

fn observation_from_open(event: &NetworkConnectionOpenEvent) -> EdgeObservation {
    observation(
        event.kubernetes.clone(),
        event.container.clone(),
        event.remote_address.clone(),
        event.remote_port,
        event.protocol,
        event.timestamp_unix_nanos,
    )
}

fn observation_from_close(event: &NetworkConnectionCloseEvent) -> EdgeObservation {
    observation(
        event.kubernetes.clone(),
        event.container.clone(),
        event.remote_address.clone(),
        event.remote_port,
        event.protocol,
        event.closed_at_unix_nanos,
    )
}

fn observation(
    kubernetes: Option<KubernetesContext>,
    container: Option<ContainerContext>,
    remote_address: String,
    remote_port: u16,
    protocol: NetworkProtocol,
    timestamp_unix_nanos: u64,
) -> EdgeObservation {
    let key = EdgeKey {
        source_workload: kubernetes.as_ref().map(workload_key),
        source_container: container
            .as_ref()
            .map(|container| container.container_id.clone()),
        destination_address: remote_address.clone(),
        destination_port: remote_port,
        protocol,
    };
    let edge = EdgeTemplate {
        source: DependencyEndpoint {
            workload: kubernetes,
            container,
            address: None,
            port: None,
            domain: None,
        },
        destination: DependencyEndpoint {
            workload: None,
            container: None,
            address: Some(remote_address),
            port: Some(remote_port),
            domain: None,
        },
        protocol,
    };

    EdgeObservation {
        key,
        edge,
        timestamp_unix_nanos,
    }
}

fn workload_key(context: &KubernetesContext) -> String {
    format!(
        "{}/{}/{}",
        context.namespace,
        context.pod_uid.as_deref().unwrap_or(&context.pod_name),
        context.container_name.as_deref().unwrap_or("")
    )
}

#[cfg(test)]
mod tests {
    use e_navigator_core::Generator;
    use e_navigator_signals::{
        ContainerContext, DependencyEndpoint, KubernetesContext, NetworkAddressFamily,
        NetworkConnectionOpenEvent, NetworkProcessIdentity, NetworkProtocol, SignalEnvelope,
        SignalPayload,
    };
    use std::collections::BTreeMap;
    use tokio::sync::mpsc;

    use super::*;

    #[tokio::test]
    async fn emits_deterministic_dependency_edge_from_network_connection() {
        let generator = DependencyGraphGenerator::default();
        let signal = network_open_signal("203.0.113.10", 443, 1_000);

        let edges = observe(&generator, &signal).await;

        assert_eq!(edges.len(), 1);
        let SignalPayload::DependencyEdge(edge) = &edges[0].payload else {
            panic!("expected dependency edge");
        };
        assert_eq!(edge.protocol, NetworkProtocol::Tcp);
        assert_eq!(edge.observations, 1);
        assert_eq!(edge.first_seen_unix_nanos, 1_000);
        assert_eq!(edge.last_seen_unix_nanos, 1_000);
        assert_eq!(
            edge.source,
            DependencyEndpoint {
                workload: Some(kubernetes_context()),
                container: Some(container_context()),
                address: None,
                port: None,
                domain: None,
            }
        );
        assert_eq!(
            edge.destination,
            DependencyEndpoint {
                workload: None,
                container: None,
                address: Some("203.0.113.10".to_string()),
                port: Some(443),
                domain: None,
            }
        );
    }

    #[tokio::test]
    async fn suppresses_duplicate_edges_for_identical_observations() {
        let generator = DependencyGraphGenerator::default();
        let signal = network_open_signal("203.0.113.10", 443, 1_000);

        let first = observe(&generator, &signal).await;
        let second = observe(&generator, &signal).await;

        assert_eq!(first.len(), 1);
        assert!(second.is_empty());
    }

    async fn observe(
        generator: &DependencyGraphGenerator,
        signal: &SignalEnvelope,
    ) -> Vec<SignalEnvelope> {
        let (tx, mut rx) = mpsc::channel(4);
        generator
            .observe(signal, &tx)
            .await
            .expect("generator succeeds");
        drop(tx);

        let mut edges = Vec::new();
        while let Some(edge) = rx.recv().await {
            edges.push(edge);
        }
        edges
    }

    fn network_open_signal(
        remote_address: &str,
        remote_port: u16,
        timestamp: u64,
    ) -> SignalEnvelope {
        SignalEnvelope::network_connection_open(
            "source.test",
            Some("node-a".to_string()),
            NetworkConnectionOpenEvent {
                process: NetworkProcessIdentity {
                    pid: 42,
                    ppid: Some(1),
                    uid: Some(1000),
                    command: "api".to_string(),
                    executable: Some("/app/api".to_string()),
                },
                protocol: NetworkProtocol::Tcp,
                address_family: NetworkAddressFamily::Ipv4,
                local_address: Some("10.0.0.5".to_string()),
                local_port: Some(43512),
                remote_address: remote_address.to_string(),
                remote_port,
                fd: Some(7),
                timestamp_unix_nanos: timestamp,
                container: Some(container_context()),
                kubernetes: Some(kubernetes_context()),
            },
        )
    }

    fn container_context() -> ContainerContext {
        ContainerContext {
            container_id: "container-a".to_string(),
            runtime: Some("containerd".to_string()),
        }
    }

    fn kubernetes_context() -> KubernetesContext {
        let mut labels = BTreeMap::new();
        labels.insert("app".to_string(), "api".to_string());

        KubernetesContext {
            namespace: "default".to_string(),
            pod_name: "api-123".to_string(),
            pod_uid: Some("pod-uid".to_string()),
            container_name: Some("api".to_string()),
            node_name: Some("node-a".to_string()),
            labels,
        }
    }
}
