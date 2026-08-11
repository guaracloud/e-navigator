use async_trait::async_trait;
use e_navigator_core::{CoreError, CoreResult, Generator, ModuleKind, ModuleMetadata};
use e_navigator_signals::{
    MetricAggregationWindow, NetworkAddressFamily, NetworkFlowEndpoint, NetworkFlowSummaryEvent,
    NetworkPeerFlowMetric, NetworkPeerIdentity, SignalEnvelope, SignalPayload,
};
use std::{
    collections::BTreeMap,
    sync::{Mutex, MutexGuard},
};
use tokio::sync::mpsc;

const DEFAULT_MAX_PEER_FLOW_KEYS: usize = 4096;

/// Aggregates already-enriched L4 flow summaries into bounded workload-pair
/// counters. The interface deliberately accepts only the native flow signal;
/// Kubernetes lookup and transport formatting remain at their existing seams.
#[derive(Debug)]
pub struct PeerFlowMetricsGenerator {
    max_keys: usize,
    counters: Mutex<BTreeMap<PeerFlowKey, PeerFlowState>>,
    overflow_counters: Mutex<BTreeMap<OverflowKey, PeerFlowState>>,
}

impl Default for PeerFlowMetricsGenerator {
    fn default() -> Self {
        Self::with_limit(DEFAULT_MAX_PEER_FLOW_KEYS)
    }
}

impl PeerFlowMetricsGenerator {
    pub fn with_limit(max_keys: usize) -> Self {
        Self {
            max_keys: max_keys.max(1),
            counters: Mutex::new(BTreeMap::new()),
            overflow_counters: Mutex::new(BTreeMap::new()),
        }
    }

    fn outputs_for_signal(&self, signal: &SignalEnvelope) -> CoreResult<Vec<SignalEnvelope>> {
        let SignalPayload::NetworkFlowSummary(flow) = &signal.payload else {
            return Ok(Vec::new());
        };
        let Some(key) = PeerFlowKey::from_flow(flow, signal.host.clone()) else {
            return Ok(Vec::new());
        };

        let mut counters = self.counters()?;
        if let Some(state) = counters.get_mut(&key) {
            state.observe(flow);
            return Ok(vec![state.to_signal()]);
        }

        if counters.len() >= self.max_keys {
            drop(counters);
            return self.observe_overflow(flow);
        }

        let state = PeerFlowState {
            key: key.clone(),
            value: flow.bytes,
            window: MetricAggregationWindow {
                start_unix_nanos: flow.first_seen_unix_nanos,
                end_unix_nanos: flow.last_seen_unix_nanos,
            },
            overflow: false,
        };
        let output = state.to_signal();
        counters.insert(key, state);
        Ok(vec![output])
    }

    fn counters(&self) -> CoreResult<MutexGuard<'_, BTreeMap<PeerFlowKey, PeerFlowState>>> {
        self.counters.lock().map_err(|err| CoreError::ModuleFailed {
            module: "generator.peer_flow_metrics".to_string(),
            message: err.to_string(),
        })
    }

    fn overflow_counters(
        &self,
    ) -> CoreResult<MutexGuard<'_, BTreeMap<OverflowKey, PeerFlowState>>> {
        self.overflow_counters
            .lock()
            .map_err(|err| CoreError::ModuleFailed {
                module: "generator.peer_flow_metrics".to_string(),
                message: err.to_string(),
            })
    }

    fn observe_overflow(&self, flow: &NetworkFlowSummaryEvent) -> CoreResult<Vec<SignalEnvelope>> {
        let overflow_key = OverflowKey {
            protocol: flow.protocol,
            address_family: flow.address_family,
            direction: flow.direction,
        };
        let mut counters = self.overflow_counters()?;
        if let Some(state) = counters.get_mut(&overflow_key) {
            state.observe(flow);
            return Ok(vec![state.to_signal()]);
        }

        let other = overflow_identity();
        let state = PeerFlowState {
            key: PeerFlowKey {
                host: None,
                protocol: flow.protocol,
                address_family: flow.address_family,
                direction: flow.direction,
                source: other.clone(),
                destination: other,
            },
            value: flow.bytes,
            window: MetricAggregationWindow {
                start_unix_nanos: flow.first_seen_unix_nanos,
                end_unix_nanos: flow.last_seen_unix_nanos,
            },
            overflow: true,
        };
        let output = state.to_signal();
        counters.insert(overflow_key, state);
        Ok(vec![output])
    }
}

#[async_trait]
impl Generator<SignalEnvelope> for PeerFlowMetricsGenerator {
    fn metadata(&self) -> ModuleMetadata {
        ModuleMetadata::new("generator.peer_flow_metrics", ModuleKind::Generator)
    }

    fn accepts(&self, signal: &SignalEnvelope) -> bool {
        matches!(signal.payload, SignalPayload::NetworkFlowSummary(_))
    }

    fn observe_immediate(
        &self,
        signal: &SignalEnvelope,
    ) -> Option<CoreResult<Vec<SignalEnvelope>>> {
        Some(self.outputs_for_signal(signal))
    }

    async fn observe(
        &self,
        signal: &SignalEnvelope,
        tx: &mpsc::Sender<SignalEnvelope>,
    ) -> CoreResult<()> {
        for output in self.outputs_for_signal(signal)? {
            tx.send(output)
                .await
                .map_err(|_| CoreError::PipelineClosed)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct PeerFlowKey {
    host: Option<String>,
    protocol: e_navigator_signals::NetworkProtocol,
    address_family: NetworkAddressFamily,
    direction: e_navigator_signals::NetworkFlowDirection,
    source: NetworkPeerIdentity,
    destination: NetworkPeerIdentity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct OverflowKey {
    protocol: e_navigator_signals::NetworkProtocol,
    address_family: NetworkAddressFamily,
    direction: e_navigator_signals::NetworkFlowDirection,
}

impl PeerFlowKey {
    fn from_flow(flow: &NetworkFlowSummaryEvent, host: Option<String>) -> Option<Self> {
        if flow.bytes == 0 {
            return None;
        }
        Some(Self {
            host,
            protocol: flow.protocol,
            address_family: flow.address_family,
            direction: flow.direction,
            source: peer_identity(&flow.source)?,
            destination: peer_identity(&flow.destination)?,
        })
    }
}

fn peer_identity(endpoint: &NetworkFlowEndpoint) -> Option<NetworkPeerIdentity> {
    Some(NetworkPeerIdentity {
        namespace: endpoint.namespace.clone()?,
        owner_name: endpoint.owner_name.clone()?,
        owner_type: endpoint.owner_type.clone()?,
    })
}

#[derive(Debug)]
struct PeerFlowState {
    key: PeerFlowKey,
    value: u64,
    window: MetricAggregationWindow,
    overflow: bool,
}

impl PeerFlowState {
    fn observe(&mut self, flow: &NetworkFlowSummaryEvent) {
        self.value = self.value.saturating_add(flow.bytes);
        self.window.start_unix_nanos = self.window.start_unix_nanos.min(flow.first_seen_unix_nanos);
        self.window.end_unix_nanos = self.window.end_unix_nanos.max(flow.last_seen_unix_nanos);
    }

    fn to_signal(&self) -> SignalEnvelope {
        SignalEnvelope::network_peer_flow_metric(
            "generator.peer_flow_metrics",
            self.key.host.clone(),
            NetworkPeerFlowMetric {
                metric_name: "network.peer.flow.bytes".to_string(),
                unit: "By".to_string(),
                value: self.value,
                window: self.window.clone(),
                protocol: self.key.protocol,
                address_family: self.key.address_family,
                direction: self.key.direction,
                source: self.key.source.clone(),
                destination: self.key.destination.clone(),
                overflow: self.overflow,
            },
        )
    }
}

fn overflow_identity() -> NetworkPeerIdentity {
    NetworkPeerIdentity {
        namespace: "__other__".to_string(),
        owner_name: "__other__".to_string(),
        owner_type: "__other__".to_string(),
    }
}
