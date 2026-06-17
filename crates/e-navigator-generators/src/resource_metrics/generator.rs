use async_trait::async_trait;
use e_navigator_core::{CoreError, CoreResult, Generator, ModuleKind, ModuleMetadata};
use e_navigator_signals::{SignalEnvelope, SignalPayload};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Mutex,
};
use tokio::sync::mpsc;

use super::state::{CounterState, ObservationFingerprint, StateKey};

const DEFAULT_MAX_RESOURCE_KEYS: usize = 4096;

#[derive(Debug)]
pub struct ResourceMetricsGenerator {
    pub(super) max_keys: usize,
    pub(super) counters: Mutex<BTreeMap<StateKey, CounterState>>,
    pub(super) gauges: Mutex<BTreeMap<StateKey, i64>>,
    pub(super) seen: Mutex<BTreeSet<ObservationFingerprint>>,
}

impl Default for ResourceMetricsGenerator {
    fn default() -> Self {
        Self::with_limits(DEFAULT_MAX_RESOURCE_KEYS)
    }
}

impl ResourceMetricsGenerator {
    pub fn with_limits(max_keys: usize) -> Self {
        Self {
            max_keys,
            counters: Mutex::new(BTreeMap::new()),
            gauges: Mutex::new(BTreeMap::new()),
            seen: Mutex::new(BTreeSet::new()),
        }
    }
}

#[async_trait]
impl Generator<SignalEnvelope> for ResourceMetricsGenerator {
    fn metadata(&self) -> ModuleMetadata {
        ModuleMetadata::new("generator.resource_metrics", ModuleKind::Generator)
    }

    async fn observe(
        &self,
        signal: &SignalEnvelope,
        tx: &mpsc::Sender<SignalEnvelope>,
    ) -> CoreResult<()> {
        let Some(fingerprint) = ObservationFingerprint::from_signal(signal) else {
            return Ok(());
        };
        if !self.mark_seen(fingerprint)? {
            return Ok(());
        }

        let metrics = match &signal.payload {
            SignalPayload::NodeCpuObservation(observation) => {
                self.node_cpu_metrics(signal, observation)?
            }
            SignalPayload::NodeLoadObservation(observation) => {
                self.node_load_metrics(signal, observation)?
            }
            SignalPayload::NodeMemoryObservation(observation) => {
                self.node_memory_metrics(signal, observation)?
            }
            SignalPayload::NodeFilesystemObservation(observation) => {
                self.node_filesystem_metrics(signal, observation)?
            }
            SignalPayload::NodeDiskIoObservation(observation) => {
                self.node_disk_metrics(signal, observation)?
            }
            SignalPayload::ProcessResourceObservation(observation) => {
                self.process_metrics(signal, observation)?
            }
            SignalPayload::CgroupCpuObservation(observation) => {
                self.cgroup_cpu_metrics(signal, observation)?
            }
            SignalPayload::CgroupMemoryObservation(observation) => {
                self.cgroup_memory_metrics(signal, observation)?
            }
            SignalPayload::CgroupPidsObservation(observation) => {
                self.cgroup_pids_metrics(signal, observation)?
            }
            SignalPayload::CgroupFileDescriptorObservation(observation) => {
                self.cgroup_fd_metrics(signal, observation)?
            }
            _ => Vec::new(),
        };

        for metric in metrics {
            tx.send(metric)
                .await
                .map_err(|_| CoreError::PipelineClosed)?;
        }

        Ok(())
    }
}
