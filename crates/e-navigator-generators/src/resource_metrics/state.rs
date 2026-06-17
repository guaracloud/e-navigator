use e_navigator_core::{CoreError, CoreResult};
use e_navigator_signals::{
    CgroupResourceContext, MetricAggregationWindow, SignalEnvelope, SignalPayload,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::MutexGuard,
};

use super::generator::ResourceMetricsGenerator;

impl ResourceMetricsGenerator {
    pub(super) fn mark_seen(&self, fingerprint: ObservationFingerprint) -> CoreResult<bool> {
        let mut seen = self.seen()?;
        if seen.contains(&fingerprint) {
            return Ok(false);
        }
        if seen.len() >= self.max_keys.saturating_mul(4).max(1)
            && let Some(first) = seen.iter().next().cloned()
        {
            seen.remove(&first);
        }
        seen.insert(fingerprint);
        Ok(true)
    }

    pub(super) fn counters(&self) -> CoreResult<MutexGuard<'_, BTreeMap<StateKey, CounterState>>> {
        self.counters.lock().map_err(module_error)
    }

    pub(super) fn gauges(&self) -> CoreResult<MutexGuard<'_, BTreeMap<StateKey, i64>>> {
        self.gauges.lock().map_err(module_error)
    }

    pub(super) fn seen(&self) -> CoreResult<MutexGuard<'_, BTreeSet<ObservationFingerprint>>> {
        self.seen.lock().map_err(module_error)
    }

    pub(super) fn counter_len(&self) -> CoreResult<usize> {
        Ok(self.counters()?.len())
    }

    pub(super) fn gauge_len(&self) -> CoreResult<usize> {
        Ok(self.gauges()?.len())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct StateKey {
    host: Option<String>,
    metric_name: String,
    state: String,
    scope: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct CounterState {
    pub(super) value: u64,
    pub(super) timestamp_unix_nanos: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct CounterDelta {
    pub(super) value: u64,
    pub(super) window: MetricAggregationWindow,
}

impl StateKey {
    pub(super) fn node(signal: &SignalEnvelope, metric_name: &str, state: &str) -> Self {
        Self::scoped(signal, metric_name, state, "")
    }

    pub(super) fn scoped(
        signal: &SignalEnvelope,
        metric_name: &str,
        state: &str,
        scope: &str,
    ) -> Self {
        Self {
            host: signal.host.clone(),
            metric_name: metric_name.to_string(),
            state: state.to_string(),
            scope: scope.to_string(),
        }
    }

    pub(super) fn process(
        signal: &SignalEnvelope,
        metric_name: &str,
        state: &str,
        pid: u32,
    ) -> Self {
        Self::scoped(signal, metric_name, state, &pid.to_string())
    }

    pub(super) fn cgroup(
        signal: &SignalEnvelope,
        metric_name: &str,
        state: &str,
        cgroup: &CgroupResourceContext,
    ) -> Self {
        Self::scoped(signal, metric_name, state, &cgroup.cgroup_path)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct ObservationFingerprint {
    kind: &'static str,
    host: Option<String>,
    timestamp: u64,
    scope: String,
    value: String,
}

impl ObservationFingerprint {
    pub(super) fn from_signal(signal: &SignalEnvelope) -> Option<Self> {
        match &signal.payload {
            SignalPayload::NodeCpuObservation(observation) => Some(Self {
                kind: "node_cpu_observation",
                host: signal.host.clone(),
                timestamp: observation.timestamp_unix_nanos,
                scope: String::new(),
                value: format!(
                    "{}:{}:{}:{}:{}:{}:{}",
                    observation.user_nanos,
                    observation.system_nanos,
                    observation.idle_nanos,
                    observation.iowait_nanos,
                    observation.steal_nanos,
                    observation.runnable_tasks.unwrap_or_default(),
                    observation.blocked_tasks.unwrap_or_default()
                ),
            }),
            SignalPayload::NodeLoadObservation(observation) => Some(Self {
                kind: "node_load_observation",
                host: signal.host.clone(),
                timestamp: observation.timestamp_unix_nanos,
                scope: String::new(),
                value: format!(
                    "{}:{}:{}",
                    observation.load1, observation.load5, observation.load15
                ),
            }),
            SignalPayload::NodeMemoryObservation(observation) => Some(Self {
                kind: "node_memory_observation",
                host: signal.host.clone(),
                timestamp: observation.timestamp_unix_nanos,
                scope: String::new(),
                value: format!(
                    "{}:{:?}:{:?}:{:?}:{:?}",
                    observation.mem_total_bytes,
                    observation.mem_available_bytes,
                    observation.mem_free_bytes,
                    observation.swap_total_bytes,
                    observation.swap_free_bytes
                ),
            }),
            SignalPayload::NodeFilesystemObservation(observation) => Some(Self {
                kind: "node_filesystem_observation",
                host: signal.host.clone(),
                timestamp: observation.timestamp_unix_nanos,
                scope: observation.mount_point.clone(),
                value: format!(
                    "{}:{}:{:?}",
                    observation.total_bytes,
                    observation.available_bytes,
                    observation.filesystem_type
                ),
            }),
            SignalPayload::NodeDiskIoObservation(observation) => Some(Self {
                kind: "node_disk_io_observation",
                host: signal.host.clone(),
                timestamp: observation.timestamp_unix_nanos,
                scope: observation.device.clone(),
                value: format!(
                    "{}:{}:{}:{}",
                    observation.reads_completed,
                    observation.writes_completed,
                    observation.read_bytes,
                    observation.written_bytes
                ),
            }),
            SignalPayload::ProcessResourceObservation(observation) => Some(Self {
                kind: "process_resource_observation",
                host: signal.host.clone(),
                timestamp: observation.timestamp_unix_nanos,
                scope: observation.process.pid.to_string(),
                value: format!(
                    "{:?}:{:?}:{:?}:{:?}:{:?}:{:?}",
                    observation.cpu_time_nanos,
                    observation.memory_rss_bytes,
                    observation.virtual_memory_bytes,
                    observation.open_fds,
                    observation.socket_count,
                    observation.thread_count
                ),
            }),
            SignalPayload::CgroupCpuObservation(observation) => Some(Self {
                kind: "cgroup_cpu_observation",
                host: signal.host.clone(),
                timestamp: observation.timestamp_unix_nanos,
                scope: observation.cgroup.cgroup_path.clone(),
                value: format!(
                    "{:?}:{:?}:{:?}:{:?}:{:?}",
                    observation.usage_nanos,
                    observation.user_nanos,
                    observation.system_nanos,
                    observation.throttled_periods,
                    observation.throttled_nanos
                ),
            }),
            SignalPayload::CgroupMemoryObservation(observation) => Some(Self {
                kind: "cgroup_memory_observation",
                host: signal.host.clone(),
                timestamp: observation.timestamp_unix_nanos,
                scope: observation.cgroup.cgroup_path.clone(),
                value: format!(
                    "{:?}:{:?}:{:?}",
                    observation.current_bytes, observation.peak_bytes, observation.max_bytes
                ),
            }),
            SignalPayload::CgroupPidsObservation(observation) => Some(Self {
                kind: "cgroup_pids_observation",
                host: signal.host.clone(),
                timestamp: observation.timestamp_unix_nanos,
                scope: observation.cgroup.cgroup_path.clone(),
                value: format!(
                    "{:?}:{:?}:{:?}",
                    observation.process_count, observation.thread_count, observation.max_processes
                ),
            }),
            SignalPayload::CgroupFileDescriptorObservation(observation) => Some(Self {
                kind: "cgroup_file_descriptor_observation",
                host: signal.host.clone(),
                timestamp: observation.timestamp_unix_nanos,
                scope: observation.cgroup.cgroup_path.clone(),
                value: format!("{:?}:{:?}", observation.open_fds, observation.socket_count),
            }),
            _ => None,
        }
    }
}

pub(super) fn evict_first<V>(entries: &mut BTreeMap<StateKey, V>) {
    if let Some(first) = entries.keys().next().cloned() {
        entries.remove(&first);
    }
}

fn module_error<T>(_: std::sync::PoisonError<T>) -> CoreError {
    CoreError::ModuleFailed {
        module: "generator.resource_metrics".to_string(),
        message: "state lock poisoned".to_string(),
    }
}
