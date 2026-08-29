use e_navigator_core::{CoreError, CoreResult};
use e_navigator_signals::{
    CgroupResourceContext, MetricAggregationWindow, SignalEnvelope, SignalPayload,
};
use std::{collections::BTreeMap, sync::MutexGuard};

use crate::bounded_fingerprints::BoundedFingerprints;

use super::generator::ResourceMetricsGenerator;

impl ResourceMetricsGenerator {
    pub(super) fn mark_seen(&self, fingerprint: ObservationFingerprint) -> CoreResult<bool> {
        let mut seen = self.seen()?;
        Ok(seen.insert_if_new(fingerprint, self.max_keys.saturating_mul(4)))
    }

    pub(super) fn counters(&self) -> CoreResult<MutexGuard<'_, BTreeMap<StateKey, CounterState>>> {
        self.counters.lock().map_err(module_error)
    }

    pub(super) fn gauges(&self) -> CoreResult<MutexGuard<'_, BTreeMap<StateKey, i64>>> {
        self.gauges.lock().map_err(module_error)
    }

    pub(super) fn seen(
        &self,
    ) -> CoreResult<MutexGuard<'_, BoundedFingerprints<ObservationFingerprint>>> {
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

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct ObservationFingerprint {
    host: Option<String>,
    timestamp: u64,
    value: ObservationValue,
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
enum ObservationValue {
    NodeCpu {
        user_nanos: u64,
        system_nanos: u64,
        idle_nanos: u64,
        iowait_nanos: u64,
        steal_nanos: u64,
        runnable_tasks: u64,
        blocked_tasks: u64,
    },
    NodeLoad {
        formatted_loads: String,
    },
    NodeMemory {
        mem_total_bytes: u64,
        mem_available_bytes: Option<u64>,
        mem_free_bytes: Option<u64>,
        swap_total_bytes: Option<u64>,
        swap_free_bytes: Option<u64>,
    },
    NodeFilesystem {
        mount_point: String,
        total_bytes: u64,
        available_bytes: u64,
        filesystem_type: Option<String>,
    },
    NodeDiskIo {
        device: String,
        reads_completed: u64,
        writes_completed: u64,
        read_bytes: u64,
        written_bytes: u64,
    },
    Process {
        pid: u32,
        cpu_time_nanos: Option<u64>,
        memory_rss_bytes: Option<u64>,
        virtual_memory_bytes: Option<u64>,
        open_fds: Option<u64>,
        socket_count: Option<u64>,
        thread_count: Option<u64>,
    },
    CgroupCpu {
        cgroup_path: String,
        usage_nanos: Option<u64>,
        user_nanos: Option<u64>,
        system_nanos: Option<u64>,
        throttled_periods: Option<u64>,
        throttled_nanos: Option<u64>,
    },
    CgroupMemory {
        cgroup_path: String,
        current_bytes: Option<u64>,
        peak_bytes: Option<u64>,
        max_bytes: Option<u64>,
    },
    CgroupPids {
        cgroup_path: String,
        process_count: Option<u64>,
        thread_count: Option<u64>,
        max_processes: Option<u64>,
    },
    CgroupFileDescriptors {
        cgroup_path: String,
        open_fds: Option<u64>,
        socket_count: Option<u64>,
    },
}

impl ObservationFingerprint {
    pub(super) fn from_signal(signal: &SignalEnvelope) -> Option<Self> {
        match &signal.payload {
            SignalPayload::NodeCpuObservation(observation) => Some(Self::new(
                signal,
                observation.timestamp_unix_nanos,
                ObservationValue::NodeCpu {
                    user_nanos: observation.user_nanos,
                    system_nanos: observation.system_nanos,
                    idle_nanos: observation.idle_nanos,
                    iowait_nanos: observation.iowait_nanos,
                    steal_nanos: observation.steal_nanos,
                    runnable_tasks: observation.runnable_tasks.unwrap_or_default(),
                    blocked_tasks: observation.blocked_tasks.unwrap_or_default(),
                },
            )),
            SignalPayload::NodeLoadObservation(observation) => Some(Self::new(
                signal,
                observation.timestamp_unix_nanos,
                ObservationValue::NodeLoad {
                    formatted_loads: format!(
                        "{}:{}:{}",
                        observation.load1, observation.load5, observation.load15
                    ),
                },
            )),
            SignalPayload::NodeMemoryObservation(observation) => Some(Self::new(
                signal,
                observation.timestamp_unix_nanos,
                ObservationValue::NodeMemory {
                    mem_total_bytes: observation.mem_total_bytes,
                    mem_available_bytes: observation.mem_available_bytes,
                    mem_free_bytes: observation.mem_free_bytes,
                    swap_total_bytes: observation.swap_total_bytes,
                    swap_free_bytes: observation.swap_free_bytes,
                },
            )),
            SignalPayload::NodeFilesystemObservation(observation) => Some(Self::new(
                signal,
                observation.timestamp_unix_nanos,
                ObservationValue::NodeFilesystem {
                    mount_point: observation.mount_point.clone(),
                    total_bytes: observation.total_bytes,
                    available_bytes: observation.available_bytes,
                    filesystem_type: observation.filesystem_type.clone(),
                },
            )),
            SignalPayload::NodeDiskIoObservation(observation) => Some(Self::new(
                signal,
                observation.timestamp_unix_nanos,
                ObservationValue::NodeDiskIo {
                    device: observation.device.clone(),
                    reads_completed: observation.reads_completed,
                    writes_completed: observation.writes_completed,
                    read_bytes: observation.read_bytes,
                    written_bytes: observation.written_bytes,
                },
            )),
            SignalPayload::ProcessResourceObservation(observation) => Some(Self::new(
                signal,
                observation.timestamp_unix_nanos,
                ObservationValue::Process {
                    pid: observation.process.pid,
                    cpu_time_nanos: observation.cpu_time_nanos,
                    memory_rss_bytes: observation.memory_rss_bytes,
                    virtual_memory_bytes: observation.virtual_memory_bytes,
                    open_fds: observation.open_fds,
                    socket_count: observation.socket_count,
                    thread_count: observation.thread_count,
                },
            )),
            SignalPayload::CgroupCpuObservation(observation) => Some(Self::new(
                signal,
                observation.timestamp_unix_nanos,
                ObservationValue::CgroupCpu {
                    cgroup_path: observation.cgroup.cgroup_path.clone(),
                    usage_nanos: observation.usage_nanos,
                    user_nanos: observation.user_nanos,
                    system_nanos: observation.system_nanos,
                    throttled_periods: observation.throttled_periods,
                    throttled_nanos: observation.throttled_nanos,
                },
            )),
            SignalPayload::CgroupMemoryObservation(observation) => Some(Self::new(
                signal,
                observation.timestamp_unix_nanos,
                ObservationValue::CgroupMemory {
                    cgroup_path: observation.cgroup.cgroup_path.clone(),
                    current_bytes: observation.current_bytes,
                    peak_bytes: observation.peak_bytes,
                    max_bytes: observation.max_bytes,
                },
            )),
            SignalPayload::CgroupPidsObservation(observation) => Some(Self::new(
                signal,
                observation.timestamp_unix_nanos,
                ObservationValue::CgroupPids {
                    cgroup_path: observation.cgroup.cgroup_path.clone(),
                    process_count: observation.process_count,
                    thread_count: observation.thread_count,
                    max_processes: observation.max_processes,
                },
            )),
            SignalPayload::CgroupFileDescriptorObservation(observation) => Some(Self::new(
                signal,
                observation.timestamp_unix_nanos,
                ObservationValue::CgroupFileDescriptors {
                    cgroup_path: observation.cgroup.cgroup_path.clone(),
                    open_fds: observation.open_fds,
                    socket_count: observation.socket_count,
                },
            )),
            _ => None,
        }
    }

    fn new(signal: &SignalEnvelope, timestamp: u64, value: ObservationValue) -> Self {
        Self {
            host: signal.host.clone(),
            timestamp,
            value,
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
