use async_trait::async_trait;
use e_navigator_core::{CoreError, CoreResult, Generator, ModuleKind, ModuleMetadata};
use e_navigator_signals::{
    CgroupCpuObservation, CgroupFileDescriptorObservation, CgroupMemoryObservation,
    CgroupPidsObservation, CgroupResourceContext, MetricAggregationWindow, NodeCpuObservation,
    NodeDiskIoObservation, NodeFilesystemObservation, NodeLoadObservation, NodeMemoryObservation,
    ProcessResourceContext, ProcessResourceObservation, ResourceContext, ResourceCounterMetric,
    ResourceGaugeMetric, ResourceMetricAttribute, SignalEnvelope, SignalPayload,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Mutex, MutexGuard},
};
use tokio::sync::mpsc;

const DEFAULT_MAX_RESOURCE_KEYS: usize = 4096;

#[derive(Debug)]
pub struct ResourceMetricsGenerator {
    max_keys: usize,
    counters: Mutex<BTreeMap<StateKey, u64>>,
    gauges: Mutex<BTreeMap<StateKey, i64>>,
    seen: Mutex<BTreeSet<ObservationFingerprint>>,
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

impl ResourceMetricsGenerator {
    fn node_cpu_metrics(
        &self,
        signal: &SignalEnvelope,
        observation: &NodeCpuObservation,
    ) -> CoreResult<Vec<SignalEnvelope>> {
        let mut metrics = Vec::new();
        let mut emitted_cpu_delta = false;
        for (state, value) in [
            ("user", observation.user_nanos),
            ("system", observation.system_nanos),
            ("idle", observation.idle_nanos),
            ("iowait", observation.iowait_nanos),
            ("steal", observation.steal_nanos),
        ] {
            if let Some(delta) =
                self.counter_delta(StateKey::node(signal, "system.cpu.time", state), value)?
            {
                emitted_cpu_delta = true;
                metrics.push(counter_metric(
                    signal,
                    "system.cpu.time",
                    "ns",
                    delta,
                    observation.window.clone(),
                    None,
                    None,
                    [("state", state)],
                ));
            }
        }
        if !emitted_cpu_delta {
            return Ok(metrics);
        }
        if let Some(value) = observation.runnable_tasks
            && let Some(metric) = self.update_gauge(
                StateKey::node(signal, "system.cpu.saturation.runnable", "runnable"),
                signal,
                "system.cpu.saturation.runnable",
                "{thread}",
                value as i64,
                observation.window.clone(),
                [("state", "runnable")],
            )?
        {
            metrics.push(metric);
        }
        if let Some(value) = observation.blocked_tasks
            && let Some(metric) = self.update_gauge(
                StateKey::node(signal, "system.cpu.saturation.blocked", "blocked"),
                signal,
                "system.cpu.saturation.blocked",
                "{thread}",
                value as i64,
                observation.window.clone(),
                [("state", "blocked")],
            )?
        {
            metrics.push(metric);
        }
        Ok(metrics)
    }

    fn node_load_metrics(
        &self,
        signal: &SignalEnvelope,
        observation: &NodeLoadObservation,
    ) -> CoreResult<Vec<SignalEnvelope>> {
        let mut metrics = Vec::new();
        for (name, state, value) in [
            ("system.cpu.load_average.1m", "1m", observation.load1),
            ("system.cpu.load_average.5m", "5m", observation.load5),
            ("system.cpu.load_average.15m", "15m", observation.load15),
        ] {
            if let Some(metric) = self.update_gauge(
                StateKey::node(signal, name, state),
                signal,
                name,
                "1",
                (value * 1000.0).round() as i64,
                observation.window.clone(),
                [("window", state)],
            )? {
                metrics.push(metric);
            }
        }
        Ok(metrics)
    }

    fn node_memory_metrics(
        &self,
        signal: &SignalEnvelope,
        observation: &NodeMemoryObservation,
    ) -> CoreResult<Vec<SignalEnvelope>> {
        let mut metrics = Vec::new();
        for (name, state, value) in [
            (
                "system.memory.limit",
                "total",
                Some(observation.mem_total_bytes),
            ),
            (
                "system.memory.available",
                "available",
                observation.mem_available_bytes,
            ),
            ("system.memory.free", "free", observation.mem_free_bytes),
            ("system.swap.limit", "total", observation.swap_total_bytes),
            ("system.swap.free", "free", observation.swap_free_bytes),
        ] {
            if let Some(value) = value
                && let Some(metric) = self.update_gauge(
                    StateKey::node(signal, name, state),
                    signal,
                    name,
                    "By",
                    saturating_i64(value),
                    observation.window.clone(),
                    [("state", state)],
                )?
            {
                metrics.push(metric);
            }
        }
        Ok(metrics)
    }

    fn node_filesystem_metrics(
        &self,
        signal: &SignalEnvelope,
        observation: &NodeFilesystemObservation,
    ) -> CoreResult<Vec<SignalEnvelope>> {
        let used = observation
            .total_bytes
            .saturating_sub(observation.available_bytes);
        let mut metrics = Vec::new();
        for (name, state, value) in [
            ("system.filesystem.usage", "used", used),
            (
                "system.filesystem.available",
                "available",
                observation.available_bytes,
            ),
            ("system.filesystem.limit", "total", observation.total_bytes),
        ] {
            if let Some(metric) = self.update_gauge(
                StateKey::scoped(signal, name, state, &observation.mount_point),
                signal,
                name,
                "By",
                saturating_i64(value),
                observation.window.clone(),
                [
                    ("state", state),
                    ("mountpoint", observation.mount_point.as_str()),
                    (
                        "filesystem.type",
                        observation.filesystem_type.as_deref().unwrap_or("unknown"),
                    ),
                ],
            )? {
                metrics.push(metric);
            }
        }
        Ok(metrics)
    }

    fn node_disk_metrics(
        &self,
        signal: &SignalEnvelope,
        observation: &NodeDiskIoObservation,
    ) -> CoreResult<Vec<SignalEnvelope>> {
        let mut metrics = Vec::new();
        for (name, state, value) in [
            ("system.disk.io", "read", observation.read_bytes),
            ("system.disk.io", "write", observation.written_bytes),
            (
                "system.disk.operations",
                "read",
                observation.reads_completed,
            ),
            (
                "system.disk.operations",
                "write",
                observation.writes_completed,
            ),
        ] {
            if let Some(delta) = self.counter_delta(
                StateKey::scoped(signal, name, state, &observation.device),
                value,
            )? {
                metrics.push(counter_metric(
                    signal,
                    name,
                    if name == "system.disk.io" {
                        "By"
                    } else {
                        "{operation}"
                    },
                    delta,
                    observation.window.clone(),
                    None,
                    None,
                    [("state", state), ("device", observation.device.as_str())],
                ));
            }
        }
        Ok(metrics)
    }

    fn process_metrics(
        &self,
        signal: &SignalEnvelope,
        observation: &ProcessResourceObservation,
    ) -> CoreResult<Vec<SignalEnvelope>> {
        let mut metrics = Vec::new();
        for (name, state, unit, value) in [
            (
                "process.memory.usage",
                "rss",
                "By",
                observation.memory_rss_bytes,
            ),
            (
                "process.memory.virtual",
                "virtual",
                "By",
                observation.virtual_memory_bytes,
            ),
            (
                "process.open_file_descriptor.count",
                "open",
                "{file_descriptor}",
                observation.open_fds,
            ),
            (
                "process.socket.count",
                "open",
                "{socket}",
                observation.socket_count,
            ),
            (
                "process.thread.count",
                "current",
                "{thread}",
                observation.thread_count,
            ),
        ] {
            if let Some(value) = value
                && let Some(metric) = self.update_process_gauge(
                    StateKey::process(signal, name, state, observation.process.pid),
                    signal,
                    name,
                    unit,
                    saturating_i64(value),
                    observation.window.clone(),
                    observation.process.clone(),
                    [("state", state)],
                )?
            {
                metrics.push(metric);
            }
        }
        Ok(metrics)
    }

    fn cgroup_cpu_metrics(
        &self,
        signal: &SignalEnvelope,
        observation: &CgroupCpuObservation,
    ) -> CoreResult<Vec<SignalEnvelope>> {
        let mut metrics = Vec::new();
        for (state, value) in [
            ("total", observation.usage_nanos),
            ("user", observation.user_nanos),
            ("system", observation.system_nanos),
            ("throttled", observation.throttled_nanos),
        ] {
            if let Some(value) = value
                && let Some(delta) = self.counter_delta(
                    StateKey::cgroup(signal, "container.cpu.time", state, &observation.cgroup),
                    value,
                )?
            {
                metrics.push(counter_metric(
                    signal,
                    "container.cpu.time",
                    "ns",
                    delta,
                    observation.window.clone(),
                    None,
                    Some(observation.cgroup.clone()),
                    [("state", state)],
                ));
            }
        }
        Ok(metrics)
    }

    fn cgroup_memory_metrics(
        &self,
        signal: &SignalEnvelope,
        observation: &CgroupMemoryObservation,
    ) -> CoreResult<Vec<SignalEnvelope>> {
        let mut metrics = Vec::new();
        for (name, state, value) in [
            (
                "container.memory.usage",
                "current",
                observation.current_bytes,
            ),
            ("container.memory.peak", "peak", observation.peak_bytes),
            ("container.memory.limit", "limit", observation.max_bytes),
        ] {
            if let Some(value) = value
                && let Some(metric) = self.update_cgroup_gauge(
                    StateKey::cgroup(signal, name, state, &observation.cgroup),
                    signal,
                    name,
                    "By",
                    saturating_i64(value),
                    observation.window.clone(),
                    observation.cgroup.clone(),
                    [("state", state)],
                )?
            {
                metrics.push(metric);
            }
        }
        Ok(metrics)
    }

    fn cgroup_pids_metrics(
        &self,
        signal: &SignalEnvelope,
        observation: &CgroupPidsObservation,
    ) -> CoreResult<Vec<SignalEnvelope>> {
        let mut metrics = Vec::new();
        for (name, state, unit, value) in [
            (
                "container.process.count",
                "current",
                "{process}",
                observation.process_count,
            ),
            (
                "container.thread.count",
                "current",
                "{thread}",
                observation.thread_count,
            ),
            (
                "container.process.limit",
                "limit",
                "{process}",
                observation.max_processes,
            ),
        ] {
            if let Some(value) = value
                && let Some(metric) = self.update_cgroup_gauge(
                    StateKey::cgroup(signal, name, state, &observation.cgroup),
                    signal,
                    name,
                    unit,
                    saturating_i64(value),
                    observation.window.clone(),
                    observation.cgroup.clone(),
                    [("state", state)],
                )?
            {
                metrics.push(metric);
            }
        }
        Ok(metrics)
    }

    fn cgroup_fd_metrics(
        &self,
        signal: &SignalEnvelope,
        observation: &CgroupFileDescriptorObservation,
    ) -> CoreResult<Vec<SignalEnvelope>> {
        let mut metrics = Vec::new();
        for (name, state, unit, value) in [
            (
                "container.file_descriptor.count",
                "open",
                "{file_descriptor}",
                observation.open_fds,
            ),
            (
                "container.socket.count",
                "open",
                "{socket}",
                observation.socket_count,
            ),
        ] {
            if let Some(value) = value
                && let Some(metric) = self.update_cgroup_gauge(
                    StateKey::cgroup(signal, name, state, &observation.cgroup),
                    signal,
                    name,
                    unit,
                    saturating_i64(value),
                    observation.window.clone(),
                    observation.cgroup.clone(),
                    [("state", state)],
                )?
            {
                metrics.push(metric);
            }
        }
        Ok(metrics)
    }

    fn counter_delta(&self, key: StateKey, value: u64) -> CoreResult<Option<u64>> {
        let gauge_len = self.gauge_len()?;
        let mut counters = self.counters()?;
        if let Some(previous) = counters.get_mut(&key) {
            if value == *previous {
                return Ok(None);
            }
            let delta = value.saturating_sub(*previous);
            *previous = value;
            return Ok((delta > 0).then_some(delta));
        }
        if counters.len().saturating_add(gauge_len) >= self.max_keys {
            return Ok(None);
        }
        counters.insert(key, value);
        Ok(None)
    }

    #[allow(clippy::too_many_arguments)]
    fn update_gauge<'a, const N: usize>(
        &self,
        key: StateKey,
        signal: &SignalEnvelope,
        name: &str,
        unit: &str,
        value: i64,
        window: MetricAggregationWindow,
        attributes: [(&'a str, &'a str); N],
    ) -> CoreResult<Option<SignalEnvelope>> {
        self.update_metric_gauge(
            key, signal, name, unit, value, window, None, None, attributes,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn update_process_gauge<'a, const N: usize>(
        &self,
        key: StateKey,
        signal: &SignalEnvelope,
        name: &str,
        unit: &str,
        value: i64,
        window: MetricAggregationWindow,
        process: ProcessResourceContext,
        attributes: [(&'a str, &'a str); N],
    ) -> CoreResult<Option<SignalEnvelope>> {
        self.update_metric_gauge(
            key,
            signal,
            name,
            unit,
            value,
            window,
            Some(process),
            None,
            attributes,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn update_cgroup_gauge<'a, const N: usize>(
        &self,
        key: StateKey,
        signal: &SignalEnvelope,
        name: &str,
        unit: &str,
        value: i64,
        window: MetricAggregationWindow,
        cgroup: CgroupResourceContext,
        attributes: [(&'a str, &'a str); N],
    ) -> CoreResult<Option<SignalEnvelope>> {
        self.update_metric_gauge(
            key,
            signal,
            name,
            unit,
            value,
            window,
            None,
            Some(cgroup),
            attributes,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn update_metric_gauge<'a, const N: usize>(
        &self,
        key: StateKey,
        signal: &SignalEnvelope,
        name: &str,
        unit: &str,
        value: i64,
        window: MetricAggregationWindow,
        process: Option<ProcessResourceContext>,
        cgroup: Option<CgroupResourceContext>,
        attributes: [(&'a str, &'a str); N],
    ) -> CoreResult<Option<SignalEnvelope>> {
        let counter_len = self.counter_len()?;
        let mut gauges = self.gauges()?;
        if let Some(previous) = gauges.get_mut(&key) {
            if *previous == value {
                return Ok(None);
            }
            *previous = value;
        } else {
            if gauges.len().saturating_add(counter_len) >= self.max_keys {
                return Ok(None);
            }
            gauges.insert(key, value);
        }
        Ok(Some(gauge_metric(
            signal, name, unit, value, window, process, cgroup, attributes,
        )))
    }

    fn mark_seen(&self, fingerprint: ObservationFingerprint) -> CoreResult<bool> {
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

    fn counters(&self) -> CoreResult<MutexGuard<'_, BTreeMap<StateKey, u64>>> {
        self.counters.lock().map_err(module_error)
    }

    fn gauges(&self) -> CoreResult<MutexGuard<'_, BTreeMap<StateKey, i64>>> {
        self.gauges.lock().map_err(module_error)
    }

    fn seen(&self) -> CoreResult<MutexGuard<'_, BTreeSet<ObservationFingerprint>>> {
        self.seen.lock().map_err(module_error)
    }

    fn counter_len(&self) -> CoreResult<usize> {
        Ok(self.counters()?.len())
    }

    fn gauge_len(&self) -> CoreResult<usize> {
        Ok(self.gauges()?.len())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct StateKey {
    host: Option<String>,
    metric_name: String,
    state: String,
    scope: String,
}

impl StateKey {
    fn node(signal: &SignalEnvelope, metric_name: &str, state: &str) -> Self {
        Self::scoped(signal, metric_name, state, "")
    }

    fn scoped(signal: &SignalEnvelope, metric_name: &str, state: &str, scope: &str) -> Self {
        Self {
            host: signal.host.clone(),
            metric_name: metric_name.to_string(),
            state: state.to_string(),
            scope: scope.to_string(),
        }
    }

    fn process(signal: &SignalEnvelope, metric_name: &str, state: &str, pid: u32) -> Self {
        Self::scoped(signal, metric_name, state, &pid.to_string())
    }

    fn cgroup(
        signal: &SignalEnvelope,
        metric_name: &str,
        state: &str,
        cgroup: &CgroupResourceContext,
    ) -> Self {
        Self::scoped(signal, metric_name, state, &cgroup.cgroup_path)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct ObservationFingerprint {
    kind: &'static str,
    host: Option<String>,
    timestamp: u64,
    scope: String,
    value: String,
}

impl ObservationFingerprint {
    fn from_signal(signal: &SignalEnvelope) -> Option<Self> {
        match &signal.payload {
            SignalPayload::NodeCpuObservation(observation) => Some(Self {
                kind: "node_cpu_observation",
                host: signal.host.clone(),
                timestamp: observation.timestamp_unix_nanos,
                scope: String::new(),
                value: format!(
                    "{}:{}:{}:{}:{}",
                    observation.user_nanos,
                    observation.system_nanos,
                    observation.idle_nanos,
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
                    "{}:{:?}:{:?}",
                    observation.mem_total_bytes,
                    observation.mem_available_bytes,
                    observation.mem_free_bytes
                ),
            }),
            SignalPayload::NodeFilesystemObservation(observation) => Some(Self {
                kind: "node_filesystem_observation",
                host: signal.host.clone(),
                timestamp: observation.timestamp_unix_nanos,
                scope: observation.mount_point.clone(),
                value: format!(
                    "{}:{}",
                    observation.total_bytes, observation.available_bytes
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
                    "{:?}:{:?}:{:?}:{:?}",
                    observation.memory_rss_bytes,
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
                    "{:?}:{:?}:{:?}",
                    observation.usage_nanos, observation.user_nanos, observation.system_nanos
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

#[allow(clippy::too_many_arguments)]
fn gauge_metric<'a, const N: usize>(
    signal: &SignalEnvelope,
    name: &str,
    unit: &str,
    value: i64,
    window: MetricAggregationWindow,
    process: Option<ProcessResourceContext>,
    cgroup: Option<CgroupResourceContext>,
    attributes: [(&'a str, &'a str); N],
) -> SignalEnvelope {
    SignalEnvelope::resource_gauge_metric(
        "generator.resource_metrics",
        signal.host.clone(),
        ResourceGaugeMetric {
            metric_name: name.to_string(),
            unit: unit.to_string(),
            value,
            window,
            resource: resource_context(signal, process.as_ref(), cgroup.as_ref()),
            process,
            cgroup,
            attributes: metric_attributes(attributes),
        },
    )
}

#[allow(clippy::too_many_arguments)]
fn counter_metric<'a, const N: usize>(
    signal: &SignalEnvelope,
    name: &str,
    unit: &str,
    value: u64,
    window: MetricAggregationWindow,
    process: Option<ProcessResourceContext>,
    cgroup: Option<CgroupResourceContext>,
    attributes: [(&'a str, &'a str); N],
) -> SignalEnvelope {
    SignalEnvelope::resource_counter_metric(
        "generator.resource_metrics",
        signal.host.clone(),
        ResourceCounterMetric {
            metric_name: name.to_string(),
            unit: unit.to_string(),
            value,
            window,
            resource: resource_context(signal, process.as_ref(), cgroup.as_ref()),
            process,
            cgroup,
            attributes: metric_attributes(attributes),
        },
    )
}

fn resource_context(
    signal: &SignalEnvelope,
    process: Option<&ProcessResourceContext>,
    cgroup: Option<&CgroupResourceContext>,
) -> ResourceContext {
    let container = process
        .and_then(|process| process.container.clone())
        .or_else(|| cgroup.and_then(|cgroup| cgroup.container.clone()));
    let kubernetes = process
        .and_then(|process| process.kubernetes.clone())
        .or_else(|| cgroup.and_then(|cgroup| cgroup.kubernetes.clone()));
    ResourceContext {
        host_name: signal.host.clone(),
        container,
        kubernetes,
    }
}

fn metric_attributes<'a, const N: usize>(
    attributes: [(&'a str, &'a str); N],
) -> Vec<ResourceMetricAttribute> {
    attributes
        .into_iter()
        .map(|(key, value)| ResourceMetricAttribute {
            key: key.to_string(),
            value: value.to_string(),
        })
        .collect()
}

fn saturating_i64(value: u64) -> i64 {
    value.min(i64::MAX as u64) as i64
}

fn module_error<T>(_: std::sync::PoisonError<T>) -> CoreError {
    CoreError::ModuleFailed {
        module: "generator.resource_metrics".to_string(),
        message: "state lock poisoned".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use e_navigator_core::{Generator, Signal};
    use e_navigator_signals::{
        CgroupCpuObservation, CgroupMemoryObservation, CgroupResourceContext,
        MetricAggregationWindow, NodeCpuObservation, NodeFilesystemObservation,
        NodeMemoryObservation, ProcessResourceContext, ProcessResourceObservation,
        ResourceCounterMetric, ResourceGaugeMetric, SignalEnvelope, SignalPayload,
    };
    use tokio::sync::mpsc;

    use crate::ResourceMetricsGenerator;

    #[tokio::test]
    async fn handles_cpu_counter_deltas_and_saturation_gauges() {
        let generator = ResourceMetricsGenerator::with_limits(64);
        let first = node_cpu(1_000, 10, 5, 100);
        let second = node_cpu(2_000, 13, 7, 102);

        assert!(collect(&generator, &first).await.is_empty());
        let metrics = collect(&generator, &second).await;

        assert_metric_counter(&metrics, "system.cpu.time", "user", 30_000_000);
        assert_metric_counter(&metrics, "system.cpu.time", "system", 20_000_000);
        assert_metric_counter(&metrics, "system.cpu.time", "idle", 20_000_000);
        assert_metric_gauge(&metrics, "system.cpu.saturation.runnable", 3);
        assert_metric_gauge(&metrics, "system.cpu.saturation.blocked", 1);
    }

    #[tokio::test]
    async fn emits_memory_and_filesystem_gauges() {
        let generator = ResourceMetricsGenerator::with_limits(64);
        let memory = SignalEnvelope::node_memory_observation(
            "source.host_resource",
            Some("node-a".to_string()),
            NodeMemoryObservation {
                metric_name: "system.memory.usage".to_string(),
                unit: "By".to_string(),
                timestamp_unix_nanos: 2_000,
                window: window(1_000, 2_000),
                mem_total_bytes: 8_192,
                mem_available_bytes: Some(4_096),
                mem_free_bytes: Some(2_048),
                swap_total_bytes: Some(1_024),
                swap_free_bytes: Some(512),
            },
        );
        let filesystem = SignalEnvelope::node_filesystem_observation(
            "source.host_resource",
            Some("node-a".to_string()),
            NodeFilesystemObservation {
                metric_name: "system.filesystem.usage".to_string(),
                unit: "By".to_string(),
                timestamp_unix_nanos: 2_000,
                window: window(1_000, 2_000),
                mount_point: "/var/lib/kubelet".to_string(),
                filesystem_type: Some("ext4".to_string()),
                total_bytes: 1_000,
                available_bytes: 250,
            },
        );

        let mut metrics = collect(&generator, &memory).await;
        metrics.extend(collect(&generator, &filesystem).await);

        assert_metric_gauge(&metrics, "system.memory.limit", 8_192);
        assert_metric_gauge(&metrics, "system.memory.available", 4_096);
        assert_metric_gauge(&metrics, "system.filesystem.usage", 750);
        assert_metric_gauge(&metrics, "system.filesystem.available", 250);
    }

    #[tokio::test]
    async fn emits_cgroup_cpu_delta_and_memory_metrics_with_context() {
        let generator = ResourceMetricsGenerator::with_limits(64);
        let cgroup = CgroupResourceContext {
            cgroup_path: "/kubepods.slice/pod123/container.scope".to_string(),
            container: None,
            kubernetes: None,
        };
        let first = cgroup_cpu(cgroup.clone(), 1_000, 100);
        let second = cgroup_cpu(cgroup.clone(), 2_000, 160);
        let memory = SignalEnvelope::cgroup_memory_observation(
            "source.host_resource",
            Some("node-a".to_string()),
            CgroupMemoryObservation {
                metric_name: "container.memory.usage".to_string(),
                unit: "By".to_string(),
                timestamp_unix_nanos: 2_000,
                window: window(1_000, 2_000),
                cgroup,
                current_bytes: Some(12_000),
                peak_bytes: Some(18_000),
                max_bytes: Some(64_000),
            },
        );

        assert!(collect(&generator, &first).await.is_empty());
        let mut metrics = collect(&generator, &second).await;
        metrics.extend(collect(&generator, &memory).await);

        assert_metric_counter(&metrics, "container.cpu.time", "total", 60_000);
        assert_metric_gauge(&metrics, "container.memory.usage", 12_000);
        assert_metric_gauge(&metrics, "container.memory.limit", 64_000);
    }

    #[tokio::test]
    async fn preserves_process_attribution_and_handles_missing_context() {
        let generator = ResourceMetricsGenerator::with_limits(64);
        let signal = SignalEnvelope::process_resource_observation(
            "source.host_resource",
            Some("node-a".to_string()),
            ProcessResourceObservation {
                metric_name: "process.resource".to_string(),
                unit: "1".to_string(),
                timestamp_unix_nanos: 2_000,
                window: window(1_000, 2_000),
                process: ProcessResourceContext {
                    pid: 42,
                    ppid: Some(1),
                    uid: Some(1000),
                    command: "api".to_string(),
                    executable: Some("/app/api".to_string()),
                    container: Some(e_navigator_signals::ContainerContext {
                        container_id: "container-a".to_string(),
                        runtime: Some("containerd".to_string()),
                    }),
                    kubernetes: Some(e_navigator_signals::KubernetesContext {
                        namespace: "default".to_string(),
                        pod_name: "api-123".to_string(),
                        pod_uid: Some("pod-uid".to_string()),
                        container_name: Some("api".to_string()),
                        node_name: Some("node-a".to_string()),
                        labels: Default::default(),
                    }),
                },
                cpu_time_nanos: Some(500),
                memory_rss_bytes: Some(4_096),
                virtual_memory_bytes: None,
                open_fds: Some(12),
                socket_count: Some(2),
                thread_count: Some(4),
            },
        );

        let metrics = collect(&generator, &signal).await;

        let Some(resource_metric) = metrics.iter().find_map(resource_gauge) else {
            panic!("expected process gauge");
        };
        assert_eq!(
            resource_metric
                .process
                .as_ref()
                .and_then(|process| process.container.as_ref())
                .map(|container| container.container_id.as_str()),
            Some("container-a")
        );
        assert_metric_gauge(&metrics, "process.memory.usage", 4_096);
        assert_metric_gauge(&metrics, "process.open_file_descriptor.count", 12);
    }

    #[tokio::test]
    async fn deterministic_duplicate_and_bounded_state_behavior() {
        let generator = ResourceMetricsGenerator::with_limits(2);
        let memory_a = memory_signal("node-a", 2_000, 8_192, 4_096);
        let memory_b = memory_signal("node-b", 2_000, 16_384, 8_192);

        let first = collect(&generator, &memory_a).await;
        let duplicate = collect(&generator, &memory_a).await;
        let over_limit = collect(&generator, &memory_b).await;

        assert!(!first.is_empty());
        assert!(duplicate.is_empty());
        assert!(over_limit.is_empty());
        let names = first
            .iter()
            .map(|signal| signal.kind().to_string())
            .collect::<Vec<_>>();
        assert_eq!(
            names,
            vec!["resource_gauge_metric", "resource_gauge_metric"]
        );
    }

    async fn collect(
        generator: &ResourceMetricsGenerator,
        signal: &SignalEnvelope,
    ) -> Vec<SignalEnvelope> {
        let (tx, mut rx) = mpsc::channel(16);
        generator
            .observe(signal, &tx)
            .await
            .expect("generator observes");
        drop(tx);
        let mut signals = Vec::new();
        while let Some(signal) = rx.recv().await {
            signals.push(signal);
        }
        signals
    }

    fn node_cpu(timestamp: u64, user: u64, system: u64, idle: u64) -> SignalEnvelope {
        SignalEnvelope::node_cpu_observation(
            "source.host_resource",
            Some("node-a".to_string()),
            NodeCpuObservation {
                metric_name: "system.cpu.time".to_string(),
                unit: "ns".to_string(),
                timestamp_unix_nanos: timestamp,
                window: window(timestamp.saturating_sub(1_000), timestamp),
                user_nanos: user * 10_000_000,
                system_nanos: system * 10_000_000,
                idle_nanos: idle * 10_000_000,
                iowait_nanos: 0,
                steal_nanos: 0,
                runnable_tasks: Some(3),
                blocked_tasks: Some(1),
            },
        )
    }

    fn cgroup_cpu(
        cgroup: CgroupResourceContext,
        timestamp: u64,
        usage_micros: u64,
    ) -> SignalEnvelope {
        SignalEnvelope::cgroup_cpu_observation(
            "source.host_resource",
            Some("node-a".to_string()),
            CgroupCpuObservation {
                metric_name: "container.cpu.time".to_string(),
                unit: "ns".to_string(),
                timestamp_unix_nanos: timestamp,
                window: window(timestamp.saturating_sub(1_000), timestamp),
                cgroup,
                usage_nanos: Some(usage_micros * 1_000),
                user_nanos: None,
                system_nanos: None,
                throttled_periods: None,
                throttled_nanos: None,
            },
        )
    }

    fn memory_signal(host: &str, timestamp: u64, total: u64, available: u64) -> SignalEnvelope {
        SignalEnvelope::node_memory_observation(
            "source.host_resource",
            Some(host.to_string()),
            NodeMemoryObservation {
                metric_name: "system.memory.usage".to_string(),
                unit: "By".to_string(),
                timestamp_unix_nanos: timestamp,
                window: window(timestamp.saturating_sub(1_000), timestamp),
                mem_total_bytes: total,
                mem_available_bytes: Some(available),
                mem_free_bytes: None,
                swap_total_bytes: None,
                swap_free_bytes: None,
            },
        )
    }

    fn window(start_unix_nanos: u64, end_unix_nanos: u64) -> MetricAggregationWindow {
        MetricAggregationWindow {
            start_unix_nanos,
            end_unix_nanos,
        }
    }

    fn assert_metric_gauge(signals: &[SignalEnvelope], name: &str, value: i64) {
        assert!(
            signals.iter().any(|signal| {
                resource_gauge(signal)
                    .map(|metric| metric.metric_name == name && metric.value == value)
                    .unwrap_or(false)
            }),
            "missing gauge {name}={value}: {signals:#?}"
        );
    }

    fn assert_metric_counter(signals: &[SignalEnvelope], name: &str, state: &str, value: u64) {
        assert!(
            signals.iter().any(|signal| {
                resource_counter(signal)
                    .map(|metric| {
                        metric.metric_name == name
                            && metric.value == value
                            && metric.attributes.iter().any(|attribute| {
                                attribute.key == "state" && attribute.value == state
                            })
                    })
                    .unwrap_or(false)
            }),
            "missing counter {name}[state={state}]={value}: {signals:#?}"
        );
    }

    fn resource_gauge(signal: &SignalEnvelope) -> Option<&ResourceGaugeMetric> {
        match &signal.payload {
            SignalPayload::ResourceGaugeMetric(metric) => Some(metric),
            _ => None,
        }
    }

    fn resource_counter(signal: &SignalEnvelope) -> Option<&ResourceCounterMetric> {
        match &signal.payload {
            SignalPayload::ResourceCounterMetric(metric) => Some(metric),
            _ => None,
        }
    }
}
