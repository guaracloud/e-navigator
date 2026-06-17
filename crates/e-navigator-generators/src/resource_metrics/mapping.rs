use e_navigator_core::CoreResult;
use e_navigator_signals::{
    CgroupCpuObservation, CgroupFileDescriptorObservation, CgroupMemoryObservation,
    CgroupPidsObservation, NodeCpuObservation, NodeDiskIoObservation, NodeFilesystemObservation,
    NodeLoadObservation, NodeMemoryObservation, ProcessResourceObservation, SignalEnvelope,
};

use super::{
    counter::counter_metric, gauge::saturating_i64, generator::ResourceMetricsGenerator,
    state::StateKey,
};

impl ResourceMetricsGenerator {
    pub(super) fn node_cpu_metrics(
        &self,
        signal: &SignalEnvelope,
        observation: &NodeCpuObservation,
    ) -> CoreResult<Vec<SignalEnvelope>> {
        let mut metrics = Vec::new();
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
        for (state, value) in [
            ("user", observation.user_nanos),
            ("system", observation.system_nanos),
            ("idle", observation.idle_nanos),
            ("iowait", observation.iowait_nanos),
            ("steal", observation.steal_nanos),
        ] {
            if let Some(delta) = self.counter_delta(
                StateKey::node(signal, "system.cpu.time", state),
                value,
                observation.timestamp_unix_nanos,
            )? {
                metrics.push(counter_metric(
                    signal,
                    "system.cpu.time",
                    "ns",
                    delta.value,
                    delta.window,
                    None,
                    None,
                    [("state", state)],
                ));
            }
        }
        Ok(metrics)
    }

    pub(super) fn node_load_metrics(
        &self,
        signal: &SignalEnvelope,
        observation: &NodeLoadObservation,
    ) -> CoreResult<Vec<SignalEnvelope>> {
        let mut metrics = Vec::new();
        for (state, value) in [
            ("1m", observation.load1),
            ("5m", observation.load5),
            ("15m", observation.load15),
        ] {
            if let Some(metric) = self.update_gauge(
                StateKey::node(signal, "system.cpu.load_average.milli", state),
                signal,
                "system.cpu.load_average.milli",
                "m1",
                (value * 1000.0).round() as i64,
                observation.window.clone(),
                [("window", state)],
            )? {
                metrics.push(metric);
            }
        }
        Ok(metrics)
    }

    pub(super) fn node_memory_metrics(
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

    pub(super) fn node_filesystem_metrics(
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

    pub(super) fn node_disk_metrics(
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
                observation.timestamp_unix_nanos,
            )? {
                metrics.push(counter_metric(
                    signal,
                    name,
                    if name == "system.disk.io" {
                        "By"
                    } else {
                        "{operation}"
                    },
                    delta.value,
                    delta.window,
                    None,
                    None,
                    [("state", state), ("device", observation.device.as_str())],
                ));
            }
        }
        Ok(metrics)
    }

    pub(super) fn process_metrics(
        &self,
        signal: &SignalEnvelope,
        observation: &ProcessResourceObservation,
    ) -> CoreResult<Vec<SignalEnvelope>> {
        let mut metrics = Vec::new();
        if let Some(value) = observation.cpu_time_nanos
            && let Some(delta) = self.counter_delta(
                StateKey::process(signal, "process.cpu.time", "total", observation.process.pid),
                value,
                observation.timestamp_unix_nanos,
            )?
        {
            metrics.push(counter_metric(
                signal,
                "process.cpu.time",
                "ns",
                delta.value,
                delta.window,
                Some(observation.process.clone()),
                None,
                [("state", "total")],
            ));
        }
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

    pub(super) fn cgroup_cpu_metrics(
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
                    observation.timestamp_unix_nanos,
                )?
            {
                metrics.push(counter_metric(
                    signal,
                    "container.cpu.time",
                    "ns",
                    delta.value,
                    delta.window,
                    None,
                    Some(observation.cgroup.clone()),
                    [("state", state)],
                ));
            }
        }
        if let Some(value) = observation.throttled_periods
            && let Some(delta) = self.counter_delta(
                StateKey::cgroup(
                    signal,
                    "container.cpu.throttling.periods",
                    "throttled",
                    &observation.cgroup,
                ),
                value,
                observation.timestamp_unix_nanos,
            )?
        {
            metrics.push(counter_metric(
                signal,
                "container.cpu.throttling.periods",
                "{period}",
                delta.value,
                delta.window,
                None,
                Some(observation.cgroup.clone()),
                [("state", "throttled")],
            ));
        }
        Ok(metrics)
    }

    pub(super) fn cgroup_memory_metrics(
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

    pub(super) fn cgroup_pids_metrics(
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

    pub(super) fn cgroup_fd_metrics(
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
}
