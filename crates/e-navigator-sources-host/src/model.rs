use e_navigator_signals::{
    CgroupCpuObservation, CgroupFileDescriptorObservation, CgroupMemoryObservation,
    CgroupPidsObservation, CgroupResourceContext, MetricAggregationWindow, SignalEnvelope,
};

#[derive(Debug, Clone, Default, PartialEq)]
pub struct HostResourceSnapshot {
    pub signals: Vec<SignalEnvelope>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CgroupSample {
    pub path: String,
    pub cpu_stat: Option<String>,
    pub memory_current: Option<String>,
    pub memory_peak: Option<String>,
    pub memory_max: Option<String>,
    pub pids_current: Option<String>,
    pub pids_max: Option<String>,
    pub fd_count: Option<u64>,
    pub socket_count: Option<u64>,
}

impl CgroupSample {
    pub fn into_observations(
        self,
        host: Option<String>,
        start_unix_nanos: u64,
        end_unix_nanos: u64,
    ) -> Vec<SignalEnvelope> {
        let cgroup = CgroupResourceContext {
            cgroup_path: self.path,
            container: None,
            kubernetes: None,
        };
        let window = MetricAggregationWindow {
            start_unix_nanos,
            end_unix_nanos,
        };
        let mut signals = Vec::new();

        if let Some(cpu_stat) = self.cpu_stat {
            signals.push(SignalEnvelope::cgroup_cpu_observation(
                "source.host_resource",
                host.clone(),
                CgroupCpuObservation {
                    metric_name: "container.cpu.time".to_string(),
                    unit: "ns".to_string(),
                    timestamp_unix_nanos: end_unix_nanos,
                    window: window.clone(),
                    cgroup: cgroup.clone(),
                    usage_nanos: cpu_stat_value(&cpu_stat, "usage_usec").map(micros_to_nanos),
                    user_nanos: cpu_stat_value(&cpu_stat, "user_usec").map(micros_to_nanos),
                    system_nanos: cpu_stat_value(&cpu_stat, "system_usec").map(micros_to_nanos),
                    throttled_periods: cpu_stat_value(&cpu_stat, "nr_throttled"),
                    throttled_nanos: cpu_stat_value(&cpu_stat, "throttled_usec")
                        .map(micros_to_nanos),
                },
            ));
        }

        if self.memory_current.is_some() || self.memory_peak.is_some() || self.memory_max.is_some()
        {
            signals.push(SignalEnvelope::cgroup_memory_observation(
                "source.host_resource",
                host.clone(),
                CgroupMemoryObservation {
                    metric_name: "container.memory.usage".to_string(),
                    unit: "By".to_string(),
                    timestamp_unix_nanos: end_unix_nanos,
                    window: window.clone(),
                    cgroup: cgroup.clone(),
                    current_bytes: self.memory_current.as_deref().and_then(parse_cgroup_limit),
                    peak_bytes: self.memory_peak.as_deref().and_then(parse_cgroup_limit),
                    max_bytes: self.memory_max.as_deref().and_then(parse_cgroup_limit),
                },
            ));
        }

        if self.pids_current.is_some() || self.pids_max.is_some() {
            signals.push(SignalEnvelope::cgroup_pids_observation(
                "source.host_resource",
                host.clone(),
                CgroupPidsObservation {
                    metric_name: "container.process.count".to_string(),
                    unit: "{process}".to_string(),
                    timestamp_unix_nanos: end_unix_nanos,
                    window: window.clone(),
                    cgroup: cgroup.clone(),
                    process_count: self.pids_current.as_deref().and_then(parse_cgroup_limit),
                    thread_count: None,
                    max_processes: self.pids_max.as_deref().and_then(parse_cgroup_limit),
                },
            ));
        }

        if self.fd_count.is_some() || self.socket_count.is_some() {
            signals.push(SignalEnvelope::cgroup_file_descriptor_observation(
                "source.host_resource",
                host,
                CgroupFileDescriptorObservation {
                    metric_name: "container.file_descriptor.count".to_string(),
                    unit: "{file_descriptor}".to_string(),
                    timestamp_unix_nanos: end_unix_nanos,
                    window,
                    cgroup,
                    open_fds: self.fd_count,
                    socket_count: self.socket_count,
                },
            ));
        }

        signals
    }
}

fn cpu_stat_value(contents: &str, key: &str) -> Option<u64> {
    contents.lines().find_map(|line| {
        let mut fields = line.split_whitespace();
        match (fields.next(), fields.next()) {
            (Some(found), Some(value)) if found == key => value.parse::<u64>().ok(),
            _ => None,
        }
    })
}

fn parse_cgroup_limit(contents: &str) -> Option<u64> {
    let value = contents.trim();
    if value == "max" {
        None
    } else {
        value.parse::<u64>().ok()
    }
}

fn micros_to_nanos(micros: u64) -> u64 {
    micros.saturating_mul(1_000)
}
