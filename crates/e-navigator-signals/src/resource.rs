use serde::{Deserialize, Serialize};

use crate::{ContainerContext, KubernetesContext, MetricAggregationWindow};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceContext {
    pub host_name: Option<String>,
    pub container: Option<ContainerContext>,
    pub kubernetes: Option<KubernetesContext>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessResourceContext {
    pub pid: u32,
    pub ppid: Option<u32>,
    pub uid: Option<u32>,
    pub command: String,
    pub executable: Option<String>,
    pub container: Option<ContainerContext>,
    pub kubernetes: Option<KubernetesContext>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CgroupResourceContext {
    pub cgroup_path: String,
    pub container: Option<ContainerContext>,
    pub kubernetes: Option<KubernetesContext>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeCpuObservation {
    pub metric_name: String,
    pub unit: String,
    pub timestamp_unix_nanos: u64,
    pub window: MetricAggregationWindow,
    pub user_nanos: u64,
    pub system_nanos: u64,
    pub idle_nanos: u64,
    pub iowait_nanos: u64,
    pub steal_nanos: u64,
    pub runnable_tasks: Option<u64>,
    pub blocked_tasks: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NodeLoadObservation {
    pub metric_name: String,
    pub unit: String,
    pub timestamp_unix_nanos: u64,
    pub window: MetricAggregationWindow,
    pub load1: f64,
    pub load5: f64,
    pub load15: f64,
    pub runnable_tasks: Option<u64>,
    pub total_tasks: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeMemoryObservation {
    pub metric_name: String,
    pub unit: String,
    pub timestamp_unix_nanos: u64,
    pub window: MetricAggregationWindow,
    pub mem_total_bytes: u64,
    pub mem_available_bytes: Option<u64>,
    pub mem_free_bytes: Option<u64>,
    pub swap_total_bytes: Option<u64>,
    pub swap_free_bytes: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeFilesystemObservation {
    pub metric_name: String,
    pub unit: String,
    pub timestamp_unix_nanos: u64,
    pub window: MetricAggregationWindow,
    pub mount_point: String,
    pub filesystem_type: Option<String>,
    pub total_bytes: u64,
    pub available_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeDiskIoObservation {
    pub metric_name: String,
    pub unit: String,
    pub timestamp_unix_nanos: u64,
    pub window: MetricAggregationWindow,
    pub device: String,
    pub reads_completed: u64,
    pub writes_completed: u64,
    pub read_bytes: u64,
    pub written_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessResourceObservation {
    pub metric_name: String,
    pub unit: String,
    pub timestamp_unix_nanos: u64,
    pub window: MetricAggregationWindow,
    pub process: ProcessResourceContext,
    pub cpu_time_nanos: Option<u64>,
    pub memory_rss_bytes: Option<u64>,
    pub virtual_memory_bytes: Option<u64>,
    pub open_fds: Option<u64>,
    pub socket_count: Option<u64>,
    pub thread_count: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CgroupCpuObservation {
    pub metric_name: String,
    pub unit: String,
    pub timestamp_unix_nanos: u64,
    pub window: MetricAggregationWindow,
    pub cgroup: CgroupResourceContext,
    pub usage_nanos: Option<u64>,
    pub user_nanos: Option<u64>,
    pub system_nanos: Option<u64>,
    pub throttled_periods: Option<u64>,
    pub throttled_nanos: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CgroupMemoryObservation {
    pub metric_name: String,
    pub unit: String,
    pub timestamp_unix_nanos: u64,
    pub window: MetricAggregationWindow,
    pub cgroup: CgroupResourceContext,
    pub current_bytes: Option<u64>,
    pub peak_bytes: Option<u64>,
    pub max_bytes: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CgroupPidsObservation {
    pub metric_name: String,
    pub unit: String,
    pub timestamp_unix_nanos: u64,
    pub window: MetricAggregationWindow,
    pub cgroup: CgroupResourceContext,
    pub process_count: Option<u64>,
    pub thread_count: Option<u64>,
    pub max_processes: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CgroupFileDescriptorObservation {
    pub metric_name: String,
    pub unit: String,
    pub timestamp_unix_nanos: u64,
    pub window: MetricAggregationWindow,
    pub cgroup: CgroupResourceContext,
    pub open_fds: Option<u64>,
    pub socket_count: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceGaugeMetric {
    pub metric_name: String,
    pub unit: String,
    pub value: i64,
    pub window: MetricAggregationWindow,
    pub resource: ResourceContext,
    pub process: Option<ProcessResourceContext>,
    pub cgroup: Option<CgroupResourceContext>,
    pub attributes: Vec<ResourceMetricAttribute>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceCounterMetric {
    pub metric_name: String,
    pub unit: String,
    pub value: u64,
    pub window: MetricAggregationWindow,
    pub resource: ResourceContext,
    pub process: Option<ProcessResourceContext>,
    pub cgroup: Option<CgroupResourceContext>,
    pub attributes: Vec<ResourceMetricAttribute>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ResourceMetricAttribute {
    pub key: String,
    pub value: String,
}
