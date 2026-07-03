use serde::{Deserialize, Serialize};

use crate::{ContainerContext, KubernetesContext, MetricAggregationWindow};

const MAX_RESOURCE_METRIC_ATTRIBUTES: usize = 16;
const MAX_RESOURCE_METRIC_ATTRIBUTE_KEY_BYTES: usize = 128;
const MAX_RESOURCE_METRIC_ATTRIBUTE_VALUE_BYTES: usize = 256;
const MAX_RESOURCE_SIGNAL_STRING_BYTES: usize = 256;

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

pub fn sanitize_resource_metric_attributes(attributes: &mut Vec<ResourceMetricAttribute>) {
    let sanitized = attributes
        .drain(..)
        .filter(|attribute| !attribute.key.is_empty())
        .map(|attribute| ResourceMetricAttribute {
            key: truncate_utf8(&attribute.key, MAX_RESOURCE_METRIC_ATTRIBUTE_KEY_BYTES),
            value: truncate_utf8(&attribute.value, MAX_RESOURCE_METRIC_ATTRIBUTE_VALUE_BYTES),
        })
        .take(MAX_RESOURCE_METRIC_ATTRIBUTES)
        .collect();
    *attributes = sanitized;
}

pub(crate) fn sanitize_node_cpu_observation(observation: &mut NodeCpuObservation) {
    sanitize_resource_signal_string(&mut observation.metric_name);
    sanitize_resource_signal_string(&mut observation.unit);
}

pub(crate) fn sanitize_node_load_observation(observation: &mut NodeLoadObservation) {
    sanitize_resource_signal_string(&mut observation.metric_name);
    sanitize_resource_signal_string(&mut observation.unit);
}

pub(crate) fn sanitize_node_memory_observation(observation: &mut NodeMemoryObservation) {
    sanitize_resource_signal_string(&mut observation.metric_name);
    sanitize_resource_signal_string(&mut observation.unit);
}

pub(crate) fn sanitize_node_filesystem_observation(observation: &mut NodeFilesystemObservation) {
    sanitize_resource_signal_string(&mut observation.metric_name);
    sanitize_resource_signal_string(&mut observation.unit);
    sanitize_resource_signal_string(&mut observation.mount_point);
    sanitize_optional_resource_signal_string(&mut observation.filesystem_type);
}

pub(crate) fn sanitize_node_disk_io_observation(observation: &mut NodeDiskIoObservation) {
    sanitize_resource_signal_string(&mut observation.metric_name);
    sanitize_resource_signal_string(&mut observation.unit);
    sanitize_resource_signal_string(&mut observation.device);
}

pub(crate) fn sanitize_process_resource_observation(observation: &mut ProcessResourceObservation) {
    sanitize_resource_signal_string(&mut observation.metric_name);
    sanitize_resource_signal_string(&mut observation.unit);
    sanitize_process_resource_context(&mut observation.process);
}

pub(crate) fn sanitize_process_resource_context(context: &mut ProcessResourceContext) {
    sanitize_resource_signal_string(&mut context.command);
    sanitize_optional_resource_signal_string(&mut context.executable);
}

fn sanitize_resource_signal_string(value: &mut String) {
    *value = truncate_utf8(value, MAX_RESOURCE_SIGNAL_STRING_BYTES);
}

fn sanitize_optional_resource_signal_string(value: &mut Option<String>) {
    if let Some(inner) = value {
        sanitize_resource_signal_string(inner);
    }
}

fn truncate_utf8(value: &str, max_bytes: usize) -> String {
    if value.len() <= max_bytes {
        return value.to_string();
    }

    let mut end = max_bytes;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_string()
}
