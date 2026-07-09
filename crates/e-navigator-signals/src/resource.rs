use serde::{Deserialize, Serialize};

use crate::sanitize::{sanitize_kubernetes_labels, truncate_utf8_in_place};

use crate::{ContainerContext, KubernetesContext, MetricAggregationWindow};

const MAX_RESOURCE_METRIC_ATTRIBUTES: usize = 16;
const MAX_RESOURCE_METRIC_ATTRIBUTE_KEY_BYTES: usize = 128;
const MAX_RESOURCE_METRIC_ATTRIBUTE_VALUE_BYTES: usize = 256;
const MAX_RESOURCE_SIGNAL_STRING_BYTES: usize = 256;
const MAX_KUBERNETES_LABELS: usize = 16;
const MAX_KUBERNETES_LABEL_KEY_BYTES: usize = 128;

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
    attributes.retain(|attribute| {
        !attribute.key.is_empty() && !is_sensitive_resource_metric_attribute_key(&attribute.key)
    });
    attributes.truncate(MAX_RESOURCE_METRIC_ATTRIBUTES);
    for attribute in attributes {
        truncate_utf8_in_place(&mut attribute.key, MAX_RESOURCE_METRIC_ATTRIBUTE_KEY_BYTES);
        truncate_utf8_in_place(
            &mut attribute.value,
            MAX_RESOURCE_METRIC_ATTRIBUTE_VALUE_BYTES,
        );
    }
}

fn is_sensitive_resource_metric_attribute_key(key: &str) -> bool {
    const AUTH_FRAGMENT: &str = concat!("au", "th");
    const SENSITIVE_FRAGMENTS: &[&str] = &[
        "authorization",
        AUTH_FRAGMENT,
        "token",
        "password",
        "passwd",
        "secret",
        "credential",
        "api_key",
        "api-key",
        "apikey",
        "api-token",
        "cookie",
        "private_key",
        "jwt",
    ];

    SENSITIVE_FRAGMENTS
        .iter()
        .any(|sensitive| contains_ascii_case_insensitive(key, sensitive))
}

fn contains_ascii_case_insensitive(haystack: &str, needle: &str) -> bool {
    haystack
        .as_bytes()
        .windows(needle.len())
        .any(|window| window.eq_ignore_ascii_case(needle.as_bytes()))
}

pub(crate) fn sanitize_resource_gauge_metric(metric: &mut ResourceGaugeMetric) {
    sanitize_resource_signal_string(&mut metric.metric_name);
    sanitize_resource_signal_string(&mut metric.unit);
    sanitize_resource_context(&mut metric.resource);
    sanitize_optional_process_resource_context(&mut metric.process);
    sanitize_optional_cgroup_resource_context(&mut metric.cgroup);
    sanitize_resource_metric_attributes(&mut metric.attributes);
}

pub(crate) fn sanitize_resource_counter_metric(metric: &mut ResourceCounterMetric) {
    sanitize_resource_signal_string(&mut metric.metric_name);
    sanitize_resource_signal_string(&mut metric.unit);
    sanitize_resource_context(&mut metric.resource);
    sanitize_optional_process_resource_context(&mut metric.process);
    sanitize_optional_cgroup_resource_context(&mut metric.cgroup);
    sanitize_resource_metric_attributes(&mut metric.attributes);
}

fn sanitize_resource_context(context: &mut ResourceContext) {
    sanitize_optional_resource_signal_string(&mut context.host_name);
    sanitize_optional_resource_container_context(&mut context.container);
    sanitize_optional_resource_kubernetes_context(&mut context.kubernetes);
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
    sanitize_optional_resource_container_context(&mut context.container);
    sanitize_optional_resource_kubernetes_context(&mut context.kubernetes);
}

fn sanitize_optional_process_resource_context(context: &mut Option<ProcessResourceContext>) {
    if let Some(inner) = context {
        sanitize_process_resource_context(inner);
    }
}

pub(crate) fn sanitize_cgroup_cpu_observation(observation: &mut CgroupCpuObservation) {
    sanitize_resource_signal_string(&mut observation.metric_name);
    sanitize_resource_signal_string(&mut observation.unit);
    sanitize_cgroup_resource_context(&mut observation.cgroup);
}

pub(crate) fn sanitize_cgroup_memory_observation(observation: &mut CgroupMemoryObservation) {
    sanitize_resource_signal_string(&mut observation.metric_name);
    sanitize_resource_signal_string(&mut observation.unit);
    sanitize_cgroup_resource_context(&mut observation.cgroup);
}

pub(crate) fn sanitize_cgroup_pids_observation(observation: &mut CgroupPidsObservation) {
    sanitize_resource_signal_string(&mut observation.metric_name);
    sanitize_resource_signal_string(&mut observation.unit);
    sanitize_cgroup_resource_context(&mut observation.cgroup);
}

pub(crate) fn sanitize_cgroup_file_descriptor_observation(
    observation: &mut CgroupFileDescriptorObservation,
) {
    sanitize_resource_signal_string(&mut observation.metric_name);
    sanitize_resource_signal_string(&mut observation.unit);
    sanitize_cgroup_resource_context(&mut observation.cgroup);
}

pub(crate) fn sanitize_cgroup_resource_context(context: &mut CgroupResourceContext) {
    sanitize_resource_signal_string(&mut context.cgroup_path);
    sanitize_optional_resource_container_context(&mut context.container);
    sanitize_optional_resource_kubernetes_context(&mut context.kubernetes);
}

fn sanitize_optional_cgroup_resource_context(context: &mut Option<CgroupResourceContext>) {
    if let Some(inner) = context {
        sanitize_cgroup_resource_context(inner);
    }
}

fn sanitize_optional_resource_container_context(context: &mut Option<ContainerContext>) {
    if let Some(inner) = context {
        sanitize_resource_signal_string(&mut inner.container_id);
        sanitize_optional_resource_signal_string(&mut inner.runtime);
    }
}

fn sanitize_optional_resource_kubernetes_context(context: &mut Option<KubernetesContext>) {
    if let Some(inner) = context {
        sanitize_resource_signal_string(&mut inner.namespace);
        sanitize_resource_signal_string(&mut inner.pod_name);
        sanitize_optional_resource_signal_string(&mut inner.pod_uid);
        sanitize_optional_resource_signal_string(&mut inner.container_name);
        sanitize_optional_resource_signal_string(&mut inner.node_name);
        sanitize_kubernetes_labels(
            &mut inner.labels,
            MAX_KUBERNETES_LABELS,
            MAX_KUBERNETES_LABEL_KEY_BYTES,
            MAX_RESOURCE_SIGNAL_STRING_BYTES,
        );
    }
}

fn sanitize_resource_signal_string(value: &mut String) {
    truncate_utf8_in_place(value, MAX_RESOURCE_SIGNAL_STRING_BYTES);
}

fn sanitize_optional_resource_signal_string(value: &mut Option<String>) {
    if let Some(inner) = value {
        sanitize_resource_signal_string(inner);
    }
}
