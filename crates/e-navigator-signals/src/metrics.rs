use serde::{Deserialize, Serialize};

use crate::network::sanitize_network_process_identity;
use crate::{
    ContainerContext, KubernetesContext, NetworkAddressFamily, NetworkProcessIdentity,
    NetworkProtocol,
};

const MAX_NETWORK_METRIC_STRING_BYTES: usize = 256;
const MAX_KUBERNETES_LABELS: usize = 16;
const MAX_KUBERNETES_LABEL_KEY_BYTES: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetricAggregationWindow {
    pub start_unix_nanos: u64,
    pub end_unix_nanos: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkCounterMetric {
    pub metric_name: String,
    pub unit: String,
    pub value: u64,
    pub window: MetricAggregationWindow,
    pub process: Option<NetworkProcessIdentity>,
    pub protocol: Option<NetworkProtocol>,
    pub address_family: Option<NetworkAddressFamily>,
    pub local_address: Option<String>,
    pub local_port: Option<u16>,
    pub remote_address: Option<String>,
    pub remote_port: Option<u16>,
    pub errno: Option<i32>,
    pub container: Option<ContainerContext>,
    pub kubernetes: Option<KubernetesContext>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkDurationMetric {
    pub metric_name: String,
    pub unit: String,
    pub count: u64,
    pub sum_nanos: u64,
    pub min_nanos: u64,
    pub max_nanos: u64,
    pub window: MetricAggregationWindow,
    pub process: Option<NetworkProcessIdentity>,
    pub protocol: Option<NetworkProtocol>,
    pub address_family: Option<NetworkAddressFamily>,
    pub remote_address: Option<String>,
    pub remote_port: Option<u16>,
    pub container: Option<ContainerContext>,
    pub kubernetes: Option<KubernetesContext>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkGaugeMetric {
    pub metric_name: String,
    pub unit: String,
    pub value: i64,
    pub window: MetricAggregationWindow,
    pub process: Option<NetworkProcessIdentity>,
    pub protocol: Option<NetworkProtocol>,
    pub address_family: Option<NetworkAddressFamily>,
    pub remote_address: Option<String>,
    pub remote_port: Option<u16>,
    pub container: Option<ContainerContext>,
    pub kubernetes: Option<KubernetesContext>,
}

pub(crate) fn sanitize_network_counter_metric(metric: &mut NetworkCounterMetric) {
    sanitize_network_metric_string(&mut metric.metric_name);
    sanitize_network_metric_string(&mut metric.unit);
    sanitize_optional_network_process_identity(&mut metric.process);
    sanitize_optional_network_metric_string(&mut metric.local_address);
    sanitize_optional_network_metric_string(&mut metric.remote_address);
    sanitize_optional_container_context(&mut metric.container);
    sanitize_optional_kubernetes_context(&mut metric.kubernetes);
}

pub(crate) fn sanitize_network_duration_metric(metric: &mut NetworkDurationMetric) {
    sanitize_network_metric_string(&mut metric.metric_name);
    sanitize_network_metric_string(&mut metric.unit);
    sanitize_optional_network_process_identity(&mut metric.process);
    sanitize_optional_network_metric_string(&mut metric.remote_address);
    sanitize_optional_container_context(&mut metric.container);
    sanitize_optional_kubernetes_context(&mut metric.kubernetes);
}

pub(crate) fn sanitize_network_gauge_metric(metric: &mut NetworkGaugeMetric) {
    sanitize_network_metric_string(&mut metric.metric_name);
    sanitize_network_metric_string(&mut metric.unit);
    sanitize_optional_network_process_identity(&mut metric.process);
    sanitize_optional_network_metric_string(&mut metric.remote_address);
    sanitize_optional_container_context(&mut metric.container);
    sanitize_optional_kubernetes_context(&mut metric.kubernetes);
}

fn sanitize_network_metric_string(value: &mut String) {
    *value = truncate_utf8(value, MAX_NETWORK_METRIC_STRING_BYTES);
}

fn sanitize_optional_network_metric_string(value: &mut Option<String>) {
    if let Some(inner) = value {
        sanitize_network_metric_string(inner);
    }
}

fn sanitize_optional_network_process_identity(process: &mut Option<NetworkProcessIdentity>) {
    if let Some(inner) = process {
        sanitize_network_process_identity(inner);
    }
}

fn sanitize_optional_container_context(context: &mut Option<ContainerContext>) {
    if let Some(inner) = context {
        sanitize_network_metric_string(&mut inner.container_id);
        sanitize_optional_network_metric_string(&mut inner.runtime);
    }
}

fn sanitize_optional_kubernetes_context(context: &mut Option<KubernetesContext>) {
    if let Some(inner) = context {
        sanitize_network_metric_string(&mut inner.namespace);
        sanitize_network_metric_string(&mut inner.pod_name);
        sanitize_optional_network_metric_string(&mut inner.pod_uid);
        sanitize_optional_network_metric_string(&mut inner.container_name);
        sanitize_optional_network_metric_string(&mut inner.node_name);
        inner.labels = inner
            .labels
            .iter()
            .filter(|(key, _)| !key.is_empty())
            .map(|(key, value)| {
                (
                    truncate_utf8(key, MAX_KUBERNETES_LABEL_KEY_BYTES),
                    truncate_utf8(value, MAX_NETWORK_METRIC_STRING_BYTES),
                )
            })
            .take(MAX_KUBERNETES_LABELS)
            .collect();
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
