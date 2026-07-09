use serde::{Deserialize, Serialize};

use crate::sanitize::{sanitize_kubernetes_labels, truncate_utf8_in_place};

use crate::network::sanitize_network_process_identity;
use crate::{
    ContainerContext, KubernetesContext, MetricAggregationWindow, NetworkProcessIdentity,
    NetworkProtocol,
};

const MAX_DNS_SIGNAL_STRING_BYTES: usize = 256;
const MAX_KUBERNETES_LABELS: usize = 16;
const MAX_KUBERNETES_LABEL_KEY_BYTES: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsQueryEvent {
    pub process: NetworkProcessIdentity,
    pub query_name: String,
    pub query_type: DnsQueryType,
    pub transport_protocol: NetworkProtocol,
    pub server_address: Option<String>,
    pub server_port: Option<u16>,
    pub timestamp_unix_nanos: u64,
    pub container: Option<ContainerContext>,
    pub kubernetes: Option<KubernetesContext>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsResponseEvent {
    pub process: NetworkProcessIdentity,
    pub query_name: String,
    pub query_type: DnsQueryType,
    pub response_code: DnsResponseCode,
    pub latency_nanos: Option<u64>,
    pub transport_protocol: NetworkProtocol,
    pub server_address: Option<String>,
    pub server_port: Option<u16>,
    pub timestamp_unix_nanos: u64,
    pub container: Option<ContainerContext>,
    pub kubernetes: Option<KubernetesContext>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum DnsQueryType {
    A,
    Aaaa,
    Cname,
    Mx,
    Txt,
    Srv,
    Ptr,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum DnsResponseCode {
    NoError,
    NxDomain,
    ServFail,
    Refused,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsCounterMetric {
    pub metric_name: String,
    pub unit: String,
    pub value: u64,
    pub window: MetricAggregationWindow,
    pub query_name: Option<String>,
    pub query_type: Option<DnsQueryType>,
    pub response_code: Option<DnsResponseCode>,
    pub server_address: Option<String>,
    pub server_port: Option<u16>,
    pub container: Option<ContainerContext>,
    pub kubernetes: Option<KubernetesContext>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsLatencyMetric {
    pub metric_name: String,
    pub unit: String,
    pub count: u64,
    pub sum_nanos: u64,
    pub min_nanos: u64,
    pub max_nanos: u64,
    pub window: MetricAggregationWindow,
    pub query_name: Option<String>,
    pub query_type: Option<DnsQueryType>,
    pub response_code: Option<DnsResponseCode>,
    pub server_address: Option<String>,
    pub server_port: Option<u16>,
    pub container: Option<ContainerContext>,
    pub kubernetes: Option<KubernetesContext>,
}

pub(crate) fn sanitize_dns_query_event(event: &mut DnsQueryEvent) {
    sanitize_network_process_identity(&mut event.process);
    sanitize_dns_string(&mut event.query_name);
    sanitize_optional_dns_string(&mut event.server_address);
    sanitize_optional_container_context(&mut event.container);
    sanitize_optional_kubernetes_context(&mut event.kubernetes);
}

pub(crate) fn sanitize_dns_response_event(event: &mut DnsResponseEvent) {
    sanitize_network_process_identity(&mut event.process);
    sanitize_dns_string(&mut event.query_name);
    sanitize_optional_dns_string(&mut event.server_address);
    sanitize_optional_container_context(&mut event.container);
    sanitize_optional_kubernetes_context(&mut event.kubernetes);
}

pub(crate) fn sanitize_dns_counter_metric(metric: &mut DnsCounterMetric) {
    sanitize_dns_string(&mut metric.metric_name);
    sanitize_dns_string(&mut metric.unit);
    sanitize_optional_dns_string(&mut metric.query_name);
    sanitize_optional_dns_string(&mut metric.server_address);
    sanitize_optional_container_context(&mut metric.container);
    sanitize_optional_kubernetes_context(&mut metric.kubernetes);
}

pub(crate) fn sanitize_dns_latency_metric(metric: &mut DnsLatencyMetric) {
    sanitize_dns_string(&mut metric.metric_name);
    sanitize_dns_string(&mut metric.unit);
    sanitize_optional_dns_string(&mut metric.query_name);
    sanitize_optional_dns_string(&mut metric.server_address);
    sanitize_optional_container_context(&mut metric.container);
    sanitize_optional_kubernetes_context(&mut metric.kubernetes);
}

fn sanitize_dns_string(value: &mut String) {
    truncate_utf8_in_place(value, MAX_DNS_SIGNAL_STRING_BYTES);
}

fn sanitize_optional_dns_string(value: &mut Option<String>) {
    if let Some(inner) = value {
        sanitize_dns_string(inner);
    }
}

fn sanitize_optional_container_context(context: &mut Option<ContainerContext>) {
    if let Some(inner) = context {
        sanitize_dns_string(&mut inner.container_id);
        sanitize_optional_dns_string(&mut inner.runtime);
    }
}

fn sanitize_optional_kubernetes_context(context: &mut Option<KubernetesContext>) {
    if let Some(inner) = context {
        sanitize_dns_string(&mut inner.namespace);
        sanitize_dns_string(&mut inner.pod_name);
        sanitize_optional_dns_string(&mut inner.pod_uid);
        sanitize_optional_dns_string(&mut inner.container_name);
        sanitize_optional_dns_string(&mut inner.node_name);
        sanitize_kubernetes_labels(
            &mut inner.labels,
            MAX_KUBERNETES_LABELS,
            MAX_KUBERNETES_LABEL_KEY_BYTES,
            MAX_DNS_SIGNAL_STRING_BYTES,
        );
    }
}
