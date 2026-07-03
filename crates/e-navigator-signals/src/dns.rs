use serde::{Deserialize, Serialize};

use crate::{
    ContainerContext, KubernetesContext, MetricAggregationWindow, NetworkProcessIdentity,
    NetworkProtocol,
};

const MAX_DNS_SIGNAL_STRING_BYTES: usize = 256;

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
    sanitize_dns_string(&mut event.query_name);
    sanitize_optional_dns_string(&mut event.server_address);
}

pub(crate) fn sanitize_dns_response_event(event: &mut DnsResponseEvent) {
    sanitize_dns_string(&mut event.query_name);
    sanitize_optional_dns_string(&mut event.server_address);
}

pub(crate) fn sanitize_dns_counter_metric(metric: &mut DnsCounterMetric) {
    sanitize_dns_string(&mut metric.metric_name);
    sanitize_dns_string(&mut metric.unit);
    sanitize_optional_dns_string(&mut metric.query_name);
    sanitize_optional_dns_string(&mut metric.server_address);
}

pub(crate) fn sanitize_dns_latency_metric(metric: &mut DnsLatencyMetric) {
    sanitize_dns_string(&mut metric.metric_name);
    sanitize_dns_string(&mut metric.unit);
    sanitize_optional_dns_string(&mut metric.query_name);
    sanitize_optional_dns_string(&mut metric.server_address);
}

fn sanitize_dns_string(value: &mut String) {
    *value = truncate_utf8(value, MAX_DNS_SIGNAL_STRING_BYTES);
}

fn sanitize_optional_dns_string(value: &mut Option<String>) {
    if let Some(inner) = value {
        sanitize_dns_string(inner);
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
