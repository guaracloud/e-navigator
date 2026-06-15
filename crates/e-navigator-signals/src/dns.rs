use serde::{Deserialize, Serialize};

use crate::{
    ContainerContext, KubernetesContext, MetricAggregationWindow, NetworkProcessIdentity,
    NetworkProtocol,
};

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
