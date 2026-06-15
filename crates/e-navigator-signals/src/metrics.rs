use serde::{Deserialize, Serialize};

use crate::{
    ContainerContext, KubernetesContext, NetworkAddressFamily, NetworkProcessIdentity,
    NetworkProtocol,
};

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
