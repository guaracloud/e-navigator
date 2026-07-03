use serde::{Deserialize, Serialize};

use crate::{ContainerContext, KubernetesContext};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkConnectionOpenEvent {
    pub process: NetworkProcessIdentity,
    pub protocol: NetworkProtocol,
    pub address_family: NetworkAddressFamily,
    pub local_address: Option<String>,
    pub local_port: Option<u16>,
    pub remote_address: String,
    pub remote_port: u16,
    pub fd: Option<i32>,
    pub timestamp_unix_nanos: u64,
    pub container: Option<ContainerContext>,
    pub kubernetes: Option<KubernetesContext>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkConnectionCloseEvent {
    pub process: NetworkProcessIdentity,
    pub protocol: NetworkProtocol,
    pub address_family: NetworkAddressFamily,
    pub local_address: Option<String>,
    pub local_port: Option<u16>,
    pub remote_address: String,
    pub remote_port: u16,
    pub fd: Option<i32>,
    pub opened_at_unix_nanos: Option<u64>,
    pub closed_at_unix_nanos: u64,
    pub duration_nanos: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes_sent: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes_received: Option<u64>,
    pub container: Option<ContainerContext>,
    pub kubernetes: Option<KubernetesContext>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkConnectionFailureEvent {
    pub process: NetworkProcessIdentity,
    pub protocol: NetworkProtocol,
    pub address_family: NetworkAddressFamily,
    pub remote_address: String,
    pub remote_port: u16,
    pub fd: Option<i32>,
    pub errno: i32,
    pub timestamp_unix_nanos: u64,
    pub container: Option<ContainerContext>,
    pub kubernetes: Option<KubernetesContext>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DependencyEdgeEvent {
    pub source: DependencyEndpoint,
    pub destination: DependencyEndpoint,
    pub protocol: NetworkProtocol,
    pub observations: u64,
    pub first_seen_unix_nanos: u64,
    pub last_seen_unix_nanos: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkFlowSummaryEvent {
    pub source: NetworkFlowEndpoint,
    pub destination: NetworkFlowEndpoint,
    pub protocol: NetworkProtocol,
    pub address_family: NetworkAddressFamily,
    pub bytes: u64,
    pub packets: Option<u64>,
    pub direction: NetworkFlowDirection,
    pub first_seen_unix_nanos: u64,
    pub last_seen_unix_nanos: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkFlowWarning {
    pub warning_type: String,
    pub message: String,
    pub timestamp_unix_nanos: u64,
    pub source_signal_kind: String,
    pub source_module: String,
    pub protocol: NetworkProtocol,
    pub address_family: NetworkAddressFamily,
    pub remote_address: String,
    pub remote_port: u16,
    pub process: NetworkProcessIdentity,
    pub container: Option<ContainerContext>,
    pub kubernetes: Option<KubernetesContext>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkFlowEndpoint {
    pub address: Option<String>,
    pub port: Option<u16>,
    pub owner_name: Option<String>,
    pub owner_type: Option<String>,
    pub container: Option<ContainerContext>,
    pub kubernetes: Option<KubernetesContext>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum NetworkFlowDirection {
    Egress,
    Ingress,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkProcessIdentity {
    pub pid: u32,
    pub ppid: Option<u32>,
    pub uid: Option<u32>,
    pub command: String,
    pub executable: Option<String>,
    pub cgroup_id: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum NetworkProtocol {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum NetworkAddressFamily {
    Ipv4,
    Ipv6,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DependencyEndpoint {
    pub workload: Option<KubernetesContext>,
    pub container: Option<ContainerContext>,
    pub address: Option<String>,
    pub port: Option<u16>,
    pub domain: Option<String>,
}
