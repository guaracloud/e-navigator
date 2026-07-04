use serde::{Deserialize, Serialize};

use crate::{ContainerContext, KubernetesContext};

const MAX_NETWORK_SIGNAL_STRING_BYTES: usize = 256;
const MAX_KUBERNETES_LABELS: usize = 16;
const MAX_KUBERNETES_LABEL_KEY_BYTES: usize = 128;

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

/// Whether a captured TCP stat is a retransmit, reset, or state transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum NetworkTcpStatKind {
    Retransmit,
    Reset,
    StateTransition,
}

/// TCP connection state (subset of the kernel state machine).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum NetworkTcpState {
    Established,
    SynSent,
    SynRecv,
    FinWait1,
    FinWait2,
    TimeWait,
    Close,
    CloseWait,
    LastAck,
    Listen,
    Closing,
    NewSynRecv,
}

impl NetworkTcpState {
    /// Maps a kernel TCP state number (1..=12) to a typed state.
    pub fn from_kernel(state: i32) -> Option<Self> {
        match state {
            1 => Some(Self::Established),
            2 => Some(Self::SynSent),
            3 => Some(Self::SynRecv),
            4 => Some(Self::FinWait1),
            5 => Some(Self::FinWait2),
            6 => Some(Self::TimeWait),
            7 => Some(Self::Close),
            8 => Some(Self::CloseWait),
            9 => Some(Self::LastAck),
            10 => Some(Self::Listen),
            11 => Some(Self::Closing),
            12 => Some(Self::NewSynRecv),
            _ => None,
        }
    }

    /// Stable low-cardinality label for the state.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Established => "established",
            Self::SynSent => "syn_sent",
            Self::SynRecv => "syn_recv",
            Self::FinWait1 => "fin_wait1",
            Self::FinWait2 => "fin_wait2",
            Self::TimeWait => "time_wait",
            Self::Close => "close",
            Self::CloseWait => "close_wait",
            Self::LastAck => "last_ack",
            Self::Listen => "listen",
            Self::Closing => "closing",
            Self::NewSynRecv => "new_syn_recv",
        }
    }
}

/// Direction of an observed TCP reset relative to the local host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum NetworkTcpResetDirection {
    Send,
    Receive,
}

impl NetworkTcpResetDirection {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Send => "send",
            Self::Receive => "receive",
        }
    }
}

/// A TCP stack event: retransmission, reset, or state transition, captured
/// from kernel `tcp`/`sock` tracepoints with best-effort process attribution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkTcpStatObservation {
    pub stat: NetworkTcpStatKind,
    pub address_family: NetworkAddressFamily,
    pub local_address: Option<String>,
    pub local_port: Option<u16>,
    pub remote_address: Option<String>,
    pub remote_port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub old_state: Option<NetworkTcpState>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_state: Option<NetworkTcpState>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reset_direction: Option<NetworkTcpResetDirection>,
    pub timestamp_unix_nanos: u64,
    pub process: Option<NetworkProcessIdentity>,
    pub container: Option<ContainerContext>,
    pub kubernetes: Option<KubernetesContext>,
}

pub(crate) fn sanitize_network_tcp_stat_observation(event: &mut NetworkTcpStatObservation) {
    if let Some(process) = event.process.as_mut() {
        sanitize_network_process_identity(process);
    }
    sanitize_optional_network_signal_string(&mut event.local_address);
    sanitize_optional_network_signal_string(&mut event.remote_address);
    sanitize_optional_container_context(&mut event.container);
    sanitize_optional_kubernetes_context(&mut event.kubernetes);
}

pub(crate) fn sanitize_network_connection_open_event(event: &mut NetworkConnectionOpenEvent) {
    sanitize_network_process_identity(&mut event.process);
    sanitize_optional_network_signal_string(&mut event.local_address);
    sanitize_network_signal_string(&mut event.remote_address);
    sanitize_optional_container_context(&mut event.container);
    sanitize_optional_kubernetes_context(&mut event.kubernetes);
}

pub(crate) fn sanitize_network_connection_close_event(event: &mut NetworkConnectionCloseEvent) {
    sanitize_network_process_identity(&mut event.process);
    sanitize_optional_network_signal_string(&mut event.local_address);
    sanitize_network_signal_string(&mut event.remote_address);
    sanitize_optional_container_context(&mut event.container);
    sanitize_optional_kubernetes_context(&mut event.kubernetes);
}

pub(crate) fn sanitize_network_connection_failure_event(event: &mut NetworkConnectionFailureEvent) {
    sanitize_network_process_identity(&mut event.process);
    sanitize_network_signal_string(&mut event.remote_address);
    sanitize_optional_container_context(&mut event.container);
    sanitize_optional_kubernetes_context(&mut event.kubernetes);
}

pub(crate) fn sanitize_network_flow_warning(warning: &mut NetworkFlowWarning) {
    sanitize_network_signal_string(&mut warning.warning_type);
    sanitize_network_signal_string(&mut warning.message);
    sanitize_network_signal_string(&mut warning.source_signal_kind);
    sanitize_network_signal_string(&mut warning.source_module);
    sanitize_network_signal_string(&mut warning.remote_address);
    sanitize_network_process_identity(&mut warning.process);
    sanitize_optional_container_context(&mut warning.container);
    sanitize_optional_kubernetes_context(&mut warning.kubernetes);
}

pub(crate) fn sanitize_network_flow_summary_event(event: &mut NetworkFlowSummaryEvent) {
    sanitize_network_flow_endpoint(&mut event.source);
    sanitize_network_flow_endpoint(&mut event.destination);
}

pub(crate) fn sanitize_dependency_edge_event(event: &mut DependencyEdgeEvent) {
    sanitize_dependency_endpoint(&mut event.source);
    sanitize_dependency_endpoint(&mut event.destination);
}

fn sanitize_network_flow_endpoint(endpoint: &mut NetworkFlowEndpoint) {
    sanitize_optional_network_signal_string(&mut endpoint.address);
    sanitize_optional_network_signal_string(&mut endpoint.owner_name);
    sanitize_optional_network_signal_string(&mut endpoint.owner_type);
    sanitize_optional_container_context(&mut endpoint.container);
    sanitize_optional_kubernetes_context(&mut endpoint.kubernetes);
}

fn sanitize_dependency_endpoint(endpoint: &mut DependencyEndpoint) {
    sanitize_optional_network_signal_string(&mut endpoint.address);
    sanitize_optional_network_signal_string(&mut endpoint.domain);
    sanitize_optional_container_context(&mut endpoint.container);
    sanitize_optional_kubernetes_context(&mut endpoint.workload);
}

pub(crate) fn sanitize_network_process_identity(process: &mut NetworkProcessIdentity) {
    sanitize_network_signal_string(&mut process.command);
    sanitize_optional_network_signal_string(&mut process.executable);
}

fn sanitize_optional_container_context(context: &mut Option<ContainerContext>) {
    if let Some(inner) = context {
        sanitize_network_signal_string(&mut inner.container_id);
        sanitize_optional_network_signal_string(&mut inner.runtime);
    }
}

fn sanitize_optional_kubernetes_context(context: &mut Option<KubernetesContext>) {
    if let Some(inner) = context {
        sanitize_network_signal_string(&mut inner.namespace);
        sanitize_network_signal_string(&mut inner.pod_name);
        sanitize_optional_network_signal_string(&mut inner.pod_uid);
        sanitize_optional_network_signal_string(&mut inner.container_name);
        sanitize_optional_network_signal_string(&mut inner.node_name);
        inner.labels = inner
            .labels
            .iter()
            .filter(|(key, _)| !key.is_empty())
            .map(|(key, value)| {
                (
                    truncate_utf8(key, MAX_KUBERNETES_LABEL_KEY_BYTES),
                    truncate_utf8(value, MAX_NETWORK_SIGNAL_STRING_BYTES),
                )
            })
            .take(MAX_KUBERNETES_LABELS)
            .collect();
    }
}

fn sanitize_network_signal_string(value: &mut String) {
    *value = truncate_utf8(value, MAX_NETWORK_SIGNAL_STRING_BYTES);
}

fn sanitize_optional_network_signal_string(value: &mut Option<String>) {
    if let Some(inner) = value {
        sanitize_network_signal_string(inner);
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
