use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

const MAX_EXEC_SIGNAL_STRING_BYTES: usize = 256;
const MAX_EXEC_ARGUMENTS: usize = 32;
const MAX_KUBERNETES_LABELS: usize = 16;
const MAX_KUBERNETES_LABEL_KEY_BYTES: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecEvent {
    pub pid: u32,
    pub ppid: Option<u32>,
    pub uid: Option<u32>,
    pub command: String,
    pub executable: Option<String>,
    pub arguments: Vec<String>,
    pub cgroup_id: Option<u64>,
    pub timestamp_unix_nanos: u64,
    pub container: Option<ContainerContext>,
    pub kubernetes: Option<KubernetesContext>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessExitEvent {
    pub pid: u32,
    pub ppid: Option<u32>,
    pub uid: Option<u32>,
    pub command: String,
    pub cgroup_id: Option<u64>,
    pub exit_code: Option<i32>,
    pub runtime_nanos: Option<u64>,
    pub timestamp_unix_nanos: u64,
    pub container: Option<ContainerContext>,
    pub kubernetes: Option<KubernetesContext>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessLifecycleDurationEvent {
    pub pid: u32,
    pub command: String,
    pub started_at_unix_nanos: u64,
    pub exited_at_unix_nanos: u64,
    pub duration_nanos: u64,
    pub container: Option<ContainerContext>,
    pub kubernetes: Option<KubernetesContext>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeSecurityFinding {
    pub rule_id: String,
    pub severity: RuntimeSecuritySeverity,
    pub matched_process: MatchedProcess,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub matched_connection: Option<MatchedNetworkConnection>,
    pub container: Option<ContainerContext>,
    pub kubernetes: Option<KubernetesContext>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeSecuritySeverity {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatchedProcess {
    pub pid: u32,
    pub command: String,
    pub executable: Option<String>,
    pub arguments: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatchedNetworkConnection {
    pub protocol: crate::NetworkProtocol,
    pub remote_address: String,
    pub remote_port: u16,
    pub local_address: Option<String>,
    pub local_port: Option<u16>,
    pub fd: Option<i32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContainerContext {
    pub container_id: String,
    pub runtime: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KubernetesContext {
    pub namespace: String,
    pub pod_name: String,
    pub pod_uid: Option<String>,
    pub container_name: Option<String>,
    pub node_name: Option<String>,
    pub labels: BTreeMap<String, String>,
}

pub(crate) fn sanitize_exec_event(event: &mut ExecEvent) {
    sanitize_exec_signal_string(&mut event.command);
    sanitize_optional_exec_signal_string(&mut event.executable);
    event.arguments.truncate(MAX_EXEC_ARGUMENTS);
    for argument in &mut event.arguments {
        sanitize_exec_signal_string(argument);
    }
    sanitize_optional_container_context(&mut event.container);
    sanitize_optional_kubernetes_context(&mut event.kubernetes);
}

pub(crate) fn sanitize_process_exit_event(event: &mut ProcessExitEvent) {
    sanitize_exec_signal_string(&mut event.command);
    sanitize_optional_container_context(&mut event.container);
    sanitize_optional_kubernetes_context(&mut event.kubernetes);
}

pub(crate) fn sanitize_process_lifecycle_duration_event(event: &mut ProcessLifecycleDurationEvent) {
    sanitize_exec_signal_string(&mut event.command);
    sanitize_optional_container_context(&mut event.container);
    sanitize_optional_kubernetes_context(&mut event.kubernetes);
}

pub(crate) fn sanitize_runtime_security_finding(finding: &mut RuntimeSecurityFinding) {
    sanitize_exec_signal_string(&mut finding.rule_id);
    sanitize_matched_process(&mut finding.matched_process);
    if let Some(connection) = &mut finding.matched_connection {
        sanitize_matched_network_connection(connection);
    }
    sanitize_optional_container_context(&mut finding.container);
    sanitize_optional_kubernetes_context(&mut finding.kubernetes);
}

fn sanitize_matched_process(process: &mut MatchedProcess) {
    sanitize_exec_signal_string(&mut process.command);
    sanitize_optional_exec_signal_string(&mut process.executable);
    process.arguments.truncate(MAX_EXEC_ARGUMENTS);
    for argument in &mut process.arguments {
        sanitize_exec_signal_string(argument);
    }
}

fn sanitize_matched_network_connection(connection: &mut MatchedNetworkConnection) {
    sanitize_exec_signal_string(&mut connection.remote_address);
    sanitize_optional_exec_signal_string(&mut connection.local_address);
}

fn sanitize_optional_container_context(context: &mut Option<ContainerContext>) {
    if let Some(inner) = context {
        sanitize_exec_signal_string(&mut inner.container_id);
        sanitize_optional_exec_signal_string(&mut inner.runtime);
    }
}

fn sanitize_optional_kubernetes_context(context: &mut Option<KubernetesContext>) {
    if let Some(inner) = context {
        sanitize_exec_signal_string(&mut inner.namespace);
        sanitize_exec_signal_string(&mut inner.pod_name);
        sanitize_optional_exec_signal_string(&mut inner.pod_uid);
        sanitize_optional_exec_signal_string(&mut inner.container_name);
        sanitize_optional_exec_signal_string(&mut inner.node_name);
        inner.labels = inner
            .labels
            .iter()
            .filter(|(key, _)| !key.is_empty())
            .map(|(key, value)| {
                (
                    truncate_utf8(key, MAX_KUBERNETES_LABEL_KEY_BYTES),
                    truncate_utf8(value, MAX_EXEC_SIGNAL_STRING_BYTES),
                )
            })
            .take(MAX_KUBERNETES_LABELS)
            .collect();
    }
}

fn sanitize_exec_signal_string(value: &mut String) {
    *value = truncate_utf8(value, MAX_EXEC_SIGNAL_STRING_BYTES);
}

fn sanitize_optional_exec_signal_string(value: &mut Option<String>) {
    if let Some(inner) = value {
        sanitize_exec_signal_string(inner);
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
