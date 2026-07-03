use serde::{Deserialize, Serialize};

use crate::network::sanitize_network_process_identity;
use crate::{
    ContainerContext, DependencyEndpoint, KubernetesContext, NetworkProcessIdentity,
    NetworkProtocol,
};

const MAX_TRACE_ATTRIBUTES: usize = 16;
const MAX_TRACE_ATTRIBUTE_KEY_BYTES: usize = 128;
const MAX_TRACE_ATTRIBUTE_VALUE_BYTES: usize = 256;
const MAX_TRACE_STRING_BYTES: usize = 256;
const MAX_TRACE_IDENTIFIER_STRING_BYTES: usize = 64;
const MAX_KUBERNETES_LABELS: usize = 16;
const MAX_KUBERNETES_LABEL_KEY_BYTES: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum TraceCorrelationKind {
    ObservedTraceContext,
    ProtocolObserved,
    NetworkInferred,
    DependencyInferred,
    Synthetic,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum TraceConfidence {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct TraceAttribute {
    pub key: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TracePeerContext {
    pub address: Option<String>,
    pub port: Option<u16>,
    pub domain: Option<String>,
    pub workload: Option<KubernetesContext>,
    pub container: Option<ContainerContext>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceSpanObservation {
    pub name: String,
    pub trace_id: Option<String>,
    pub span_id: Option<String>,
    pub parent_span_id: Option<String>,
    pub start_unix_nanos: u64,
    pub end_unix_nanos: Option<u64>,
    pub duration_nanos: Option<u64>,
    pub correlation_kind: TraceCorrelationKind,
    pub confidence: TraceConfidence,
    pub service_name: Option<String>,
    pub process: Option<NetworkProcessIdentity>,
    pub container: Option<ContainerContext>,
    pub kubernetes: Option<KubernetesContext>,
    pub peer: Option<TracePeerContext>,
    pub attributes: Vec<TraceAttribute>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceInteractionSpanObservation {
    pub name: String,
    pub trace_id: Option<String>,
    pub span_id: Option<String>,
    pub parent_span_id: Option<String>,
    pub start_unix_nanos: u64,
    pub end_unix_nanos: Option<u64>,
    pub duration_nanos: Option<u64>,
    pub correlation_kind: TraceCorrelationKind,
    pub confidence: TraceConfidence,
    pub source: DependencyEndpoint,
    pub destination: DependencyEndpoint,
    pub protocol: NetworkProtocol,
    pub process: Option<NetworkProcessIdentity>,
    pub error_type: Option<String>,
    pub attributes: Vec<TraceAttribute>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceServicePathObservation {
    pub path_key: String,
    pub source: DependencyEndpoint,
    pub destination: DependencyEndpoint,
    pub protocol: NetworkProtocol,
    pub observations: u64,
    pub first_seen_unix_nanos: u64,
    pub last_seen_unix_nanos: u64,
    pub correlation_kind: TraceCorrelationKind,
    pub confidence: TraceConfidence,
    pub attributes: Vec<TraceAttribute>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceCorrelationWarning {
    pub warning_type: String,
    pub message: String,
    pub timestamp_unix_nanos: u64,
    pub source_signal_kind: String,
    pub source_module: String,
    pub correlation_kind: TraceCorrelationKind,
    pub process: Option<NetworkProcessIdentity>,
    pub container: Option<ContainerContext>,
    pub kubernetes: Option<KubernetesContext>,
    pub peer: Option<TracePeerContext>,
}

pub fn sanitize_trace_attributes(attributes: &mut Vec<TraceAttribute>) {
    let sanitized = attributes
        .drain(..)
        .filter(|attribute| {
            !attribute.key.is_empty()
                && attribute.key.len() <= MAX_TRACE_ATTRIBUTE_KEY_BYTES
                && attribute.value.len() <= MAX_TRACE_ATTRIBUTE_VALUE_BYTES
                && !is_sensitive_trace_attribute_key(&attribute.key)
        })
        .take(MAX_TRACE_ATTRIBUTES)
        .collect();
    *attributes = sanitized;
}

pub fn is_sensitive_trace_attribute_key(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    key.contains("password")
        || key.contains("passwd")
        || key.contains("secret")
        || key.contains("token")
        || key.contains("authorization")
        || key.contains("cookie")
        || key.contains("api_key")
        || key.contains("apikey")
        || key.contains("credential")
}

pub(crate) fn sanitize_trace_string(value: &mut String) {
    *value = truncate_utf8(value, MAX_TRACE_STRING_BYTES);
}

pub(crate) fn sanitize_optional_trace_string(value: &mut Option<String>) {
    if let Some(inner) = value {
        sanitize_trace_string(inner);
    }
}

pub(crate) fn sanitize_optional_trace_identifier_string(value: &mut Option<String>) {
    if let Some(inner) = value {
        *inner = truncate_utf8(inner, MAX_TRACE_IDENTIFIER_STRING_BYTES);
    }
}

pub(crate) fn sanitize_optional_trace_process_identity(
    process: &mut Option<NetworkProcessIdentity>,
) {
    if let Some(inner) = process {
        sanitize_network_process_identity(inner);
    }
}

pub(crate) fn sanitize_optional_trace_container_context(context: &mut Option<ContainerContext>) {
    if let Some(inner) = context {
        sanitize_trace_string(&mut inner.container_id);
        sanitize_optional_trace_string(&mut inner.runtime);
    }
}

pub(crate) fn sanitize_optional_trace_kubernetes_context(context: &mut Option<KubernetesContext>) {
    if let Some(inner) = context {
        sanitize_trace_string(&mut inner.namespace);
        sanitize_trace_string(&mut inner.pod_name);
        sanitize_optional_trace_string(&mut inner.pod_uid);
        sanitize_optional_trace_string(&mut inner.container_name);
        sanitize_optional_trace_string(&mut inner.node_name);
        inner.labels = inner
            .labels
            .iter()
            .filter(|(key, _)| !key.is_empty())
            .map(|(key, value)| {
                (
                    truncate_utf8(key, MAX_KUBERNETES_LABEL_KEY_BYTES),
                    truncate_utf8(value, MAX_TRACE_STRING_BYTES),
                )
            })
            .take(MAX_KUBERNETES_LABELS)
            .collect();
    }
}

pub(crate) fn sanitize_optional_trace_peer_context(context: &mut Option<TracePeerContext>) {
    if let Some(inner) = context {
        sanitize_optional_trace_string(&mut inner.address);
        sanitize_optional_trace_string(&mut inner.domain);
        sanitize_optional_trace_kubernetes_context(&mut inner.workload);
        sanitize_optional_trace_container_context(&mut inner.container);
    }
}

pub(crate) fn sanitize_trace_dependency_endpoint(endpoint: &mut DependencyEndpoint) {
    sanitize_optional_trace_string(&mut endpoint.address);
    sanitize_optional_trace_string(&mut endpoint.domain);
    sanitize_optional_trace_kubernetes_context(&mut endpoint.workload);
    sanitize_optional_trace_container_context(&mut endpoint.container);
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
