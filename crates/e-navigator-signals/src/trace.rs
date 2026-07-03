use serde::{Deserialize, Serialize};

use crate::{
    ContainerContext, DependencyEndpoint, KubernetesContext, NetworkProcessIdentity,
    NetworkProtocol,
};

const MAX_TRACE_ATTRIBUTES: usize = 16;
const MAX_TRACE_ATTRIBUTE_KEY_BYTES: usize = 128;
const MAX_TRACE_ATTRIBUTE_VALUE_BYTES: usize = 256;

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
