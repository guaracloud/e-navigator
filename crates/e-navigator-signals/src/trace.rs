use serde::{Deserialize, Serialize};

use crate::network::sanitize_network_process_identity;
use crate::sanitize::{
    contains_ascii_case_insensitive, sanitize_kubernetes_labels, truncate_utf8_in_place,
};
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
    GeneratedTraceContext,
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
    attributes.retain(|attribute| {
        !attribute.key.is_empty()
            && attribute.key.len() <= MAX_TRACE_ATTRIBUTE_KEY_BYTES
            && attribute.value.len() <= MAX_TRACE_ATTRIBUTE_VALUE_BYTES
            && !is_sensitive_trace_attribute_key(&attribute.key)
    });
    attributes.truncate(MAX_TRACE_ATTRIBUTES);
}

pub fn is_sensitive_trace_attribute_key(key: &str) -> bool {
    const SENSITIVE_KEY_PARTS: [&str; 9] = [
        "password",
        "passwd",
        "secret",
        "token",
        "authorization",
        "cookie",
        "api_key",
        "apikey",
        "credential",
    ];

    SENSITIVE_KEY_PARTS
        .iter()
        .any(|sensitive| contains_ascii_case_insensitive(key, sensitive))
}

pub(crate) fn sanitize_trace_string(value: &mut String) {
    truncate_utf8_in_place(value, MAX_TRACE_STRING_BYTES);
}

pub(crate) fn sanitize_optional_trace_string(value: &mut Option<String>) {
    if let Some(inner) = value {
        sanitize_trace_string(inner);
    }
}

pub(crate) fn sanitize_optional_trace_identifier_string(value: &mut Option<String>) {
    if let Some(inner) = value {
        truncate_utf8_in_place(inner, MAX_TRACE_IDENTIFIER_STRING_BYTES);
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
        sanitize_kubernetes_labels(
            &mut inner.labels,
            MAX_KUBERNETES_LABELS,
            MAX_KUBERNETES_LABEL_KEY_BYTES,
            MAX_TRACE_STRING_BYTES,
        );
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sensitive_trace_key_check_is_case_insensitive_without_allocating() {
        for key in [
            "authorization",
            "Authorization",
            "http.request.header.X-API_KEY",
            "db.PassWord",
            "session.Cookie.value",
            "refresh_TOKEN",
        ] {
            assert!(is_sensitive_trace_attribute_key(key), "{key}");
        }
        for key in [
            "http.route",
            "db.system",
            "net.peer.name",
            "e.navigator.protocol.capture.role",
            "",
            "toke",
        ] {
            assert!(!is_sensitive_trace_attribute_key(key), "{key}");
        }
    }

    #[test]
    fn sanitize_trace_attributes_drops_sensitive_and_oversized_entries() {
        let mut attributes = vec![
            TraceAttribute {
                key: "http.route".to_string(),
                value: "/orders".to_string(),
            },
            TraceAttribute {
                key: "http.request.header.authorization".to_string(),
                value: "Bearer secret".to_string(),
            },
            TraceAttribute {
                key: String::new(),
                value: "empty".to_string(),
            },
        ];
        sanitize_trace_attributes(&mut attributes);
        assert_eq!(attributes.len(), 1);
        assert_eq!(attributes[0].key, "http.route");
    }
}
