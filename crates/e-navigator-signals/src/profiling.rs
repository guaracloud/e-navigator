use serde::{Deserialize, Serialize};

use crate::network::sanitize_network_process_identity;
use crate::{ContainerContext, KubernetesContext, MetricAggregationWindow, NetworkProcessIdentity};

const MAX_PROFILING_ATTRIBUTES: usize = 16;
const MAX_PROFILING_ATTRIBUTE_KEY_BYTES: usize = 64;
const MAX_PROFILING_ATTRIBUTE_VALUE_BYTES: usize = 256;
const MAX_PROFILING_STACK_FRAMES: usize = 256;
const MAX_PROFILING_FRAME_STRING_BYTES: usize = 256;
const MAX_PROFILING_STRING_BYTES: usize = 256;
const MAX_KUBERNETES_LABELS: usize = 16;
const MAX_KUBERNETES_LABEL_KEY_BYTES: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ProfilingKind {
    Cpu,
    Memory,
    Lock,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ProfilingCorrelationKind {
    ObservedProfileSample,
    Synthetic,
    RuntimeInferred,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ProfilingConfidence {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfilingAttribute {
    pub key: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfilingFrame {
    pub symbol: Option<String>,
    pub module: Option<String>,
    pub file: Option<String>,
    pub line: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileSampleObservation {
    pub timestamp_unix_nanos: u64,
    pub profiling_kind: ProfilingKind,
    pub correlation_kind: ProfilingCorrelationKind,
    pub confidence: ProfilingConfidence,
    pub sample_count: u64,
    pub sampling_period_nanos: Option<u64>,
    pub stack_id: String,
    pub stack_frames: Vec<ProfilingFrame>,
    pub process: Option<NetworkProcessIdentity>,
    pub container: Option<ContainerContext>,
    pub kubernetes: Option<KubernetesContext>,
    pub thread_id: Option<u64>,
    pub thread_name: Option<String>,
    pub attributes: Vec<ProfilingAttribute>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfilingStackTraceObservation {
    pub timestamp_unix_nanos: u64,
    pub profiling_kind: ProfilingKind,
    pub correlation_kind: ProfilingCorrelationKind,
    pub confidence: ProfilingConfidence,
    pub stack_id: String,
    pub stack_frames: Vec<ProfilingFrame>,
    pub process: Option<NetworkProcessIdentity>,
    pub container: Option<ContainerContext>,
    pub kubernetes: Option<KubernetesContext>,
    pub attributes: Vec<ProfilingAttribute>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfilingSessionObservation {
    pub window: MetricAggregationWindow,
    pub profiling_kind: ProfilingKind,
    pub correlation_kind: ProfilingCorrelationKind,
    pub confidence: ProfilingConfidence,
    pub profile_id: String,
    pub observed_sample_count: u64,
    pub dropped_sample_count: u64,
    pub distinct_stack_count: u64,
    pub sampling_period_nanos: Option<u64>,
    pub process: Option<NetworkProcessIdentity>,
    pub container: Option<ContainerContext>,
    pub kubernetes: Option<KubernetesContext>,
    pub source: String,
    pub attributes: Vec<ProfilingAttribute>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfilingWarningObservation {
    pub warning_type: String,
    pub message: String,
    pub timestamp_unix_nanos: u64,
    pub source_signal_kind: String,
    pub source_module: String,
    pub profiling_kind: ProfilingKind,
    pub correlation_kind: ProfilingCorrelationKind,
    pub confidence: ProfilingConfidence,
    pub process: Option<NetworkProcessIdentity>,
    pub container: Option<ContainerContext>,
    pub kubernetes: Option<KubernetesContext>,
    pub attributes: Vec<ProfilingAttribute>,
}

pub fn sanitize_profiling_attributes(attributes: &mut Vec<ProfilingAttribute>) {
    let sanitized = attributes
        .drain(..)
        .filter(|attribute| !is_sensitive_profiling_attribute_key(&attribute.key))
        .take(MAX_PROFILING_ATTRIBUTES)
        .map(|attribute| ProfilingAttribute {
            key: truncate_utf8(&attribute.key, MAX_PROFILING_ATTRIBUTE_KEY_BYTES),
            value: truncate_utf8(&attribute.value, MAX_PROFILING_ATTRIBUTE_VALUE_BYTES),
        })
        .collect();
    *attributes = sanitized;
}

pub fn sanitize_profiling_frames(frames: &mut Vec<ProfilingFrame>) {
    frames.truncate(MAX_PROFILING_STACK_FRAMES);
    for frame in frames {
        truncate_optional_string(&mut frame.symbol, MAX_PROFILING_FRAME_STRING_BYTES);
        truncate_optional_string(&mut frame.module, MAX_PROFILING_FRAME_STRING_BYTES);
        truncate_optional_string(&mut frame.file, MAX_PROFILING_FRAME_STRING_BYTES);
    }
}

pub(crate) fn sanitize_profiling_string(value: &mut String) {
    *value = truncate_utf8(value, MAX_PROFILING_STRING_BYTES);
}

pub(crate) fn sanitize_optional_profiling_string(value: &mut Option<String>) {
    truncate_optional_string(value, MAX_PROFILING_STRING_BYTES);
}

pub(crate) fn sanitize_optional_profiling_process_identity(
    process: &mut Option<NetworkProcessIdentity>,
) {
    if let Some(inner) = process {
        sanitize_network_process_identity(inner);
    }
}

pub(crate) fn sanitize_optional_profiling_container_context(
    context: &mut Option<ContainerContext>,
) {
    if let Some(inner) = context {
        sanitize_profiling_string(&mut inner.container_id);
        sanitize_optional_profiling_string(&mut inner.runtime);
    }
}

pub(crate) fn sanitize_optional_profiling_kubernetes_context(
    context: &mut Option<KubernetesContext>,
) {
    if let Some(inner) = context {
        sanitize_profiling_string(&mut inner.namespace);
        sanitize_profiling_string(&mut inner.pod_name);
        sanitize_optional_profiling_string(&mut inner.pod_uid);
        sanitize_optional_profiling_string(&mut inner.container_name);
        sanitize_optional_profiling_string(&mut inner.node_name);
        inner.labels = inner
            .labels
            .iter()
            .filter(|(key, _)| !key.is_empty())
            .map(|(key, value)| {
                (
                    truncate_utf8(key, MAX_KUBERNETES_LABEL_KEY_BYTES),
                    truncate_utf8(value, MAX_PROFILING_STRING_BYTES),
                )
            })
            .take(MAX_KUBERNETES_LABELS)
            .collect();
    }
}

pub fn is_sensitive_profiling_attribute_key(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    key.contains("token")
        || key.contains("authorization")
        || key.contains("cookie")
        || key.contains("password")
        || key.contains("secret")
        || key.contains("api_key")
        || key.contains("apikey")
        || key.contains("x-api-key")
        || key.contains("credential")
        || key.contains("private_key")
        || key.contains("jwt")
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

fn truncate_optional_string(value: &mut Option<String>, max_bytes: usize) {
    if let Some(inner) = value {
        *inner = truncate_utf8(inner, max_bytes);
    }
}
