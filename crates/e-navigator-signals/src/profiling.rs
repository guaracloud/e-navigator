use serde::{Deserialize, Serialize};

use crate::{ContainerContext, KubernetesContext, MetricAggregationWindow, NetworkProcessIdentity};

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
    attributes.retain(|attribute| !is_sensitive_profiling_attribute_key(&attribute.key));
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
