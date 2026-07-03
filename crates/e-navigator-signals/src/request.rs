use serde::{Deserialize, Serialize};

use crate::{
    ContainerContext, KubernetesContext, NetworkProcessIdentity, TraceAttribute, TraceConfidence,
    TraceCorrelationKind, TracePeerContext,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ProtocolKind {
    Http,
    Grpc,
    Kafka,
    Mongodb,
    Mysql,
    Nats,
    Postgresql,
    Redis,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtocolRequestObservation {
    pub protocol: ProtocolKind,
    pub start_unix_nanos: u64,
    pub end_unix_nanos: Option<u64>,
    pub duration_nanos: Option<u64>,
    pub trace_id: Option<String>,
    pub span_id: Option<String>,
    pub parent_span_id: Option<String>,
    #[serde(default, skip_serializing)]
    pub traceparent: Option<String>,
    #[serde(default, skip_serializing)]
    pub tracestate: Option<String>,
    pub correlation_kind: TraceCorrelationKind,
    pub confidence: TraceConfidence,
    pub service_name: Option<String>,
    pub method: Option<String>,
    pub status_code: Option<u16>,
    pub process: Option<NetworkProcessIdentity>,
    pub container: Option<ContainerContext>,
    pub kubernetes: Option<KubernetesContext>,
    pub peer: Option<TracePeerContext>,
    pub attributes: Vec<TraceAttribute>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtractedTraceContextObservation {
    pub protocol: ProtocolKind,
    pub timestamp_unix_nanos: u64,
    pub trace_id: Option<String>,
    pub span_id: Option<String>,
    pub parent_span_id: Option<String>,
    #[serde(default, skip_serializing)]
    pub traceparent: Option<String>,
    #[serde(default, skip_serializing)]
    pub tracestate: Option<String>,
    pub correlation_kind: TraceCorrelationKind,
    pub confidence: TraceConfidence,
    pub process: Option<NetworkProcessIdentity>,
    pub container: Option<ContainerContext>,
    pub kubernetes: Option<KubernetesContext>,
    pub peer: Option<TracePeerContext>,
    pub attributes: Vec<TraceAttribute>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestSpanObservation {
    pub name: String,
    pub protocol: ProtocolKind,
    pub trace_id: Option<String>,
    pub span_id: Option<String>,
    pub parent_span_id: Option<String>,
    pub start_unix_nanos: u64,
    pub end_unix_nanos: Option<u64>,
    pub duration_nanos: Option<u64>,
    pub correlation_kind: TraceCorrelationKind,
    pub confidence: TraceConfidence,
    pub service_name: Option<String>,
    pub method: Option<String>,
    pub status_code: Option<u16>,
    pub process: Option<NetworkProcessIdentity>,
    pub container: Option<ContainerContext>,
    pub kubernetes: Option<KubernetesContext>,
    pub peer: Option<TracePeerContext>,
    pub attributes: Vec<TraceAttribute>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestCorrelationWarning {
    pub warning_type: String,
    pub message: String,
    pub timestamp_unix_nanos: u64,
    pub source_signal_kind: String,
    pub source_module: String,
    pub correlation_kind: TraceCorrelationKind,
    pub protocol: ProtocolKind,
    pub process: Option<NetworkProcessIdentity>,
    pub container: Option<ContainerContext>,
    pub kubernetes: Option<KubernetesContext>,
    pub peer: Option<TracePeerContext>,
}
