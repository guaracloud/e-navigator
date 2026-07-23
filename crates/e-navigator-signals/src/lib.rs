#![forbid(unsafe_code)]
#![warn(missing_debug_implementations, rust_2018_idioms, unreachable_pub)]
//! Versioned, bounded signal envelopes shared across the E-Navigator pipeline.

pub mod dns;
pub mod envelope;
pub mod exec;
pub mod metrics;
pub mod network;
pub mod profiling;
pub mod request;
pub mod resource;
mod sanitize;
pub use sanitize::contains_ascii_case_insensitive;
pub mod trace;

pub use dns::{
    DnsCounterMetric, DnsLatencyMetric, DnsQueryEvent, DnsQueryType, DnsResponseCode,
    DnsResponseEvent,
};
pub use envelope::{SignalEnvelope, SignalKind, SignalPayload};
pub use exec::{
    ContainerContext, ExecEvent, KubernetesContext, MatchedNetworkConnection, MatchedProcess,
    ProcessExitEvent, ProcessLifecycleDurationEvent, RuntimeSecurityFinding,
    RuntimeSecuritySeverity,
};
pub use metrics::{
    MetricAggregationWindow, NetworkCounterMetric, NetworkDurationMetric, NetworkGaugeMetric,
};
pub use network::{
    DependencyEdgeEvent, DependencyEndpoint, NetworkAddressFamily, NetworkConnectionCloseEvent,
    NetworkConnectionFailureEvent, NetworkConnectionOpenEvent, NetworkFlowDirection,
    NetworkFlowEndpoint, NetworkFlowSummaryEvent, NetworkFlowWarning, NetworkProcessIdentity,
    NetworkProtocol, NetworkTcpResetDirection, NetworkTcpStatKind, NetworkTcpStatObservation,
    NetworkTcpState,
};
pub use profiling::{
    ProfileSampleObservation, ProfilingAttribute, ProfilingConfidence, ProfilingCorrelationKind,
    ProfilingFrame, ProfilingKind, ProfilingSessionObservation, ProfilingStackTraceObservation,
    ProfilingWarningObservation, is_sensitive_profiling_attribute_key,
    sanitize_profiling_attributes, sanitize_profiling_frames,
};
pub use request::{
    ExtractedTraceContextObservation, ProtocolCaptureRole, ProtocolKind,
    ProtocolRequestObservation, RequestCorrelationWarning, RequestSpanObservation,
};
pub use resource::{
    CgroupCpuObservation, CgroupFileDescriptorObservation, CgroupMemoryObservation,
    CgroupPidsObservation, CgroupResourceContext, NodeCpuObservation, NodeDiskIoObservation,
    NodeFilesystemObservation, NodeLoadObservation, NodeMemoryObservation, ProcessResourceContext,
    ProcessResourceObservation, ResourceContext, ResourceCounterMetric, ResourceGaugeMetric,
    ResourceMetricAttribute, sanitize_resource_metric_attributes,
};
pub use trace::{
    ServiceInteractionSpanObservation, TraceAttribute, TraceConfidence, TraceCorrelationKind,
    TraceCorrelationWarning, TracePeerContext, TraceServicePathObservation, TraceSpanObservation,
    is_sensitive_trace_attribute_key, sanitize_trace_attributes,
};
