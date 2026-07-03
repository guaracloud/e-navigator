use e_navigator_core::Signal;
use serde::{Deserialize, Deserializer, Serialize, de::Error as DeError};

use crate::dns::{
    sanitize_dns_counter_metric, sanitize_dns_latency_metric, sanitize_dns_query_event,
    sanitize_dns_response_event,
};
use crate::exec::{
    sanitize_exec_event, sanitize_process_exit_event, sanitize_process_lifecycle_duration_event,
    sanitize_runtime_security_finding,
};
use crate::metrics::{
    sanitize_network_counter_metric, sanitize_network_duration_metric,
    sanitize_network_gauge_metric,
};
use crate::network::{
    sanitize_dependency_edge_event, sanitize_network_connection_close_event,
    sanitize_network_connection_failure_event, sanitize_network_connection_open_event,
    sanitize_network_flow_summary_event, sanitize_network_flow_warning,
};
use crate::profiling::{
    sanitize_optional_profiling_container_context, sanitize_optional_profiling_kubernetes_context,
    sanitize_optional_profiling_process_identity, sanitize_optional_profiling_string,
    sanitize_profiling_string,
};
use crate::resource::{
    sanitize_cgroup_cpu_observation, sanitize_cgroup_file_descriptor_observation,
    sanitize_cgroup_memory_observation, sanitize_cgroup_pids_observation,
    sanitize_node_cpu_observation, sanitize_node_disk_io_observation,
    sanitize_node_filesystem_observation, sanitize_node_load_observation,
    sanitize_node_memory_observation, sanitize_process_resource_observation,
    sanitize_resource_counter_metric, sanitize_resource_gauge_metric,
};
use crate::trace::{
    sanitize_optional_trace_container_context, sanitize_optional_trace_kubernetes_context,
    sanitize_optional_trace_peer_context, sanitize_optional_trace_process_identity,
    sanitize_optional_trace_string, sanitize_trace_attributes, sanitize_trace_dependency_endpoint,
    sanitize_trace_string,
};
use crate::{
    CgroupCpuObservation, CgroupFileDescriptorObservation, CgroupMemoryObservation,
    CgroupPidsObservation, DependencyEdgeEvent, DnsCounterMetric, DnsLatencyMetric, DnsQueryEvent,
    DnsResponseEvent, ExecEvent, ExtractedTraceContextObservation, NetworkConnectionCloseEvent,
    NetworkConnectionFailureEvent, NetworkConnectionOpenEvent, NetworkCounterMetric,
    NetworkDurationMetric, NetworkFlowSummaryEvent, NetworkFlowWarning, NetworkGaugeMetric,
    NodeCpuObservation, NodeDiskIoObservation, NodeFilesystemObservation, NodeLoadObservation,
    NodeMemoryObservation, ProcessExitEvent, ProcessLifecycleDurationEvent,
    ProcessResourceObservation, ProfileSampleObservation, ProfilingSessionObservation,
    ProfilingStackTraceObservation, ProfilingWarningObservation, ProtocolRequestObservation,
    RequestCorrelationWarning, RequestSpanObservation, ResourceCounterMetric, ResourceGaugeMetric,
    RuntimeSecurityFinding, ServiceInteractionSpanObservation, TraceCorrelationWarning,
    TraceServicePathObservation, TraceSpanObservation, sanitize_profiling_attributes,
    sanitize_profiling_frames,
};

pub const SIGNAL_SCHEMA_VERSION: u16 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum SignalKind {
    Exec,
    ProcessExit,
    ProcessLifecycleDuration,
    NetworkConnectionOpen,
    NetworkConnectionClose,
    NetworkConnectionFailure,
    NetworkFlowSummary,
    NetworkFlowWarning,
    NetworkCounterMetric,
    NetworkDurationMetric,
    NetworkGaugeMetric,
    DnsQuery,
    DnsResponse,
    DnsCounterMetric,
    DnsLatencyMetric,
    DependencyEdge,
    RuntimeSecurityFinding,
    NodeCpuObservation,
    NodeLoadObservation,
    NodeMemoryObservation,
    NodeFilesystemObservation,
    NodeDiskIoObservation,
    ProcessResourceObservation,
    CgroupCpuObservation,
    CgroupMemoryObservation,
    CgroupPidsObservation,
    CgroupFileDescriptorObservation,
    ResourceGaugeMetric,
    ResourceCounterMetric,
    TraceSpanObservation,
    ServiceInteractionSpanObservation,
    TraceServicePathObservation,
    TraceCorrelationWarning,
    ProtocolRequestObservation,
    ExtractedTraceContextObservation,
    RequestSpanObservation,
    RequestCorrelationWarning,
    ProfileSampleObservation,
    ProfilingStackTraceObservation,
    ProfilingSessionObservation,
    ProfilingWarningObservation,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
#[non_exhaustive]
pub enum SignalPayload {
    Exec(ExecEvent),
    ProcessExit(ProcessExitEvent),
    ProcessLifecycleDuration(ProcessLifecycleDurationEvent),
    NetworkFlowWarning(NetworkFlowWarning),
    NetworkConnectionOpen(NetworkConnectionOpenEvent),
    NetworkConnectionClose(NetworkConnectionCloseEvent),
    NetworkConnectionFailure(NetworkConnectionFailureEvent),
    NetworkFlowSummary(NetworkFlowSummaryEvent),
    NetworkCounterMetric(NetworkCounterMetric),
    NetworkDurationMetric(NetworkDurationMetric),
    NetworkGaugeMetric(NetworkGaugeMetric),
    DnsQuery(DnsQueryEvent),
    DnsResponse(DnsResponseEvent),
    DnsCounterMetric(DnsCounterMetric),
    DnsLatencyMetric(DnsLatencyMetric),
    RequestSpanObservation(RequestSpanObservation),
    ProtocolRequestObservation(ProtocolRequestObservation),
    ExtractedTraceContextObservation(ExtractedTraceContextObservation),
    RequestCorrelationWarning(RequestCorrelationWarning),
    ProfileSampleObservation(ProfileSampleObservation),
    ProfilingStackTraceObservation(ProfilingStackTraceObservation),
    ProfilingSessionObservation(ProfilingSessionObservation),
    ProfilingWarningObservation(ProfilingWarningObservation),
    TraceSpanObservation(TraceSpanObservation),
    ServiceInteractionSpanObservation(ServiceInteractionSpanObservation),
    TraceServicePathObservation(TraceServicePathObservation),
    TraceCorrelationWarning(TraceCorrelationWarning),
    DependencyEdge(DependencyEdgeEvent),
    RuntimeSecurityFinding(RuntimeSecurityFinding),
    NodeCpuObservation(NodeCpuObservation),
    NodeLoadObservation(NodeLoadObservation),
    NodeMemoryObservation(NodeMemoryObservation),
    NodeFilesystemObservation(NodeFilesystemObservation),
    NodeDiskIoObservation(NodeDiskIoObservation),
    ProcessResourceObservation(ProcessResourceObservation),
    CgroupCpuObservation(CgroupCpuObservation),
    CgroupMemoryObservation(CgroupMemoryObservation),
    CgroupPidsObservation(CgroupPidsObservation),
    CgroupFileDescriptorObservation(CgroupFileDescriptorObservation),
    ResourceGaugeMetric(ResourceGaugeMetric),
    ResourceCounterMetric(ResourceCounterMetric),
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SignalEnvelope {
    pub schema_version: u16,
    kind: SignalKind,
    pub source: String,
    pub host: Option<String>,
    pub payload: SignalPayload,
}

impl<'de> Deserialize<'de> for SignalEnvelope {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct RawSignalEnvelope {
            schema_version: u16,
            kind: SignalKind,
            source: String,
            host: Option<String>,
            payload: serde_json::Value,
        }

        let raw = RawSignalEnvelope::deserialize(deserializer)?;
        let payload = match raw.kind {
            SignalKind::Exec => serde_json::from_value::<ExecEvent>(raw.payload)
                .map(SignalPayload::Exec)
                .map_err(|err| D::Error::custom(format!("invalid exec payload: {err}")))?,
            SignalKind::ProcessExit => serde_json::from_value::<ProcessExitEvent>(raw.payload)
                .map(SignalPayload::ProcessExit)
                .map_err(|err| D::Error::custom(format!("invalid process_exit payload: {err}")))?,
            SignalKind::ProcessLifecycleDuration => serde_json::from_value::<
                ProcessLifecycleDurationEvent,
            >(raw.payload)
            .map(SignalPayload::ProcessLifecycleDuration)
            .map_err(|err| {
                D::Error::custom(format!("invalid process_lifecycle_duration payload: {err}"))
            })?,
            SignalKind::NetworkConnectionOpen => {
                serde_json::from_value::<NetworkConnectionOpenEvent>(raw.payload)
                    .map(SignalPayload::NetworkConnectionOpen)
                    .map_err(|err| {
                        D::Error::custom(format!("invalid network_connection_open payload: {err}"))
                    })?
            }
            SignalKind::NetworkConnectionClose => {
                serde_json::from_value::<NetworkConnectionCloseEvent>(raw.payload)
                    .map(SignalPayload::NetworkConnectionClose)
                    .map_err(|err| {
                        D::Error::custom(format!("invalid network_connection_close payload: {err}"))
                    })?
            }
            SignalKind::NetworkConnectionFailure => serde_json::from_value::<
                NetworkConnectionFailureEvent,
            >(raw.payload)
            .map(SignalPayload::NetworkConnectionFailure)
            .map_err(|err| {
                D::Error::custom(format!("invalid network_connection_failure payload: {err}"))
            })?,
            SignalKind::NetworkFlowSummary => {
                serde_json::from_value::<NetworkFlowSummaryEvent>(raw.payload)
                    .map(SignalPayload::NetworkFlowSummary)
                    .map_err(|err| {
                        D::Error::custom(format!("invalid network_flow_summary payload: {err}"))
                    })?
            }
            SignalKind::NetworkFlowWarning => {
                serde_json::from_value::<NetworkFlowWarning>(raw.payload)
                    .map(SignalPayload::NetworkFlowWarning)
                    .map_err(|err| {
                        D::Error::custom(format!("invalid network_flow_warning payload: {err}"))
                    })?
            }
            SignalKind::NetworkCounterMetric => {
                serde_json::from_value::<NetworkCounterMetric>(raw.payload)
                    .map(SignalPayload::NetworkCounterMetric)
                    .map_err(|err| {
                        D::Error::custom(format!("invalid network_counter_metric payload: {err}"))
                    })?
            }
            SignalKind::NetworkDurationMetric => {
                serde_json::from_value::<NetworkDurationMetric>(raw.payload)
                    .map(SignalPayload::NetworkDurationMetric)
                    .map_err(|err| {
                        D::Error::custom(format!("invalid network_duration_metric payload: {err}"))
                    })?
            }
            SignalKind::NetworkGaugeMetric => {
                serde_json::from_value::<NetworkGaugeMetric>(raw.payload)
                    .map(SignalPayload::NetworkGaugeMetric)
                    .map_err(|err| {
                        D::Error::custom(format!("invalid network_gauge_metric payload: {err}"))
                    })?
            }
            SignalKind::DnsQuery => serde_json::from_value::<DnsQueryEvent>(raw.payload)
                .map(SignalPayload::DnsQuery)
                .map_err(|err| D::Error::custom(format!("invalid dns_query payload: {err}")))?,
            SignalKind::DnsResponse => serde_json::from_value::<DnsResponseEvent>(raw.payload)
                .map(SignalPayload::DnsResponse)
                .map_err(|err| D::Error::custom(format!("invalid dns_response payload: {err}")))?,
            SignalKind::DnsCounterMetric => serde_json::from_value::<DnsCounterMetric>(raw.payload)
                .map(SignalPayload::DnsCounterMetric)
                .map_err(|err| {
                    D::Error::custom(format!("invalid dns_counter_metric payload: {err}"))
                })?,
            SignalKind::DnsLatencyMetric => serde_json::from_value::<DnsLatencyMetric>(raw.payload)
                .map(SignalPayload::DnsLatencyMetric)
                .map_err(|err| {
                    D::Error::custom(format!("invalid dns_latency_metric payload: {err}"))
                })?,
            SignalKind::DependencyEdge => {
                serde_json::from_value::<DependencyEdgeEvent>(raw.payload)
                    .map(SignalPayload::DependencyEdge)
                    .map_err(|err| {
                        D::Error::custom(format!("invalid dependency_edge payload: {err}"))
                    })?
            }
            SignalKind::RuntimeSecurityFinding => {
                serde_json::from_value::<RuntimeSecurityFinding>(raw.payload)
                    .map(SignalPayload::RuntimeSecurityFinding)
                    .map_err(|err| {
                        D::Error::custom(format!("invalid runtime_security_finding payload: {err}"))
                    })?
            }
            SignalKind::NodeCpuObservation => {
                serde_json::from_value::<NodeCpuObservation>(raw.payload)
                    .map(SignalPayload::NodeCpuObservation)
                    .map_err(|err| {
                        D::Error::custom(format!("invalid node_cpu_observation payload: {err}"))
                    })?
            }
            SignalKind::NodeLoadObservation => {
                serde_json::from_value::<NodeLoadObservation>(raw.payload)
                    .map(SignalPayload::NodeLoadObservation)
                    .map_err(|err| {
                        D::Error::custom(format!("invalid node_load_observation payload: {err}"))
                    })?
            }
            SignalKind::NodeMemoryObservation => {
                serde_json::from_value::<NodeMemoryObservation>(raw.payload)
                    .map(SignalPayload::NodeMemoryObservation)
                    .map_err(|err| {
                        D::Error::custom(format!("invalid node_memory_observation payload: {err}"))
                    })?
            }
            SignalKind::NodeFilesystemObservation => {
                serde_json::from_value::<NodeFilesystemObservation>(raw.payload)
                    .map(SignalPayload::NodeFilesystemObservation)
                    .map_err(|err| {
                        D::Error::custom(format!(
                            "invalid node_filesystem_observation payload: {err}"
                        ))
                    })?
            }
            SignalKind::NodeDiskIoObservation => {
                serde_json::from_value::<NodeDiskIoObservation>(raw.payload)
                    .map(SignalPayload::NodeDiskIoObservation)
                    .map_err(|err| {
                        D::Error::custom(format!("invalid node_disk_io_observation payload: {err}"))
                    })?
            }
            SignalKind::ProcessResourceObservation => {
                serde_json::from_value::<ProcessResourceObservation>(raw.payload)
                    .map(SignalPayload::ProcessResourceObservation)
                    .map_err(|err| {
                        D::Error::custom(format!(
                            "invalid process_resource_observation payload: {err}"
                        ))
                    })?
            }
            SignalKind::CgroupCpuObservation => {
                serde_json::from_value::<CgroupCpuObservation>(raw.payload)
                    .map(SignalPayload::CgroupCpuObservation)
                    .map_err(|err| {
                        D::Error::custom(format!("invalid cgroup_cpu_observation payload: {err}"))
                    })?
            }
            SignalKind::CgroupMemoryObservation => {
                serde_json::from_value::<CgroupMemoryObservation>(raw.payload)
                    .map(SignalPayload::CgroupMemoryObservation)
                    .map_err(|err| {
                        D::Error::custom(format!(
                            "invalid cgroup_memory_observation payload: {err}"
                        ))
                    })?
            }
            SignalKind::CgroupPidsObservation => {
                serde_json::from_value::<CgroupPidsObservation>(raw.payload)
                    .map(SignalPayload::CgroupPidsObservation)
                    .map_err(|err| {
                        D::Error::custom(format!("invalid cgroup_pids_observation payload: {err}"))
                    })?
            }
            SignalKind::CgroupFileDescriptorObservation => {
                serde_json::from_value::<CgroupFileDescriptorObservation>(raw.payload)
                    .map(SignalPayload::CgroupFileDescriptorObservation)
                    .map_err(|err| {
                        D::Error::custom(format!(
                            "invalid cgroup_file_descriptor_observation payload: {err}"
                        ))
                    })?
            }
            SignalKind::ResourceGaugeMetric => {
                serde_json::from_value::<ResourceGaugeMetric>(raw.payload)
                    .map(SignalPayload::ResourceGaugeMetric)
                    .map_err(|err| {
                        D::Error::custom(format!("invalid resource_gauge_metric payload: {err}"))
                    })?
            }
            SignalKind::ResourceCounterMetric => {
                serde_json::from_value::<ResourceCounterMetric>(raw.payload)
                    .map(SignalPayload::ResourceCounterMetric)
                    .map_err(|err| {
                        D::Error::custom(format!("invalid resource_counter_metric payload: {err}"))
                    })?
            }
            SignalKind::TraceSpanObservation => {
                serde_json::from_value::<TraceSpanObservation>(raw.payload)
                    .map(SignalPayload::TraceSpanObservation)
                    .map_err(|err| {
                        D::Error::custom(format!("invalid trace_span_observation payload: {err}"))
                    })?
            }
            SignalKind::ServiceInteractionSpanObservation => {
                serde_json::from_value::<ServiceInteractionSpanObservation>(raw.payload)
                    .map(SignalPayload::ServiceInteractionSpanObservation)
                    .map_err(|err| {
                        D::Error::custom(format!(
                            "invalid service_interaction_span_observation payload: {err}"
                        ))
                    })?
            }
            SignalKind::TraceServicePathObservation => {
                serde_json::from_value::<TraceServicePathObservation>(raw.payload)
                    .map(SignalPayload::TraceServicePathObservation)
                    .map_err(|err| {
                        D::Error::custom(format!(
                            "invalid trace_service_path_observation payload: {err}"
                        ))
                    })?
            }
            SignalKind::TraceCorrelationWarning => {
                serde_json::from_value::<TraceCorrelationWarning>(raw.payload)
                    .map(SignalPayload::TraceCorrelationWarning)
                    .map_err(|err| {
                        D::Error::custom(format!(
                            "invalid trace_correlation_warning payload: {err}"
                        ))
                    })?
            }
            SignalKind::ProtocolRequestObservation => {
                serde_json::from_value::<ProtocolRequestObservation>(raw.payload)
                    .map(SignalPayload::ProtocolRequestObservation)
                    .map_err(|err| {
                        D::Error::custom(format!(
                            "invalid protocol_request_observation payload: {err}"
                        ))
                    })?
            }
            SignalKind::ExtractedTraceContextObservation => {
                serde_json::from_value::<ExtractedTraceContextObservation>(raw.payload)
                    .map(SignalPayload::ExtractedTraceContextObservation)
                    .map_err(|err| {
                        D::Error::custom(format!(
                            "invalid extracted_trace_context_observation payload: {err}"
                        ))
                    })?
            }
            SignalKind::RequestSpanObservation => {
                serde_json::from_value::<RequestSpanObservation>(raw.payload)
                    .map(SignalPayload::RequestSpanObservation)
                    .map_err(|err| {
                        D::Error::custom(format!("invalid request_span_observation payload: {err}"))
                    })?
            }
            SignalKind::RequestCorrelationWarning => {
                serde_json::from_value::<RequestCorrelationWarning>(raw.payload)
                    .map(SignalPayload::RequestCorrelationWarning)
                    .map_err(|err| {
                        D::Error::custom(format!(
                            "invalid request_correlation_warning payload: {err}"
                        ))
                    })?
            }
            SignalKind::ProfileSampleObservation => serde_json::from_value::<
                ProfileSampleObservation,
            >(raw.payload)
            .map(SignalPayload::ProfileSampleObservation)
            .map_err(|err| {
                D::Error::custom(format!("invalid profile_sample_observation payload: {err}"))
            })?,
            SignalKind::ProfilingStackTraceObservation => {
                serde_json::from_value::<ProfilingStackTraceObservation>(raw.payload)
                    .map(SignalPayload::ProfilingStackTraceObservation)
                    .map_err(|err| {
                        D::Error::custom(format!(
                            "invalid profiling_stack_trace_observation payload: {err}"
                        ))
                    })?
            }
            SignalKind::ProfilingSessionObservation => {
                serde_json::from_value::<ProfilingSessionObservation>(raw.payload)
                    .map(SignalPayload::ProfilingSessionObservation)
                    .map_err(|err| {
                        D::Error::custom(format!(
                            "invalid profiling_session_observation payload: {err}"
                        ))
                    })?
            }
            SignalKind::ProfilingWarningObservation => {
                serde_json::from_value::<ProfilingWarningObservation>(raw.payload)
                    .map(SignalPayload::ProfilingWarningObservation)
                    .map_err(|err| {
                        D::Error::custom(format!(
                            "invalid profiling_warning_observation payload: {err}"
                        ))
                    })?
            }
        };

        Ok(Self {
            schema_version: raw.schema_version,
            kind: raw.kind,
            source: raw.source,
            host: raw.host,
            payload,
        })
    }
}

impl SignalEnvelope {
    pub fn exec(source: impl Into<String>, host: Option<String>, mut event: ExecEvent) -> Self {
        sanitize_exec_event(&mut event);
        Self {
            schema_version: SIGNAL_SCHEMA_VERSION,
            kind: SignalKind::Exec,
            source: source.into(),
            host,
            payload: SignalPayload::Exec(event),
        }
    }

    pub fn process_exit(
        source: impl Into<String>,
        host: Option<String>,
        mut event: ProcessExitEvent,
    ) -> Self {
        sanitize_process_exit_event(&mut event);
        Self {
            schema_version: SIGNAL_SCHEMA_VERSION,
            kind: SignalKind::ProcessExit,
            source: source.into(),
            host,
            payload: SignalPayload::ProcessExit(event),
        }
    }

    pub fn process_lifecycle_duration(
        source: impl Into<String>,
        host: Option<String>,
        mut event: ProcessLifecycleDurationEvent,
    ) -> Self {
        sanitize_process_lifecycle_duration_event(&mut event);
        Self {
            schema_version: SIGNAL_SCHEMA_VERSION,
            kind: SignalKind::ProcessLifecycleDuration,
            source: source.into(),
            host,
            payload: SignalPayload::ProcessLifecycleDuration(event),
        }
    }

    pub fn runtime_security_finding(
        source: impl Into<String>,
        host: Option<String>,
        mut finding: RuntimeSecurityFinding,
    ) -> Self {
        sanitize_runtime_security_finding(&mut finding);
        Self {
            schema_version: SIGNAL_SCHEMA_VERSION,
            kind: SignalKind::RuntimeSecurityFinding,
            source: source.into(),
            host,
            payload: SignalPayload::RuntimeSecurityFinding(finding),
        }
    }

    pub fn network_connection_open(
        source: impl Into<String>,
        host: Option<String>,
        mut event: NetworkConnectionOpenEvent,
    ) -> Self {
        sanitize_network_connection_open_event(&mut event);
        Self {
            schema_version: SIGNAL_SCHEMA_VERSION,
            kind: SignalKind::NetworkConnectionOpen,
            source: source.into(),
            host,
            payload: SignalPayload::NetworkConnectionOpen(event),
        }
    }

    pub fn network_connection_close(
        source: impl Into<String>,
        host: Option<String>,
        mut event: NetworkConnectionCloseEvent,
    ) -> Self {
        sanitize_network_connection_close_event(&mut event);
        Self {
            schema_version: SIGNAL_SCHEMA_VERSION,
            kind: SignalKind::NetworkConnectionClose,
            source: source.into(),
            host,
            payload: SignalPayload::NetworkConnectionClose(event),
        }
    }

    pub fn network_connection_failure(
        source: impl Into<String>,
        host: Option<String>,
        mut event: NetworkConnectionFailureEvent,
    ) -> Self {
        sanitize_network_connection_failure_event(&mut event);
        Self {
            schema_version: SIGNAL_SCHEMA_VERSION,
            kind: SignalKind::NetworkConnectionFailure,
            source: source.into(),
            host,
            payload: SignalPayload::NetworkConnectionFailure(event),
        }
    }

    pub fn network_flow_summary(
        source: impl Into<String>,
        host: Option<String>,
        mut event: NetworkFlowSummaryEvent,
    ) -> Self {
        sanitize_network_flow_summary_event(&mut event);
        Self {
            schema_version: SIGNAL_SCHEMA_VERSION,
            kind: SignalKind::NetworkFlowSummary,
            source: source.into(),
            host,
            payload: SignalPayload::NetworkFlowSummary(event),
        }
    }

    pub fn network_flow_warning(
        source: impl Into<String>,
        host: Option<String>,
        mut warning: NetworkFlowWarning,
    ) -> Self {
        sanitize_network_flow_warning(&mut warning);
        Self {
            schema_version: SIGNAL_SCHEMA_VERSION,
            kind: SignalKind::NetworkFlowWarning,
            source: source.into(),
            host,
            payload: SignalPayload::NetworkFlowWarning(warning),
        }
    }

    pub fn network_counter_metric(
        source: impl Into<String>,
        host: Option<String>,
        mut metric: NetworkCounterMetric,
    ) -> Self {
        sanitize_network_counter_metric(&mut metric);
        Self {
            schema_version: SIGNAL_SCHEMA_VERSION,
            kind: SignalKind::NetworkCounterMetric,
            source: source.into(),
            host,
            payload: SignalPayload::NetworkCounterMetric(metric),
        }
    }

    pub fn network_duration_metric(
        source: impl Into<String>,
        host: Option<String>,
        mut metric: NetworkDurationMetric,
    ) -> Self {
        sanitize_network_duration_metric(&mut metric);
        Self {
            schema_version: SIGNAL_SCHEMA_VERSION,
            kind: SignalKind::NetworkDurationMetric,
            source: source.into(),
            host,
            payload: SignalPayload::NetworkDurationMetric(metric),
        }
    }

    pub fn network_gauge_metric(
        source: impl Into<String>,
        host: Option<String>,
        mut metric: NetworkGaugeMetric,
    ) -> Self {
        sanitize_network_gauge_metric(&mut metric);
        Self {
            schema_version: SIGNAL_SCHEMA_VERSION,
            kind: SignalKind::NetworkGaugeMetric,
            source: source.into(),
            host,
            payload: SignalPayload::NetworkGaugeMetric(metric),
        }
    }

    pub fn dns_query(
        source: impl Into<String>,
        host: Option<String>,
        mut event: DnsQueryEvent,
    ) -> Self {
        sanitize_dns_query_event(&mut event);
        Self {
            schema_version: SIGNAL_SCHEMA_VERSION,
            kind: SignalKind::DnsQuery,
            source: source.into(),
            host,
            payload: SignalPayload::DnsQuery(event),
        }
    }

    pub fn dns_response(
        source: impl Into<String>,
        host: Option<String>,
        mut event: DnsResponseEvent,
    ) -> Self {
        sanitize_dns_response_event(&mut event);
        Self {
            schema_version: SIGNAL_SCHEMA_VERSION,
            kind: SignalKind::DnsResponse,
            source: source.into(),
            host,
            payload: SignalPayload::DnsResponse(event),
        }
    }

    pub fn dns_counter_metric(
        source: impl Into<String>,
        host: Option<String>,
        mut metric: DnsCounterMetric,
    ) -> Self {
        sanitize_dns_counter_metric(&mut metric);
        Self {
            schema_version: SIGNAL_SCHEMA_VERSION,
            kind: SignalKind::DnsCounterMetric,
            source: source.into(),
            host,
            payload: SignalPayload::DnsCounterMetric(metric),
        }
    }

    pub fn dns_latency_metric(
        source: impl Into<String>,
        host: Option<String>,
        mut metric: DnsLatencyMetric,
    ) -> Self {
        sanitize_dns_latency_metric(&mut metric);
        Self {
            schema_version: SIGNAL_SCHEMA_VERSION,
            kind: SignalKind::DnsLatencyMetric,
            source: source.into(),
            host,
            payload: SignalPayload::DnsLatencyMetric(metric),
        }
    }

    pub fn dependency_edge(
        source: impl Into<String>,
        host: Option<String>,
        mut event: DependencyEdgeEvent,
    ) -> Self {
        sanitize_dependency_edge_event(&mut event);
        Self {
            schema_version: SIGNAL_SCHEMA_VERSION,
            kind: SignalKind::DependencyEdge,
            source: source.into(),
            host,
            payload: SignalPayload::DependencyEdge(event),
        }
    }

    pub fn node_cpu_observation(
        source: impl Into<String>,
        host: Option<String>,
        mut observation: NodeCpuObservation,
    ) -> Self {
        sanitize_node_cpu_observation(&mut observation);
        Self::new(
            source,
            host,
            SignalKind::NodeCpuObservation,
            SignalPayload::NodeCpuObservation(observation),
        )
    }

    pub fn node_load_observation(
        source: impl Into<String>,
        host: Option<String>,
        mut observation: NodeLoadObservation,
    ) -> Self {
        sanitize_node_load_observation(&mut observation);
        Self::new(
            source,
            host,
            SignalKind::NodeLoadObservation,
            SignalPayload::NodeLoadObservation(observation),
        )
    }

    pub fn node_memory_observation(
        source: impl Into<String>,
        host: Option<String>,
        mut observation: NodeMemoryObservation,
    ) -> Self {
        sanitize_node_memory_observation(&mut observation);
        Self::new(
            source,
            host,
            SignalKind::NodeMemoryObservation,
            SignalPayload::NodeMemoryObservation(observation),
        )
    }

    pub fn node_filesystem_observation(
        source: impl Into<String>,
        host: Option<String>,
        mut observation: NodeFilesystemObservation,
    ) -> Self {
        sanitize_node_filesystem_observation(&mut observation);
        Self::new(
            source,
            host,
            SignalKind::NodeFilesystemObservation,
            SignalPayload::NodeFilesystemObservation(observation),
        )
    }

    pub fn node_disk_io_observation(
        source: impl Into<String>,
        host: Option<String>,
        mut observation: NodeDiskIoObservation,
    ) -> Self {
        sanitize_node_disk_io_observation(&mut observation);
        Self::new(
            source,
            host,
            SignalKind::NodeDiskIoObservation,
            SignalPayload::NodeDiskIoObservation(observation),
        )
    }

    pub fn process_resource_observation(
        source: impl Into<String>,
        host: Option<String>,
        mut observation: ProcessResourceObservation,
    ) -> Self {
        sanitize_process_resource_observation(&mut observation);
        Self::new(
            source,
            host,
            SignalKind::ProcessResourceObservation,
            SignalPayload::ProcessResourceObservation(observation),
        )
    }

    pub fn cgroup_cpu_observation(
        source: impl Into<String>,
        host: Option<String>,
        mut observation: CgroupCpuObservation,
    ) -> Self {
        sanitize_cgroup_cpu_observation(&mut observation);
        Self::new(
            source,
            host,
            SignalKind::CgroupCpuObservation,
            SignalPayload::CgroupCpuObservation(observation),
        )
    }

    pub fn cgroup_memory_observation(
        source: impl Into<String>,
        host: Option<String>,
        mut observation: CgroupMemoryObservation,
    ) -> Self {
        sanitize_cgroup_memory_observation(&mut observation);
        Self::new(
            source,
            host,
            SignalKind::CgroupMemoryObservation,
            SignalPayload::CgroupMemoryObservation(observation),
        )
    }

    pub fn cgroup_pids_observation(
        source: impl Into<String>,
        host: Option<String>,
        mut observation: CgroupPidsObservation,
    ) -> Self {
        sanitize_cgroup_pids_observation(&mut observation);
        Self::new(
            source,
            host,
            SignalKind::CgroupPidsObservation,
            SignalPayload::CgroupPidsObservation(observation),
        )
    }

    pub fn cgroup_file_descriptor_observation(
        source: impl Into<String>,
        host: Option<String>,
        mut observation: CgroupFileDescriptorObservation,
    ) -> Self {
        sanitize_cgroup_file_descriptor_observation(&mut observation);
        Self::new(
            source,
            host,
            SignalKind::CgroupFileDescriptorObservation,
            SignalPayload::CgroupFileDescriptorObservation(observation),
        )
    }

    pub fn resource_gauge_metric(
        source: impl Into<String>,
        host: Option<String>,
        mut metric: ResourceGaugeMetric,
    ) -> Self {
        sanitize_resource_gauge_metric(&mut metric);
        Self::new(
            source,
            host,
            SignalKind::ResourceGaugeMetric,
            SignalPayload::ResourceGaugeMetric(metric),
        )
    }

    pub fn resource_counter_metric(
        source: impl Into<String>,
        host: Option<String>,
        mut metric: ResourceCounterMetric,
    ) -> Self {
        sanitize_resource_counter_metric(&mut metric);
        Self::new(
            source,
            host,
            SignalKind::ResourceCounterMetric,
            SignalPayload::ResourceCounterMetric(metric),
        )
    }

    pub fn trace_span_observation(
        source: impl Into<String>,
        host: Option<String>,
        mut observation: TraceSpanObservation,
    ) -> Self {
        sanitize_trace_attributes(&mut observation.attributes);
        sanitize_trace_string(&mut observation.name);
        sanitize_optional_trace_string(&mut observation.service_name);
        sanitize_optional_trace_process_identity(&mut observation.process);
        sanitize_optional_trace_container_context(&mut observation.container);
        sanitize_optional_trace_kubernetes_context(&mut observation.kubernetes);
        sanitize_optional_trace_peer_context(&mut observation.peer);
        Self::new(
            source,
            host,
            SignalKind::TraceSpanObservation,
            SignalPayload::TraceSpanObservation(observation),
        )
    }

    pub fn service_interaction_span_observation(
        source: impl Into<String>,
        host: Option<String>,
        mut observation: ServiceInteractionSpanObservation,
    ) -> Self {
        sanitize_trace_attributes(&mut observation.attributes);
        sanitize_trace_string(&mut observation.name);
        sanitize_optional_trace_string(&mut observation.error_type);
        sanitize_trace_dependency_endpoint(&mut observation.source);
        sanitize_trace_dependency_endpoint(&mut observation.destination);
        sanitize_optional_trace_process_identity(&mut observation.process);
        Self::new(
            source,
            host,
            SignalKind::ServiceInteractionSpanObservation,
            SignalPayload::ServiceInteractionSpanObservation(observation),
        )
    }

    pub fn trace_service_path_observation(
        source: impl Into<String>,
        host: Option<String>,
        mut observation: TraceServicePathObservation,
    ) -> Self {
        sanitize_trace_attributes(&mut observation.attributes);
        sanitize_trace_string(&mut observation.path_key);
        sanitize_trace_dependency_endpoint(&mut observation.source);
        sanitize_trace_dependency_endpoint(&mut observation.destination);
        Self::new(
            source,
            host,
            SignalKind::TraceServicePathObservation,
            SignalPayload::TraceServicePathObservation(observation),
        )
    }

    pub fn trace_correlation_warning(
        source: impl Into<String>,
        host: Option<String>,
        mut warning: TraceCorrelationWarning,
    ) -> Self {
        sanitize_trace_string(&mut warning.warning_type);
        sanitize_trace_string(&mut warning.message);
        sanitize_trace_string(&mut warning.source_signal_kind);
        sanitize_trace_string(&mut warning.source_module);
        sanitize_optional_trace_process_identity(&mut warning.process);
        sanitize_optional_trace_container_context(&mut warning.container);
        sanitize_optional_trace_kubernetes_context(&mut warning.kubernetes);
        sanitize_optional_trace_peer_context(&mut warning.peer);
        Self::new(
            source,
            host,
            SignalKind::TraceCorrelationWarning,
            SignalPayload::TraceCorrelationWarning(warning),
        )
    }

    pub fn protocol_request_observation(
        source: impl Into<String>,
        host: Option<String>,
        mut observation: ProtocolRequestObservation,
    ) -> Self {
        sanitize_trace_attributes(&mut observation.attributes);
        sanitize_optional_trace_string(&mut observation.service_name);
        sanitize_optional_trace_string(&mut observation.method);
        sanitize_optional_trace_process_identity(&mut observation.process);
        sanitize_optional_trace_container_context(&mut observation.container);
        sanitize_optional_trace_kubernetes_context(&mut observation.kubernetes);
        sanitize_optional_trace_peer_context(&mut observation.peer);
        Self::new(
            source,
            host,
            SignalKind::ProtocolRequestObservation,
            SignalPayload::ProtocolRequestObservation(observation),
        )
    }

    pub fn extracted_trace_context_observation(
        source: impl Into<String>,
        host: Option<String>,
        mut observation: ExtractedTraceContextObservation,
    ) -> Self {
        sanitize_trace_attributes(&mut observation.attributes);
        sanitize_optional_trace_process_identity(&mut observation.process);
        sanitize_optional_trace_container_context(&mut observation.container);
        sanitize_optional_trace_kubernetes_context(&mut observation.kubernetes);
        sanitize_optional_trace_peer_context(&mut observation.peer);
        Self::new(
            source,
            host,
            SignalKind::ExtractedTraceContextObservation,
            SignalPayload::ExtractedTraceContextObservation(observation),
        )
    }

    pub fn request_span_observation(
        source: impl Into<String>,
        host: Option<String>,
        mut observation: RequestSpanObservation,
    ) -> Self {
        sanitize_trace_attributes(&mut observation.attributes);
        sanitize_trace_string(&mut observation.name);
        sanitize_optional_trace_string(&mut observation.service_name);
        sanitize_optional_trace_string(&mut observation.method);
        sanitize_optional_trace_process_identity(&mut observation.process);
        sanitize_optional_trace_container_context(&mut observation.container);
        sanitize_optional_trace_kubernetes_context(&mut observation.kubernetes);
        sanitize_optional_trace_peer_context(&mut observation.peer);
        Self::new(
            source,
            host,
            SignalKind::RequestSpanObservation,
            SignalPayload::RequestSpanObservation(observation),
        )
    }

    pub fn request_correlation_warning(
        source: impl Into<String>,
        host: Option<String>,
        mut warning: RequestCorrelationWarning,
    ) -> Self {
        sanitize_trace_string(&mut warning.warning_type);
        sanitize_trace_string(&mut warning.message);
        sanitize_trace_string(&mut warning.source_signal_kind);
        sanitize_trace_string(&mut warning.source_module);
        sanitize_optional_trace_process_identity(&mut warning.process);
        sanitize_optional_trace_container_context(&mut warning.container);
        sanitize_optional_trace_kubernetes_context(&mut warning.kubernetes);
        sanitize_optional_trace_peer_context(&mut warning.peer);
        Self::new(
            source,
            host,
            SignalKind::RequestCorrelationWarning,
            SignalPayload::RequestCorrelationWarning(warning),
        )
    }

    pub fn profile_sample_observation(
        source: impl Into<String>,
        host: Option<String>,
        mut observation: ProfileSampleObservation,
    ) -> Self {
        sanitize_profiling_attributes(&mut observation.attributes);
        sanitize_profiling_frames(&mut observation.stack_frames);
        sanitize_profiling_string(&mut observation.stack_id);
        sanitize_optional_profiling_string(&mut observation.thread_name);
        sanitize_optional_profiling_process_identity(&mut observation.process);
        sanitize_optional_profiling_container_context(&mut observation.container);
        sanitize_optional_profiling_kubernetes_context(&mut observation.kubernetes);
        Self::new(
            source,
            host,
            SignalKind::ProfileSampleObservation,
            SignalPayload::ProfileSampleObservation(observation),
        )
    }

    pub fn profiling_stack_trace_observation(
        source: impl Into<String>,
        host: Option<String>,
        mut observation: ProfilingStackTraceObservation,
    ) -> Self {
        sanitize_profiling_attributes(&mut observation.attributes);
        sanitize_profiling_frames(&mut observation.stack_frames);
        sanitize_profiling_string(&mut observation.stack_id);
        sanitize_optional_profiling_process_identity(&mut observation.process);
        sanitize_optional_profiling_container_context(&mut observation.container);
        sanitize_optional_profiling_kubernetes_context(&mut observation.kubernetes);
        Self::new(
            source,
            host,
            SignalKind::ProfilingStackTraceObservation,
            SignalPayload::ProfilingStackTraceObservation(observation),
        )
    }

    pub fn profiling_session_observation(
        source: impl Into<String>,
        host: Option<String>,
        mut observation: ProfilingSessionObservation,
    ) -> Self {
        sanitize_profiling_attributes(&mut observation.attributes);
        sanitize_profiling_string(&mut observation.profile_id);
        sanitize_profiling_string(&mut observation.source);
        sanitize_optional_profiling_process_identity(&mut observation.process);
        sanitize_optional_profiling_container_context(&mut observation.container);
        sanitize_optional_profiling_kubernetes_context(&mut observation.kubernetes);
        Self::new(
            source,
            host,
            SignalKind::ProfilingSessionObservation,
            SignalPayload::ProfilingSessionObservation(observation),
        )
    }

    pub fn profiling_warning_observation(
        source: impl Into<String>,
        host: Option<String>,
        mut observation: ProfilingWarningObservation,
    ) -> Self {
        sanitize_profiling_attributes(&mut observation.attributes);
        sanitize_profiling_string(&mut observation.warning_type);
        sanitize_profiling_string(&mut observation.message);
        sanitize_profiling_string(&mut observation.source_signal_kind);
        sanitize_profiling_string(&mut observation.source_module);
        sanitize_optional_profiling_process_identity(&mut observation.process);
        sanitize_optional_profiling_container_context(&mut observation.container);
        sanitize_optional_profiling_kubernetes_context(&mut observation.kubernetes);
        Self::new(
            source,
            host,
            SignalKind::ProfilingWarningObservation,
            SignalPayload::ProfilingWarningObservation(observation),
        )
    }

    fn new(
        source: impl Into<String>,
        host: Option<String>,
        kind: SignalKind,
        payload: SignalPayload,
    ) -> Self {
        Self {
            schema_version: SIGNAL_SCHEMA_VERSION,
            kind,
            source: source.into(),
            host,
            payload,
        }
    }

    pub fn signal_kind(&self) -> SignalKind {
        self.kind
    }
}

impl Signal for SignalEnvelope {
    fn kind(&self) -> &'static str {
        match self.kind {
            SignalKind::Exec => "exec",
            SignalKind::ProcessExit => "process_exit",
            SignalKind::ProcessLifecycleDuration => "process_lifecycle_duration",
            SignalKind::NetworkConnectionOpen => "network_connection_open",
            SignalKind::NetworkConnectionClose => "network_connection_close",
            SignalKind::NetworkConnectionFailure => "network_connection_failure",
            SignalKind::NetworkFlowSummary => "network_flow_summary",
            SignalKind::NetworkFlowWarning => "network_flow_warning",
            SignalKind::NetworkCounterMetric => "network_counter_metric",
            SignalKind::NetworkDurationMetric => "network_duration_metric",
            SignalKind::NetworkGaugeMetric => "network_gauge_metric",
            SignalKind::DnsQuery => "dns_query",
            SignalKind::DnsResponse => "dns_response",
            SignalKind::DnsCounterMetric => "dns_counter_metric",
            SignalKind::DnsLatencyMetric => "dns_latency_metric",
            SignalKind::DependencyEdge => "dependency_edge",
            SignalKind::RuntimeSecurityFinding => "runtime_security_finding",
            SignalKind::NodeCpuObservation => "node_cpu_observation",
            SignalKind::NodeLoadObservation => "node_load_observation",
            SignalKind::NodeMemoryObservation => "node_memory_observation",
            SignalKind::NodeFilesystemObservation => "node_filesystem_observation",
            SignalKind::NodeDiskIoObservation => "node_disk_io_observation",
            SignalKind::ProcessResourceObservation => "process_resource_observation",
            SignalKind::CgroupCpuObservation => "cgroup_cpu_observation",
            SignalKind::CgroupMemoryObservation => "cgroup_memory_observation",
            SignalKind::CgroupPidsObservation => "cgroup_pids_observation",
            SignalKind::CgroupFileDescriptorObservation => "cgroup_file_descriptor_observation",
            SignalKind::ResourceGaugeMetric => "resource_gauge_metric",
            SignalKind::ResourceCounterMetric => "resource_counter_metric",
            SignalKind::TraceSpanObservation => "trace_span_observation",
            SignalKind::ServiceInteractionSpanObservation => "service_interaction_span_observation",
            SignalKind::TraceServicePathObservation => "trace_service_path_observation",
            SignalKind::TraceCorrelationWarning => "trace_correlation_warning",
            SignalKind::ProtocolRequestObservation => "protocol_request_observation",
            SignalKind::ExtractedTraceContextObservation => "extracted_trace_context_observation",
            SignalKind::RequestSpanObservation => "request_span_observation",
            SignalKind::RequestCorrelationWarning => "request_correlation_warning",
            SignalKind::ProfileSampleObservation => "profile_sample_observation",
            SignalKind::ProfilingStackTraceObservation => "profiling_stack_trace_observation",
            SignalKind::ProfilingSessionObservation => "profiling_session_observation",
            SignalKind::ProfilingWarningObservation => "profiling_warning_observation",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        CgroupCpuObservation, CgroupFileDescriptorObservation, CgroupMemoryObservation,
        CgroupPidsObservation, CgroupResourceContext, DependencyEndpoint, DnsCounterMetric,
        DnsLatencyMetric, DnsQueryEvent, DnsQueryType, DnsResponseCode, DnsResponseEvent,
        MetricAggregationWindow, NetworkAddressFamily, NetworkCounterMetric, NetworkDurationMetric,
        NetworkFlowDirection, NetworkFlowEndpoint, NetworkGaugeMetric, NetworkProcessIdentity,
        NetworkProtocol, NodeCpuObservation, NodeDiskIoObservation, NodeFilesystemObservation,
        NodeLoadObservation, NodeMemoryObservation, ProcessResourceContext,
        ProcessResourceObservation, ResourceContext, ResourceCounterMetric, ResourceGaugeMetric,
        ResourceMetricAttribute, ServiceInteractionSpanObservation, TraceAttribute,
        TraceConfidence, TraceCorrelationKind, TraceCorrelationWarning, TracePeerContext,
        TraceServicePathObservation, TraceSpanObservation,
    };
    use crate::{MatchedNetworkConnection, MatchedProcess, RuntimeSecuritySeverity};

    #[test]
    fn serializes_exec_signal_with_version() {
        let signal = SignalEnvelope::exec(
            "source.test",
            Some("node-a".to_string()),
            ExecEvent {
                pid: 42,
                ppid: Some(1),
                uid: Some(1000),
                command: "bash".to_string(),
                executable: Some("/usr/bin/bash".to_string()),
                arguments: vec!["bash".to_string()],
                cgroup_id: Some(7),
                timestamp_unix_nanos: 123,
                container: None,
                kubernetes: None,
            },
        );

        let json = serde_json::to_value(&signal).expect("signal serializes");

        assert_eq!(json["schema_version"], 1);
        assert_eq!(json["kind"], "exec");
        assert_eq!(json["source"], "source.test");
        assert_eq!(json["host"], "node-a");
        assert_eq!(json["payload"]["pid"], 42);
        assert_eq!(json["payload"]["uid"], 1000);
        assert_eq!(json["payload"]["command"], "bash");
        assert_eq!(json["payload"]["executable"], "/usr/bin/bash");
        assert_eq!(json["payload"]["timestamp_unix_nanos"], 123);
        assert!(json["payload"].get("kind").is_none());
    }

    #[test]
    fn serializes_process_exit_signal_with_version() {
        let signal = SignalEnvelope::process_exit(
            "source.test",
            Some("node-a".to_string()),
            ProcessExitEvent {
                pid: 42,
                ppid: Some(1),
                uid: Some(1000),
                command: "bash".to_string(),
                cgroup_id: None,
                exit_code: Some(0),
                runtime_nanos: Some(55),
                timestamp_unix_nanos: 200,
                container: None,
                kubernetes: None,
            },
        );

        let json = serde_json::to_value(&signal).expect("signal serializes");

        assert_eq!(json["schema_version"], 1);
        assert_eq!(json["kind"], "process_exit");
        assert_eq!(json["source"], "source.test");
        assert_eq!(json["payload"]["pid"], 42);
        assert_eq!(json["payload"]["runtime_nanos"], 55);
    }

    #[test]
    fn serializes_process_lifecycle_duration_signal_with_version() {
        let signal = SignalEnvelope::process_lifecycle_duration(
            "generator.test",
            Some("node-a".to_string()),
            ProcessLifecycleDurationEvent {
                pid: 42,
                command: "bash".to_string(),
                started_at_unix_nanos: 100,
                exited_at_unix_nanos: 250,
                duration_nanos: 150,
                container: None,
                kubernetes: None,
            },
        );

        let json = serde_json::to_value(&signal).expect("signal serializes");

        assert_eq!(json["schema_version"], 1);
        assert_eq!(json["kind"], "process_lifecycle_duration");
        assert_eq!(json["payload"]["pid"], 42);
        assert_eq!(json["payload"]["duration_nanos"], 150);
    }

    #[test]
    fn exec_constructors_bound_strings_before_json_stdout() {
        let long = "e".repeat(320);
        let exec = SignalEnvelope::exec(
            "source.test",
            None,
            ExecEvent {
                pid: 42,
                ppid: Some(1),
                uid: Some(1000),
                command: long.clone(),
                executable: Some(long.clone()),
                arguments: vec![long.clone(); 40],
                cgroup_id: Some(7),
                timestamp_unix_nanos: 123,
                container: None,
                kubernetes: None,
            },
        );
        let exit = SignalEnvelope::process_exit(
            "source.test",
            None,
            ProcessExitEvent {
                pid: 42,
                ppid: Some(1),
                uid: Some(1000),
                command: long.clone(),
                cgroup_id: None,
                exit_code: Some(0),
                runtime_nanos: Some(55),
                timestamp_unix_nanos: 200,
                container: None,
                kubernetes: None,
            },
        );
        let lifecycle = SignalEnvelope::process_lifecycle_duration(
            "generator.test",
            None,
            ProcessLifecycleDurationEvent {
                pid: 42,
                command: long,
                started_at_unix_nanos: 100,
                exited_at_unix_nanos: 250,
                duration_nanos: 150,
                container: None,
                kubernetes: None,
            },
        );

        assert_payload_string_lengths(&exec, &[&["command"], &["executable"]]);
        let exec_json = serde_json::to_value(&exec).expect("exec serializes");
        let arguments = exec_json["payload"]["arguments"]
            .as_array()
            .expect("arguments serialize as an array");
        assert_eq!(arguments.len(), 32);
        assert!(
            arguments
                .iter()
                .all(|argument| argument.as_str().map(str::len) == Some(256))
        );
        assert_payload_string_lengths(&exit, &[&["command"]]);
        assert_payload_string_lengths(&lifecycle, &[&["command"]]);
    }

    #[test]
    fn runtime_security_constructor_bounds_strings_before_json_stdout() {
        let long = "s".repeat(320);
        let signal = SignalEnvelope::runtime_security_finding(
            "generator.runtime_security",
            None,
            RuntimeSecurityFinding {
                rule_id: long.clone(),
                severity: RuntimeSecuritySeverity::High,
                matched_process: MatchedProcess {
                    pid: 42,
                    command: long.clone(),
                    executable: Some(long.clone()),
                    arguments: vec![long.clone(); 40],
                },
                matched_connection: Some(MatchedNetworkConnection {
                    protocol: NetworkProtocol::Tcp,
                    remote_address: long.clone(),
                    remote_port: 443,
                    local_address: Some(long),
                    local_port: Some(43512),
                    fd: Some(7),
                }),
                container: None,
                kubernetes: None,
            },
        );

        assert_payload_string_lengths(
            &signal,
            &[
                &["rule_id"],
                &["matched_process", "command"],
                &["matched_process", "executable"],
                &["matched_connection", "remote_address"],
                &["matched_connection", "local_address"],
            ],
        );
        let json = serde_json::to_value(&signal).expect("finding serializes");
        let arguments = json["payload"]["matched_process"]["arguments"]
            .as_array()
            .expect("arguments serialize as an array");
        assert_eq!(arguments.len(), 32);
        assert!(
            arguments
                .iter()
                .all(|argument| argument.as_str().map(str::len) == Some(256))
        );
    }

    #[test]
    fn exec_constructors_bound_context_strings_before_json_stdout() {
        let long = "k".repeat(320);
        let exec = SignalEnvelope::exec(
            "source.test",
            None,
            ExecEvent {
                pid: 42,
                ppid: Some(1),
                uid: Some(1000),
                command: "bash".to_string(),
                executable: Some("/usr/bin/bash".to_string()),
                arguments: vec!["bash".to_string()],
                cgroup_id: Some(7),
                timestamp_unix_nanos: 123,
                container: Some(crate::ContainerContext {
                    container_id: long.clone(),
                    runtime: Some(long.clone()),
                }),
                kubernetes: Some(crate::KubernetesContext {
                    namespace: long.clone(),
                    pod_name: long.clone(),
                    pod_uid: Some(long.clone()),
                    container_name: Some(long.clone()),
                    node_name: Some(long.clone()),
                    labels: std::collections::BTreeMap::from_iter(
                        (0..20).map(|index| (format!("label-{index}-{long}"), long.clone())),
                    ),
                }),
            },
        );

        assert_payload_string_lengths(
            &exec,
            &[
                &["container", "container_id"],
                &["container", "runtime"],
                &["kubernetes", "namespace"],
                &["kubernetes", "pod_name"],
                &["kubernetes", "pod_uid"],
                &["kubernetes", "container_name"],
                &["kubernetes", "node_name"],
            ],
        );
        let json = serde_json::to_value(&exec).expect("exec serializes");
        let labels = json["payload"]["kubernetes"]["labels"]
            .as_object()
            .expect("labels serialize as an object");
        assert_eq!(labels.len(), 16);
        assert!(
            labels
                .iter()
                .all(|(key, value)| key.len() == 128 && value.as_str().map(str::len) == Some(256))
        );
    }

    #[test]
    fn serializes_network_connection_open_signal_with_version() {
        let signal = SignalEnvelope::network_connection_open(
            "source.test",
            Some("node-a".to_string()),
            NetworkConnectionOpenEvent {
                process: NetworkProcessIdentity {
                    pid: 42,
                    ppid: Some(1),
                    uid: Some(1000),
                    command: "api".to_string(),
                    executable: Some("/usr/bin/api".to_string()),
                    cgroup_id: None,
                },
                protocol: NetworkProtocol::Tcp,
                address_family: NetworkAddressFamily::Ipv4,
                local_address: Some("10.0.0.10".to_string()),
                local_port: Some(43512),
                remote_address: "10.0.0.20".to_string(),
                remote_port: 5432,
                fd: Some(7),
                timestamp_unix_nanos: 300,
                container: None,
                kubernetes: None,
            },
        );

        let json = serde_json::to_value(&signal).expect("signal serializes");

        assert_eq!(json["schema_version"], 1);
        assert_eq!(json["kind"], "network_connection_open");
        assert_eq!(json["payload"]["protocol"], "tcp");
        assert_eq!(json["payload"]["address_family"], "ipv4");
        assert_eq!(json["payload"]["process"]["pid"], 42);
        assert_eq!(json["payload"]["remote_address"], "10.0.0.20");
        assert_eq!(json["payload"]["remote_port"], 5432);
    }

    #[test]
    fn serializes_network_connection_close_signal_with_duration() {
        let signal = SignalEnvelope::network_connection_close(
            "source.test",
            Some("node-a".to_string()),
            NetworkConnectionCloseEvent {
                process: NetworkProcessIdentity {
                    pid: 42,
                    ppid: Some(1),
                    uid: Some(1000),
                    command: "api".to_string(),
                    executable: Some("/usr/bin/api".to_string()),
                    cgroup_id: None,
                },
                protocol: NetworkProtocol::Tcp,
                address_family: NetworkAddressFamily::Ipv4,
                local_address: Some("10.0.0.10".to_string()),
                local_port: Some(43512),
                remote_address: "10.0.0.20".to_string(),
                remote_port: 5432,
                fd: Some(7),
                opened_at_unix_nanos: Some(300),
                closed_at_unix_nanos: 900,
                duration_nanos: Some(600),
                bytes_sent: None,
                bytes_received: None,
                container: None,
                kubernetes: None,
            },
        );

        let json = serde_json::to_value(&signal).expect("signal serializes");

        assert_eq!(json["kind"], "network_connection_close");
        assert_eq!(json["payload"]["duration_nanos"], 600);
        assert_eq!(json["payload"]["closed_at_unix_nanos"], 900);
    }

    #[test]
    fn serializes_network_connection_failure_signal_with_errno() {
        let signal = SignalEnvelope::network_connection_failure(
            "source.test",
            Some("node-a".to_string()),
            NetworkConnectionFailureEvent {
                process: NetworkProcessIdentity {
                    pid: 42,
                    ppid: Some(1),
                    uid: Some(1000),
                    command: "api".to_string(),
                    executable: Some("/usr/bin/api".to_string()),
                    cgroup_id: None,
                },
                protocol: NetworkProtocol::Tcp,
                address_family: NetworkAddressFamily::Ipv4,
                remote_address: "203.0.113.10".to_string(),
                remote_port: 443,
                fd: Some(7),
                errno: 111,
                timestamp_unix_nanos: 350,
                container: None,
                kubernetes: None,
            },
        );

        let json = serde_json::to_value(&signal).expect("signal serializes");

        assert_eq!(json["kind"], "network_connection_failure");
        assert_eq!(json["payload"]["errno"], 111);
        assert_eq!(json["payload"]["remote_address"], "203.0.113.10");
    }

    #[test]
    fn network_connection_constructors_bound_strings_before_json_stdout() {
        let long = "x".repeat(300);
        let process = NetworkProcessIdentity {
            pid: 42,
            ppid: Some(1),
            uid: Some(1000),
            command: long.clone(),
            executable: Some(long.clone()),
            cgroup_id: None,
        };

        let open = SignalEnvelope::network_connection_open(
            "source.test",
            None,
            NetworkConnectionOpenEvent {
                process: process.clone(),
                protocol: NetworkProtocol::Tcp,
                address_family: NetworkAddressFamily::Ipv4,
                local_address: Some(long.clone()),
                local_port: Some(43512),
                remote_address: long.clone(),
                remote_port: 5432,
                fd: Some(7),
                timestamp_unix_nanos: 300,
                container: None,
                kubernetes: None,
            },
        );
        let close = SignalEnvelope::network_connection_close(
            "source.test",
            None,
            NetworkConnectionCloseEvent {
                process: process.clone(),
                protocol: NetworkProtocol::Tcp,
                address_family: NetworkAddressFamily::Ipv4,
                local_address: Some(long.clone()),
                local_port: Some(43512),
                remote_address: long.clone(),
                remote_port: 5432,
                fd: Some(7),
                opened_at_unix_nanos: Some(300),
                closed_at_unix_nanos: 900,
                duration_nanos: Some(600),
                bytes_sent: None,
                bytes_received: None,
                container: None,
                kubernetes: None,
            },
        );
        let failure = SignalEnvelope::network_connection_failure(
            "source.test",
            None,
            NetworkConnectionFailureEvent {
                process,
                protocol: NetworkProtocol::Tcp,
                address_family: NetworkAddressFamily::Ipv4,
                remote_address: long,
                remote_port: 443,
                fd: Some(7),
                errno: 111,
                timestamp_unix_nanos: 350,
                container: None,
                kubernetes: None,
            },
        );

        assert_payload_string_lengths(
            &open,
            &[
                &["process", "command"],
                &["process", "executable"],
                &["local_address"],
                &["remote_address"],
            ],
        );
        assert_payload_string_lengths(
            &close,
            &[
                &["process", "command"],
                &["process", "executable"],
                &["local_address"],
                &["remote_address"],
            ],
        );
        assert_payload_string_lengths(
            &failure,
            &[
                &["process", "command"],
                &["process", "executable"],
                &["remote_address"],
            ],
        );
    }

    #[test]
    fn network_connection_constructors_bound_context_strings_before_json_stdout() {
        let long = "n".repeat(320);
        let signal = SignalEnvelope::network_connection_open(
            "source.test",
            None,
            NetworkConnectionOpenEvent {
                process: network_process(),
                protocol: NetworkProtocol::Tcp,
                address_family: NetworkAddressFamily::Ipv4,
                local_address: Some("10.0.0.10".to_string()),
                local_port: Some(43512),
                remote_address: "10.0.0.20".to_string(),
                remote_port: 5432,
                fd: Some(7),
                timestamp_unix_nanos: 300,
                container: Some(crate::ContainerContext {
                    container_id: long.clone(),
                    runtime: Some(long.clone()),
                }),
                kubernetes: Some(crate::KubernetesContext {
                    namespace: long.clone(),
                    pod_name: long.clone(),
                    pod_uid: Some(long.clone()),
                    container_name: Some(long.clone()),
                    node_name: Some(long.clone()),
                    labels: std::collections::BTreeMap::from_iter(
                        (0..20).map(|index| (format!("label-{index}-{long}"), long.clone())),
                    ),
                }),
            },
        );

        assert_payload_string_lengths(
            &signal,
            &[
                &["container", "container_id"],
                &["container", "runtime"],
                &["kubernetes", "namespace"],
                &["kubernetes", "pod_name"],
                &["kubernetes", "pod_uid"],
                &["kubernetes", "container_name"],
                &["kubernetes", "node_name"],
            ],
        );
        assert_payload_label_bounds(&signal, &["kubernetes", "labels"]);
    }

    #[test]
    fn serializes_network_flow_warning_signal() {
        let signal = SignalEnvelope::network_flow_warning(
            "generator.network_metrics",
            Some("node-a".to_string()),
            NetworkFlowWarning {
                warning_type: "missing_attribution".to_string(),
                message: "byte-counted network flow has incomplete source attribution".to_string(),
                timestamp_unix_nanos: 900,
                source_signal_kind: "network_connection_close".to_string(),
                source_module: "source.test".to_string(),
                protocol: NetworkProtocol::Tcp,
                address_family: NetworkAddressFamily::Ipv4,
                remote_address: "203.0.113.10".to_string(),
                remote_port: 443,
                process: network_process(),
                container: None,
                kubernetes: None,
            },
        );

        let json = serde_json::to_value(&signal).expect("signal serializes");
        let decoded =
            serde_json::from_value::<SignalEnvelope>(json.clone()).expect("signal deserializes");

        assert_eq!(json["kind"], "network_flow_warning");
        assert_eq!(json["payload"]["warning_type"], "missing_attribution");
        assert_eq!(json["payload"]["source_module"], "source.test");
        assert_eq!(json["payload"]["remote_address"], "203.0.113.10");
        assert_eq!(decoded.signal_kind(), SignalKind::NetworkFlowWarning);

        let decoded_payload =
            serde_json::from_value::<SignalPayload>(json["payload"].clone()).expect("payload");
        assert!(matches!(
            decoded_payload,
            SignalPayload::NetworkFlowWarning(_)
        ));
    }

    #[test]
    fn network_flow_warning_constructor_bounds_strings_before_json_stdout() {
        let long = "x".repeat(300);
        let signal = SignalEnvelope::network_flow_warning(
            "generator.network_metrics",
            None,
            NetworkFlowWarning {
                warning_type: long.clone(),
                message: long.clone(),
                timestamp_unix_nanos: 900,
                source_signal_kind: long.clone(),
                source_module: long.clone(),
                protocol: NetworkProtocol::Tcp,
                address_family: NetworkAddressFamily::Ipv4,
                remote_address: long.clone(),
                remote_port: 443,
                process: NetworkProcessIdentity {
                    pid: 42,
                    ppid: Some(1),
                    uid: Some(1000),
                    command: long.clone(),
                    executable: Some(long),
                    cgroup_id: None,
                },
                container: None,
                kubernetes: None,
            },
        );

        assert_payload_string_lengths(
            &signal,
            &[
                &["warning_type"],
                &["message"],
                &["source_signal_kind"],
                &["source_module"],
                &["remote_address"],
                &["process", "command"],
                &["process", "executable"],
            ],
        );
    }

    #[test]
    fn serializes_dependency_edge_signal_with_observation_bounds() {
        let signal = SignalEnvelope::dependency_edge(
            "generator.test",
            Some("node-a".to_string()),
            DependencyEdgeEvent {
                source: DependencyEndpoint {
                    workload: None,
                    container: None,
                    address: None,
                    port: None,
                    domain: None,
                },
                destination: DependencyEndpoint {
                    workload: None,
                    container: None,
                    address: Some("203.0.113.10".to_string()),
                    port: Some(443),
                    domain: None,
                },
                protocol: NetworkProtocol::Tcp,
                observations: 2,
                first_seen_unix_nanos: 300,
                last_seen_unix_nanos: 350,
            },
        );

        let json = serde_json::to_value(&signal).expect("signal serializes");

        assert_eq!(json["kind"], "dependency_edge");
        assert_eq!(json["payload"]["observations"], 2);
        assert_eq!(json["payload"]["first_seen_unix_nanos"], 300);
        assert_eq!(json["payload"]["last_seen_unix_nanos"], 350);
    }

    #[test]
    fn network_endpoint_constructors_bound_strings_before_json_stdout() {
        let long = "x".repeat(300);
        let endpoint = NetworkFlowEndpoint {
            address: Some(long.clone()),
            port: Some(443),
            owner_name: Some(long.clone()),
            owner_type: Some(long.clone()),
            container: None,
            kubernetes: None,
        };
        let dependency_endpoint = DependencyEndpoint {
            workload: None,
            container: None,
            address: Some(long.clone()),
            port: Some(443),
            domain: Some(long.clone()),
        };

        let summary = SignalEnvelope::network_flow_summary(
            "generator.test",
            None,
            NetworkFlowSummaryEvent {
                source: endpoint.clone(),
                destination: endpoint,
                protocol: NetworkProtocol::Tcp,
                address_family: NetworkAddressFamily::Ipv4,
                bytes: 512,
                packets: Some(4),
                direction: NetworkFlowDirection::Egress,
                first_seen_unix_nanos: 300,
                last_seen_unix_nanos: 350,
            },
        );
        let dependency = SignalEnvelope::dependency_edge(
            "generator.test",
            None,
            DependencyEdgeEvent {
                source: dependency_endpoint.clone(),
                destination: dependency_endpoint,
                protocol: NetworkProtocol::Tcp,
                observations: 2,
                first_seen_unix_nanos: 300,
                last_seen_unix_nanos: 350,
            },
        );

        assert_payload_string_lengths(
            &summary,
            &[
                &["source", "address"],
                &["source", "owner_name"],
                &["source", "owner_type"],
                &["destination", "address"],
                &["destination", "owner_name"],
                &["destination", "owner_type"],
            ],
        );
        assert_payload_string_lengths(
            &dependency,
            &[
                &["source", "address"],
                &["source", "domain"],
                &["destination", "address"],
                &["destination", "domain"],
            ],
        );
    }

    #[test]
    fn network_endpoint_constructors_bound_context_strings_before_json_stdout() {
        let long = "w".repeat(320);
        let container = crate::ContainerContext {
            container_id: long.clone(),
            runtime: Some(long.clone()),
        };
        let kubernetes = crate::KubernetesContext {
            namespace: long.clone(),
            pod_name: long.clone(),
            pod_uid: Some(long.clone()),
            container_name: Some(long.clone()),
            node_name: Some(long.clone()),
            labels: std::collections::BTreeMap::from_iter(
                (0..20).map(|index| (format!("label-{index}-{long}"), long.clone())),
            ),
        };

        let summary = SignalEnvelope::network_flow_summary(
            "generator.test",
            None,
            NetworkFlowSummaryEvent {
                source: NetworkFlowEndpoint {
                    address: Some("10.0.0.5".to_string()),
                    port: Some(443),
                    owner_name: None,
                    owner_type: None,
                    container: Some(container.clone()),
                    kubernetes: Some(kubernetes.clone()),
                },
                destination: NetworkFlowEndpoint {
                    address: Some("10.0.0.6".to_string()),
                    port: Some(443),
                    owner_name: None,
                    owner_type: None,
                    container: Some(container.clone()),
                    kubernetes: Some(kubernetes.clone()),
                },
                protocol: NetworkProtocol::Tcp,
                address_family: NetworkAddressFamily::Ipv4,
                bytes: 512,
                packets: Some(4),
                direction: NetworkFlowDirection::Egress,
                first_seen_unix_nanos: 300,
                last_seen_unix_nanos: 350,
            },
        );
        let dependency = SignalEnvelope::dependency_edge(
            "generator.test",
            None,
            DependencyEdgeEvent {
                source: DependencyEndpoint {
                    workload: Some(kubernetes.clone()),
                    container: Some(container.clone()),
                    address: Some("10.0.0.5".to_string()),
                    port: Some(443),
                    domain: None,
                },
                destination: DependencyEndpoint {
                    workload: Some(kubernetes),
                    container: Some(container),
                    address: Some("10.0.0.6".to_string()),
                    port: Some(443),
                    domain: None,
                },
                protocol: NetworkProtocol::Tcp,
                observations: 2,
                first_seen_unix_nanos: 300,
                last_seen_unix_nanos: 350,
            },
        );

        assert_payload_string_lengths(
            &summary,
            &[
                &["source", "container", "container_id"],
                &["source", "container", "runtime"],
                &["source", "kubernetes", "namespace"],
                &["source", "kubernetes", "pod_name"],
                &["destination", "container", "container_id"],
                &["destination", "kubernetes", "container_name"],
            ],
        );
        assert_payload_label_bounds(&summary, &["source", "kubernetes", "labels"]);
        assert_payload_string_lengths(
            &dependency,
            &[
                &["source", "container", "container_id"],
                &["source", "workload", "namespace"],
                &["source", "workload", "pod_name"],
                &["destination", "container", "runtime"],
                &["destination", "workload", "container_name"],
            ],
        );
        assert_payload_label_bounds(&dependency, &["source", "workload", "labels"]);
    }

    #[test]
    fn serializes_trace_span_observation_signal_with_optional_context() {
        let signal = SignalEnvelope::trace_span_observation(
            "source.synthetic_exec",
            Some("node-a".to_string()),
            TraceSpanObservation {
                name: "synthetic checkout".to_string(),
                trace_id: Some("4bf92f3577b34da6a3ce929d0e0e4736".to_string()),
                span_id: Some("00f067aa0ba902b7".to_string()),
                parent_span_id: Some("f0f067aa0ba902b0".to_string()),
                start_unix_nanos: 1_000,
                end_unix_nanos: Some(3_000),
                duration_nanos: Some(2_000),
                correlation_kind: TraceCorrelationKind::Synthetic,
                confidence: TraceConfidence::High,
                service_name: Some("checkout-api".to_string()),
                process: Some(network_process()),
                container: Some(container_context()),
                kubernetes: Some(kubernetes_context()),
                peer: Some(trace_peer_context()),
                attributes: vec![TraceAttribute {
                    key: "net.transport".to_string(),
                    value: "tcp".to_string(),
                }],
            },
        );

        let json = serde_json::to_value(&signal).expect("signal serializes");
        let decoded =
            serde_json::from_value::<SignalEnvelope>(json.clone()).expect("signal deserializes");

        assert_eq!(json["schema_version"], 1);
        assert_eq!(json["kind"], "trace_span_observation");
        assert_eq!(
            json["payload"]["trace_id"],
            "4bf92f3577b34da6a3ce929d0e0e4736"
        );
        assert_eq!(json["payload"]["duration_nanos"], 2_000);
        assert_eq!(json["payload"]["correlation_kind"], "synthetic");
        assert_eq!(json["payload"]["confidence"], "high");
        assert_eq!(decoded.signal_kind(), SignalKind::TraceSpanObservation);
    }

    #[test]
    fn serializes_service_interaction_span_without_trace_ids() {
        let signal = SignalEnvelope::service_interaction_span_observation(
            "generator.trace_correlation",
            Some("node-a".to_string()),
            ServiceInteractionSpanObservation {
                name: "tcp client".to_string(),
                trace_id: None,
                span_id: None,
                parent_span_id: None,
                start_unix_nanos: 10_000,
                end_unix_nanos: Some(15_000),
                duration_nanos: Some(5_000),
                correlation_kind: TraceCorrelationKind::NetworkInferred,
                confidence: TraceConfidence::Medium,
                source: DependencyEndpoint {
                    workload: Some(kubernetes_context()),
                    container: Some(container_context()),
                    address: Some("10.0.0.5".to_string()),
                    port: Some(43512),
                    domain: None,
                },
                destination: DependencyEndpoint {
                    workload: None,
                    container: None,
                    address: Some("203.0.113.10".to_string()),
                    port: Some(443),
                    domain: None,
                },
                protocol: NetworkProtocol::Tcp,
                process: Some(network_process()),
                error_type: None,
                attributes: vec![],
            },
        );

        let json = serde_json::to_value(&signal).expect("signal serializes");
        let decoded =
            serde_json::from_value::<SignalEnvelope>(json.clone()).expect("signal deserializes");

        assert_eq!(json["kind"], "service_interaction_span_observation");
        assert!(json["payload"]["trace_id"].is_null());
        assert_eq!(json["payload"]["correlation_kind"], "network_inferred");
        assert_eq!(json["payload"]["destination"]["address"], "203.0.113.10");
        assert_eq!(
            decoded.signal_kind(),
            SignalKind::ServiceInteractionSpanObservation
        );
    }

    #[test]
    fn serializes_trace_service_path_observation() {
        let signal = SignalEnvelope::trace_service_path_observation(
            "generator.trace_correlation",
            Some("node-a".to_string()),
            TraceServicePathObservation {
                path_key: "trace-path:0123456789abcdef".to_string(),
                source: DependencyEndpoint {
                    workload: Some(kubernetes_context()),
                    container: Some(container_context()),
                    address: None,
                    port: None,
                    domain: None,
                },
                destination: DependencyEndpoint {
                    workload: None,
                    container: None,
                    address: Some("203.0.113.10".to_string()),
                    port: Some(443),
                    domain: Some("api.example.com".to_string()),
                },
                protocol: NetworkProtocol::Tcp,
                observations: 2,
                first_seen_unix_nanos: 1_000,
                last_seen_unix_nanos: 3_000,
                correlation_kind: TraceCorrelationKind::DependencyInferred,
                confidence: TraceConfidence::Low,
                attributes: vec![],
            },
        );

        let json = serde_json::to_value(&signal).expect("signal serializes");
        let decoded =
            serde_json::from_value::<SignalEnvelope>(json.clone()).expect("signal deserializes");

        assert_eq!(json["kind"], "trace_service_path_observation");
        assert_eq!(json["payload"]["path_key"], "trace-path:0123456789abcdef");
        assert_eq!(json["payload"]["observations"], 2);
        assert_eq!(json["payload"]["correlation_kind"], "dependency_inferred");
        assert_eq!(
            decoded.signal_kind(),
            SignalKind::TraceServicePathObservation
        );

        let decoded_payload =
            serde_json::from_value::<SignalPayload>(json["payload"].clone()).expect("payload");
        assert!(
            matches!(
                decoded_payload,
                SignalPayload::TraceServicePathObservation(_)
            ),
            "direct SignalPayload deserialization must preserve trace service path identity"
        );
    }

    #[test]
    fn trace_constructors_bound_and_filter_attributes_before_json_stdout() {
        let attributes = oversized_trace_attributes();
        let span = SignalEnvelope::trace_span_observation(
            "source.synthetic_exec",
            Some("node-a".to_string()),
            TraceSpanObservation {
                name: "synthetic checkout".to_string(),
                trace_id: None,
                span_id: None,
                parent_span_id: None,
                start_unix_nanos: 1_000,
                end_unix_nanos: Some(3_000),
                duration_nanos: Some(2_000),
                correlation_kind: TraceCorrelationKind::Synthetic,
                confidence: TraceConfidence::High,
                service_name: Some("checkout-api".to_string()),
                process: None,
                container: None,
                kubernetes: None,
                peer: None,
                attributes: attributes.clone(),
            },
        );
        let interaction = SignalEnvelope::service_interaction_span_observation(
            "generator.trace_correlation",
            Some("node-a".to_string()),
            ServiceInteractionSpanObservation {
                name: "tcp client".to_string(),
                trace_id: None,
                span_id: None,
                parent_span_id: None,
                start_unix_nanos: 10_000,
                end_unix_nanos: Some(15_000),
                duration_nanos: Some(5_000),
                correlation_kind: TraceCorrelationKind::NetworkInferred,
                confidence: TraceConfidence::Medium,
                source: DependencyEndpoint {
                    workload: None,
                    container: None,
                    address: Some("10.0.0.5".to_string()),
                    port: Some(43512),
                    domain: None,
                },
                destination: DependencyEndpoint {
                    workload: None,
                    container: None,
                    address: Some("203.0.113.10".to_string()),
                    port: Some(443),
                    domain: None,
                },
                protocol: NetworkProtocol::Tcp,
                process: None,
                error_type: None,
                attributes: attributes.clone(),
            },
        );
        let path = SignalEnvelope::trace_service_path_observation(
            "generator.trace_correlation",
            Some("node-a".to_string()),
            TraceServicePathObservation {
                path_key: "trace-path:0123456789abcdef".to_string(),
                source: DependencyEndpoint {
                    workload: None,
                    container: None,
                    address: Some("10.0.0.5".to_string()),
                    port: Some(43512),
                    domain: None,
                },
                destination: DependencyEndpoint {
                    workload: None,
                    container: None,
                    address: Some("203.0.113.10".to_string()),
                    port: Some(443),
                    domain: None,
                },
                protocol: NetworkProtocol::Tcp,
                observations: 2,
                first_seen_unix_nanos: 1_000,
                last_seen_unix_nanos: 3_000,
                correlation_kind: TraceCorrelationKind::DependencyInferred,
                confidence: TraceConfidence::Low,
                attributes,
            },
        );

        assert_bounded_safe_trace_attributes(&span);
        assert_bounded_safe_trace_attributes(&interaction);
        assert_bounded_safe_trace_attributes(&path);
    }

    #[test]
    fn trace_constructors_bound_scalar_strings_before_json_stdout() {
        let long_value = "t".repeat(320);
        let span = SignalEnvelope::trace_span_observation(
            "source.synthetic_exec",
            Some("node-a".to_string()),
            TraceSpanObservation {
                name: long_value.clone(),
                trace_id: None,
                span_id: None,
                parent_span_id: None,
                start_unix_nanos: 1_000,
                end_unix_nanos: Some(3_000),
                duration_nanos: Some(2_000),
                correlation_kind: TraceCorrelationKind::Synthetic,
                confidence: TraceConfidence::High,
                service_name: Some(long_value.clone()),
                process: None,
                container: None,
                kubernetes: None,
                peer: None,
                attributes: vec![],
            },
        );
        let interaction = SignalEnvelope::service_interaction_span_observation(
            "generator.trace_correlation",
            Some("node-a".to_string()),
            ServiceInteractionSpanObservation {
                name: long_value.clone(),
                trace_id: None,
                span_id: None,
                parent_span_id: None,
                start_unix_nanos: 10_000,
                end_unix_nanos: Some(15_000),
                duration_nanos: Some(5_000),
                correlation_kind: TraceCorrelationKind::NetworkInferred,
                confidence: TraceConfidence::Medium,
                source: DependencyEndpoint {
                    workload: None,
                    container: None,
                    address: None,
                    port: None,
                    domain: None,
                },
                destination: DependencyEndpoint {
                    workload: None,
                    container: None,
                    address: None,
                    port: None,
                    domain: None,
                },
                protocol: NetworkProtocol::Tcp,
                process: None,
                error_type: Some(long_value.clone()),
                attributes: vec![],
            },
        );
        let path = SignalEnvelope::trace_service_path_observation(
            "generator.trace_correlation",
            Some("node-a".to_string()),
            TraceServicePathObservation {
                path_key: long_value.clone(),
                source: DependencyEndpoint {
                    workload: None,
                    container: None,
                    address: None,
                    port: None,
                    domain: None,
                },
                destination: DependencyEndpoint {
                    workload: None,
                    container: None,
                    address: None,
                    port: None,
                    domain: None,
                },
                protocol: NetworkProtocol::Tcp,
                observations: 2,
                first_seen_unix_nanos: 1_000,
                last_seen_unix_nanos: 3_000,
                correlation_kind: TraceCorrelationKind::DependencyInferred,
                confidence: TraceConfidence::Low,
                attributes: vec![],
            },
        );
        let warning = SignalEnvelope::trace_correlation_warning(
            "generator.trace_correlation",
            Some("node-a".to_string()),
            TraceCorrelationWarning {
                warning_type: long_value.clone(),
                message: long_value.clone(),
                timestamp_unix_nanos: 1_200,
                source_signal_kind: long_value.clone(),
                source_module: long_value,
                correlation_kind: TraceCorrelationKind::NetworkInferred,
                process: None,
                container: None,
                kubernetes: None,
                peer: None,
            },
        );

        let span_json = serde_json::to_value(&span).expect("span serializes");
        let interaction_json = serde_json::to_value(&interaction).expect("interaction serializes");
        let path_json = serde_json::to_value(&path).expect("path serializes");
        let warning_json = serde_json::to_value(&warning).expect("warning serializes");

        assert_eq!(
            span_json["payload"]["name"].as_str().map(str::len),
            Some(256)
        );
        assert_eq!(
            span_json["payload"]["service_name"].as_str().map(str::len),
            Some(256)
        );
        assert_eq!(
            interaction_json["payload"]["name"].as_str().map(str::len),
            Some(256)
        );
        assert_eq!(
            interaction_json["payload"]["error_type"]
                .as_str()
                .map(str::len),
            Some(256)
        );
        assert_eq!(
            path_json["payload"]["path_key"].as_str().map(str::len),
            Some(256)
        );
        assert_eq!(
            warning_json["payload"]["message"].as_str().map(str::len),
            Some(256)
        );
        assert_eq!(
            warning_json["payload"]["source_module"]
                .as_str()
                .map(str::len),
            Some(256)
        );
    }

    #[test]
    fn trace_constructors_bound_context_strings_before_json_stdout() {
        let long = "t".repeat(320);
        let process = NetworkProcessIdentity {
            pid: 42,
            ppid: Some(1),
            uid: Some(1000),
            command: long.clone(),
            executable: Some(long.clone()),
            cgroup_id: None,
        };
        let container = crate::ContainerContext {
            container_id: long.clone(),
            runtime: Some(long.clone()),
        };
        let kubernetes = crate::KubernetesContext {
            namespace: long.clone(),
            pod_name: long.clone(),
            pod_uid: Some(long.clone()),
            container_name: Some(long.clone()),
            node_name: Some(long.clone()),
            labels: std::collections::BTreeMap::from_iter(
                (0..20).map(|index| (format!("label-{index}-{long}"), long.clone())),
            ),
        };
        let peer = TracePeerContext {
            address: Some(long.clone()),
            port: Some(443),
            domain: Some(long.clone()),
            workload: Some(kubernetes.clone()),
            container: Some(container.clone()),
        };
        let endpoint = DependencyEndpoint {
            workload: Some(kubernetes.clone()),
            container: Some(container.clone()),
            address: Some(long.clone()),
            port: Some(443),
            domain: Some(long.clone()),
        };

        let span = SignalEnvelope::trace_span_observation(
            "source.synthetic_exec",
            None,
            TraceSpanObservation {
                name: "synthetic checkout".to_string(),
                trace_id: None,
                span_id: None,
                parent_span_id: None,
                start_unix_nanos: 1_000,
                end_unix_nanos: Some(3_000),
                duration_nanos: Some(2_000),
                correlation_kind: TraceCorrelationKind::Synthetic,
                confidence: TraceConfidence::High,
                service_name: Some("checkout-api".to_string()),
                process: Some(process.clone()),
                container: Some(container.clone()),
                kubernetes: Some(kubernetes.clone()),
                peer: Some(peer.clone()),
                attributes: vec![],
            },
        );
        let interaction = SignalEnvelope::service_interaction_span_observation(
            "generator.trace_correlation",
            None,
            ServiceInteractionSpanObservation {
                name: "tcp client".to_string(),
                trace_id: None,
                span_id: None,
                parent_span_id: None,
                start_unix_nanos: 10_000,
                end_unix_nanos: Some(15_000),
                duration_nanos: Some(5_000),
                correlation_kind: TraceCorrelationKind::NetworkInferred,
                confidence: TraceConfidence::Medium,
                source: endpoint.clone(),
                destination: endpoint.clone(),
                protocol: NetworkProtocol::Tcp,
                process: Some(process.clone()),
                error_type: None,
                attributes: vec![],
            },
        );
        let path = SignalEnvelope::trace_service_path_observation(
            "generator.trace_correlation",
            None,
            TraceServicePathObservation {
                path_key: "trace-path:0123456789abcdef".to_string(),
                source: endpoint.clone(),
                destination: endpoint,
                protocol: NetworkProtocol::Tcp,
                observations: 2,
                first_seen_unix_nanos: 1_000,
                last_seen_unix_nanos: 3_000,
                correlation_kind: TraceCorrelationKind::DependencyInferred,
                confidence: TraceConfidence::Low,
                attributes: vec![],
            },
        );
        let warning = SignalEnvelope::trace_correlation_warning(
            "generator.trace_correlation",
            None,
            TraceCorrelationWarning {
                warning_type: "missing_attribution".to_string(),
                message: "trace correlation source signal has no context".to_string(),
                timestamp_unix_nanos: 1_000,
                source_signal_kind: "network_connection_open".to_string(),
                source_module: "source.test".to_string(),
                correlation_kind: TraceCorrelationKind::NetworkInferred,
                process: Some(process),
                container: Some(container),
                kubernetes: Some(kubernetes),
                peer: Some(peer),
            },
        );

        for signal in [&span, &warning] {
            assert_payload_string_lengths(
                signal,
                &[
                    &["process", "command"],
                    &["process", "executable"],
                    &["container", "container_id"],
                    &["container", "runtime"],
                    &["kubernetes", "namespace"],
                    &["kubernetes", "pod_name"],
                    &["kubernetes", "pod_uid"],
                    &["kubernetes", "container_name"],
                    &["kubernetes", "node_name"],
                    &["peer", "address"],
                    &["peer", "domain"],
                    &["peer", "container", "container_id"],
                    &["peer", "workload", "namespace"],
                ],
            );
            assert_payload_label_bounds(signal, &["kubernetes", "labels"]);
            assert_payload_label_bounds(signal, &["peer", "workload", "labels"]);
        }

        assert_payload_string_lengths(
            &interaction,
            &[
                &["process", "command"],
                &["process", "executable"],
                &["source", "address"],
                &["source", "domain"],
                &["source", "container", "container_id"],
                &["source", "workload", "namespace"],
                &["destination", "address"],
                &["destination", "domain"],
                &["destination", "container", "runtime"],
                &["destination", "workload", "node_name"],
            ],
        );
        assert_payload_label_bounds(&interaction, &["source", "workload", "labels"]);
        assert_payload_label_bounds(&interaction, &["destination", "workload", "labels"]);
        assert_payload_string_lengths(
            &path,
            &[
                &["source", "address"],
                &["source", "domain"],
                &["source", "container", "container_id"],
                &["source", "workload", "namespace"],
                &["destination", "address"],
                &["destination", "domain"],
                &["destination", "container", "runtime"],
                &["destination", "workload", "node_name"],
            ],
        );
        assert_payload_label_bounds(&path, &["source", "workload", "labels"]);
        assert_payload_label_bounds(&path, &["destination", "workload", "labels"]);
    }

    #[test]
    fn serializes_trace_correlation_warning_signal() {
        let signal = SignalEnvelope::trace_correlation_warning(
            "generator.trace_correlation",
            Some("node-a".to_string()),
            TraceCorrelationWarning {
                warning_type: "missing_attribution".to_string(),
                message: "network observation has no container or Kubernetes context".to_string(),
                timestamp_unix_nanos: 1_000,
                source_signal_kind: "network_connection_open".to_string(),
                source_module: "source.test".to_string(),
                correlation_kind: TraceCorrelationKind::NetworkInferred,
                process: None,
                container: None,
                kubernetes: None,
                peer: Some(trace_peer_context()),
            },
        );

        let json = serde_json::to_value(&signal).expect("signal serializes");
        let decoded =
            serde_json::from_value::<SignalEnvelope>(json.clone()).expect("signal deserializes");

        assert_eq!(json["kind"], "trace_correlation_warning");
        assert_eq!(json["payload"]["warning_type"], "missing_attribution");
        assert_eq!(json["payload"]["correlation_kind"], "network_inferred");
        assert_eq!(decoded.signal_kind(), SignalKind::TraceCorrelationWarning);
    }

    #[test]
    fn rejects_deserializing_mismatched_kind_and_payload() {
        let json = serde_json::json!({
            "schema_version": 1,
            "kind": "network_connection_failure",
            "source": "source.test",
            "host": null,
            "payload": {
                "process": {
                    "pid": 42,
                    "ppid": null,
                    "uid": 1000,
                    "command": "api",
                    "executable": "/usr/bin/api"
                },
                "protocol": "tcp",
                "address_family": "ipv4",
                "local_address": "10.0.0.10",
                "local_port": 43512,
                "remote_address": "10.0.0.20",
                "remote_port": 5432,
                "fd": 7,
                "timestamp_unix_nanos": 300,
                "container": null,
                "kubernetes": null
            }
        });

        let err = serde_json::from_value::<SignalEnvelope>(json)
            .expect_err("mismatched kind and payload must be rejected");

        assert!(err.to_string().contains("payload"));
    }

    #[test]
    fn serializes_network_counter_metric_signal() {
        let metric = NetworkCounterMetric {
            metric_name: "network.connection.open.count".to_string(),
            unit: "{connection}".to_string(),
            value: 1,
            window: MetricAggregationWindow {
                start_unix_nanos: 100,
                end_unix_nanos: 100,
            },
            process: Some(network_process()),
            protocol: Some(NetworkProtocol::Tcp),
            address_family: Some(NetworkAddressFamily::Ipv4),
            local_address: Some("10.0.0.5".to_string()),
            local_port: Some(43512),
            remote_address: Some("203.0.113.10".to_string()),
            remote_port: Some(443),
            errno: None,
            container: None,
            kubernetes: None,
        };
        let signal =
            SignalEnvelope::network_counter_metric("generator.test", Some("node-a".into()), metric);

        let json = serde_json::to_value(&signal).expect("signal serializes");
        let decoded: SignalEnvelope = serde_json::from_value(json.clone()).expect("round trips");

        assert_eq!(json["kind"], "network_counter_metric");
        assert_eq!(
            json["payload"]["metric_name"],
            "network.connection.open.count"
        );
        assert_eq!(json["payload"]["unit"], "{connection}");
        assert_eq!(json["payload"]["value"], 1);
        assert_eq!(json["payload"]["window"]["start_unix_nanos"], 100);
        assert!(matches!(
            decoded.payload,
            SignalPayload::NetworkCounterMetric(_)
        ));
    }

    #[test]
    fn serializes_network_duration_metric_signal() {
        let metric = NetworkDurationMetric {
            metric_name: "network.connection.duration".to_string(),
            unit: "ns".to_string(),
            count: 1,
            sum_nanos: 600,
            min_nanos: 600,
            max_nanos: 600,
            window: MetricAggregationWindow {
                start_unix_nanos: 300,
                end_unix_nanos: 900,
            },
            process: Some(network_process()),
            protocol: Some(NetworkProtocol::Tcp),
            address_family: Some(NetworkAddressFamily::Ipv4),
            remote_address: Some("203.0.113.10".to_string()),
            remote_port: Some(443),
            container: None,
            kubernetes: None,
        };
        let signal = SignalEnvelope::network_duration_metric("generator.test", None, metric);

        let json = serde_json::to_value(&signal).expect("signal serializes");
        let decoded: SignalEnvelope = serde_json::from_value(json.clone()).expect("round trips");

        assert_eq!(json["kind"], "network_duration_metric");
        assert_eq!(
            json["payload"]["metric_name"],
            "network.connection.duration"
        );
        assert_eq!(json["payload"]["unit"], "ns");
        assert_eq!(json["payload"]["count"], 1);
        assert_eq!(json["payload"]["sum_nanos"], 600);
        assert!(matches!(
            decoded.payload,
            SignalPayload::NetworkDurationMetric(_)
        ));
    }

    #[test]
    fn serializes_network_gauge_metric_signal() {
        let metric = NetworkGaugeMetric {
            metric_name: "network.connection.active".to_string(),
            unit: "{connection}".to_string(),
            value: 1,
            window: MetricAggregationWindow {
                start_unix_nanos: 300,
                end_unix_nanos: 900,
            },
            process: Some(network_process()),
            protocol: Some(NetworkProtocol::Tcp),
            address_family: Some(NetworkAddressFamily::Ipv4),
            remote_address: Some("203.0.113.10".to_string()),
            remote_port: Some(443),
            container: None,
            kubernetes: None,
        };
        let signal = SignalEnvelope::network_gauge_metric("generator.test", None, metric);

        let json = serde_json::to_value(&signal).expect("signal serializes");
        let decoded: SignalEnvelope = serde_json::from_value(json.clone()).expect("round trips");

        assert_eq!(json["kind"], "network_gauge_metric");
        assert_eq!(json["payload"]["metric_name"], "network.connection.active");
        assert_eq!(json["payload"]["value"], 1);
        assert!(matches!(
            decoded.payload,
            SignalPayload::NetworkGaugeMetric(_)
        ));
    }

    #[test]
    fn network_metric_constructors_bound_strings_before_json_stdout() {
        let long = "x".repeat(300);
        let process = NetworkProcessIdentity {
            pid: 42,
            ppid: Some(1),
            uid: Some(1000),
            command: long.clone(),
            executable: Some(long.clone()),
            cgroup_id: None,
        };
        let window = MetricAggregationWindow {
            start_unix_nanos: 300,
            end_unix_nanos: 900,
        };

        let counter = SignalEnvelope::network_counter_metric(
            "generator.test",
            None,
            NetworkCounterMetric {
                metric_name: long.clone(),
                unit: long.clone(),
                value: 1,
                window: window.clone(),
                process: Some(process.clone()),
                protocol: Some(NetworkProtocol::Tcp),
                address_family: Some(NetworkAddressFamily::Ipv4),
                local_address: Some(long.clone()),
                local_port: Some(43512),
                remote_address: Some(long.clone()),
                remote_port: Some(443),
                errno: None,
                container: None,
                kubernetes: None,
            },
        );
        let duration = SignalEnvelope::network_duration_metric(
            "generator.test",
            None,
            NetworkDurationMetric {
                metric_name: long.clone(),
                unit: long.clone(),
                count: 1,
                sum_nanos: 600,
                min_nanos: 600,
                max_nanos: 600,
                window: window.clone(),
                process: Some(process.clone()),
                protocol: Some(NetworkProtocol::Tcp),
                address_family: Some(NetworkAddressFamily::Ipv4),
                remote_address: Some(long.clone()),
                remote_port: Some(443),
                container: None,
                kubernetes: None,
            },
        );
        let gauge = SignalEnvelope::network_gauge_metric(
            "generator.test",
            None,
            NetworkGaugeMetric {
                metric_name: long.clone(),
                unit: long,
                value: 1,
                window,
                process: Some(process),
                protocol: Some(NetworkProtocol::Tcp),
                address_family: Some(NetworkAddressFamily::Ipv4),
                remote_address: Some("x".repeat(300)),
                remote_port: Some(443),
                container: None,
                kubernetes: None,
            },
        );

        assert_payload_string_lengths(
            &counter,
            &[
                &["process", "command"],
                &["process", "executable"],
                &["local_address"],
                &["remote_address"],
            ],
        );
        assert_payload_string_lengths(
            &duration,
            &[
                &["process", "command"],
                &["process", "executable"],
                &["remote_address"],
            ],
        );
        assert_payload_string_lengths(
            &gauge,
            &[
                &["process", "command"],
                &["process", "executable"],
                &["remote_address"],
            ],
        );

        let counter_json = serde_json::to_value(counter).expect("counter serializes");
        let duration_json = serde_json::to_value(duration).expect("duration serializes");
        let gauge_json = serde_json::to_value(gauge).expect("gauge serializes");

        assert_eq!(
            counter_json["payload"]["metric_name"]
                .as_str()
                .expect("metric name")
                .len(),
            256
        );
        assert_eq!(
            counter_json["payload"]["unit"]
                .as_str()
                .expect("unit")
                .len(),
            256
        );
        assert_eq!(
            counter_json["payload"]["local_address"]
                .as_str()
                .expect("local address")
                .len(),
            256
        );
        assert_eq!(
            counter_json["payload"]["remote_address"]
                .as_str()
                .expect("remote address")
                .len(),
            256
        );
        assert_eq!(
            duration_json["payload"]["metric_name"]
                .as_str()
                .expect("metric name")
                .len(),
            256
        );
        assert_eq!(
            duration_json["payload"]["unit"]
                .as_str()
                .expect("unit")
                .len(),
            256
        );
        assert_eq!(
            duration_json["payload"]["remote_address"]
                .as_str()
                .expect("remote address")
                .len(),
            256
        );
        assert_eq!(
            gauge_json["payload"]["metric_name"]
                .as_str()
                .expect("metric name")
                .len(),
            256
        );
        assert_eq!(
            gauge_json["payload"]["unit"].as_str().expect("unit").len(),
            256
        );
        assert_eq!(
            gauge_json["payload"]["remote_address"]
                .as_str()
                .expect("remote address")
                .len(),
            256
        );
    }

    #[test]
    fn network_metric_constructors_bound_context_strings_before_json_stdout() {
        let long = "m".repeat(320);
        let container = crate::ContainerContext {
            container_id: long.clone(),
            runtime: Some(long.clone()),
        };
        let kubernetes = crate::KubernetesContext {
            namespace: long.clone(),
            pod_name: long.clone(),
            pod_uid: Some(long.clone()),
            container_name: Some(long.clone()),
            node_name: Some(long.clone()),
            labels: std::collections::BTreeMap::from_iter(
                (0..20).map(|index| (format!("label-{index}-{long}"), long.clone())),
            ),
        };
        let window = MetricAggregationWindow {
            start_unix_nanos: 300,
            end_unix_nanos: 900,
        };

        let counter = SignalEnvelope::network_counter_metric(
            "generator.test",
            None,
            NetworkCounterMetric {
                metric_name: "network.connection.attempts".to_string(),
                unit: "{connection}".to_string(),
                value: 1,
                window: window.clone(),
                process: Some(network_process()),
                protocol: Some(NetworkProtocol::Tcp),
                address_family: Some(NetworkAddressFamily::Ipv4),
                local_address: Some("10.0.0.10".to_string()),
                local_port: Some(43512),
                remote_address: Some("203.0.113.10".to_string()),
                remote_port: Some(443),
                errno: None,
                container: Some(container.clone()),
                kubernetes: Some(kubernetes.clone()),
            },
        );
        let duration = SignalEnvelope::network_duration_metric(
            "generator.test",
            None,
            NetworkDurationMetric {
                metric_name: "network.connection.duration".to_string(),
                unit: "ns".to_string(),
                count: 1,
                sum_nanos: 600,
                min_nanos: 600,
                max_nanos: 600,
                window: window.clone(),
                process: Some(network_process()),
                protocol: Some(NetworkProtocol::Tcp),
                address_family: Some(NetworkAddressFamily::Ipv4),
                remote_address: Some("203.0.113.10".to_string()),
                remote_port: Some(443),
                container: Some(container.clone()),
                kubernetes: Some(kubernetes.clone()),
            },
        );
        let gauge = SignalEnvelope::network_gauge_metric(
            "generator.test",
            None,
            NetworkGaugeMetric {
                metric_name: "network.connection.active".to_string(),
                unit: "{connection}".to_string(),
                value: 1,
                window,
                process: Some(network_process()),
                protocol: Some(NetworkProtocol::Tcp),
                address_family: Some(NetworkAddressFamily::Ipv4),
                remote_address: Some("203.0.113.10".to_string()),
                remote_port: Some(443),
                container: Some(container),
                kubernetes: Some(kubernetes),
            },
        );

        for signal in [counter, duration, gauge] {
            assert_payload_string_lengths(
                &signal,
                &[
                    &["container", "container_id"],
                    &["container", "runtime"],
                    &["kubernetes", "namespace"],
                    &["kubernetes", "pod_name"],
                    &["kubernetes", "pod_uid"],
                    &["kubernetes", "container_name"],
                    &["kubernetes", "node_name"],
                ],
            );
            assert_payload_label_bounds(&signal, &["kubernetes", "labels"]);
        }
    }

    #[test]
    fn serializes_dns_query_and_response_signals() {
        let query = SignalEnvelope::dns_query(
            "source.synthetic_dns",
            Some("node-a".to_string()),
            DnsQueryEvent {
                process: network_process(),
                query_name: "api.example.com".to_string(),
                query_type: DnsQueryType::A,
                transport_protocol: NetworkProtocol::Udp,
                server_address: Some("10.96.0.10".to_string()),
                server_port: Some(53),
                timestamp_unix_nanos: 400,
                container: None,
                kubernetes: None,
            },
        );
        let response = SignalEnvelope::dns_response(
            "source.synthetic_dns",
            Some("node-a".to_string()),
            DnsResponseEvent {
                process: network_process(),
                query_name: "missing.example.com".to_string(),
                query_type: DnsQueryType::Aaaa,
                response_code: DnsResponseCode::NxDomain,
                latency_nanos: Some(15_000),
                transport_protocol: NetworkProtocol::Udp,
                server_address: Some("10.96.0.10".to_string()),
                server_port: Some(53),
                timestamp_unix_nanos: 415,
                container: None,
                kubernetes: None,
            },
        );

        let query_json = serde_json::to_value(&query).expect("query serializes");
        let response_json = serde_json::to_value(&response).expect("response serializes");

        assert_eq!(query_json["kind"], "dns_query");
        assert_eq!(query_json["payload"]["query_name"], "api.example.com");
        assert_eq!(query_json["payload"]["query_type"], "a");
        assert_eq!(response_json["kind"], "dns_response");
        assert_eq!(response_json["payload"]["response_code"], "nx_domain");
        assert!(matches!(
            serde_json::from_value::<SignalEnvelope>(query_json)
                .expect("query round trips")
                .payload,
            SignalPayload::DnsQuery(_)
        ));
        assert!(matches!(
            serde_json::from_value::<SignalEnvelope>(response_json)
                .expect("response round trips")
                .payload,
            SignalPayload::DnsResponse(_)
        ));
    }

    #[test]
    fn serializes_dns_metric_signals() {
        let counter = SignalEnvelope::dns_counter_metric(
            "generator.dns_metrics",
            Some("node-a".to_string()),
            DnsCounterMetric {
                metric_name: "dns.query.count".to_string(),
                unit: "{query}".to_string(),
                value: 1,
                window: MetricAggregationWindow {
                    start_unix_nanos: 400,
                    end_unix_nanos: 415,
                },
                query_name: Some("api.example.com".to_string()),
                query_type: Some(DnsQueryType::A),
                response_code: None,
                server_address: Some("10.96.0.10".to_string()),
                server_port: Some(53),
                container: None,
                kubernetes: None,
            },
        );
        let latency = SignalEnvelope::dns_latency_metric(
            "generator.dns_metrics",
            Some("node-a".to_string()),
            DnsLatencyMetric {
                metric_name: "dns.lookup.duration".to_string(),
                unit: "ns".to_string(),
                count: 1,
                sum_nanos: 15_000,
                min_nanos: 15_000,
                max_nanos: 15_000,
                window: MetricAggregationWindow {
                    start_unix_nanos: 400,
                    end_unix_nanos: 415,
                },
                query_name: Some("api.example.com".to_string()),
                query_type: Some(DnsQueryType::A),
                response_code: Some(DnsResponseCode::NoError),
                server_address: Some("10.96.0.10".to_string()),
                server_port: Some(53),
                container: None,
                kubernetes: None,
            },
        );

        let counter_json = serde_json::to_value(&counter).expect("counter serializes");
        let latency_json = serde_json::to_value(&latency).expect("latency serializes");

        assert_eq!(counter_json["kind"], "dns_counter_metric");
        assert_eq!(counter_json["payload"]["metric_name"], "dns.query.count");
        assert_eq!(latency_json["kind"], "dns_latency_metric");
        assert_eq!(
            latency_json["payload"]["metric_name"],
            "dns.lookup.duration"
        );
        assert!(matches!(
            serde_json::from_value::<SignalEnvelope>(counter_json)
                .expect("counter round trips")
                .payload,
            SignalPayload::DnsCounterMetric(_)
        ));
        assert!(matches!(
            serde_json::from_value::<SignalEnvelope>(latency_json)
                .expect("latency round trips")
                .payload,
            SignalPayload::DnsLatencyMetric(_)
        ));
    }

    #[test]
    fn dns_constructors_bound_strings_before_json_stdout() {
        let long_value = "d".repeat(320);
        let process = NetworkProcessIdentity {
            pid: 42,
            ppid: Some(1),
            uid: Some(1000),
            command: long_value.clone(),
            executable: Some(long_value.clone()),
            cgroup_id: None,
        };
        let query = SignalEnvelope::dns_query(
            "source.synthetic_dns",
            Some("node-a".to_string()),
            DnsQueryEvent {
                process: process.clone(),
                query_name: long_value.clone(),
                query_type: DnsQueryType::A,
                transport_protocol: NetworkProtocol::Udp,
                server_address: Some(long_value.clone()),
                server_port: Some(53),
                timestamp_unix_nanos: 400,
                container: None,
                kubernetes: None,
            },
        );
        let response = SignalEnvelope::dns_response(
            "source.synthetic_dns",
            Some("node-a".to_string()),
            DnsResponseEvent {
                process,
                query_name: long_value.clone(),
                query_type: DnsQueryType::Aaaa,
                response_code: DnsResponseCode::NxDomain,
                latency_nanos: Some(15_000),
                transport_protocol: NetworkProtocol::Udp,
                server_address: Some(long_value.clone()),
                server_port: Some(53),
                timestamp_unix_nanos: 415,
                container: None,
                kubernetes: None,
            },
        );
        let counter = SignalEnvelope::dns_counter_metric(
            "generator.dns_metrics",
            Some("node-a".to_string()),
            DnsCounterMetric {
                metric_name: long_value.clone(),
                unit: long_value.clone(),
                value: 1,
                window: MetricAggregationWindow {
                    start_unix_nanos: 400,
                    end_unix_nanos: 415,
                },
                query_name: Some(long_value.clone()),
                query_type: Some(DnsQueryType::A),
                response_code: None,
                server_address: Some(long_value.clone()),
                server_port: Some(53),
                container: None,
                kubernetes: None,
            },
        );
        let latency = SignalEnvelope::dns_latency_metric(
            "generator.dns_metrics",
            Some("node-a".to_string()),
            DnsLatencyMetric {
                metric_name: long_value.clone(),
                unit: long_value,
                count: 1,
                sum_nanos: 15_000,
                min_nanos: 15_000,
                max_nanos: 15_000,
                window: MetricAggregationWindow {
                    start_unix_nanos: 400,
                    end_unix_nanos: 415,
                },
                query_name: Some("q".repeat(320)),
                query_type: Some(DnsQueryType::A),
                response_code: Some(DnsResponseCode::NoError),
                server_address: Some("s".repeat(320)),
                server_port: Some(53),
                container: None,
                kubernetes: None,
            },
        );

        assert_dns_string_lengths(&query, &["query_name", "server_address"]);
        assert_dns_string_lengths(&response, &["query_name", "server_address"]);
        assert_payload_string_lengths(
            &query,
            &[&["process", "command"], &["process", "executable"]],
        );
        assert_payload_string_lengths(
            &response,
            &[&["process", "command"], &["process", "executable"]],
        );
        assert_dns_string_lengths(
            &counter,
            &["metric_name", "unit", "query_name", "server_address"],
        );
        assert_dns_string_lengths(
            &latency,
            &["metric_name", "unit", "query_name", "server_address"],
        );
    }

    #[test]
    fn dns_constructors_bound_context_strings_before_json_stdout() {
        let long = "d".repeat(320);
        let container = crate::ContainerContext {
            container_id: long.clone(),
            runtime: Some(long.clone()),
        };
        let kubernetes = crate::KubernetesContext {
            namespace: long.clone(),
            pod_name: long.clone(),
            pod_uid: Some(long.clone()),
            container_name: Some(long.clone()),
            node_name: Some(long.clone()),
            labels: std::collections::BTreeMap::from_iter(
                (0..20).map(|index| (format!("label-{index}-{long}"), long.clone())),
            ),
        };
        let window = MetricAggregationWindow {
            start_unix_nanos: 400,
            end_unix_nanos: 415,
        };

        let query = SignalEnvelope::dns_query(
            "source.synthetic_dns",
            None,
            DnsQueryEvent {
                process: network_process(),
                query_name: "api.example.com".to_string(),
                query_type: DnsQueryType::A,
                transport_protocol: NetworkProtocol::Udp,
                server_address: Some("10.96.0.10".to_string()),
                server_port: Some(53),
                timestamp_unix_nanos: 400,
                container: Some(container.clone()),
                kubernetes: Some(kubernetes.clone()),
            },
        );
        let response = SignalEnvelope::dns_response(
            "source.synthetic_dns",
            None,
            DnsResponseEvent {
                process: network_process(),
                query_name: "api.example.com".to_string(),
                query_type: DnsQueryType::A,
                response_code: DnsResponseCode::NoError,
                latency_nanos: Some(15_000),
                transport_protocol: NetworkProtocol::Udp,
                server_address: Some("10.96.0.10".to_string()),
                server_port: Some(53),
                timestamp_unix_nanos: 415,
                container: Some(container.clone()),
                kubernetes: Some(kubernetes.clone()),
            },
        );
        let counter = SignalEnvelope::dns_counter_metric(
            "generator.dns_metrics",
            None,
            DnsCounterMetric {
                metric_name: "dns.query.count".to_string(),
                unit: "{query}".to_string(),
                value: 1,
                window: window.clone(),
                query_name: Some("api.example.com".to_string()),
                query_type: Some(DnsQueryType::A),
                response_code: None,
                server_address: Some("10.96.0.10".to_string()),
                server_port: Some(53),
                container: Some(container.clone()),
                kubernetes: Some(kubernetes.clone()),
            },
        );
        let latency = SignalEnvelope::dns_latency_metric(
            "generator.dns_metrics",
            None,
            DnsLatencyMetric {
                metric_name: "dns.lookup.duration".to_string(),
                unit: "ns".to_string(),
                count: 1,
                sum_nanos: 15_000,
                min_nanos: 15_000,
                max_nanos: 15_000,
                window,
                query_name: Some("api.example.com".to_string()),
                query_type: Some(DnsQueryType::A),
                response_code: Some(DnsResponseCode::NoError),
                server_address: Some("10.96.0.10".to_string()),
                server_port: Some(53),
                container: Some(container),
                kubernetes: Some(kubernetes),
            },
        );

        for signal in [query, response, counter, latency] {
            assert_payload_string_lengths(
                &signal,
                &[
                    &["container", "container_id"],
                    &["container", "runtime"],
                    &["kubernetes", "namespace"],
                    &["kubernetes", "pod_name"],
                    &["kubernetes", "pod_uid"],
                    &["kubernetes", "container_name"],
                    &["kubernetes", "node_name"],
                ],
            );
            assert_payload_label_bounds(&signal, &["kubernetes", "labels"]);
        }
    }

    #[test]
    fn serializes_resource_observation_signals() {
        let window = MetricAggregationWindow {
            start_unix_nanos: 1_000,
            end_unix_nanos: 2_000,
        };
        let signals = [
            SignalEnvelope::node_cpu_observation(
                "source.procfs_resource",
                Some("node-a".to_string()),
                NodeCpuObservation {
                    metric_name: "system.cpu.time".to_string(),
                    unit: "ns".to_string(),
                    timestamp_unix_nanos: 2_000,
                    window: window.clone(),
                    user_nanos: 1_000,
                    system_nanos: 500,
                    idle_nanos: 5_000,
                    iowait_nanos: 100,
                    steal_nanos: 0,
                    runnable_tasks: Some(2),
                    blocked_tasks: Some(0),
                },
            ),
            SignalEnvelope::node_load_observation(
                "source.procfs_resource",
                Some("node-a".to_string()),
                NodeLoadObservation {
                    metric_name: "system.cpu.load_average.1m".to_string(),
                    unit: "1".to_string(),
                    timestamp_unix_nanos: 2_000,
                    window: window.clone(),
                    load1: 0.25,
                    load5: 0.5,
                    load15: 0.75,
                    runnable_tasks: Some(2),
                    total_tasks: Some(200),
                },
            ),
            SignalEnvelope::node_memory_observation(
                "source.procfs_resource",
                Some("node-a".to_string()),
                NodeMemoryObservation {
                    metric_name: "system.memory.usage".to_string(),
                    unit: "By".to_string(),
                    timestamp_unix_nanos: 2_000,
                    window: window.clone(),
                    mem_total_bytes: 8_192,
                    mem_available_bytes: Some(4_096),
                    mem_free_bytes: Some(2_048),
                    swap_total_bytes: Some(1_024),
                    swap_free_bytes: Some(512),
                },
            ),
            SignalEnvelope::node_filesystem_observation(
                "source.procfs_resource",
                Some("node-a".to_string()),
                NodeFilesystemObservation {
                    metric_name: "system.filesystem.usage".to_string(),
                    unit: "By".to_string(),
                    timestamp_unix_nanos: 2_000,
                    window: window.clone(),
                    mount_point: "/var/lib/kubelet".to_string(),
                    filesystem_type: Some("ext4".to_string()),
                    total_bytes: 1_000_000,
                    available_bytes: 250_000,
                },
            ),
            SignalEnvelope::node_disk_io_observation(
                "source.procfs_resource",
                Some("node-a".to_string()),
                NodeDiskIoObservation {
                    metric_name: "system.disk.io".to_string(),
                    unit: "By".to_string(),
                    timestamp_unix_nanos: 2_000,
                    window: window.clone(),
                    device: "nvme0n1".to_string(),
                    reads_completed: 10,
                    writes_completed: 20,
                    read_bytes: 4_096,
                    written_bytes: 8_192,
                },
            ),
        ];

        let kinds: Vec<_> = signals.iter().map(SignalEnvelope::kind).collect();

        assert_eq!(
            kinds,
            vec![
                "node_cpu_observation",
                "node_load_observation",
                "node_memory_observation",
                "node_filesystem_observation",
                "node_disk_io_observation"
            ]
        );
        for signal in signals {
            let json = serde_json::to_value(&signal).expect("signal serializes");
            let decoded: SignalEnvelope = serde_json::from_value(json).expect("round trips");
            assert_eq!(decoded.schema_version, 1);
        }
    }

    #[test]
    fn node_resource_constructors_bound_strings_before_json_stdout() {
        let long = "r".repeat(320);
        let window = MetricAggregationWindow {
            start_unix_nanos: 1_000,
            end_unix_nanos: 2_000,
        };
        let cpu = SignalEnvelope::node_cpu_observation(
            "source.procfs_resource",
            None,
            NodeCpuObservation {
                metric_name: long.clone(),
                unit: long.clone(),
                timestamp_unix_nanos: 2_000,
                window: window.clone(),
                user_nanos: 1_000,
                system_nanos: 500,
                idle_nanos: 5_000,
                iowait_nanos: 100,
                steal_nanos: 0,
                runnable_tasks: Some(2),
                blocked_tasks: Some(0),
            },
        );
        let load = SignalEnvelope::node_load_observation(
            "source.procfs_resource",
            None,
            NodeLoadObservation {
                metric_name: long.clone(),
                unit: long.clone(),
                timestamp_unix_nanos: 2_000,
                window: window.clone(),
                load1: 0.25,
                load5: 0.5,
                load15: 0.75,
                runnable_tasks: Some(2),
                total_tasks: Some(200),
            },
        );
        let memory = SignalEnvelope::node_memory_observation(
            "source.procfs_resource",
            None,
            NodeMemoryObservation {
                metric_name: long.clone(),
                unit: long.clone(),
                timestamp_unix_nanos: 2_000,
                window: window.clone(),
                mem_total_bytes: 8_192,
                mem_available_bytes: Some(4_096),
                mem_free_bytes: Some(2_048),
                swap_total_bytes: Some(1_024),
                swap_free_bytes: Some(512),
            },
        );
        let filesystem = SignalEnvelope::node_filesystem_observation(
            "source.procfs_resource",
            None,
            NodeFilesystemObservation {
                metric_name: long.clone(),
                unit: long.clone(),
                timestamp_unix_nanos: 2_000,
                window: window.clone(),
                mount_point: long.clone(),
                filesystem_type: Some(long.clone()),
                total_bytes: 1_000_000,
                available_bytes: 250_000,
            },
        );
        let disk = SignalEnvelope::node_disk_io_observation(
            "source.procfs_resource",
            None,
            NodeDiskIoObservation {
                metric_name: long.clone(),
                unit: long.clone(),
                timestamp_unix_nanos: 2_000,
                window,
                device: long,
                reads_completed: 10,
                writes_completed: 20,
                read_bytes: 4_096,
                written_bytes: 8_192,
            },
        );

        assert_payload_string_lengths(&cpu, &[&["metric_name"], &["unit"]]);
        assert_payload_string_lengths(&load, &[&["metric_name"], &["unit"]]);
        assert_payload_string_lengths(&memory, &[&["metric_name"], &["unit"]]);
        assert_payload_string_lengths(
            &filesystem,
            &[
                &["metric_name"],
                &["unit"],
                &["mount_point"],
                &["filesystem_type"],
            ],
        );
        assert_payload_string_lengths(&disk, &[&["metric_name"], &["unit"], &["device"]]);
    }

    #[test]
    fn serializes_process_and_resource_metric_signals() {
        let process = ProcessResourceContext {
            pid: 42,
            ppid: Some(1),
            uid: Some(1000),
            command: "api".to_string(),
            executable: Some("/app/api".to_string()),
            container: None,
            kubernetes: None,
        };
        let window = MetricAggregationWindow {
            start_unix_nanos: 1_000,
            end_unix_nanos: 2_000,
        };
        let observation = SignalEnvelope::process_resource_observation(
            "source.procfs_resource",
            Some("node-a".to_string()),
            ProcessResourceObservation {
                metric_name: "process.memory.usage".to_string(),
                unit: "By".to_string(),
                timestamp_unix_nanos: 2_000,
                window: window.clone(),
                process: process.clone(),
                cpu_time_nanos: Some(500),
                memory_rss_bytes: Some(4_096),
                virtual_memory_bytes: Some(8_192),
                open_fds: Some(12),
                socket_count: Some(2),
                thread_count: Some(4),
            },
        );
        let gauge = SignalEnvelope::resource_gauge_metric(
            "generator.resource_metrics",
            Some("node-a".to_string()),
            ResourceGaugeMetric {
                metric_name: "process.memory.usage".to_string(),
                unit: "By".to_string(),
                value: 4_096,
                window: window.clone(),
                resource: ResourceContext {
                    host_name: Some("node-a".to_string()),
                    container: None,
                    kubernetes: None,
                },
                process: Some(process.clone()),
                cgroup: None,
                attributes: vec![ResourceMetricAttribute {
                    key: "state".to_string(),
                    value: "rss".to_string(),
                }],
            },
        );
        let counter = SignalEnvelope::resource_counter_metric(
            "generator.resource_metrics",
            Some("node-a".to_string()),
            ResourceCounterMetric {
                metric_name: "process.cpu.time".to_string(),
                unit: "ns".to_string(),
                value: 500,
                window,
                resource: ResourceContext {
                    host_name: Some("node-a".to_string()),
                    container: None,
                    kubernetes: None,
                },
                process: Some(process),
                cgroup: None,
                attributes: vec![ResourceMetricAttribute {
                    key: "cpu.mode".to_string(),
                    value: "total".to_string(),
                }],
            },
        );

        assert_eq!(observation.kind(), "process_resource_observation");
        assert_eq!(gauge.kind(), "resource_gauge_metric");
        assert_eq!(counter.kind(), "resource_counter_metric");

        for signal in [observation, gauge, counter] {
            let json = serde_json::to_value(&signal).expect("signal serializes");
            assert_eq!(json["schema_version"], 1);
            let decoded: SignalEnvelope = serde_json::from_value(json).expect("round trips");
            assert_eq!(decoded.schema_version, 1);
        }
    }

    #[test]
    fn process_resource_constructor_bounds_strings_before_json_stdout() {
        let long = "p".repeat(320);
        let signal = SignalEnvelope::process_resource_observation(
            "source.procfs_resource",
            None,
            ProcessResourceObservation {
                metric_name: long.clone(),
                unit: long.clone(),
                timestamp_unix_nanos: 2_000,
                window: MetricAggregationWindow {
                    start_unix_nanos: 1_000,
                    end_unix_nanos: 2_000,
                },
                process: ProcessResourceContext {
                    pid: 42,
                    ppid: Some(1),
                    uid: Some(1000),
                    command: long.clone(),
                    executable: Some(long),
                    container: None,
                    kubernetes: None,
                },
                cpu_time_nanos: Some(500),
                memory_rss_bytes: Some(4_096),
                virtual_memory_bytes: Some(8_192),
                open_fds: Some(12),
                socket_count: Some(2),
                thread_count: Some(4),
            },
        );

        assert_payload_string_lengths(
            &signal,
            &[
                &["metric_name"],
                &["unit"],
                &["process", "command"],
                &["process", "executable"],
            ],
        );
    }

    #[test]
    fn resource_metric_constructors_bound_dynamic_attributes_before_json_stdout() {
        let attributes = oversized_resource_metric_attributes();
        let window = MetricAggregationWindow {
            start_unix_nanos: 1_000,
            end_unix_nanos: 2_000,
        };
        let gauge = SignalEnvelope::resource_gauge_metric(
            "generator.resource_metrics",
            Some("node-a".to_string()),
            ResourceGaugeMetric {
                metric_name: "process.memory.usage".to_string(),
                unit: "By".to_string(),
                value: 4_096,
                window: window.clone(),
                resource: ResourceContext {
                    host_name: Some("node-a".to_string()),
                    container: None,
                    kubernetes: None,
                },
                process: None,
                cgroup: None,
                attributes: attributes.clone(),
            },
        );
        let counter = SignalEnvelope::resource_counter_metric(
            "generator.resource_metrics",
            Some("node-a".to_string()),
            ResourceCounterMetric {
                metric_name: "process.cpu.time".to_string(),
                unit: "ns".to_string(),
                value: 500,
                window,
                resource: ResourceContext {
                    host_name: Some("node-a".to_string()),
                    container: None,
                    kubernetes: None,
                },
                process: None,
                cgroup: None,
                attributes,
            },
        );

        assert_bounded_resource_metric_attributes(&gauge);
        assert_bounded_resource_metric_attributes(&counter);
    }

    #[test]
    fn resource_metric_constructors_bound_scalar_and_context_strings_before_json_stdout() {
        let long = "m".repeat(320);
        let process = ProcessResourceContext {
            pid: 42,
            ppid: Some(1),
            uid: Some(1000),
            command: long.clone(),
            executable: Some(long.clone()),
            container: None,
            kubernetes: None,
        };
        let cgroup = CgroupResourceContext {
            cgroup_path: long.clone(),
            container: None,
            kubernetes: None,
        };
        let resource = ResourceContext {
            host_name: Some(long.clone()),
            container: None,
            kubernetes: None,
        };
        let window = MetricAggregationWindow {
            start_unix_nanos: 1_000,
            end_unix_nanos: 2_000,
        };
        let gauge = SignalEnvelope::resource_gauge_metric(
            "generator.resource_metrics",
            None,
            ResourceGaugeMetric {
                metric_name: long.clone(),
                unit: long.clone(),
                value: 4_096,
                window: window.clone(),
                resource: resource.clone(),
                process: Some(process.clone()),
                cgroup: Some(cgroup.clone()),
                attributes: vec![],
            },
        );
        let counter = SignalEnvelope::resource_counter_metric(
            "generator.resource_metrics",
            None,
            ResourceCounterMetric {
                metric_name: long.clone(),
                unit: long,
                value: 500,
                window,
                resource,
                process: Some(process),
                cgroup: Some(cgroup),
                attributes: vec![],
            },
        );

        for signal in [gauge, counter] {
            assert_payload_string_lengths(
                &signal,
                &[
                    &["metric_name"],
                    &["unit"],
                    &["resource", "host_name"],
                    &["process", "command"],
                    &["process", "executable"],
                    &["cgroup", "cgroup_path"],
                ],
            );
        }
    }

    #[test]
    fn serializes_cgroup_resource_observation_signals() {
        let cgroup = CgroupResourceContext {
            cgroup_path: "/kubepods.slice/pod123/container.scope".to_string(),
            container: None,
            kubernetes: None,
        };
        let window = MetricAggregationWindow {
            start_unix_nanos: 1_000,
            end_unix_nanos: 2_000,
        };
        let signals = [
            SignalEnvelope::cgroup_cpu_observation(
                "source.procfs_resource",
                Some("node-a".to_string()),
                CgroupCpuObservation {
                    metric_name: "container.cpu.time".to_string(),
                    unit: "ns".to_string(),
                    timestamp_unix_nanos: 2_000,
                    window: window.clone(),
                    cgroup: cgroup.clone(),
                    usage_nanos: Some(10_000),
                    user_nanos: Some(6_000),
                    system_nanos: Some(4_000),
                    throttled_periods: Some(1),
                    throttled_nanos: Some(100),
                },
            ),
            SignalEnvelope::cgroup_memory_observation(
                "source.procfs_resource",
                Some("node-a".to_string()),
                CgroupMemoryObservation {
                    metric_name: "container.memory.usage".to_string(),
                    unit: "By".to_string(),
                    timestamp_unix_nanos: 2_000,
                    window: window.clone(),
                    cgroup: cgroup.clone(),
                    current_bytes: Some(8_192),
                    peak_bytes: Some(16_384),
                    max_bytes: Some(65_536),
                },
            ),
            SignalEnvelope::cgroup_pids_observation(
                "source.procfs_resource",
                Some("node-a".to_string()),
                CgroupPidsObservation {
                    metric_name: "container.process.count".to_string(),
                    unit: "{process}".to_string(),
                    timestamp_unix_nanos: 2_000,
                    window: window.clone(),
                    cgroup: cgroup.clone(),
                    process_count: Some(3),
                    thread_count: Some(9),
                    max_processes: Some(512),
                },
            ),
            SignalEnvelope::cgroup_file_descriptor_observation(
                "source.procfs_resource",
                Some("node-a".to_string()),
                CgroupFileDescriptorObservation {
                    metric_name: "container.file_descriptor.count".to_string(),
                    unit: "{file_descriptor}".to_string(),
                    timestamp_unix_nanos: 2_000,
                    window,
                    cgroup,
                    open_fds: Some(42),
                    socket_count: Some(7),
                },
            ),
        ];

        let kinds: Vec<_> = signals.iter().map(SignalEnvelope::kind).collect();

        assert_eq!(
            kinds,
            vec![
                "cgroup_cpu_observation",
                "cgroup_memory_observation",
                "cgroup_pids_observation",
                "cgroup_file_descriptor_observation"
            ]
        );
        for signal in signals {
            let json = serde_json::to_value(&signal).expect("signal serializes");
            let decoded: SignalEnvelope = serde_json::from_value(json).expect("round trips");
            assert_eq!(decoded.schema_version, 1);
        }
    }

    #[test]
    fn cgroup_resource_constructors_bound_strings_before_json_stdout() {
        let long = "c".repeat(320);
        let cgroup = CgroupResourceContext {
            cgroup_path: long.clone(),
            container: None,
            kubernetes: None,
        };
        let window = MetricAggregationWindow {
            start_unix_nanos: 1_000,
            end_unix_nanos: 2_000,
        };
        let cpu = SignalEnvelope::cgroup_cpu_observation(
            "source.procfs_resource",
            None,
            CgroupCpuObservation {
                metric_name: long.clone(),
                unit: long.clone(),
                timestamp_unix_nanos: 2_000,
                window: window.clone(),
                cgroup: cgroup.clone(),
                usage_nanos: Some(10_000),
                user_nanos: Some(6_000),
                system_nanos: Some(4_000),
                throttled_periods: Some(1),
                throttled_nanos: Some(100),
            },
        );
        let memory = SignalEnvelope::cgroup_memory_observation(
            "source.procfs_resource",
            None,
            CgroupMemoryObservation {
                metric_name: long.clone(),
                unit: long.clone(),
                timestamp_unix_nanos: 2_000,
                window: window.clone(),
                cgroup: cgroup.clone(),
                current_bytes: Some(8_192),
                peak_bytes: Some(16_384),
                max_bytes: Some(65_536),
            },
        );
        let pids = SignalEnvelope::cgroup_pids_observation(
            "source.procfs_resource",
            None,
            CgroupPidsObservation {
                metric_name: long.clone(),
                unit: long.clone(),
                timestamp_unix_nanos: 2_000,
                window: window.clone(),
                cgroup: cgroup.clone(),
                process_count: Some(3),
                thread_count: Some(9),
                max_processes: Some(512),
            },
        );
        let file_descriptors = SignalEnvelope::cgroup_file_descriptor_observation(
            "source.procfs_resource",
            None,
            CgroupFileDescriptorObservation {
                metric_name: long.clone(),
                unit: long,
                timestamp_unix_nanos: 2_000,
                window,
                cgroup,
                open_fds: Some(42),
                socket_count: Some(7),
            },
        );

        for signal in [cpu, memory, pids, file_descriptors] {
            assert_payload_string_lengths(
                &signal,
                &[&["metric_name"], &["unit"], &["cgroup", "cgroup_path"]],
            );
        }
    }

    fn network_process() -> NetworkProcessIdentity {
        NetworkProcessIdentity {
            pid: 42,
            ppid: Some(1),
            uid: Some(1000),
            command: "api".to_string(),
            executable: Some("/app/api".to_string()),
            cgroup_id: None,
        }
    }

    fn container_context() -> crate::ContainerContext {
        crate::ContainerContext {
            container_id: "container-a".to_string(),
            runtime: Some("containerd".to_string()),
        }
    }

    fn kubernetes_context() -> crate::KubernetesContext {
        crate::KubernetesContext {
            namespace: "default".to_string(),
            pod_name: "api-123".to_string(),
            pod_uid: Some("pod-uid".to_string()),
            container_name: Some("api".to_string()),
            node_name: Some("node-a".to_string()),
            labels: std::collections::BTreeMap::new(),
        }
    }

    fn trace_peer_context() -> TracePeerContext {
        TracePeerContext {
            address: Some("203.0.113.10".to_string()),
            port: Some(443),
            domain: Some("payments.example.com".to_string()),
            workload: None,
            container: None,
        }
    }

    fn oversized_trace_attributes() -> Vec<TraceAttribute> {
        let mut attributes = vec![
            TraceAttribute {
                key: String::new(),
                value: "dropped".to_string(),
            },
            TraceAttribute {
                key: "authorization".to_string(),
                value: "Bearer secret".to_string(),
            },
            TraceAttribute {
                key: "k".repeat(160),
                value: "v".repeat(320),
            },
        ];
        attributes.extend((0..20).map(|index| TraceAttribute {
            key: format!("custom.attribute.{index}"),
            value: "value".to_string(),
        }));
        attributes
    }

    fn assert_bounded_safe_trace_attributes(signal: &SignalEnvelope) {
        let json = serde_json::to_value(signal).expect("signal serializes");
        let attributes = json["payload"]["attributes"]
            .as_array()
            .expect("attributes are serialized");

        assert_eq!(attributes.len(), 16);
        assert_eq!(attributes[0]["key"], "custom.attribute.0");
        assert_eq!(attributes[15]["key"], "custom.attribute.15");
        assert!(!json.to_string().contains("authorization"));
        assert!(!json.to_string().contains("Bearer secret"));
        assert!(!json.to_string().contains(&"k".repeat(160)));
        assert!(!json.to_string().contains(&"v".repeat(320)));
    }

    fn oversized_resource_metric_attributes() -> Vec<ResourceMetricAttribute> {
        let mut attributes = vec![
            ResourceMetricAttribute {
                key: String::new(),
                value: "dropped".to_string(),
            },
            ResourceMetricAttribute {
                key: "k".repeat(160),
                value: "value".to_string(),
            },
            ResourceMetricAttribute {
                key: "valid.but.too_large".to_string(),
                value: "v".repeat(320),
            },
        ];
        attributes.extend((0..20).map(|index| ResourceMetricAttribute {
            key: format!("resource.attribute.{index}"),
            value: "value".to_string(),
        }));
        attributes
    }

    fn assert_bounded_resource_metric_attributes(signal: &SignalEnvelope) {
        let json = serde_json::to_value(signal).expect("signal serializes");
        let attributes = json["payload"]["attributes"]
            .as_array()
            .expect("attributes are serialized");

        assert_eq!(attributes.len(), 16);
        assert_eq!(attributes[0]["key"].as_str().map(str::len), Some(128));
        assert_eq!(attributes[1]["value"].as_str().map(str::len), Some(256));
        assert_eq!(attributes[15]["key"], "resource.attribute.13");
        assert!(!json.to_string().contains(&"k".repeat(129)));
        assert!(!json.to_string().contains(&"v".repeat(257)));
        assert!(json.to_string().contains("valid.but.too_large"));
    }

    fn assert_dns_string_lengths(signal: &SignalEnvelope, fields: &[&str]) {
        let json = serde_json::to_value(signal).expect("signal serializes");
        for field in fields {
            assert_eq!(
                json["payload"][*field].as_str().map(str::len),
                Some(256),
                "{field} should be bounded"
            );
        }
    }

    fn assert_payload_string_lengths(signal: &SignalEnvelope, paths: &[&[&str]]) {
        let json = serde_json::to_value(signal).expect("signal serializes");
        for path in paths {
            let mut value = &json["payload"];
            for field in *path {
                value = &value[*field];
            }
            assert_eq!(
                value.as_str().map(str::len),
                Some(256),
                "{path:?} should be bounded"
            );
        }
    }

    fn assert_payload_label_bounds(signal: &SignalEnvelope, path: &[&str]) {
        let json = serde_json::to_value(signal).expect("signal serializes");
        let mut value = &json["payload"];
        for field in path {
            value = &value[*field];
        }
        let labels = value.as_object().expect("labels serialize as an object");
        assert_eq!(labels.len(), 16);
        assert!(
            labels
                .iter()
                .all(|(key, value)| key.len() == 128 && value.as_str().map(str::len) == Some(256))
        );
    }
}
