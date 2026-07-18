use async_trait::async_trait;
use e_navigator_core::{
    CoreError, CoreResult, JsonStdoutConfig, JsonStdoutMode, ModuleKind, ModuleMetadata, Sink,
};
use e_navigator_signals::{SignalEnvelope, SignalPayload};
use std::borrow::Cow;
use tokio::io::{self, AsyncWriteExt};

#[derive(Debug, Default)]
pub struct JsonStdoutSink {
    mode: JsonStdoutMode,
}

impl JsonStdoutSink {
    pub fn new(config: JsonStdoutConfig) -> Self {
        Self { mode: config.mode }
    }

    fn includes(&self, signal: &SignalEnvelope) -> bool {
        match self.mode {
            JsonStdoutMode::All => true,
            JsonStdoutMode::Topology => matches!(
                &signal.payload,
                SignalPayload::NetworkFlowSummary(_)
                    | SignalPayload::NetworkFlowWarning(_)
                    | SignalPayload::DependencyEdge(_)
                    | SignalPayload::ServiceInteractionSpanObservation(_)
                    | SignalPayload::TraceServicePathObservation(_)
                    | SignalPayload::TraceCorrelationWarning(_)
            ),
        }
    }
}

#[async_trait]
impl Sink<SignalEnvelope> for JsonStdoutSink {
    fn metadata(&self) -> ModuleMetadata {
        ModuleMetadata::new("sink.json_stdout", ModuleKind::Sink)
    }

    async fn write(&self, signal: &SignalEnvelope) -> CoreResult<()> {
        if !self.includes(signal) {
            return Ok(());
        }

        let line = serialize_signal_line(signal)?;
        let mut stdout = io::stdout();
        stdout
            .write_all(&line)
            .await
            .map_err(|err| module_error(err.to_string()))?;
        stdout
            .flush()
            .await
            .map_err(|err| module_error(err.to_string()))
    }
}

pub fn serialize_signal_line(signal: &SignalEnvelope) -> CoreResult<Vec<u8>> {
    let sanitized = sanitize_signal_for_stdout(signal);
    let mut line =
        serde_json::to_vec(sanitized.as_ref()).map_err(|err| module_error(err.to_string()))?;
    line.push(b'\n');
    Ok(line)
}

fn sanitize_signal_for_stdout(signal: &SignalEnvelope) -> Cow<'_, SignalEnvelope> {
    if !matches!(
        signal.payload,
        SignalPayload::Exec(_) | SignalPayload::RuntimeSecurityFinding(_)
    ) {
        return Cow::Borrowed(signal);
    }

    let mut sanitized = signal.clone();
    match &mut sanitized.payload {
        SignalPayload::Exec(event) => redact_argv(&mut event.arguments),
        SignalPayload::RuntimeSecurityFinding(finding) => {
            redact_argv(&mut finding.matched_process.arguments);
        }
        _ => unreachable!("argv-bearing payload checked before cloning"),
    }
    Cow::Owned(sanitized)
}

fn redact_argv(arguments: &mut [String]) {
    let mut redact_next = false;
    for argument in arguments {
        if redact_next {
            *argument = "<redacted>".to_string();
            redact_next = false;
            continue;
        }

        let (redacted, consumes_next) = redact_argument(argument);
        if let Some(redacted) = redacted {
            *argument = redacted;
        }
        redact_next = consumes_next;
    }
}

fn redact_argument(argument: &str) -> (Option<String>, bool) {
    let lower = argument.to_ascii_lowercase();
    if lower.starts_with("bearer ") {
        return (Some("<redacted>".to_string()), false);
    }

    let Some(key_range) = sensitive_key_range(&lower) else {
        return (None, false);
    };
    let suffix = &argument[key_range.end..];
    let separator = suffix
        .char_indices()
        .find(|(_, character)| matches!(character, '=' | ':' | ' '))
        .map(|(index, character)| (key_range.end + index, character));

    match separator {
        Some((index, separator)) if argument[index + separator.len_utf8()..].is_empty() => {
            (None, true)
        }
        Some((index, separator)) => {
            let prefix_end = index + separator.len_utf8();
            (
                Some(format!("{}<redacted>", &argument[..prefix_end])),
                false,
            )
        }
        None => (None, true),
    }
}

fn sensitive_key_range(lower: &str) -> Option<std::ops::Range<usize>> {
    [
        "authorization",
        "auth-token",
        "api-token",
        "api_key",
        "api-key",
        "apikey",
        "password",
        "passwd",
        "secret",
        "credential",
        "token",
    ]
    .into_iter()
    .filter_map(|key| lower.find(key).map(|start| start..start + key.len()))
    .next()
}

fn module_error(message: String) -> CoreError {
    CoreError::ModuleFailed {
        module: "sink.json_stdout".to_string(),
        message,
    }
}

#[cfg(test)]
mod tests {
    use e_navigator_signals::{
        ContainerContext, DependencyEdgeEvent, DependencyEndpoint, ExecEvent, KubernetesContext,
        MatchedProcess, MetricAggregationWindow, NetworkAddressFamily, NetworkFlowDirection,
        NetworkFlowEndpoint, NetworkFlowSummaryEvent, NetworkFlowWarning, NetworkProcessIdentity,
        NetworkProtocol, ProfileSampleObservation, ProfilingAttribute, ProfilingConfidence,
        ProfilingCorrelationKind, ProfilingFrame, ProfilingKind, ProfilingSessionObservation,
        ProfilingStackTraceObservation, ProfilingWarningObservation, ProtocolKind,
        ProtocolRequestObservation, RuntimeSecurityFinding, RuntimeSecuritySeverity,
        TraceAttribute, TraceConfidence, TraceCorrelationKind,
    };
    use std::collections::BTreeMap;

    use super::*;

    #[test]
    fn topology_mode_emits_only_topology_contracts() {
        let exec = SignalEnvelope::exec(
            "source.test",
            None,
            ExecEvent {
                pid: 1,
                ppid: None,
                uid: None,
                command: "true".to_string(),
                executable: None,
                arguments: vec![],
                cgroup_id: None,
                timestamp_unix_nanos: 1,
                container: None,
                kubernetes: None,
            },
        );
        let dependency = SignalEnvelope::dependency_edge(
            "generator.dependency_graph",
            None,
            DependencyEdgeEvent {
                source: DependencyEndpoint {
                    owner_name: Some("default/api".to_string()),
                    owner_type: Some("deployment".to_string()),
                    workload: None,
                    container: None,
                    address: None,
                    port: None,
                    domain: None,
                },
                destination: DependencyEndpoint {
                    owner_name: Some("default/database".to_string()),
                    owner_type: Some("service".to_string()),
                    workload: None,
                    container: None,
                    address: Some("10.96.0.20".to_string()),
                    port: Some(5432),
                    domain: None,
                },
                protocol: NetworkProtocol::Tcp,
                observations: 1,
                first_seen_unix_nanos: 1,
                last_seen_unix_nanos: 1,
            },
        );

        let all = JsonStdoutSink::default();
        let topology = JsonStdoutSink::new(JsonStdoutConfig {
            mode: JsonStdoutMode::Topology,
        });

        assert!(all.includes(&exec));
        assert!(all.includes(&dependency));
        assert!(!topology.includes(&exec));
        assert!(topology.includes(&dependency));
    }

    #[test]
    fn serializes_signal_as_newline_delimited_json() {
        let signal = SignalEnvelope::exec(
            "source.test",
            None,
            ExecEvent {
                pid: 1,
                ppid: None,
                uid: Some(1000),
                command: "true".to_string(),
                executable: None,
                arguments: vec![],
                cgroup_id: None,
                timestamp_unix_nanos: 1,
                container: None,
                kubernetes: None,
            },
        );

        let line = serialize_signal_line(&signal).expect("signal serializes");
        assert!(matches!(sanitize_signal_for_stdout(&signal), Cow::Owned(_)));
        let value: serde_json::Value =
            serde_json::from_slice(&line[..line.len() - 1]).expect("line is valid JSON");

        assert!(line.ends_with(b"\n"));
        assert_eq!(line.iter().filter(|byte| **byte == b'\n').count(), 1);
        assert_eq!(value["schema_version"], 1);
        assert_eq!(value["kind"], "exec");
        assert_eq!(value["payload"]["command"], "true");
    }

    #[test]
    fn redacts_secret_like_exec_arguments_in_json_stdout() {
        let signal = SignalEnvelope::exec(
            "source.test",
            None,
            ExecEvent {
                pid: 1,
                ppid: None,
                uid: Some(1000),
                command: "curl".to_string(),
                executable: Some("/usr/bin/curl".to_string()),
                arguments: vec![
                    "curl".to_string(),
                    "--token=abc123".to_string(),
                    "--password".to_string(),
                    "plain-secret".to_string(),
                    "--api-key".to_string(),
                    "key-123".to_string(),
                    "Authorization: Bearer abc.def".to_string(),
                ],
                cgroup_id: None,
                timestamp_unix_nanos: 1,
                container: None,
                kubernetes: None,
            },
        );

        let line = serialize_signal_line(&signal).expect("signal serializes");
        let value: serde_json::Value =
            serde_json::from_slice(&line[..line.len() - 1]).expect("line is valid JSON");

        assert_eq!(
            value["payload"]["arguments"],
            serde_json::json!([
                "curl",
                "--token=<redacted>",
                "--password",
                "<redacted>",
                "--api-key",
                "<redacted>",
                "Authorization:<redacted>"
            ])
        );
    }

    #[test]
    fn redacts_runtime_security_matched_process_arguments_in_json_stdout() {
        let signal = SignalEnvelope::runtime_security_finding(
            "generator.runtime_security",
            Some("node-a".to_string()),
            RuntimeSecurityFinding {
                rule_id: "suspicious_process".to_string(),
                severity: RuntimeSecuritySeverity::High,
                matched_process: MatchedProcess {
                    pid: 42,
                    command: "curl".to_string(),
                    executable: Some("/usr/bin/curl".to_string()),
                    arguments: vec![
                        "curl".to_string(),
                        "--authorization".to_string(),
                        "Bearer abc.def".to_string(),
                        "--password=plain-secret".to_string(),
                    ],
                },
                matched_connection: None,
                container: None,
                kubernetes: None,
            },
        );

        let line = serialize_signal_line(&signal).expect("signal serializes");
        let value: serde_json::Value =
            serde_json::from_slice(&line[..line.len() - 1]).expect("line is valid JSON");

        assert_eq!(
            value["payload"]["matched_process"]["arguments"],
            serde_json::json!([
                "curl",
                "--authorization",
                "<redacted>",
                "--password=<redacted>"
            ])
        );
    }

    #[test]
    fn serializes_network_flow_warning_as_json_stdout() {
        let signal = SignalEnvelope::network_flow_warning(
            "generator.network_metrics",
            Some("node-a".to_string()),
            NetworkFlowWarning {
                warning_type: "missing_attribution".to_string(),
                message: "network flow has byte counters but incomplete source attribution"
                    .to_string(),
                timestamp_unix_nanos: 1,
                source_signal_kind: "network_connection_close".to_string(),
                source_module: "source.synthetic_network".to_string(),
                protocol: NetworkProtocol::Tcp,
                address_family: NetworkAddressFamily::Ipv4,
                remote_address: "198.51.100.30".to_string(),
                remote_port: 9443,
                process: NetworkProcessIdentity {
                    pid: 42,
                    ppid: Some(1),
                    uid: Some(1000),
                    command: "api".to_string(),
                    executable: Some("/app/api".to_string()),
                    cgroup_id: None,
                },
                container: None,
                kubernetes: None,
            },
        );

        let line = serialize_signal_line(&signal).expect("signal serializes");
        assert!(matches!(
            sanitize_signal_for_stdout(&signal),
            Cow::Borrowed(_)
        ));
        let value: serde_json::Value =
            serde_json::from_slice(&line[..line.len() - 1]).expect("line is valid JSON");

        assert!(line.ends_with(b"\n"));
        assert_eq!(value["kind"], "network_flow_warning");
        assert_eq!(value["payload"]["warning_type"], "missing_attribution");
        assert_eq!(
            value["payload"]["source_signal_kind"],
            "network_connection_close"
        );
        assert_eq!(value["payload"]["protocol"], "tcp");
        assert_eq!(value["payload"]["address_family"], "ipv4");
        assert_eq!(value["payload"]["remote_address"], "198.51.100.30");
        assert_eq!(value["payload"]["remote_port"], 9443);
        assert_eq!(value["payload"]["process"]["command"], "api");
    }

    #[test]
    fn serializes_network_flow_summary_as_json_stdout() {
        let signal = SignalEnvelope::network_flow_summary(
            "generator.network_metrics",
            Some("node-a".to_string()),
            NetworkFlowSummaryEvent {
                source: network_flow_endpoint(
                    "10.0.0.5",
                    41000,
                    "checkout-7d8f",
                    "checkout",
                    Some("container-source"),
                ),
                destination: network_flow_endpoint("10.0.0.20", 6379, "redis-0", "redis", None),
                protocol: NetworkProtocol::Tcp,
                address_family: NetworkAddressFamily::Ipv4,
                bytes: 1536,
                packets: None,
                direction: NetworkFlowDirection::Egress,
                first_seen_unix_nanos: 1_000,
                last_seen_unix_nanos: 3_000,
            },
        );

        let line = serialize_signal_line(&signal).expect("signal serializes");
        let value: serde_json::Value =
            serde_json::from_slice(&line[..line.len() - 1]).expect("line is valid JSON");

        assert!(line.ends_with(b"\n"));
        assert_eq!(value["kind"], "network_flow_summary");
        assert_eq!(value["payload"]["protocol"], "tcp");
        assert_eq!(value["payload"]["address_family"], "ipv4");
        assert_eq!(value["payload"]["bytes"], 1536);
        assert_eq!(value["payload"]["direction"], "egress");
        assert_eq!(value["payload"]["source"]["address"], "10.0.0.5");
        assert_eq!(value["payload"]["source"]["port"], 41000);
        assert_eq!(
            value["payload"]["source"]["kubernetes"]["pod_name"],
            "checkout-7d8f"
        );
        assert_eq!(value["payload"]["destination"]["address"], "10.0.0.20");
        assert_eq!(value["payload"]["destination"]["port"], 6379);
        assert_eq!(
            value["payload"]["destination"]["kubernetes"]["pod_name"],
            "redis-0"
        );
    }

    #[test]
    fn serializes_protocol_request_as_json_stdout_without_raw_trace_headers() {
        let signal = SignalEnvelope::protocol_request_observation(
            "source.protocol_fixture",
            Some("node-a".to_string()),
            ProtocolRequestObservation {
                protocol: ProtocolKind::Grpc,
                role: None,
                start_unix_nanos: 1_000,
                end_unix_nanos: Some(2_500),
                duration_nanos: Some(1_500),
                trace_id: Some("4bf92f3577b34da6a3ce929d0e0e4736".to_string()),
                span_id: Some("00f067aa0ba902b7".to_string()),
                parent_span_id: None,
                traceparent: Some(
                    "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01".to_string(),
                ),
                tracestate: Some("vendor=value".to_string()),
                correlation_kind: TraceCorrelationKind::ProtocolObserved,
                confidence: TraceConfidence::High,
                service_name: Some("checkout-api".to_string()),
                method: Some("GetCart".to_string()),
                status_code: Some(0),
                process: None,
                container: None,
                kubernetes: None,
                peer: None,
                attributes: vec![TraceAttribute {
                    key: "rpc.system".to_string(),
                    value: "grpc".to_string(),
                }],
            },
        );

        let line = serialize_signal_line(&signal).expect("signal serializes");
        let value: serde_json::Value =
            serde_json::from_slice(&line[..line.len() - 1]).expect("line is valid JSON");

        assert!(line.ends_with(b"\n"));
        assert_eq!(value["kind"], "protocol_request_observation");
        assert_eq!(value["payload"]["protocol"], "grpc");
        assert_eq!(value["payload"]["method"], "GetCart");
        assert_eq!(value["payload"]["status_code"], 0);
        assert_eq!(value["payload"]["attributes"][0]["key"], "rpc.system");
        assert!(value["payload"].get("traceparent").is_none());
        assert!(value["payload"].get("tracestate").is_none());
    }

    #[test]
    fn serializes_profile_sample_as_json_stdout() {
        let signal = SignalEnvelope::profile_sample_observation(
            "source.synthetic_profile",
            Some("node-a".to_string()),
            ProfileSampleObservation {
                timestamp_unix_nanos: 10,
                profiling_kind: ProfilingKind::Cpu,
                correlation_kind: ProfilingCorrelationKind::ObservedProfileSample,
                confidence: ProfilingConfidence::High,
                sample_count: 3,
                sampling_period_nanos: Some(10_000_000),
                stack_id: "stack:abc".to_string(),
                stack_frames: vec![ProfilingFrame {
                    symbol: Some("checkout::handler".to_string()),
                    module: Some("checkout".to_string()),
                    file: None,
                    line: None,
                    module_offset: None,
                }],
                process: None,
                container: None,
                kubernetes: None,
                thread_id: Some(7),
                thread_name: Some("worker".to_string()),
                attributes: vec![
                    profile_attr("phase", "steady"),
                    profile_attr("token", "secret"),
                ],
            },
        );

        let line = serialize_signal_line(&signal).expect("signal serializes");
        let value: serde_json::Value =
            serde_json::from_slice(&line[..line.len() - 1]).expect("line is valid JSON");

        assert!(line.ends_with(b"\n"));
        assert_eq!(value["kind"], "profile_sample_observation");
        assert_eq!(value["payload"]["profiling_kind"], "cpu");
        assert_eq!(value["payload"]["sample_count"], 3);
        assert_eq!(value["payload"]["stack_id"], "stack:abc");
        assert_eq!(
            value["payload"]["stack_frames"][0]["symbol"],
            "checkout::handler"
        );
        assert_eq!(value["payload"]["attributes"][0]["key"], "phase");
        assert_eq!(value["payload"]["attributes"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn serializes_profile_session_as_json_stdout() {
        let signal = SignalEnvelope::profiling_session_observation(
            "generator.profiling",
            Some("node-a".to_string()),
            ProfilingSessionObservation {
                window: MetricAggregationWindow {
                    start_unix_nanos: 1,
                    end_unix_nanos: 2,
                },
                profiling_kind: ProfilingKind::Cpu,
                correlation_kind: ProfilingCorrelationKind::ObservedProfileSample,
                confidence: ProfilingConfidence::High,
                profile_id: "profile:abc".to_string(),
                observed_sample_count: 27,
                dropped_sample_count: 3,
                distinct_stack_count: 5,
                sampling_period_nanos: Some(10_000_000),
                process: None,
                container: None,
                kubernetes: None,
                source: "source.aya_cpu_profile".to_string(),
                attributes: vec![
                    profile_attr("phase", "steady"),
                    profile_attr("token", "secret"),
                ],
            },
        );

        let line = serialize_signal_line(&signal).expect("signal serializes");
        let value: serde_json::Value =
            serde_json::from_slice(&line[..line.len() - 1]).expect("line is valid JSON");

        assert!(line.ends_with(b"\n"));
        assert_eq!(value["kind"], "profiling_session_observation");
        assert_eq!(value["payload"]["profile_id"], "profile:abc");
        assert_eq!(value["payload"]["observed_sample_count"], 27);
        assert_eq!(value["payload"]["dropped_sample_count"], 3);
        assert_eq!(value["payload"]["distinct_stack_count"], 5);
        assert_eq!(value["payload"]["attributes"][0]["key"], "phase");
        assert_eq!(value["payload"]["attributes"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn serializes_profile_stack_trace_as_json_stdout() {
        let signal = SignalEnvelope::profiling_stack_trace_observation(
            "source.synthetic_profile",
            Some("node-a".to_string()),
            ProfilingStackTraceObservation {
                timestamp_unix_nanos: 11,
                profiling_kind: ProfilingKind::Cpu,
                correlation_kind: ProfilingCorrelationKind::Synthetic,
                confidence: ProfilingConfidence::Medium,
                stack_id: "stack:missing".to_string(),
                stack_frames: vec![ProfilingFrame {
                    symbol: None,
                    module: Some("libunknown.so".to_string()),
                    file: None,
                    line: None,
                    module_offset: None,
                }],
                process: None,
                container: None,
                kubernetes: None,
                attributes: vec![
                    profile_attr("phase", "symbolication_pending"),
                    profile_attr("api_key", "secret"),
                ],
            },
        );

        let line = serialize_signal_line(&signal).expect("signal serializes");
        let value: serde_json::Value =
            serde_json::from_slice(&line[..line.len() - 1]).expect("line is valid JSON");

        assert!(line.ends_with(b"\n"));
        assert_eq!(value["kind"], "profiling_stack_trace_observation");
        assert_eq!(value["payload"]["stack_id"], "stack:missing");
        assert_eq!(
            value["payload"]["stack_frames"][0]["symbol"],
            serde_json::Value::Null
        );
        assert_eq!(
            value["payload"]["stack_frames"][0]["module"],
            "libunknown.so"
        );
        assert_eq!(value["payload"]["attributes"][0]["key"], "phase");
        assert_eq!(value["payload"]["attributes"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn serializes_profiling_warning_as_json_stdout() {
        let signal = SignalEnvelope::profiling_warning_observation(
            "generator.profiling",
            Some("node-a".to_string()),
            ProfilingWarningObservation {
                warning_type: "missing_attribution".to_string(),
                message: "profile sample has no container or Kubernetes context".to_string(),
                timestamp_unix_nanos: 12,
                source_signal_kind: "profile_sample_observation".to_string(),
                source_module: "source.synthetic_profile".to_string(),
                profiling_kind: ProfilingKind::Cpu,
                correlation_kind: ProfilingCorrelationKind::ObservedProfileSample,
                confidence: ProfilingConfidence::Low,
                process: None,
                container: None,
                kubernetes: None,
                attributes: vec![profile_attr("phase", "warning")],
            },
        );

        let line = serialize_signal_line(&signal).expect("signal serializes");
        let value: serde_json::Value =
            serde_json::from_slice(&line[..line.len() - 1]).expect("line is valid JSON");

        assert!(line.ends_with(b"\n"));
        assert_eq!(value["kind"], "profiling_warning_observation");
        assert_eq!(value["payload"]["warning_type"], "missing_attribution");
        assert_eq!(
            value["payload"]["source_signal_kind"],
            "profile_sample_observation"
        );
        assert_eq!(value["payload"]["attributes"][0]["key"], "phase");
    }

    fn profile_attr(key: &str, value: &str) -> ProfilingAttribute {
        ProfilingAttribute {
            key: key.to_string(),
            value: value.to_string(),
        }
    }

    fn network_flow_endpoint(
        address: &str,
        port: u16,
        pod_name: &str,
        container_name: &str,
        container_id: Option<&str>,
    ) -> NetworkFlowEndpoint {
        NetworkFlowEndpoint {
            address: Some(address.to_string()),
            port: Some(port),
            owner_name: None,
            owner_type: None,
            container: container_id.map(|container_id| ContainerContext {
                container_id: container_id.to_string(),
                runtime: Some("containerd".to_string()),
            }),
            kubernetes: Some(KubernetesContext {
                namespace: "shop".to_string(),
                pod_name: pod_name.to_string(),
                pod_uid: Some(format!("{pod_name}-uid")),
                container_name: Some(container_name.to_string()),
                node_name: Some("node-a".to_string()),
                labels: BTreeMap::new(),
            }),
        }
    }
}
