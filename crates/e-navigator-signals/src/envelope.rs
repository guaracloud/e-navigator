use e_navigator_core::Signal;
use serde::{Deserialize, Deserializer, Serialize, de::Error as DeError};

use crate::{
    DependencyEdgeEvent, DnsCounterMetric, DnsLatencyMetric, DnsQueryEvent, DnsResponseEvent,
    ExecEvent, NetworkConnectionCloseEvent, NetworkConnectionFailureEvent,
    NetworkConnectionOpenEvent, NetworkCounterMetric, NetworkDurationMetric, NetworkGaugeMetric,
    ProcessExitEvent, ProcessLifecycleDurationEvent, RuntimeSecurityFinding,
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
    NetworkCounterMetric,
    NetworkDurationMetric,
    NetworkGaugeMetric,
    DnsQuery,
    DnsResponse,
    DnsCounterMetric,
    DnsLatencyMetric,
    DependencyEdge,
    RuntimeSecurityFinding,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
#[non_exhaustive]
pub enum SignalPayload {
    Exec(ExecEvent),
    ProcessExit(ProcessExitEvent),
    ProcessLifecycleDuration(ProcessLifecycleDurationEvent),
    NetworkConnectionOpen(NetworkConnectionOpenEvent),
    NetworkConnectionClose(NetworkConnectionCloseEvent),
    NetworkConnectionFailure(NetworkConnectionFailureEvent),
    NetworkCounterMetric(NetworkCounterMetric),
    NetworkDurationMetric(NetworkDurationMetric),
    NetworkGaugeMetric(NetworkGaugeMetric),
    DnsQuery(DnsQueryEvent),
    DnsResponse(DnsResponseEvent),
    DnsCounterMetric(DnsCounterMetric),
    DnsLatencyMetric(DnsLatencyMetric),
    DependencyEdge(DependencyEdgeEvent),
    RuntimeSecurityFinding(RuntimeSecurityFinding),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
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
    pub fn exec(source: impl Into<String>, host: Option<String>, event: ExecEvent) -> Self {
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
        event: ProcessExitEvent,
    ) -> Self {
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
        event: ProcessLifecycleDurationEvent,
    ) -> Self {
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
        finding: RuntimeSecurityFinding,
    ) -> Self {
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
        event: NetworkConnectionOpenEvent,
    ) -> Self {
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
        event: NetworkConnectionCloseEvent,
    ) -> Self {
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
        event: NetworkConnectionFailureEvent,
    ) -> Self {
        Self {
            schema_version: SIGNAL_SCHEMA_VERSION,
            kind: SignalKind::NetworkConnectionFailure,
            source: source.into(),
            host,
            payload: SignalPayload::NetworkConnectionFailure(event),
        }
    }

    pub fn network_counter_metric(
        source: impl Into<String>,
        host: Option<String>,
        metric: NetworkCounterMetric,
    ) -> Self {
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
        metric: NetworkDurationMetric,
    ) -> Self {
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
        metric: NetworkGaugeMetric,
    ) -> Self {
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
        event: DnsQueryEvent,
    ) -> Self {
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
        event: DnsResponseEvent,
    ) -> Self {
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
        metric: DnsCounterMetric,
    ) -> Self {
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
        metric: DnsLatencyMetric,
    ) -> Self {
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
        event: DependencyEdgeEvent,
    ) -> Self {
        Self {
            schema_version: SIGNAL_SCHEMA_VERSION,
            kind: SignalKind::DependencyEdge,
            source: source.into(),
            host,
            payload: SignalPayload::DependencyEdge(event),
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
            SignalKind::NetworkCounterMetric => "network_counter_metric",
            SignalKind::NetworkDurationMetric => "network_duration_metric",
            SignalKind::NetworkGaugeMetric => "network_gauge_metric",
            SignalKind::DnsQuery => "dns_query",
            SignalKind::DnsResponse => "dns_response",
            SignalKind::DnsCounterMetric => "dns_counter_metric",
            SignalKind::DnsLatencyMetric => "dns_latency_metric",
            SignalKind::DependencyEdge => "dependency_edge",
            SignalKind::RuntimeSecurityFinding => "runtime_security_finding",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        DependencyEndpoint, DnsCounterMetric, DnsLatencyMetric, DnsQueryEvent, DnsQueryType,
        DnsResponseCode, DnsResponseEvent, MetricAggregationWindow, NetworkAddressFamily,
        NetworkCounterMetric, NetworkDurationMetric, NetworkGaugeMetric, NetworkProcessIdentity,
        NetworkProtocol,
    };

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

    fn network_process() -> NetworkProcessIdentity {
        NetworkProcessIdentity {
            pid: 42,
            ppid: Some(1),
            uid: Some(1000),
            command: "api".to_string(),
            executable: Some("/app/api".to_string()),
        }
    }
}
