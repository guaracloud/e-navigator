use crate::{
    otel_metric::{OtelMetricRecord, OtelMetricValue, format_otel_metric_record},
    profile_format::format_profile_record,
};
use async_trait::async_trait;
use e_navigator_core::{
    CoreError, CoreResult, ModuleKind, ModuleMetadata, PrometheusHttpConfig, Sink,
};
use e_navigator_signals::{SignalEnvelope, SignalPayload};
use std::{
    collections::{BTreeMap, VecDeque},
    io,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

const MAX_REQUEST_BYTES: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrometheusMetricLine {
    pub name: String,
    pub labels: BTreeMap<String, String>,
    pub value: String,
}

fn format_prometheus_metric_lines(signal: &SignalEnvelope) -> Vec<PrometheusMetricLine> {
    let Some(record) = format_otel_metric_record(signal) else {
        return format_profile_session_metric_lines(signal);
    };

    format_otel_prometheus_metric_lines(record)
}

fn format_otel_prometheus_metric_lines(record: OtelMetricRecord) -> Vec<PrometheusMetricLine> {
    let mut labels = BTreeMap::new();
    for (key, value) in record.resource.iter().chain(record.attributes.iter()) {
        insert_prometheus_label(&mut labels, key, value);
    }

    let metric_name = sanitize_identifier(&record.name);
    match record.value {
        OtelMetricValue::U64(value) => vec![PrometheusMetricLine {
            name: metric_name,
            labels,
            value: value.to_string(),
        }],
        OtelMetricValue::I64(value) => vec![PrometheusMetricLine {
            name: metric_name,
            labels,
            value: value.to_string(),
        }],
        OtelMetricValue::Summary {
            count,
            sum_nanos,
            min_nanos,
            max_nanos,
        } => [
            ("count", count),
            ("sum_nanos", sum_nanos),
            ("min_nanos", min_nanos),
            ("max_nanos", max_nanos),
        ]
        .into_iter()
        .map(|(suffix, value)| PrometheusMetricLine {
            name: format!("{metric_name}_{suffix}"),
            labels: labels.clone(),
            value: value.to_string(),
        })
        .collect(),
    }
}

fn format_profile_session_metric_lines(signal: &SignalEnvelope) -> Vec<PrometheusMetricLine> {
    let SignalPayload::ProfilingSessionObservation(observation) = &signal.payload else {
        return Vec::new();
    };
    let Some(record) = format_profile_record(signal) else {
        return Vec::new();
    };

    let mut labels = BTreeMap::new();
    for (key, value) in &record.resource {
        insert_prometheus_label(&mut labels, key, &serde_json::json!(value));
    }
    insert_prometheus_label(
        &mut labels,
        "profile.kind",
        &serde_json::json!(record.profile_kind),
    );
    insert_prometheus_label(
        &mut labels,
        "profile.correlation.kind",
        &serde_json::json!(record.correlation_kind),
    );
    insert_prometheus_label(
        &mut labels,
        "profile.confidence",
        &serde_json::json!(record.confidence),
    );
    insert_prometheus_label(
        &mut labels,
        "profile.source",
        &serde_json::json!(observation.source),
    );

    let mut lines = [
        (
            "profile.session.samples.observed",
            observation.observed_sample_count,
        ),
        (
            "profile.session.samples.dropped",
            observation.dropped_sample_count,
        ),
        (
            "profile.session.stacks.distinct",
            observation.distinct_stack_count,
        ),
    ]
    .into_iter()
    .map(|(name, value)| PrometheusMetricLine {
        name: sanitize_identifier(name),
        labels: labels.clone(),
        value: value.to_string(),
    })
    .collect::<Vec<_>>();
    if let Some(value) = observation.sampling_period_nanos {
        lines.push(PrometheusMetricLine {
            name: sanitize_identifier("profile.session.sampling.period.nanos"),
            labels,
            value: value.to_string(),
        });
    }
    lines
}

pub fn render_prometheus_text(metrics: &[PrometheusMetricLine]) -> String {
    let mut output = String::new();
    for metric in metrics {
        output.push_str(&metric.name);
        if !metric.labels.is_empty() {
            output.push('{');
            for (index, (key, value)) in metric.labels.iter().enumerate() {
                if index > 0 {
                    output.push(',');
                }
                output.push_str(key);
                output.push_str("=\"");
                output.push_str(&escape_label_value(value));
                output.push('"');
            }
            output.push('}');
        }
        output.push(' ');
        output.push_str(&metric.value);
        output.push('\n');
    }
    output
}

#[derive(Debug)]
pub struct PrometheusHttpSink {
    state: Arc<PrometheusState>,
}

impl PrometheusHttpSink {
    pub fn bind(config: PrometheusHttpConfig) -> CoreResult<Self> {
        let bind_address = format!("{}:{}", config.bind_address, config.port);
        let listener = std::net::TcpListener::bind(&bind_address).map_err(module_error)?;
        listener.set_nonblocking(true).map_err(module_error)?;
        let state = Arc::new(PrometheusState::new(config.max_metric_lines));
        if tokio::runtime::Handle::try_current().is_ok() {
            let listener = TcpListener::from_std(listener).map_err(module_error)?;
            spawn_http_server(listener, state.clone());
        }
        Ok(Self { state })
    }

    #[cfg(test)]
    pub async fn bind_for_test(
        max_metric_lines: usize,
    ) -> CoreResult<(Self, std::net::SocketAddr)> {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").map_err(module_error)?;
        let address = listener.local_addr().map_err(module_error)?;
        listener.set_nonblocking(true).map_err(module_error)?;
        let listener = TcpListener::from_std(listener).map_err(module_error)?;
        let state = Arc::new(PrometheusState::new(max_metric_lines));
        spawn_http_server(listener, state.clone());
        Ok((Self { state }, address))
    }
}

#[async_trait]
impl Sink<SignalEnvelope> for PrometheusHttpSink {
    fn metadata(&self) -> ModuleMetadata {
        ModuleMetadata::new("sink.prometheus_http", ModuleKind::Sink)
    }

    async fn write(&self, signal: &SignalEnvelope) -> CoreResult<()> {
        for line in format_prometheus_metric_lines(signal) {
            self.state.push(line)?;
        }
        Ok(())
    }
}

#[derive(Debug)]
struct PrometheusState {
    max_metric_lines: usize,
    metrics: Mutex<VecDeque<PrometheusMetricLine>>,
    healthy: AtomicBool,
}

impl PrometheusState {
    fn new(max_metric_lines: usize) -> Self {
        Self {
            max_metric_lines,
            metrics: Mutex::new(VecDeque::new()),
            healthy: AtomicBool::new(true),
        }
    }

    fn push(&self, line: PrometheusMetricLine) -> CoreResult<()> {
        let mut metrics = self
            .metrics
            .lock()
            .map_err(|err| module_error(err.to_string()))?;
        if let Some(existing) = metrics
            .iter_mut()
            .find(|existing| existing.name == line.name && existing.labels == line.labels)
        {
            *existing = line;
            return Ok(());
        }
        while metrics.len() >= self.max_metric_lines {
            metrics.pop_front();
        }
        metrics.push_back(line);
        Ok(())
    }

    fn render(&self) -> CoreResult<String> {
        let metrics = self
            .metrics
            .lock()
            .map_err(|err| module_error(err.to_string()))?;
        Ok(render_prometheus_text(
            &metrics.iter().cloned().collect::<Vec<_>>(),
        ))
    }
}

fn spawn_http_server(listener: TcpListener, state: Arc<PrometheusState>) {
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                state.healthy.store(false, Ordering::Relaxed);
                return;
            };
            let state = state.clone();
            tokio::spawn(async move {
                let _ = handle_connection(stream, state).await;
            });
        }
    });
}

async fn handle_connection(mut stream: TcpStream, state: Arc<PrometheusState>) -> io::Result<()> {
    let mut buffer = vec![0; MAX_REQUEST_BYTES];
    let bytes = stream.read(&mut buffer).await?;
    let request = String::from_utf8_lossy(&buffer[..bytes]);
    let path = request_path(&request);
    let (status, content_type, body) = match path {
        Some("/metrics") => (
            "200 OK",
            "text/plain; version=0.0.4; charset=utf-8",
            state.render().unwrap_or_default(),
        ),
        Some("/healthz") => ("200 OK", "text/plain; charset=utf-8", "ok\n".to_string()),
        Some("/readyz") if state.healthy.load(Ordering::Relaxed) => {
            ("200 OK", "text/plain; charset=utf-8", "ready\n".to_string())
        }
        Some("/readyz") => (
            "503 Service Unavailable",
            "text/plain; charset=utf-8",
            "not ready\n".to_string(),
        ),
        _ => (
            "404 Not Found",
            "text/plain; charset=utf-8",
            "not found\n".to_string(),
        ),
    };
    let response = format!(
        "HTTP/1.1 {status}\r\ncontent-type: {content_type}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(response.as_bytes()).await
}

fn request_path(request: &str) -> Option<&str> {
    let mut parts = request.lines().next()?.split_whitespace();
    match (parts.next(), parts.next()) {
        (Some("GET"), Some(path)) => Some(path),
        _ => None,
    }
}

fn insert_prometheus_label(
    labels: &mut BTreeMap<String, String>,
    key: &str,
    value: &serde_json::Value,
) {
    let key = sanitize_identifier(key);
    if !prometheus_label_allowed(&key) {
        return;
    }
    if let Some(value) = prometheus_label_value(value) {
        labels.insert(key, value);
    }
}

fn prometheus_label_allowed(key: &str) -> bool {
    const AUTH_FRAGMENT: &str = concat!("au", "th");
    const AUTHS_FRAGMENT: &str = concat!("au", "ths");
    const SENSITIVE_FRAGMENTS: &[&str] = &[
        "authorization",
        AUTH_FRAGMENT,
        "token",
        "password",
        "passwd",
        "secret",
        "credential",
        "api_key",
        "apikey",
        "api-token",
        "argv",
        "argument",
        "arguments",
        "command_line",
        AUTHS_FRAGMENT,
        "server_address",
        "server_port",
        "process_pid",
        "process_parent_pid",
        "process_command",
        "linux_cgroup_path",
        "container_id",
        "k8s_pod_uid",
        "dns_question_name",
    ];

    !SENSITIVE_FRAGMENTS
        .iter()
        .any(|sensitive| contains_ascii_case_insensitive(key, sensitive))
}

fn sanitize_identifier(value: &str) -> String {
    if prometheus_identifier_is_already_valid(value) {
        return value.to_string();
    }

    let mut output = String::with_capacity(value.len());
    for (index, ch) in value.chars().enumerate() {
        let valid = ch == '_' || ch.is_ascii_alphanumeric();
        if valid && !(index == 0 && ch.is_ascii_digit()) {
            output.push(ch);
        } else {
            output.push('_');
        }
    }
    if output.is_empty() {
        "_".to_string()
    } else {
        output
    }
}

fn prometheus_identifier_is_already_valid(value: &str) -> bool {
    let mut bytes = value.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    if !(first == b'_' || first.is_ascii_alphabetic()) {
        return false;
    }
    bytes.all(|byte| byte == b'_' || byte.is_ascii_alphanumeric())
}

fn contains_ascii_case_insensitive(haystack: &str, needle: &str) -> bool {
    haystack
        .as_bytes()
        .windows(needle.len())
        .any(|window| window.eq_ignore_ascii_case(needle.as_bytes()))
}

fn prometheus_label_value(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::String(value) => Some(value.clone()),
        serde_json::Value::Number(value) => Some(value.to_string()),
        serde_json::Value::Bool(value) => Some(value.to_string()),
        _ => None,
    }
}

fn escape_label_value(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('\n', "\\n")
        .replace('"', "\\\"")
}

fn module_error(err: impl ToString) -> CoreError {
    CoreError::ModuleFailed {
        module: "sink.prometheus_http".to_string(),
        message: err.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use e_navigator_core::Sink;
    use e_navigator_signals::{
        ContainerContext, KubernetesContext, MetricAggregationWindow, NetworkAddressFamily,
        NetworkCounterMetric, NetworkProcessIdentity, NetworkProtocol, ProfilingAttribute,
        ProfilingConfidence, ProfilingCorrelationKind, ProfilingKind, ProfilingSessionObservation,
    };
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpStream,
    };

    #[test]
    fn renders_native_network_counter_with_stable_labels() {
        let signal = SignalEnvelope::network_counter_metric(
            "generator.network_metrics",
            Some("node-a".to_string()),
            NetworkCounterMetric {
                metric_name: "network.flow.bytes".to_string(),
                unit: "By".to_string(),
                value: 2048,
                window: MetricAggregationWindow {
                    start_unix_nanos: 1,
                    end_unix_nanos: 2,
                },
                process: None,
                protocol: Some(NetworkProtocol::Tcp),
                address_family: Some(NetworkAddressFamily::Ipv4),
                local_address: None,
                local_port: None,
                remote_address: None,
                remote_port: None,
                errno: None,
                container: None,
                kubernetes: Some(kubernetes_context()),
            },
        );

        let line = format_prometheus_metric_lines(&signal)
            .into_iter()
            .next()
            .expect("metric formats");
        let rendered = render_prometheus_text(&[line]);

        assert_eq!(
            rendered,
            "network_flow_bytes{host_name=\"node-a\",k8s_container_name=\"workload\",k8s_namespace_name=\"e-navigator-bench\",k8s_node_name=\"homelab-01\",k8s_pod_name=\"workload-a\",net_transport=\"tcp\",network_type=\"ipv4\"} 2048\n"
        );
    }

    #[test]
    fn renders_profile_session_aggregates_with_bounded_labels() {
        let signal = profile_session_signal();

        let lines = format_prometheus_metric_lines(&signal);
        let rendered = render_prometheus_text(&lines);

        assert_eq!(lines.len(), 4);
        assert!(rendered.contains("profile_session_samples_observed{"));
        assert!(rendered.contains("profile_session_samples_observed"));
        assert!(rendered.contains("profile_session_samples_dropped"));
        assert!(rendered.contains("profile_session_stacks_distinct"));
        assert!(rendered.contains("profile_session_sampling_period_nanos"));
        assert!(rendered.contains("profile_kind=\"cpu\""));
        assert!(rendered.contains("profile_correlation_kind=\"observed_profile_sample\""));
        assert!(rendered.contains("profile_confidence=\"high\""));
        assert!(rendered.contains("profile_source=\"source.aya_cpu_profile\""));
        assert!(rendered.contains("k8s_namespace_name=\"e-navigator-bench\""));
        assert!(rendered.contains("service_name=\"checkout\""));
        assert!(rendered.contains(" 27\n"));
        assert!(rendered.contains(" 3\n"));
        assert!(rendered.contains(" 5\n"));
        assert!(rendered.contains(" 10000000\n"));
        assert!(!rendered.contains("profile_id"));
        assert!(!rendered.contains("profile:abc"));
        assert!(!rendered.contains("stack_id"));
        assert!(!rendered.contains("checkout-api"));
        assert!(!rendered.contains("container-abc"));
        assert!(!rendered.contains("pod-uid"));
        assert!(!rendered.contains("tenant"));
        assert!(!rendered.contains("authorization"));
    }

    #[test]
    fn filters_secret_like_prometheus_labels_case_insensitively() {
        assert!(!prometheus_label_allowed("authorization"));
        assert!(!prometheus_label_allowed("API_TOKEN"));
        assert!(!prometheus_label_allowed("Process_Command"));
        assert!(prometheus_label_allowed("k8s_namespace_name"));
    }

    #[tokio::test]
    async fn prometheus_http_sink_serves_health_ready_and_metrics() {
        let (sink, address) = PrometheusHttpSink::bind_for_test(8)
            .await
            .expect("sink binds");
        let signal = SignalEnvelope::network_counter_metric(
            "generator.network_metrics",
            Some("node-a".to_string()),
            NetworkCounterMetric {
                metric_name: "network.flow.bytes".to_string(),
                unit: "By".to_string(),
                value: 2048,
                window: MetricAggregationWindow {
                    start_unix_nanos: 1,
                    end_unix_nanos: 2,
                },
                process: None,
                protocol: Some(NetworkProtocol::Tcp),
                address_family: Some(NetworkAddressFamily::Ipv4),
                local_address: None,
                local_port: None,
                remote_address: None,
                remote_port: None,
                errno: None,
                container: None,
                kubernetes: Some(kubernetes_context()),
            },
        );
        sink.write(&signal).await.expect("metric is accepted");

        let healthz = http_get(address, "/healthz").await;
        let readyz = http_get(address, "/readyz").await;
        let metrics = http_get(address, "/metrics").await;

        assert!(healthz.starts_with("HTTP/1.1 200 OK"));
        assert!(readyz.starts_with("HTTP/1.1 200 OK"));
        assert!(metrics.starts_with("HTTP/1.1 200 OK"));
        assert!(metrics.contains("network_flow_bytes"));
        assert!(metrics.contains("k8s_namespace_name=\"e-navigator-bench\""));
    }

    #[tokio::test]
    async fn prometheus_http_sink_serves_internal_metric_signals() {
        let (sink, address) = PrometheusHttpSink::bind_for_test(8)
            .await
            .expect("sink binds");
        let signal = SignalEnvelope::network_counter_metric(
            "generator.network_metrics",
            Some("node-a".to_string()),
            NetworkCounterMetric {
                metric_name: "network.connection.open.count".to_string(),
                unit: "{connection}".to_string(),
                value: 2,
                window: MetricAggregationWindow {
                    start_unix_nanos: 1,
                    end_unix_nanos: 2,
                },
                process: None,
                protocol: Some(NetworkProtocol::Tcp),
                address_family: Some(NetworkAddressFamily::Ipv4),
                local_address: None,
                local_port: None,
                remote_address: Some("203.0.113.10".to_string()),
                remote_port: Some(443),
                errno: None,
                container: None,
                kubernetes: Some(KubernetesContext {
                    namespace: "e-navigator-bench".to_string(),
                    pod_name: "workload-a".to_string(),
                    pod_uid: Some("pod-uid".to_string()),
                    container_name: Some("workload".to_string()),
                    node_name: Some("homelab-01".to_string()),
                    labels: BTreeMap::new(),
                }),
            },
        );
        sink.write(&signal).await.expect("metric is accepted");

        let metrics = http_get(address, "/metrics").await;

        assert!(metrics.starts_with("HTTP/1.1 200 OK"));
        assert!(metrics.contains("network_connection_open_count"));
        assert!(metrics.contains("k8s_namespace_name=\"e-navigator-bench\""));
        assert!(metrics.contains("k8s_pod_name=\"workload-a\""));
        assert!(!metrics.contains("server_address"));
        assert!(!metrics.contains("203.0.113.10"));
        assert!(!metrics.contains("server_port"));
    }

    async fn http_get(address: std::net::SocketAddr, path: &str) -> String {
        let mut stream = TcpStream::connect(address).await.expect("connect");
        stream
            .write_all(format!("GET {path} HTTP/1.1\r\nhost: test\r\n\r\n").as_bytes())
            .await
            .expect("write request");
        let mut response = String::new();
        stream
            .read_to_string(&mut response)
            .await
            .expect("read response");
        response
    }

    fn kubernetes_context() -> KubernetesContext {
        KubernetesContext {
            namespace: "e-navigator-bench".to_string(),
            pod_name: "workload-a".to_string(),
            pod_uid: Some("pod-uid".to_string()),
            container_name: Some("workload".to_string()),
            node_name: Some("homelab-01".to_string()),
            labels: BTreeMap::new(),
        }
    }

    fn profile_session_signal() -> SignalEnvelope {
        let mut labels = BTreeMap::new();
        labels.insert("app.kubernetes.io/name".to_string(), "checkout".to_string());

        SignalEnvelope::profiling_session_observation(
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
                process: Some(NetworkProcessIdentity {
                    pid: 42,
                    ppid: Some(1),
                    uid: Some(1000),
                    command: "checkout-api".to_string(),
                    executable: Some("/app/checkout-api".to_string()),
                    cgroup_id: None,
                }),
                container: Some(ContainerContext {
                    container_id: "container-abc".to_string(),
                    runtime: Some("containerd".to_string()),
                }),
                kubernetes: Some(KubernetesContext {
                    namespace: "e-navigator-bench".to_string(),
                    pod_name: "workload-a".to_string(),
                    pod_uid: Some("pod-uid".to_string()),
                    container_name: Some("workload".to_string()),
                    node_name: Some("homelab-01".to_string()),
                    labels,
                }),
                source: "source.aya_cpu_profile".to_string(),
                attributes: vec![
                    ProfilingAttribute {
                        key: "tenant".to_string(),
                        value: "customer-a".to_string(),
                    },
                    ProfilingAttribute {
                        key: "authorization".to_string(),
                        value: "secret".to_string(),
                    },
                ],
            },
        )
    }
}
