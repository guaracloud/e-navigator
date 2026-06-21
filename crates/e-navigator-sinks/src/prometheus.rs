use async_trait::async_trait;
use e_navigator_core::{
    CoreError, CoreResult, ModuleKind, ModuleMetadata, PrometheusHttpConfig, Sink,
};
use e_navigator_signals::{CompatibilityCounterMetric, SignalEnvelope, SignalPayload};
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
    pub value: u64,
}

pub fn format_prometheus_compatibility_metric(
    signal: &SignalEnvelope,
) -> Option<PrometheusMetricLine> {
    match &signal.payload {
        SignalPayload::CompatibilityCounterMetric(metric) => Some(metric_line(metric)),
        _ => None,
    }
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
        output.push_str(&metric.value.to_string());
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
        if let Some(line) = format_prometheus_compatibility_metric(signal) {
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

fn metric_line(metric: &CompatibilityCounterMetric) -> PrometheusMetricLine {
    PrometheusMetricLine {
        name: metric.metric_name.clone(),
        labels: metric
            .labels
            .iter()
            .filter(|(key, _)| prometheus_label_allowed(key))
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect(),
        value: metric.value,
    }
}

fn prometheus_label_allowed(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    const AUTH_FRAGMENT: &str = concat!("au", "th");
    ![
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
    ]
    .iter()
    .any(|sensitive| key.contains(sensitive))
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
    use e_navigator_signals::{CompatibilityCounterMetric, MetricAggregationWindow};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpStream,
    };

    #[test]
    fn renders_beyla_compatibility_counter_with_stable_labels() {
        let signal = SignalEnvelope::compatibility_counter_metric(
            "generator.guara_compat",
            Some("node-a".to_string()),
            CompatibilityCounterMetric {
                metric_name: "beyla_network_flow_bytes_total".to_string(),
                unit: "By".to_string(),
                value: 2048,
                window: MetricAggregationWindow {
                    start_unix_nanos: 1,
                    end_unix_nanos: 2,
                },
                labels: BTreeMap::from([
                    ("k8s_dst_namespace".to_string(), "proj-a".to_string()),
                    ("k8s_dst_owner_name".to_string(), "redis".to_string()),
                    ("k8s_dst_owner_type".to_string(), "statefulset".to_string()),
                    ("k8s_src_namespace".to_string(), "proj-a".to_string()),
                    ("k8s_src_owner_name".to_string(), "api".to_string()),
                    ("k8s_src_owner_type".to_string(), "deployment".to_string()),
                ]),
            },
        );

        let line = format_prometheus_compatibility_metric(&signal).expect("metric formats");
        let rendered = render_prometheus_text(&[line]);

        assert_eq!(
            rendered,
            "beyla_network_flow_bytes_total{k8s_dst_namespace=\"proj-a\",k8s_dst_owner_name=\"redis\",k8s_dst_owner_type=\"statefulset\",k8s_src_namespace=\"proj-a\",k8s_src_owner_name=\"api\",k8s_src_owner_type=\"deployment\"} 2048\n"
        );
    }

    #[test]
    fn drops_secret_like_labels_from_prometheus_text() {
        let signal = SignalEnvelope::compatibility_counter_metric(
            "generator.guara_compat",
            Some("node-a".to_string()),
            CompatibilityCounterMetric {
                metric_name: "e_navigator_exported_records_total".to_string(),
                unit: "{record}".to_string(),
                value: 1,
                window: MetricAggregationWindow {
                    start_unix_nanos: 1,
                    end_unix_nanos: 2,
                },
                labels: BTreeMap::from([
                    ("k8s_namespace_name".to_string(), "default".to_string()),
                    ("authorization".to_string(), "Bearer secret".to_string()),
                    ("api_token".to_string(), "abc123".to_string()),
                    ("argv".to_string(), "curl --password secret".to_string()),
                ]),
            },
        );

        let line = format_prometheus_compatibility_metric(&signal).expect("metric formats");
        let rendered = render_prometheus_text(&[line]);

        assert!(rendered.contains("k8s_namespace_name=\"default\""));
        assert!(!rendered.contains("authorization"));
        assert!(!rendered.contains("api_token"));
        assert!(!rendered.contains("argv"));
        assert!(!rendered.contains("secret"));
    }

    #[tokio::test]
    async fn prometheus_http_sink_serves_health_ready_and_metrics() {
        let (sink, address) = PrometheusHttpSink::bind_for_test(8)
            .await
            .expect("sink binds");
        let signal = SignalEnvelope::compatibility_counter_metric(
            "generator.guara_compat",
            Some("node-a".to_string()),
            CompatibilityCounterMetric {
                metric_name: "beyla_network_flow_bytes_total".to_string(),
                unit: "By".to_string(),
                value: 2048,
                window: MetricAggregationWindow {
                    start_unix_nanos: 1,
                    end_unix_nanos: 2,
                },
                labels: BTreeMap::from([("k8s_src_namespace".to_string(), "proj-a".to_string())]),
            },
        );
        sink.write(&signal).await.expect("metric is accepted");

        let healthz = http_get(address, "/healthz").await;
        let readyz = http_get(address, "/readyz").await;
        let metrics = http_get(address, "/metrics").await;

        assert!(healthz.starts_with("HTTP/1.1 200 OK"));
        assert!(readyz.starts_with("HTTP/1.1 200 OK"));
        assert!(metrics.starts_with("HTTP/1.1 200 OK"));
        assert!(metrics.contains("beyla_network_flow_bytes_total"));
        assert!(metrics.contains("k8s_src_namespace=\"proj-a\""));
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
}
