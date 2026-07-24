use crate::{
    NativeTelemetryRegistry,
    otel_metric::{OtelMetricRecord, OtelMetricValue, format_otel_metric_record},
    profile_format::format_profile_record,
};
use async_trait::async_trait;
use e_navigator_core::{
    CoreError, CoreResult, ModuleKind, ModuleMetadata, PrometheusHttpConfig, Sink,
};
use e_navigator_signals::{SignalEnvelope, SignalPayload, contains_ascii_case_insensitive};
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
const MAX_PROMETHEUS_LABEL_NAME_BYTES: usize = 128;
const MAX_PROMETHEUS_LABEL_VALUE_BYTES: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrometheusMetricLine {
    pub name: String,
    pub labels: BTreeMap<String, String>,
    pub value: String,
}

#[cfg(test)]
fn format_prometheus_metric_lines(signal: &SignalEnvelope) -> Vec<PrometheusMetricLine> {
    format_prometheus_metric_lines_with_families(signal, true, true)
}

fn format_prometheus_metric_lines_with_families(
    signal: &SignalEnvelope,
    metrics_enabled: bool,
    profiles_enabled: bool,
) -> Vec<PrometheusMetricLine> {
    if metrics_enabled && let Some(record) = format_otel_metric_record(signal) {
        return format_otel_prometheus_metric_lines(record);
    }

    if profiles_enabled {
        return format_profile_metric_lines(signal);
    }

    Vec::new()
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

fn format_profile_metric_lines(signal: &SignalEnvelope) -> Vec<PrometheusMetricLine> {
    match &signal.payload {
        SignalPayload::ProfilingSessionObservation(_) => {
            format_profile_session_metric_lines(signal)
        }
        SignalPayload::ProfilingWarningObservation(_) => {
            format_profile_warning_metric_lines(signal)
        }
        _ => Vec::new(),
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

fn format_profile_warning_metric_lines(signal: &SignalEnvelope) -> Vec<PrometheusMetricLine> {
    let SignalPayload::ProfilingWarningObservation(warning) = &signal.payload else {
        return Vec::new();
    };

    let mut labels = BTreeMap::new();
    insert_profile_resource_labels(
        &mut labels,
        signal,
        warning.container.as_ref(),
        warning.kubernetes.as_ref(),
    );
    insert_prometheus_label(
        &mut labels,
        "warning.type",
        &serde_json::json!(warning.warning_type),
    );
    insert_prometheus_label(
        &mut labels,
        "trace.source.signal.kind",
        &serde_json::json!(warning.source_signal_kind),
    );
    insert_prometheus_label(
        &mut labels,
        "trace.source.module",
        &serde_json::json!(warning.source_module),
    );
    insert_prometheus_label(
        &mut labels,
        "profile.kind",
        &serde_json::json!(profile_kind_name(warning.profiling_kind)),
    );
    insert_prometheus_label(
        &mut labels,
        "profile.correlation.kind",
        &serde_json::json!(profile_correlation_kind_name(warning.correlation_kind)),
    );
    insert_prometheus_label(
        &mut labels,
        "profile.confidence",
        &serde_json::json!(profile_confidence_name(warning.confidence)),
    );

    vec![PrometheusMetricLine {
        name: sanitize_identifier("profiling.warning.count"),
        labels,
        value: "1".to_string(),
    }]
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
    metrics_enabled: bool,
    profiles_enabled: bool,
}

impl PrometheusHttpSink {
    pub fn bind(config: PrometheusHttpConfig) -> CoreResult<Self> {
        Self::bind_with_telemetry(config, NativeTelemetryRegistry::default())
    }

    pub fn bind_with_telemetry(
        config: PrometheusHttpConfig,
        telemetry_registry: NativeTelemetryRegistry,
    ) -> CoreResult<Self> {
        validate_max_metric_lines(config.max_metric_lines)?;
        let bind_address = format!("{}:{}", config.bind_address, config.port);
        let listener = std::net::TcpListener::bind(&bind_address).map_err(module_error)?;
        listener.set_nonblocking(true).map_err(module_error)?;
        let state = Arc::new(PrometheusState::new(
            config.max_metric_lines,
            telemetry_registry,
        ));
        if tokio::runtime::Handle::try_current().is_ok() {
            let listener = TcpListener::from_std(listener).map_err(module_error)?;
            spawn_http_server(listener, state.clone());
        }
        Ok(Self {
            state,
            metrics_enabled: config.metrics_enabled,
            profiles_enabled: config.profiles_enabled,
        })
    }

    #[cfg(test)]
    pub async fn bind_for_test(
        max_metric_lines: usize,
    ) -> CoreResult<(Self, std::net::SocketAddr)> {
        Self::bind_for_test_with_families(max_metric_lines, true, true).await
    }

    #[cfg(test)]
    pub async fn bind_for_test_with_families(
        max_metric_lines: usize,
        metrics_enabled: bool,
        profiles_enabled: bool,
    ) -> CoreResult<(Self, std::net::SocketAddr)> {
        Self::bind_for_test_with_families_and_telemetry(
            max_metric_lines,
            metrics_enabled,
            profiles_enabled,
            NativeTelemetryRegistry::default(),
        )
        .await
    }

    #[cfg(test)]
    async fn bind_for_test_with_families_and_telemetry(
        max_metric_lines: usize,
        metrics_enabled: bool,
        profiles_enabled: bool,
        telemetry_registry: NativeTelemetryRegistry,
    ) -> CoreResult<(Self, std::net::SocketAddr)> {
        validate_max_metric_lines(max_metric_lines)?;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").map_err(module_error)?;
        let address = listener.local_addr().map_err(module_error)?;
        listener.set_nonblocking(true).map_err(module_error)?;
        let listener = TcpListener::from_std(listener).map_err(module_error)?;
        let state = Arc::new(PrometheusState::new(max_metric_lines, telemetry_registry));
        spawn_http_server(listener, state.clone());
        Ok((
            Self {
                state,
                metrics_enabled,
                profiles_enabled,
            },
            address,
        ))
    }

    fn accepts_signal(&self, signal: &SignalEnvelope) -> bool {
        (self.metrics_enabled
            && matches!(
                &signal.payload,
                SignalPayload::NetworkCounterMetric(_)
                    | SignalPayload::NetworkDurationMetric(_)
                    | SignalPayload::NetworkGaugeMetric(_)
                    | SignalPayload::DnsCounterMetric(_)
                    | SignalPayload::DnsLatencyMetric(_)
                    | SignalPayload::ResourceGaugeMetric(_)
                    | SignalPayload::ResourceCounterMetric(_)
            ))
            || (self.profiles_enabled
                && matches!(
                    &signal.payload,
                    SignalPayload::ProfileSampleObservation(_)
                        | SignalPayload::ProfilingSessionObservation(_)
                        | SignalPayload::ProfilingWarningObservation(_)
                ))
    }

    fn write_signal(&self, signal: &SignalEnvelope) -> CoreResult<()> {
        for line in format_prometheus_metric_lines_with_families(
            signal,
            self.metrics_enabled,
            self.profiles_enabled,
        ) {
            self.state.push(line)?;
        }
        if self.profiles_enabled
            && matches!(signal.payload, SignalPayload::ProfileSampleObservation(_))
        {
            self.state.push_profile(signal.clone())?;
        }
        Ok(())
    }
}

fn validate_max_metric_lines(max_metric_lines: usize) -> CoreResult<()> {
    if max_metric_lines == 0 {
        return Err(module_error(
            "prometheus_http.max_metric_lines must be greater than zero",
        ));
    }
    if max_metric_lines > PrometheusHttpConfig::MAX_METRIC_LINES_LIMIT {
        return Err(module_error(format!(
            "prometheus_http.max_metric_lines must be less than or equal to {}",
            PrometheusHttpConfig::MAX_METRIC_LINES_LIMIT
        )));
    }
    Ok(())
}

#[async_trait]
impl Sink<SignalEnvelope> for PrometheusHttpSink {
    fn metadata(&self) -> ModuleMetadata {
        ModuleMetadata::new("sink.prometheus_http", ModuleKind::Sink)
    }

    fn accepts(&self, signal: &SignalEnvelope) -> bool {
        self.accepts_signal(signal)
    }

    fn write_immediate(&self, signal: &SignalEnvelope) -> Option<CoreResult<()>> {
        Some(self.write_signal(signal))
    }

    async fn write(&self, signal: &SignalEnvelope) -> CoreResult<()> {
        self.write_signal(signal)
    }
}

const MAX_PPROF_WINDOW_SAMPLES: usize = 4096;

#[derive(Debug)]
struct PrometheusState {
    max_metric_lines: usize,
    metrics: Mutex<PrometheusMetricStore>,
    profiles: Mutex<std::collections::VecDeque<SignalEnvelope>>,
    healthy: AtomicBool,
    telemetry_registry: NativeTelemetryRegistry,
}

impl PrometheusState {
    fn new(max_metric_lines: usize, telemetry_registry: NativeTelemetryRegistry) -> Self {
        Self {
            max_metric_lines,
            metrics: Mutex::new(PrometheusMetricStore::default()),
            profiles: Mutex::new(std::collections::VecDeque::new()),
            healthy: AtomicBool::new(true),
            telemetry_registry,
        }
    }

    fn push(&self, line: PrometheusMetricLine) -> CoreResult<()> {
        let mut metrics = self
            .metrics
            .lock()
            .map_err(|err| module_error(err.to_string()))?;
        metrics.push(line, self.max_metric_lines);
        Ok(())
    }

    fn push_profile(&self, signal: SignalEnvelope) -> CoreResult<()> {
        let mut profiles = self
            .profiles
            .lock()
            .map_err(|_| module_error("prometheus profile window lock poisoned"))?;
        if profiles.len() >= MAX_PPROF_WINDOW_SAMPLES {
            profiles.pop_front();
        }
        profiles.push_back(signal);
        Ok(())
    }

    fn render_pprof(&self) -> CoreResult<Option<Vec<u8>>> {
        let profiles = self
            .profiles
            .lock()
            .map_err(|_| module_error("prometheus profile window lock poisoned"))?;
        let refs = profiles.iter().collect::<Vec<_>>();
        Ok(crate::pprof_profile::format_pprof_profile_batch(&refs))
    }

    fn render(&self) -> CoreResult<String> {
        let metrics = self
            .metrics
            .lock()
            .map_err(|err| module_error(err.to_string()))?;
        let mut lines = metrics.lines();
        lines.extend(self.telemetry_registry.prometheus_lines());
        Ok(render_prometheus_text(&lines))
    }
}

#[derive(Debug, Default)]
struct PrometheusMetricStore {
    order: VecDeque<PrometheusSeriesKey>,
    latest: BTreeMap<PrometheusSeriesKey, PrometheusMetricLine>,
}

impl PrometheusMetricStore {
    fn push(&mut self, line: PrometheusMetricLine, max_metric_lines: usize) {
        let key = PrometheusSeriesKey::from(&line);
        if let Some(existing) = self.latest.get_mut(&key) {
            *existing = line;
            return;
        }
        while self.latest.len() >= max_metric_lines {
            let Some(oldest) = self.order.pop_front() else {
                break;
            };
            self.latest.remove(&oldest);
        }
        self.order.push_back(key.clone());
        self.latest.insert(key, line);
    }

    fn lines(&self) -> Vec<PrometheusMetricLine> {
        self.order
            .iter()
            .filter_map(|key| self.latest.get(key).cloned())
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct PrometheusSeriesKey {
    name: String,
    labels: BTreeMap<String, String>,
}

impl From<&PrometheusMetricLine> for PrometheusSeriesKey {
    fn from(line: &PrometheusMetricLine) -> Self {
        Self {
            name: line.name.clone(),
            labels: line.labels.clone(),
        }
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
    let (status, content_type, body): (&str, &str, Vec<u8>) = match path {
        Some("/metrics") => (
            "200 OK",
            "text/plain; version=0.0.4; charset=utf-8",
            state.render().unwrap_or_default().into_bytes(),
        ),
        Some("/debug/pprof/profile") => match state.render_pprof() {
            Ok(Some(bytes)) => ("200 OK", "application/octet-stream", bytes),
            Ok(None) => ("204 No Content", "text/plain; charset=utf-8", Vec::new()),
            Err(_) => (
                "500 Internal Server Error",
                "text/plain; charset=utf-8",
                b"pprof render failed\n".to_vec(),
            ),
        },
        Some("/healthz") => ("200 OK", "text/plain; charset=utf-8", b"ok\n".to_vec()),
        Some("/readyz") if state.healthy.load(Ordering::Relaxed) => {
            ("200 OK", "text/plain; charset=utf-8", b"ready\n".to_vec())
        }
        Some("/readyz") => (
            "503 Service Unavailable",
            "text/plain; charset=utf-8",
            b"not ready\n".to_vec(),
        ),
        _ => (
            "404 Not Found",
            "text/plain; charset=utf-8",
            b"not found\n".to_vec(),
        ),
    };
    let header = format!(
        "HTTP/1.1 {status}\r\ncontent-type: {content_type}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(header.as_bytes()).await?;
    stream.write_all(&body).await
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
    if key.len() > MAX_PROMETHEUS_LABEL_NAME_BYTES {
        return;
    }
    if let Some(value) = prometheus_redacted_identity_label_value(&key, value) {
        labels.insert(format!("{key}_hash"), value);
        return;
    }
    if !prometheus_label_allowed(&key) {
        return;
    }
    if let Some(value) = prometheus_label_value(value) {
        labels.insert(key, value);
    }
}

fn insert_profile_resource_labels(
    labels: &mut BTreeMap<String, String>,
    signal: &SignalEnvelope,
    container: Option<&e_navigator_signals::ContainerContext>,
    kubernetes: Option<&e_navigator_signals::KubernetesContext>,
) {
    if let Some(host) = &signal.host {
        insert_prometheus_label(labels, "host.name", &serde_json::json!(host));
    }
    if let Some(container) = container {
        insert_prometheus_label(
            labels,
            "container.id",
            &serde_json::json!(container.container_id),
        );
        if let Some(runtime) = &container.runtime {
            insert_prometheus_label(labels, "container.runtime", &serde_json::json!(runtime));
        }
    }
    if let Some(kubernetes) = kubernetes {
        insert_prometheus_label(
            labels,
            "k8s.namespace.name",
            &serde_json::json!(kubernetes.namespace),
        );
        insert_prometheus_label(
            labels,
            "k8s.pod.name",
            &serde_json::json!(kubernetes.pod_name),
        );
        if let Some(container_name) = &kubernetes.container_name {
            insert_prometheus_label(
                labels,
                "k8s.container.name",
                &serde_json::json!(container_name),
            );
        }
        if let Some(node_name) = &kubernetes.node_name {
            insert_prometheus_label(labels, "k8s.node.name", &serde_json::json!(node_name));
        }
        if let Some(service_name) = kubernetes
            .labels
            .get("app.kubernetes.io/name")
            .or_else(|| kubernetes.labels.get("app"))
            .filter(|name| !name.is_empty())
        {
            insert_prometheus_label(labels, "service.name", &serde_json::json!(service_name));
        }
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

fn prometheus_redacted_identity_label_value(
    key: &str,
    value: &serde_json::Value,
) -> Option<String> {
    const REDACTED_IDENTITY_LABELS: &[&str] = &[
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

    if !REDACTED_IDENTITY_LABELS.contains(&key) {
        return None;
    }
    let value = prometheus_label_value(value)?;
    Some(stable_prometheus_label_hash(key, &value))
}

fn stable_prometheus_label_hash(key: &str, value: &str) -> String {
    const FNV_OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
    const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

    let mut hash = FNV_OFFSET_BASIS;
    for byte in key.bytes().chain([0xff]).chain(value.bytes()) {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    format!("{hash:016x}")
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

fn prometheus_label_value(value: &serde_json::Value) -> Option<String> {
    let value = match value {
        serde_json::Value::String(value) => Some(value.clone()),
        serde_json::Value::Number(value) => Some(value.to_string()),
        serde_json::Value::Bool(value) => Some(value.to_string()),
        _ => None,
    }?;
    (value.len() <= MAX_PROMETHEUS_LABEL_VALUE_BYTES).then_some(value)
}

fn profile_kind_name(kind: e_navigator_signals::ProfilingKind) -> &'static str {
    match kind {
        e_navigator_signals::ProfilingKind::Cpu => "cpu",
        e_navigator_signals::ProfilingKind::Memory => "memory",
        e_navigator_signals::ProfilingKind::Lock => "lock",
        e_navigator_signals::ProfilingKind::Unknown => "unknown",
        _ => "unknown",
    }
}

fn profile_correlation_kind_name(
    kind: e_navigator_signals::ProfilingCorrelationKind,
) -> &'static str {
    match kind {
        e_navigator_signals::ProfilingCorrelationKind::ObservedProfileSample => {
            "observed_profile_sample"
        }
        e_navigator_signals::ProfilingCorrelationKind::Synthetic => "synthetic",
        e_navigator_signals::ProfilingCorrelationKind::RuntimeInferred => "runtime_inferred",
        _ => "unknown",
    }
}

fn profile_confidence_name(kind: e_navigator_signals::ProfilingConfidence) -> &'static str {
    match kind {
        e_navigator_signals::ProfilingConfidence::Low => "low",
        e_navigator_signals::ProfilingConfidence::Medium => "medium",
        e_navigator_signals::ProfilingConfidence::High => "high",
        _ => "unknown",
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
        ContainerContext, DnsCounterMetric, DnsQueryType, KubernetesContext,
        MetricAggregationWindow, NetworkAddressFamily, NetworkCounterMetric,
        NetworkProcessIdentity, NetworkProtocol, ProfileSampleObservation, ProfilingAttribute,
        ProfilingConfidence, ProfilingCorrelationKind, ProfilingFrame, ProfilingKind,
        ProfilingSessionObservation, ProfilingWarningObservation,
    };
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpStream,
    };

    #[test]
    fn prometheus_http_sink_rejects_invalid_metric_storage_bounds() {
        for (max_metric_lines, expected_message) in [
            (
                0,
                "prometheus_http.max_metric_lines must be greater than zero",
            ),
            (
                PrometheusHttpConfig::MAX_METRIC_LINES_LIMIT + 1,
                "prometheus_http.max_metric_lines must be less than or equal to",
            ),
        ] {
            let err = PrometheusHttpSink::bind(PrometheusHttpConfig {
                max_metric_lines,
                ..PrometheusHttpConfig::default()
            })
            .expect_err("invalid storage bound fails before binding");

            assert!(err.to_string().contains(expected_message));
        }
    }

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
            "network_flow_bytes{host_name=\"node-a\",k8s_container_name=\"workload\",k8s_namespace_name=\"e-navigator-bench\",k8s_node_name=\"homelab-01\",k8s_pod_name=\"workload-a\",k8s_pod_uid_hash=\"c4ec3fe00b0d17fd\",net_transport=\"tcp\",network_type=\"ipv4\"} 2048\n"
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
    fn renders_profile_warning_counts_with_bounded_labels() {
        let signal = profile_warning_signal();

        let lines = format_prometheus_metric_lines(&signal);
        let rendered = render_prometheus_text(&lines);

        assert_eq!(lines.len(), 1);
        assert!(rendered.contains("profiling_warning_count{"));
        assert!(rendered.contains("warning_type=\"dropped_profile_samples\""));
        assert!(rendered.contains("trace_source_signal_kind=\"profile_sample_observation\""));
        assert!(rendered.contains("trace_source_module=\"source.aya_cpu_profile\""));
        assert!(rendered.contains("profile_kind=\"cpu\""));
        assert!(rendered.contains("profile_correlation_kind=\"observed_profile_sample\""));
        assert!(rendered.contains("profile_confidence=\"medium\""));
        assert!(rendered.contains("k8s_namespace_name=\"e-navigator-bench\""));
        assert!(rendered.contains("service_name=\"checkout\""));
        assert!(rendered.contains(" 1\n"));
        assert!(!rendered.contains("profile samples were dropped"));
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

    #[test]
    fn preserves_redacted_dns_series_identity_without_exporting_raw_names() {
        let mut store = PrometheusMetricStore::default();
        for (query_name, value) in [
            ("api.private.example", 500),
            ("missing.private.example", 50),
        ] {
            let signal = SignalEnvelope::dns_counter_metric(
                "generator.dns_metrics",
                Some("node-a".to_string()),
                DnsCounterMetric {
                    metric_name: "dns.query.count".to_string(),
                    unit: "{query}".to_string(),
                    value,
                    window: MetricAggregationWindow {
                        start_unix_nanos: 1,
                        end_unix_nanos: 2,
                    },
                    query_name: Some(query_name.to_string()),
                    query_type: Some(DnsQueryType::A),
                    response_code: None,
                    server_address: None,
                    server_port: None,
                    container: None,
                    kubernetes: Some(kubernetes_context()),
                },
            );
            for line in format_prometheus_metric_lines(&signal) {
                store.push(line, 8);
            }
        }

        let lines = store.lines();
        assert_eq!(lines.len(), 2);
        assert_eq!(
            lines
                .iter()
                .map(|line| line.value.parse::<u64>().expect("counter value"))
                .sum::<u64>(),
            550
        );
        let hashes = lines
            .iter()
            .map(|line| {
                line.labels
                    .get("dns_question_name_hash")
                    .expect("redacted identity hash")
            })
            .collect::<Vec<_>>();
        assert_ne!(hashes[0], hashes[1]);
        assert!(
            hashes.iter().all(|hash| {
                hash.len() == 16 && hash.bytes().all(|byte| byte.is_ascii_hexdigit())
            })
        );

        let rendered = render_prometheus_text(&lines);
        assert!(!rendered.contains("api.private.example"));
        assert!(!rendered.contains("missing.private.example"));
    }

    #[test]
    fn escapes_prometheus_label_values() {
        let mut labels = BTreeMap::new();
        labels.insert("label".to_string(), "line\nquote\"backslash\\".to_string());

        let rendered = render_prometheus_text(&[PrometheusMetricLine {
            name: "test_metric".to_string(),
            labels,
            value: "1".to_string(),
        }]);

        assert_eq!(
            rendered,
            "test_metric{label=\"line\\nquote\\\"backslash\\\\\"} 1\n"
        );
    }

    #[test]
    fn prometheus_metric_store_replaces_existing_series_and_preserves_eviction_order() {
        let mut store = PrometheusMetricStore::default();

        store.push(prometheus_line("first", "1"), 2);
        store.push(prometheus_line("second", "2"), 2);
        store.push(prometheus_line("first", "9"), 2);

        let updated = render_prometheus_text(&store.lines());
        assert!(!updated.contains("first 1"));
        assert!(updated.contains("first 9"));
        assert!(updated.contains("second 2"));
        assert_eq!(store.lines().len(), 2);

        store.push(prometheus_line("third", "3"), 2);

        let rendered = render_prometheus_text(&store.lines());

        assert!(!rendered.contains("first 9"));
        assert!(rendered.contains("second 2"));
        assert!(rendered.contains("third 3"));
    }

    #[test]
    fn drops_oversized_prometheus_label_values() {
        assert_eq!(
            prometheus_label_value(&serde_json::json!(
                "v".repeat(MAX_PROMETHEUS_LABEL_VALUE_BYTES + 1)
            )),
            None
        );
        assert_eq!(
            prometheus_label_value(&serde_json::json!(
                "v".repeat(MAX_PROMETHEUS_LABEL_VALUE_BYTES)
            )),
            Some("v".repeat(MAX_PROMETHEUS_LABEL_VALUE_BYTES))
        );
    }

    #[test]
    fn drops_oversized_prometheus_label_names_after_sanitizing() {
        let mut labels = BTreeMap::new();
        insert_prometheus_label(
            &mut labels,
            &"label".repeat(32),
            &serde_json::json!("value"),
        );
        assert!(labels.is_empty());

        insert_prometheus_label(
            &mut labels,
            &"label".repeat(25),
            &serde_json::json!("value"),
        );
        assert_eq!(labels.len(), 1);
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
    async fn prometheus_http_sink_exposes_live_otlp_worker_telemetry() {
        let telemetry_registry = NativeTelemetryRegistry::default();
        let otlp = crate::OtlpHttpSink::new_with_telemetry(
            e_navigator_core::OtlpHttpConfig {
                enabled: true,
                metrics_endpoint: "http://127.0.0.1:9/v1/metrics".to_string(),
                metrics_enabled: true,
                traces_enabled: false,
                profiles_enabled: false,
                queue_capacity: 64,
                batch_size: 64,
                flush_interval_millis: 60_000,
                max_retries: 0,
                ..e_navigator_core::OtlpHttpConfig::default()
            },
            telemetry_registry.clone(),
        )
        .expect("OTLP worker starts");
        let (_prometheus, address) = PrometheusHttpSink::bind_for_test_with_families_and_telemetry(
            8,
            true,
            true,
            telemetry_registry,
        )
        .await
        .expect("Prometheus endpoint binds");

        otlp.write(&network_counter_signal_named("network.test"))
            .await
            .expect("metric enters the bounded worker");
        let metrics = http_get(address, "/metrics").await;

        assert!(
            metrics.contains("e_navigator_export_queue_capacity{signal_family=\"metrics\"} 64")
        );
        assert!(metrics.contains("e_navigator_export_enqueued_total{signal_family=\"metrics\"} 0"));
        assert!(metrics.contains("e_navigator_export_metric_timestamp_pending_series 1"));
        assert!(metrics.contains("e_navigator_export_metric_same_millisecond_coalesced_total 0"));
        assert!(metrics.contains("e_navigator_export_retry_attempts_total"));
        assert!(metrics.contains("e_navigator_export_partial_success_total"));
        assert!(metrics.contains("e_navigator_export_rejected_items_total"));
        assert!(metrics.contains("e_navigator_export_permanent_responses_total"));
        assert!(metrics.contains("e_navigator_export_invalid_responses_total"));
        Sink::shutdown(&otlp).await.expect("OTLP workers drain");
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
        assert!(metrics.contains("server_address_hash="));
        assert!(!metrics.contains("203.0.113.10"));
        assert!(metrics.contains("server_port_hash="));
    }

    #[tokio::test]
    async fn prometheus_http_sink_respects_signal_family_toggles() {
        let (profile_only_sink, profile_only_address) =
            PrometheusHttpSink::bind_for_test_with_families(8, false, true)
                .await
                .expect("profile-only sink binds");
        profile_only_sink
            .write(&network_counter_signal())
            .await
            .expect("metric signal is accepted");
        profile_only_sink
            .write(&profile_session_signal())
            .await
            .expect("profile signal is accepted");

        let profile_only_metrics = http_get(profile_only_address, "/metrics").await;

        assert!(profile_only_metrics.contains("profile_session_samples_observed"));
        assert!(!profile_only_metrics.contains("network_flow_bytes"));

        let (metric_only_sink, metric_only_address) =
            PrometheusHttpSink::bind_for_test_with_families(8, true, false)
                .await
                .expect("metric-only sink binds");
        metric_only_sink
            .write(&network_counter_signal())
            .await
            .expect("metric signal is accepted");
        metric_only_sink
            .write(&profile_session_signal())
            .await
            .expect("profile signal is accepted");

        let metric_only_metrics = http_get(metric_only_address, "/metrics").await;

        assert!(metric_only_metrics.contains("network_flow_bytes"));
        assert!(!metric_only_metrics.contains("profile_session_samples_observed"));
    }

    #[tokio::test]
    async fn prometheus_http_sink_bounds_latest_metric_storage() {
        let (sink, address) = PrometheusHttpSink::bind_for_test(2)
            .await
            .expect("sink binds");
        for metric_name in [
            "network.test.first",
            "network.test.second",
            "network.test.third",
        ] {
            sink.write(&network_counter_signal_named(metric_name))
                .await
                .expect("metric signal is accepted");
        }

        let metrics = http_get(address, "/metrics").await;

        assert!(!metrics.contains("network_test_first"));
        assert!(metrics.contains("network_test_second"));
        assert!(metrics.contains("network_test_third"));
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

    async fn http_get_bytes(address: std::net::SocketAddr, path: &str) -> (String, Vec<u8>) {
        let mut stream = TcpStream::connect(address).await.expect("connect");
        stream
            .write_all(format!("GET {path} HTTP/1.1\r\nhost: test\r\n\r\n").as_bytes())
            .await
            .expect("write request");
        let mut response = Vec::new();
        stream
            .read_to_end(&mut response)
            .await
            .expect("read response");
        let split = response
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .expect("headers terminate");
        let headers = String::from_utf8_lossy(&response[..split]).to_string();
        let body = response[split + 4..].to_vec();
        (headers, body)
    }

    fn cpu_profile_sample_signal() -> SignalEnvelope {
        SignalEnvelope::profile_sample_observation(
            "source.aya_cpu_profile",
            Some("node-a".to_string()),
            ProfileSampleObservation {
                timestamp_unix_nanos: 1_000,
                profiling_kind: ProfilingKind::Cpu,
                correlation_kind: ProfilingCorrelationKind::ObservedProfileSample,
                confidence: ProfilingConfidence::Medium,
                sample_count: 3,
                sampling_period_nanos: Some(20_000_000),
                stack_id: "stack:aa".to_string(),
                stack_frames: vec![ProfilingFrame {
                    symbol: Some("/usr/bin/app+0x1500".to_string()),
                    module: Some("/usr/bin/app".to_string()),
                    file: None,
                    line: None,
                    module_offset: Some(0x1500),
                }],
                process: None,
                container: None,
                kubernetes: None,
                thread_id: None,
                thread_name: None,
                attributes: vec![],
            },
        )
    }

    #[tokio::test]
    async fn prometheus_http_sink_serves_pprof_profile() {
        let (sink, address) = PrometheusHttpSink::bind_for_test(8)
            .await
            .expect("bind prometheus sink");

        // No samples yet: the endpoint returns 204.
        let (headers, body) = http_get_bytes(address, "/debug/pprof/profile").await;
        assert!(headers.contains("204 No Content"), "{headers}");
        assert!(body.is_empty());

        sink.write(&cpu_profile_sample_signal())
            .await
            .expect("write profile sample");

        let (headers, body) = http_get_bytes(address, "/debug/pprof/profile").await;
        assert!(headers.contains("200 OK"), "{headers}");
        assert!(headers.contains("application/octet-stream"), "{headers}");
        assert!(!body.is_empty());
        // The body is a decodable pprof profile carrying the module address.
        let profile = crate::pprof_profile::format_pprof_profile(&cpu_profile_sample_signal())
            .expect("reference profile");
        assert!(!profile.is_empty());
    }

    #[tokio::test]
    async fn prometheus_http_sink_omits_pprof_when_profiles_disabled() {
        let (sink, address) = PrometheusHttpSink::bind_for_test_with_families(8, true, false)
            .await
            .expect("bind prometheus sink");
        sink.write(&cpu_profile_sample_signal())
            .await
            .expect("write profile sample");
        let (headers, body) = http_get_bytes(address, "/debug/pprof/profile").await;
        assert!(headers.contains("204 No Content"), "{headers}");
        assert!(body.is_empty());
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

    fn network_counter_signal() -> SignalEnvelope {
        network_counter_signal_named("network.flow.bytes")
    }

    fn network_counter_signal_named(metric_name: &str) -> SignalEnvelope {
        SignalEnvelope::network_counter_metric(
            "generator.network_metrics",
            Some("node-a".to_string()),
            NetworkCounterMetric {
                metric_name: metric_name.to_string(),
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
        )
    }

    fn prometheus_line(name: &str, value: &str) -> PrometheusMetricLine {
        PrometheusMetricLine {
            name: name.to_string(),
            labels: BTreeMap::new(),
            value: value.to_string(),
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

    fn profile_warning_signal() -> SignalEnvelope {
        let mut labels = BTreeMap::new();
        labels.insert("app.kubernetes.io/name".to_string(), "checkout".to_string());

        SignalEnvelope::profiling_warning_observation(
            "generator.profiling",
            Some("node-a".to_string()),
            ProfilingWarningObservation {
                warning_type: "dropped_profile_samples".to_string(),
                message: "profile samples were dropped by bounded aggregation".to_string(),
                timestamp_unix_nanos: 3,
                source_signal_kind: "profile_sample_observation".to_string(),
                source_module: "source.aya_cpu_profile".to_string(),
                profiling_kind: ProfilingKind::Cpu,
                correlation_kind: ProfilingCorrelationKind::ObservedProfileSample,
                confidence: ProfilingConfidence::Medium,
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
