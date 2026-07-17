use async_trait::async_trait;
use e_navigator_core::{CoreResult, ModuleKind, ModuleMetadata, OtlpHttpConfig, Sink};
use e_navigator_signals::{SignalEnvelope, SignalPayload};
use std::{
    collections::BTreeMap,
    sync::{
        Arc, Mutex as StdMutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::{
    sync::{Mutex, mpsc},
    task::JoinHandle,
    time::{Instant, sleep_until, timeout},
};
use tracing::warn;

use crate::{
    HttpExporterConfig, HttpProtobufExporter, format_otel_metric_record,
    format_otel_profile_record, format_otel_trace_record,
    native_telemetry::{NativeTelemetryRegistry, NativeTelemetrySource},
    otlp_metric_proto::{encode_metric_export_request, metric_series_key},
    otlp_profile_proto::encode_profile_export_request,
    otlp_trace_proto::{encode_trace_export_request, trace_record_has_valid_ids},
};

#[derive(Debug)]
pub struct OtlpHttpSink {
    config: OtlpHttpConfig,
    metric_exporter: Option<AsyncProtobufExporter<crate::OtelMetricRecord>>,
    profile_exporter: Option<AsyncProtobufExporter<crate::OtelProfileRecord>>,
    trace_exporter: Option<AsyncProtobufExporter<crate::OtelTraceRecord>>,
    invalid_trace_records: Arc<AtomicU64>,
    metric_timestamp_guard: Option<Arc<MetricTimestampGuard>>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ExportWorkerTelemetry {
    pub queue_capacity: usize,
    pub queue_depth: usize,
    pub enqueued: u64,
    pub exported: u64,
    pub dropped_queue_full: u64,
    pub dropped_worker_closed: u64,
    pub dropped_export_failure: u64,
    pub dropped_circuit_open: u64,
    pub failed_batches: u64,
    pub retry_attempts: u64,
    pub circuit_opened: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct OtlpHttpTelemetry {
    pub metrics: Option<ExportWorkerTelemetry>,
    pub traces: Option<ExportWorkerTelemetry>,
    pub profiles: Option<ExportWorkerTelemetry>,
    pub invalid_trace_records: u64,
    pub metric_timestamps: Option<MetricTimestampTelemetry>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MetricTimestampTelemetry {
    pub tracked_series: usize,
    pub same_millisecond_suppressed: u64,
    pub out_of_order_dropped: u64,
    pub series_evicted: u64,
}

const MAX_METRIC_TIMESTAMP_SERIES: usize = 65_536;
const METRIC_TIMESTAMP_STALE_NANOS: u64 = 10 * 60 * 1_000_000_000;

#[derive(Debug, Clone, Copy)]
struct MetricSeriesTimestamp {
    receiver_timestamp_millis: u64,
    last_seen_unix_nanos: u64,
}

#[derive(Debug)]
struct MetricTimestampGuard {
    series: StdMutex<BTreeMap<String, MetricSeriesTimestamp>>,
    same_millisecond_suppressed: AtomicU64,
    out_of_order_dropped: AtomicU64,
    series_evicted: AtomicU64,
}

#[derive(Debug, Default)]
struct AtomicExportWorkerTelemetry {
    enqueued: AtomicU64,
    exported: AtomicU64,
    dropped_queue_full: AtomicU64,
    dropped_worker_closed: AtomicU64,
    dropped_export_failure: AtomicU64,
    dropped_circuit_open: AtomicU64,
    failed_batches: AtomicU64,
    retry_attempts: AtomicU64,
    circuit_opened: AtomicU64,
}

impl AtomicExportWorkerTelemetry {
    fn snapshot(&self) -> ExportWorkerTelemetry {
        ExportWorkerTelemetry {
            queue_capacity: 0,
            queue_depth: 0,
            enqueued: self.enqueued.load(Ordering::Relaxed),
            exported: self.exported.load(Ordering::Relaxed),
            dropped_queue_full: self.dropped_queue_full.load(Ordering::Relaxed),
            dropped_worker_closed: self.dropped_worker_closed.load(Ordering::Relaxed),
            dropped_export_failure: self.dropped_export_failure.load(Ordering::Relaxed),
            dropped_circuit_open: self.dropped_circuit_open.load(Ordering::Relaxed),
            failed_batches: self.failed_batches.load(Ordering::Relaxed),
            retry_attempts: self.retry_attempts.load(Ordering::Relaxed),
            circuit_opened: self.circuit_opened.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug)]
enum ExportCommand<T> {
    Record(T),
    Shutdown,
}

#[derive(Debug)]
struct AsyncProtobufExporter<T> {
    sender: mpsc::Sender<ExportCommand<T>>,
    worker: Mutex<Option<JoinHandle<()>>>,
    telemetry: Arc<AtomicExportWorkerTelemetry>,
    accepting: AtomicBool,
    shutdown_timeout: Duration,
}

impl OtlpHttpSink {
    pub fn new(config: OtlpHttpConfig) -> CoreResult<Self> {
        Self::new_with_telemetry(config, NativeTelemetryRegistry::default())
    }

    pub fn new_with_telemetry(
        config: OtlpHttpConfig,
        telemetry_registry: NativeTelemetryRegistry,
    ) -> CoreResult<Self> {
        validate_worker_tuning(&config).map_err(exporter_module_error)?;
        let invalid_trace_records = Arc::new(AtomicU64::new(0));
        if config.traces_enabled {
            telemetry_registry.register_source(Arc::new(InvalidTraceTelemetrySource {
                invalid_trace_records: invalid_trace_records.clone(),
            }));
        }
        let metric_timestamp_guard = if config.metrics_enabled {
            let guard = Arc::new(MetricTimestampGuard::default());
            telemetry_registry.register_source(guard.clone());
            Some(guard)
        } else {
            None
        };
        let metric_exporter = if config.metrics_enabled {
            Some(build_exporter(
                exporter_config_for(&config, required_metrics_endpoint(&config)?),
                encode_metric_export_request,
                &config,
                "metrics",
                &telemetry_registry,
            )?)
        } else {
            None
        };
        let profile_exporter = if config.profiles_enabled {
            Some(build_exporter(
                exporter_config_for(&config, required_profiles_endpoint(&config)?),
                encode_profile_export_request,
                &config,
                "profiles",
                &telemetry_registry,
            )?)
        } else {
            None
        };
        let trace_exporter = if config.traces_enabled {
            Some(build_exporter(
                exporter_config_for(&config, required_traces_endpoint(&config)?),
                encode_trace_export_request,
                &config,
                "traces",
                &telemetry_registry,
            )?)
        } else {
            None
        };

        Ok(Self {
            config,
            metric_exporter,
            profile_exporter,
            trace_exporter,
            invalid_trace_records,
            metric_timestamp_guard,
        })
    }

    pub fn telemetry(&self) -> OtlpHttpTelemetry {
        OtlpHttpTelemetry {
            metrics: self
                .metric_exporter
                .as_ref()
                .map(AsyncProtobufExporter::telemetry),
            traces: self
                .trace_exporter
                .as_ref()
                .map(AsyncProtobufExporter::telemetry),
            profiles: self
                .profile_exporter
                .as_ref()
                .map(AsyncProtobufExporter::telemetry),
            invalid_trace_records: self.invalid_trace_records.load(Ordering::Relaxed),
            metric_timestamps: self
                .metric_timestamp_guard
                .as_ref()
                .map(|guard| guard.telemetry()),
        }
    }
}

fn validate_worker_tuning(config: &OtlpHttpConfig) -> Result<(), String> {
    for (name, value, maximum) in [
        (
            "flush_interval_millis",
            config.flush_interval_millis,
            OtlpHttpConfig::MAX_FLUSH_INTERVAL_MILLIS_LIMIT,
        ),
        (
            "retry_initial_backoff_millis",
            config.retry_initial_backoff_millis,
            OtlpHttpConfig::MAX_RETRY_BACKOFF_MILLIS_LIMIT,
        ),
        (
            "retry_max_backoff_millis",
            config.retry_max_backoff_millis,
            OtlpHttpConfig::MAX_RETRY_BACKOFF_MILLIS_LIMIT,
        ),
        (
            "circuit_breaker_cooldown_millis",
            config.circuit_breaker_cooldown_millis,
            OtlpHttpConfig::MAX_CIRCUIT_BREAKER_COOLDOWN_MILLIS_LIMIT,
        ),
        (
            "shutdown_timeout_millis",
            config.shutdown_timeout_millis,
            OtlpHttpConfig::MAX_SHUTDOWN_TIMEOUT_MILLIS_LIMIT,
        ),
    ] {
        if value == 0 {
            return Err(format!("{name} must be greater than zero"));
        }
        if value > maximum {
            return Err(format!("{name} must be less than or equal to {maximum}"));
        }
    }
    if config.retry_initial_backoff_millis > config.retry_max_backoff_millis {
        return Err(
            "retry_initial_backoff_millis must be less than or equal to retry_max_backoff_millis"
                .to_string(),
        );
    }
    if config.circuit_breaker_failure_threshold == 0 {
        return Err("circuit_breaker_failure_threshold must be greater than zero".to_string());
    }
    if config.circuit_breaker_failure_threshold
        > OtlpHttpConfig::MAX_CIRCUIT_BREAKER_FAILURE_THRESHOLD_LIMIT
    {
        return Err(format!(
            "circuit_breaker_failure_threshold must be less than or equal to {}",
            OtlpHttpConfig::MAX_CIRCUIT_BREAKER_FAILURE_THRESHOLD_LIMIT
        ));
    }
    Ok(())
}

#[async_trait]
impl Sink<SignalEnvelope> for OtlpHttpSink {
    fn metadata(&self) -> ModuleMetadata {
        ModuleMetadata::new("sink.otlp_http", ModuleKind::Sink)
    }

    async fn write(&self, signal: &SignalEnvelope) -> CoreResult<()> {
        if self.config.traces_enabled
            && let Some(record) = format_otel_trace_record(signal)
            && let Some(exporter) = &self.trace_exporter
        {
            if !trace_record_has_valid_ids(&record) {
                if signal_declares_trace_identity(signal) {
                    self.invalid_trace_records.fetch_add(1, Ordering::Relaxed);
                }
                return Ok(());
            }

            exporter.enqueue(record);
            return Ok(());
        }

        if self.config.metrics_enabled
            && let Some(record) = format_otel_metric_record(signal)
            && let Some(exporter) = &self.metric_exporter
        {
            if let Some(guard) = &self.metric_timestamp_guard {
                guard.enqueue(record, exporter)?;
            } else {
                exporter.enqueue(record);
            }
            return Ok(());
        }

        if self.config.profiles_enabled
            && matches!(&signal.payload, SignalPayload::ProfileSampleObservation(_))
            && let Some(record) = format_otel_profile_record(signal)
            && let Some(exporter) = &self.profile_exporter
        {
            exporter.enqueue(record);
            return Ok(());
        }

        Ok(())
    }

    async fn shutdown(&self) -> CoreResult<()> {
        let (metrics, traces, profiles) = tokio::join!(
            shutdown_exporter(self.metric_exporter.as_ref()),
            shutdown_exporter(self.trace_exporter.as_ref()),
            shutdown_exporter(self.profile_exporter.as_ref()),
        );
        metrics.and(traces).and(profiles)
    }
}

fn signal_declares_trace_identity(signal: &SignalEnvelope) -> bool {
    let has_identity = |trace_id: &Option<String>, span_id: &Option<String>| {
        trace_id.is_some() || span_id.is_some()
    };
    match &signal.payload {
        SignalPayload::TraceSpanObservation(span) => has_identity(&span.trace_id, &span.span_id),
        SignalPayload::ServiceInteractionSpanObservation(span) => {
            has_identity(&span.trace_id, &span.span_id)
        }
        SignalPayload::RequestSpanObservation(span) => has_identity(&span.trace_id, &span.span_id),
        _ => false,
    }
}

async fn shutdown_exporter<T>(exporter: Option<&AsyncProtobufExporter<T>>) -> CoreResult<()>
where
    T: Clone + Send + Sync + 'static,
{
    match exporter {
        Some(exporter) => exporter.shutdown().await,
        None => Ok(()),
    }
}

fn required_metrics_endpoint(config: &OtlpHttpConfig) -> CoreResult<&str> {
    config.effective_metrics_endpoint().ok_or_else(|| {
        e_navigator_core::CoreError::ModuleFailed {
            module: "sink.otlp_http".to_string(),
            message:
                "otlp_http.metrics_endpoint or otlp_http.endpoint is required when OTLP metrics are enabled"
                    .to_string(),
        }
    })
}

fn required_traces_endpoint(config: &OtlpHttpConfig) -> CoreResult<&str> {
    config.effective_traces_endpoint().ok_or_else(|| {
        e_navigator_core::CoreError::ModuleFailed {
            module: "sink.otlp_http".to_string(),
            message:
                "otlp_http.traces_endpoint or otlp_http.endpoint is required when OTLP traces are enabled"
                    .to_string(),
        }
    })
}

fn required_profiles_endpoint(config: &OtlpHttpConfig) -> CoreResult<&str> {
    config.effective_profiles_endpoint().ok_or_else(|| {
        e_navigator_core::CoreError::ModuleFailed {
            module: "sink.otlp_http".to_string(),
            message:
                "otlp_http.profiles_endpoint or otlp_http.endpoint is required when OTLP profiles are enabled"
                    .to_string(),
        }
    })
}

fn exporter_config_for(config: &OtlpHttpConfig, endpoint: &str) -> HttpExporterConfig {
    HttpExporterConfig {
        endpoint: endpoint.to_string(),
        headers: Vec::new(),
        batch_size: config.batch_size,
        queue_capacity: config.queue_capacity,
        timeout_millis: config.timeout_millis,
        max_retries: config.max_retries,
        tls_insecure_skip_verify: config.tls_insecure_skip_verify,
    }
}

fn build_exporter<T>(
    config: HttpExporterConfig,
    encode_batch: fn(&[T]) -> Result<Vec<u8>, crate::ExporterError>,
    runtime_config: &OtlpHttpConfig,
    family: &'static str,
    telemetry_registry: &NativeTelemetryRegistry,
) -> CoreResult<AsyncProtobufExporter<T>>
where
    T: Clone + Send + Sync + 'static,
{
    let exporter = HttpProtobufExporter::new(config, encode_batch)
        .map(|exporter| {
            exporter.with_retry_backoff(
                runtime_config.retry_initial_backoff_millis,
                runtime_config.retry_max_backoff_millis,
            )
        })
        .map_err(|err| e_navigator_core::CoreError::ModuleFailed {
            module: "sink.otlp_http".to_string(),
            message: err.to_string(),
        })?;
    AsyncProtobufExporter::spawn(exporter, runtime_config, family, telemetry_registry).map_err(
        |err| e_navigator_core::CoreError::ModuleFailed {
            module: "sink.otlp_http".to_string(),
            message: err,
        },
    )
}

impl<T> AsyncProtobufExporter<T>
where
    T: Clone + Send + Sync + 'static,
{
    fn spawn(
        exporter: HttpProtobufExporter<T>,
        config: &OtlpHttpConfig,
        family: &'static str,
        telemetry_registry: &NativeTelemetryRegistry,
    ) -> Result<Self, String> {
        let runtime = tokio::runtime::Handle::try_current()
            .map_err(|_| "OTLP export workers require a Tokio runtime".to_string())?;
        let (sender, receiver) = mpsc::channel(config.queue_capacity);
        let telemetry = Arc::new(AtomicExportWorkerTelemetry::default());
        telemetry_registry.register_source(Arc::new(ExportWorkerTelemetrySource {
            family,
            sender: sender.downgrade(),
            telemetry: telemetry.clone(),
        }));
        let worker_telemetry = telemetry.clone();
        let tuning = ExportWorkerTuning {
            batch_size: config.batch_size,
            flush_interval: Duration::from_millis(config.flush_interval_millis),
            circuit_breaker_failure_threshold: config.circuit_breaker_failure_threshold,
            circuit_breaker_cooldown: Duration::from_millis(config.circuit_breaker_cooldown_millis),
        };
        let worker = runtime.spawn(run_export_worker(
            receiver,
            exporter,
            worker_telemetry,
            tuning,
            family,
        ));
        Ok(Self {
            sender,
            worker: Mutex::new(Some(worker)),
            telemetry,
            accepting: AtomicBool::new(true),
            shutdown_timeout: Duration::from_millis(config.shutdown_timeout_millis),
        })
    }

    fn enqueue(&self, record: T) -> bool {
        if !self.accepting.load(Ordering::Acquire) {
            self.telemetry
                .dropped_worker_closed
                .fetch_add(1, Ordering::Relaxed);
            return false;
        }
        match self.sender.try_send(ExportCommand::Record(record)) {
            Ok(()) => {
                self.telemetry.enqueued.fetch_add(1, Ordering::Relaxed);
                true
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                self.telemetry
                    .dropped_queue_full
                    .fetch_add(1, Ordering::Relaxed);
                false
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                self.telemetry
                    .dropped_worker_closed
                    .fetch_add(1, Ordering::Relaxed);
                false
            }
        }
    }

    fn telemetry(&self) -> ExportWorkerTelemetry {
        let mut snapshot = self.telemetry.snapshot();
        snapshot.queue_capacity = self.sender.max_capacity();
        snapshot.queue_depth = snapshot
            .queue_capacity
            .saturating_sub(self.sender.capacity());
        snapshot
    }

    async fn shutdown(&self) -> CoreResult<()> {
        if !self.accepting.swap(false, Ordering::AcqRel) {
            return Ok(());
        }
        timeout(
            self.shutdown_timeout,
            self.sender.send(ExportCommand::Shutdown),
        )
        .await
        .map_err(|_| exporter_module_error("timed out requesting OTLP worker shutdown"))?
        .map_err(|_| exporter_module_error("OTLP worker closed before shutdown request"))?;

        let Some(mut worker) = self.worker.lock().await.take() else {
            return Ok(());
        };
        match timeout(self.shutdown_timeout, &mut worker).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(err)) => Err(exporter_module_error(format!(
                "OTLP export worker join failed: {err}"
            ))),
            Err(_) => {
                worker.abort();
                Err(exporter_module_error(
                    "timed out draining OTLP export worker",
                ))
            }
        }
    }
}

struct ExportWorkerTelemetrySource<T> {
    family: &'static str,
    sender: mpsc::WeakSender<ExportCommand<T>>,
    telemetry: Arc<AtomicExportWorkerTelemetry>,
}

struct InvalidTraceTelemetrySource {
    invalid_trace_records: Arc<AtomicU64>,
}

impl Default for MetricTimestampGuard {
    fn default() -> Self {
        Self {
            series: StdMutex::new(BTreeMap::new()),
            same_millisecond_suppressed: AtomicU64::new(0),
            out_of_order_dropped: AtomicU64::new(0),
            series_evicted: AtomicU64::new(0),
        }
    }
}

impl MetricTimestampGuard {
    fn enqueue(
        &self,
        record: crate::OtelMetricRecord,
        exporter: &AsyncProtobufExporter<crate::OtelMetricRecord>,
    ) -> CoreResult<()> {
        let key =
            metric_series_key(&record).map_err(|err| exporter_module_error(err.to_string()))?;
        let observed_unix_nanos = record.window.end_unix_nanos;
        let receiver_timestamp_millis = observed_unix_nanos / 1_000_000;
        let mut series = self
            .series
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        let expired = series.len();
        series.retain(|_, state| {
            observed_unix_nanos.saturating_sub(state.last_seen_unix_nanos)
                <= METRIC_TIMESTAMP_STALE_NANOS
        });
        let expired = expired.saturating_sub(series.len());
        if expired > 0 {
            self.series_evicted
                .fetch_add(expired as u64, Ordering::Relaxed);
        }

        if let Some(previous) = series.get(&key) {
            if receiver_timestamp_millis < previous.receiver_timestamp_millis {
                self.out_of_order_dropped.fetch_add(1, Ordering::Relaxed);
                return Ok(());
            }
            if receiver_timestamp_millis == previous.receiver_timestamp_millis {
                self.same_millisecond_suppressed
                    .fetch_add(1, Ordering::Relaxed);
                return Ok(());
            }
        } else if series.len() >= MAX_METRIC_TIMESTAMP_SERIES
            && let Some(oldest_key) = series
                .iter()
                .min_by_key(|(_, state)| state.last_seen_unix_nanos)
                .map(|(key, _)| key.clone())
        {
            series.remove(&oldest_key);
            self.series_evicted.fetch_add(1, Ordering::Relaxed);
        }

        if exporter.enqueue(record) {
            series.insert(
                key,
                MetricSeriesTimestamp {
                    receiver_timestamp_millis,
                    last_seen_unix_nanos: observed_unix_nanos,
                },
            );
        }
        Ok(())
    }

    fn telemetry(&self) -> MetricTimestampTelemetry {
        MetricTimestampTelemetry {
            tracked_series: self.series.lock().map_or(0, |series| series.len()),
            same_millisecond_suppressed: self.same_millisecond_suppressed.load(Ordering::Relaxed),
            out_of_order_dropped: self.out_of_order_dropped.load(Ordering::Relaxed),
            series_evicted: self.series_evicted.load(Ordering::Relaxed),
        }
    }
}

impl NativeTelemetrySource for MetricTimestampGuard {
    fn prometheus_lines(&self) -> Vec<crate::PrometheusMetricLine> {
        let telemetry = self.telemetry();
        let metric = |name: &str, value: u64| crate::PrometheusMetricLine {
            name: name.to_string(),
            labels: BTreeMap::new(),
            value: value.to_string(),
        };
        vec![
            metric(
                "e_navigator_export_metric_timestamp_series",
                telemetry.tracked_series as u64,
            ),
            metric(
                "e_navigator_export_metric_same_millisecond_suppressed_total",
                telemetry.same_millisecond_suppressed,
            ),
            metric(
                "e_navigator_export_metric_out_of_order_dropped_total",
                telemetry.out_of_order_dropped,
            ),
            metric(
                "e_navigator_export_metric_timestamp_series_evicted_total",
                telemetry.series_evicted,
            ),
        ]
    }
}

impl NativeTelemetrySource for InvalidTraceTelemetrySource {
    fn prometheus_lines(&self) -> Vec<crate::PrometheusMetricLine> {
        vec![crate::PrometheusMetricLine {
            name: "e_navigator_export_invalid_trace_records_total".to_string(),
            labels: std::collections::BTreeMap::new(),
            value: self
                .invalid_trace_records
                .load(Ordering::Relaxed)
                .to_string(),
        }]
    }
}

impl<T> NativeTelemetrySource for ExportWorkerTelemetrySource<T>
where
    T: Send + Sync + 'static,
{
    fn prometheus_lines(&self) -> Vec<crate::PrometheusMetricLine> {
        let mut snapshot = self.telemetry.snapshot();
        if let Some(sender) = self.sender.upgrade() {
            snapshot.queue_capacity = sender.max_capacity();
            snapshot.queue_depth = snapshot.queue_capacity.saturating_sub(sender.capacity());
        }
        export_worker_prometheus_lines(self.family, snapshot)
    }
}

fn export_worker_prometheus_lines(
    family: &'static str,
    telemetry: ExportWorkerTelemetry,
) -> Vec<crate::PrometheusMetricLine> {
    let labels =
        std::collections::BTreeMap::from([("signal_family".to_string(), family.to_string())]);
    let metric = |name: &str, value: u64| crate::PrometheusMetricLine {
        name: name.to_string(),
        labels: labels.clone(),
        value: value.to_string(),
    };
    vec![
        metric(
            "e_navigator_export_queue_capacity",
            telemetry.queue_capacity as u64,
        ),
        metric(
            "e_navigator_export_queue_depth",
            telemetry.queue_depth as u64,
        ),
        metric("e_navigator_export_enqueued_total", telemetry.enqueued),
        metric("e_navigator_export_sent_total", telemetry.exported),
        metric(
            "e_navigator_export_dropped_queue_full_total",
            telemetry.dropped_queue_full,
        ),
        metric(
            "e_navigator_export_dropped_worker_closed_total",
            telemetry.dropped_worker_closed,
        ),
        metric(
            "e_navigator_export_dropped_failure_total",
            telemetry.dropped_export_failure,
        ),
        metric(
            "e_navigator_export_dropped_circuit_open_total",
            telemetry.dropped_circuit_open,
        ),
        metric(
            "e_navigator_export_failed_batches_total",
            telemetry.failed_batches,
        ),
        metric(
            "e_navigator_export_retry_attempts_total",
            telemetry.retry_attempts,
        ),
        metric(
            "e_navigator_export_circuit_opened_total",
            telemetry.circuit_opened,
        ),
    ]
}

#[derive(Debug, Clone, Copy)]
struct ExportWorkerTuning {
    batch_size: usize,
    flush_interval: Duration,
    circuit_breaker_failure_threshold: usize,
    circuit_breaker_cooldown: Duration,
}

async fn run_export_worker<T>(
    mut receiver: mpsc::Receiver<ExportCommand<T>>,
    mut exporter: HttpProtobufExporter<T>,
    telemetry: Arc<AtomicExportWorkerTelemetry>,
    tuning: ExportWorkerTuning,
    family: &'static str,
) where
    T: Clone + Send + Sync + 'static,
{
    let mut queued = 0_usize;
    let mut flush_deadline = None;
    let mut consecutive_failures = 0_usize;
    let mut circuit_open_until = None;

    loop {
        let command = match flush_deadline {
            Some(deadline) => {
                tokio::select! {
                    command = receiver.recv() => command,
                    () = sleep_until(deadline) => {
                        flush_worker_batch(
                            &mut exporter,
                            &telemetry,
                            &tuning,
                            family,
                            &mut queued,
                            &mut consecutive_failures,
                            &mut circuit_open_until,
                        ).await;
                        flush_deadline = None;
                        continue;
                    }
                }
            }
            None => receiver.recv().await,
        };

        match command {
            Some(ExportCommand::Record(record)) => {
                if circuit_open_until.is_some_and(|until| until > Instant::now()) {
                    telemetry
                        .dropped_circuit_open
                        .fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                if circuit_open_until.take().is_some() {
                    consecutive_failures = 0;
                }
                exporter.enqueue(record);
                queued = queued.saturating_add(1);
                if queued == 1 {
                    flush_deadline = Some(Instant::now() + tuning.flush_interval);
                }
                if queued >= tuning.batch_size {
                    flush_worker_batch(
                        &mut exporter,
                        &telemetry,
                        &tuning,
                        family,
                        &mut queued,
                        &mut consecutive_failures,
                        &mut circuit_open_until,
                    )
                    .await;
                    flush_deadline = None;
                }
            }
            Some(ExportCommand::Shutdown) | None => {
                while let Ok(ExportCommand::Record(record)) = receiver.try_recv() {
                    exporter.enqueue(record);
                    queued = queued.saturating_add(1);
                    if queued >= tuning.batch_size {
                        flush_worker_batch(
                            &mut exporter,
                            &telemetry,
                            &tuning,
                            family,
                            &mut queued,
                            &mut consecutive_failures,
                            &mut circuit_open_until,
                        )
                        .await;
                    }
                }
                if queued > 0 {
                    flush_worker_batch(
                        &mut exporter,
                        &telemetry,
                        &tuning,
                        family,
                        &mut queued,
                        &mut consecutive_failures,
                        &mut circuit_open_until,
                    )
                    .await;
                }
                return;
            }
        }
    }
}

async fn flush_worker_batch<T>(
    exporter: &mut HttpProtobufExporter<T>,
    telemetry: &AtomicExportWorkerTelemetry,
    tuning: &ExportWorkerTuning,
    family: &'static str,
    queued: &mut usize,
    consecutive_failures: &mut usize,
    circuit_open_until: &mut Option<Instant>,
) where
    T: Clone + Sync,
{
    if *queued == 0 {
        return;
    }
    let counters_before = exporter.counters();
    match exporter.flush_once().await {
        Ok(()) => {
            let exported = (*queued).min(tuning.batch_size);
            telemetry
                .exported
                .fetch_add(exported as u64, Ordering::Relaxed);
            *queued = queued.saturating_sub(exported);
            *consecutive_failures = 0;
        }
        Err(err) => {
            telemetry.failed_batches.fetch_add(1, Ordering::Relaxed);
            let dropped = exporter.discard_next_batch();
            telemetry
                .dropped_export_failure
                .fetch_add(dropped as u64, Ordering::Relaxed);
            *queued = queued.saturating_sub(dropped);
            *consecutive_failures = consecutive_failures.saturating_add(1);
            warn!(
                signal_family = family,
                dropped,
                error = %err,
                "OTLP export batch failed after retries; dropping bounded batch"
            );
            if *consecutive_failures >= tuning.circuit_breaker_failure_threshold {
                *circuit_open_until = Some(Instant::now() + tuning.circuit_breaker_cooldown);
                telemetry.circuit_opened.fetch_add(1, Ordering::Relaxed);
                warn!(
                    signal_family = family,
                    cooldown_millis = tuning.circuit_breaker_cooldown.as_millis(),
                    "OTLP export circuit opened"
                );
            }
        }
    }
    let retry_attempts = exporter
        .counters()
        .retry_attempts
        .saturating_sub(counters_before.retry_attempts);
    telemetry
        .retry_attempts
        .fetch_add(retry_attempts, Ordering::Relaxed);
}

fn exporter_module_error(message: impl Into<String>) -> e_navigator_core::CoreError {
    e_navigator_core::CoreError::ModuleFailed {
        module: "sink.otlp_http".to_string(),
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::otlp_profile_proto::collector_profile_proto;
    use e_navigator_core::Sink;
    use e_navigator_signals::{
        ContainerContext, KubernetesContext, MetricAggregationWindow, NetworkAddressFamily,
        NetworkCounterMetric, NetworkFlowWarning, NetworkProcessIdentity, NetworkProtocol,
        ProfileSampleObservation, ProfilingAttribute, ProfilingConfidence,
        ProfilingCorrelationKind, ProfilingFrame, ProfilingKind, ProfilingSessionObservation,
        ProfilingWarningObservation, ProtocolKind, RequestSpanObservation, SignalEnvelope,
        SignalPayload, TraceAttribute, TraceConfidence, TraceCorrelationKind,
    };
    use opentelemetry_proto::tonic::{
        collector::{
            metrics::v1::ExportMetricsServiceRequest, trace::v1::ExportTraceServiceRequest,
        },
        metrics::v1::{metric::Data, number_data_point},
        trace::v1::{span, status},
    };
    use prost::Message;
    use std::collections::BTreeMap;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    #[test]
    fn otlp_http_sink_requires_endpoints_for_enabled_families() {
        for (config, expected_message) in [
            (
                OtlpHttpConfig {
                    enabled: true,
                    metrics_enabled: true,
                    traces_enabled: false,
                    profiles_enabled: false,
                    ..OtlpHttpConfig::default()
                },
                "otlp_http.metrics_endpoint or otlp_http.endpoint is required when OTLP metrics are enabled",
            ),
            (
                OtlpHttpConfig {
                    enabled: true,
                    metrics_enabled: false,
                    traces_enabled: true,
                    profiles_enabled: false,
                    ..OtlpHttpConfig::default()
                },
                "otlp_http.traces_endpoint or otlp_http.endpoint is required when OTLP traces are enabled",
            ),
            (
                OtlpHttpConfig {
                    enabled: true,
                    metrics_enabled: false,
                    traces_enabled: false,
                    profiles_enabled: true,
                    ..OtlpHttpConfig::default()
                },
                "otlp_http.profiles_endpoint or otlp_http.endpoint is required when OTLP profiles are enabled",
            ),
        ] {
            let err = OtlpHttpSink::new(config).expect_err("enabled family without endpoint fails");

            assert!(err.to_string().contains(expected_message));
        }
    }

    #[test]
    fn otlp_http_sink_rejects_invalid_runtime_bounds() {
        for (config, expected_message) in [
            (
                OtlpHttpConfig {
                    metrics_endpoint: "http://127.0.0.1:4318/v1/metrics".to_string(),
                    batch_size: 0,
                    metrics_enabled: true,
                    traces_enabled: false,
                    profiles_enabled: false,
                    ..OtlpHttpConfig::default()
                },
                "batch_size must be greater than zero",
            ),
            (
                OtlpHttpConfig {
                    metrics_endpoint: "http://127.0.0.1:4318/v1/metrics".to_string(),
                    batch_size: OtlpHttpConfig::MAX_BATCH_SIZE_LIMIT + 1,
                    metrics_enabled: true,
                    traces_enabled: false,
                    profiles_enabled: false,
                    ..OtlpHttpConfig::default()
                },
                "batch_size must be less than or equal to 4096",
            ),
            (
                OtlpHttpConfig {
                    metrics_endpoint: "http://127.0.0.1:4318/v1/metrics".to_string(),
                    queue_capacity: 0,
                    metrics_enabled: true,
                    traces_enabled: false,
                    profiles_enabled: false,
                    ..OtlpHttpConfig::default()
                },
                "queue_capacity must be greater than zero",
            ),
            (
                OtlpHttpConfig {
                    metrics_endpoint: "http://127.0.0.1:4318/v1/metrics".to_string(),
                    queue_capacity: OtlpHttpConfig::MAX_QUEUE_CAPACITY_LIMIT + 1,
                    metrics_enabled: true,
                    traces_enabled: false,
                    profiles_enabled: false,
                    ..OtlpHttpConfig::default()
                },
                "queue_capacity must be less than or equal to 65536",
            ),
            (
                OtlpHttpConfig {
                    metrics_endpoint: "http://127.0.0.1:4318/v1/metrics".to_string(),
                    timeout_millis: 0,
                    metrics_enabled: true,
                    traces_enabled: false,
                    profiles_enabled: false,
                    ..OtlpHttpConfig::default()
                },
                "timeout_millis must be greater than zero",
            ),
            (
                OtlpHttpConfig {
                    metrics_endpoint: "http://127.0.0.1:4318/v1/metrics".to_string(),
                    timeout_millis: OtlpHttpConfig::MAX_TIMEOUT_MILLIS_LIMIT + 1,
                    metrics_enabled: true,
                    traces_enabled: false,
                    profiles_enabled: false,
                    ..OtlpHttpConfig::default()
                },
                "timeout_millis must be less than or equal to 300000",
            ),
            (
                OtlpHttpConfig {
                    metrics_endpoint: "http://127.0.0.1:4318/v1/metrics".to_string(),
                    max_retries: OtlpHttpConfig::MAX_RETRIES_LIMIT + 1,
                    metrics_enabled: true,
                    traces_enabled: false,
                    profiles_enabled: false,
                    ..OtlpHttpConfig::default()
                },
                "max_retries must be less than or equal to 16",
            ),
            (
                OtlpHttpConfig {
                    flush_interval_millis: 0,
                    ..OtlpHttpConfig::default()
                },
                "flush_interval_millis must be greater than zero",
            ),
            (
                OtlpHttpConfig {
                    retry_initial_backoff_millis: 2,
                    retry_max_backoff_millis: 1,
                    ..OtlpHttpConfig::default()
                },
                "retry_initial_backoff_millis must be less than or equal to retry_max_backoff_millis",
            ),
            (
                OtlpHttpConfig {
                    circuit_breaker_failure_threshold: 0,
                    ..OtlpHttpConfig::default()
                },
                "circuit_breaker_failure_threshold must be greater than zero",
            ),
            (
                OtlpHttpConfig {
                    shutdown_timeout_millis: 0,
                    ..OtlpHttpConfig::default()
                },
                "shutdown_timeout_millis must be greater than zero",
            ),
        ] {
            let err = OtlpHttpSink::new(config).expect_err("invalid runtime bound fails");

            assert!(err.to_string().contains(expected_message));
        }
    }

    #[test]
    fn otlp_http_sink_rejects_invalid_effective_endpoints() {
        for (endpoint, expected_message) in [
            (
                "grpc://127.0.0.1:4317",
                "endpoint must start with http:// or https://",
            ),
            ("http:///v1/metrics", "endpoint must include a host"),
        ] {
            let err = OtlpHttpSink::new(OtlpHttpConfig {
                endpoint: endpoint.to_string(),
                metrics_enabled: true,
                traces_enabled: false,
                profiles_enabled: false,
                ..OtlpHttpConfig::default()
            })
            .expect_err("invalid effective endpoint fails");

            assert!(err.to_string().contains(expected_message));
        }
    }

    #[tokio::test]
    async fn otlp_http_sink_exports_metric_records_as_otlp_protobuf() {
        let collector = FakeCollector::spawn(vec![200]).await;
        let sink = OtlpHttpSink::new(OtlpHttpConfig {
            enabled: true,
            metrics_endpoint: collector.url_with_path("/v1/metrics"),
            metrics_enabled: true,
            traces_enabled: false,
            profiles_enabled: false,
            batch_size: 1,
            queue_capacity: 2,
            timeout_millis: 1_000,
            max_retries: 0,
            ..OtlpHttpConfig::default()
        })
        .expect("sink builds");

        sink.write(&network_metric())
            .await
            .expect("metric export succeeds");
        let request = collector.next_request().await;

        assert!(request.contains("POST /v1/metrics HTTP/1.1"));
        assert!(request.contains("content-type: application/x-protobuf"));
        assert!(!request.contains("signal_family"));
        let decoded = ExportMetricsServiceRequest::decode(request.body())
            .expect("OTLP metrics request decodes");
        let resource_metrics = decoded.resource_metrics.first().expect("resource metrics");
        let scope_metrics = resource_metrics
            .scope_metrics
            .first()
            .expect("scope metrics are present");
        let metric = scope_metrics.metrics.first().expect("metric is present");

        assert_eq!(metric.name, "network.connection.open.count");
        assert_eq!(metric.unit, "{connection}");
        let Some(Data::Sum(sum)) = metric.data.as_ref() else {
            panic!("metric is exported as OTLP Sum");
        };
        let point = sum.data_points.first().expect("sum data point");
        assert_eq!(point.value, Some(number_data_point::Value::AsInt(1)));
        assert!(point.attributes.iter().any(|attribute| {
            attribute.key == "net.transport" && format!("{:?}", attribute.value).contains("tcp")
        }));
        let resource = resource_metrics.resource.as_ref().expect("resource");
        assert!(resource.attributes.iter().any(|attribute| {
            attribute.key == "host.name" && format!("{:?}", attribute.value).contains("node-a")
        }));
    }

    #[tokio::test]
    async fn otlp_http_sink_suppresses_cross_batch_receiver_timestamp_collisions() {
        const BASE: u64 = 1_784_321_612_093_000_000;
        let collector = FakeCollector::spawn(vec![200, 200]).await;
        let sink = OtlpHttpSink::new(OtlpHttpConfig {
            enabled: true,
            metrics_endpoint: collector.url_with_path("/v1/metrics"),
            metrics_enabled: true,
            traces_enabled: false,
            profiles_enabled: false,
            batch_size: 1,
            queue_capacity: 8,
            timeout_millis: 1_000,
            max_retries: 0,
            ..OtlpHttpConfig::default()
        })
        .expect("sink builds");

        sink.write(&network_metric_at(333, BASE))
            .await
            .expect("first cumulative point enqueues");
        let first = collector.next_request().await;
        assert_eq!(metric_point(&first), (333, BASE));

        sink.write(&network_metric_at(557, BASE + 500_000))
            .await
            .expect("same-millisecond point is intentionally suppressed");
        sink.write(&network_metric_at(100, BASE - 1_000_000))
            .await
            .expect("out-of-order point is intentionally dropped");
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(collector.try_next_request().is_none());

        sink.write(&network_metric_at(558, BASE + 1_000_000))
            .await
            .expect("next receiver timestamp enqueues");
        let next = collector.next_request().await;
        assert_eq!(metric_point(&next), (558, BASE + 1_000_000));

        let telemetry = sink
            .telemetry()
            .metric_timestamps
            .expect("metric timestamp guard");
        assert_eq!(telemetry.same_millisecond_suppressed, 1);
        assert_eq!(telemetry.out_of_order_dropped, 1);
        assert_eq!(telemetry.tracked_series, 1);
        Sink::shutdown(&sink).await.expect("worker drains");
    }

    #[tokio::test]
    async fn otlp_http_sink_sustains_high_rate_without_duplicate_receiver_timestamps() {
        const BASE: u64 = 1_784_321_612_093_000_000;
        const MILLISECONDS: u64 = 100;
        const POINTS_PER_MILLISECOND: u64 = 20;
        let collector = FakeCollector::spawn(vec![200; MILLISECONDS as usize]).await;
        let sink = OtlpHttpSink::new(OtlpHttpConfig {
            enabled: true,
            metrics_endpoint: collector.url_with_path("/v1/metrics"),
            metrics_enabled: true,
            traces_enabled: false,
            profiles_enabled: false,
            batch_size: 1,
            queue_capacity: 4_096,
            timeout_millis: 1_000,
            max_retries: 0,
            ..OtlpHttpConfig::default()
        })
        .expect("sink builds");

        for offset in 0..(MILLISECONDS * POINTS_PER_MILLISECOND) {
            let millisecond = offset / POINTS_PER_MILLISECOND;
            let within_millisecond = offset % POINTS_PER_MILLISECOND;
            let timestamp = BASE + millisecond * 1_000_000 + within_millisecond * 10_000;
            sink.write(&network_metric_at(offset + 1, timestamp))
                .await
                .expect("bounded high-rate write succeeds");
        }

        let telemetry = sink
            .telemetry()
            .metric_timestamps
            .expect("metric timestamp guard");
        assert_eq!(
            telemetry.same_millisecond_suppressed,
            MILLISECONDS * (POINTS_PER_MILLISECOND - 1)
        );
        assert_eq!(telemetry.out_of_order_dropped, 0);

        let mut previous_timestamp = None;
        let mut previous_value = None;
        for _ in 0..MILLISECONDS {
            let request = collector.next_request().await;
            let (value, timestamp) = metric_point(&request);
            if let Some(previous) = previous_timestamp {
                assert!(timestamp > previous, "receiver timestamps must be unique");
            }
            if let Some(previous) = previous_value {
                assert!(value > previous, "cumulative values must remain monotonic");
            }
            previous_timestamp = Some(timestamp);
            previous_value = Some(value);
        }
        Sink::shutdown(&sink).await.expect("worker drains");
    }

    #[tokio::test]
    async fn otlp_http_sink_exports_native_flow_byte_metric_as_otlp_protobuf() {
        let collector = FakeCollector::spawn(vec![200]).await;
        let sink = OtlpHttpSink::new(OtlpHttpConfig {
            enabled: true,
            metrics_endpoint: collector.url_with_path("/v1/metrics"),
            metrics_enabled: true,
            traces_enabled: false,
            profiles_enabled: false,
            batch_size: 1,
            queue_capacity: 2,
            timeout_millis: 1_000,
            max_retries: 0,
            ..OtlpHttpConfig::default()
        })
        .expect("sink builds");

        sink.write(&flow_byte_metric())
            .await
            .expect("flow byte metric export succeeds");
        let request = collector.next_request().await;

        assert!(request.contains("POST /v1/metrics HTTP/1.1"));
        let decoded = ExportMetricsServiceRequest::decode(request.body())
            .expect("OTLP metrics request decodes");
        let resource_metrics = decoded.resource_metrics.first().expect("resource metrics");
        let scope_metrics = resource_metrics
            .scope_metrics
            .first()
            .expect("scope metrics are present");
        let metric = scope_metrics.metrics.first().expect("metric is present");

        assert_eq!(metric.name, "network.flow.bytes");
        assert_eq!(metric.unit, "By");
        let Some(Data::Sum(sum)) = metric.data.as_ref() else {
            panic!("flow bytes are exported as OTLP Sum");
        };
        let point = sum.data_points.first().expect("sum data point");
        assert_eq!(point.value, Some(number_data_point::Value::AsInt(2048)));
        assert!(point.attributes.iter().any(|attribute| {
            attribute.key == "net.transport" && format!("{:?}", attribute.value).contains("tcp")
        }));
        assert!(point.attributes.iter().any(|attribute| {
            attribute.key == "network.type" && format!("{:?}", attribute.value).contains("ipv4")
        }));
        assert!(
            !point
                .attributes
                .iter()
                .any(|attribute| attribute.key == "server.address")
        );
        assert!(
            !point
                .attributes
                .iter()
                .any(|attribute| attribute.key == "server.port")
        );
        let resource = resource_metrics.resource.as_ref().expect("resource");
        assert!(resource.attributes.iter().any(|attribute| {
            attribute.key == "k8s.namespace.name"
                && format!("{:?}", attribute.value).contains("e-navigator-bench")
        }));
        assert!(resource.attributes.iter().any(|attribute| {
            attribute.key == "k8s.pod.name"
                && format!("{:?}", attribute.value).contains("workload-a")
        }));
    }

    #[tokio::test]
    async fn otlp_http_sink_retries_failed_metric_export() {
        let collector = FakeCollector::spawn(vec![500, 200]).await;
        let sink = OtlpHttpSink::new(OtlpHttpConfig {
            enabled: true,
            endpoint: collector.url(),
            batch_size: 1,
            queue_capacity: 2,
            timeout_millis: 1_000,
            max_retries: 1,
            ..OtlpHttpConfig::default()
        })
        .expect("sink builds");

        sink.write(&network_metric())
            .await
            .expect("retry export succeeds");

        assert!(
            collector
                .next_request()
                .await
                .contains("network.connection.open.count")
        );
        assert!(
            collector
                .next_request()
                .await
                .contains("network.connection.open.count")
        );
    }

    #[tokio::test]
    async fn otlp_http_sink_write_does_not_wait_for_slow_collector() {
        let collector =
            FakeCollector::spawn_with_delay(vec![200], Duration::from_millis(250)).await;
        let sink = OtlpHttpSink::new(OtlpHttpConfig {
            enabled: true,
            metrics_endpoint: collector.url_with_path("/v1/metrics"),
            metrics_enabled: true,
            traces_enabled: false,
            profiles_enabled: false,
            batch_size: 1,
            queue_capacity: 2,
            timeout_millis: 1_000,
            max_retries: 0,
            ..OtlpHttpConfig::default()
        })
        .expect("sink builds");

        let started = Instant::now();
        sink.write(&network_metric())
            .await
            .expect("enqueue succeeds");
        assert!(started.elapsed() < Duration::from_millis(100));

        let _ = collector.next_request().await;
        Sink::shutdown(&sink).await.expect("worker drains");
    }

    #[tokio::test]
    async fn otlp_http_sink_flushes_partial_batch_on_interval() {
        let collector = FakeCollector::spawn(vec![200]).await;
        let sink = OtlpHttpSink::new(OtlpHttpConfig {
            enabled: true,
            metrics_endpoint: collector.url_with_path("/v1/metrics"),
            metrics_enabled: true,
            traces_enabled: false,
            profiles_enabled: false,
            batch_size: 4,
            queue_capacity: 4,
            flush_interval_millis: 20,
            timeout_millis: 1_000,
            max_retries: 0,
            ..OtlpHttpConfig::default()
        })
        .expect("sink builds");

        sink.write(&network_metric())
            .await
            .expect("enqueue succeeds");
        timeout(Duration::from_secs(1), collector.next_request())
            .await
            .expect("partial batch flushes on interval");
        Sink::shutdown(&sink).await.expect("worker drains");
        assert_eq!(
            sink.telemetry().metrics.expect("metrics worker").exported,
            1
        );
    }

    #[tokio::test]
    async fn otlp_http_sink_counts_bounded_queue_overflow() {
        let collector =
            FakeCollector::spawn_with_delay(vec![200, 200, 200], Duration::from_millis(100)).await;
        let sink = OtlpHttpSink::new(OtlpHttpConfig {
            enabled: true,
            metrics_endpoint: collector.url_with_path("/v1/metrics"),
            metrics_enabled: true,
            traces_enabled: false,
            profiles_enabled: false,
            batch_size: 1,
            queue_capacity: 2,
            timeout_millis: 1_000,
            max_retries: 0,
            ..OtlpHttpConfig::default()
        })
        .expect("sink builds");

        sink.write(&network_metric()).await.expect("first enqueue");
        let _ = collector.next_request().await;
        for index in 0..3 {
            sink.write(&network_metric_at(index + 2, (index + 1) * 1_000_000))
                .await
                .expect("bounded enqueue");
        }

        assert_eq!(
            sink.telemetry()
                .metrics
                .expect("metrics worker")
                .dropped_queue_full,
            1
        );
        Sink::shutdown(&sink).await.expect("worker drains");
    }

    #[tokio::test]
    async fn otlp_http_sink_opens_circuit_and_counts_drops() {
        let collector = FakeCollector::spawn(vec![500]).await;
        let sink = OtlpHttpSink::new(OtlpHttpConfig {
            enabled: true,
            metrics_endpoint: collector.url_with_path("/v1/metrics"),
            metrics_enabled: true,
            traces_enabled: false,
            profiles_enabled: false,
            batch_size: 1,
            queue_capacity: 2,
            timeout_millis: 1_000,
            max_retries: 0,
            circuit_breaker_failure_threshold: 1,
            circuit_breaker_cooldown_millis: 1_000,
            ..OtlpHttpConfig::default()
        })
        .expect("sink builds");

        sink.write(&network_metric()).await.expect("first enqueue");
        let _ = collector.next_request().await;
        timeout(Duration::from_secs(1), async {
            while sink
                .telemetry()
                .metrics
                .expect("metrics worker")
                .circuit_opened
                == 0
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("circuit opens");
        sink.write(&network_metric_at(2, 1_000_000))
            .await
            .expect("second enqueue");
        timeout(Duration::from_secs(1), async {
            while sink
                .telemetry()
                .metrics
                .expect("metrics worker")
                .dropped_circuit_open
                == 0
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("open circuit counts a drop");

        let telemetry = sink.telemetry().metrics.expect("metrics worker");
        assert_eq!(telemetry.failed_batches, 1);
        assert_eq!(telemetry.dropped_export_failure, 1);
        assert_eq!(telemetry.dropped_circuit_open, 1);
        Sink::shutdown(&sink).await.expect("worker drains");
    }

    #[tokio::test]
    async fn otlp_http_sink_shutdown_drains_partial_batch() {
        let collector = FakeCollector::spawn(vec![200]).await;
        let sink = OtlpHttpSink::new(OtlpHttpConfig {
            enabled: true,
            metrics_endpoint: collector.url_with_path("/v1/metrics"),
            metrics_enabled: true,
            traces_enabled: false,
            profiles_enabled: false,
            batch_size: 4,
            queue_capacity: 4,
            flush_interval_millis: 60_000,
            timeout_millis: 1_000,
            max_retries: 0,
            ..OtlpHttpConfig::default()
        })
        .expect("sink builds");

        sink.write(&network_metric())
            .await
            .expect("enqueue succeeds");
        Sink::shutdown(&sink).await.expect("shutdown drains");
        assert!(
            collector
                .next_request()
                .await
                .contains("network.connection.open.count")
        );
        assert_eq!(
            sink.telemetry().metrics.expect("metrics worker").exported,
            1
        );
    }

    #[tokio::test]
    async fn otlp_http_sink_respects_disabled_signal_families() {
        let collector = FakeCollector::spawn(vec![]).await;
        let sink = OtlpHttpSink::new(OtlpHttpConfig {
            enabled: true,
            traces_endpoint: collector.url_with_path("/v1/traces"),
            metrics_enabled: false,
            traces_enabled: true,
            profiles_enabled: false,
            batch_size: 1,
            queue_capacity: 2,
            timeout_millis: 50,
            max_retries: 0,
            ..OtlpHttpConfig::default()
        })
        .expect("sink builds");

        sink.write(&network_metric())
            .await
            .expect("non-enabled family is ignored");

        assert!(collector.try_next_request().is_none());
    }

    #[tokio::test]
    async fn otlp_http_sink_respects_disabled_trace_and_profile_families() {
        let collector = FakeCollector::spawn(vec![]).await;
        let sink = OtlpHttpSink::new(OtlpHttpConfig {
            enabled: true,
            metrics_endpoint: collector.url_with_path("/v1/metrics"),
            metrics_enabled: true,
            traces_enabled: false,
            profiles_enabled: false,
            batch_size: 1,
            queue_capacity: 2,
            timeout_millis: 50,
            max_retries: 0,
            ..OtlpHttpConfig::default()
        })
        .expect("sink builds");

        sink.write(&request_span())
            .await
            .expect("disabled trace family is ignored");
        sink.write(&profile_sample())
            .await
            .expect("disabled profile family is ignored");

        assert!(collector.try_next_request().is_none());
    }

    #[tokio::test]
    async fn otlp_http_sink_exports_trace_records_as_otlp_protobuf() {
        let collector = FakeCollector::spawn(vec![200]).await;
        let sink = OtlpHttpSink::new(OtlpHttpConfig {
            enabled: true,
            traces_endpoint: collector.url_with_path("/v1/traces"),
            metrics_enabled: false,
            traces_enabled: true,
            profiles_enabled: false,
            batch_size: 1,
            queue_capacity: 2,
            timeout_millis: 1_000,
            max_retries: 0,
            ..OtlpHttpConfig::default()
        })
        .expect("sink builds");

        sink.write(&request_span())
            .await
            .expect("trace export succeeds");
        let request = collector.next_request().await;

        assert!(request.contains("POST /v1/traces HTTP/1.1"));
        assert!(request.contains("content-type: application/x-protobuf"));
        assert!(!request.contains("signal_family"));
        let decoded =
            ExportTraceServiceRequest::decode(request.body()).expect("OTLP trace request decodes");
        let resource_spans = decoded.resource_spans.first().expect("resource spans");
        let scope_spans = resource_spans
            .scope_spans
            .first()
            .expect("scope spans are present");
        let span = scope_spans.spans.first().expect("span is present");

        assert_eq!(span.name, "GET /checkout");
        assert_eq!(
            lower_hex(&span.trace_id),
            "4bf92f3577b34da6a3ce929d0e0e4736"
        );
        assert_eq!(lower_hex(&span.span_id), "00f067aa0ba902b7");
        let resource = resource_spans.resource.as_ref().expect("resource");
        assert!(resource.attributes.iter().any(|attribute| {
            attribute.key == "service.name"
                && format!("{:?}", attribute.value).contains("checkout-api")
        }));
        assert!(resource.attributes.iter().any(|attribute| {
            attribute.key == "k8s.namespace.name"
                && format!("{:?}", attribute.value).contains("default")
        }));
        assert!(resource.attributes.iter().any(|attribute| {
            attribute.key == "k8s.pod.name"
                && format!("{:?}", attribute.value).contains("checkout-123")
        }));
        assert!(resource.attributes.iter().any(|attribute| {
            attribute.key == "k8s.container.name"
                && format!("{:?}", attribute.value).contains("checkout")
        }));
        assert_eq!(span.kind, span::SpanKind::Server as i32);
        assert!(span.attributes.iter().any(|attribute| {
            attribute.key == "http.request.method"
                && format!("{:?}", attribute.value).contains("GET")
        }));
        let status = span.status.as_ref().expect("span status is present");
        assert_eq!(status.code, status::StatusCode::Error as i32);
        assert_eq!(status.message, "HTTP status code 503");
    }

    #[tokio::test]
    async fn otlp_http_sink_does_not_export_profiling_warnings_without_trace_ids() {
        let collector = FakeCollector::spawn(vec![]).await;
        let sink = OtlpHttpSink::new(OtlpHttpConfig {
            enabled: true,
            traces_endpoint: collector.url_with_path("/v1/traces"),
            metrics_enabled: false,
            traces_enabled: true,
            profiles_enabled: false,
            batch_size: 1,
            queue_capacity: 2,
            timeout_millis: 50,
            max_retries: 0,
            ..OtlpHttpConfig::default()
        })
        .expect("sink builds");

        sink.write(&profiling_warning())
            .await
            .expect("profiling warning without ids is ignored");

        assert!(collector.try_next_request().is_none());
        assert_eq!(sink.telemetry().invalid_trace_records, 0);
    }

    #[tokio::test]
    async fn otlp_http_sink_does_not_export_network_flow_warnings_without_trace_ids() {
        let collector = FakeCollector::spawn(vec![]).await;
        let sink = OtlpHttpSink::new(OtlpHttpConfig {
            enabled: true,
            traces_endpoint: collector.url_with_path("/v1/traces"),
            metrics_enabled: false,
            traces_enabled: true,
            profiles_enabled: false,
            batch_size: 1,
            queue_capacity: 2,
            timeout_millis: 50,
            max_retries: 0,
            ..OtlpHttpConfig::default()
        })
        .expect("sink builds");

        sink.write(&network_flow_warning())
            .await
            .expect("network flow warning without ids is ignored");

        assert!(collector.try_next_request().is_none());
        assert_eq!(sink.telemetry().invalid_trace_records, 0);
    }

    #[tokio::test]
    async fn otlp_http_sink_counts_declared_but_invalid_trace_identity() {
        let collector = FakeCollector::spawn(vec![]).await;
        let sink = OtlpHttpSink::new(OtlpHttpConfig {
            enabled: true,
            traces_endpoint: collector.url_with_path("/v1/traces"),
            metrics_enabled: false,
            traces_enabled: true,
            profiles_enabled: false,
            batch_size: 1,
            queue_capacity: 2,
            timeout_millis: 50,
            max_retries: 0,
            ..OtlpHttpConfig::default()
        })
        .expect("sink builds");
        let mut signal = request_span();
        let SignalPayload::RequestSpanObservation(span) = &mut signal.payload else {
            panic!("request span fixture");
        };
        span.trace_id = Some("invalid".to_string());

        sink.write(&signal)
            .await
            .expect("invalid declared identity is dropped");

        assert!(collector.try_next_request().is_none());
        assert_eq!(sink.telemetry().invalid_trace_records, 1);
    }

    #[tokio::test]
    async fn otlp_http_sink_exports_grpc_trace_error_status_as_otlp_protobuf() {
        let collector = FakeCollector::spawn(vec![200]).await;
        let sink = OtlpHttpSink::new(OtlpHttpConfig {
            enabled: true,
            traces_endpoint: collector.url_with_path("/v1/traces"),
            metrics_enabled: false,
            traces_enabled: true,
            profiles_enabled: false,
            batch_size: 1,
            queue_capacity: 2,
            timeout_millis: 1_000,
            max_retries: 0,
            ..OtlpHttpConfig::default()
        })
        .expect("sink builds");

        sink.write(&grpc_request_span())
            .await
            .expect("trace export succeeds");
        let request = collector.next_request().await;

        let decoded =
            ExportTraceServiceRequest::decode(request.body()).expect("OTLP trace request decodes");
        let span = decoded
            .resource_spans
            .first()
            .and_then(|resource_spans| resource_spans.scope_spans.first())
            .and_then(|scope_spans| scope_spans.spans.first())
            .expect("span is present");

        assert_eq!(span.name, "grpc request");
        assert!(span.attributes.iter().any(|attribute| {
            attribute.key == "rpc.grpc.status_code"
                && format!("{:?}", attribute.value).contains("13")
        }));
        assert!(
            !span
                .attributes
                .iter()
                .any(|attribute| attribute.key == "http.response.status_code")
        );
        let status = span.status.as_ref().expect("span status is present");
        assert_eq!(status.code, status::StatusCode::Error as i32);
        assert_eq!(status.message, "gRPC status code 13 (internal)");
    }

    #[tokio::test]
    async fn otlp_http_sink_exports_request_error_type_as_otlp_error_status() {
        let collector = FakeCollector::spawn(vec![200]).await;
        let sink = OtlpHttpSink::new(OtlpHttpConfig {
            enabled: true,
            traces_endpoint: collector.url_with_path("/v1/traces"),
            metrics_enabled: false,
            traces_enabled: true,
            profiles_enabled: false,
            batch_size: 1,
            queue_capacity: 2,
            timeout_millis: 1_000,
            max_retries: 0,
            ..OtlpHttpConfig::default()
        })
        .expect("sink builds");

        sink.write(&redis_error_request_span())
            .await
            .expect("trace export succeeds");
        let request = collector.next_request().await;

        let decoded =
            ExportTraceServiceRequest::decode(request.body()).expect("OTLP trace request decodes");
        let span = decoded
            .resource_spans
            .first()
            .and_then(|resource_spans| resource_spans.scope_spans.first())
            .and_then(|scope_spans| scope_spans.spans.first())
            .expect("span is present");

        assert_eq!(span.name, "redis command");
        assert!(span.attributes.iter().any(|attribute| {
            attribute.key == "error.type"
                && format!("{:?}", attribute.value).contains("redis_wrongtype")
        }));
        assert!(span.attributes.iter().any(|attribute| {
            attribute.key == "db.response.status_code"
                && format!("{:?}", attribute.value).contains("WRONGTYPE")
        }));
        let status = span.status.as_ref().expect("span status is present");
        assert_eq!(status.code, status::StatusCode::Error as i32);
        assert_eq!(status.message, "redis_wrongtype");
    }

    #[tokio::test]
    async fn otlp_http_sink_exports_response_status_attribute_as_otlp_error_status() {
        let collector = FakeCollector::spawn(vec![200]).await;
        let sink = OtlpHttpSink::new(OtlpHttpConfig {
            enabled: true,
            traces_endpoint: collector.url_with_path("/v1/traces"),
            metrics_enabled: false,
            traces_enabled: true,
            profiles_enabled: false,
            batch_size: 1,
            queue_capacity: 2,
            timeout_millis: 1_000,
            max_retries: 0,
            ..OtlpHttpConfig::default()
        })
        .expect("sink builds");
        let mut signal = redis_error_request_span();
        let SignalPayload::RequestSpanObservation(span) = &mut signal.payload else {
            panic!("expected request span");
        };
        span.attributes
            .retain(|attribute| attribute.key != "error.type");

        sink.write(&signal).await.expect("trace export succeeds");
        let request = collector.next_request().await;

        let decoded =
            ExportTraceServiceRequest::decode(request.body()).expect("OTLP trace request decodes");
        let span = decoded
            .resource_spans
            .first()
            .and_then(|resource_spans| resource_spans.scope_spans.first())
            .and_then(|scope_spans| scope_spans.spans.first())
            .expect("span is present");

        assert!(span.attributes.iter().any(|attribute| {
            attribute.key == "db.response.status_code"
                && format!("{:?}", attribute.value).contains("WRONGTYPE")
        }));
        assert!(
            !span
                .attributes
                .iter()
                .any(|attribute| attribute.key == "error.type")
        );
        let status = span.status.as_ref().expect("span status is present");
        assert_eq!(status.code, status::StatusCode::Error as i32);
        assert_eq!(status.message, "WRONGTYPE");
    }

    #[tokio::test]
    async fn otlp_http_sink_exports_kafka_request_error_type_as_otlp_error_status() {
        let collector = FakeCollector::spawn(vec![200]).await;
        let sink = OtlpHttpSink::new(OtlpHttpConfig {
            enabled: true,
            traces_endpoint: collector.url_with_path("/v1/traces"),
            metrics_enabled: false,
            traces_enabled: true,
            profiles_enabled: false,
            batch_size: 1,
            queue_capacity: 2,
            timeout_millis: 1_000,
            max_retries: 0,
            ..OtlpHttpConfig::default()
        })
        .expect("sink builds");

        sink.write(&kafka_error_request_span())
            .await
            .expect("trace export succeeds");
        let request = collector.next_request().await;

        let decoded =
            ExportTraceServiceRequest::decode(request.body()).expect("OTLP trace request decodes");
        let span = decoded
            .resource_spans
            .first()
            .and_then(|resource_spans| resource_spans.scope_spans.first())
            .and_then(|scope_spans| scope_spans.spans.first())
            .expect("span is present");

        assert_eq!(span.name, "kafka request");
        assert!(span.attributes.iter().any(|attribute| {
            attribute.key == "error.type" && format!("{:?}", attribute.value).contains("35")
        }));
        assert!(span.attributes.iter().any(|attribute| {
            attribute.key == "messaging.kafka.response.error_code"
                && format!("{:?}", attribute.value).contains("35")
        }));
        let status = span.status.as_ref().expect("span status is present");
        assert_eq!(status.code, status::StatusCode::Error as i32);
        assert_eq!(status.message, "35");
    }

    #[tokio::test]
    async fn otlp_http_sink_exports_nats_request_error_type_as_otlp_error_status() {
        let collector = FakeCollector::spawn(vec![200]).await;
        let sink = OtlpHttpSink::new(OtlpHttpConfig {
            enabled: true,
            traces_endpoint: collector.url_with_path("/v1/traces"),
            metrics_enabled: false,
            traces_enabled: true,
            profiles_enabled: false,
            batch_size: 1,
            queue_capacity: 2,
            timeout_millis: 1_000,
            max_retries: 0,
            ..OtlpHttpConfig::default()
        })
        .expect("sink builds");

        sink.write(&nats_error_request_span())
            .await
            .expect("trace export succeeds");
        let request = collector.next_request().await;

        let decoded =
            ExportTraceServiceRequest::decode(request.body()).expect("OTLP trace request decodes");
        let span = decoded
            .resource_spans
            .first()
            .and_then(|resource_spans| resource_spans.scope_spans.first())
            .and_then(|scope_spans| scope_spans.spans.first())
            .expect("span is present");

        assert_eq!(span.name, "nats message");
        assert!(span.attributes.iter().any(|attribute| {
            attribute.key == "error.type" && format!("{:?}", attribute.value).contains("nats_error")
        }));
        assert!(span.attributes.iter().any(|attribute| {
            attribute.key == "messaging.nats.status_code"
                && format!("{:?}", attribute.value).contains("ERR")
        }));
        let status = span.status.as_ref().expect("span status is present");
        assert_eq!(status.code, status::StatusCode::Error as i32);
        assert_eq!(status.message, "nats_error");
    }

    #[tokio::test]
    async fn otlp_http_sink_exports_database_error_types_as_otlp_error_status() {
        for (protocol, name, method, db_system, error_type) in [
            (
                ProtocolKind::Mongodb,
                "mongodb command",
                "find",
                "mongodb",
                "13",
            ),
            (
                ProtocolKind::Mysql,
                "mysql query",
                "SELECT",
                "mysql",
                "42000/1064",
            ),
            (
                ProtocolKind::Postgresql,
                "postgresql query",
                "SELECT",
                "postgresql",
                "23505",
            ),
        ] {
            let collector = FakeCollector::spawn(vec![200]).await;
            let sink = OtlpHttpSink::new(OtlpHttpConfig {
                enabled: true,
                traces_endpoint: collector.url_with_path("/v1/traces"),
                metrics_enabled: false,
                traces_enabled: true,
                profiles_enabled: false,
                batch_size: 1,
                queue_capacity: 2,
                timeout_millis: 1_000,
                max_retries: 0,
                ..OtlpHttpConfig::default()
            })
            .expect("sink builds");

            sink.write(&database_error_request_span(
                protocol, name, method, db_system, error_type,
            ))
            .await
            .expect("trace export succeeds");
            let request = collector.next_request().await;

            let decoded = ExportTraceServiceRequest::decode(request.body())
                .expect("OTLP trace request decodes");
            let span = decoded
                .resource_spans
                .first()
                .and_then(|resource_spans| resource_spans.scope_spans.first())
                .and_then(|scope_spans| scope_spans.spans.first())
                .expect("span is present");

            assert_eq!(span.name, name);
            assert!(span.attributes.iter().any(|attribute| {
                attribute.key == "db.system" && format!("{:?}", attribute.value).contains(db_system)
            }));
            assert!(span.attributes.iter().any(|attribute| {
                attribute.key == "db.response.status_code"
                    && format!("{:?}", attribute.value).contains(error_type)
            }));
            assert!(span.attributes.iter().any(|attribute| {
                attribute.key == "error.type"
                    && format!("{:?}", attribute.value).contains(error_type)
            }));
            let status = span.status.as_ref().expect("span status is present");
            assert_eq!(status.code, status::StatusCode::Error as i32);
            assert_eq!(status.message, error_type);
        }
    }

    #[tokio::test]
    async fn otlp_http_sink_exports_profile_records_as_otlp_protobuf() {
        let collector = FakeCollector::spawn(vec![200]).await;
        let sink = OtlpHttpSink::new(OtlpHttpConfig {
            enabled: true,
            profiles_endpoint: collector.url_with_path("/v1development/profiles"),
            metrics_enabled: false,
            traces_enabled: false,
            profiles_enabled: true,
            batch_size: 1,
            queue_capacity: 2,
            timeout_millis: 1_000,
            max_retries: 0,
            ..OtlpHttpConfig::default()
        })
        .expect("sink builds");

        sink.write(&profile_sample())
            .await
            .expect("profile export succeeds");
        let request = collector.next_request().await;

        assert!(request.contains("POST /v1development/profiles HTTP/1.1"));
        assert!(request.contains("content-type: application/x-protobuf"));
        assert!(!request.contains("signal_family"));
        let decoded = collector_profile_proto::ExportProfilesServiceRequest::decode(request.body())
            .expect("OTLP profile request decodes");
        let dictionary = decoded.dictionary.as_ref().expect("profile dictionary");
        let resource_profiles = decoded
            .resource_profiles
            .first()
            .expect("resource profiles are present");
        let scope_profiles = resource_profiles
            .scope_profiles
            .first()
            .expect("scope profiles are present");
        let profile = scope_profiles.profiles.first().expect("profile is present");
        let sample = profile.samples.first().expect("sample is present");

        assert!(dictionary.string_table.contains(&"samples".to_string()));
        assert!(dictionary.string_table.contains(&"count".to_string()));
        assert!(dictionary.string_table.contains(&"cpu".to_string()));
        assert!(dictionary.string_table.contains(&"nanoseconds".to_string()));
        assert!(
            dictionary
                .string_table
                .contains(&"checkout::handler".to_string())
        );
        assert_eq!(sample.values, vec![2]);
        assert_eq!(sample.stack_index, 1);
        assert_eq!(dictionary.stack_table[1].location_indices, vec![1]);
        assert_eq!(sample.timestamps_unix_nano, vec![1_000]);
        assert_eq!(profile.duration_nano, 10_000_000);
        assert_eq!(profile.period, 10_000_000);
        let resource = resource_profiles.resource.as_ref().expect("resource");
        assert!(resource.attributes.iter().any(|attribute| {
            attribute.key == "k8s.pod.name"
                && format!("{:?}", attribute.value).contains("checkout-123")
        }));
    }

    #[tokio::test]
    async fn otlp_http_sink_filters_and_bounds_profile_attributes() {
        let collector = FakeCollector::spawn(vec![200]).await;
        let sink = OtlpHttpSink::new(OtlpHttpConfig {
            enabled: true,
            profiles_endpoint: collector.url_with_path("/v1development/profiles"),
            metrics_enabled: false,
            traces_enabled: false,
            profiles_enabled: true,
            batch_size: 1,
            queue_capacity: 2,
            timeout_millis: 1_000,
            max_retries: 0,
            ..OtlpHttpConfig::default()
        })
        .expect("sink builds");
        let mut signal = profile_sample();
        let long_key = format!("profiling.long.{}", "k".repeat(80));
        let truncated_long_key = long_key[..64].to_string();
        let long_value = "v".repeat(300);
        let truncated_long_value = "v".repeat(256);
        if let SignalPayload::ProfileSampleObservation(sample) = &mut signal.payload {
            sample.attributes = vec![
                ProfilingAttribute {
                    key: "profiling.synthetic.fixture".to_string(),
                    value: "cpu_sample".to_string(),
                },
                ProfilingAttribute {
                    key: "authorization".to_string(),
                    value: "Bearer token".to_string(),
                },
                ProfilingAttribute {
                    key: "profile_id".to_string(),
                    value: "canonical".to_string(),
                },
                ProfilingAttribute {
                    key: long_key.clone(),
                    value: long_value,
                },
            ];
            sample
                .attributes
                .extend((0..20).map(|index| ProfilingAttribute {
                    key: format!("profiling.extra.{index:02}"),
                    value: format!("value-{index:02}"),
                }));
        }

        sink.write(&signal).await.expect("profile export succeeds");
        let request = collector.next_request().await;
        let decoded = collector_profile_proto::ExportProfilesServiceRequest::decode(request.body())
            .expect("OTLP profile request decodes");
        let dictionary = decoded.dictionary.as_ref().expect("profile dictionary");
        let resource_profiles = decoded
            .resource_profiles
            .first()
            .expect("resource profiles are present");
        let profile = resource_profiles
            .scope_profiles
            .first()
            .expect("scope profiles are present")
            .profiles
            .first()
            .expect("profile is present");

        assert_eq!(profile.attribute_indices.len(), 16);
        assert_profile_attribute(
            dictionary,
            &profile.attribute_indices,
            "profiling.synthetic.fixture",
            "cpu_sample",
        );
        assert_profile_attribute(
            dictionary,
            &profile.attribute_indices,
            &truncated_long_key,
            &truncated_long_value,
        );
        assert_profile_attribute(
            dictionary,
            &profile.attribute_indices,
            "profiling.extra.10",
            "value-10",
        );
        assert!(!profile_attribute_exists(
            dictionary,
            &profile.attribute_indices,
            "authorization"
        ));
        assert!(!profile_attribute_exists(
            dictionary,
            &profile.attribute_indices,
            "profile_id"
        ));
        assert!(!profile_attribute_exists(
            dictionary,
            &profile.attribute_indices,
            &long_key
        ));
        assert!(!profile_attribute_exists(
            dictionary,
            &profile.attribute_indices,
            "profiling.extra.11"
        ));
    }

    #[tokio::test]
    async fn otlp_http_sink_does_not_reexport_cumulative_profile_sessions() {
        let collector = FakeCollector::spawn(vec![200]).await;
        let sink = OtlpHttpSink::new(OtlpHttpConfig {
            enabled: true,
            profiles_endpoint: collector.url_with_path("/v1development/profiles"),
            metrics_enabled: false,
            traces_enabled: false,
            profiles_enabled: true,
            batch_size: 1,
            queue_capacity: 2,
            timeout_millis: 1_000,
            max_retries: 0,
            ..OtlpHttpConfig::default()
        })
        .expect("sink builds");

        sink.write(&profile_session())
            .await
            .expect("profile session is ignored");
        tokio::time::sleep(Duration::from_millis(20)).await;

        assert!(collector.try_next_request().is_none());
    }

    #[tokio::test]
    async fn otlp_http_sink_falls_back_to_single_endpoint_for_enabled_families() {
        let collector = FakeCollector::spawn(vec![200, 200, 200]).await;
        let sink = OtlpHttpSink::new(OtlpHttpConfig {
            enabled: true,
            endpoint: collector.url_with_path("/otlp"),
            batch_size: 1,
            queue_capacity: 4,
            timeout_millis: 1_000,
            max_retries: 0,
            ..OtlpHttpConfig::default()
        })
        .expect("sink builds");

        sink.write(&network_metric())
            .await
            .expect("metric export succeeds");
        sink.write(&request_span())
            .await
            .expect("trace export succeeds");
        sink.write(&profile_sample())
            .await
            .expect("profile export succeeds");

        assert!(
            collector
                .next_request()
                .await
                .contains("POST /otlp HTTP/1.1")
        );
        assert!(
            collector
                .next_request()
                .await
                .contains("POST /otlp HTTP/1.1")
        );
        assert!(
            collector
                .next_request()
                .await
                .contains("POST /otlp HTTP/1.1")
        );
    }

    #[tokio::test]
    async fn otlp_http_sink_supports_mixed_family_specific_and_fallback_endpoints() {
        let metrics_collector = FakeCollector::spawn(vec![200]).await;
        let fallback_collector = FakeCollector::spawn(vec![200, 200]).await;
        let sink = OtlpHttpSink::new(OtlpHttpConfig {
            enabled: true,
            endpoint: fallback_collector.url_with_path("/fallback"),
            metrics_endpoint: metrics_collector.url_with_path("/v1/metrics"),
            batch_size: 1,
            queue_capacity: 4,
            timeout_millis: 1_000,
            max_retries: 0,
            ..OtlpHttpConfig::default()
        })
        .expect("sink builds");

        sink.write(&network_metric())
            .await
            .expect("metric export succeeds");
        sink.write(&request_span())
            .await
            .expect("trace export succeeds");
        sink.write(&profile_sample())
            .await
            .expect("profile export succeeds");

        assert!(
            metrics_collector
                .next_request()
                .await
                .contains("POST /v1/metrics HTTP/1.1")
        );
        assert!(
            fallback_collector
                .next_request()
                .await
                .contains("POST /fallback HTTP/1.1")
        );
        assert!(
            fallback_collector
                .next_request()
                .await
                .contains("POST /fallback HTTP/1.1")
        );
    }

    fn network_metric() -> SignalEnvelope {
        network_metric_at(1, 200)
    }

    fn network_metric_at(value: u64, end_unix_nanos: u64) -> SignalEnvelope {
        SignalEnvelope::network_counter_metric(
            "generator.network_metrics",
            Some("node-a".to_string()),
            NetworkCounterMetric {
                metric_name: "network.connection.open.count".to_string(),
                unit: "{connection}".to_string(),
                value,
                window: MetricAggregationWindow {
                    start_unix_nanos: 100,
                    end_unix_nanos,
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
                kubernetes: None,
            },
        )
    }

    fn metric_point(request: &RecordedRequest) -> (u64, u64) {
        let decoded = ExportMetricsServiceRequest::decode(request.body())
            .expect("OTLP metrics request decodes");
        let metric = decoded.resource_metrics[0].scope_metrics[0]
            .metrics
            .first()
            .expect("metric is present");
        let Some(Data::Sum(sum)) = metric.data.as_ref() else {
            panic!("metric is exported as OTLP Sum");
        };
        let point = sum.data_points.first().expect("sum data point");
        let Some(number_data_point::Value::AsInt(value)) = point.value else {
            panic!("cumulative value is encoded as an integer");
        };
        (value as u64, point.time_unix_nano)
    }

    fn flow_byte_metric() -> SignalEnvelope {
        SignalEnvelope::network_counter_metric(
            "generator.network_metrics",
            Some("node-a".to_string()),
            NetworkCounterMetric {
                metric_name: "network.flow.bytes".to_string(),
                unit: "By".to_string(),
                value: 2048,
                window: MetricAggregationWindow {
                    start_unix_nanos: 100,
                    end_unix_nanos: 200,
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
                kubernetes: Some(KubernetesContext {
                    namespace: "e-navigator-bench".to_string(),
                    pod_name: "workload-a".to_string(),
                    pod_uid: Some("pod-uid".to_string()),
                    container_name: Some("workload".to_string()),
                    node_name: Some("homelab-01".to_string()),
                    labels: BTreeMap::new(),
                }),
            },
        )
    }

    fn request_span() -> SignalEnvelope {
        SignalEnvelope::request_span_observation(
            "generator.request_correlation",
            Some("node-a".to_string()),
            RequestSpanObservation {
                name: "GET /checkout".to_string(),
                protocol: e_navigator_signals::ProtocolKind::Http,
                trace_id: Some("4bf92f3577b34da6a3ce929d0e0e4736".to_string()),
                span_id: Some("00f067aa0ba902b7".to_string()),
                parent_span_id: None,
                start_unix_nanos: 1_000,
                end_unix_nanos: Some(2_000),
                duration_nanos: Some(1_000),
                correlation_kind: TraceCorrelationKind::ObservedTraceContext,
                confidence: TraceConfidence::High,
                service_name: Some("checkout-api".to_string()),
                method: Some("GET".to_string()),
                status_code: Some(503),
                process: None,
                container: Some(ContainerContext {
                    container_id: "container-a".to_string(),
                    runtime: Some("containerd".to_string()),
                }),
                kubernetes: Some(KubernetesContext {
                    namespace: "default".to_string(),
                    pod_name: "checkout-123".to_string(),
                    pod_uid: Some("pod-uid".to_string()),
                    container_name: Some("checkout".to_string()),
                    node_name: Some("node-a".to_string()),
                    labels: BTreeMap::new(),
                }),
                peer: None,
                attributes: Vec::new(),
            },
        )
    }

    fn grpc_request_span() -> SignalEnvelope {
        SignalEnvelope::request_span_observation(
            "generator.request_correlation",
            Some("node-a".to_string()),
            RequestSpanObservation {
                name: "grpc request".to_string(),
                protocol: ProtocolKind::Grpc,
                trace_id: Some("4bf92f3577b34da6a3ce929d0e0e4736".to_string()),
                span_id: Some("00f067aa0ba902b7".to_string()),
                parent_span_id: None,
                start_unix_nanos: 1_000,
                end_unix_nanos: Some(2_000),
                duration_nanos: Some(1_000),
                correlation_kind: TraceCorrelationKind::ObservedTraceContext,
                confidence: TraceConfidence::High,
                service_name: Some("checkout-api".to_string()),
                method: Some("GetCart".to_string()),
                status_code: Some(13),
                process: None,
                container: Some(ContainerContext {
                    container_id: "container-a".to_string(),
                    runtime: Some("containerd".to_string()),
                }),
                kubernetes: Some(KubernetesContext {
                    namespace: "default".to_string(),
                    pod_name: "checkout-123".to_string(),
                    pod_uid: Some("pod-uid".to_string()),
                    container_name: Some("checkout".to_string()),
                    node_name: Some("node-a".to_string()),
                    labels: BTreeMap::new(),
                }),
                peer: None,
                attributes: Vec::new(),
            },
        )
    }

    fn redis_error_request_span() -> SignalEnvelope {
        SignalEnvelope::request_span_observation(
            "generator.request_correlation",
            Some("node-a".to_string()),
            RequestSpanObservation {
                name: "redis command".to_string(),
                protocol: ProtocolKind::Redis,
                trace_id: Some("4bf92f3577b34da6a3ce929d0e0e4736".to_string()),
                span_id: Some("00f067aa0ba902b7".to_string()),
                parent_span_id: None,
                start_unix_nanos: 1_000,
                end_unix_nanos: Some(2_000),
                duration_nanos: Some(1_000),
                correlation_kind: TraceCorrelationKind::ObservedTraceContext,
                confidence: TraceConfidence::High,
                service_name: Some("cache-client".to_string()),
                method: Some("GET".to_string()),
                status_code: None,
                process: None,
                container: Some(ContainerContext {
                    container_id: "container-a".to_string(),
                    runtime: Some("containerd".to_string()),
                }),
                kubernetes: Some(KubernetesContext {
                    namespace: "default".to_string(),
                    pod_name: "redis-client-123".to_string(),
                    pod_uid: Some("pod-uid".to_string()),
                    container_name: Some("redis-client".to_string()),
                    node_name: Some("node-a".to_string()),
                    labels: BTreeMap::new(),
                }),
                peer: None,
                attributes: vec![
                    TraceAttribute {
                        key: "db.system".to_string(),
                        value: "redis".to_string(),
                    },
                    TraceAttribute {
                        key: "db.response.status_code".to_string(),
                        value: "WRONGTYPE".to_string(),
                    },
                    TraceAttribute {
                        key: "error.type".to_string(),
                        value: "redis_wrongtype".to_string(),
                    },
                ],
            },
        )
    }

    fn kafka_error_request_span() -> SignalEnvelope {
        SignalEnvelope::request_span_observation(
            "generator.request_correlation",
            Some("node-a".to_string()),
            RequestSpanObservation {
                name: "kafka request".to_string(),
                protocol: ProtocolKind::Kafka,
                trace_id: Some("4bf92f3577b34da6a3ce929d0e0e4736".to_string()),
                span_id: Some("00f067aa0ba902b7".to_string()),
                parent_span_id: None,
                start_unix_nanos: 1_000,
                end_unix_nanos: Some(2_000),
                duration_nanos: Some(1_000),
                correlation_kind: TraceCorrelationKind::ObservedTraceContext,
                confidence: TraceConfidence::High,
                service_name: Some("messaging-client".to_string()),
                method: Some("api_versions".to_string()),
                status_code: None,
                process: None,
                container: Some(ContainerContext {
                    container_id: "container-a".to_string(),
                    runtime: Some("containerd".to_string()),
                }),
                kubernetes: Some(KubernetesContext {
                    namespace: "default".to_string(),
                    pod_name: "kafka-client-123".to_string(),
                    pod_uid: Some("pod-uid".to_string()),
                    container_name: Some("kafka-client".to_string()),
                    node_name: Some("node-a".to_string()),
                    labels: BTreeMap::new(),
                }),
                peer: None,
                attributes: vec![
                    TraceAttribute {
                        key: "messaging.system".to_string(),
                        value: "kafka".to_string(),
                    },
                    TraceAttribute {
                        key: "messaging.kafka.response.error_code".to_string(),
                        value: "35".to_string(),
                    },
                    TraceAttribute {
                        key: "error.type".to_string(),
                        value: "35".to_string(),
                    },
                ],
            },
        )
    }

    fn nats_error_request_span() -> SignalEnvelope {
        SignalEnvelope::request_span_observation(
            "generator.request_correlation",
            Some("node-a".to_string()),
            RequestSpanObservation {
                name: "nats message".to_string(),
                protocol: ProtocolKind::Nats,
                trace_id: Some("4bf92f3577b34da6a3ce929d0e0e4736".to_string()),
                span_id: Some("00f067aa0ba902b7".to_string()),
                parent_span_id: None,
                start_unix_nanos: 1_000,
                end_unix_nanos: Some(2_000),
                duration_nanos: Some(1_000),
                correlation_kind: TraceCorrelationKind::ObservedTraceContext,
                confidence: TraceConfidence::High,
                service_name: Some("messaging-client".to_string()),
                method: Some("pub".to_string()),
                status_code: None,
                process: None,
                container: Some(ContainerContext {
                    container_id: "container-a".to_string(),
                    runtime: Some("containerd".to_string()),
                }),
                kubernetes: Some(KubernetesContext {
                    namespace: "default".to_string(),
                    pod_name: "nats-client-123".to_string(),
                    pod_uid: Some("pod-uid".to_string()),
                    container_name: Some("nats-client".to_string()),
                    node_name: Some("node-a".to_string()),
                    labels: BTreeMap::new(),
                }),
                peer: None,
                attributes: vec![
                    TraceAttribute {
                        key: "messaging.system".to_string(),
                        value: "nats".to_string(),
                    },
                    TraceAttribute {
                        key: "messaging.nats.status_code".to_string(),
                        value: "ERR".to_string(),
                    },
                    TraceAttribute {
                        key: "error.type".to_string(),
                        value: "nats_error".to_string(),
                    },
                ],
            },
        )
    }

    fn database_error_request_span(
        protocol: ProtocolKind,
        name: &str,
        method: &str,
        db_system: &str,
        error_type: &str,
    ) -> SignalEnvelope {
        SignalEnvelope::request_span_observation(
            "generator.request_correlation",
            Some("node-a".to_string()),
            RequestSpanObservation {
                name: name.to_string(),
                protocol,
                trace_id: Some("4bf92f3577b34da6a3ce929d0e0e4736".to_string()),
                span_id: Some("00f067aa0ba902b7".to_string()),
                parent_span_id: None,
                start_unix_nanos: 1_000,
                end_unix_nanos: Some(2_000),
                duration_nanos: Some(1_000),
                correlation_kind: TraceCorrelationKind::ObservedTraceContext,
                confidence: TraceConfidence::High,
                service_name: Some("database-client".to_string()),
                method: Some(method.to_string()),
                status_code: None,
                process: None,
                container: Some(ContainerContext {
                    container_id: "container-a".to_string(),
                    runtime: Some("containerd".to_string()),
                }),
                kubernetes: Some(KubernetesContext {
                    namespace: "default".to_string(),
                    pod_name: "database-client-123".to_string(),
                    pod_uid: Some("pod-uid".to_string()),
                    container_name: Some("database-client".to_string()),
                    node_name: Some("node-a".to_string()),
                    labels: BTreeMap::new(),
                }),
                peer: None,
                attributes: vec![
                    TraceAttribute {
                        key: "db.system".to_string(),
                        value: db_system.to_string(),
                    },
                    TraceAttribute {
                        key: "db.response.status_code".to_string(),
                        value: error_type.to_string(),
                    },
                    TraceAttribute {
                        key: "error.type".to_string(),
                        value: error_type.to_string(),
                    },
                ],
            },
        )
    }

    fn profile_sample() -> SignalEnvelope {
        SignalEnvelope::profile_sample_observation(
            "source.synthetic_exec",
            Some("node-a".to_string()),
            ProfileSampleObservation {
                timestamp_unix_nanos: 1_000,
                profiling_kind: ProfilingKind::Cpu,
                correlation_kind: ProfilingCorrelationKind::Synthetic,
                confidence: ProfilingConfidence::High,
                sample_count: 2,
                sampling_period_nanos: Some(10_000_000),
                stack_id: "stack:abc".to_string(),
                stack_frames: vec![ProfilingFrame {
                    symbol: Some("checkout::handler".to_string()),
                    module: Some("checkout".to_string()),
                    file: Some("/src/checkout.rs".to_string()),
                    line: Some(42),
                    module_offset: None,
                }],
                process: Some(NetworkProcessIdentity {
                    pid: 42,
                    ppid: Some(1),
                    uid: Some(1000),
                    command: "checkout-api".to_string(),
                    executable: Some("/app/checkout-api".to_string()),
                    cgroup_id: None,
                }),
                container: Some(ContainerContext {
                    container_id: "container-a".to_string(),
                    runtime: Some("containerd".to_string()),
                }),
                kubernetes: Some(KubernetesContext {
                    namespace: "default".to_string(),
                    pod_name: "checkout-123".to_string(),
                    pod_uid: Some("pod-uid".to_string()),
                    container_name: Some("checkout".to_string()),
                    node_name: Some("node-a".to_string()),
                    labels: BTreeMap::new(),
                }),
                thread_id: Some(7),
                thread_name: Some("worker".to_string()),
                attributes: vec![ProfilingAttribute {
                    key: "profiling.synthetic.fixture".to_string(),
                    value: "cpu_sample".to_string(),
                }],
            },
        )
    }

    fn profile_session() -> SignalEnvelope {
        SignalEnvelope::profiling_session_observation(
            "generator.profiling",
            Some("node-a".to_string()),
            ProfilingSessionObservation {
                window: MetricAggregationWindow {
                    start_unix_nanos: 1_000,
                    end_unix_nanos: 3_000,
                },
                profiling_kind: ProfilingKind::Cpu,
                correlation_kind: ProfilingCorrelationKind::ObservedProfileSample,
                confidence: ProfilingConfidence::Medium,
                profile_id: "profile:abc".to_string(),
                observed_sample_count: 24,
                dropped_sample_count: 76,
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
                container: None,
                kubernetes: None,
                source: "source.aya_cpu_profile".to_string(),
                attributes: vec![
                    ProfilingAttribute {
                        key: "profiling.synthetic.fixture".to_string(),
                        value: "cpu_session".to_string(),
                    },
                    ProfilingAttribute {
                        key: "authorization".to_string(),
                        value: "Bearer token".to_string(),
                    },
                ],
            },
        )
    }

    fn profiling_warning() -> SignalEnvelope {
        SignalEnvelope::profiling_warning_observation(
            "generator.profiling",
            Some("node-a".to_string()),
            ProfilingWarningObservation {
                warning_type: "dropped_profile_samples".to_string(),
                message: "profile samples were dropped by bounded aggregation".to_string(),
                timestamp_unix_nanos: 3_000,
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
                container: None,
                kubernetes: None,
                attributes: vec![ProfilingAttribute {
                    key: "profile.dropped_sample_count".to_string(),
                    value: "76".to_string(),
                }],
            },
        )
    }

    fn network_flow_warning() -> SignalEnvelope {
        SignalEnvelope::network_flow_warning(
            "generator.network_metrics",
            Some("node-a".to_string()),
            NetworkFlowWarning {
                warning_type: "missing_attribution".to_string(),
                message: "network flow has byte counters but incomplete source attribution"
                    .to_string(),
                timestamp_unix_nanos: 1_500,
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
                    command: "checkout-api".to_string(),
                    executable: Some("/app/checkout-api".to_string()),
                    cgroup_id: None,
                },
                container: None,
                kubernetes: Some(KubernetesContext {
                    namespace: "default".to_string(),
                    pod_name: "checkout-123".to_string(),
                    pod_uid: Some("pod-uid".to_string()),
                    container_name: Some("checkout".to_string()),
                    node_name: Some("node-a".to_string()),
                    labels: BTreeMap::new(),
                }),
            },
        )
    }

    fn assert_profile_attribute(
        dictionary: &collector_profile_proto::ProfilesDictionary,
        indices: &[i32],
        key: &str,
        value_fragment: &str,
    ) {
        let Some(attribute) = indices
            .iter()
            .filter_map(|index| usize::try_from(*index).ok())
            .find(|index| profile_attribute_key(dictionary, *index) == key)
            .and_then(|index| dictionary.attribute_table.get(index))
        else {
            panic!("profile attribute {key} is present");
        };

        assert!(
            format!("{:?}", attribute.value).contains(value_fragment),
            "profile attribute {key} should contain {value_fragment}, got {:?}",
            attribute.value
        );
    }

    fn profile_attribute_exists(
        dictionary: &collector_profile_proto::ProfilesDictionary,
        indices: &[i32],
        key: &str,
    ) -> bool {
        indices
            .iter()
            .filter_map(|index| usize::try_from(*index).ok())
            .any(|index| profile_attribute_key(dictionary, index) == key)
    }

    fn profile_attribute_key(
        dictionary: &collector_profile_proto::ProfilesDictionary,
        index: usize,
    ) -> &str {
        dictionary
            .attribute_table
            .get(index)
            .and_then(|attribute| usize::try_from(attribute.key_strindex).ok())
            .and_then(|index| dictionary.string_table.get(index))
            .map(String::as_str)
            .unwrap_or("")
    }

    fn lower_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[derive(Debug, Clone)]
    struct RecordedRequest {
        raw: Vec<u8>,
    }

    impl RecordedRequest {
        fn contains(&self, needle: &str) -> bool {
            String::from_utf8_lossy(&self.raw).contains(needle)
        }

        fn body(&self) -> &[u8] {
            let split_at = self
                .raw
                .windows(4)
                .position(|window| window == b"\r\n\r\n")
                .expect("request has body separator")
                + 4;
            &self.raw[split_at..]
        }
    }

    #[derive(Debug)]
    struct FakeCollector {
        address: std::net::SocketAddr,
        requests: tokio::sync::Mutex<tokio::sync::mpsc::Receiver<RecordedRequest>>,
    }

    impl FakeCollector {
        async fn spawn(statuses: Vec<u16>) -> Self {
            Self::spawn_with_delay(statuses, Duration::ZERO).await
        }

        async fn spawn_with_delay(statuses: Vec<u16>, response_delay: Duration) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind fake collector");
            let address = listener.local_addr().expect("collector address");
            let request_capacity = statuses.len().max(8);
            let (tx, rx) = tokio::sync::mpsc::channel(request_capacity);
            tokio::spawn(async move {
                for status in statuses {
                    let (mut socket, _) = listener.accept().await.expect("accept request");
                    let mut buffer = vec![0; 8192];
                    let bytes = socket.read(&mut buffer).await.expect("read request");
                    let request = RecordedRequest {
                        raw: buffer[..bytes].to_vec(),
                    };
                    let _ = tx.send(request).await;
                    tokio::time::sleep(response_delay).await;
                    let status_text = if status == 200 { "OK" } else { "ERR" };
                    let response = format!(
                        "HTTP/1.1 {status} {status_text}\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
                    );
                    socket
                        .write_all(response.as_bytes())
                        .await
                        .expect("write response");
                }
            });
            Self {
                address,
                requests: tokio::sync::Mutex::new(rx),
            }
        }

        fn url(&self) -> String {
            format!("http://{}", self.address)
        }

        fn url_with_path(&self, path: &str) -> String {
            format!("http://{}{}", self.address, path)
        }

        async fn next_request(&self) -> RecordedRequest {
            self.requests
                .lock()
                .await
                .recv()
                .await
                .expect("request received")
        }

        fn try_next_request(&self) -> Option<RecordedRequest> {
            self.requests.try_lock().ok()?.try_recv().ok()
        }
    }
}
