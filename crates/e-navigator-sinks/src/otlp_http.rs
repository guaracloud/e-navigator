use async_trait::async_trait;
use e_navigator_core::{CoreResult, ModuleKind, ModuleMetadata, OtlpHttpConfig, Sink};
use e_navigator_signals::SignalEnvelope;
use tokio::sync::Mutex;

use crate::{
    HttpExporterConfig, HttpProtobufExporter, format_otel_metric_record,
    format_otel_profile_record, format_otel_trace_record,
    otlp_metric_proto::encode_metric_export_request,
    otlp_profile_proto::encode_profile_export_request,
    otlp_trace_proto::{encode_trace_export_request, trace_record_has_valid_ids},
};

#[derive(Debug)]
pub struct OtlpHttpSink {
    config: OtlpHttpConfig,
    metric_exporter: Mutex<HttpProtobufExporter<crate::OtelMetricRecord>>,
    profile_exporter: Mutex<HttpProtobufExporter<crate::OtelProfileRecord>>,
    trace_exporter: Mutex<HttpProtobufExporter<crate::OtelTraceRecord>>,
}

impl OtlpHttpSink {
    pub fn new(config: OtlpHttpConfig) -> CoreResult<Self> {
        let exporter_config = HttpExporterConfig {
            endpoint: config.endpoint.clone(),
            headers: Vec::new(),
            batch_size: config.batch_size,
            queue_capacity: config.queue_capacity,
            timeout_millis: config.timeout_millis,
            max_retries: config.max_retries,
            tls_insecure_skip_verify: config.tls_insecure_skip_verify,
        };
        let metric_exporter =
            HttpProtobufExporter::new(exporter_config.clone(), encode_metric_export_request)
                .map_err(|err| e_navigator_core::CoreError::ModuleFailed {
                    module: "sink.otlp_http".to_string(),
                    message: err.to_string(),
                })?;
        let profile_exporter =
            HttpProtobufExporter::new(exporter_config.clone(), encode_profile_export_request)
                .map_err(|err| e_navigator_core::CoreError::ModuleFailed {
                    module: "sink.otlp_http".to_string(),
                    message: err.to_string(),
                })?;
        let trace_exporter =
            HttpProtobufExporter::new(exporter_config, encode_trace_export_request).map_err(
                |err| e_navigator_core::CoreError::ModuleFailed {
                    module: "sink.otlp_http".to_string(),
                    message: err.to_string(),
                },
            )?;

        Ok(Self {
            config,
            metric_exporter: Mutex::new(metric_exporter),
            profile_exporter: Mutex::new(profile_exporter),
            trace_exporter: Mutex::new(trace_exporter),
        })
    }
}

#[async_trait]
impl Sink<SignalEnvelope> for OtlpHttpSink {
    fn metadata(&self) -> ModuleMetadata {
        ModuleMetadata::new("sink.otlp_http", ModuleKind::Sink)
    }

    async fn write(&self, signal: &SignalEnvelope) -> CoreResult<()> {
        if self.config.traces_enabled
            && let Some(record) = format_otel_trace_record(signal)
        {
            if !trace_record_has_valid_ids(&record) {
                return Ok(());
            }

            let mut exporter = self.trace_exporter.lock().await;
            exporter.enqueue(record);
            return exporter.flush_once().await.map_err(|err| {
                e_navigator_core::CoreError::ModuleFailed {
                    module: "sink.otlp_http".to_string(),
                    message: err.to_string(),
                }
            });
        }

        if self.config.metrics_enabled
            && let Some(record) = format_otel_metric_record(signal)
        {
            let mut exporter = self.metric_exporter.lock().await;
            exporter.enqueue(record);
            return exporter.flush_once().await.map_err(|err| {
                e_navigator_core::CoreError::ModuleFailed {
                    module: "sink.otlp_http".to_string(),
                    message: err.to_string(),
                }
            });
        }

        if self.config.profiles_enabled
            && let Some(record) = format_otel_profile_record(signal)
        {
            let mut exporter = self.profile_exporter.lock().await;
            exporter.enqueue(record);
            return exporter.flush_once().await.map_err(|err| {
                e_navigator_core::CoreError::ModuleFailed {
                    module: "sink.otlp_http".to_string(),
                    message: err.to_string(),
                }
            });
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use e_navigator_core::Sink;
    use e_navigator_signals::{
        ContainerContext, KubernetesContext, MetricAggregationWindow, NetworkAddressFamily,
        NetworkCounterMetric, NetworkProcessIdentity, NetworkProtocol, ProfileSampleObservation,
        ProfilingAttribute, ProfilingConfidence, ProfilingCorrelationKind, ProfilingFrame,
        ProfilingKind, RequestSpanObservation, SignalEnvelope, TraceConfidence,
        TraceCorrelationKind,
    };
    use opentelemetry_proto::tonic::{
        collector::{
            metrics::v1::ExportMetricsServiceRequest,
            profiles::v1development::ExportProfilesServiceRequest,
            trace::v1::ExportTraceServiceRequest,
        },
        metrics::v1::{metric::Data, number_data_point},
    };
    use prost::Message;
    use std::collections::BTreeMap;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    #[tokio::test]
    async fn otlp_http_sink_exports_metric_records_as_otlp_protobuf() {
        let collector = FakeCollector::spawn(vec![200]).await;
        let sink = OtlpHttpSink::new(OtlpHttpConfig {
            enabled: true,
            endpoint: collector.url(),
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

        assert!(request.contains("POST / HTTP/1.1"));
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
    async fn otlp_http_sink_respects_disabled_signal_families() {
        let collector = FakeCollector::spawn(vec![]).await;
        let sink = OtlpHttpSink::new(OtlpHttpConfig {
            enabled: true,
            endpoint: collector.url(),
            metrics_enabled: false,
            traces_enabled: true,
            profiles_enabled: true,
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
    async fn otlp_http_sink_exports_trace_records_as_otlp_protobuf() {
        let collector = FakeCollector::spawn(vec![200]).await;
        let sink = OtlpHttpSink::new(OtlpHttpConfig {
            enabled: true,
            endpoint: collector.url(),
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
        assert!(span.attributes.iter().any(|attribute| {
            attribute.key == "http.request.method"
                && format!("{:?}", attribute.value).contains("GET")
        }));
    }

    #[tokio::test]
    async fn otlp_http_sink_exports_profile_records_as_otlp_protobuf() {
        let collector = FakeCollector::spawn(vec![200]).await;
        let sink = OtlpHttpSink::new(OtlpHttpConfig {
            enabled: true,
            endpoint: collector.url(),
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

        assert!(request.contains("content-type: application/x-protobuf"));
        assert!(!request.contains("signal_family"));
        let decoded = ExportProfilesServiceRequest::decode(request.body())
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

        assert!(dictionary.string_table.contains(&"cpu".to_string()));
        assert!(dictionary.string_table.contains(&"nanoseconds".to_string()));
        assert!(
            dictionary
                .string_table
                .contains(&"checkout::handler".to_string())
        );
        assert_eq!(sample.values, vec![2]);
        assert_eq!(sample.timestamps_unix_nano, vec![1_000]);
        assert_eq!(profile.period, 10_000_000);
        let resource = resource_profiles.resource.as_ref().expect("resource");
        assert!(resource.attributes.iter().any(|attribute| {
            attribute.key == "k8s.pod.name"
                && format!("{:?}", attribute.value).contains("checkout-123")
        }));
    }

    fn network_metric() -> SignalEnvelope {
        SignalEnvelope::network_counter_metric(
            "generator.network_metrics",
            Some("node-a".to_string()),
            NetworkCounterMetric {
                metric_name: "network.connection.open.count".to_string(),
                unit: "{connection}".to_string(),
                value: 1,
                window: MetricAggregationWindow {
                    start_unix_nanos: 100,
                    end_unix_nanos: 200,
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
                status_code: Some(200),
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
            let listener = TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind fake collector");
            let address = listener.local_addr().expect("collector address");
            let (tx, rx) = tokio::sync::mpsc::channel(8);
            tokio::spawn(async move {
                for status in statuses {
                    let (mut socket, _) = listener.accept().await.expect("accept request");
                    let mut buffer = vec![0; 8192];
                    let bytes = socket.read(&mut buffer).await.expect("read request");
                    let request = RecordedRequest {
                        raw: buffer[..bytes].to_vec(),
                    };
                    let _ = tx.send(request).await;
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
