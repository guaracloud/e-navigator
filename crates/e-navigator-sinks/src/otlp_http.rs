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
    metric_exporter: Option<Mutex<HttpProtobufExporter<crate::OtelMetricRecord>>>,
    profile_exporter: Option<Mutex<HttpProtobufExporter<crate::OtelProfileRecord>>>,
    trace_exporter: Option<Mutex<HttpProtobufExporter<crate::OtelTraceRecord>>>,
}

impl OtlpHttpSink {
    pub fn new(config: OtlpHttpConfig) -> CoreResult<Self> {
        let metric_exporter = if config.metrics_enabled {
            Some(Mutex::new(build_exporter(
                exporter_config_for(&config, required_metrics_endpoint(&config)?),
                encode_metric_export_request,
            )?))
        } else {
            None
        };
        let profile_exporter = if config.profiles_enabled {
            Some(Mutex::new(build_exporter(
                exporter_config_for(&config, required_profiles_endpoint(&config)?),
                encode_profile_export_request,
            )?))
        } else {
            None
        };
        let trace_exporter = if config.traces_enabled {
            Some(Mutex::new(build_exporter(
                exporter_config_for(&config, required_traces_endpoint(&config)?),
                encode_trace_export_request,
            )?))
        } else {
            None
        };

        Ok(Self {
            config,
            metric_exporter,
            profile_exporter,
            trace_exporter,
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
            && let Some(exporter) = &self.trace_exporter
        {
            if !trace_record_has_valid_ids(&record) {
                return Ok(());
            }

            let mut exporter = exporter.lock().await;
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
            && let Some(exporter) = &self.metric_exporter
        {
            let mut exporter = exporter.lock().await;
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
            && let Some(exporter) = &self.profile_exporter
        {
            let mut exporter = exporter.lock().await;
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
) -> CoreResult<HttpProtobufExporter<T>>
where
    T: Clone,
{
    HttpProtobufExporter::new(config, encode_batch).map_err(|err| {
        e_navigator_core::CoreError::ModuleFailed {
            module: "sink.otlp_http".to_string(),
            message: err.to_string(),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
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
        let sample = profile.sample.first().expect("sample is present");

        assert!(dictionary.string_table.contains(&"cpu".to_string()));
        assert!(dictionary.string_table.contains(&"nanoseconds".to_string()));
        assert!(
            dictionary
                .string_table
                .contains(&"checkout::handler".to_string())
        );
        assert_eq!(sample.value, vec![2]);
        assert_eq!(sample.locations_start_index, 0);
        assert_eq!(sample.locations_length, 1);
        assert_eq!(profile.location_indices, vec![1]);
        assert_eq!(sample.timestamps_unix_nano, vec![1_000]);
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
    async fn otlp_http_sink_exports_profile_session_dropped_samples_as_otlp_protobuf() {
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
            .expect("profile session export succeeds");
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
        let sample = profile.sample.first().expect("sample is present");

        assert!(dictionary.string_table.contains(&"cpu".to_string()));
        assert!(dictionary.string_table.contains(&"nanoseconds".to_string()));
        assert_eq!(sample.value, vec![24]);
        assert_eq!(sample.locations_start_index, 0);
        assert_eq!(sample.locations_length, 0);
        assert!(profile.location_indices.is_empty());
        assert_eq!(sample.timestamps_unix_nano, vec![3_000]);
        assert_eq!(profile.time_nanos, 3_000);
        assert_eq!(profile.duration_nanos, 2_000);
        assert_eq!(profile.period, 10_000_000);
        assert_eq!(profile.profile_id.len(), 16);
        assert_profile_attribute(
            dictionary,
            &profile.attribute_indices,
            "profile.distinct_stack_count",
            "5",
        );
        assert_profile_attribute(
            dictionary,
            &profile.attribute_indices,
            "profile.dropped_sample_count",
            "76",
        );
        assert_profile_attribute(
            dictionary,
            &profile.attribute_indices,
            "profile.source",
            "source.aya_cpu_profile",
        );
        assert!(
            !dictionary
                .attribute_table
                .iter()
                .any(|attribute| attribute.key == "authorization")
        );
        assert_eq!(sample.attribute_indices, profile.attribute_indices);
        let resource = resource_profiles.resource.as_ref().expect("resource");
        assert!(resource.attributes.iter().any(|attribute| {
            attribute.key == "process.pid" && format!("{:?}", attribute.value).contains("42")
        }));
        assert!(resource.attributes.iter().any(|attribute| {
            attribute.key == "host.name" && format!("{:?}", attribute.value).contains("node-a")
        }));
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
            .filter_map(|index| dictionary.attribute_table.get(index))
            .find(|attribute| attribute.key == key)
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
            .filter_map(|index| dictionary.attribute_table.get(index))
            .any(|attribute| attribute.key == key)
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

    mod collector_profile_proto {
        use opentelemetry_proto::tonic::{
            common::v1::{InstrumentationScope, KeyValue},
            resource::v1::Resource,
        };
        use prost::Message;

        #[derive(Clone, PartialEq, Message)]
        pub(super) struct ExportProfilesServiceRequest {
            #[prost(message, repeated, tag = "1")]
            pub resource_profiles: Vec<ResourceProfiles>,
            #[prost(message, optional, tag = "2")]
            pub dictionary: Option<ProfilesDictionary>,
        }

        #[derive(Clone, PartialEq, Message)]
        pub(super) struct ProfilesDictionary {
            #[prost(message, repeated, tag = "1")]
            pub mapping_table: Vec<Mapping>,
            #[prost(message, repeated, tag = "2")]
            pub location_table: Vec<Location>,
            #[prost(message, repeated, tag = "3")]
            pub function_table: Vec<Function>,
            #[prost(message, repeated, tag = "4")]
            pub link_table: Vec<Link>,
            #[prost(string, repeated, tag = "5")]
            pub string_table: Vec<String>,
            #[prost(message, repeated, tag = "6")]
            pub attribute_table: Vec<KeyValue>,
            #[prost(message, repeated, tag = "7")]
            pub attribute_units: Vec<AttributeUnit>,
        }

        #[derive(Clone, PartialEq, Message)]
        pub(super) struct ResourceProfiles {
            #[prost(message, optional, tag = "1")]
            pub resource: Option<Resource>,
            #[prost(message, repeated, tag = "2")]
            pub scope_profiles: Vec<ScopeProfiles>,
            #[prost(string, tag = "3")]
            pub schema_url: String,
        }

        #[derive(Clone, PartialEq, Message)]
        pub(super) struct ScopeProfiles {
            #[prost(message, optional, tag = "1")]
            pub scope: Option<InstrumentationScope>,
            #[prost(message, repeated, tag = "2")]
            pub profiles: Vec<Profile>,
            #[prost(string, tag = "3")]
            pub schema_url: String,
        }

        #[derive(Clone, PartialEq, Message)]
        pub(super) struct Profile {
            #[prost(message, repeated, tag = "1")]
            pub sample_type: Vec<ValueType>,
            #[prost(message, repeated, tag = "2")]
            pub sample: Vec<Sample>,
            #[prost(int32, repeated, packed = "true", tag = "3")]
            pub location_indices: Vec<i32>,
            #[prost(int64, tag = "4")]
            pub time_nanos: i64,
            #[prost(int64, tag = "5")]
            pub duration_nanos: i64,
            #[prost(message, optional, tag = "6")]
            pub period_type: Option<ValueType>,
            #[prost(int64, tag = "7")]
            pub period: i64,
            #[prost(int32, repeated, packed = "true", tag = "8")]
            pub comment_strindices: Vec<i32>,
            #[prost(int32, tag = "9")]
            pub default_sample_type_index: i32,
            #[prost(bytes = "vec", tag = "10")]
            pub profile_id: Vec<u8>,
            #[prost(uint32, tag = "11")]
            pub dropped_attributes_count: u32,
            #[prost(string, tag = "12")]
            pub original_payload_format: String,
            #[prost(bytes = "vec", tag = "13")]
            pub original_payload: Vec<u8>,
            #[prost(int32, repeated, packed = "true", tag = "14")]
            pub attribute_indices: Vec<i32>,
        }

        #[derive(Clone, PartialEq, Message)]
        pub(super) struct AttributeUnit {
            #[prost(int32, tag = "1")]
            pub attribute_key_strindex: i32,
            #[prost(int32, tag = "2")]
            pub unit_strindex: i32,
        }

        #[derive(Clone, PartialEq, Message)]
        pub(super) struct Link {
            #[prost(bytes = "vec", tag = "1")]
            pub trace_id: Vec<u8>,
            #[prost(bytes = "vec", tag = "2")]
            pub span_id: Vec<u8>,
        }

        #[derive(Clone, PartialEq, Message)]
        pub(super) struct ValueType {
            #[prost(int32, tag = "1")]
            pub type_strindex: i32,
            #[prost(int32, tag = "2")]
            pub unit_strindex: i32,
            #[prost(enumeration = "AggregationTemporality", tag = "3")]
            pub aggregation_temporality: i32,
        }

        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, prost::Enumeration)]
        #[repr(i32)]
        pub(super) enum AggregationTemporality {
            Unspecified = 0,
            Delta = 1,
            Cumulative = 2,
        }

        #[derive(Clone, PartialEq, Message)]
        pub(super) struct Sample {
            #[prost(int32, tag = "1")]
            pub locations_start_index: i32,
            #[prost(int32, tag = "2")]
            pub locations_length: i32,
            #[prost(int64, repeated, packed = "true", tag = "3")]
            pub value: Vec<i64>,
            #[prost(int32, repeated, packed = "true", tag = "4")]
            pub attribute_indices: Vec<i32>,
            #[prost(int32, optional, tag = "5")]
            pub link_index: Option<i32>,
            #[prost(uint64, repeated, packed = "true", tag = "6")]
            pub timestamps_unix_nano: Vec<u64>,
        }

        #[derive(Clone, PartialEq, Message)]
        pub(super) struct Mapping {
            #[prost(uint64, tag = "1")]
            pub memory_start: u64,
            #[prost(uint64, tag = "2")]
            pub memory_limit: u64,
            #[prost(uint64, tag = "3")]
            pub file_offset: u64,
            #[prost(int32, tag = "4")]
            pub filename_strindex: i32,
            #[prost(int32, repeated, packed = "true", tag = "5")]
            pub attribute_indices: Vec<i32>,
            #[prost(bool, tag = "6")]
            pub has_functions: bool,
            #[prost(bool, tag = "7")]
            pub has_filenames: bool,
            #[prost(bool, tag = "8")]
            pub has_line_numbers: bool,
            #[prost(bool, tag = "9")]
            pub has_inline_frames: bool,
        }

        #[derive(Clone, PartialEq, Message)]
        pub(super) struct Location {
            #[prost(int32, optional, tag = "1")]
            pub mapping_index: Option<i32>,
            #[prost(uint64, tag = "2")]
            pub address: u64,
            #[prost(message, repeated, tag = "3")]
            pub line: Vec<Line>,
            #[prost(bool, tag = "4")]
            pub is_folded: bool,
            #[prost(int32, repeated, packed = "true", tag = "5")]
            pub attribute_indices: Vec<i32>,
        }

        #[derive(Clone, PartialEq, Message)]
        pub(super) struct Line {
            #[prost(int32, tag = "1")]
            pub function_index: i32,
            #[prost(int64, tag = "2")]
            pub line: i64,
            #[prost(int64, tag = "3")]
            pub column: i64,
        }

        #[derive(Clone, PartialEq, Message)]
        pub(super) struct Function {
            #[prost(int32, tag = "1")]
            pub name_strindex: i32,
            #[prost(int32, tag = "2")]
            pub system_name_strindex: i32,
            #[prost(int32, tag = "3")]
            pub filename_strindex: i32,
            #[prost(int64, tag = "4")]
            pub start_line: i64,
        }
    }
}
