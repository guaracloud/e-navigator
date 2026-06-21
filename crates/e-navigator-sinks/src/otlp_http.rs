use async_trait::async_trait;
use e_navigator_core::{CoreResult, ModuleKind, ModuleMetadata, OtlpHttpConfig, Sink};
use e_navigator_signals::SignalEnvelope;
use serde::Serialize;
use tokio::sync::Mutex;

use crate::{
    HttpExporterConfig, HttpJsonExporter, ProfileRecord, format_otel_metric_record,
    format_otel_trace_record, format_profile_record,
};

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case", tag = "signal_family", content = "record")]
enum OtlpHttpRecord {
    Metric(crate::OtelMetricRecord),
    Trace(crate::OtelTraceRecord),
    Profile(ProfileRecord),
}

#[derive(Debug)]
pub struct OtlpHttpSink {
    config: OtlpHttpConfig,
    exporter: Mutex<HttpJsonExporter<OtlpHttpRecord>>,
}

impl OtlpHttpSink {
    pub fn new(config: OtlpHttpConfig) -> CoreResult<Self> {
        let exporter = HttpJsonExporter::new(HttpExporterConfig {
            endpoint: config.endpoint.clone(),
            headers: Vec::new(),
            batch_size: config.batch_size,
            queue_capacity: config.queue_capacity,
            timeout_millis: config.timeout_millis,
            max_retries: config.max_retries,
            tls_insecure_skip_verify: config.tls_insecure_skip_verify,
        })
        .map_err(|err| e_navigator_core::CoreError::ModuleFailed {
            module: "sink.otlp_http".to_string(),
            message: err.to_string(),
        })?;

        Ok(Self {
            config,
            exporter: Mutex::new(exporter),
        })
    }
}

#[async_trait]
impl Sink<SignalEnvelope> for OtlpHttpSink {
    fn metadata(&self) -> ModuleMetadata {
        ModuleMetadata::new("sink.otlp_http", ModuleKind::Sink)
    }

    async fn write(&self, signal: &SignalEnvelope) -> CoreResult<()> {
        let record = if self.config.metrics_enabled {
            format_otel_metric_record(signal).map(OtlpHttpRecord::Metric)
        } else {
            None
        }
        .or_else(|| {
            if self.config.traces_enabled {
                format_otel_trace_record(signal).map(OtlpHttpRecord::Trace)
            } else {
                None
            }
        })
        .or_else(|| {
            if self.config.profiles_enabled {
                format_profile_record(signal).map(OtlpHttpRecord::Profile)
            } else {
                None
            }
        });

        let Some(record) = record else {
            return Ok(());
        };

        let mut exporter = self.exporter.lock().await;
        exporter.enqueue(record);
        exporter
            .flush_once()
            .await
            .map_err(|err| e_navigator_core::CoreError::ModuleFailed {
                module: "sink.otlp_http".to_string(),
                message: err.to_string(),
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use e_navigator_core::Sink;
    use e_navigator_signals::{
        MetricAggregationWindow, NetworkAddressFamily, NetworkCounterMetric, NetworkProtocol,
        SignalEnvelope,
    };
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    #[tokio::test]
    async fn otlp_http_sink_exports_metric_records_to_fake_collector() {
        let collector = FakeCollector::spawn(vec![200]).await;
        let sink = OtlpHttpSink::new(OtlpHttpConfig {
            enabled: true,
            endpoint: collector.url(),
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
        assert!(request.contains("network.connection.open.count"));
        assert!(request.contains("signal_family"));
        assert!(request.contains("metric"));
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

    #[derive(Debug)]
    struct FakeCollector {
        address: std::net::SocketAddr,
        requests: tokio::sync::Mutex<tokio::sync::mpsc::Receiver<String>>,
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
                    let request = String::from_utf8_lossy(&buffer[..bytes]).to_string();
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

        async fn next_request(&self) -> String {
            self.requests
                .lock()
                .await
                .recv()
                .await
                .expect("request received")
        }

        fn try_next_request(&self) -> Option<String> {
            self.requests.try_lock().ok()?.try_recv().ok()
        }
    }
}
