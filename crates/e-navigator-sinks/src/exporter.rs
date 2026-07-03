use reqwest::{
    Client,
    header::{CONTENT_TYPE, HeaderMap},
};
use serde::Serialize;
use std::{collections::VecDeque, time::Duration};
use thiserror::Error;
use tokio::time::timeout;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpExporterConfig {
    pub endpoint: String,
    pub headers: Vec<(String, String)>,
    pub batch_size: usize,
    pub queue_capacity: usize,
    pub timeout_millis: u64,
    pub max_retries: usize,
    pub tls_insecure_skip_verify: bool,
}

impl HttpExporterConfig {
    pub const MAX_ENDPOINT_BYTES_LIMIT: usize = 2048;
    pub const MAX_BATCH_SIZE_LIMIT: usize = 4096;
    pub const MAX_QUEUE_CAPACITY_LIMIT: usize = 65_536;
    pub const MAX_TIMEOUT_MILLIS_LIMIT: u64 = 300_000;
    pub const MAX_RETRIES_LIMIT: usize = 16;
    pub const MAX_HEADERS_LIMIT: usize = 64;
    pub const MAX_HEADER_NAME_BYTES_LIMIT: usize = 128;
    pub const MAX_HEADER_VALUE_BYTES_LIMIT: usize = 4096;

    pub fn validate(&self) -> Result<(), ExporterError> {
        if self.endpoint.is_empty() {
            return Err(ExporterError::InvalidConfig("endpoint is required"));
        }
        if self.endpoint.len() > Self::MAX_ENDPOINT_BYTES_LIMIT {
            return Err(ExporterError::InvalidConfig(
                "endpoint must be at most 2048 bytes",
            ));
        }
        if self.endpoint.trim() != self.endpoint || self.endpoint.chars().any(char::is_whitespace) {
            return Err(ExporterError::InvalidConfig(
                "endpoint must not contain whitespace",
            ));
        }
        if self.endpoint.bytes().any(|byte| byte.is_ascii_control()) {
            return Err(ExporterError::InvalidConfig(
                "endpoint must not contain control characters",
            ));
        }
        let endpoint = reqwest::Url::parse(&self.endpoint)
            .map_err(|_| ExporterError::InvalidConfig("endpoint must be a valid URL"))?;
        if !matches!(endpoint.scheme(), "http" | "https") {
            return Err(ExporterError::InvalidConfig(
                "endpoint must start with http:// or https://",
            ));
        }
        let rest = self
            .endpoint
            .strip_prefix("http://")
            .or_else(|| self.endpoint.strip_prefix("https://"))
            .ok_or(ExporterError::InvalidConfig(
                "endpoint must start with http:// or https://",
            ))?;
        let authority = rest
            .split(['/', '?', '#'])
            .next()
            .expect("split always returns at least one segment");
        if authority.is_empty() || authority.starts_with(':') {
            return Err(ExporterError::InvalidConfig("endpoint must include a host"));
        }
        if endpoint.host_str().is_none() {
            return Err(ExporterError::InvalidConfig("endpoint must include a host"));
        }
        validate_headers(&self.headers)?;
        if self.batch_size == 0 {
            return Err(ExporterError::InvalidConfig(
                "batch_size must be greater than zero",
            ));
        }
        if self.batch_size > Self::MAX_BATCH_SIZE_LIMIT {
            return Err(ExporterError::InvalidConfig(
                "batch_size must be less than or equal to 4096",
            ));
        }
        if self.queue_capacity == 0 {
            return Err(ExporterError::InvalidConfig(
                "queue_capacity must be greater than zero",
            ));
        }
        if self.queue_capacity > Self::MAX_QUEUE_CAPACITY_LIMIT {
            return Err(ExporterError::InvalidConfig(
                "queue_capacity must be less than or equal to 65536",
            ));
        }
        if self.timeout_millis == 0 {
            return Err(ExporterError::InvalidConfig(
                "timeout_millis must be greater than zero",
            ));
        }
        if self.timeout_millis > Self::MAX_TIMEOUT_MILLIS_LIMIT {
            return Err(ExporterError::InvalidConfig(
                "timeout_millis must be less than or equal to 300000",
            ));
        }
        if self.max_retries > Self::MAX_RETRIES_LIMIT {
            return Err(ExporterError::InvalidConfig(
                "max_retries must be less than or equal to 16",
            ));
        }
        Ok(())
    }
}

fn validate_headers(headers: &[(String, String)]) -> Result<(), ExporterError> {
    if headers.len() > HttpExporterConfig::MAX_HEADERS_LIMIT {
        return Err(ExporterError::InvalidConfig(
            "headers must contain at most 64 entries",
        ));
    }
    for (name, value) in headers {
        if name.len() > HttpExporterConfig::MAX_HEADER_NAME_BYTES_LIMIT {
            return Err(ExporterError::InvalidConfig(
                "header names must be at most 128 bytes",
            ));
        }
        if value.len() > HttpExporterConfig::MAX_HEADER_VALUE_BYTES_LIMIT {
            return Err(ExporterError::InvalidConfig(
                "header values must be at most 4096 bytes",
            ));
        }
        if value.bytes().any(|byte| byte.is_ascii_control()) {
            return Err(ExporterError::InvalidConfig(
                "header values must not contain control characters",
            ));
        }
    }
    header_map(headers)?;
    Ok(())
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ExporterCounters {
    pub enqueued: u64,
    pub exported: u64,
    pub dropped_queue_full: u64,
    pub failed_batches: u64,
    pub retry_attempts: u64,
}

#[derive(Debug)]
pub struct HttpJsonExporter<T> {
    config: HttpExporterConfig,
    queue: VecDeque<T>,
    counters: ExporterCounters,
    client: Client,
}

#[derive(Debug)]
pub struct HttpProtobufExporter<T> {
    config: HttpExporterConfig,
    queue: VecDeque<T>,
    counters: ExporterCounters,
    client: Client,
    encode_batch: fn(&[T]) -> Result<Vec<u8>, ExporterError>,
}

impl<T> HttpJsonExporter<T>
where
    T: Clone + Serialize,
{
    pub fn new(config: HttpExporterConfig) -> Result<Self, ExporterError> {
        config.validate()?;
        let client = Client::builder()
            .use_rustls_tls()
            .danger_accept_invalid_certs(config.tls_insecure_skip_verify)
            .build()
            .map_err(ExporterError::BuildClient)?;
        Ok(Self {
            config,
            queue: VecDeque::new(),
            counters: ExporterCounters::default(),
            client,
        })
    }

    pub fn enqueue(&mut self, item: T) {
        if self.queue.len() >= self.config.queue_capacity {
            self.counters.dropped_queue_full = self.counters.dropped_queue_full.saturating_add(1);
            return;
        }
        self.queue.push_back(item);
        self.counters.enqueued = self.counters.enqueued.saturating_add(1);
    }

    pub fn counters(&self) -> ExporterCounters {
        self.counters
    }

    pub fn queued_len(&self) -> usize {
        self.queue.len()
    }

    pub async fn flush_once(&mut self) -> Result<(), ExporterError> {
        if self.queue.is_empty() {
            return Ok(());
        }

        let batch_len = self.queue.len().min(self.config.batch_size);
        let batch = self
            .queue
            .iter()
            .take(batch_len)
            .cloned()
            .collect::<Vec<_>>();

        let mut last_error = None;
        for attempt in 0..=self.config.max_retries {
            if attempt > 0 {
                self.counters.retry_attempts = self.counters.retry_attempts.saturating_add(1);
            }
            match self.send_batch(&batch).await {
                Ok(()) => {
                    for _ in 0..batch_len {
                        let _ = self.queue.pop_front();
                    }
                    self.counters.exported =
                        self.counters.exported.saturating_add(batch_len as u64);
                    return Ok(());
                }
                Err(err) => last_error = Some(err),
            }
        }

        self.counters.failed_batches = self.counters.failed_batches.saturating_add(1);
        Err(last_error.unwrap_or(ExporterError::RetriesExhausted))
    }

    async fn send_batch(&self, batch: &[T]) -> Result<(), ExporterError> {
        let headers = header_map(&self.config.headers)?;
        let request = self
            .client
            .post(&self.config.endpoint)
            .headers(headers)
            .json(batch);
        let response = timeout(
            Duration::from_millis(self.config.timeout_millis),
            request.send(),
        )
        .await
        .map_err(|_| ExporterError::Timeout)??;

        if !response.status().is_success() {
            return Err(ExporterError::Status(response.status().as_u16()));
        }
        Ok(())
    }
}

impl<T> HttpProtobufExporter<T>
where
    T: Clone,
{
    pub fn new(
        config: HttpExporterConfig,
        encode_batch: fn(&[T]) -> Result<Vec<u8>, ExporterError>,
    ) -> Result<Self, ExporterError> {
        config.validate()?;
        let client = Client::builder()
            .use_rustls_tls()
            .danger_accept_invalid_certs(config.tls_insecure_skip_verify)
            .build()
            .map_err(ExporterError::BuildClient)?;
        Ok(Self {
            config,
            queue: VecDeque::new(),
            counters: ExporterCounters::default(),
            client,
            encode_batch,
        })
    }

    pub fn enqueue(&mut self, item: T) {
        if self.queue.len() >= self.config.queue_capacity {
            self.counters.dropped_queue_full = self.counters.dropped_queue_full.saturating_add(1);
            return;
        }
        self.queue.push_back(item);
        self.counters.enqueued = self.counters.enqueued.saturating_add(1);
    }

    pub fn counters(&self) -> ExporterCounters {
        self.counters
    }

    pub fn queued_len(&self) -> usize {
        self.queue.len()
    }

    pub async fn flush_once(&mut self) -> Result<(), ExporterError> {
        if self.queue.is_empty() {
            return Ok(());
        }

        let batch_len = self.queue.len().min(self.config.batch_size);
        let batch = self
            .queue
            .iter()
            .take(batch_len)
            .cloned()
            .collect::<Vec<_>>();

        let mut last_error = None;
        for attempt in 0..=self.config.max_retries {
            if attempt > 0 {
                self.counters.retry_attempts = self.counters.retry_attempts.saturating_add(1);
            }
            match self.send_batch(&batch).await {
                Ok(()) => {
                    for _ in 0..batch_len {
                        let _ = self.queue.pop_front();
                    }
                    self.counters.exported =
                        self.counters.exported.saturating_add(batch_len as u64);
                    return Ok(());
                }
                Err(err) => last_error = Some(err),
            }
        }

        self.counters.failed_batches = self.counters.failed_batches.saturating_add(1);
        Err(last_error.unwrap_or(ExporterError::RetriesExhausted))
    }

    async fn send_batch(&self, batch: &[T]) -> Result<(), ExporterError> {
        let headers = header_map(&self.config.headers)?;
        let body = (self.encode_batch)(batch)?;
        let request = self
            .client
            .post(&self.config.endpoint)
            .headers(headers)
            .header(CONTENT_TYPE, "application/x-protobuf")
            .body(body);
        let response = timeout(
            Duration::from_millis(self.config.timeout_millis),
            request.send(),
        )
        .await
        .map_err(|_| ExporterError::Timeout)??;

        if !response.status().is_success() {
            return Err(ExporterError::Status(response.status().as_u16()));
        }
        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum ExporterError {
    #[error("invalid exporter config: {0}")]
    InvalidConfig(&'static str),
    #[error("failed to build HTTP client: {0}")]
    BuildClient(reqwest::Error),
    #[error("invalid header")]
    InvalidHeader,
    #[error("failed to encode export payload: {0}")]
    Encode(String),
    #[error("export request timed out")]
    Timeout,
    #[error("collector returned HTTP {0}")]
    Status(u16),
    #[error("request failed: {0}")]
    Request(#[from] reqwest::Error),
    #[error("export retries exhausted")]
    RetriesExhausted,
}

fn header_map(headers: &[(String, String)]) -> Result<HeaderMap, ExporterError> {
    let mut map = HeaderMap::new();
    for (name, value) in headers {
        let name = reqwest::header::HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| ExporterError::InvalidHeader)?;
        let value = reqwest::header::HeaderValue::from_str(value)
            .map_err(|_| ExporterError::InvalidHeader)?;
        map.insert(name, value);
    }
    Ok(map)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    struct TestRecord {
        value: u64,
    }

    fn valid_config() -> HttpExporterConfig {
        HttpExporterConfig {
            endpoint: "http://127.0.0.1:9".to_string(),
            headers: Vec::new(),
            batch_size: 1,
            queue_capacity: 1,
            timeout_millis: 1,
            max_retries: 0,
            tls_insecure_skip_verify: false,
        }
    }

    #[test]
    fn exporter_rejects_invalid_endpoints() {
        for (endpoint, expected_message) in [
            (
                " http://127.0.0.1:9",
                "endpoint must not contain whitespace",
            ),
            (
                "http://exa mple.test",
                "endpoint must not contain whitespace",
            ),
            (
                "http://127.0.0.1:9/\u{7}",
                "endpoint must not contain control characters",
            ),
            (
                "grpc://127.0.0.1:4317",
                "endpoint must start with http:// or https://",
            ),
            ("http://", "endpoint must be a valid URL"),
            ("http:///v1/metrics", "endpoint must include a host"),
            ("http://:4318/v1/metrics", "endpoint must be a valid URL"),
        ] {
            let err = HttpExporterConfig {
                endpoint: endpoint.to_string(),
                ..valid_config()
            }
            .validate()
            .expect_err("invalid endpoint fails");

            assert_eq!(
                err.to_string(),
                format!("invalid exporter config: {expected_message}")
            );
        }

        let err = HttpExporterConfig {
            endpoint: format!(
                "http://127.0.0.1:9/{}",
                "x".repeat(HttpExporterConfig::MAX_ENDPOINT_BYTES_LIMIT)
            ),
            ..valid_config()
        }
        .validate()
        .expect_err("oversized endpoint fails");

        assert_eq!(
            err.to_string(),
            "invalid exporter config: endpoint must be at most 2048 bytes"
        );
    }

    #[test]
    fn exporter_runtime_limits_match_otlp_http_config_limits() {
        assert_eq!(
            HttpExporterConfig::MAX_ENDPOINT_BYTES_LIMIT,
            e_navigator_core::OtlpHttpConfig::MAX_ENDPOINT_BYTES_LIMIT
        );
        assert_eq!(
            HttpExporterConfig::MAX_BATCH_SIZE_LIMIT,
            e_navigator_core::OtlpHttpConfig::MAX_BATCH_SIZE_LIMIT
        );
        assert_eq!(
            HttpExporterConfig::MAX_QUEUE_CAPACITY_LIMIT,
            e_navigator_core::OtlpHttpConfig::MAX_QUEUE_CAPACITY_LIMIT
        );
        assert_eq!(
            HttpExporterConfig::MAX_TIMEOUT_MILLIS_LIMIT,
            e_navigator_core::OtlpHttpConfig::MAX_TIMEOUT_MILLIS_LIMIT
        );
        assert_eq!(
            HttpExporterConfig::MAX_RETRIES_LIMIT,
            e_navigator_core::OtlpHttpConfig::MAX_RETRIES_LIMIT
        );
    }

    #[test]
    fn exporter_rejects_oversized_runtime_bounds() {
        for (config, expected_message) in [
            (
                HttpExporterConfig {
                    batch_size: HttpExporterConfig::MAX_BATCH_SIZE_LIMIT + 1,
                    ..valid_config()
                },
                "batch_size must be less than or equal to 4096",
            ),
            (
                HttpExporterConfig {
                    queue_capacity: HttpExporterConfig::MAX_QUEUE_CAPACITY_LIMIT + 1,
                    ..valid_config()
                },
                "queue_capacity must be less than or equal to 65536",
            ),
            (
                HttpExporterConfig {
                    timeout_millis: HttpExporterConfig::MAX_TIMEOUT_MILLIS_LIMIT + 1,
                    ..valid_config()
                },
                "timeout_millis must be less than or equal to 300000",
            ),
            (
                HttpExporterConfig {
                    max_retries: HttpExporterConfig::MAX_RETRIES_LIMIT + 1,
                    ..valid_config()
                },
                "max_retries must be less than or equal to 16",
            ),
        ] {
            let err = config.validate().expect_err("oversized bound is invalid");

            assert_eq!(
                err.to_string(),
                format!("invalid exporter config: {expected_message}")
            );
        }
    }

    #[test]
    fn exporter_rejects_unbounded_or_invalid_headers() {
        for (headers, expected_message) in [
            (
                (0..=HttpExporterConfig::MAX_HEADERS_LIMIT)
                    .map(|index| (format!("x-header-{index}"), "value".to_string()))
                    .collect::<Vec<_>>(),
                "headers must contain at most 64 entries",
            ),
            (
                vec![(
                    "x".repeat(HttpExporterConfig::MAX_HEADER_NAME_BYTES_LIMIT + 1),
                    "value".to_string(),
                )],
                "header names must be at most 128 bytes",
            ),
            (
                vec![(
                    "x-header".to_string(),
                    "v".repeat(HttpExporterConfig::MAX_HEADER_VALUE_BYTES_LIMIT + 1),
                )],
                "header values must be at most 4096 bytes",
            ),
            (
                vec![("x-header".to_string(), "bad\nvalue".to_string())],
                "header values must not contain control characters",
            ),
        ] {
            let err = HttpExporterConfig {
                headers,
                ..valid_config()
            }
            .validate()
            .expect_err("invalid headers fail");

            assert_eq!(
                err.to_string(),
                format!("invalid exporter config: {expected_message}")
            );
        }

        let err = HttpExporterConfig {
            headers: vec![("bad header".to_string(), "value".to_string())],
            ..valid_config()
        }
        .validate()
        .expect_err("invalid header syntax fails");

        assert_eq!(err.to_string(), "invalid header");
    }

    #[tokio::test]
    async fn exporter_batches_to_local_collector_with_headers() {
        let server = FakeCollector::spawn(vec![200]).await;
        let mut exporter = HttpJsonExporter::new(HttpExporterConfig {
            endpoint: server.url(),
            headers: vec![("authorization".to_string(), "Bearer test".to_string())],
            batch_size: 2,
            queue_capacity: 4,
            timeout_millis: 1_000,
            max_retries: 0,
            tls_insecure_skip_verify: false,
        })
        .expect("config valid");

        exporter.enqueue(TestRecord { value: 1 });
        exporter.enqueue(TestRecord { value: 2 });
        exporter.enqueue(TestRecord { value: 3 });

        exporter.flush_once().await.expect("flush succeeds");
        let request = server.next_request().await;

        assert_eq!(exporter.counters().exported, 2);
        assert_eq!(exporter.queued_len(), 1);
        assert!(request.contains("authorization: Bearer test"));
        assert!(request.contains(r#"[{"value":1},{"value":2}]"#));
    }

    #[tokio::test]
    async fn exporter_retries_failed_batches_without_dropping_them() {
        let server = FakeCollector::spawn(vec![500, 200]).await;
        let mut exporter = HttpJsonExporter::new(HttpExporterConfig {
            endpoint: server.url(),
            headers: Vec::new(),
            batch_size: 1,
            queue_capacity: 2,
            timeout_millis: 1_000,
            max_retries: 1,
            tls_insecure_skip_verify: false,
        })
        .expect("config valid");

        exporter.enqueue(TestRecord { value: 7 });

        exporter.flush_once().await.expect("retry succeeds");

        assert_eq!(exporter.counters().retry_attempts, 1);
        assert_eq!(exporter.counters().exported, 1);
        assert_eq!(exporter.queued_len(), 0);
    }

    #[test]
    fn bounded_queue_drops_new_items_with_counter() {
        let mut exporter = HttpJsonExporter::new(HttpExporterConfig {
            endpoint: "http://127.0.0.1:9".to_string(),
            headers: Vec::new(),
            batch_size: 1,
            queue_capacity: 1,
            timeout_millis: 1,
            max_retries: 0,
            tls_insecure_skip_verify: false,
        })
        .expect("config valid");

        exporter.enqueue(TestRecord { value: 1 });
        exporter.enqueue(TestRecord { value: 2 });

        assert_eq!(exporter.queued_len(), 1);
        assert_eq!(exporter.counters().dropped_queue_full, 1);
    }

    #[derive(Debug)]
    struct FakeCollector {
        address: std::net::SocketAddr,
        requests: tokio::sync::mpsc::Receiver<String>,
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
                requests: rx,
            }
        }

        fn url(&self) -> String {
            format!("http://{}", self.address)
        }

        async fn next_request(mut self) -> String {
            self.requests.recv().await.expect("request received")
        }
    }
}
