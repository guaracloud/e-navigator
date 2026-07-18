use serde::{Deserialize, Serialize};

use super::{ConfigError, ConfigResult};

/// Configuration for the uprobe-based TLS plaintext capture source
/// (`source.aya_tls`).
///
/// This is library-boundary interception at the userspace TLS read/write
/// calls (OpenSSL 1.1.1/3 `SSL_read`/`SSL_write`, GnuTLS ABI 30
/// `gnutls_record_recv`/`gnutls_record_send`), NOT on-the-wire decryption.
/// Captured plaintext is classified by the remote port and fed to the same
/// bounded protocol parsers used for cleartext capture.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsSourceConfig {
    /// Remote ports whose decrypted plaintext is HTTP/1 (for example 443).
    #[serde(default)]
    pub http1_ports: Vec<u16>,
    /// Remote ports whose decrypted plaintext is HTTP/2/gRPC over TLS.
    #[serde(default)]
    pub http2_ports: Vec<u16>,
    /// Remote ports whose decrypted plaintext is a Kafka stream over TLS.
    #[serde(default)]
    pub kafka_ports: Vec<u16>,
    /// Remote ports whose decrypted plaintext is a MongoDB stream over TLS.
    #[serde(default)]
    pub mongodb_ports: Vec<u16>,
    /// Remote ports whose decrypted plaintext is a MySQL stream over TLS.
    #[serde(default)]
    pub mysql_ports: Vec<u16>,
    /// Remote ports whose decrypted plaintext is a NATS stream over TLS.
    #[serde(default)]
    pub nats_ports: Vec<u16>,
    /// Remote ports whose decrypted plaintext is a PostgreSQL stream over TLS.
    #[serde(default)]
    pub postgresql_ports: Vec<u16>,
    /// Remote ports whose decrypted plaintext is a Redis stream over TLS
    /// (for example 6380 for rediss).
    #[serde(default)]
    pub redis_ports: Vec<u16>,
    /// Bytes captured per TLS read/write call. Plaintext beyond this stays
    /// accounted as an uncaptured gap by the stream reassembler.
    #[serde(default = "default_tls_source_capture_bytes_per_call")]
    pub capture_bytes_per_call: usize,
    /// Maximum concurrently tracked TLS connections.
    #[serde(default = "default_tls_source_max_tracked_connections")]
    pub max_tracked_connections: usize,
    /// Maximum bytes buffered per connection while reassembling a frame.
    #[serde(default = "default_tls_source_max_buffered_bytes_per_connection")]
    pub max_buffered_bytes_per_connection: usize,
    /// Maximum bounded semantic attributes emitted per observation.
    #[serde(default = "default_tls_source_max_attributes")]
    pub max_attributes: usize,
}

impl Default for TlsSourceConfig {
    fn default() -> Self {
        Self {
            http1_ports: Vec::new(),
            http2_ports: Vec::new(),
            kafka_ports: Vec::new(),
            mongodb_ports: Vec::new(),
            mysql_ports: Vec::new(),
            nats_ports: Vec::new(),
            postgresql_ports: Vec::new(),
            redis_ports: Vec::new(),
            capture_bytes_per_call: default_tls_source_capture_bytes_per_call(),
            max_tracked_connections: default_tls_source_max_tracked_connections(),
            max_buffered_bytes_per_connection: default_tls_source_max_buffered_bytes_per_connection(
            ),
            max_attributes: default_tls_source_max_attributes(),
        }
    }
}

impl TlsSourceConfig {
    /// Matches the eBPF `TLS_CAPTURE_PORTS` map capacity.
    pub const MAX_TOTAL_PORTS: usize = 64;
    /// Matches the eBPF per-call segment size; smaller windows gain nothing.
    pub const MIN_CAPTURE_BYTES_PER_CALL: usize = 256;
    /// Matches the eBPF per-call segment emission bound (16 * 256 bytes).
    pub const MAX_CAPTURE_BYTES_PER_CALL: usize = 4096;
    pub const MAX_BUFFERED_BYTES_LIMIT: usize = 64 * 1024;
    pub const MAX_TRACKED_CONNECTIONS_LIMIT: usize = 65_536;
    pub const MAX_ATTRIBUTES_LIMIT: usize = 32;

    pub fn port_protocols(&self) -> impl Iterator<Item = (&'static str, &[u16])> {
        [
            ("http1", self.http1_ports.as_slice()),
            ("http2", self.http2_ports.as_slice()),
            ("kafka", self.kafka_ports.as_slice()),
            ("mongodb", self.mongodb_ports.as_slice()),
            ("mysql", self.mysql_ports.as_slice()),
            ("nats", self.nats_ports.as_slice()),
            ("postgresql", self.postgresql_ports.as_slice()),
            ("redis", self.redis_ports.as_slice()),
        ]
        .into_iter()
    }

    /// True when at least one protocol port is configured for capture.
    pub fn has_capture_ports(&self) -> bool {
        self.port_protocols().any(|(_, ports)| !ports.is_empty())
    }

    pub(super) fn validate(&self) -> ConfigResult<()> {
        let mut seen_ports = std::collections::BTreeMap::new();
        let mut total_ports = 0_usize;
        for (protocol, ports) in self.port_protocols() {
            for port in ports {
                if *port == 0 {
                    return Err(ConfigError::invalid_value(
                        port_field(protocol),
                        format!("tls_source.{protocol}_ports must not contain port 0"),
                    ));
                }
                if let Some(existing) = seen_ports.insert(*port, protocol) {
                    return Err(ConfigError::invalid_value(
                        port_field(protocol),
                        format!(
                            "port {port} is assigned to both {existing} and {protocol}; each port must map to exactly one protocol"
                        ),
                    ));
                }
                total_ports += 1;
            }
        }
        if total_ports > Self::MAX_TOTAL_PORTS {
            return Err(ConfigError::invalid_value(
                "tls_source",
                format!(
                    "tls_source port lists declare {total_ports} ports; at most {} are supported",
                    Self::MAX_TOTAL_PORTS
                ),
            ));
        }
        if !(Self::MIN_CAPTURE_BYTES_PER_CALL..=Self::MAX_CAPTURE_BYTES_PER_CALL)
            .contains(&self.capture_bytes_per_call)
        {
            return Err(ConfigError::invalid_value(
                "tls_source.capture_bytes_per_call",
                format!(
                    "tls_source.capture_bytes_per_call must be between {} and {}",
                    Self::MIN_CAPTURE_BYTES_PER_CALL,
                    Self::MAX_CAPTURE_BYTES_PER_CALL
                ),
            ));
        }
        if !(1..=Self::MAX_BUFFERED_BYTES_LIMIT).contains(&self.max_buffered_bytes_per_connection) {
            return Err(ConfigError::invalid_value(
                "tls_source.max_buffered_bytes_per_connection",
                format!(
                    "tls_source.max_buffered_bytes_per_connection must be between 1 and {}",
                    Self::MAX_BUFFERED_BYTES_LIMIT
                ),
            ));
        }
        if !(1..=Self::MAX_TRACKED_CONNECTIONS_LIMIT).contains(&self.max_tracked_connections) {
            return Err(ConfigError::invalid_value(
                "tls_source.max_tracked_connections",
                format!(
                    "tls_source.max_tracked_connections must be between 1 and {}",
                    Self::MAX_TRACKED_CONNECTIONS_LIMIT
                ),
            ));
        }
        if !(1..=Self::MAX_ATTRIBUTES_LIMIT).contains(&self.max_attributes) {
            return Err(ConfigError::invalid_value(
                "tls_source.max_attributes",
                format!(
                    "tls_source.max_attributes must be between 1 and {}",
                    Self::MAX_ATTRIBUTES_LIMIT
                ),
            ));
        }
        Ok(())
    }
}

fn port_field(protocol: &str) -> &'static str {
    match protocol {
        "http1" => "tls_source.http1_ports",
        "http2" => "tls_source.http2_ports",
        "kafka" => "tls_source.kafka_ports",
        "mongodb" => "tls_source.mongodb_ports",
        "mysql" => "tls_source.mysql_ports",
        "nats" => "tls_source.nats_ports",
        "postgresql" => "tls_source.postgresql_ports",
        "redis" => "tls_source.redis_ports",
        _ => "tls_source",
    }
}

fn default_tls_source_capture_bytes_per_call() -> usize {
    1024
}

fn default_tls_source_max_tracked_connections() -> usize {
    2048
}

fn default_tls_source_max_buffered_bytes_per_connection() -> usize {
    8 * 1024
}

fn default_tls_source_max_attributes() -> usize {
    8
}
