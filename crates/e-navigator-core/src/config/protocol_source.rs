use serde::{Deserialize, Serialize};

use super::{ConfigError, ConfigResult};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolSourceConfig {
    #[serde(default = "default_protocol_source_kafka_ports")]
    pub kafka_ports: Vec<u16>,
    #[serde(default = "default_protocol_source_mongodb_ports")]
    pub mongodb_ports: Vec<u16>,
    #[serde(default = "default_protocol_source_mysql_ports")]
    pub mysql_ports: Vec<u16>,
    #[serde(default = "default_protocol_source_nats_ports")]
    pub nats_ports: Vec<u16>,
    #[serde(default = "default_protocol_source_postgresql_ports")]
    pub postgresql_ports: Vec<u16>,
    #[serde(default = "default_protocol_source_redis_ports")]
    pub redis_ports: Vec<u16>,
    #[serde(default = "default_protocol_source_max_buffered_bytes_per_connection")]
    pub max_buffered_bytes_per_connection: usize,
    #[serde(default = "default_protocol_source_max_tracked_connections")]
    pub max_tracked_connections: usize,
    #[serde(default = "default_protocol_source_max_attributes")]
    pub max_attributes: usize,
}

impl Default for ProtocolSourceConfig {
    fn default() -> Self {
        Self {
            kafka_ports: default_protocol_source_kafka_ports(),
            mongodb_ports: default_protocol_source_mongodb_ports(),
            mysql_ports: default_protocol_source_mysql_ports(),
            nats_ports: default_protocol_source_nats_ports(),
            postgresql_ports: default_protocol_source_postgresql_ports(),
            redis_ports: default_protocol_source_redis_ports(),
            max_buffered_bytes_per_connection:
                default_protocol_source_max_buffered_bytes_per_connection(),
            max_tracked_connections: default_protocol_source_max_tracked_connections(),
            max_attributes: default_protocol_source_max_attributes(),
        }
    }
}

impl ProtocolSourceConfig {
    /// Matches the eBPF `PROTOCOL_CAPTURE_PORTS` map capacity.
    pub const MAX_TOTAL_PORTS: usize = 64;
    pub const MAX_BUFFERED_BYTES_LIMIT: usize = 64 * 1024;
    pub const MAX_TRACKED_CONNECTIONS_LIMIT: usize = 65_536;
    pub const MAX_ATTRIBUTES_LIMIT: usize = 32;

    pub fn port_protocols(&self) -> impl Iterator<Item = (&'static str, &[u16])> {
        [
            ("kafka", self.kafka_ports.as_slice()),
            ("mongodb", self.mongodb_ports.as_slice()),
            ("mysql", self.mysql_ports.as_slice()),
            ("nats", self.nats_ports.as_slice()),
            ("postgresql", self.postgresql_ports.as_slice()),
            ("redis", self.redis_ports.as_slice()),
        ]
        .into_iter()
    }

    pub(super) fn validate(&self) -> ConfigResult<()> {
        let mut seen_ports = std::collections::BTreeMap::new();
        let mut total_ports = 0_usize;
        for (protocol, ports) in self.port_protocols() {
            for port in ports {
                if *port == 0 {
                    return Err(ConfigError::invalid_value(
                        port_field(protocol),
                        format!("protocol_source.{protocol}_ports must not contain port 0"),
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
                "protocol_source",
                format!(
                    "protocol_source port lists declare {total_ports} ports; at most {} are supported",
                    Self::MAX_TOTAL_PORTS
                ),
            ));
        }
        if !(1..=Self::MAX_BUFFERED_BYTES_LIMIT).contains(&self.max_buffered_bytes_per_connection) {
            return Err(ConfigError::invalid_value(
                "protocol_source.max_buffered_bytes_per_connection",
                format!(
                    "protocol_source.max_buffered_bytes_per_connection must be between 1 and {}",
                    Self::MAX_BUFFERED_BYTES_LIMIT
                ),
            ));
        }
        if !(1..=Self::MAX_TRACKED_CONNECTIONS_LIMIT).contains(&self.max_tracked_connections) {
            return Err(ConfigError::invalid_value(
                "protocol_source.max_tracked_connections",
                format!(
                    "protocol_source.max_tracked_connections must be between 1 and {}",
                    Self::MAX_TRACKED_CONNECTIONS_LIMIT
                ),
            ));
        }
        if !(1..=Self::MAX_ATTRIBUTES_LIMIT).contains(&self.max_attributes) {
            return Err(ConfigError::invalid_value(
                "protocol_source.max_attributes",
                format!(
                    "protocol_source.max_attributes must be between 1 and {}",
                    Self::MAX_ATTRIBUTES_LIMIT
                ),
            ));
        }
        Ok(())
    }
}

fn port_field(protocol: &str) -> &'static str {
    match protocol {
        "kafka" => "protocol_source.kafka_ports",
        "mongodb" => "protocol_source.mongodb_ports",
        "mysql" => "protocol_source.mysql_ports",
        "nats" => "protocol_source.nats_ports",
        "postgresql" => "protocol_source.postgresql_ports",
        "redis" => "protocol_source.redis_ports",
        _ => "protocol_source",
    }
}

fn default_protocol_source_kafka_ports() -> Vec<u16> {
    vec![9092]
}

fn default_protocol_source_mongodb_ports() -> Vec<u16> {
    vec![27017]
}

fn default_protocol_source_mysql_ports() -> Vec<u16> {
    vec![3306]
}

fn default_protocol_source_nats_ports() -> Vec<u16> {
    vec![4222]
}

fn default_protocol_source_postgresql_ports() -> Vec<u16> {
    vec![5432]
}

fn default_protocol_source_redis_ports() -> Vec<u16> {
    vec![6379]
}

fn default_protocol_source_max_buffered_bytes_per_connection() -> usize {
    8 * 1024
}

fn default_protocol_source_max_tracked_connections() -> usize {
    2048
}

fn default_protocol_source_max_attributes() -> usize {
    8
}
