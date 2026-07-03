use serde::{Deserialize, Serialize};

use super::{ConfigError, ConfigResult};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsSourceConfig {
    #[serde(default = "default_dns_source_max_packet_bytes")]
    pub max_packet_bytes: usize,
    #[serde(default = "default_dns_source_max_preview_bytes")]
    pub max_preview_bytes: usize,
}

impl Default for DnsSourceConfig {
    fn default() -> Self {
        Self {
            max_packet_bytes: default_dns_source_max_packet_bytes(),
            max_preview_bytes: default_dns_source_max_preview_bytes(),
        }
    }
}

impl DnsSourceConfig {
    pub const MIN_PACKET_BYTES_LIMIT: usize = 12;
    pub const MAX_PACKET_BYTES_LIMIT: usize = 512;
    pub const MAX_PREVIEW_BYTES_LIMIT: usize = 160;

    pub(super) fn validate(&self) -> ConfigResult<()> {
        if !(Self::MIN_PACKET_BYTES_LIMIT..=Self::MAX_PACKET_BYTES_LIMIT)
            .contains(&self.max_packet_bytes)
        {
            return Err(ConfigError::invalid_value(
                "dns_source.max_packet_bytes",
                format!(
                    "dns_source.max_packet_bytes must be between {} and {}",
                    Self::MIN_PACKET_BYTES_LIMIT,
                    Self::MAX_PACKET_BYTES_LIMIT
                ),
            ));
        }

        if !(1..=Self::MAX_PREVIEW_BYTES_LIMIT).contains(&self.max_preview_bytes) {
            return Err(ConfigError::invalid_value(
                "dns_source.max_preview_bytes",
                format!(
                    "dns_source.max_preview_bytes must be between 1 and {}",
                    Self::MAX_PREVIEW_BYTES_LIMIT
                ),
            ));
        }

        Ok(())
    }
}

fn default_dns_source_max_packet_bytes() -> usize {
    512
}

fn default_dns_source_max_preview_bytes() -> usize {
    160
}
