use serde::{Deserialize, Serialize};

use super::{ConfigError, ConfigResult};

/// Kernel-to-userspace event transport requested for Aya sources.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EbpfEventTransport {
    /// Prefer the BPF ring buffer when the kernel probe succeeds, otherwise
    /// use the legacy perf-event buffer.
    #[default]
    Auto,
    /// Require BPF ring-buffer support and fail source startup when it is not
    /// available or cannot be probed.
    RingBuffer,
    /// Require the legacy perf-event transport. This remains available for
    /// older kernels and controlled A/B measurements.
    PerfBuffer,
}

/// Shared eBPF loader and event-transport limits.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EbpfConfig {
    #[serde(default)]
    pub event_transport: EbpfEventTransport,
    #[serde(default = "default_ring_buffer_bytes")]
    pub ring_buffer_bytes: u32,
}

impl Default for EbpfConfig {
    fn default() -> Self {
        Self {
            event_transport: EbpfEventTransport::Auto,
            ring_buffer_bytes: default_ring_buffer_bytes(),
        }
    }
}

impl EbpfConfig {
    pub const MIN_RING_BUFFER_BYTES: u32 = 4 * 1024;
    pub const MAX_RING_BUFFER_BYTES: u32 = 16 * 1024 * 1024;

    pub fn validate(&self) -> ConfigResult<()> {
        if self.ring_buffer_bytes < Self::MIN_RING_BUFFER_BYTES {
            return Err(ConfigError::invalid_value(
                "ebpf.ring_buffer_bytes",
                format!(
                    "ebpf.ring_buffer_bytes must be greater than or equal to {}",
                    Self::MIN_RING_BUFFER_BYTES
                ),
            ));
        }
        if self.ring_buffer_bytes > Self::MAX_RING_BUFFER_BYTES {
            return Err(ConfigError::invalid_value(
                "ebpf.ring_buffer_bytes",
                format!(
                    "ebpf.ring_buffer_bytes must be less than or equal to {}",
                    Self::MAX_RING_BUFFER_BYTES
                ),
            ));
        }
        if !self.ring_buffer_bytes.is_power_of_two() {
            return Err(ConfigError::invalid_value(
                "ebpf.ring_buffer_bytes",
                "ebpf.ring_buffer_bytes must be a power of two",
            ));
        }

        Ok(())
    }
}

const fn default_ring_buffer_bytes() -> u32 {
    256 * 1024
}
