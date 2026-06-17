use serde::{Deserialize, Serialize};

use super::{ConfigError, ConfigResult};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArgvCaptureConfig {
    #[serde(default = "default_argv_capture_enabled")]
    pub enabled: bool,
    #[serde(default = "default_argv_capture_max_args")]
    pub max_args: usize,
    #[serde(default = "default_argv_capture_max_bytes")]
    pub max_bytes: usize,
}

impl Default for ArgvCaptureConfig {
    fn default() -> Self {
        Self {
            enabled: default_argv_capture_enabled(),
            max_args: default_argv_capture_max_args(),
            max_bytes: default_argv_capture_max_bytes(),
        }
    }
}

impl ArgvCaptureConfig {
    pub const MAX_ARGS_LIMIT: usize = 8;
    pub const MAX_BYTES_LIMIT: usize = 512;

    pub(super) fn validate(&self) -> ConfigResult<()> {
        if !(1..=Self::MAX_ARGS_LIMIT).contains(&self.max_args) {
            return Err(ConfigError::invalid_value(
                "argv_capture.max_args",
                format!(
                    "argv_capture.max_args must be between 1 and {}",
                    Self::MAX_ARGS_LIMIT
                ),
            ));
        }

        if !(1..=Self::MAX_BYTES_LIMIT).contains(&self.max_bytes) {
            return Err(ConfigError::invalid_value(
                "argv_capture.max_bytes",
                format!(
                    "argv_capture.max_bytes must be between 1 and {}",
                    Self::MAX_BYTES_LIMIT
                ),
            ));
        }

        Ok(())
    }
}

fn default_argv_capture_enabled() -> bool {
    true
}

fn default_argv_capture_max_args() -> usize {
    ArgvCaptureConfig::MAX_ARGS_LIMIT
}

fn default_argv_capture_max_bytes() -> usize {
    ArgvCaptureConfig::MAX_BYTES_LIMIT
}
