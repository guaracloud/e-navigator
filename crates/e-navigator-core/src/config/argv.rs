use serde::{Deserialize, Serialize};

use super::{ConfigResult, bounds::validate_inclusive};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
        validate_inclusive(
            "argv_capture.max_args",
            self.max_args,
            1,
            Self::MAX_ARGS_LIMIT,
        )?;
        validate_inclusive(
            "argv_capture.max_bytes",
            self.max_bytes,
            1,
            Self::MAX_BYTES_LIMIT,
        )?;
        Ok(())
    }
}

fn default_argv_capture_enabled() -> bool {
    false
}

fn default_argv_capture_max_args() -> usize {
    ArgvCaptureConfig::MAX_ARGS_LIMIT
}

fn default_argv_capture_max_bytes() -> usize {
    ArgvCaptureConfig::MAX_BYTES_LIMIT
}
