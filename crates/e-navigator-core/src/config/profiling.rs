use serde::{Deserialize, Serialize};

use super::{ConfigResult, bounds::validate_inclusive};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfilingConfig {
    #[serde(default = "default_profiling_max_windows")]
    pub max_windows: usize,
    #[serde(default = "default_profiling_max_seen_samples")]
    pub max_seen_samples: usize,
    #[serde(default = "default_profiling_max_warnings")]
    pub max_warnings: usize,
    #[serde(default = "default_profiling_window_nanos")]
    pub window_nanos: u64,
}

impl Default for ProfilingConfig {
    fn default() -> Self {
        Self {
            max_windows: default_profiling_max_windows(),
            max_seen_samples: default_profiling_max_seen_samples(),
            max_warnings: default_profiling_max_warnings(),
            window_nanos: default_profiling_window_nanos(),
        }
    }
}

impl ProfilingConfig {
    pub const MAX_WINDOWS_LIMIT: usize = 65_536;
    pub const MAX_SEEN_SAMPLES_LIMIT: usize = 131_072;
    pub const MAX_WARNINGS_LIMIT: usize = 16_384;
    pub const MAX_WINDOW_NANOS_LIMIT: u64 = 86_400_000_000_000;

    pub(super) fn validate(&self) -> ConfigResult<()> {
        validate_inclusive(
            "profiling.max_windows",
            self.max_windows,
            1,
            Self::MAX_WINDOWS_LIMIT,
        )?;
        validate_inclusive(
            "profiling.max_seen_samples",
            self.max_seen_samples,
            1,
            Self::MAX_SEEN_SAMPLES_LIMIT,
        )?;
        validate_inclusive(
            "profiling.max_warnings",
            self.max_warnings,
            1,
            Self::MAX_WARNINGS_LIMIT,
        )?;
        validate_inclusive(
            "profiling.window_nanos",
            self.window_nanos,
            1,
            Self::MAX_WINDOW_NANOS_LIMIT,
        )?;
        Ok(())
    }
}

fn default_profiling_max_windows() -> usize {
    4096
}

fn default_profiling_max_seen_samples() -> usize {
    8192
}

fn default_profiling_max_warnings() -> usize {
    1024
}

fn default_profiling_window_nanos() -> u64 {
    30_000_000_000
}
