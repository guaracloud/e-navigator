use serde::{Deserialize, Serialize};

use super::{ConfigError, ConfigResult};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceCorrelationConfig {
    #[serde(default = "default_trace_correlation_max_service_paths")]
    pub max_service_paths: usize,
    #[serde(default = "default_trace_correlation_max_seen_interactions")]
    pub max_seen_interactions: usize,
    #[serde(default = "default_trace_correlation_max_warnings")]
    pub max_warnings: usize,
}

impl Default for TraceCorrelationConfig {
    fn default() -> Self {
        Self {
            max_service_paths: default_trace_correlation_max_service_paths(),
            max_seen_interactions: default_trace_correlation_max_seen_interactions(),
            max_warnings: default_trace_correlation_max_warnings(),
        }
    }
}

impl TraceCorrelationConfig {
    pub const MAX_SERVICE_PATHS_LIMIT: usize = 65_536;
    pub const MAX_SEEN_INTERACTIONS_LIMIT: usize = 131_072;
    pub const MAX_WARNINGS_LIMIT: usize = 16_384;

    pub(super) fn validate(&self) -> ConfigResult<()> {
        if !(1..=Self::MAX_SERVICE_PATHS_LIMIT).contains(&self.max_service_paths) {
            return Err(ConfigError::invalid_value(
                "trace_correlation.max_service_paths",
                format!(
                    "trace_correlation.max_service_paths must be between 1 and {}",
                    Self::MAX_SERVICE_PATHS_LIMIT
                ),
            ));
        }
        if !(1..=Self::MAX_SEEN_INTERACTIONS_LIMIT).contains(&self.max_seen_interactions) {
            return Err(ConfigError::invalid_value(
                "trace_correlation.max_seen_interactions",
                format!(
                    "trace_correlation.max_seen_interactions must be between 1 and {}",
                    Self::MAX_SEEN_INTERACTIONS_LIMIT
                ),
            ));
        }
        if !(1..=Self::MAX_WARNINGS_LIMIT).contains(&self.max_warnings) {
            return Err(ConfigError::invalid_value(
                "trace_correlation.max_warnings",
                format!(
                    "trace_correlation.max_warnings must be between 1 and {}",
                    Self::MAX_WARNINGS_LIMIT
                ),
            ));
        }
        Ok(())
    }
}

fn default_trace_correlation_max_service_paths() -> usize {
    4096
}

fn default_trace_correlation_max_seen_interactions() -> usize {
    8192
}

fn default_trace_correlation_max_warnings() -> usize {
    1024
}
