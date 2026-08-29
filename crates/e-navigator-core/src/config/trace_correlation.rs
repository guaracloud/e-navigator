use serde::{Deserialize, Serialize};

use super::{ConfigResult, bounds::validate_inclusive};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
        validate_inclusive(
            "trace_correlation.max_service_paths",
            self.max_service_paths,
            1,
            Self::MAX_SERVICE_PATHS_LIMIT,
        )?;
        validate_inclusive(
            "trace_correlation.max_seen_interactions",
            self.max_seen_interactions,
            1,
            Self::MAX_SEEN_INTERACTIONS_LIMIT,
        )?;
        validate_inclusive(
            "trace_correlation.max_warnings",
            self.max_warnings,
            1,
            Self::MAX_WARNINGS_LIMIT,
        )?;
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
