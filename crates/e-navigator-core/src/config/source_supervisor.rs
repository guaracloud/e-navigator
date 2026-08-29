use serde::{Deserialize, Serialize};

use super::{ConfigResult, bounds::validate_nonzero_bounded};

/// Policy applied when one registered source returns an error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceFailurePolicy {
    /// Abort every remaining source and return the failure immediately.
    FailFast,
    /// Keep healthy sources running and return the first isolated failure only
    /// after the remaining sources stop.
    Isolate,
}

/// Process-wide lifecycle policy for statically registered sources.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceSupervisorConfig {
    #[serde(default = "default_source_failure_policy")]
    pub failure_policy: SourceFailurePolicy,
    #[serde(default = "default_shutdown_timeout_millis")]
    pub shutdown_timeout_millis: u64,
}

impl Default for SourceSupervisorConfig {
    fn default() -> Self {
        Self {
            failure_policy: default_source_failure_policy(),
            shutdown_timeout_millis: default_shutdown_timeout_millis(),
        }
    }
}

impl SourceSupervisorConfig {
    pub const MAX_SHUTDOWN_TIMEOUT_MILLIS: u64 = 300_000;

    pub(super) fn validate(&self) -> ConfigResult<()> {
        validate_nonzero_bounded(
            "source_supervisor.shutdown_timeout_millis",
            self.shutdown_timeout_millis,
            Self::MAX_SHUTDOWN_TIMEOUT_MILLIS,
        )?;
        Ok(())
    }
}

fn default_source_failure_policy() -> SourceFailurePolicy {
    SourceFailurePolicy::FailFast
}

fn default_shutdown_timeout_millis() -> u64 {
    10_000
}
