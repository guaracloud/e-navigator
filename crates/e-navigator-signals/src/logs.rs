use crate::sanitize::truncate_utf8_in_place;
use serde::{Deserialize, Serialize};

/// Container instance is (pod UID, container name, restart count), not pod name.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApplicationLogObservation {
    pub namespace: String,
    pub pod_name: String,
    pub pod_uid: String,
    pub container_name: String,
    pub restart_count: u32,
    pub stream: LogStream,
    /// Validated RFC3339 UTC event time, preserving CRI precision.
    pub timestamp: String,
    pub observed_at_unix_nanos: u64,
    pub body: Option<String>,
    pub body_bytes: u64,
    pub truncated: bool,
    pub incomplete: bool,
    pub invalid_utf8: bool,
}

impl std::fmt::Debug for ApplicationLogObservation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApplicationLogObservation")
            .field("pod_uid", &self.pod_uid)
            .field("container_name", &self.container_name)
            .field("restart_count", &self.restart_count)
            .field("stream", &self.stream)
            .field("body_bytes", &self.body_bytes)
            .field("truncated", &self.truncated)
            .field("incomplete", &self.incomplete)
            .field("invalid_utf8", &self.invalid_utf8)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogStream {
    Stdout,
    Stderr,
}

/// Fixed reasons never contain file content or unrestricted host paths.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogCollectionOutcome {
    UnsupportedFormat,
    RecordTooLarge,
    FileReset,
    DiscoveryLimit,
    FileLimit,
    UnsafePath,
    RetentionExpired,
    CheckpointRejected,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogCollectionWarning {
    pub outcome: LogCollectionOutcome,
    pub count: u64,
}

pub(crate) fn sanitize_log(event: &mut ApplicationLogObservation) {
    for value in [
        &mut event.namespace,
        &mut event.pod_name,
        &mut event.pod_uid,
        &mut event.container_name,
    ] {
        truncate_utf8_in_place(value, 256);
    }
    truncate_utf8_in_place(&mut event.timestamp, 64);
    if let Some(body) = &mut event.body {
        if body.len() > 65_536 {
            event.truncated = true;
        }
        truncate_utf8_in_place(body, 65_536);
    }
}
