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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub processing: Option<Box<LogProcessing>>,
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
    if let Some(processed) = &mut event.processing {
        for value in [
            &mut processed.severity_text,
            &mut processed.workload_name,
            &mut processed.workload_kind,
        ]
        .into_iter()
        .flatten()
        {
            truncate_utf8_in_place(value, 256);
        }
        while processed.attributes.len() > 32 {
            processed.attributes.pop_last();
        }
        processed
            .attributes
            .retain(|k, v| !k.is_empty() && k.len() <= 64 && v.len() <= 256);
    }
    if let Some(body) = &mut event.body {
        if body.len() > 65_536 {
            event.truncated = true;
        }
        truncate_utf8_in_place(body, 65_536);
    }
}

/// Only a payload processed under the configured privacy policy is exportable.
/// Resource identity always comes from CRI, never from application fields.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogProcessing {
    pub outcome: LogProcessingOutcome,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workload_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workload_kind: Option<String>,
    pub severity_text: Option<String>,
    pub trace_id: Option<String>,
    pub span_id: Option<String>,
    pub attributes: std::collections::BTreeMap<String, String>,
}
impl std::fmt::Debug for LogProcessing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LogProcessing")
            .field("outcome", &self.outcome)
            .finish_non_exhaustive()
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogProcessingOutcome {
    Json,
    PlainText,
    MalformedJson,
    BodyOmitted,
    BudgetRejected,
}
