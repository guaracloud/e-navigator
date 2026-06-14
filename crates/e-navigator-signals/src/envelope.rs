use e_navigator_core::Signal;
use serde::{Deserialize, Serialize};

use crate::{ExecEvent, ProcessExitEvent, ProcessLifecycleDurationEvent};

pub const SIGNAL_SCHEMA_VERSION: u16 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignalKind {
    Exec,
    ProcessExit,
    ProcessLifecycleDuration,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SignalPayload {
    Exec(ExecEvent),
    ProcessExit(ProcessExitEvent),
    ProcessLifecycleDuration(ProcessLifecycleDurationEvent),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignalEnvelope {
    pub schema_version: u16,
    kind: SignalKind,
    pub source: String,
    pub host: Option<String>,
    pub payload: SignalPayload,
}

impl SignalEnvelope {
    pub fn exec(source: impl Into<String>, host: Option<String>, event: ExecEvent) -> Self {
        Self {
            schema_version: SIGNAL_SCHEMA_VERSION,
            kind: SignalKind::Exec,
            source: source.into(),
            host,
            payload: SignalPayload::Exec(event),
        }
    }

    pub fn process_exit(
        source: impl Into<String>,
        host: Option<String>,
        event: ProcessExitEvent,
    ) -> Self {
        Self {
            schema_version: SIGNAL_SCHEMA_VERSION,
            kind: SignalKind::ProcessExit,
            source: source.into(),
            host,
            payload: SignalPayload::ProcessExit(event),
        }
    }

    pub fn process_lifecycle_duration(
        source: impl Into<String>,
        host: Option<String>,
        event: ProcessLifecycleDurationEvent,
    ) -> Self {
        Self {
            schema_version: SIGNAL_SCHEMA_VERSION,
            kind: SignalKind::ProcessLifecycleDuration,
            source: source.into(),
            host,
            payload: SignalPayload::ProcessLifecycleDuration(event),
        }
    }

    pub fn signal_kind(&self) -> SignalKind {
        self.kind
    }
}

impl Signal for SignalEnvelope {
    fn kind(&self) -> &'static str {
        match self.kind {
            SignalKind::Exec => "exec",
            SignalKind::ProcessExit => "process_exit",
            SignalKind::ProcessLifecycleDuration => "process_lifecycle_duration",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serializes_exec_signal_with_version() {
        let signal = SignalEnvelope::exec(
            "source.test",
            Some("node-a".to_string()),
            ExecEvent {
                pid: 42,
                ppid: Some(1),
                uid: Some(1000),
                command: "bash".to_string(),
                executable: Some("/usr/bin/bash".to_string()),
                arguments: vec!["bash".to_string()],
                cgroup_id: Some(7),
                timestamp_unix_nanos: 123,
                container: None,
                kubernetes: None,
            },
        );

        let json = serde_json::to_value(&signal).expect("signal serializes");

        assert_eq!(json["schema_version"], 1);
        assert_eq!(json["kind"], "exec");
        assert_eq!(json["source"], "source.test");
        assert_eq!(json["host"], "node-a");
        assert_eq!(json["payload"]["pid"], 42);
        assert_eq!(json["payload"]["uid"], 1000);
        assert_eq!(json["payload"]["command"], "bash");
        assert_eq!(json["payload"]["executable"], "/usr/bin/bash");
        assert_eq!(json["payload"]["timestamp_unix_nanos"], 123);
        assert!(json["payload"].get("kind").is_none());
    }

    #[test]
    fn serializes_process_exit_signal_with_version() {
        let signal = SignalEnvelope::process_exit(
            "source.test",
            Some("node-a".to_string()),
            ProcessExitEvent {
                pid: 42,
                ppid: Some(1),
                uid: Some(1000),
                command: "bash".to_string(),
                exit_code: Some(0),
                runtime_nanos: Some(55),
                timestamp_unix_nanos: 200,
                container: None,
                kubernetes: None,
            },
        );

        let json = serde_json::to_value(&signal).expect("signal serializes");

        assert_eq!(json["schema_version"], 1);
        assert_eq!(json["kind"], "process_exit");
        assert_eq!(json["source"], "source.test");
        assert_eq!(json["payload"]["pid"], 42);
        assert_eq!(json["payload"]["runtime_nanos"], 55);
    }

    #[test]
    fn serializes_process_lifecycle_duration_signal_with_version() {
        let signal = SignalEnvelope::process_lifecycle_duration(
            "generator.test",
            Some("node-a".to_string()),
            ProcessLifecycleDurationEvent {
                pid: 42,
                command: "bash".to_string(),
                started_at_unix_nanos: 100,
                exited_at_unix_nanos: 250,
                duration_nanos: 150,
                container: None,
                kubernetes: None,
            },
        );

        let json = serde_json::to_value(&signal).expect("signal serializes");

        assert_eq!(json["schema_version"], 1);
        assert_eq!(json["kind"], "process_lifecycle_duration");
        assert_eq!(json["payload"]["pid"], 42);
        assert_eq!(json["payload"]["duration_nanos"], 150);
    }
}
