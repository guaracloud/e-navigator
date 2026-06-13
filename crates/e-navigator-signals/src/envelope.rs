use e_navigator_core::Signal;
use serde::{Deserialize, Serialize};

use crate::ExecEvent;

pub const SIGNAL_SCHEMA_VERSION: u16 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignalKind {
    Exec,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SignalPayload {
    Exec(ExecEvent),
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

    pub fn signal_kind(&self) -> SignalKind {
        self.kind
    }
}

impl Signal for SignalEnvelope {
    fn kind(&self) -> &'static str {
        match self.kind {
            SignalKind::Exec => "exec",
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
}
