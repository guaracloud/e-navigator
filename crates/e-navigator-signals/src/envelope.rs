use e_navigator_core::Signal;
use serde::{Deserialize, Serialize};

use crate::ExecEvent;

pub const SIGNAL_SCHEMA_VERSION: u16 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "payload", rename_all = "snake_case")]
pub enum SignalPayload {
    Exec(ExecEvent),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignalEnvelope {
    pub schema_version: u16,
    pub source: String,
    pub host: Option<String>,
    pub payload: SignalPayload,
}

impl SignalEnvelope {
    pub fn exec(source: impl Into<String>, host: Option<String>, event: ExecEvent) -> Self {
        Self {
            schema_version: SIGNAL_SCHEMA_VERSION,
            source: source.into(),
            host,
            payload: SignalPayload::Exec(event),
        }
    }
}

impl Signal for SignalEnvelope {
    fn kind(&self) -> &'static str {
        match self.payload {
            SignalPayload::Exec(_) => "exec",
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

        let json = serde_json::to_string(&signal).expect("signal serializes");
        assert!(json.contains("\"schema_version\":1"));
        assert!(json.contains("\"kind\":\"exec\""));
        assert!(json.contains("\"command\":\"bash\""));
    }
}
