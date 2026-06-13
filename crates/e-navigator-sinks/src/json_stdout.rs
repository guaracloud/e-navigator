use async_trait::async_trait;
use e_navigator_core::{CoreError, CoreResult, ModuleKind, ModuleMetadata, Sink};
use e_navigator_signals::SignalEnvelope;
use tokio::io::{self, AsyncWriteExt};

#[derive(Debug, Default)]
pub struct JsonStdoutSink;

#[async_trait]
impl Sink<SignalEnvelope> for JsonStdoutSink {
    fn metadata(&self) -> ModuleMetadata {
        ModuleMetadata::new("sink.json_stdout", ModuleKind::Sink)
    }

    async fn write(&self, signal: &SignalEnvelope) -> CoreResult<()> {
        let line = serialize_signal_line(signal)?;
        io::stdout()
            .write_all(&line)
            .await
            .map_err(|err| CoreError::ModuleFailed {
                module: "sink.json_stdout".to_string(),
                message: err.to_string(),
            })
    }
}

fn serialize_signal_line(signal: &SignalEnvelope) -> CoreResult<Vec<u8>> {
    let mut line = serde_json::to_vec(signal).map_err(|err| CoreError::ModuleFailed {
        module: "sink.json_stdout".to_string(),
        message: err.to_string(),
    })?;
    line.push(b'\n');
    Ok(line)
}

#[cfg(test)]
mod tests {
    use e_navigator_signals::ExecEvent;

    use super::*;

    #[test]
    fn serializes_signal_as_newline_delimited_json() {
        let signal = SignalEnvelope::exec(
            "source.test",
            None,
            ExecEvent {
                pid: 1,
                ppid: None,
                uid: Some(1000),
                command: "true".to_string(),
                executable: None,
                arguments: vec![],
                cgroup_id: None,
                timestamp_unix_nanos: 1,
                container: None,
                kubernetes: None,
            },
        );

        let line = serialize_signal_line(&signal).expect("signal serializes");

        assert!(line.ends_with(b"\n"));
        assert_eq!(line.iter().filter(|byte| **byte == b'\n').count(), 1);
    }
}
