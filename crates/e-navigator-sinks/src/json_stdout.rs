use async_trait::async_trait;
use e_navigator_core::{CoreError, CoreResult, ModuleKind, ModuleMetadata, Sink};
use e_navigator_signals::{SignalEnvelope, SignalPayload};
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
        let mut stdout = io::stdout();
        stdout
            .write_all(&line)
            .await
            .map_err(|err| module_error(err.to_string()))?;
        stdout
            .flush()
            .await
            .map_err(|err| module_error(err.to_string()))
    }
}

fn serialize_signal_line(signal: &SignalEnvelope) -> CoreResult<Vec<u8>> {
    let sanitized = sanitize_signal_for_stdout(signal);
    let mut line = serde_json::to_vec(&sanitized).map_err(|err| module_error(err.to_string()))?;
    line.push(b'\n');
    Ok(line)
}

fn sanitize_signal_for_stdout(signal: &SignalEnvelope) -> SignalEnvelope {
    let mut sanitized = signal.clone();
    match &mut sanitized.payload {
        SignalPayload::Exec(event) => redact_argv(&mut event.arguments),
        SignalPayload::RuntimeSecurityFinding(finding) => {
            redact_argv(&mut finding.matched_process.arguments);
        }
        _ => {}
    }
    sanitized
}

fn redact_argv(arguments: &mut [String]) {
    let mut redact_next = false;
    for argument in arguments {
        if redact_next {
            *argument = "<redacted>".to_string();
            redact_next = false;
            continue;
        }

        let (redacted, consumes_next) = redact_argument(argument);
        if let Some(redacted) = redacted {
            *argument = redacted;
        }
        redact_next = consumes_next;
    }
}

fn redact_argument(argument: &str) -> (Option<String>, bool) {
    let lower = argument.to_ascii_lowercase();
    if lower.starts_with("bearer ") {
        return (Some("<redacted>".to_string()), false);
    }

    let Some(key_range) = sensitive_key_range(&lower) else {
        return (None, false);
    };
    let suffix = &argument[key_range.end..];
    let separator = suffix
        .char_indices()
        .find(|(_, character)| matches!(character, '=' | ':' | ' '))
        .map(|(index, character)| (key_range.end + index, character));

    match separator {
        Some((index, separator)) if argument[index + separator.len_utf8()..].is_empty() => {
            (None, true)
        }
        Some((index, separator)) => {
            let prefix_end = index + separator.len_utf8();
            (
                Some(format!("{}<redacted>", &argument[..prefix_end])),
                false,
            )
        }
        None => (None, true),
    }
}

fn sensitive_key_range(lower: &str) -> Option<std::ops::Range<usize>> {
    [
        "authorization",
        "auth-token",
        "api-token",
        "api_key",
        "api-key",
        "apikey",
        "password",
        "passwd",
        "secret",
        "credential",
        "token",
    ]
    .into_iter()
    .filter_map(|key| lower.find(key).map(|start| start..start + key.len()))
    .next()
}

fn module_error(message: String) -> CoreError {
    CoreError::ModuleFailed {
        module: "sink.json_stdout".to_string(),
        message,
    }
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
        let value: serde_json::Value =
            serde_json::from_slice(&line[..line.len() - 1]).expect("line is valid JSON");

        assert!(line.ends_with(b"\n"));
        assert_eq!(line.iter().filter(|byte| **byte == b'\n').count(), 1);
        assert_eq!(value["schema_version"], 1);
        assert_eq!(value["kind"], "exec");
        assert_eq!(value["payload"]["command"], "true");
    }

    #[test]
    fn redacts_secret_like_exec_arguments_in_json_stdout() {
        let signal = SignalEnvelope::exec(
            "source.test",
            None,
            ExecEvent {
                pid: 1,
                ppid: None,
                uid: Some(1000),
                command: "curl".to_string(),
                executable: Some("/usr/bin/curl".to_string()),
                arguments: vec![
                    "curl".to_string(),
                    "--token=abc123".to_string(),
                    "--password".to_string(),
                    "plain-secret".to_string(),
                    "--api-key".to_string(),
                    "key-123".to_string(),
                    "Authorization: Bearer abc.def".to_string(),
                ],
                cgroup_id: None,
                timestamp_unix_nanos: 1,
                container: None,
                kubernetes: None,
            },
        );

        let line = serialize_signal_line(&signal).expect("signal serializes");
        let value: serde_json::Value =
            serde_json::from_slice(&line[..line.len() - 1]).expect("line is valid JSON");

        assert_eq!(
            value["payload"]["arguments"],
            serde_json::json!([
                "curl",
                "--token=<redacted>",
                "--password",
                "<redacted>",
                "--api-key",
                "<redacted>",
                "Authorization:<redacted>"
            ])
        );
    }
}
