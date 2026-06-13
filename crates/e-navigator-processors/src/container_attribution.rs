use async_trait::async_trait;
use e_navigator_core::{CoreResult, ModuleKind, ModuleMetadata, Processor};
use e_navigator_signals::{SignalEnvelope, SignalPayload};

#[derive(Debug, Default)]
pub struct ContainerAttributionProcessor;

#[async_trait]
impl Processor<SignalEnvelope> for ContainerAttributionProcessor {
    fn metadata(&self) -> ModuleMetadata {
        ModuleMetadata::new("processor.container_attribution", ModuleKind::Processor)
    }

    async fn process(&self, mut signal: SignalEnvelope) -> CoreResult<Option<SignalEnvelope>> {
        match &mut signal.payload {
            SignalPayload::Exec(event) => {
                if event.cgroup_id.is_none() {
                    event.container = None;
                    event.kubernetes = None;
                }
            }
        }

        Ok(Some(signal))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use e_navigator_signals::ExecEvent;

    #[tokio::test]
    async fn processor_preserves_exec_event() {
        let processor = ContainerAttributionProcessor;
        let signal = SignalEnvelope::exec(
            "source.test",
            None,
            ExecEvent {
                pid: 7,
                ppid: Some(1),
                uid: Some(1000),
                command: "sh".to_string(),
                executable: Some("/bin/sh".to_string()),
                arguments: vec!["sh".to_string()],
                cgroup_id: None,
                timestamp_unix_nanos: 99,
                container: None,
                kubernetes: None,
            },
        );

        let processed = processor
            .process(signal)
            .await
            .expect("processor succeeds")
            .expect("signal remains");

        assert!(matches!(
            processed.payload,
            e_navigator_signals::SignalPayload::Exec(_)
        ));
    }
}
