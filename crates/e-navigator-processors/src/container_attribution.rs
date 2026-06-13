use async_trait::async_trait;
use e_navigator_core::{CoreResult, ModuleKind, ModuleMetadata, Processor};
use e_navigator_signals::SignalEnvelope;

#[derive(Debug, Default)]
pub struct ContainerAttributionProcessor;

#[async_trait]
impl Processor<SignalEnvelope> for ContainerAttributionProcessor {
    fn metadata(&self) -> ModuleMetadata {
        ModuleMetadata::new("processor.container_attribution", ModuleKind::Processor)
    }

    async fn process(&self, signal: SignalEnvelope) -> CoreResult<Option<SignalEnvelope>> {
        Ok(Some(signal))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use e_navigator_signals::{ContainerContext, ExecEvent, KubernetesContext};

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

    #[tokio::test]
    async fn processor_preserves_existing_attribution_without_cgroup_id() {
        let processor = ContainerAttributionProcessor;
        let signal = SignalEnvelope::exec(
            "source.test",
            Some("node-a".to_string()),
            ExecEvent {
                pid: 7,
                ppid: Some(1),
                uid: Some(1000),
                command: "sh".to_string(),
                executable: Some("/bin/sh".to_string()),
                arguments: vec!["sh".to_string()],
                cgroup_id: None,
                container: Some(ContainerContext {
                    container_id: "container-a".to_string(),
                    runtime: Some("containerd".to_string()),
                }),
                kubernetes: Some(KubernetesContext {
                    namespace: "default".to_string(),
                    pod_name: "pod-a".to_string(),
                    container_name: Some("app".to_string()),
                    node_name: Some("node-a".to_string()),
                }),
                timestamp_unix_nanos: 99,
            },
        );

        let processed = processor
            .process(signal.clone())
            .await
            .expect("processor succeeds")
            .expect("signal remains");

        assert_eq!(processed, signal);
    }
}
