use e_navigator_core::{CoreError, CoreResult, RuntimeConfig};
use e_navigator_signals::SignalEnvelope;
use tokio::sync::mpsc;
use tracing::debug;

use crate::ModuleRegistry;

pub struct Runner {
    config: RuntimeConfig,
    registry: ModuleRegistry,
}

impl Runner {
    pub fn new(config: RuntimeConfig, registry: ModuleRegistry) -> CoreResult<Self> {
        config.validate().map_err(CoreError::InvalidConfig)?;

        if registry.module_count() == 0 {
            return Err(CoreError::InvalidConfig(
                "at least one registered module is required".to_string(),
            ));
        }

        if !registry.has_source_and_sink() {
            return Err(CoreError::InvalidConfig(
                "at least one source and one sink are required".to_string(),
            ));
        }

        Ok(Self { config, registry })
    }

    pub async fn run(mut self) -> CoreResult<()> {
        let (tx, mut rx) = mpsc::channel::<SignalEnvelope>(self.config.queue_capacity);
        let (source_result_tx, mut source_result_rx) =
            mpsc::channel::<CoreResult<()>>(self.registry.sources.len());

        for source in self.registry.sources.drain(..) {
            let source_tx = tx.clone();
            let result_tx = source_result_tx.clone();
            let name = source.metadata().name.to_string();
            tokio::spawn(async move {
                let result = source
                    .run(source_tx)
                    .await
                    .map_err(|err| CoreError::ModuleFailed {
                        module: name,
                        message: err.to_string(),
                    });
                let _ = result_tx.send(result).await;
            });
        }
        drop(tx);
        drop(source_result_tx);
        let mut source_results_open = true;

        loop {
            tokio::select! {
                source_result = source_result_rx.recv(), if source_results_open => {
                    match source_result {
                        Some(Ok(())) => debug!("source exited cleanly"),
                        Some(Err(err)) => return Err(err),
                        None => source_results_open = false,
                    }
                }
                signal = rx.recv() => {
                    match signal {
                        Some(signal) => self.handle_signal(signal).await?,
                        None => return Ok(()),
                    }
                }
            }
        }
    }

    async fn handle_signal(&self, signal: SignalEnvelope) -> CoreResult<()> {
        let mut current = Some(signal);

        for processor in &self.registry.processors {
            let signal = current.take().ok_or(CoreError::PipelineClosed)?;
            match processor.process(signal).await? {
                Some(processed) => current = Some(processed),
                None => {
                    debug!("signal dropped by processor");
                    return Ok(());
                }
            }
        }

        let signal = current.ok_or(CoreError::PipelineClosed)?;

        for generator in &self.registry.generators {
            let (derived_tx, mut derived_rx) = mpsc::channel(16);
            generator.observe(&signal, &derived_tx).await?;
            drop(derived_tx);
            while let Some(derived) = derived_rx.recv().await {
                for sink in &self.registry.sinks {
                    sink.write(&derived).await?;
                }
            }
        }

        for sink in &self.registry.sinks {
            sink.write(&signal).await?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;
    use e_navigator_core::{CoreResult, ModuleKind, ModuleMetadata, Sink, Source};
    use e_navigator_signals::{ExecEvent, SignalEnvelope};
    use tokio::sync::{Mutex, mpsc};

    use super::*;
    use std::sync::Arc;

    struct OneSignalSource;

    #[async_trait]
    impl Source<SignalEnvelope> for OneSignalSource {
        fn metadata(&self) -> ModuleMetadata {
            ModuleMetadata::new("source.test", ModuleKind::Source)
        }

        async fn run(self: Box<Self>, tx: mpsc::Sender<SignalEnvelope>) -> CoreResult<()> {
            let signal = SignalEnvelope::exec(
                "source.test",
                None,
                ExecEvent {
                    pid: 1,
                    ppid: None,
                    uid: None,
                    command: "true".to_string(),
                    executable: Some("/usr/bin/true".to_string()),
                    arguments: vec![],
                    cgroup_id: None,
                    timestamp_unix_nanos: 1,
                    container: None,
                    kubernetes: None,
                },
            );
            tx.send(signal).await.map_err(|_| CoreError::PipelineClosed)
        }
    }

    struct MemorySink {
        seen: Arc<Mutex<Vec<SignalEnvelope>>>,
    }

    #[async_trait]
    impl Sink<SignalEnvelope> for MemorySink {
        fn metadata(&self) -> ModuleMetadata {
            ModuleMetadata::new("sink.memory", ModuleKind::Sink)
        }

        async fn write(&self, signal: &SignalEnvelope) -> CoreResult<()> {
            self.seen.lock().await.push(signal.clone());
            Ok(())
        }
    }

    #[tokio::test]
    async fn runner_routes_source_signal_to_sink() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let registry = ModuleRegistry::new()
            .with_source(Box::new(OneSignalSource))
            .with_sink(Box::new(MemorySink { seen: seen.clone() }));
        let runner = Runner::new(RuntimeConfig::default(), registry).expect("runner builds");

        runner
            .run()
            .await
            .expect("runner exits after source closes");

        assert_eq!(seen.lock().await.len(), 1);
    }
}
