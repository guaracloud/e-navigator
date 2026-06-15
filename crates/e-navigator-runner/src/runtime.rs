use e_navigator_core::{CoreError, CoreResult, ModuleMetadata, RuntimeConfig};
use e_navigator_signals::SignalEnvelope;
use std::collections::VecDeque;
use tokio::{sync::mpsc, task::JoinHandle};
use tracing::debug;

use crate::ModuleRegistry;

const MAX_DERIVED_SIGNALS_PER_GENERATOR: usize = 64;

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

        let mut source_handles = Vec::new();

        for source in self.registry.sources.drain(..) {
            let source_tx = tx.clone();
            let result_tx = source_result_tx.clone();
            let metadata = source.metadata();
            source_handles.push(tokio::spawn(async move {
                let result = source
                    .run(source_tx)
                    .await
                    .map_err(|err| with_module_context(metadata, err));
                let _ = result_tx.send(result).await;
            }));
        }
        drop(tx);
        drop(source_result_tx);
        let mut source_results_open = true;

        loop {
            tokio::select! {
                source_result = source_result_rx.recv(), if source_results_open => {
                    match source_result {
                        Some(Ok(())) => debug!("source exited cleanly"),
                        Some(Err(err)) => {
                            abort_sources(&source_handles);
                            return Err(err);
                        }
                        None => source_results_open = false,
                    }
                }
                signal = rx.recv() => {
                    match signal {
                        Some(signal) => {
                            if let Err(err) = self.handle_signal(signal).await {
                                abort_sources(&source_handles);
                                return Err(err);
                            }
                        }
                        None => return finish_source_results(&mut source_result_rx, &mut source_results_open).await,
                    }
                }
            }
        }
    }

    async fn handle_signal(&self, signal: SignalEnvelope) -> CoreResult<()> {
        let mut current = Some(signal);

        for processor in &self.registry.processors {
            let metadata = processor.metadata();
            let signal = current.take().ok_or(CoreError::PipelineClosed)?;
            match processor
                .process(signal)
                .await
                .map_err(|err| with_module_context(metadata, err))?
            {
                Some(processed) => current = Some(processed),
                None => {
                    debug!("signal dropped by processor");
                    return Ok(());
                }
            }
        }

        let signal = current.ok_or(CoreError::PipelineClosed)?;

        let mut pending_generated = VecDeque::new();
        for (generator_index, generator) in self.registry.generators.iter().enumerate() {
            let generated = self.handle_generator(generator.as_ref(), &signal).await?;
            for derived in generated {
                self.write_to_sinks(&derived).await?;
                pending_generated.push_back((generator_index + 1, derived));
            }
        }

        while let Some((start_index, generated_signal)) = pending_generated.pop_front() {
            for (generator_index, generator) in self
                .registry
                .generators
                .iter()
                .enumerate()
                .skip(start_index)
            {
                let downstream = self
                    .handle_generator(generator.as_ref(), &generated_signal)
                    .await?;
                for derived in downstream {
                    self.write_to_sinks(&derived).await?;
                    pending_generated.push_back((generator_index + 1, derived));
                }
            }
        }

        self.write_to_sinks(&signal).await?;

        Ok(())
    }

    async fn handle_generator(
        &self,
        generator: &dyn e_navigator_core::Generator<SignalEnvelope>,
        signal: &SignalEnvelope,
    ) -> CoreResult<Vec<SignalEnvelope>> {
        let (derived_tx, mut derived_rx) = mpsc::channel(16);
        let observe = generator.observe(signal, &derived_tx);
        tokio::pin!(observe);
        let mut observe_done = false;
        let mut generated = Vec::new();

        while !observe_done {
            tokio::select! {
                result = &mut observe => {
                    result.map_err(|err| with_module_context(generator.metadata(), err))?;
                    observe_done = true;
                }
                derived = derived_rx.recv() => {
                    if let Some(derived) = derived {
                        push_generated(&mut generated, derived, generator.metadata())?;
                    }
                }
            }
        }

        while let Ok(derived) = derived_rx.try_recv() {
            push_generated(&mut generated, derived, generator.metadata())?;
        }

        Ok(generated)
    }

    async fn write_to_sinks(&self, signal: &SignalEnvelope) -> CoreResult<()> {
        for sink in &self.registry.sinks {
            let metadata = sink.metadata();
            sink.write(signal)
                .await
                .map_err(|err| with_module_context(metadata, err))?;
        }

        Ok(())
    }
}

fn push_generated(
    generated: &mut Vec<SignalEnvelope>,
    signal: SignalEnvelope,
    metadata: ModuleMetadata,
) -> CoreResult<()> {
    if generated.len() >= MAX_DERIVED_SIGNALS_PER_GENERATOR {
        return Err(CoreError::ModuleFailed {
            module: metadata.name.to_string(),
            message: format!(
                "generator emitted more than {MAX_DERIVED_SIGNALS_PER_GENERATOR} derived signals for one input"
            ),
        });
    }

    generated.push(signal);
    Ok(())
}

async fn finish_source_results(
    source_result_rx: &mut mpsc::Receiver<CoreResult<()>>,
    source_results_open: &mut bool,
) -> CoreResult<()> {
    while *source_results_open {
        match source_result_rx.recv().await {
            Some(Ok(())) => debug!("source exited cleanly"),
            Some(Err(err)) => return Err(err),
            None => *source_results_open = false,
        }
    }

    Ok(())
}

fn abort_sources(source_handles: &[JoinHandle<()>]) {
    for handle in source_handles {
        handle.abort();
    }
}

fn with_module_context(metadata: ModuleMetadata, err: CoreError) -> CoreError {
    match err {
        CoreError::ModuleFailed { .. } => err,
        other => CoreError::ModuleFailed {
            module: metadata.name.to_string(),
            message: other.to_string(),
        },
    }
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;
    use e_navigator_core::{
        CoreResult, Generator, ModuleKind, ModuleMetadata, Processor, Signal, Sink, Source,
    };
    use e_navigator_signals::{ExecEvent, ProcessExitEvent, SignalEnvelope, SignalPayload};
    use tokio::{
        sync::{Mutex, mpsc},
        time::{Duration, timeout},
    };

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

    struct OneExitSignalSource;

    #[async_trait]
    impl Source<SignalEnvelope> for OneExitSignalSource {
        fn metadata(&self) -> ModuleMetadata {
            ModuleMetadata::new("source.test_exit", ModuleKind::Source)
        }

        async fn run(self: Box<Self>, tx: mpsc::Sender<SignalEnvelope>) -> CoreResult<()> {
            let signal = SignalEnvelope::process_exit(
                "source.test_exit",
                None,
                ProcessExitEvent {
                    pid: 1,
                    ppid: Some(0),
                    uid: None,
                    command: "true".to_string(),
                    exit_code: Some(0),
                    runtime_nanos: Some(10),
                    timestamp_unix_nanos: 11,
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

    struct FailingProcessor;

    #[async_trait]
    impl Processor<SignalEnvelope> for FailingProcessor {
        fn metadata(&self) -> ModuleMetadata {
            ModuleMetadata::new("processor.failing", ModuleKind::Processor)
        }

        async fn process(&self, _signal: SignalEnvelope) -> CoreResult<Option<SignalEnvelope>> {
            Err(CoreError::PipelineClosed)
        }
    }

    struct FailingSource;

    #[async_trait]
    impl Source<SignalEnvelope> for FailingSource {
        fn metadata(&self) -> ModuleMetadata {
            ModuleMetadata::new("source.failing", ModuleKind::Source)
        }

        async fn run(self: Box<Self>, tx: mpsc::Sender<SignalEnvelope>) -> CoreResult<()> {
            drop(tx);
            tokio::task::yield_now().await;
            Err(CoreError::ModuleFailed {
                module: "source.failing".to_string(),
                message: "boom".to_string(),
            })
        }
    }

    struct ManySignalsGenerator {
        count: usize,
    }

    #[async_trait]
    impl Generator<SignalEnvelope> for ManySignalsGenerator {
        fn metadata(&self) -> ModuleMetadata {
            ModuleMetadata::new("generator.many", ModuleKind::Generator)
        }

        async fn observe(
            &self,
            signal: &SignalEnvelope,
            tx: &mpsc::Sender<SignalEnvelope>,
        ) -> CoreResult<()> {
            for _ in 0..self.count {
                tx.send(signal.clone())
                    .await
                    .map_err(|_| CoreError::PipelineClosed)?;
            }

            Ok(())
        }
    }

    struct ProcessExitGenerator;

    #[async_trait]
    impl Generator<SignalEnvelope> for ProcessExitGenerator {
        fn metadata(&self) -> ModuleMetadata {
            ModuleMetadata::new("generator.process_exit", ModuleKind::Generator)
        }

        async fn observe(
            &self,
            signal: &SignalEnvelope,
            tx: &mpsc::Sender<SignalEnvelope>,
        ) -> CoreResult<()> {
            if matches!(&signal.payload, SignalPayload::Exec(_)) {
                tx.send(SignalEnvelope::process_exit(
                    "generator.process_exit",
                    None,
                    ProcessExitEvent {
                        pid: 1,
                        ppid: None,
                        uid: None,
                        command: "generated-exit".to_string(),
                        exit_code: Some(0),
                        runtime_nanos: Some(1),
                        timestamp_unix_nanos: 2,
                        container: None,
                        kubernetes: None,
                    },
                ))
                .await
                .map_err(|_| CoreError::PipelineClosed)?;
            }

            Ok(())
        }
    }

    struct DownstreamExecGenerator;

    #[async_trait]
    impl Generator<SignalEnvelope> for DownstreamExecGenerator {
        fn metadata(&self) -> ModuleMetadata {
            ModuleMetadata::new("generator.downstream_exec", ModuleKind::Generator)
        }

        async fn observe(
            &self,
            signal: &SignalEnvelope,
            tx: &mpsc::Sender<SignalEnvelope>,
        ) -> CoreResult<()> {
            if matches!(&signal.payload, SignalPayload::ProcessExit(_)) {
                tx.send(SignalEnvelope::exec(
                    "generator.downstream_exec",
                    None,
                    ExecEvent {
                        pid: 2,
                        ppid: Some(1),
                        uid: None,
                        command: "downstream-derived".to_string(),
                        executable: None,
                        arguments: vec![],
                        cgroup_id: None,
                        timestamp_unix_nanos: 3,
                        container: None,
                        kubernetes: None,
                    },
                ))
                .await
                .map_err(|_| CoreError::PipelineClosed)?;
            }

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

    #[tokio::test]
    async fn runner_routes_process_exit_signal_to_sink() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let registry = ModuleRegistry::new()
            .with_source(Box::new(OneExitSignalSource))
            .with_sink(Box::new(MemorySink { seen: seen.clone() }));
        let runner = Runner::new(RuntimeConfig::default(), registry).expect("runner builds");

        runner
            .run()
            .await
            .expect("runner exits after source closes");

        let seen = seen.lock().await;
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].kind(), "process_exit");
    }

    #[tokio::test]
    async fn runner_returns_source_failure_when_signal_channel_closes() {
        for _ in 0..100 {
            let registry = ModuleRegistry::new()
                .with_source(Box::new(FailingSource))
                .with_sink(Box::new(MemorySink {
                    seen: Arc::new(Mutex::new(Vec::new())),
                }));
            let runner = Runner::new(RuntimeConfig::default(), registry).expect("runner builds");

            let err = runner.run().await.expect_err("source failure propagates");

            assert!(err.to_string().contains("source.failing"));
        }
    }

    #[tokio::test]
    async fn runner_drains_generator_outputs_while_observe_is_running() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let registry = ModuleRegistry::new()
            .with_source(Box::new(OneSignalSource))
            .with_generator(Box::new(ManySignalsGenerator { count: 17 }))
            .with_sink(Box::new(MemorySink { seen: seen.clone() }));
        let runner = Runner::new(RuntimeConfig::default(), registry).expect("runner builds");

        timeout(Duration::from_secs(1), runner.run())
            .await
            .expect("runner must not deadlock on generator backpressure")
            .expect("runner exits after source closes");

        assert_eq!(seen.lock().await.len(), 18);
    }

    #[tokio::test]
    async fn runner_routes_generated_signals_to_downstream_generators() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let registry = ModuleRegistry::new()
            .with_source(Box::new(OneSignalSource))
            .with_generator(Box::new(ProcessExitGenerator))
            .with_generator(Box::new(DownstreamExecGenerator))
            .with_sink(Box::new(MemorySink { seen: seen.clone() }));
        let runner = Runner::new(RuntimeConfig::default(), registry).expect("runner builds");

        runner
            .run()
            .await
            .expect("runner exits after source closes");

        let seen = seen.lock().await;
        assert_eq!(seen.len(), 3);
        assert!(seen.iter().any(|signal| {
            matches!(
                &signal.payload,
                SignalPayload::ProcessExit(event) if event.command == "generated-exit"
            )
        }));
        assert!(seen.iter().any(|signal| {
            matches!(
                &signal.payload,
                SignalPayload::Exec(event) if event.command == "downstream-derived"
            )
        }));
    }

    #[tokio::test]
    async fn runner_adds_module_context_to_processor_errors() {
        let registry = ModuleRegistry::new()
            .with_source(Box::new(OneSignalSource))
            .with_processor(Box::new(FailingProcessor))
            .with_sink(Box::new(MemorySink {
                seen: Arc::new(Mutex::new(Vec::new())),
            }));
        let runner = Runner::new(RuntimeConfig::default(), registry).expect("runner builds");

        let err = runner.run().await.expect_err("processor error propagates");

        assert!(err.to_string().contains("processor.failing"));
        assert!(err.to_string().contains("pipeline closed"));
    }
}
