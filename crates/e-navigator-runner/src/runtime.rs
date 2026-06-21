use e_navigator_core::{ConfigError, CoreError, CoreResult, ModuleMetadata, RuntimeConfig, Signal};
use e_navigator_signals::SignalEnvelope;
use std::{collections::VecDeque, fmt};
use tokio::{sync::mpsc, task::JoinHandle};
use tracing::{debug, warn};

use crate::ModuleRegistry;

const MAX_DERIVED_SIGNALS_PER_GENERATOR: usize = 64;

pub struct Runner {
    config: RuntimeConfig,
    registry: ModuleRegistry,
}

impl fmt::Debug for Runner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Runner")
            .field("config", &self.config)
            .field("registry", &self.registry)
            .finish()
    }
}

impl Runner {
    pub fn new(config: RuntimeConfig, registry: ModuleRegistry) -> CoreResult<Self> {
        config.validate_typed().map_err(CoreError::InvalidConfig)?;

        if registry.module_count() == 0 {
            return Err(CoreError::InvalidConfig(ConfigError::invalid_value(
                "modules",
                "at least one registered module is required",
            )));
        }

        if !registry.has_source_and_sink() {
            return Err(CoreError::InvalidConfig(ConfigError::invalid_value(
                "modules",
                "at least one source and one sink are required",
            )));
        }

        Ok(Self { config, registry })
    }

    pub async fn run(mut self) -> CoreResult<()> {
        let (tx, mut rx) = mpsc::channel::<SignalEnvelope>(self.config.queue_capacity);
        let (source_result_tx, mut source_result_rx) =
            mpsc::channel::<CoreResult<()>>(self.registry.sources().len());

        let mut source_handles = Vec::new();

        for source in self.registry.drain_sources() {
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
        let Some(signal) = self.process_signal(signal).await? else {
            return Ok(());
        };

        let mut budget = DerivedSignalBudget::new(
            self.config.max_derived_signals_per_input,
            self.config.max_derived_signal_depth,
        );
        let mut pending_generated = VecDeque::new();
        for (generator_index, generator) in self.registry.generators().iter().enumerate() {
            let generated = self.handle_generator(generator.as_ref(), &signal).await?;
            for derived in generated {
                if !budget.try_accept(generator.metadata(), 1) {
                    continue;
                }
                if let Some(processed) = self.process_signal(derived).await? {
                    self.write_to_sinks(&processed).await?;
                    pending_generated.push_back((generator_index + 1, 1_usize, processed));
                }
            }
        }

        while let Some((start_index, depth, generated_signal)) = pending_generated.pop_front() {
            for (generator_index, generator) in self
                .registry
                .generators()
                .iter()
                .enumerate()
                .skip(start_index)
            {
                let next_depth = depth.saturating_add(1);
                let downstream = self
                    .handle_generator(generator.as_ref(), &generated_signal)
                    .await?;
                for derived in downstream {
                    if !budget.try_accept(generator.metadata(), next_depth) {
                        continue;
                    }
                    if let Some(processed) = self.process_signal(derived).await? {
                        self.write_to_sinks(&processed).await?;
                        pending_generated.push_back((generator_index + 1, next_depth, processed));
                    }
                }
            }
        }

        self.write_to_sinks(&signal).await?;

        Ok(())
    }

    async fn process_signal(&self, signal: SignalEnvelope) -> CoreResult<Option<SignalEnvelope>> {
        let mut current = Some(signal);

        for processor in self.registry.processors() {
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
                    return Ok(None);
                }
            }
        }

        current.ok_or(CoreError::PipelineClosed).map(Some)
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
        for sink in self.registry.sinks() {
            let metadata = sink.metadata();
            if let Err(err) = sink.write(signal).await {
                let module = metadata.name;
                let err = with_module_context(metadata, err);
                warn!(
                    module,
                    signal_kind = signal.kind(),
                    error = %err,
                    "sink write failed; dropping signal for this sink"
                );
            }
        }

        Ok(())
    }
}

#[derive(Debug)]
struct DerivedSignalBudget {
    remaining: usize,
    max_signals: usize,
    max_depth: usize,
}

impl DerivedSignalBudget {
    fn new(max_signals: usize, max_depth: usize) -> Self {
        Self {
            remaining: max_signals,
            max_signals,
            max_depth,
        }
    }

    fn try_accept(&mut self, metadata: ModuleMetadata, depth: usize) -> bool {
        if depth > self.max_depth {
            warn!(
                module = metadata.name,
                depth,
                max_depth = self.max_depth,
                "derived signal dropped because generation depth budget was exhausted"
            );
            return false;
        }

        if self.remaining == 0 {
            warn!(
                module = metadata.name,
                max_derived_signals_per_input = self.max_signals,
                "derived signal dropped because per-input derived signal budget was exhausted"
            );
            return false;
        }

        self.remaining -= 1;
        true
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
    use e_navigator_generators::{DependencyGraphGenerator, TraceCorrelationGenerator};
    use e_navigator_signals::{
        ContainerContext, ExecEvent, KubernetesContext, NetworkAddressFamily,
        NetworkConnectionCloseEvent, NetworkConnectionOpenEvent, NetworkProcessIdentity,
        NetworkProtocol, ProcessExitEvent, SignalEnvelope, SignalPayload,
    };
    use tokio::{
        sync::{Mutex, mpsc},
        time::{Duration, sleep, timeout},
    };

    use super::*;
    use std::{
        collections::BTreeMap,
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
    };

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
                    cgroup_id: None,
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

    struct NetworkOpenAndCloseSource;

    #[async_trait]
    impl Source<SignalEnvelope> for NetworkOpenAndCloseSource {
        fn metadata(&self) -> ModuleMetadata {
            ModuleMetadata::new("source.network_contract", ModuleKind::Source)
        }

        async fn run(self: Box<Self>, tx: mpsc::Sender<SignalEnvelope>) -> CoreResult<()> {
            let process = NetworkProcessIdentity {
                pid: 42,
                ppid: Some(1),
                uid: Some(1000),
                command: "checkout-api".to_string(),
                executable: Some("/app/checkout-api".to_string()),
                cgroup_id: None,
            };
            let container = Some(ContainerContext {
                container_id: "container-1".to_string(),
                runtime: Some("containerd".to_string()),
            });
            let kubernetes = Some(KubernetesContext {
                namespace: "shop".to_string(),
                pod_name: "checkout-7d8f".to_string(),
                pod_uid: Some("pod-uid-1".to_string()),
                container_name: Some("checkout".to_string()),
                node_name: Some("node-a".to_string()),
                labels: BTreeMap::new(),
            });
            let opened_at = 1_000;
            tx.send(SignalEnvelope::network_connection_open(
                "source.network_contract",
                Some("node-a".to_string()),
                NetworkConnectionOpenEvent {
                    process: process.clone(),
                    protocol: NetworkProtocol::Tcp,
                    address_family: NetworkAddressFamily::Ipv4,
                    local_address: Some("10.0.0.5".to_string()),
                    local_port: Some(41000),
                    remote_address: "203.0.113.10".to_string(),
                    remote_port: 443,
                    fd: Some(9),
                    timestamp_unix_nanos: opened_at,
                    container: container.clone(),
                    kubernetes: kubernetes.clone(),
                },
            ))
            .await
            .map_err(|_| CoreError::PipelineClosed)?;

            tx.send(SignalEnvelope::network_connection_close(
                "source.network_contract",
                Some("node-a".to_string()),
                NetworkConnectionCloseEvent {
                    process,
                    protocol: NetworkProtocol::Tcp,
                    address_family: NetworkAddressFamily::Ipv4,
                    local_address: Some("10.0.0.5".to_string()),
                    local_port: Some(41000),
                    remote_address: "203.0.113.10".to_string(),
                    remote_port: 443,
                    fd: Some(9),
                    opened_at_unix_nanos: Some(opened_at),
                    closed_at_unix_nanos: opened_at + 2_000,
                    duration_nanos: Some(2_000),
                    container,
                    kubernetes,
                },
            ))
            .await
            .map_err(|_| CoreError::PipelineClosed)
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

    struct SlowMemorySink {
        seen: Arc<Mutex<Vec<SignalEnvelope>>>,
        delay: Duration,
    }

    #[async_trait]
    impl Sink<SignalEnvelope> for SlowMemorySink {
        fn metadata(&self) -> ModuleMetadata {
            ModuleMetadata::new("sink.slow_memory", ModuleKind::Sink)
        }

        async fn write(&self, signal: &SignalEnvelope) -> CoreResult<()> {
            sleep(self.delay).await;
            self.seen.lock().await.push(signal.clone());
            Ok(())
        }
    }

    struct FailingSink;

    #[async_trait]
    impl Sink<SignalEnvelope> for FailingSink {
        fn metadata(&self) -> ModuleMetadata {
            ModuleMetadata::new("sink.failing", ModuleKind::Sink)
        }

        async fn write(&self, _signal: &SignalEnvelope) -> CoreResult<()> {
            Err(CoreError::ModuleFailed {
                module: "sink.failing".to_string(),
                message: "collector unavailable".to_string(),
            })
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

    struct GeneratedExitProcessor;

    #[async_trait]
    impl Processor<SignalEnvelope> for GeneratedExitProcessor {
        fn metadata(&self) -> ModuleMetadata {
            ModuleMetadata::new("processor.generated_exit", ModuleKind::Processor)
        }

        async fn process(&self, mut signal: SignalEnvelope) -> CoreResult<Option<SignalEnvelope>> {
            if let SignalPayload::ProcessExit(event) = &mut signal.payload
                && event.command == "generated-exit"
            {
                event.command = "processed-generated-exit".to_string();
            }

            Ok(Some(signal))
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

    struct SignalThenFailingSource;

    #[async_trait]
    impl Source<SignalEnvelope> for SignalThenFailingSource {
        fn metadata(&self) -> ModuleMetadata {
            ModuleMetadata::new("source.signal_then_failing", ModuleKind::Source)
        }

        async fn run(self: Box<Self>, tx: mpsc::Sender<SignalEnvelope>) -> CoreResult<()> {
            Box::new(OneSignalSource).run(tx).await?;
            Err(CoreError::ModuleFailed {
                module: "source.signal_then_failing".to_string(),
                message: "source failed after send".to_string(),
            })
        }
    }

    struct NeverEndingSource {
        aborted: Arc<AtomicBool>,
    }

    #[async_trait]
    impl Source<SignalEnvelope> for NeverEndingSource {
        fn metadata(&self) -> ModuleMetadata {
            ModuleMetadata::new("source.never_ending", ModuleKind::Source)
        }

        async fn run(self: Box<Self>, _tx: mpsc::Sender<SignalEnvelope>) -> CoreResult<()> {
            struct AbortFlag(Arc<AtomicBool>);
            impl Drop for AbortFlag {
                fn drop(&mut self) {
                    self.0.store(true, Ordering::SeqCst);
                }
            }

            let _abort_flag = AbortFlag(self.aborted);
            std::future::pending::<CoreResult<()>>().await
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
                        cgroup_id: None,
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

    struct ProcessedExitOnlyGenerator;

    #[async_trait]
    impl Generator<SignalEnvelope> for ProcessedExitOnlyGenerator {
        fn metadata(&self) -> ModuleMetadata {
            ModuleMetadata::new("generator.processed_exit_only", ModuleKind::Generator)
        }

        async fn observe(
            &self,
            signal: &SignalEnvelope,
            tx: &mpsc::Sender<SignalEnvelope>,
        ) -> CoreResult<()> {
            if matches!(
                &signal.payload,
                SignalPayload::ProcessExit(event) if event.command == "processed-generated-exit"
            ) {
                tx.send(SignalEnvelope::exec(
                    "generator.processed_exit_only",
                    None,
                    ExecEvent {
                        pid: 3,
                        ppid: Some(1),
                        uid: None,
                        command: "saw-processed-generated-exit".to_string(),
                        executable: None,
                        arguments: vec![],
                        cgroup_id: None,
                        timestamp_unix_nanos: 4,
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
    async fn runner_rejects_generator_cascade_that_exceeds_per_input_limit() {
        let registry = ModuleRegistry::new()
            .with_source(Box::new(OneSignalSource))
            .with_generator(Box::new(ManySignalsGenerator { count: 65 }))
            .with_sink(Box::new(MemorySink {
                seen: Arc::new(Mutex::new(Vec::new())),
            }));
        let runner = Runner::new(RuntimeConfig::default(), registry).expect("runner builds");

        let err = timeout(Duration::from_secs(1), runner.run())
            .await
            .expect("runner does not deadlock")
            .expect_err("derived signal limit is enforced");

        assert!(err.to_string().contains("generator.many"));
        assert!(
            err.to_string()
                .contains("more than 64 derived signals for one input")
        );
    }

    #[tokio::test]
    async fn slow_sink_backpressure_does_not_hide_source_errors() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let registry = ModuleRegistry::new()
            .with_source(Box::new(SignalThenFailingSource))
            .with_sink(Box::new(SlowMemorySink {
                seen: seen.clone(),
                delay: Duration::from_millis(25),
            }));
        let runner = Runner::new(RuntimeConfig::default(), registry).expect("runner builds");

        let err = timeout(Duration::from_secs(1), runner.run())
            .await
            .expect("runner returns")
            .expect_err("source failure propagates");

        assert!(err.to_string().contains("source.signal_then_failing"));
        assert!(err.to_string().contains("source failed after send"));
        assert!(seen.lock().await.len() <= 1);
    }

    #[tokio::test]
    async fn sink_failure_does_not_abort_the_runner_or_other_sinks() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let registry = ModuleRegistry::new()
            .with_source(Box::new(OneSignalSource))
            .with_sink(Box::new(FailingSink))
            .with_sink(Box::new(MemorySink { seen: seen.clone() }));
        let runner = Runner::new(RuntimeConfig::default(), registry).expect("runner builds");

        timeout(Duration::from_secs(1), runner.run())
            .await
            .expect("runner returns")
            .expect("sink failure is non-fatal");

        assert_eq!(seen.lock().await.len(), 1);
    }

    #[tokio::test]
    async fn source_failure_aborts_remaining_sources() {
        let aborted = Arc::new(AtomicBool::new(false));
        let registry = ModuleRegistry::new()
            .with_source(Box::new(NeverEndingSource {
                aborted: aborted.clone(),
            }))
            .with_source(Box::new(FailingSource))
            .with_sink(Box::new(MemorySink {
                seen: Arc::new(Mutex::new(Vec::new())),
            }));
        let runner = Runner::new(RuntimeConfig::default(), registry).expect("runner builds");

        let err = timeout(Duration::from_secs(1), runner.run())
            .await
            .expect("runner returns")
            .expect_err("source failure propagates");

        assert!(err.to_string().contains("source.failing"));
        for _ in 0..20 {
            if aborted.load(Ordering::SeqCst) {
                return;
            }
            sleep(Duration::from_millis(5)).await;
        }
        panic!("remaining source was not aborted");
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
    async fn runner_global_derived_budget_bounds_total_fanout_per_original_signal() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let registry = ModuleRegistry::new()
            .with_source(Box::new(OneSignalSource))
            .with_generator(Box::new(ManySignalsGenerator { count: 3 }))
            .with_generator(Box::new(ManySignalsGenerator { count: 3 }))
            .with_sink(Box::new(MemorySink { seen: seen.clone() }));
        let runner = Runner::new(
            RuntimeConfig {
                max_derived_signals_per_input: 4,
                ..RuntimeConfig::default()
            },
            registry,
        )
        .expect("runner builds");

        runner
            .run()
            .await
            .expect("runner exits after source closes");

        let seen = seen.lock().await;
        assert_eq!(seen.len(), 5);
        assert_eq!(
            seen.iter()
                .filter(|signal| signal.source == "source.test")
                .count(),
            5
        );
    }

    #[tokio::test]
    async fn runner_depth_budget_drops_downstream_derived_signals() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let registry = ModuleRegistry::new()
            .with_source(Box::new(OneSignalSource))
            .with_generator(Box::new(ProcessExitGenerator))
            .with_generator(Box::new(DownstreamExecGenerator))
            .with_sink(Box::new(MemorySink { seen: seen.clone() }));
        let runner = Runner::new(
            RuntimeConfig {
                max_derived_signal_depth: 1,
                ..RuntimeConfig::default()
            },
            registry,
        )
        .expect("runner builds");

        runner
            .run()
            .await
            .expect("runner exits after source closes");

        let seen = seen.lock().await;
        assert_eq!(seen.len(), 2);
        assert!(seen.iter().any(|signal| {
            matches!(
                &signal.payload,
                SignalPayload::ProcessExit(event) if event.command == "generated-exit"
            )
        }));
        assert!(!seen.iter().any(|signal| {
            matches!(
                &signal.payload,
                SignalPayload::Exec(event) if event.command == "downstream-derived"
            )
        }));
    }

    #[tokio::test]
    async fn runner_processes_generated_signals_before_downstream_generators_and_sinks() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let registry = ModuleRegistry::new()
            .with_source(Box::new(OneSignalSource))
            .with_processor(Box::new(GeneratedExitProcessor))
            .with_generator(Box::new(ProcessExitGenerator))
            .with_generator(Box::new(ProcessedExitOnlyGenerator))
            .with_sink(Box::new(MemorySink { seen: seen.clone() }));
        let runner = Runner::new(RuntimeConfig::default(), registry).expect("runner builds");

        runner
            .run()
            .await
            .expect("runner exits after source closes");

        let seen = seen.lock().await;
        assert!(seen.iter().any(|signal| {
            matches!(
                &signal.payload,
                SignalPayload::ProcessExit(event) if event.command == "processed-generated-exit"
            )
        }));
        assert!(seen.iter().any(|signal| {
            matches!(
                &signal.payload,
                SignalPayload::Exec(event) if event.command == "saw-processed-generated-exit"
            )
        }));
    }

    #[tokio::test]
    async fn dependency_graph_output_reaches_trace_correlation_in_static_generator_order() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let registry = ModuleRegistry::new()
            .with_source(Box::new(NetworkOpenAndCloseSource))
            .with_generator(Box::new(DependencyGraphGenerator::default()))
            .with_generator(Box::new(TraceCorrelationGenerator::default()))
            .with_sink(Box::new(MemorySink { seen: seen.clone() }));
        let runner = Runner::new(RuntimeConfig::default(), registry).expect("runner builds");

        runner
            .run()
            .await
            .expect("runner exits after source closes");

        let seen = seen.lock().await;
        assert!(seen.iter().any(|signal| {
            matches!(&signal.payload, SignalPayload::DependencyEdge(edge)
                if edge.destination.address.as_deref() == Some("203.0.113.10")
                    && edge.destination.port == Some(443))
        }));
        assert!(seen.iter().any(|signal| {
            matches!(&signal.payload, SignalPayload::TraceServicePathObservation(path)
                if path.path_key.starts_with("trace-path:")
                    && path.destination.address.as_deref() == Some("203.0.113.10")
                    && path.destination.port == Some(443))
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
