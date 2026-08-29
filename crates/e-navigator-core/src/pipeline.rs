use async_trait::async_trait;
use tokio::sync::mpsc;

use crate::{CoreError, CoreResult, ModuleMetadata};

pub trait Signal: Send + Sync + Clone + 'static {
    fn kind(&self) -> &'static str;
}

#[async_trait]
pub trait Source<S: Signal>: Send + 'static {
    fn metadata(&self) -> ModuleMetadata;

    async fn run(self: Box<Self>, tx: mpsc::Sender<S>) -> CoreResult<()>;
}

#[async_trait]
pub trait Processor<S: Signal>: Send + Sync + 'static {
    fn metadata(&self) -> ModuleMetadata;

    async fn process(&self, signal: S) -> CoreResult<Option<S>>;
}

#[async_trait]
pub trait Generator<S: Signal>: Send + Sync + 'static {
    fn metadata(&self) -> ModuleMetadata;

    /// Returns whether this generator can derive output from the signal.
    ///
    /// The default preserves compatibility for generators that inspect every
    /// signal. Implementations with a closed input set can override this to
    /// avoid allocating an output channel for unrelated high-volume signals.
    fn accepts(&self, _signal: &S) -> bool {
        true
    }

    /// Generates output synchronously when the implementation has no need to
    /// hold or await the output channel.
    ///
    /// Returning `None` preserves the asynchronous `observe` path. The
    /// default therefore remains compatible with existing generators, while
    /// native generators with an immediate result can avoid allocating a
    /// channel and boxed future for every accepted signal.
    fn observe_immediate(&self, _signal: &S) -> Option<CoreResult<Vec<S>>> {
        None
    }

    /// Generates output asynchronously.
    ///
    /// The default forwards the result of `observe_immediate`, keeping the two
    /// public entry points equivalent for synchronous generators. Generators
    /// whose derivation itself awaits can override this method instead.
    async fn observe(&self, signal: &S, tx: &mpsc::Sender<S>) -> CoreResult<()> {
        let Some(outputs) = self.observe_immediate(signal) else {
            return Err(CoreError::ModuleFailed {
                module: self.metadata().name.to_owned(),
                message: "generator implements neither observe nor observe_immediate".to_owned(),
            });
        };

        for output in outputs? {
            tx.send(output)
                .await
                .map_err(|_| CoreError::PipelineClosed)?;
        }
        Ok(())
    }
}

#[async_trait]
pub trait Sink<S: Signal>: Send + Sync + 'static {
    fn metadata(&self) -> ModuleMetadata;

    /// Returns whether this sink can consume the signal.
    ///
    /// The default preserves compatibility for sinks that inspect every
    /// signal. Implementations with a closed input set can override this so
    /// the runner does not allocate an async-trait future for unrelated
    /// high-volume signals.
    fn accepts(&self, _signal: &S) -> bool {
        true
    }

    /// Writes synchronously when no asynchronous I/O is required.
    ///
    /// Returning `None` preserves the asynchronous `write` path.
    fn write_immediate(&self, _signal: &S) -> Option<CoreResult<()>> {
        None
    }

    async fn write(&self, signal: &S) -> CoreResult<()>;

    async fn shutdown(&self) -> CoreResult<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct TestSignal(&'static str);

    impl Signal for TestSignal {
        fn kind(&self) -> &'static str {
            "test"
        }
    }

    #[derive(Debug)]
    struct ImmediateGenerator {
        outputs: Option<Vec<TestSignal>>,
    }

    impl Generator<TestSignal> for ImmediateGenerator {
        fn metadata(&self) -> ModuleMetadata {
            ModuleMetadata::new("generator.test", crate::ModuleKind::Generator)
        }

        fn observe_immediate(&self, _signal: &TestSignal) -> Option<CoreResult<Vec<TestSignal>>> {
            self.outputs.clone().map(Ok)
        }
    }

    #[tokio::test]
    async fn generator_default_observe_forwards_immediate_outputs() {
        let generator = ImmediateGenerator {
            outputs: Some(vec![TestSignal("first"), TestSignal("second")]),
        };
        let (tx, mut rx) = mpsc::channel(2);

        generator
            .observe(&TestSignal("input"), &tx)
            .await
            .expect("default observe forwards immediate outputs");

        assert_eq!(rx.recv().await, Some(TestSignal("first")));
        assert_eq!(rx.recv().await, Some(TestSignal("second")));
    }

    #[tokio::test]
    async fn generator_default_observe_rejects_missing_generation_path() {
        let generator = ImmediateGenerator { outputs: None };
        let (tx, _rx) = mpsc::channel(1);

        let err = generator
            .observe(&TestSignal("input"), &tx)
            .await
            .expect_err("a generator must implement one generation path");

        assert!(matches!(
            err,
            CoreError::ModuleFailed { module, message }
                if module == "generator.test"
                    && message == "generator implements neither observe nor observe_immediate"
        ));
    }

    #[tokio::test]
    async fn generator_default_observe_reports_closed_pipeline() {
        let generator = ImmediateGenerator {
            outputs: Some(vec![TestSignal("output")]),
        };
        let (tx, rx) = mpsc::channel(1);
        drop(rx);

        let err = generator
            .observe(&TestSignal("input"), &tx)
            .await
            .expect_err("a closed output channel must fail");

        assert!(matches!(err, CoreError::PipelineClosed));
    }
}
