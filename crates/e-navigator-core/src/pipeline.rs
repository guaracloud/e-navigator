use async_trait::async_trait;
use tokio::sync::mpsc;

use crate::{CoreResult, ModuleMetadata};

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

    async fn observe(&self, signal: &S, tx: &mpsc::Sender<S>) -> CoreResult<()>;
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
