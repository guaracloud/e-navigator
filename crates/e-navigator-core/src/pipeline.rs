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

    async fn observe(&self, signal: &S, tx: &mpsc::Sender<S>) -> CoreResult<()>;
}

#[async_trait]
pub trait Sink<S: Signal>: Send + Sync + 'static {
    fn metadata(&self) -> ModuleMetadata;

    async fn write(&self, signal: &S) -> CoreResult<()>;
}
