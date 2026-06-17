use e_navigator_core::{Generator, Processor, Sink, Source};
use e_navigator_signals::SignalEnvelope;
use std::fmt;

#[derive(Default)]
pub struct ModuleRegistry {
    sources: Vec<Box<dyn Source<SignalEnvelope>>>,
    processors: Vec<Box<dyn Processor<SignalEnvelope>>>,
    generators: Vec<Box<dyn Generator<SignalEnvelope>>>,
    sinks: Vec<Box<dyn Sink<SignalEnvelope>>>,
}

impl fmt::Debug for ModuleRegistry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ModuleRegistry")
            .field("sources", &self.sources.len())
            .field("processors", &self.processors.len())
            .field("generators", &self.generators.len())
            .field("sinks", &self.sinks.len())
            .finish()
    }
}

impl ModuleRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_source(mut self, source: Box<dyn Source<SignalEnvelope>>) -> Self {
        self.sources.push(source);
        self
    }

    pub fn with_processor(mut self, processor: Box<dyn Processor<SignalEnvelope>>) -> Self {
        self.processors.push(processor);
        self
    }

    pub fn with_generator(mut self, generator: Box<dyn Generator<SignalEnvelope>>) -> Self {
        self.generators.push(generator);
        self
    }

    pub fn with_sink(mut self, sink: Box<dyn Sink<SignalEnvelope>>) -> Self {
        self.sinks.push(sink);
        self
    }

    pub fn sources(&self) -> &[Box<dyn Source<SignalEnvelope>>] {
        &self.sources
    }

    pub fn processors(&self) -> &[Box<dyn Processor<SignalEnvelope>>] {
        &self.processors
    }

    pub fn generators(&self) -> &[Box<dyn Generator<SignalEnvelope>>] {
        &self.generators
    }

    pub fn sinks(&self) -> &[Box<dyn Sink<SignalEnvelope>>] {
        &self.sinks
    }

    pub(crate) fn drain_sources(
        &mut self,
    ) -> impl Iterator<Item = Box<dyn Source<SignalEnvelope>>> + '_ {
        self.sources.drain(..)
    }

    pub fn module_count(&self) -> usize {
        self.sources.len() + self.processors.len() + self.generators.len() + self.sinks.len()
    }

    pub fn has_source_and_sink(&self) -> bool {
        !self.sources.is_empty() && !self.sinks.is_empty()
    }
}
