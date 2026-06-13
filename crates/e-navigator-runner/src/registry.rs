use e_navigator_core::{Generator, Processor, Sink, Source};
use e_navigator_signals::SignalEnvelope;

#[derive(Default)]
pub struct ModuleRegistry {
    pub sources: Vec<Box<dyn Source<SignalEnvelope>>>,
    pub processors: Vec<Box<dyn Processor<SignalEnvelope>>>,
    pub generators: Vec<Box<dyn Generator<SignalEnvelope>>>,
    pub sinks: Vec<Box<dyn Sink<SignalEnvelope>>>,
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

    pub fn module_count(&self) -> usize {
        self.sources.len() + self.processors.len() + self.generators.len() + self.sinks.len()
    }

    pub fn has_source_and_sink(&self) -> bool {
        !self.sources.is_empty() && !self.sinks.is_empty()
    }
}
