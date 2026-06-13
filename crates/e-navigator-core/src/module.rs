#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModuleKind {
    Source,
    Processor,
    Generator,
    Sink,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModuleMetadata {
    pub name: &'static str,
    pub kind: ModuleKind,
}

impl ModuleMetadata {
    pub const fn new(name: &'static str, kind: ModuleKind) -> Self {
        Self { name, kind }
    }
}
