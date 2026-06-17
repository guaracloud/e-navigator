use crate::ModuleKind;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModuleConfig {
    pub name: String,
    pub enabled: bool,
}

impl ModuleConfig {
    pub fn enabled(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            enabled: true,
        }
    }

    pub fn disabled(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            enabled: false,
        }
    }
}

pub(super) fn default_modules() -> Vec<ModuleConfig> {
    KNOWN_MODULES
        .iter()
        .map(|module| {
            if module.default_enabled {
                ModuleConfig::enabled(module.name)
            } else {
                ModuleConfig::disabled(module.name)
            }
        })
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KnownModule {
    pub name: &'static str,
    pub kind: ModuleKind,
    default_enabled: bool,
}

pub const KNOWN_MODULES: &[KnownModule] = &[
    KnownModule {
        name: "source.aya_exec",
        kind: ModuleKind::Source,
        default_enabled: true,
    },
    KnownModule {
        name: "source.aya_network",
        kind: ModuleKind::Source,
        default_enabled: true,
    },
    KnownModule {
        name: "source.aya_cpu_profile",
        kind: ModuleKind::Source,
        default_enabled: false,
    },
    KnownModule {
        name: "source.host_resource",
        kind: ModuleKind::Source,
        default_enabled: true,
    },
    KnownModule {
        name: "source.synthetic_exec",
        kind: ModuleKind::Source,
        default_enabled: true,
    },
    KnownModule {
        name: "processor.container_attribution",
        kind: ModuleKind::Processor,
        default_enabled: true,
    },
    KnownModule {
        name: "generator.resource_metrics",
        kind: ModuleKind::Generator,
        default_enabled: true,
    },
    KnownModule {
        name: "generator.network_metrics",
        kind: ModuleKind::Generator,
        default_enabled: true,
    },
    KnownModule {
        name: "generator.dns_metrics",
        kind: ModuleKind::Generator,
        default_enabled: true,
    },
    KnownModule {
        name: "generator.trace_correlation",
        kind: ModuleKind::Generator,
        default_enabled: true,
    },
    KnownModule {
        name: "generator.request_correlation",
        kind: ModuleKind::Generator,
        default_enabled: true,
    },
    KnownModule {
        name: "generator.profiling",
        kind: ModuleKind::Generator,
        default_enabled: true,
    },
    KnownModule {
        name: "generator.dependency_graph",
        kind: ModuleKind::Generator,
        default_enabled: true,
    },
    KnownModule {
        name: "generator.runtime_security",
        kind: ModuleKind::Generator,
        default_enabled: true,
    },
    KnownModule {
        name: "sink.json_stdout",
        kind: ModuleKind::Sink,
        default_enabled: true,
    },
];

pub fn known_module_names() -> impl Iterator<Item = &'static str> {
    KNOWN_MODULES.iter().map(|module| module.name)
}

pub fn is_known_module_name(name: &str) -> bool {
    KNOWN_MODULES.iter().any(|module| module.name == name)
}
