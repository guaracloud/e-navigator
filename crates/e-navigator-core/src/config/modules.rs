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
    vec![
        ModuleConfig::enabled("source.aya_exec"),
        ModuleConfig::enabled("source.aya_network"),
        ModuleConfig::disabled("source.aya_cpu_profile"),
        ModuleConfig::enabled("source.host_resource"),
        ModuleConfig::enabled("source.synthetic_exec"),
        ModuleConfig::enabled("processor.container_attribution"),
        ModuleConfig::enabled("generator.resource_metrics"),
        ModuleConfig::enabled("generator.network_metrics"),
        ModuleConfig::enabled("generator.dns_metrics"),
        ModuleConfig::enabled("generator.trace_correlation"),
        ModuleConfig::enabled("generator.request_correlation"),
        ModuleConfig::enabled("generator.profiling"),
        ModuleConfig::enabled("generator.dependency_graph"),
        ModuleConfig::enabled("generator.runtime_security"),
        ModuleConfig::enabled("sink.json_stdout"),
    ]
}
