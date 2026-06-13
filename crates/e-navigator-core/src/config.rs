use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeConfig {
    pub log_level: String,
    pub queue_capacity: usize,
    pub modules: Vec<ModuleConfig>,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            log_level: "info".to_string(),
            queue_capacity: 1024,
            modules: vec![
                ModuleConfig::enabled("source.aya_exec"),
                ModuleConfig::enabled("source.synthetic_exec"),
                ModuleConfig::enabled("processor.container_attribution"),
                ModuleConfig::enabled("sink.json_stdout"),
            ],
        }
    }
}

impl RuntimeConfig {
    pub fn validate(&self) -> Result<(), String> {
        if self.queue_capacity == 0 {
            return Err("queue_capacity must be greater than zero".to_string());
        }

        if self.modules.iter().filter(|module| module.enabled).count() == 0 {
            return Err("at least one module must be enabled".to_string());
        }

        Ok(())
    }

    pub fn module_enabled(&self, name: &str) -> bool {
        self.modules
            .iter()
            .find(|module| module.name == name)
            .is_some_and(|module| module.enabled)
    }
}

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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_is_valid() {
        let config = RuntimeConfig::default();

        assert!(config.validate().is_ok());
        assert!(config.module_enabled("source.aya_exec"));
        assert!(config.module_enabled("source.synthetic_exec"));
        assert!(config.module_enabled("processor.container_attribution"));
        assert!(config.module_enabled("sink.json_stdout"));
    }

    #[test]
    fn zero_queue_capacity_is_invalid() {
        let config = RuntimeConfig {
            queue_capacity: 0,
            ..RuntimeConfig::default()
        };

        assert_eq!(
            config.validate(),
            Err("queue_capacity must be greater than zero".to_string())
        );
    }

    #[test]
    fn config_with_no_enabled_modules_is_invalid() {
        let config = RuntimeConfig {
            modules: vec![ModuleConfig {
                name: "sink.json_stdout".to_string(),
                enabled: false,
            }],
            ..RuntimeConfig::default()
        };

        assert_eq!(
            config.validate(),
            Err("at least one module must be enabled".to_string())
        );
    }
}
