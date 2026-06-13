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
        assert!(RuntimeConfig::default().validate().is_ok());
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
}
