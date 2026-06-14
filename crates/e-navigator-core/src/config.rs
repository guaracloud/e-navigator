use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeConfig {
    #[serde(default = "default_log_level")]
    pub log_level: String,
    #[serde(default = "default_queue_capacity")]
    pub queue_capacity: usize,
    #[serde(default = "default_modules")]
    pub modules: Vec<ModuleConfig>,
    #[serde(default)]
    pub argv_capture: ArgvCaptureConfig,
    #[serde(default)]
    pub attribution: AttributionConfig,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            log_level: default_log_level(),
            queue_capacity: default_queue_capacity(),
            modules: default_modules(),
            argv_capture: ArgvCaptureConfig::default(),
            attribution: AttributionConfig::default(),
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

        self.argv_capture.validate()?;
        self.attribution.validate()?;

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
pub struct ArgvCaptureConfig {
    #[serde(default = "default_argv_capture_enabled")]
    pub enabled: bool,
    #[serde(default = "default_argv_capture_max_args")]
    pub max_args: usize,
    #[serde(default = "default_argv_capture_max_bytes")]
    pub max_bytes: usize,
}

impl Default for ArgvCaptureConfig {
    fn default() -> Self {
        Self {
            enabled: default_argv_capture_enabled(),
            max_args: default_argv_capture_max_args(),
            max_bytes: default_argv_capture_max_bytes(),
        }
    }
}

impl ArgvCaptureConfig {
    pub const MAX_ARGS_LIMIT: usize = 8;
    pub const MAX_BYTES_LIMIT: usize = 512;

    fn validate(&self) -> Result<(), String> {
        if !(1..=Self::MAX_ARGS_LIMIT).contains(&self.max_args) {
            return Err(format!(
                "argv_capture.max_args must be between 1 and {}",
                Self::MAX_ARGS_LIMIT
            ));
        }

        if !(1..=Self::MAX_BYTES_LIMIT).contains(&self.max_bytes) {
            return Err(format!(
                "argv_capture.max_bytes must be between 1 and {}",
                Self::MAX_BYTES_LIMIT
            ));
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttributionConfig {
    #[serde(default = "default_procfs_root")]
    pub procfs_root: PathBuf,
    #[serde(default)]
    pub kubernetes: KubernetesAttributionConfig,
}

impl Default for AttributionConfig {
    fn default() -> Self {
        Self {
            procfs_root: default_procfs_root(),
            kubernetes: KubernetesAttributionConfig::default(),
        }
    }
}

impl AttributionConfig {
    fn validate(&self) -> Result<(), String> {
        if self.procfs_root.as_os_str().is_empty() {
            return Err("attribution.procfs_root must not be empty".to_string());
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KubernetesAttributionConfig {
    #[serde(default = "default_kubernetes_attribution_enabled")]
    pub enabled: bool,
    #[serde(default = "default_service_account_token_path")]
    pub token_path: PathBuf,
    #[serde(default = "default_service_account_ca_path")]
    pub ca_cert_path: PathBuf,
}

impl Default for KubernetesAttributionConfig {
    fn default() -> Self {
        Self {
            enabled: default_kubernetes_attribution_enabled(),
            token_path: default_service_account_token_path(),
            ca_cert_path: default_service_account_ca_path(),
        }
    }
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_queue_capacity() -> usize {
    1024
}

fn default_modules() -> Vec<ModuleConfig> {
    vec![
        ModuleConfig::enabled("source.aya_exec"),
        ModuleConfig::enabled("source.aya_network"),
        ModuleConfig::enabled("source.synthetic_exec"),
        ModuleConfig::enabled("processor.container_attribution"),
        ModuleConfig::enabled("generator.dependency_graph"),
        ModuleConfig::enabled("generator.runtime_security"),
        ModuleConfig::enabled("sink.json_stdout"),
    ]
}

fn default_argv_capture_enabled() -> bool {
    true
}

fn default_argv_capture_max_args() -> usize {
    ArgvCaptureConfig::MAX_ARGS_LIMIT
}

fn default_argv_capture_max_bytes() -> usize {
    ArgvCaptureConfig::MAX_BYTES_LIMIT
}

fn default_procfs_root() -> PathBuf {
    PathBuf::from("/proc")
}

fn default_kubernetes_attribution_enabled() -> bool {
    true
}

fn default_service_account_token_path() -> PathBuf {
    PathBuf::from("/var/run/secrets/kubernetes.io/serviceaccount/token")
}

fn default_service_account_ca_path() -> PathBuf {
    PathBuf::from("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")
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
    fn argv_capture_defaults_are_bounded_and_enabled() {
        let config = RuntimeConfig::default();

        assert!(config.argv_capture.enabled);
        assert_eq!(config.argv_capture.max_args, 8);
        assert_eq!(config.argv_capture.max_bytes, 512);
    }

    #[test]
    fn argv_capture_limits_are_validated() {
        let zero_args = RuntimeConfig {
            argv_capture: ArgvCaptureConfig {
                enabled: true,
                max_args: 0,
                max_bytes: 512,
            },
            ..RuntimeConfig::default()
        };
        assert_eq!(
            zero_args.validate(),
            Err("argv_capture.max_args must be between 1 and 8".to_string())
        );

        let too_many_args = RuntimeConfig {
            argv_capture: ArgvCaptureConfig {
                enabled: true,
                max_args: 9,
                max_bytes: 512,
            },
            ..RuntimeConfig::default()
        };
        assert_eq!(
            too_many_args.validate(),
            Err("argv_capture.max_args must be between 1 and 8".to_string())
        );

        let too_many_bytes = RuntimeConfig {
            argv_capture: ArgvCaptureConfig {
                enabled: true,
                max_args: 8,
                max_bytes: 513,
            },
            ..RuntimeConfig::default()
        };
        assert_eq!(
            too_many_bytes.validate(),
            Err("argv_capture.max_bytes must be between 1 and 512".to_string())
        );
    }

    #[test]
    fn default_config_is_valid() {
        let config = RuntimeConfig::default();

        assert!(config.validate().is_ok());
        assert!(config.module_enabled("source.aya_exec"));
        assert!(config.module_enabled("source.aya_network"));
        assert!(config.module_enabled("source.synthetic_exec"));
        assert!(config.module_enabled("processor.container_attribution"));
        assert!(config.module_enabled("generator.dependency_graph"));
        assert!(config.module_enabled("generator.runtime_security"));
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
