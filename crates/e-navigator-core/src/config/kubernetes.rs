use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use super::{ConfigError, ConfigResult};

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

impl KubernetesAttributionConfig {
    pub(super) fn validate(&self) -> ConfigResult<()> {
        if !self.enabled {
            return Ok(());
        }

        if self.token_path.as_os_str().is_empty() {
            return Err(ConfigError::invalid_value(
                "attribution.kubernetes.token_path",
                "attribution.kubernetes.token_path must not be empty when Kubernetes attribution is enabled",
            ));
        }
        if self.ca_cert_path.as_os_str().is_empty() {
            return Err(ConfigError::invalid_value(
                "attribution.kubernetes.ca_cert_path",
                "attribution.kubernetes.ca_cert_path must not be empty when Kubernetes attribution is enabled",
            ));
        }

        Ok(())
    }
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
