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
    #[serde(default = "default_require_node_name")]
    pub require_node_name: bool,
    #[serde(default = "default_allow_cluster_wide_pod_list")]
    pub allow_cluster_wide_pod_list: bool,
    #[serde(default = "default_max_response_bytes")]
    pub max_response_bytes: u64,
    #[serde(default = "default_max_pods")]
    pub max_pods: usize,
    #[serde(default = "default_max_cache_entries")]
    pub max_cache_entries: usize,
    #[serde(default = "default_max_labels_per_pod")]
    pub max_labels_per_pod: usize,
    #[serde(default)]
    pub label_allowlist: Vec<String>,
}

impl Default for KubernetesAttributionConfig {
    fn default() -> Self {
        Self {
            enabled: default_kubernetes_attribution_enabled(),
            token_path: default_service_account_token_path(),
            ca_cert_path: default_service_account_ca_path(),
            require_node_name: default_require_node_name(),
            allow_cluster_wide_pod_list: default_allow_cluster_wide_pod_list(),
            max_response_bytes: default_max_response_bytes(),
            max_pods: default_max_pods(),
            max_cache_entries: default_max_cache_entries(),
            max_labels_per_pod: default_max_labels_per_pod(),
            label_allowlist: Vec::new(),
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
        if self.max_response_bytes == 0 {
            return Err(ConfigError::invalid_value(
                "attribution.kubernetes.max_response_bytes",
                "attribution.kubernetes.max_response_bytes must be greater than zero",
            ));
        }
        if self.max_pods == 0 {
            return Err(ConfigError::invalid_value(
                "attribution.kubernetes.max_pods",
                "attribution.kubernetes.max_pods must be greater than zero",
            ));
        }
        if self.max_cache_entries == 0 {
            return Err(ConfigError::invalid_value(
                "attribution.kubernetes.max_cache_entries",
                "attribution.kubernetes.max_cache_entries must be greater than zero",
            ));
        }
        if self.max_labels_per_pod == 0 && self.label_allowlist.is_empty() {
            return Err(ConfigError::invalid_value(
                "attribution.kubernetes.max_labels_per_pod",
                "attribution.kubernetes.max_labels_per_pod must be greater than zero unless label_allowlist is set",
            ));
        }
        if self.require_node_name && self.allow_cluster_wide_pod_list {
            return Err(ConfigError::invalid_value(
                "attribution.kubernetes.allow_cluster_wide_pod_list",
                "attribution.kubernetes.allow_cluster_wide_pod_list cannot be true when require_node_name is true",
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

fn default_require_node_name() -> bool {
    true
}

fn default_allow_cluster_wide_pod_list() -> bool {
    false
}

fn default_max_response_bytes() -> u64 {
    2 * 1024 * 1024
}

fn default_max_pods() -> usize {
    1024
}

fn default_max_cache_entries() -> usize {
    4096
}

fn default_max_labels_per_pod() -> usize {
    16
}
