use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
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
    #[serde(default)]
    pub namespace_allowlist: Vec<String>,
    #[serde(default)]
    pub namespace_denylist: Vec<String>,
    #[serde(default)]
    pub node_name_allowlist: Vec<String>,
    #[serde(default)]
    pub node_name_denylist: Vec<String>,
    #[serde(default)]
    pub pod_label_selector: BTreeMap<String, String>,
    #[serde(default)]
    pub pod_label_exclude_selector: BTreeMap<String, String>,
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
            namespace_allowlist: Vec::new(),
            namespace_denylist: Vec::new(),
            node_name_allowlist: Vec::new(),
            node_name_denylist: Vec::new(),
            pod_label_selector: BTreeMap::new(),
            pod_label_exclude_selector: BTreeMap::new(),
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
        validate_non_empty_list(
            "attribution.kubernetes.label_allowlist",
            &self.label_allowlist,
        )?;
        validate_selector_lists(
            "attribution.kubernetes.namespace_allowlist",
            &self.namespace_allowlist,
            "attribution.kubernetes.namespace_denylist",
            &self.namespace_denylist,
        )?;
        validate_selector_lists(
            "attribution.kubernetes.node_name_allowlist",
            &self.node_name_allowlist,
            "attribution.kubernetes.node_name_denylist",
            &self.node_name_denylist,
        )?;
        validate_label_selector(
            "attribution.kubernetes.pod_label_selector",
            &self.pod_label_selector,
        )?;
        validate_label_selector(
            "attribution.kubernetes.pod_label_exclude_selector",
            &self.pod_label_exclude_selector,
        )?;
        for (key, value) in &self.pod_label_selector {
            if self
                .pod_label_exclude_selector
                .get(key)
                .is_some_and(|excluded| excluded == value)
            {
                return Err(ConfigError::invalid_value(
                    "attribution.kubernetes.pod_label_exclude_selector",
                    format!(
                        "attribution.kubernetes pod label selector for '{key}' cannot require and exclude the same value"
                    ),
                ));
            }
        }

        Ok(())
    }
}

fn validate_non_empty_list(path: &'static str, values: &[String]) -> ConfigResult<()> {
    if values.iter().any(|value| value.trim().is_empty()) {
        return Err(ConfigError::invalid_value(
            path,
            format!("{path} entries must not be empty"),
        ));
    }
    Ok(())
}

fn validate_selector_lists(
    allowlist_path: &'static str,
    allowlist: &[String],
    denylist_path: &'static str,
    denylist: &[String],
) -> ConfigResult<()> {
    validate_non_empty_list(allowlist_path, allowlist)?;
    validate_non_empty_list(denylist_path, denylist)?;
    for allowed in allowlist {
        if denylist.iter().any(|denied| denied == allowed) {
            return Err(ConfigError::invalid_value(
                denylist_path,
                format!("{denylist_path} cannot contain '{allowed}' because it is also allowed"),
            ));
        }
    }
    Ok(())
}

fn validate_label_selector(
    path: &'static str,
    selector: &BTreeMap<String, String>,
) -> ConfigResult<()> {
    for (key, value) in selector {
        if key.trim().is_empty() {
            return Err(ConfigError::invalid_value(
                path,
                format!("{path} keys must not be empty"),
            ));
        }
        if value.trim().is_empty() {
            return Err(ConfigError::invalid_value(
                path,
                format!("{path} value for '{key}' must not be empty"),
            ));
        }
    }
    Ok(())
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
