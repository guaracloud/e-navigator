use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

use super::{ConfigError, ConfigResult};

/// Posture applied when no explicit rule decides an event's fate.
///
/// `Allow` captures (probes) the workload; `Deny` skips probing it entirely.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapturePosture {
    Allow,
    Deny,
}

impl CapturePosture {
    /// Whether this posture captures (probes) the workload.
    pub fn captures(self) -> bool {
        matches!(self, CapturePosture::Allow)
    }
}

/// Kubernetes-aware capture filter: controls which workloads are *probed*
/// (not merely enriched) by the eBPF sources, keyed on cgroup id.
///
/// Precedence when [`Self::enabled`] and a workload resolves to a pod
/// (namespace + labels), highest first. This ordering is fixed and part of
/// the contract:
///
/// 1. **Exclude wins.** If the namespace matches any `namespace_exclude`
///    pattern, or the pod carries any `label_exclude` key=value, the workload
///    is denied.
/// 2. **Include gate.** If any include list is non-empty, the workload is
///    allowed only when it satisfies *every* configured top-level include
///    criterion and at least one complete `any_of` group when those groups are
///    present; otherwise it is denied.
/// 3. **Default posture.** With no exclude match and no include lists
///    configured, [`Self::default_posture`] decides.
///
/// Workloads whose cgroup id cannot yet be resolved to a pod follow
/// [`Self::unknown_cgroup`] instead. This includes the bootstrap window, host or
/// non-pod processes, and missing Kubernetes API access. Namespace patterns
/// support `*`
/// (any run) and `?` (single byte) globbing. Label selectors support equality,
/// inequality, existence, non-existence, and value sets. Matching is bytewise
/// over the ASCII DNS-label domain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureFilterConfig {
    /// Master switch. When false the filter is a no-op and every workload is
    /// probed exactly as before.
    #[serde(default = "default_capture_filter_enabled")]
    pub enabled: bool,
    /// Verdict for a resolved pod that matches no include/exclude rule.
    #[serde(default = "default_capture_filter_default_posture")]
    pub default_posture: CapturePosture,
    /// Verdict for a cgroup that cannot be resolved to a pod (bootstrap
    /// window, host processes, Kubernetes API unavailable).
    #[serde(default = "default_capture_filter_unknown_cgroup")]
    pub unknown_cgroup: CapturePosture,
    /// Namespaces to include (exact or `*`/`?` glob). Empty disables the
    /// namespace include gate.
    #[serde(default)]
    pub namespace_include: Vec<String>,
    /// Namespaces to exclude (exact or `*`/`?` glob). Highest precedence.
    #[serde(default)]
    pub namespace_exclude: Vec<String>,
    /// Exact `key=value` labels a pod must all carry to be included.
    #[serde(default)]
    pub label_include: BTreeMap<String, String>,
    /// Exact `key=value` labels; a pod carrying any of these is excluded.
    #[serde(default)]
    pub label_exclude: BTreeMap<String, String>,
    /// Exact `key=value` labels a pod must not carry to pass the include gate.
    #[serde(default)]
    pub label_not_equal: BTreeMap<String, String>,
    /// Label keys that must exist for a pod to pass the include gate.
    #[serde(default)]
    pub label_exists: Vec<String>,
    /// Label keys that must not exist for a pod to pass the include gate.
    #[serde(default)]
    pub label_not_exists: Vec<String>,
    /// Allowed value set per label key.
    #[serde(default)]
    pub label_in: BTreeMap<String, Vec<String>>,
    /// Denied value set per label key. Missing labels satisfy this condition.
    #[serde(default)]
    pub label_not_in: BTreeMap<String, Vec<String>>,
    /// Optional OR groups in the include gate.
    #[serde(default)]
    pub any_of: Vec<WorkloadSelectorConfig>,
    /// Exclude-wins OR groups.
    #[serde(default)]
    pub exclude_any: Vec<WorkloadSelectorConfig>,
    /// Process-name exclusion patterns, used when process identity is known.
    #[serde(default)]
    pub process_exclude: Vec<String>,
    /// Container-name exclusion patterns, used when container identity is known.
    #[serde(default)]
    pub container_exclude: Vec<String>,
}

/// One AND-connected workload match used inside an OR selector list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct WorkloadSelectorConfig {
    #[serde(default)]
    pub namespaces: Vec<String>,
    #[serde(default)]
    pub label_equal: BTreeMap<String, String>,
    #[serde(default)]
    pub label_not_equal: BTreeMap<String, String>,
    #[serde(default)]
    pub label_exists: Vec<String>,
    #[serde(default)]
    pub label_not_exists: Vec<String>,
    #[serde(default)]
    pub label_in: BTreeMap<String, Vec<String>>,
    #[serde(default)]
    pub label_not_in: BTreeMap<String, Vec<String>>,
}

impl WorkloadSelectorConfig {
    fn is_empty(&self) -> bool {
        self.namespaces.is_empty()
            && self.label_equal.is_empty()
            && self.label_not_equal.is_empty()
            && self.label_exists.is_empty()
            && self.label_not_exists.is_empty()
            && self.label_in.is_empty()
            && self.label_not_in.is_empty()
    }
}

impl Default for CaptureFilterConfig {
    fn default() -> Self {
        Self {
            enabled: default_capture_filter_enabled(),
            default_posture: default_capture_filter_default_posture(),
            unknown_cgroup: default_capture_filter_unknown_cgroup(),
            namespace_include: Vec::new(),
            namespace_exclude: Vec::new(),
            label_include: BTreeMap::new(),
            label_exclude: BTreeMap::new(),
            label_not_equal: BTreeMap::new(),
            label_exists: Vec::new(),
            label_not_exists: Vec::new(),
            label_in: BTreeMap::new(),
            label_not_in: BTreeMap::new(),
            any_of: Vec::new(),
            exclude_any: Vec::new(),
            process_exclude: Vec::new(),
            container_exclude: Vec::new(),
        }
    }
}

impl CaptureFilterConfig {
    pub const MAX_NAMESPACE_PATTERNS: usize = 128;
    pub const MAX_LABEL_SELECTOR_ENTRIES: usize = 64;
    pub const MAX_OR_GROUPS: usize = 32;
    pub const MAX_SET_VALUES: usize = 64;
    /// A DNS-1123 label is at most 63 bytes; glob patterns are allowed a
    /// little headroom for wildcards.
    pub const MAX_PATTERN_BYTES: usize = 253;

    /// True when the filter would actually constrain capture. A disabled
    /// filter, or one with no rules and an `Allow` default/unknown posture,
    /// changes nothing.
    pub fn is_active(&self) -> bool {
        self.enabled
    }

    pub(super) fn validate(&self) -> ConfigResult<()> {
        if !self.enabled {
            return Ok(());
        }

        validate_pattern_list("capture_filter.namespace_include", &self.namespace_include)?;
        validate_pattern_list("capture_filter.namespace_exclude", &self.namespace_exclude)?;
        validate_label_selector("capture_filter.label_include", &self.label_include)?;
        validate_label_selector("capture_filter.label_exclude", &self.label_exclude)?;
        validate_label_selector("capture_filter.label_not_equal", &self.label_not_equal)?;
        validate_label_keys("capture_filter.label_exists", &self.label_exists)?;
        validate_label_keys("capture_filter.label_not_exists", &self.label_not_exists)?;
        validate_label_value_sets("capture_filter.label_in", &self.label_in)?;
        validate_label_value_sets("capture_filter.label_not_in", &self.label_not_in)?;
        validate_pattern_list("capture_filter.process_exclude", &self.process_exclude)?;
        validate_pattern_list("capture_filter.container_exclude", &self.container_exclude)?;
        validate_selector_groups("capture_filter.any_of", &self.any_of)?;
        validate_selector_groups("capture_filter.exclude_any", &self.exclude_any)?;

        for (key, value) in &self.label_include {
            if self
                .label_exclude
                .get(key)
                .is_some_and(|excluded| excluded == value)
            {
                return Err(ConfigError::invalid_value(
                    "capture_filter.label_exclude",
                    format!(
                        "capture_filter label '{key}={value}' cannot be both included and excluded"
                    ),
                ));
            }
        }

        for key in &self.label_exists {
            if self.label_not_exists.contains(key) {
                return Err(ConfigError::invalid_value(
                    "capture_filter.label_not_exists",
                    format!("capture_filter label '{key}' cannot both exist and not exist"),
                ));
            }
        }

        Ok(())
    }
}

fn validate_pattern_list(path: &'static str, patterns: &[String]) -> ConfigResult<()> {
    if patterns.len() > CaptureFilterConfig::MAX_NAMESPACE_PATTERNS {
        return Err(ConfigError::invalid_value(
            path,
            format!(
                "{path} must contain at most {} entries",
                CaptureFilterConfig::MAX_NAMESPACE_PATTERNS
            ),
        ));
    }
    let mut seen = BTreeSet::new();
    for pattern in patterns {
        if pattern.is_empty() {
            return Err(ConfigError::invalid_value(
                path,
                format!("{path} entries must not be empty"),
            ));
        }
        if pattern.len() > CaptureFilterConfig::MAX_PATTERN_BYTES {
            return Err(ConfigError::invalid_value(
                path,
                format!(
                    "{path} entries must be at most {} bytes",
                    CaptureFilterConfig::MAX_PATTERN_BYTES
                ),
            ));
        }
        if pattern.bytes().any(|byte| byte.is_ascii_control()) {
            return Err(ConfigError::invalid_value(
                path,
                format!("{path} entries must not contain control characters"),
            ));
        }
        if pattern.chars().any(char::is_whitespace) {
            return Err(ConfigError::invalid_value(
                path,
                format!("{path} entries must not contain whitespace"),
            ));
        }
        if !seen.insert(pattern.as_str()) {
            return Err(ConfigError::invalid_value(
                path,
                format!("{path} must not contain duplicate entry '{pattern}'"),
            ));
        }
    }
    Ok(())
}

fn validate_label_selector(
    path: &'static str,
    selector: &BTreeMap<String, String>,
) -> ConfigResult<()> {
    if selector.len() > CaptureFilterConfig::MAX_LABEL_SELECTOR_ENTRIES {
        return Err(ConfigError::invalid_value(
            path,
            format!(
                "{path} must contain at most {} entries",
                CaptureFilterConfig::MAX_LABEL_SELECTOR_ENTRIES
            ),
        ));
    }
    for (key, value) in selector {
        validate_label_component(path, "keys", key)?;
        validate_label_component(path, &format!("value for '{key}'"), value)?;
    }
    Ok(())
}

fn validate_label_keys(path: &'static str, keys: &[String]) -> ConfigResult<()> {
    if keys.len() > CaptureFilterConfig::MAX_LABEL_SELECTOR_ENTRIES {
        return Err(ConfigError::invalid_value(
            path,
            format!(
                "{path} must contain at most {} entries",
                CaptureFilterConfig::MAX_LABEL_SELECTOR_ENTRIES
            ),
        ));
    }
    let mut seen = BTreeSet::new();
    for key in keys {
        validate_label_component(path, "keys", key)?;
        if !seen.insert(key) {
            return Err(ConfigError::invalid_value(
                path,
                format!("{path} must not contain duplicate key '{key}'"),
            ));
        }
    }
    Ok(())
}

fn validate_label_value_sets(
    path: &'static str,
    sets: &BTreeMap<String, Vec<String>>,
) -> ConfigResult<()> {
    if sets.len() > CaptureFilterConfig::MAX_LABEL_SELECTOR_ENTRIES {
        return Err(ConfigError::invalid_value(
            path,
            format!(
                "{path} must contain at most {} keys",
                CaptureFilterConfig::MAX_LABEL_SELECTOR_ENTRIES
            ),
        ));
    }
    for (key, values) in sets {
        validate_label_component(path, "keys", key)?;
        if values.is_empty() {
            return Err(ConfigError::invalid_value(
                path,
                format!("{path} values for '{key}' must not be empty"),
            ));
        }
        if values.len() > CaptureFilterConfig::MAX_SET_VALUES {
            return Err(ConfigError::invalid_value(
                path,
                format!(
                    "{path} values for '{key}' must contain at most {} entries",
                    CaptureFilterConfig::MAX_SET_VALUES
                ),
            ));
        }
        let mut seen = BTreeSet::new();
        for value in values {
            validate_label_component(path, &format!("value for '{key}'"), value)?;
            if !seen.insert(value) {
                return Err(ConfigError::invalid_value(
                    path,
                    format!("{path} values for '{key}' must not contain duplicate '{value}'"),
                ));
            }
        }
    }
    Ok(())
}

fn validate_selector_groups(
    path: &'static str,
    groups: &[WorkloadSelectorConfig],
) -> ConfigResult<()> {
    if groups.len() > CaptureFilterConfig::MAX_OR_GROUPS {
        return Err(ConfigError::invalid_value(
            path,
            format!(
                "{path} must contain at most {} groups",
                CaptureFilterConfig::MAX_OR_GROUPS
            ),
        ));
    }
    for group in groups {
        if group.is_empty() {
            return Err(ConfigError::invalid_value(
                path,
                format!("{path} groups must not be empty"),
            ));
        }
        validate_pattern_list(path, &group.namespaces)?;
        validate_label_selector(path, &group.label_equal)?;
        validate_label_selector(path, &group.label_not_equal)?;
        validate_label_keys(path, &group.label_exists)?;
        validate_label_keys(path, &group.label_not_exists)?;
        validate_label_value_sets(path, &group.label_in)?;
        validate_label_value_sets(path, &group.label_not_in)?;
    }
    Ok(())
}

fn validate_label_component(path: &'static str, what: &str, component: &str) -> ConfigResult<()> {
    if component.trim().is_empty() {
        return Err(ConfigError::invalid_value(
            path,
            format!("{path} {what} must not be empty"),
        ));
    }
    if component.len() > CaptureFilterConfig::MAX_PATTERN_BYTES {
        return Err(ConfigError::invalid_value(
            path,
            format!(
                "{path} {what} must be at most {} bytes",
                CaptureFilterConfig::MAX_PATTERN_BYTES
            ),
        ));
    }
    if component.bytes().any(|byte| byte.is_ascii_control()) {
        return Err(ConfigError::invalid_value(
            path,
            format!("{path} {what} must not contain control characters"),
        ));
    }
    if component.chars().any(char::is_whitespace) {
        return Err(ConfigError::invalid_value(
            path,
            format!("{path} {what} must not contain whitespace"),
        ));
    }
    Ok(())
}

fn default_capture_filter_enabled() -> bool {
    false
}

fn default_capture_filter_default_posture() -> CapturePosture {
    CapturePosture::Allow
}

fn default_capture_filter_unknown_cgroup() -> CapturePosture {
    CapturePosture::Allow
}
