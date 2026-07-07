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
/// (namespace + labels), highest first — this ordering is fixed and part of
/// the contract:
///
/// 1. **Exclude wins.** If the namespace matches any `namespace_exclude`
///    pattern, or the pod carries any `label_exclude` key=value, the workload
///    is denied.
/// 2. **Include gate.** If any include list is non-empty, the workload is
///    allowed only when it satisfies *every* configured include criterion
///    (namespace matches `namespace_include` AND labels match all
///    `label_include` entries); otherwise it is denied.
/// 3. **Default posture.** With no exclude match and no include lists
///    configured, [`Self::default_posture`] decides.
///
/// Workloads whose cgroup id cannot (yet) be resolved to a pod — the bootstrap
/// window, host/non-pod processes, or a missing Kubernetes API — follow
/// [`Self::unknown_cgroup`] instead. Namespace patterns support `*`
/// (any run) and `?` (single byte) globbing; label selectors are exact
/// key=value. Matching is bytewise over the ASCII DNS-label domain.
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
        }
    }
}

impl CaptureFilterConfig {
    pub const MAX_NAMESPACE_PATTERNS: usize = 128;
    pub const MAX_LABEL_SELECTOR_ENTRIES: usize = 64;
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
