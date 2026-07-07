//! Pure, allocation-light evaluation of the Kubernetes-aware capture filter.
//!
//! [`CaptureFilterPolicy`] is compiled once from a validated
//! [`CaptureFilterConfig`] and answers, for a resolved pod, whether its
//! workload should be probed. It holds only the operator's rules — never a
//! live pod list — so it is trivially unit-testable and carries no I/O.
//!
//! Cgroups that cannot be resolved to a pod are handled by the caller via
//! [`CaptureFilterPolicy::unknown_decision`]; the precedence and glob
//! semantics are documented on [`CaptureFilterConfig`].

use std::collections::BTreeMap;

use crate::config::{CaptureFilterConfig, CapturePosture};

mod resolve;

pub use resolve::{
    CAPTURE_FILTER_MAP_CAPACITY, CgroupObservation, DesiredFilterMap, FilterMapDiff,
    FilterMapMirror, RawNodePodIndex, RawPod, build_desired_filter_map,
    parse_container_id_from_cgroup_path, parse_pod_uid_from_cgroup_path,
};

/// Whether a workload should be probed (`Capture`) or skipped (`Drop`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureDecision {
    Capture,
    Drop,
}

impl CaptureDecision {
    /// Byte written into the eBPF membership map: `1` captures, `0` drops.
    pub fn as_filter_byte(self) -> u8 {
        match self {
            CaptureDecision::Capture => 1,
            CaptureDecision::Drop => 0,
        }
    }

    /// Whether this decision probes the workload.
    pub fn captures(self) -> bool {
        matches!(self, CaptureDecision::Capture)
    }
}

impl From<CapturePosture> for CaptureDecision {
    fn from(posture: CapturePosture) -> Self {
        if posture.captures() {
            CaptureDecision::Capture
        } else {
            CaptureDecision::Drop
        }
    }
}

/// A single namespace matcher: an exact string or a `*`/`?` glob.
#[derive(Debug, Clone, PartialEq, Eq)]
enum NamespacePattern {
    Exact(String),
    Glob(String),
}

impl NamespacePattern {
    fn compile(pattern: &str) -> Self {
        if pattern.contains(['*', '?']) {
            NamespacePattern::Glob(pattern.to_string())
        } else {
            NamespacePattern::Exact(pattern.to_string())
        }
    }

    fn matches(&self, value: &str) -> bool {
        match self {
            NamespacePattern::Exact(exact) => exact == value,
            NamespacePattern::Glob(pattern) => glob_match(pattern, value),
        }
    }
}

/// Compiled, immutable form of [`CaptureFilterConfig`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureFilterPolicy {
    enabled: bool,
    default_decision: CaptureDecision,
    unknown_decision: CaptureDecision,
    namespace_include: Vec<NamespacePattern>,
    namespace_exclude: Vec<NamespacePattern>,
    label_include: BTreeMap<String, String>,
    label_exclude: BTreeMap<String, String>,
}

impl CaptureFilterPolicy {
    pub fn from_config(config: &CaptureFilterConfig) -> Self {
        Self {
            enabled: config.enabled,
            default_decision: config.default_posture.into(),
            unknown_decision: config.unknown_cgroup.into(),
            namespace_include: compile_patterns(&config.namespace_include),
            namespace_exclude: compile_patterns(&config.namespace_exclude),
            label_include: config.label_include.clone(),
            label_exclude: config.label_exclude.clone(),
        }
    }

    /// Whether the filter is engaged at all. When false, callers must probe
    /// every workload (the historical behaviour).
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Decision for a cgroup that could not be resolved to a pod.
    pub fn unknown_decision(&self) -> CaptureDecision {
        self.unknown_decision
    }

    /// Evaluate a resolved pod. See [`CaptureFilterConfig`] for the fixed
    /// precedence: exclude wins, then the include gate, then the default
    /// posture.
    pub fn evaluate(&self, namespace: &str, labels: &BTreeMap<String, String>) -> CaptureDecision {
        // 1. Exclude wins.
        if self
            .namespace_exclude
            .iter()
            .any(|pattern| pattern.matches(namespace))
        {
            return CaptureDecision::Drop;
        }
        if labels_match_any(&self.label_exclude, labels) {
            return CaptureDecision::Drop;
        }

        // 2. Include gate.
        let has_include = !self.namespace_include.is_empty() || !self.label_include.is_empty();
        if has_include {
            let namespace_ok = self.namespace_include.is_empty()
                || self
                    .namespace_include
                    .iter()
                    .any(|pattern| pattern.matches(namespace));
            let labels_ok = labels_match_all(&self.label_include, labels);
            return if namespace_ok && labels_ok {
                CaptureDecision::Capture
            } else {
                CaptureDecision::Drop
            };
        }

        // 3. Default posture.
        self.default_decision
    }
}

fn compile_patterns(patterns: &[String]) -> Vec<NamespacePattern> {
    patterns
        .iter()
        .map(|pattern| NamespacePattern::compile(pattern))
        .collect()
}

/// True when every `key=value` in `selector` is present on `labels` (AND).
/// An empty selector matches everything.
fn labels_match_all(
    selector: &BTreeMap<String, String>,
    labels: &BTreeMap<String, String>,
) -> bool {
    selector
        .iter()
        .all(|(key, value)| labels.get(key).is_some_and(|actual| actual == value))
}

/// True when any `key=value` in `selector` is present on `labels` (OR).
/// An empty selector matches nothing.
fn labels_match_any(
    selector: &BTreeMap<String, String>,
    labels: &BTreeMap<String, String>,
) -> bool {
    selector
        .iter()
        .any(|(key, value)| labels.get(key).is_some_and(|actual| actual == value))
}

/// Bytewise glob match supporting `*` (any run, including empty) and `?`
/// (exactly one byte). Iterative with backtracking — no allocation, no
/// recursion, bounded by the input lengths. Values in this domain are ASCII
/// DNS labels, so bytewise matching never splits a multibyte character.
pub fn glob_match(pattern: &str, value: &str) -> bool {
    let pattern = pattern.as_bytes();
    let value = value.as_bytes();
    let mut pi = 0usize;
    let mut vi = 0usize;
    // Position to backtrack to on the most recent `*`, and where in `value`
    // that star has consumed up to.
    let mut star_pi: Option<usize> = None;
    let mut star_vi = 0usize;

    while vi < value.len() {
        if pi < pattern.len() && (pattern[pi] == b'?' || pattern[pi] == value[vi]) {
            pi += 1;
            vi += 1;
        } else if pi < pattern.len() && pattern[pi] == b'*' {
            star_pi = Some(pi);
            star_vi = vi;
            pi += 1;
        } else if let Some(sp) = star_pi {
            // Backtrack: let the last `*` swallow one more byte.
            pi = sp + 1;
            star_vi += 1;
            vi = star_vi;
        } else {
            return false;
        }
    }

    while pi < pattern.len() && pattern[pi] == b'*' {
        pi += 1;
    }
    pi == pattern.len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::CaptureFilterConfig;

    fn labels(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    }

    fn policy(config: CaptureFilterConfig) -> CaptureFilterPolicy {
        CaptureFilterPolicy::from_config(&config)
    }

    // ----- glob matcher -----

    #[test]
    fn glob_exact_and_wildcards() {
        assert!(glob_match("proj", "proj"));
        assert!(!glob_match("proj", "proja"));
        assert!(glob_match("proj-*", "proj-web"));
        assert!(glob_match("proj-*", "proj-"));
        assert!(!glob_match("proj-*", "prod-web"));
        assert!(glob_match("*-web", "proj-web"));
        assert!(glob_match("*", ""));
        assert!(glob_match("*", "anything"));
        assert!(glob_match("a?c", "abc"));
        assert!(!glob_match("a?c", "ac"));
        assert!(glob_match("*proj*", "my-proj-ns"));
        assert!(glob_match("a*b*c", "axxbyyc"));
        assert!(!glob_match("a*b*c", "axxbyy"));
    }

    #[test]
    fn glob_empty_pattern_only_matches_empty() {
        assert!(glob_match("", ""));
        assert!(!glob_match("", "x"));
    }

    #[test]
    fn glob_does_not_panic_on_arbitrary_bytes() {
        // Non-ASCII / control bytes must never panic the bytewise matcher.
        let long = "a".repeat(1000);
        let samples = ["", "*", "??", "\u{1f600}", "*\u{1f600}*", long.as_str()];
        for pattern in samples {
            for value in samples {
                let _ = glob_match(pattern, value);
            }
        }
    }

    // ----- policy evaluation -----

    #[test]
    fn disabled_policy_reports_disabled() {
        let policy = policy(CaptureFilterConfig::default());
        assert!(!policy.is_enabled());
    }

    #[test]
    fn default_allow_captures_unmatched() {
        let config = CaptureFilterConfig {
            enabled: true,
            ..Default::default()
        };
        let policy = policy(config);
        assert_eq!(
            policy.evaluate("anything", &BTreeMap::new()),
            CaptureDecision::Capture
        );
        assert_eq!(policy.unknown_decision(), CaptureDecision::Capture);
    }

    #[test]
    fn namespace_include_gate_denies_non_matching() {
        let config = CaptureFilterConfig {
            enabled: true,
            namespace_include: vec!["proj-*".to_string()],
            ..Default::default()
        };
        let policy = policy(config);
        assert_eq!(
            policy.evaluate("proj-web", &BTreeMap::new()),
            CaptureDecision::Capture
        );
        assert_eq!(
            policy.evaluate("kube-system", &BTreeMap::new()),
            CaptureDecision::Drop
        );
    }

    #[test]
    fn namespace_exclude_wins_over_include() {
        let config = CaptureFilterConfig {
            enabled: true,
            namespace_include: vec!["proj-*".to_string()],
            namespace_exclude: vec!["proj-secret".to_string()],
            ..Default::default()
        };
        let policy = policy(config);
        assert_eq!(
            policy.evaluate("proj-web", &BTreeMap::new()),
            CaptureDecision::Capture
        );
        assert_eq!(
            policy.evaluate("proj-secret", &BTreeMap::new()),
            CaptureDecision::Drop
        );
    }

    #[test]
    fn denylist_posture_excludes_named_namespace() {
        // default_posture=allow + a single exclude == a denylist.
        let config = CaptureFilterConfig {
            enabled: true,
            default_posture: CapturePosture::Allow,
            namespace_exclude: vec!["kube-system".to_string()],
            ..Default::default()
        };
        let policy = policy(config);
        assert_eq!(
            policy.evaluate("kube-system", &BTreeMap::new()),
            CaptureDecision::Drop
        );
        assert_eq!(
            policy.evaluate("payments", &BTreeMap::new()),
            CaptureDecision::Capture
        );
    }

    #[test]
    fn label_include_requires_all_entries() {
        let config = CaptureFilterConfig {
            enabled: true,
            label_include: labels(&[("team", "payments"), ("tier", "prod")]),
            ..Default::default()
        };
        let policy = policy(config);
        assert_eq!(
            policy.evaluate("ns", &labels(&[("team", "payments"), ("tier", "prod")])),
            CaptureDecision::Capture
        );
        assert_eq!(
            policy.evaluate("ns", &labels(&[("team", "payments")])),
            CaptureDecision::Drop
        );
    }

    #[test]
    fn label_exclude_matches_any_entry() {
        let config = CaptureFilterConfig {
            enabled: true,
            label_exclude: labels(&[("sensitive", "true")]),
            ..Default::default()
        };
        let policy = policy(config);
        assert_eq!(
            policy.evaluate("ns", &labels(&[("sensitive", "true")])),
            CaptureDecision::Drop
        );
        assert_eq!(
            policy.evaluate("ns", &labels(&[("sensitive", "false")])),
            CaptureDecision::Capture
        );
    }

    #[test]
    fn namespace_and_label_include_are_anded() {
        let config = CaptureFilterConfig {
            enabled: true,
            namespace_include: vec!["proj-*".to_string()],
            label_include: labels(&[("tier", "prod")]),
            ..Default::default()
        };
        let policy = policy(config);
        // Matches namespace but not label -> denied (AND semantics).
        assert_eq!(
            policy.evaluate("proj-web", &labels(&[("tier", "dev")])),
            CaptureDecision::Drop
        );
        assert_eq!(
            policy.evaluate("proj-web", &labels(&[("tier", "prod")])),
            CaptureDecision::Capture
        );
        // Matches label but not namespace -> denied.
        assert_eq!(
            policy.evaluate("other", &labels(&[("tier", "prod")])),
            CaptureDecision::Drop
        );
    }

    #[test]
    fn allowlist_posture_unknown_deny() {
        // default_posture=deny + namespace include == an allowlist; unknown
        // cgroups excluded to avoid bootstrap over-capture.
        let config = CaptureFilterConfig {
            enabled: true,
            default_posture: CapturePosture::Deny,
            unknown_cgroup: CapturePosture::Deny,
            namespace_include: vec!["proj-*".to_string()],
            ..Default::default()
        };
        let policy = policy(config);
        assert_eq!(policy.unknown_decision(), CaptureDecision::Drop);
        assert_eq!(
            policy.evaluate("proj-web", &BTreeMap::new()),
            CaptureDecision::Capture
        );
        assert_eq!(
            policy.evaluate("other", &BTreeMap::new()),
            CaptureDecision::Drop
        );
    }

    #[test]
    fn decision_filter_byte_encoding() {
        assert_eq!(CaptureDecision::Capture.as_filter_byte(), 1);
        assert_eq!(CaptureDecision::Drop.as_filter_byte(), 0);
    }
}
