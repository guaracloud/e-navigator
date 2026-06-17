use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

#[derive(Clone, Debug)]
pub(crate) struct SourceDiagnostics {
    enabled: bool,
    remaining: Arc<AtomicUsize>,
    filtered_preview_remaining: Arc<AtomicUsize>,
    filters: Arc<Vec<String>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DiagnosticSampleDecision {
    Disabled,
    Filtered,
    Matched,
    Exhausted,
}

impl SourceDiagnostics {
    pub(crate) const DEFAULT_LIMIT: usize = 64;

    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) fn from_env() -> Self {
        Self::from_values(
            std::env::var("E_NAVIGATOR_SOURCE_DIAGNOSTICS")
                .ok()
                .as_deref(),
            std::env::var("E_NAVIGATOR_SOURCE_DIAGNOSTICS_LIMIT")
                .ok()
                .as_deref(),
            std::env::var("E_NAVIGATOR_SOURCE_DIAGNOSTICS_FILTER")
                .ok()
                .as_deref(),
            std::env::var("E_NAVIGATOR_SOURCE_DIAGNOSTICS_FILTERED_LIMIT")
                .ok()
                .as_deref(),
        )
    }

    fn from_values(
        enabled: Option<&str>,
        limit: Option<&str>,
        filter: Option<&str>,
        filtered_preview_limit: Option<&str>,
    ) -> Self {
        let enabled = enabled
            .map(|value| matches!(value, "1" | "true" | "TRUE" | "yes" | "YES" | "on" | "ON"))
            .unwrap_or(false);
        let limit = limit
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(Self::DEFAULT_LIMIT);
        let filtered_preview_limit = filtered_preview_limit
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(0);
        let filters = filter
            .into_iter()
            .flat_map(|value| value.split(','))
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned)
            .collect();
        Self::with_filters(enabled, limit, filtered_preview_limit, filters)
    }

    #[cfg(test)]
    fn new(enabled: bool, limit: usize) -> Self {
        Self::with_filters(enabled, limit, 0, Vec::new())
    }

    fn with_filters(
        enabled: bool,
        limit: usize,
        filtered_preview_limit: usize,
        filters: Vec<String>,
    ) -> Self {
        Self {
            enabled,
            remaining: Arc::new(AtomicUsize::new(limit)),
            filtered_preview_remaining: Arc::new(AtomicUsize::new(filtered_preview_limit)),
            filters: Arc::new(filters),
        }
    }

    pub(crate) fn enabled(&self) -> bool {
        self.enabled
    }

    pub(crate) fn remaining_samples(&self) -> usize {
        self.remaining.load(Ordering::Relaxed)
    }

    pub(crate) fn remaining_filtered_preview_samples(&self) -> usize {
        self.filtered_preview_remaining.load(Ordering::Relaxed)
    }

    #[cfg(test)]
    pub(crate) fn try_acquire_sample(&self) -> bool {
        self.try_acquire_sample_for(&[])
    }

    #[cfg(test)]
    pub(crate) fn try_acquire_sample_for(&self, values: &[&str]) -> bool {
        matches!(
            self.sample_decision_for(values),
            DiagnosticSampleDecision::Matched
        )
    }

    pub(crate) fn sample_decision_for(&self, values: &[&str]) -> DiagnosticSampleDecision {
        if !self.enabled {
            return DiagnosticSampleDecision::Disabled;
        }

        if !self.filters.is_empty()
            && !self
                .filters
                .iter()
                .any(|filter| values.iter().any(|value| value.contains(filter)))
        {
            return DiagnosticSampleDecision::Filtered;
        }

        if self
            .remaining
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |remaining| {
                if remaining > 0 {
                    Some(remaining - 1)
                } else {
                    None
                }
            })
            .is_ok()
        {
            DiagnosticSampleDecision::Matched
        } else {
            DiagnosticSampleDecision::Exhausted
        }
    }

    pub(crate) fn try_acquire_filtered_preview(&self) -> bool {
        if !self.enabled {
            return false;
        }

        self.filtered_preview_remaining
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |remaining| {
                if remaining > 0 {
                    Some(remaining - 1)
                } else {
                    None
                }
            })
            .is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::SourceDiagnostics;

    #[test]
    fn diagnostics_are_disabled_by_default() {
        let diagnostics = SourceDiagnostics::new(false, 64);

        assert!(!diagnostics.enabled());
        assert!(!diagnostics.try_acquire_sample());
    }

    #[test]
    fn diagnostics_are_bounded_by_limit() {
        let diagnostics = SourceDiagnostics::new(true, 2);

        assert!(diagnostics.enabled());
        assert!(diagnostics.try_acquire_sample());
        assert!(diagnostics.try_acquire_sample());
        assert!(!diagnostics.try_acquire_sample());
    }

    #[test]
    fn diagnostics_parse_environment_flags_and_limits() {
        let disabled = SourceDiagnostics::from_values(None, None, None, None);
        let enabled = SourceDiagnostics::from_values(Some("1"), Some("7"), None, Some("3"));
        let invalid_limit =
            SourceDiagnostics::from_values(Some("true"), Some("not-a-number"), None, None);

        assert!(!disabled.enabled());
        assert!(enabled.enabled());
        assert_eq!(enabled.remaining_samples(), 7);
        assert_eq!(enabled.remaining_filtered_preview_samples(), 3);
        assert_eq!(
            invalid_limit.remaining_samples(),
            SourceDiagnostics::DEFAULT_LIMIT
        );
    }

    #[test]
    fn diagnostics_filter_samples_by_text() {
        let diagnostics =
            SourceDiagnostics::from_values(Some("1"), Some("2"), Some("wget,known-exec"), None);

        assert!(!diagnostics.try_acquire_sample_for(&["longhorn-manager"]));
        assert_eq!(
            diagnostics.sample_decision_for(&["longhorn-manager"]),
            super::DiagnosticSampleDecision::Filtered
        );
        assert_eq!(diagnostics.remaining_samples(), 2);
        assert!(diagnostics.try_acquire_sample_for(&["/bin/sh", "echo known-exec"]));
        assert!(diagnostics.try_acquire_sample_for(&["wget"]));
        assert!(!diagnostics.try_acquire_sample_for(&["wget"]));
        assert_eq!(
            diagnostics.sample_decision_for(&["wget"]),
            super::DiagnosticSampleDecision::Exhausted
        );
    }

    #[test]
    fn diagnostics_bound_filtered_preview_samples() {
        let diagnostics =
            SourceDiagnostics::from_values(Some("1"), Some("2"), Some("wget"), Some("1"));

        assert_eq!(
            diagnostics.sample_decision_for(&["longhorn-manager"]),
            super::DiagnosticSampleDecision::Filtered
        );
        assert_eq!(diagnostics.remaining_samples(), 2);
        assert!(diagnostics.try_acquire_filtered_preview());
        assert!(!diagnostics.try_acquire_filtered_preview());
    }
}
