use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceHealthSnapshot {
    pub source: &'static str,
    pub running: bool,
    pub starts: u64,
    pub clean_exits: u64,
    pub failures: u64,
    pub last_transition_unix_seconds: u64,
}

#[derive(Debug, Default)]
struct SourceHealthState {
    running: bool,
    starts: u64,
    clean_exits: u64,
    failures: u64,
    last_transition_unix_seconds: u64,
}

/// Bounded process-local state for statically registered source modules.
///
/// Source names come only from [`crate::ModuleRegistry`], so the registry's
/// label cardinality is capped by the configured source count.
#[derive(Clone, Debug, Default)]
pub struct SourceHealthRegistry {
    states: Arc<Mutex<BTreeMap<&'static str, SourceHealthState>>>,
}

impl SourceHealthRegistry {
    pub fn snapshots(&self) -> Vec<SourceHealthSnapshot> {
        self.states.lock().map_or_else(
            |_| Vec::new(),
            |states| {
                states
                    .iter()
                    .map(|(source, state)| SourceHealthSnapshot {
                        source,
                        running: state.running,
                        starts: state.starts,
                        clean_exits: state.clean_exits,
                        failures: state.failures,
                        last_transition_unix_seconds: state.last_transition_unix_seconds,
                    })
                    .collect()
            },
        )
    }

    pub(crate) fn register(&self, source: &'static str) {
        if let Ok(mut states) = self.states.lock() {
            states.entry(source).or_default();
        }
    }

    pub(crate) fn record_start(&self, source: &'static str) {
        if let Ok(mut states) = self.states.lock() {
            let state = states.entry(source).or_default();
            state.running = true;
            state.starts = state.starts.saturating_add(1);
            state.last_transition_unix_seconds = now_unix_seconds();
        }
    }

    pub(crate) fn record_result(&self, source: &'static str, succeeded: bool) {
        if let Ok(mut states) = self.states.lock() {
            let state = states.entry(source).or_default();
            state.running = false;
            if succeeded {
                state.clean_exits = state.clean_exits.saturating_add(1);
            } else {
                state.failures = state.failures.saturating_add(1);
            }
            state.last_transition_unix_seconds = now_unix_seconds();
        }
    }
}

fn now_unix_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

#[cfg(test)]
mod tests {
    use super::SourceHealthRegistry;

    #[test]
    fn source_lifecycle_is_bounded_and_cumulative() {
        let registry = SourceHealthRegistry::default();
        registry.register("source.test");
        registry.record_start("source.test");
        registry.record_result("source.test", false);
        registry.record_start("source.test");
        registry.record_result("source.test", true);

        let snapshots = registry.snapshots();
        assert_eq!(snapshots.len(), 1);
        assert_eq!(snapshots[0].source, "source.test");
        assert!(!snapshots[0].running);
        assert_eq!(snapshots[0].starts, 2);
        assert_eq!(snapshots[0].failures, 1);
        assert_eq!(snapshots[0].clean_exits, 1);
        assert!(snapshots[0].last_transition_unix_seconds > 0);
    }
}
