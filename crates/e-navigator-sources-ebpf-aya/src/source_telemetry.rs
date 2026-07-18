#[cfg(any(target_os = "linux", test))]
use crate::diagnostics::DiagnosticSampleDecision;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};
use tracing::info;

#[derive(Debug)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) struct SourceTelemetry {
    source: &'static str,
    started_at: Instant,
    summary_interval_nanos: u64,
    next_summary_nanos: AtomicU64,
    counters: Arc<SourceCounters>,
    last_summary: Mutex<SourceTelemetrySnapshot>,
}

#[derive(Debug, Default)]
struct SourceCounters {
    initialized: AtomicU64,
    decoded_samples: AtomicU64,
    invalid_samples: AtomicU64,
    sent_signals: AtomicU64,
    send_failures: AtomicU64,
    lost_perf_events: AtomicU64,
    diagnostic_matches: AtomicU64,
    diagnostic_filtered: AtomicU64,
    diagnostic_exhausted: AtomicU64,
    optional_targets_discovered: AtomicU64,
    optional_targets_ready: AtomicU64,
    optional_targets_unsupported: AtomicU64,
    optional_probe_attachments: AtomicU64,
    optional_attachment_failures: AtomicU64,
    optional_rescans: AtomicU64,
    optional_capacity_rejections: AtomicU64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceTelemetrySnapshot {
    pub source: &'static str,
    pub initialized: bool,
    pub decoded_samples: u64,
    pub invalid_samples: u64,
    pub sent_signals: u64,
    pub send_failures: u64,
    pub lost_perf_events: u64,
    pub diagnostic_matches: u64,
    pub diagnostic_filtered: u64,
    pub diagnostic_exhausted: u64,
    pub optional_targets_discovered: u64,
    pub optional_targets_ready: u64,
    pub optional_targets_unsupported: u64,
    pub optional_probe_attachments: u64,
    pub optional_attachment_failures: u64,
    pub optional_rescans: u64,
    pub optional_capacity_rejections: u64,
}

static SOURCE_COUNTERS: OnceLock<Mutex<BTreeMap<&'static str, Arc<SourceCounters>>>> =
    OnceLock::new();

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
impl SourceTelemetry {
    pub(crate) const DEFAULT_SUMMARY_INTERVAL: Duration = Duration::from_secs(10);

    pub(crate) fn new(source: &'static str) -> Self {
        Self::with_summary_interval(source, Self::DEFAULT_SUMMARY_INTERVAL)
    }

    fn with_summary_interval(source: &'static str, summary_interval: Duration) -> Self {
        let summary_interval_nanos = u64::try_from(summary_interval.as_nanos())
            .unwrap_or(u64::MAX)
            .max(1);
        let counters = Arc::new(SourceCounters::default());
        SOURCE_COUNTERS
            .get_or_init(|| Mutex::new(BTreeMap::new()))
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(source, counters.clone());
        Self {
            source,
            started_at: Instant::now(),
            summary_interval_nanos,
            next_summary_nanos: AtomicU64::new(summary_interval_nanos),
            counters,
            last_summary: Mutex::new(SourceTelemetrySnapshot::empty(source)),
        }
    }

    pub(crate) fn mark_initialized(&self) {
        self.counters.initialized.store(1, Ordering::Relaxed);
    }

    pub(crate) fn record_decoded_sample(&self) {
        self.counters
            .decoded_samples
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_invalid_sample(&self) {
        self.counters
            .invalid_samples
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_sent_signal(&self) {
        self.counters.sent_signals.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_send_failure(&self) {
        self.counters.send_failures.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_lost_perf_events(&self, count: u64) {
        self.counters
            .lost_perf_events
            .fetch_add(count, Ordering::Relaxed);
    }

    #[cfg(any(target_os = "linux", test))]
    pub(crate) fn record_diagnostic_decision(&self, decision: DiagnosticSampleDecision) {
        match decision {
            DiagnosticSampleDecision::Matched => {
                self.counters
                    .diagnostic_matches
                    .fetch_add(1, Ordering::Relaxed);
            }
            DiagnosticSampleDecision::Filtered => {
                self.counters
                    .diagnostic_filtered
                    .fetch_add(1, Ordering::Relaxed);
            }
            DiagnosticSampleDecision::Exhausted => {
                self.counters
                    .diagnostic_exhausted
                    .fetch_add(1, Ordering::Relaxed);
            }
            DiagnosticSampleDecision::Disabled => {}
        }
    }

    pub(crate) fn record_optional_target_discovered(&self) {
        self.counters
            .optional_targets_discovered
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_optional_target_ready(&self) {
        self.counters
            .optional_targets_ready
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_optional_target_unsupported(&self) {
        self.counters
            .optional_targets_unsupported
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_optional_probe_attachments(&self, count: usize) {
        self.counters
            .optional_probe_attachments
            .fetch_add(u64::try_from(count).unwrap_or(u64::MAX), Ordering::Relaxed);
    }

    pub(crate) fn record_optional_attachment_failure(&self) {
        self.counters
            .optional_attachment_failures
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_optional_rescan(&self) {
        self.counters
            .optional_rescans
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_optional_capacity_rejections(&self, count: usize) {
        self.counters
            .optional_capacity_rejections
            .fetch_add(u64::try_from(count).unwrap_or(u64::MAX), Ordering::Relaxed);
    }

    pub(crate) fn maybe_log_summary(&self) {
        let elapsed_nanos = u64::try_from(self.started_at.elapsed().as_nanos()).unwrap_or(u64::MAX);
        if !self.try_claim_summary(elapsed_nanos) {
            return;
        }

        let snapshot = self.take_summary_delta();
        if snapshot.is_empty() {
            return;
        }

        info!(
            target: "e_navigator_sources_ebpf_aya::source_telemetry",
            source = self.source,
            initialized = snapshot.initialized,
            decoded_samples = snapshot.decoded_samples,
            invalid_samples = snapshot.invalid_samples,
            sent_signals = snapshot.sent_signals,
            send_failures = snapshot.send_failures,
            lost_perf_events = snapshot.lost_perf_events,
            diagnostic_matches = snapshot.diagnostic_matches,
            diagnostic_filtered = snapshot.diagnostic_filtered,
            diagnostic_exhausted = snapshot.diagnostic_exhausted,
            optional_targets_discovered = snapshot.optional_targets_discovered,
            optional_targets_ready = snapshot.optional_targets_ready,
            optional_targets_unsupported = snapshot.optional_targets_unsupported,
            optional_probe_attachments = snapshot.optional_probe_attachments,
            optional_attachment_failures = snapshot.optional_attachment_failures,
            optional_rescans = snapshot.optional_rescans,
            optional_capacity_rejections = snapshot.optional_capacity_rejections,
            "source telemetry summary"
        );
    }

    fn try_claim_summary(&self, elapsed_nanos: u64) -> bool {
        let mut next_summary_nanos = self.next_summary_nanos.load(Ordering::Relaxed);
        loop {
            if elapsed_nanos < next_summary_nanos {
                return false;
            }

            let following_summary_nanos = elapsed_nanos.saturating_add(self.summary_interval_nanos);
            match self.next_summary_nanos.compare_exchange_weak(
                next_summary_nanos,
                following_summary_nanos,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return true,
                Err(observed) => next_summary_nanos = observed,
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn snapshot_for_test(&self) -> SourceTelemetrySnapshot {
        self.snapshot()
    }

    fn snapshot(&self) -> SourceTelemetrySnapshot {
        snapshot_counters(self.source, &self.counters)
    }

    fn take_summary_delta(&self) -> SourceTelemetrySnapshot {
        let current = self.snapshot();
        let mut last = self
            .last_summary
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let delta = current.delta_since(*last);
        *last = current;
        delta
    }
}

/// Cumulative source telemetry for source instances created in this process.
pub fn source_telemetry_snapshots() -> Vec<SourceTelemetrySnapshot> {
    SOURCE_COUNTERS.get().map_or_else(Vec::new, |registry| {
        registry.lock().map_or_else(
            |_| Vec::new(),
            |counters| {
                counters
                    .iter()
                    .map(|(source, counters)| snapshot_counters(source, counters))
                    .collect()
            },
        )
    })
}

fn snapshot_counters(source: &'static str, counters: &SourceCounters) -> SourceTelemetrySnapshot {
    SourceTelemetrySnapshot {
        source,
        initialized: counters.initialized.load(Ordering::Relaxed) != 0,
        decoded_samples: counters.decoded_samples.load(Ordering::Relaxed),
        invalid_samples: counters.invalid_samples.load(Ordering::Relaxed),
        sent_signals: counters.sent_signals.load(Ordering::Relaxed),
        send_failures: counters.send_failures.load(Ordering::Relaxed),
        lost_perf_events: counters.lost_perf_events.load(Ordering::Relaxed),
        diagnostic_matches: counters.diagnostic_matches.load(Ordering::Relaxed),
        diagnostic_filtered: counters.diagnostic_filtered.load(Ordering::Relaxed),
        diagnostic_exhausted: counters.diagnostic_exhausted.load(Ordering::Relaxed),
        optional_targets_discovered: counters.optional_targets_discovered.load(Ordering::Relaxed),
        optional_targets_ready: counters.optional_targets_ready.load(Ordering::Relaxed),
        optional_targets_unsupported: counters
            .optional_targets_unsupported
            .load(Ordering::Relaxed),
        optional_probe_attachments: counters.optional_probe_attachments.load(Ordering::Relaxed),
        optional_attachment_failures: counters
            .optional_attachment_failures
            .load(Ordering::Relaxed),
        optional_rescans: counters.optional_rescans.load(Ordering::Relaxed),
        optional_capacity_rejections: counters
            .optional_capacity_rejections
            .load(Ordering::Relaxed),
    }
}

impl SourceTelemetrySnapshot {
    const fn empty(source: &'static str) -> Self {
        Self {
            source,
            initialized: false,
            decoded_samples: 0,
            invalid_samples: 0,
            sent_signals: 0,
            send_failures: 0,
            lost_perf_events: 0,
            diagnostic_matches: 0,
            diagnostic_filtered: 0,
            diagnostic_exhausted: 0,
            optional_targets_discovered: 0,
            optional_targets_ready: 0,
            optional_targets_unsupported: 0,
            optional_probe_attachments: 0,
            optional_attachment_failures: 0,
            optional_rescans: 0,
            optional_capacity_rejections: 0,
        }
    }

    fn delta_since(self, previous: Self) -> Self {
        Self {
            source: self.source,
            initialized: self.initialized,
            decoded_samples: self
                .decoded_samples
                .saturating_sub(previous.decoded_samples),
            invalid_samples: self
                .invalid_samples
                .saturating_sub(previous.invalid_samples),
            sent_signals: self.sent_signals.saturating_sub(previous.sent_signals),
            send_failures: self.send_failures.saturating_sub(previous.send_failures),
            lost_perf_events: self
                .lost_perf_events
                .saturating_sub(previous.lost_perf_events),
            diagnostic_matches: self
                .diagnostic_matches
                .saturating_sub(previous.diagnostic_matches),
            diagnostic_filtered: self
                .diagnostic_filtered
                .saturating_sub(previous.diagnostic_filtered),
            diagnostic_exhausted: self
                .diagnostic_exhausted
                .saturating_sub(previous.diagnostic_exhausted),
            optional_targets_discovered: self
                .optional_targets_discovered
                .saturating_sub(previous.optional_targets_discovered),
            optional_targets_ready: self
                .optional_targets_ready
                .saturating_sub(previous.optional_targets_ready),
            optional_targets_unsupported: self
                .optional_targets_unsupported
                .saturating_sub(previous.optional_targets_unsupported),
            optional_probe_attachments: self
                .optional_probe_attachments
                .saturating_sub(previous.optional_probe_attachments),
            optional_attachment_failures: self
                .optional_attachment_failures
                .saturating_sub(previous.optional_attachment_failures),
            optional_rescans: self
                .optional_rescans
                .saturating_sub(previous.optional_rescans),
            optional_capacity_rejections: self
                .optional_capacity_rejections
                .saturating_sub(previous.optional_capacity_rejections),
        }
    }

    fn is_empty(&self) -> bool {
        self.decoded_samples == 0
            && self.invalid_samples == 0
            && self.sent_signals == 0
            && self.send_failures == 0
            && self.lost_perf_events == 0
            && self.diagnostic_matches == 0
            && self.diagnostic_filtered == 0
            && self.diagnostic_exhausted == 0
            && self.optional_targets_discovered == 0
            && self.optional_targets_ready == 0
            && self.optional_targets_unsupported == 0
            && self.optional_probe_attachments == 0
            && self.optional_attachment_failures == 0
            && self.optional_rescans == 0
            && self.optional_capacity_rejections == 0
    }
}

#[cfg(feature = "fuzzing")]
pub fn bench_source_telemetry_summary_checks(
    worker_count: usize,
    calls_per_worker: usize,
) -> usize {
    use std::sync::Arc;

    let telemetry = Arc::new(SourceTelemetry::new("source.bench"));
    std::thread::scope(|scope| {
        for _ in 0..worker_count {
            let telemetry = Arc::clone(&telemetry);
            scope.spawn(move || {
                for _ in 0..calls_per_worker {
                    telemetry.maybe_log_summary();
                }
            });
        }
    });
    worker_count.saturating_mul(calls_per_worker)
}

#[cfg(test)]
mod tests {
    use super::{SourceTelemetry, source_telemetry_snapshots};
    use crate::diagnostics::DiagnosticSampleDecision;
    use std::time::Duration;

    #[test]
    fn source_telemetry_is_cumulative_while_log_summaries_are_deltas() {
        let telemetry = SourceTelemetry::with_summary_interval(
            "source.test.cumulative",
            Duration::from_secs(10),
        );

        telemetry.mark_initialized();
        telemetry.record_decoded_sample();
        telemetry.record_invalid_sample();
        telemetry.record_sent_signal();
        telemetry.record_send_failure();
        telemetry.record_lost_perf_events(3);
        telemetry.record_diagnostic_decision(DiagnosticSampleDecision::Matched);
        telemetry.record_diagnostic_decision(DiagnosticSampleDecision::Filtered);
        telemetry.record_diagnostic_decision(DiagnosticSampleDecision::Exhausted);
        telemetry.record_diagnostic_decision(DiagnosticSampleDecision::Disabled);

        let snapshot = telemetry.snapshot_for_test();
        assert!(snapshot.initialized);
        assert_eq!(snapshot.decoded_samples, 1);
        assert_eq!(snapshot.invalid_samples, 1);
        assert_eq!(snapshot.sent_signals, 1);
        assert_eq!(snapshot.send_failures, 1);
        assert_eq!(snapshot.lost_perf_events, 3);
        assert_eq!(snapshot.diagnostic_matches, 1);
        assert_eq!(snapshot.diagnostic_filtered, 1);
        assert_eq!(snapshot.diagnostic_exhausted, 1);

        let first_delta = telemetry.take_summary_delta();
        assert_eq!(first_delta.decoded_samples, 1);
        assert_eq!(first_delta.lost_perf_events, 3);
        let empty_delta = telemetry.take_summary_delta();
        assert_eq!(empty_delta.decoded_samples, 0);
        assert_eq!(empty_delta.lost_perf_events, 0);

        let cumulative = telemetry.snapshot_for_test();
        assert_eq!(cumulative.decoded_samples, 1);
        assert_eq!(cumulative.lost_perf_events, 3);
        let registered = source_telemetry_snapshots()
            .into_iter()
            .find(|snapshot| snapshot.source == "source.test.cumulative")
            .expect("registered cumulative counters");
        assert!(registered.initialized);
        assert_eq!(registered.sent_signals, 1);
    }

    #[test]
    fn summary_gate_allows_one_claim_per_interval_without_catch_up() {
        let telemetry =
            SourceTelemetry::with_summary_interval("source.test.gate", Duration::from_nanos(10));

        assert!(!telemetry.try_claim_summary(9));
        assert!(telemetry.try_claim_summary(10));
        assert!(!telemetry.try_claim_summary(19));
        assert!(telemetry.try_claim_summary(20));
        assert!(telemetry.try_claim_summary(50));
        assert!(!telemetry.try_claim_summary(50));
        assert!(!telemetry.try_claim_summary(59));
        assert!(telemetry.try_claim_summary(60));
    }
}
