#[cfg(any(target_os = "linux", test))]
use crate::diagnostics::DiagnosticSampleDecision;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tracing::info;

#[derive(Debug)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) struct SourceTelemetry {
    source: &'static str,
    started_at: Instant,
    summary_interval_nanos: u64,
    next_summary_nanos: AtomicU64,
    decoded_samples: AtomicU64,
    invalid_samples: AtomicU64,
    sent_signals: AtomicU64,
    send_failures: AtomicU64,
    lost_perf_events: AtomicU64,
    diagnostic_matches: AtomicU64,
    diagnostic_filtered: AtomicU64,
    diagnostic_exhausted: AtomicU64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SourceTelemetrySnapshot {
    pub(crate) decoded_samples: u64,
    pub(crate) invalid_samples: u64,
    pub(crate) sent_signals: u64,
    pub(crate) send_failures: u64,
    pub(crate) lost_perf_events: u64,
    pub(crate) diagnostic_matches: u64,
    pub(crate) diagnostic_filtered: u64,
    pub(crate) diagnostic_exhausted: u64,
}

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
        Self {
            source,
            started_at: Instant::now(),
            summary_interval_nanos,
            next_summary_nanos: AtomicU64::new(summary_interval_nanos),
            decoded_samples: AtomicU64::new(0),
            invalid_samples: AtomicU64::new(0),
            sent_signals: AtomicU64::new(0),
            send_failures: AtomicU64::new(0),
            lost_perf_events: AtomicU64::new(0),
            diagnostic_matches: AtomicU64::new(0),
            diagnostic_filtered: AtomicU64::new(0),
            diagnostic_exhausted: AtomicU64::new(0),
        }
    }

    pub(crate) fn record_decoded_sample(&self) {
        self.decoded_samples.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_invalid_sample(&self) {
        self.invalid_samples.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_sent_signal(&self) {
        self.sent_signals.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_send_failure(&self) {
        self.send_failures.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_lost_perf_events(&self, count: u64) {
        self.lost_perf_events.fetch_add(count, Ordering::Relaxed);
    }

    #[cfg(any(target_os = "linux", test))]
    pub(crate) fn record_diagnostic_decision(&self, decision: DiagnosticSampleDecision) {
        match decision {
            DiagnosticSampleDecision::Matched => {
                self.diagnostic_matches.fetch_add(1, Ordering::Relaxed);
            }
            DiagnosticSampleDecision::Filtered => {
                self.diagnostic_filtered.fetch_add(1, Ordering::Relaxed);
            }
            DiagnosticSampleDecision::Exhausted => {
                self.diagnostic_exhausted.fetch_add(1, Ordering::Relaxed);
            }
            DiagnosticSampleDecision::Disabled => {}
        }
    }

    pub(crate) fn maybe_log_summary(&self) {
        let elapsed_nanos = u64::try_from(self.started_at.elapsed().as_nanos()).unwrap_or(u64::MAX);
        if !self.try_claim_summary(elapsed_nanos) {
            return;
        }

        let snapshot = self.take_snapshot();
        if snapshot.is_empty() {
            return;
        }

        info!(
            target: "e_navigator_sources_ebpf_aya::source_telemetry",
            source = self.source,
            decoded_samples = snapshot.decoded_samples,
            invalid_samples = snapshot.invalid_samples,
            sent_signals = snapshot.sent_signals,
            send_failures = snapshot.send_failures,
            lost_perf_events = snapshot.lost_perf_events,
            diagnostic_matches = snapshot.diagnostic_matches,
            diagnostic_filtered = snapshot.diagnostic_filtered,
            diagnostic_exhausted = snapshot.diagnostic_exhausted,
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
        self.take_snapshot()
    }

    fn take_snapshot(&self) -> SourceTelemetrySnapshot {
        SourceTelemetrySnapshot {
            decoded_samples: self.decoded_samples.swap(0, Ordering::Relaxed),
            invalid_samples: self.invalid_samples.swap(0, Ordering::Relaxed),
            sent_signals: self.sent_signals.swap(0, Ordering::Relaxed),
            send_failures: self.send_failures.swap(0, Ordering::Relaxed),
            lost_perf_events: self.lost_perf_events.swap(0, Ordering::Relaxed),
            diagnostic_matches: self.diagnostic_matches.swap(0, Ordering::Relaxed),
            diagnostic_filtered: self.diagnostic_filtered.swap(0, Ordering::Relaxed),
            diagnostic_exhausted: self.diagnostic_exhausted.swap(0, Ordering::Relaxed),
        }
    }
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
impl SourceTelemetrySnapshot {
    fn is_empty(&self) -> bool {
        self.decoded_samples == 0
            && self.invalid_samples == 0
            && self.sent_signals == 0
            && self.send_failures == 0
            && self.lost_perf_events == 0
            && self.diagnostic_matches == 0
            && self.diagnostic_filtered == 0
            && self.diagnostic_exhausted == 0
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
    use super::SourceTelemetry;
    use crate::diagnostics::DiagnosticSampleDecision;
    use std::time::Duration;

    #[test]
    fn source_telemetry_records_and_resets_delta_counters() {
        let telemetry =
            SourceTelemetry::with_summary_interval("source.test", Duration::from_secs(10));

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
        assert_eq!(snapshot.decoded_samples, 1);
        assert_eq!(snapshot.invalid_samples, 1);
        assert_eq!(snapshot.sent_signals, 1);
        assert_eq!(snapshot.send_failures, 1);
        assert_eq!(snapshot.lost_perf_events, 3);
        assert_eq!(snapshot.diagnostic_matches, 1);
        assert_eq!(snapshot.diagnostic_filtered, 1);
        assert_eq!(snapshot.diagnostic_exhausted, 1);

        let empty = telemetry.snapshot_for_test();
        assert_eq!(empty.decoded_samples, 0);
        assert_eq!(empty.lost_perf_events, 0);
    }

    #[test]
    fn summary_gate_allows_one_claim_per_interval_without_catch_up() {
        let telemetry =
            SourceTelemetry::with_summary_interval("source.test", Duration::from_nanos(10));

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
