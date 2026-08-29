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

macro_rules! define_source_telemetry_counters {
    ($($counter:ident),+ $(,)?) => {
        #[derive(Debug)]
        struct SourceCounters {
            event_transport: &'static str,
            initialized: AtomicU64,
            $($counter: AtomicU64,)+
        }

        impl SourceCounters {
            fn new(event_transport: &'static str) -> Self {
                Self {
                    event_transport,
                    initialized: AtomicU64::new(0),
                    $($counter: AtomicU64::new(0),)+
                }
            }
        }

        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub struct SourceTelemetrySnapshot {
            pub source: &'static str,
            pub event_transport: &'static str,
            pub initialized: bool,
            $(pub $counter: u64,)+
        }

        impl SourceTelemetrySnapshot {
            const fn empty(source: &'static str) -> Self {
                Self {
                    source,
                    event_transport: "unknown",
                    initialized: false,
                    $($counter: 0,)+
                }
            }

            fn delta_since(self, previous: Self) -> Self {
                Self {
                    source: self.source,
                    event_transport: self.event_transport,
                    initialized: self.initialized,
                    $($counter: self.$counter.saturating_sub(previous.$counter),)+
                }
            }

            fn is_empty(&self) -> bool {
                true $(&& self.$counter == 0)+
            }

            /// Returns the fixed native metric name and cumulative value for every counter.
            pub fn native_metric_values(
                &self,
            ) -> impl Iterator<Item = (&'static str, u64)> + '_ {
                std::iter::once((
                    "e_navigator_ebpf_source_initialized",
                    u64::from(self.initialized),
                ))
                .chain([
                    $((
                        concat!(
                            "e_navigator_ebpf_source_",
                            stringify!($counter),
                            "_total"
                        ),
                        self.$counter,
                    ),)+
                ])
            }

            fn log_summary(&self) {
                info!(
                    target: "e_navigator_sources_ebpf_aya::source_telemetry",
                    source = self.source,
                    event_transport = self.event_transport,
                    initialized = self.initialized,
                    $($counter = self.$counter,)+
                    "source telemetry summary"
                );
            }
        }

        fn snapshot_counters(
            source: &'static str,
            counters: &SourceCounters,
        ) -> SourceTelemetrySnapshot {
            SourceTelemetrySnapshot {
                source,
                event_transport: counters.event_transport,
                initialized: counters.initialized.load(Ordering::Relaxed) != 0,
                $($counter: counters.$counter.load(Ordering::Relaxed),)+
            }
        }
    };
}

define_source_telemetry_counters! {
    decoded_samples,
    filtered_samples,
    invalid_samples,
    sent_signals,
    send_failures,
    lost_transport_events,
    lost_perf_events,
    ring_buffer_reservation_failures,
    network_mmsg_accounted_batches,
    network_mmsg_unsupported_batches,
    diagnostic_matches,
    diagnostic_filtered,
    diagnostic_exhausted,
    optional_targets_discovered,
    optional_targets_ready,
    optional_targets_unsupported,
    optional_probe_attachments,
    optional_attachment_failures,
    optional_rescans,
    optional_capacity_rejections,
    go_tls_entries,
    go_tls_exits,
    go_tls_layout_misses,
    go_tls_pending_misses,
    go_tls_state_update_failures,
    go_tls_fd_resolutions,
    go_tls_fd_resolution_failures,
    go_tls_output_attempts,
    go_tls_state_replacements,
    profile_events,
    profile_capture_failures,
    profile_state_replacements,
    profile_pending_misses,
    profile_below_min_duration,
    profile_rate_limited,
    profile_output_attempts,
    protocol_websocket_upgrades,
    protocol_websocket_frames,
    protocol_websocket_transition_rejections,
    protocol_grpc_web_requests,
    protocol_redis_ambiguous_state_transitions,
    protocol_discovered_connections,
    protocol_discovery_unclassified_events,
    protocol_discovery_candidate_evictions,
    protocol_postgres_startup_auth_messages,
    protocol_postgres_encryption_negotiation_accepted,
    protocol_postgres_encryption_negotiation_rejected,
    protocol_postgres_negotiation_failures,
    protocol_postgres_encrypted_transport_events,
    protocol_postgres_copy_ignored_controls,
    protocol_mysql_local_infile_packets,
    protocol_mysql_local_infile_bytes,
    protocol_mysql_logical_request_continuations,
    protocol_mysql_logical_response_continuations,
    protocol_mysql_logical_sequence_failures,
    protocol_mysql_server_greetings,
    protocol_mysql_client_handshakes,
    protocol_mysql_auth_packets,
    protocol_mysql_compression_zlib_connections,
    protocol_mysql_compression_zstd_rejections,
    protocol_mysql_compression_unverified_rejections,
    protocol_mysql_compressed_packets,
    protocol_mysql_compression_failures,
    protocol_mysql_compression_opaque_events,
    protocol_mysql_handshake_failures,
    protocol_mongodb_fire_and_forget_requests,
    protocol_mongodb_response_continuations,
    protocol_mongodb_lifecycle_failures,
}

static SOURCE_COUNTERS: OnceLock<Mutex<BTreeMap<&'static str, Arc<SourceCounters>>>> =
    OnceLock::new();

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
impl SourceTelemetry {
    pub(crate) const DEFAULT_SUMMARY_INTERVAL: Duration = Duration::from_secs(10);

    #[cfg(feature = "fuzzing")]
    pub(crate) fn new(source: &'static str) -> Self {
        Self::with_transport_and_summary_interval(source, "unknown", Self::DEFAULT_SUMMARY_INTERVAL)
    }

    pub(crate) fn new_with_transport(source: &'static str, event_transport: &'static str) -> Self {
        Self::with_transport_and_summary_interval(
            source,
            event_transport,
            Self::DEFAULT_SUMMARY_INTERVAL,
        )
    }

    #[cfg(test)]
    fn with_summary_interval(source: &'static str, summary_interval: Duration) -> Self {
        Self::with_transport_and_summary_interval(source, "unknown", summary_interval)
    }

    fn with_transport_and_summary_interval(
        source: &'static str,
        event_transport: &'static str,
        summary_interval: Duration,
    ) -> Self {
        let summary_interval_nanos = u64::try_from(summary_interval.as_nanos())
            .unwrap_or(u64::MAX)
            .max(1);
        let counters = Arc::new(SourceCounters::new(event_transport));
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

    pub(crate) fn record_filtered_sample(&self) {
        self.counters
            .filtered_samples
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
            .lost_transport_events
            .fetch_add(count, Ordering::Relaxed);
        self.counters
            .lost_perf_events
            .fetch_add(count, Ordering::Relaxed);
    }

    pub(crate) fn record_ring_buffer_reservation_failures(&self, count: u64) {
        self.counters
            .lost_transport_events
            .fetch_add(count, Ordering::Relaxed);
        self.counters
            .ring_buffer_reservation_failures
            .fetch_add(count, Ordering::Relaxed);
    }

    pub(crate) fn record_network_mmsg_counter_deltas(&self, deltas: [u64; 2]) {
        for (counter, delta) in [
            &self.counters.network_mmsg_accounted_batches,
            &self.counters.network_mmsg_unsupported_batches,
        ]
        .into_iter()
        .zip(deltas)
        {
            counter.fetch_add(delta, Ordering::Relaxed);
        }
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

    pub(crate) fn record_go_tls_counter_deltas(&self, deltas: [u64; 9]) {
        for (counter, delta) in [
            &self.counters.go_tls_entries,
            &self.counters.go_tls_exits,
            &self.counters.go_tls_layout_misses,
            &self.counters.go_tls_pending_misses,
            &self.counters.go_tls_state_update_failures,
            &self.counters.go_tls_fd_resolutions,
            &self.counters.go_tls_fd_resolution_failures,
            &self.counters.go_tls_output_attempts,
            &self.counters.go_tls_state_replacements,
        ]
        .into_iter()
        .zip(deltas)
        {
            counter.fetch_add(delta, Ordering::Relaxed);
        }
    }

    pub(crate) fn record_profile_counter_deltas(&self, deltas: [u64; 7]) {
        for (counter, delta) in [
            &self.counters.profile_events,
            &self.counters.profile_capture_failures,
            &self.counters.profile_state_replacements,
            &self.counters.profile_pending_misses,
            &self.counters.profile_below_min_duration,
            &self.counters.profile_rate_limited,
            &self.counters.profile_output_attempts,
        ]
        .into_iter()
        .zip(deltas)
        {
            counter.fetch_add(delta, Ordering::Relaxed);
        }
    }

    pub(crate) fn record_protocol_surface_counter_deltas(
        &self,
        deltas: crate::protocol::ProtocolSurfaceCounters,
    ) {
        macro_rules! record {
            ($counter:ident, $delta:ident) => {
                self.counters
                    .$counter
                    .fetch_add(deltas.$delta, Ordering::Relaxed);
            };
        }

        record!(protocol_websocket_upgrades, websocket_upgrades);
        record!(protocol_websocket_frames, websocket_frames);
        record!(
            protocol_websocket_transition_rejections,
            websocket_transition_rejections
        );
        record!(protocol_grpc_web_requests, grpc_web_requests);
        record!(
            protocol_redis_ambiguous_state_transitions,
            redis_ambiguous_state_transitions
        );
        record!(protocol_discovered_connections, discovered_connections);
        record!(
            protocol_discovery_unclassified_events,
            discovery_unclassified_events
        );
        record!(
            protocol_discovery_candidate_evictions,
            discovery_candidate_evictions
        );
        record!(
            protocol_postgres_startup_auth_messages,
            postgres_startup_auth_messages
        );
        record!(
            protocol_postgres_encryption_negotiation_accepted,
            postgres_encryption_negotiation_accepted
        );
        record!(
            protocol_postgres_encryption_negotiation_rejected,
            postgres_encryption_negotiation_rejected
        );
        record!(
            protocol_postgres_negotiation_failures,
            postgres_negotiation_failures
        );
        record!(
            protocol_postgres_encrypted_transport_events,
            postgres_encrypted_transport_events
        );
        record!(
            protocol_postgres_copy_ignored_controls,
            postgres_copy_ignored_controls
        );
        record!(
            protocol_mysql_local_infile_packets,
            mysql_local_infile_packets
        );
        record!(protocol_mysql_local_infile_bytes, mysql_local_infile_bytes);
        record!(
            protocol_mysql_logical_request_continuations,
            mysql_logical_request_continuations
        );
        record!(
            protocol_mysql_logical_response_continuations,
            mysql_logical_response_continuations
        );
        record!(
            protocol_mysql_logical_sequence_failures,
            mysql_logical_sequence_failures
        );
        record!(protocol_mysql_server_greetings, mysql_server_greetings);
        record!(protocol_mysql_client_handshakes, mysql_client_handshakes);
        record!(protocol_mysql_auth_packets, mysql_auth_packets);
        record!(
            protocol_mysql_compression_zlib_connections,
            mysql_compression_zlib_connections
        );
        record!(
            protocol_mysql_compression_zstd_rejections,
            mysql_compression_zstd_rejections
        );
        record!(
            protocol_mysql_compression_unverified_rejections,
            mysql_compression_unverified_rejections
        );
        record!(protocol_mysql_compressed_packets, mysql_compressed_packets);
        record!(
            protocol_mysql_compression_failures,
            mysql_compression_failures
        );
        record!(
            protocol_mysql_compression_opaque_events,
            mysql_compression_opaque_events
        );
        record!(protocol_mysql_handshake_failures, mysql_handshake_failures);
        record!(
            protocol_mongodb_fire_and_forget_requests,
            mongodb_fire_and_forget_requests
        );
        record!(
            protocol_mongodb_response_continuations,
            mongodb_response_continuations
        );
        record!(
            protocol_mongodb_lifecycle_failures,
            mongodb_lifecycle_failures
        );
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

        snapshot.log_summary();
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
    use crate::protocol::ProtocolSurfaceCounters;
    use std::time::Duration;

    #[test]
    fn source_telemetry_is_cumulative_while_log_summaries_are_deltas() {
        let telemetry = SourceTelemetry::with_summary_interval(
            "source.test.cumulative",
            Duration::from_secs(10),
        );

        telemetry.mark_initialized();
        telemetry.record_decoded_sample();
        telemetry.record_filtered_sample();
        telemetry.record_invalid_sample();
        telemetry.record_sent_signal();
        telemetry.record_send_failure();
        telemetry.record_lost_perf_events(3);
        telemetry.record_ring_buffer_reservation_failures(2);
        telemetry.record_network_mmsg_counter_deltas([15, 2]);
        telemetry.record_diagnostic_decision(DiagnosticSampleDecision::Matched);
        telemetry.record_diagnostic_decision(DiagnosticSampleDecision::Filtered);
        telemetry.record_diagnostic_decision(DiagnosticSampleDecision::Exhausted);
        telemetry.record_diagnostic_decision(DiagnosticSampleDecision::Disabled);
        telemetry.record_profile_counter_deltas([8, 1, 2, 3, 4, 5, 6]);
        telemetry.record_protocol_surface_counter_deltas(ProtocolSurfaceCounters {
            websocket_upgrades: 9,
            websocket_frames: 10,
            websocket_transition_rejections: 1,
            grpc_web_requests: 11,
            redis_ambiguous_state_transitions: 12,
            discovered_connections: 12,
            discovery_unclassified_events: 13,
            discovery_candidate_evictions: 14,
            postgres_startup_auth_messages: 15,
            postgres_encryption_negotiation_accepted: 16,
            postgres_encryption_negotiation_rejected: 17,
            postgres_negotiation_failures: 18,
            postgres_encrypted_transport_events: 19,
            postgres_copy_ignored_controls: 20,
            mysql_local_infile_packets: 21,
            mysql_local_infile_bytes: 22,
            mysql_logical_request_continuations: 23,
            mysql_logical_response_continuations: 24,
            mysql_logical_sequence_failures: 25,
            mysql_server_greetings: 26,
            mysql_client_handshakes: 27,
            mysql_auth_packets: 28,
            mysql_compression_zlib_connections: 29,
            mysql_compression_zstd_rejections: 30,
            mysql_compression_unverified_rejections: 31,
            mysql_compressed_packets: 32,
            mysql_compression_failures: 33,
            mysql_compression_opaque_events: 34,
            mysql_handshake_failures: 35,
            mongodb_fire_and_forget_requests: 36,
            mongodb_response_continuations: 37,
            mongodb_lifecycle_failures: 38,
        });

        let snapshot = telemetry.snapshot_for_test();
        assert!(snapshot.initialized);
        assert_eq!(snapshot.decoded_samples, 1);
        assert_eq!(snapshot.filtered_samples, 1);
        assert_eq!(snapshot.invalid_samples, 1);
        assert_eq!(snapshot.sent_signals, 1);
        assert_eq!(snapshot.send_failures, 1);
        assert_eq!(snapshot.lost_transport_events, 5);
        assert_eq!(snapshot.lost_perf_events, 3);
        assert_eq!(snapshot.ring_buffer_reservation_failures, 2);
        assert_eq!(snapshot.network_mmsg_accounted_batches, 15);
        assert_eq!(snapshot.network_mmsg_unsupported_batches, 2);
        assert_eq!(snapshot.diagnostic_matches, 1);
        assert_eq!(snapshot.diagnostic_filtered, 1);
        assert_eq!(snapshot.diagnostic_exhausted, 1);
        assert_eq!(snapshot.profile_events, 8);
        assert_eq!(snapshot.profile_capture_failures, 1);
        assert_eq!(snapshot.profile_state_replacements, 2);
        assert_eq!(snapshot.profile_pending_misses, 3);
        assert_eq!(snapshot.profile_below_min_duration, 4);
        assert_eq!(snapshot.profile_rate_limited, 5);
        assert_eq!(snapshot.profile_output_attempts, 6);
        assert_eq!(snapshot.protocol_websocket_upgrades, 9);
        assert_eq!(snapshot.protocol_websocket_frames, 10);
        assert_eq!(snapshot.protocol_websocket_transition_rejections, 1);
        assert_eq!(snapshot.protocol_grpc_web_requests, 11);
        assert_eq!(snapshot.protocol_redis_ambiguous_state_transitions, 12);
        assert_eq!(snapshot.protocol_discovered_connections, 12);
        assert_eq!(snapshot.protocol_discovery_unclassified_events, 13);
        assert_eq!(snapshot.protocol_discovery_candidate_evictions, 14);
        assert_eq!(snapshot.protocol_postgres_startup_auth_messages, 15);
        assert_eq!(
            snapshot.protocol_postgres_encryption_negotiation_accepted,
            16
        );
        assert_eq!(
            snapshot.protocol_postgres_encryption_negotiation_rejected,
            17
        );
        assert_eq!(snapshot.protocol_postgres_negotiation_failures, 18);
        assert_eq!(snapshot.protocol_postgres_encrypted_transport_events, 19);
        assert_eq!(snapshot.protocol_postgres_copy_ignored_controls, 20);
        assert_eq!(snapshot.protocol_mysql_local_infile_packets, 21);
        assert_eq!(snapshot.protocol_mysql_local_infile_bytes, 22);
        assert_eq!(snapshot.protocol_mysql_logical_request_continuations, 23);
        assert_eq!(snapshot.protocol_mysql_logical_response_continuations, 24);
        assert_eq!(snapshot.protocol_mysql_logical_sequence_failures, 25);
        assert_eq!(snapshot.protocol_mysql_server_greetings, 26);
        assert_eq!(snapshot.protocol_mysql_client_handshakes, 27);
        assert_eq!(snapshot.protocol_mysql_auth_packets, 28);
        assert_eq!(snapshot.protocol_mysql_compression_zlib_connections, 29);
        assert_eq!(snapshot.protocol_mysql_compression_zstd_rejections, 30);
        assert_eq!(
            snapshot.protocol_mysql_compression_unverified_rejections,
            31
        );
        assert_eq!(snapshot.protocol_mysql_compressed_packets, 32);
        assert_eq!(snapshot.protocol_mysql_compression_failures, 33);
        assert_eq!(snapshot.protocol_mysql_compression_opaque_events, 34);
        assert_eq!(snapshot.protocol_mysql_handshake_failures, 35);
        assert_eq!(snapshot.protocol_mongodb_fire_and_forget_requests, 36);
        assert_eq!(snapshot.protocol_mongodb_response_continuations, 37);
        assert_eq!(snapshot.protocol_mongodb_lifecycle_failures, 38);

        let first_delta = telemetry.take_summary_delta();
        assert_eq!(first_delta.decoded_samples, 1);
        assert_eq!(first_delta.filtered_samples, 1);
        assert_eq!(first_delta.lost_perf_events, 3);
        assert_eq!(first_delta.lost_transport_events, 5);
        assert_eq!(first_delta.ring_buffer_reservation_failures, 2);
        let empty_delta = telemetry.take_summary_delta();
        assert_eq!(empty_delta.decoded_samples, 0);
        assert_eq!(empty_delta.lost_perf_events, 0);
        assert_eq!(empty_delta.lost_transport_events, 0);
        assert_eq!(empty_delta.ring_buffer_reservation_failures, 0);

        let cumulative = telemetry.snapshot_for_test();
        assert_eq!(cumulative.decoded_samples, 1);
        assert_eq!(cumulative.filtered_samples, 1);
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
