#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
use super::ProtocolRegistryCounters;

/// Named protocol counters shared with source telemetry.
///
/// Keeping this boundary typed prevents a reordered positional array from
/// silently publishing one protocol diagnostic under another metric name.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct ProtocolSurfaceCounters {
    pub(crate) websocket_upgrades: u64,
    pub(crate) websocket_frames: u64,
    pub(crate) websocket_transition_rejections: u64,
    pub(crate) grpc_web_requests: u64,
    pub(crate) redis_ambiguous_state_transitions: u64,
    pub(crate) discovered_connections: u64,
    pub(crate) discovery_unclassified_events: u64,
    pub(crate) discovery_candidate_evictions: u64,
    pub(crate) postgres_startup_auth_messages: u64,
    pub(crate) postgres_encryption_negotiation_accepted: u64,
    pub(crate) postgres_encryption_negotiation_rejected: u64,
    pub(crate) postgres_negotiation_failures: u64,
    pub(crate) postgres_encrypted_transport_events: u64,
    pub(crate) postgres_copy_ignored_controls: u64,
    pub(crate) mysql_local_infile_packets: u64,
    pub(crate) mysql_local_infile_bytes: u64,
    pub(crate) mysql_logical_request_continuations: u64,
    pub(crate) mysql_logical_response_continuations: u64,
    pub(crate) mysql_logical_sequence_failures: u64,
    pub(crate) mysql_server_greetings: u64,
    pub(crate) mysql_client_handshakes: u64,
    pub(crate) mysql_auth_packets: u64,
    pub(crate) mysql_compression_zlib_connections: u64,
    pub(crate) mysql_compression_zstd_rejections: u64,
    pub(crate) mysql_compression_unverified_rejections: u64,
    pub(crate) mysql_compressed_packets: u64,
    pub(crate) mysql_compression_failures: u64,
    pub(crate) mysql_compression_opaque_events: u64,
    pub(crate) mysql_handshake_failures: u64,
    pub(crate) mongodb_fire_and_forget_requests: u64,
    pub(crate) mongodb_response_continuations: u64,
    pub(crate) mongodb_lifecycle_failures: u64,
}

impl ProtocolSurfaceCounters {
    pub(crate) fn delta_since(self, previous: Self) -> Self {
        macro_rules! delta {
            ($field:ident) => {
                self.$field.saturating_sub(previous.$field)
            };
        }

        Self {
            websocket_upgrades: delta!(websocket_upgrades),
            websocket_frames: delta!(websocket_frames),
            websocket_transition_rejections: delta!(websocket_transition_rejections),
            grpc_web_requests: delta!(grpc_web_requests),
            redis_ambiguous_state_transitions: delta!(redis_ambiguous_state_transitions),
            discovered_connections: delta!(discovered_connections),
            discovery_unclassified_events: delta!(discovery_unclassified_events),
            discovery_candidate_evictions: delta!(discovery_candidate_evictions),
            postgres_startup_auth_messages: delta!(postgres_startup_auth_messages),
            postgres_encryption_negotiation_accepted: delta!(
                postgres_encryption_negotiation_accepted
            ),
            postgres_encryption_negotiation_rejected: delta!(
                postgres_encryption_negotiation_rejected
            ),
            postgres_negotiation_failures: delta!(postgres_negotiation_failures),
            postgres_encrypted_transport_events: delta!(postgres_encrypted_transport_events),
            postgres_copy_ignored_controls: delta!(postgres_copy_ignored_controls),
            mysql_local_infile_packets: delta!(mysql_local_infile_packets),
            mysql_local_infile_bytes: delta!(mysql_local_infile_bytes),
            mysql_logical_request_continuations: delta!(mysql_logical_request_continuations),
            mysql_logical_response_continuations: delta!(mysql_logical_response_continuations),
            mysql_logical_sequence_failures: delta!(mysql_logical_sequence_failures),
            mysql_server_greetings: delta!(mysql_server_greetings),
            mysql_client_handshakes: delta!(mysql_client_handshakes),
            mysql_auth_packets: delta!(mysql_auth_packets),
            mysql_compression_zlib_connections: delta!(mysql_compression_zlib_connections),
            mysql_compression_zstd_rejections: delta!(mysql_compression_zstd_rejections),
            mysql_compression_unverified_rejections: delta!(
                mysql_compression_unverified_rejections
            ),
            mysql_compressed_packets: delta!(mysql_compressed_packets),
            mysql_compression_failures: delta!(mysql_compression_failures),
            mysql_compression_opaque_events: delta!(mysql_compression_opaque_events),
            mysql_handshake_failures: delta!(mysql_handshake_failures),
            mongodb_fire_and_forget_requests: delta!(mongodb_fire_and_forget_requests),
            mongodb_response_continuations: delta!(mongodb_response_continuations),
            mongodb_lifecycle_failures: delta!(mongodb_lifecycle_failures),
        }
    }
}

#[cfg(any(target_os = "linux", test, feature = "fuzzing"))]
impl From<ProtocolRegistryCounters> for ProtocolSurfaceCounters {
    fn from(counters: ProtocolRegistryCounters) -> Self {
        Self {
            websocket_upgrades: counters.websocket_upgrades,
            websocket_frames: counters.websocket_frames,
            websocket_transition_rejections: counters.websocket_transition_rejections,
            grpc_web_requests: counters.grpc_web_requests,
            redis_ambiguous_state_transitions: counters.redis_ambiguous_state_transitions,
            discovered_connections: counters.discovered_connections,
            discovery_unclassified_events: counters.discovery_unclassified_events,
            discovery_candidate_evictions: counters.discovery_candidate_evictions,
            postgres_startup_auth_messages: counters.postgres_startup_auth_messages,
            postgres_encryption_negotiation_accepted: counters
                .postgres_encryption_negotiation_accepted,
            postgres_encryption_negotiation_rejected: counters
                .postgres_encryption_negotiation_rejected,
            postgres_negotiation_failures: counters.postgres_negotiation_failures,
            postgres_encrypted_transport_events: counters.postgres_encrypted_transport_events,
            postgres_copy_ignored_controls: counters.postgres_copy_ignored_controls,
            mysql_local_infile_packets: counters.mysql_local_infile_packets,
            mysql_local_infile_bytes: counters.mysql_local_infile_bytes,
            mysql_logical_request_continuations: counters.mysql_logical_request_continuations,
            mysql_logical_response_continuations: counters.mysql_logical_response_continuations,
            mysql_logical_sequence_failures: counters.mysql_logical_sequence_failures,
            mysql_server_greetings: counters.mysql_server_greetings,
            mysql_client_handshakes: counters.mysql_client_handshakes,
            mysql_auth_packets: counters.mysql_auth_packets,
            mysql_compression_zlib_connections: counters.mysql_compression_zlib_connections,
            mysql_compression_zstd_rejections: counters.mysql_compression_zstd_rejections,
            mysql_compression_unverified_rejections: counters
                .mysql_compression_unverified_rejections,
            mysql_compressed_packets: counters.mysql_compressed_packets,
            mysql_compression_failures: counters.mysql_compression_failures,
            mysql_compression_opaque_events: counters.mysql_compression_opaque_events,
            mysql_handshake_failures: counters.mysql_handshake_failures,
            mongodb_fire_and_forget_requests: counters.mongodb_fire_and_forget_requests,
            mongodb_response_continuations: counters.mongodb_response_continuations,
            mongodb_lifecycle_failures: counters.mongodb_lifecycle_failures,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_conversion_preserves_every_named_surface_counter() {
        let counters = ProtocolRegistryCounters {
            websocket_upgrades: 1,
            websocket_frames: 2,
            websocket_transition_rejections: 3,
            grpc_web_requests: 4,
            redis_ambiguous_state_transitions: 5,
            discovered_connections: 6,
            discovery_unclassified_events: 7,
            discovery_candidate_evictions: 8,
            postgres_startup_auth_messages: 9,
            postgres_encryption_negotiation_accepted: 10,
            postgres_encryption_negotiation_rejected: 11,
            postgres_negotiation_failures: 12,
            postgres_encrypted_transport_events: 13,
            postgres_copy_ignored_controls: 14,
            mysql_local_infile_packets: 15,
            mysql_local_infile_bytes: 16,
            mysql_logical_request_continuations: 17,
            mysql_logical_response_continuations: 18,
            mysql_logical_sequence_failures: 19,
            mysql_server_greetings: 20,
            mysql_client_handshakes: 21,
            mysql_auth_packets: 22,
            mysql_compression_zlib_connections: 23,
            mysql_compression_zstd_rejections: 24,
            mysql_compression_unverified_rejections: 25,
            mysql_compressed_packets: 26,
            mysql_compression_failures: 27,
            mysql_compression_opaque_events: 28,
            mysql_handshake_failures: 29,
            mongodb_fire_and_forget_requests: 30,
            mongodb_response_continuations: 31,
            mongodb_lifecycle_failures: 32,
            ..ProtocolRegistryCounters::default()
        };

        assert_eq!(
            ProtocolSurfaceCounters::from(counters),
            ProtocolSurfaceCounters {
                websocket_upgrades: 1,
                websocket_frames: 2,
                websocket_transition_rejections: 3,
                grpc_web_requests: 4,
                redis_ambiguous_state_transitions: 5,
                discovered_connections: 6,
                discovery_unclassified_events: 7,
                discovery_candidate_evictions: 8,
                postgres_startup_auth_messages: 9,
                postgres_encryption_negotiation_accepted: 10,
                postgres_encryption_negotiation_rejected: 11,
                postgres_negotiation_failures: 12,
                postgres_encrypted_transport_events: 13,
                postgres_copy_ignored_controls: 14,
                mysql_local_infile_packets: 15,
                mysql_local_infile_bytes: 16,
                mysql_logical_request_continuations: 17,
                mysql_logical_response_continuations: 18,
                mysql_logical_sequence_failures: 19,
                mysql_server_greetings: 20,
                mysql_client_handshakes: 21,
                mysql_auth_packets: 22,
                mysql_compression_zlib_connections: 23,
                mysql_compression_zstd_rejections: 24,
                mysql_compression_unverified_rejections: 25,
                mysql_compressed_packets: 26,
                mysql_compression_failures: 27,
                mysql_compression_opaque_events: 28,
                mysql_handshake_failures: 29,
                mongodb_fire_and_forget_requests: 30,
                mongodb_response_continuations: 31,
                mongodb_lifecycle_failures: 32,
            }
        );
    }

    #[test]
    fn named_delta_saturates_after_a_counter_reset() {
        let current = ProtocolSurfaceCounters {
            websocket_frames: 3,
            mysql_compressed_packets: 5,
            ..ProtocolSurfaceCounters::default()
        };
        let previous = ProtocolSurfaceCounters {
            websocket_frames: 2,
            mysql_compressed_packets: 8,
            ..ProtocolSurfaceCounters::default()
        };

        let delta = current.delta_since(previous);

        assert_eq!(delta.websocket_frames, 1);
        assert_eq!(delta.mysql_compressed_packets, 0);
        assert_eq!(delta.mongodb_lifecycle_failures, 0);
    }
}
