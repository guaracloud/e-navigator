//! Per-source sizing for maps embedded in the monolithic eBPF object.
//!
//! Every statically registered source loads the same object so the kernel can
//! verify only the programs that source owns. Without load-time overrides,
//! however, every load also allocates the maximum capacity of every unrelated
//! source map. Keep each source's required maps unchanged and collapse only
//! maps that its loaded programs can never access.

use aya::EbpfLoader;

use crate::event_transport::EventTransportKind;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SourceMapProfile {
    Exec,
    Network,
    Dns,
    Http,
    Protocol,
    Tls,
    CpuProfile,
}

const CAPACITY_MAPS: [&str; 18] = [
    "UNWIND_ROWS",
    "UNWIND_MODULES",
    "UNWIND_PROC_MAPPINGS",
    "PY_PROC_INFO",
    "PENDING_CONNECTS",
    "ACTIVE_CONNECTIONS",
    "PENDING_NETWORK_IO",
    "PENDING_DNS_RECVS",
    "PENDING_BINDS",
    "PROCESS_LISTENER_ENDPOINTS",
    "LISTENER_ENDPOINTS",
    "PENDING_ACCEPTS",
    "PENDING_HTTP_READS",
    "PENDING_PROTOCOL_READS",
    "PENDING_PROTOCOL_IOVEC_READS",
    "TLS_HANDLE_FDS",
    "PENDING_TLS_SET_FD",
    "PENDING_TLS_IO",
];

const EVENT_MAPS: [&str; 9] = [
    "EXEC_EVENTS",
    "EXIT_EVENTS",
    "NETWORK_EVENTS",
    "TCP_STAT_EVENTS",
    "CPU_PROFILE_EVENTS",
    "DNS_EVENTS",
    "HTTP_REQUEST_EVENTS",
    "PROTOCOL_DATA_EVENTS",
    "TLS_DATA_EVENTS",
];

pub(crate) fn constrain_unrelated_maps(loader: &mut EbpfLoader<'_>, profile: SourceMapProfile) {
    for name in CAPACITY_MAPS {
        if !retains_map(profile, name) {
            loader.map_max_entries(name, 1);
        }
    }
}

pub(crate) fn configure_event_transport_maps(
    loader: &mut EbpfLoader<'_>,
    profile: SourceMapProfile,
    transport: EventTransportKind,
    ring_buffer_bytes: u32,
) {
    if transport != EventTransportKind::RingBuffer {
        return;
    }
    let minimum_ring_buffer_bytes = u32::try_from(rustix::param::page_size())
        .unwrap_or(ring_buffer_bytes)
        .max(e_navigator_core::EbpfConfig::MIN_RING_BUFFER_BYTES);
    for name in EVENT_MAPS {
        let bytes = if retains_event_map(profile, name) {
            ring_buffer_bytes
        } else {
            minimum_ring_buffer_bytes
        };
        loader.map_max_entries(name, bytes);
    }
}

impl SourceMapProfile {
    pub(crate) const fn transport_loss_indices(self) -> &'static [u32] {
        match self {
            Self::Exec => &[0, 1],
            Self::Network => &[2, 3],
            Self::CpuProfile => &[4],
            Self::Dns => &[5],
            Self::Http => &[6],
            Self::Protocol => &[7],
            Self::Tls => &[8],
        }
    }
}

fn retains_event_map(profile: SourceMapProfile, name: &str) -> bool {
    match profile {
        SourceMapProfile::Exec => matches!(name, "EXEC_EVENTS" | "EXIT_EVENTS"),
        SourceMapProfile::Network => matches!(name, "NETWORK_EVENTS" | "TCP_STAT_EVENTS"),
        SourceMapProfile::Dns => name == "DNS_EVENTS",
        SourceMapProfile::Http => name == "HTTP_REQUEST_EVENTS",
        SourceMapProfile::Protocol => name == "PROTOCOL_DATA_EVENTS",
        SourceMapProfile::Tls => name == "TLS_DATA_EVENTS",
        SourceMapProfile::CpuProfile => name == "CPU_PROFILE_EVENTS",
    }
}

fn retains_map(profile: SourceMapProfile, name: &str) -> bool {
    match profile {
        SourceMapProfile::Exec => false,
        SourceMapProfile::Network => matches!(
            name,
            "PENDING_CONNECTS" | "ACTIVE_CONNECTIONS" | "PENDING_NETWORK_IO"
        ),
        SourceMapProfile::Dns => matches!(
            name,
            "PENDING_CONNECTS" | "ACTIVE_CONNECTIONS" | "PENDING_DNS_RECVS"
        ),
        SourceMapProfile::Http => matches!(
            name,
            "PENDING_CONNECTS"
                | "ACTIVE_CONNECTIONS"
                | "PENDING_BINDS"
                | "PROCESS_LISTENER_ENDPOINTS"
                | "LISTENER_ENDPOINTS"
                | "PENDING_ACCEPTS"
                | "PENDING_HTTP_READS"
        ),
        SourceMapProfile::Protocol => matches!(
            name,
            "PENDING_CONNECTS"
                | "ACTIVE_CONNECTIONS"
                | "PENDING_BINDS"
                | "PROCESS_LISTENER_ENDPOINTS"
                | "LISTENER_ENDPOINTS"
                | "PENDING_ACCEPTS"
                | "PENDING_PROTOCOL_READS"
                | "PENDING_PROTOCOL_IOVEC_READS"
        ),
        SourceMapProfile::Tls => matches!(
            name,
            "PENDING_CONNECTS"
                | "ACTIVE_CONNECTIONS"
                | "PENDING_BINDS"
                | "PROCESS_LISTENER_ENDPOINTS"
                | "LISTENER_ENDPOINTS"
                | "PENDING_ACCEPTS"
                | "TLS_HANDLE_FDS"
                | "PENDING_TLS_SET_FD"
                | "PENDING_TLS_IO"
        ),
        SourceMapProfile::CpuProfile => matches!(
            name,
            "UNWIND_ROWS" | "UNWIND_MODULES" | "UNWIND_PROC_MAPPINGS" | "PY_PROC_INFO"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROFILES: [SourceMapProfile; 7] = [
        SourceMapProfile::Exec,
        SourceMapProfile::Network,
        SourceMapProfile::Dns,
        SourceMapProfile::Http,
        SourceMapProfile::Protocol,
        SourceMapProfile::Tls,
        SourceMapProfile::CpuProfile,
    ];

    #[test]
    fn profile_keeps_only_unwind_capacity_maps() {
        let retained = CAPACITY_MAPS
            .iter()
            .copied()
            .filter(|name| retains_map(SourceMapProfile::CpuProfile, name))
            .collect::<Vec<_>>();

        assert_eq!(
            retained,
            vec![
                "UNWIND_ROWS",
                "UNWIND_MODULES",
                "UNWIND_PROC_MAPPINGS",
                "PY_PROC_INFO"
            ]
        );
    }

    #[test]
    fn http_keeps_connection_and_inbound_request_state() {
        assert!(retains_map(SourceMapProfile::Http, "ACTIVE_CONNECTIONS"));
        assert!(retains_map(SourceMapProfile::Http, "PENDING_HTTP_READS"));
        assert!(!retains_map(
            SourceMapProfile::Http,
            "PENDING_PROTOCOL_READS"
        ));
        assert!(!retains_map(SourceMapProfile::Http, "UNWIND_ROWS"));
    }

    #[test]
    fn tls_keeps_library_and_socket_state_but_not_cleartext_pending_reads() {
        assert!(retains_map(SourceMapProfile::Tls, "TLS_HANDLE_FDS"));
        assert!(retains_map(SourceMapProfile::Tls, "PENDING_ACCEPTS"));
        assert!(!retains_map(SourceMapProfile::Tls, "PENDING_HTTP_READS"));
        assert!(!retains_map(
            SourceMapProfile::Tls,
            "PENDING_PROTOCOL_IOVEC_READS"
        ));
    }

    #[test]
    fn every_event_map_is_owned_by_exactly_one_source_profile() {
        for name in EVENT_MAPS {
            let owners = PROFILES
                .iter()
                .filter(|profile| retains_event_map(**profile, name))
                .count();

            assert_eq!(owners, 1, "unexpected owner count for {name}");
        }
    }

    #[test]
    fn transport_loss_slots_cover_every_event_map_without_overlap() {
        let mut slots = PROFILES
            .iter()
            .flat_map(|profile| profile.transport_loss_indices().iter().copied())
            .collect::<Vec<_>>();
        slots.sort_unstable();

        assert_eq!(slots, (0..EVENT_MAPS.len() as u32).collect::<Vec<_>>());
    }
}
