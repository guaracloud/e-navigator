//! Per-source sizing for maps embedded in the monolithic eBPF object.
//!
//! Every statically registered source loads the same object so the kernel can
//! verify only the programs that source owns. Without load-time overrides,
//! however, every load also allocates the maximum capacity of every unrelated
//! source map. Keep each source's required maps unchanged and collapse only
//! maps that its loaded programs can never access.

use aya::EbpfLoader;

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

pub(crate) fn constrain_unrelated_maps(loader: &mut EbpfLoader<'_>, profile: SourceMapProfile) {
    for name in CAPACITY_MAPS {
        if !retains_map(profile, name) {
            loader.map_max_entries(name, 1);
        }
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
}
