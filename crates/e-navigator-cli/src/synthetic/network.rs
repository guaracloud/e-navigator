use e_navigator_signals::{
    ContainerContext, KubernetesContext, NetworkAddressFamily, NetworkConnectionCloseEvent,
    NetworkConnectionFailureEvent, NetworkConnectionOpenEvent, NetworkProtocol, SignalEnvelope,
};

pub(super) fn open_signal(
    host: Option<String>,
    container: ContainerContext,
    kubernetes: KubernetesContext,
    opened_at: u64,
) -> SignalEnvelope {
    SignalEnvelope::network_connection_open(
        super::source_name(),
        host,
        NetworkConnectionOpenEvent {
            process: super::process_identity(),
            protocol: NetworkProtocol::Tcp,
            address_family: NetworkAddressFamily::Ipv4,
            local_address: Some("10.0.0.5".to_string()),
            local_port: Some(43512),
            remote_address: "203.0.113.10".to_string(),
            remote_port: 443,
            fd: Some(7),
            timestamp_unix_nanos: opened_at,
            container: Some(container),
            kubernetes: Some(kubernetes),
        },
    )
}

pub(super) fn close_signal(
    host: Option<String>,
    container: ContainerContext,
    kubernetes: KubernetesContext,
    opened_at: u64,
    duration_nanos: u64,
) -> SignalEnvelope {
    SignalEnvelope::network_connection_close(
        super::source_name(),
        host,
        NetworkConnectionCloseEvent {
            process: super::process_identity(),
            protocol: NetworkProtocol::Tcp,
            address_family: NetworkAddressFamily::Ipv4,
            local_address: Some("10.0.0.5".to_string()),
            local_port: Some(43512),
            remote_address: "203.0.113.10".to_string(),
            remote_port: 443,
            fd: Some(7),
            opened_at_unix_nanos: Some(opened_at),
            closed_at_unix_nanos: opened_at.saturating_add(duration_nanos),
            duration_nanos: Some(duration_nanos),
            container: Some(container),
            kubernetes: Some(kubernetes),
        },
    )
}

pub(super) fn failure_signal(
    host: Option<String>,
    container: ContainerContext,
    kubernetes: KubernetesContext,
    opened_at: u64,
    duration_nanos: u64,
) -> SignalEnvelope {
    SignalEnvelope::network_connection_failure(
        super::source_name(),
        host,
        NetworkConnectionFailureEvent {
            process: super::process_identity(),
            protocol: NetworkProtocol::Tcp,
            address_family: NetworkAddressFamily::Ipv4,
            remote_address: "198.51.100.20".to_string(),
            remote_port: 5432,
            fd: Some(8),
            errno: 111,
            timestamp_unix_nanos: opened_at.saturating_add(duration_nanos + 30_000),
            container: Some(container),
            kubernetes: Some(kubernetes),
        },
    )
}
