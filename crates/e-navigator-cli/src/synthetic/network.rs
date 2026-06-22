use e_navigator_signals::{
    ContainerContext, KubernetesContext, NetworkAddressFamily, NetworkConnectionCloseEvent,
    NetworkConnectionFailureEvent, NetworkConnectionOpenEvent, NetworkFlowDirection,
    NetworkFlowEndpoint, NetworkFlowSummaryEvent, NetworkProtocol, SignalEnvelope,
};
use std::collections::BTreeMap;

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
            bytes_sent: None,
            bytes_received: None,
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

pub(super) fn flow_summary_signal(host: Option<String>, opened_at: u64) -> SignalEnvelope {
    SignalEnvelope::network_flow_summary(
        super::source_name(),
        host,
        NetworkFlowSummaryEvent {
            source: flow_endpoint("api", "deployment", None, "10.0.0.5", 43512),
            destination: flow_endpoint("redis", "statefulset", Some("redis"), "10.0.0.20", 6379),
            protocol: NetworkProtocol::Tcp,
            address_family: NetworkAddressFamily::Ipv4,
            bytes: 4096,
            packets: Some(8),
            direction: NetworkFlowDirection::Egress,
            first_seen_unix_nanos: opened_at,
            last_seen_unix_nanos: opened_at.saturating_add(2_000_000),
        },
    )
}

fn flow_endpoint(
    owner_name: &str,
    owner_type: &str,
    catalog_slug: Option<&str>,
    address: &str,
    port: u16,
) -> NetworkFlowEndpoint {
    let mut labels = BTreeMap::from([
        ("app.kubernetes.io/name".to_string(), owner_name.to_string()),
        ("guara.cloud/tier".to_string(), "pro".to_string()),
    ]);
    if let Some(catalog_slug) = catalog_slug {
        labels.insert(
            "guara.cloud/catalog-slug".to_string(),
            catalog_slug.to_string(),
        );
    }

    NetworkFlowEndpoint {
        address: Some(address.to_string()),
        port: Some(port),
        owner_name: Some(owner_name.to_string()),
        owner_type: Some(owner_type.to_string()),
        container: None,
        kubernetes: Some(KubernetesContext {
            namespace: "proj-smoke".to_string(),
            pod_name: format!("{owner_name}-123"),
            pod_uid: Some(format!("{owner_name}-pod-uid")),
            container_name: Some("app".to_string()),
            node_name: Some("synthetic-node".to_string()),
            labels,
        }),
    }
}
