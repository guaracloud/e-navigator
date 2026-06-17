use e_navigator_signals::{
    ContainerContext, DnsQueryEvent, DnsQueryType, DnsResponseCode, DnsResponseEvent,
    KubernetesContext, NetworkProtocol, SignalEnvelope,
};

pub(super) fn query_signal(
    host: Option<String>,
    container: ContainerContext,
    kubernetes: KubernetesContext,
    opened_at: u64,
    duration_nanos: u64,
) -> SignalEnvelope {
    SignalEnvelope::dns_query(
        super::source_name(),
        host,
        DnsQueryEvent {
            process: super::process_identity(),
            query_name: "api.example.com".to_string(),
            query_type: DnsQueryType::A,
            transport_protocol: NetworkProtocol::Udp,
            server_address: Some("10.96.0.10".to_string()),
            server_port: Some(53),
            timestamp_unix_nanos: opened_at.saturating_add(duration_nanos + 1),
            container: Some(container),
            kubernetes: Some(kubernetes),
        },
    )
}

pub(super) fn response_signal(
    host: Option<String>,
    container: ContainerContext,
    kubernetes: KubernetesContext,
    opened_at: u64,
    duration_nanos: u64,
) -> SignalEnvelope {
    SignalEnvelope::dns_response(
        super::source_name(),
        host,
        DnsResponseEvent {
            process: super::process_identity(),
            query_name: "api.example.com".to_string(),
            query_type: DnsQueryType::A,
            response_code: DnsResponseCode::NoError,
            latency_nanos: Some(15_000),
            transport_protocol: NetworkProtocol::Udp,
            server_address: Some("10.96.0.10".to_string()),
            server_port: Some(53),
            timestamp_unix_nanos: opened_at.saturating_add(duration_nanos + 15_001),
            container: Some(container),
            kubernetes: Some(kubernetes),
        },
    )
}
