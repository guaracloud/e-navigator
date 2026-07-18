use e_navigator_core::Generator;
use e_navigator_generators::TraceCorrelationGenerator;
use e_navigator_signals::{
    ContainerContext, DependencyEdgeEvent, DependencyEndpoint, DnsQueryType, DnsResponseCode,
    DnsResponseEvent, KubernetesContext, NetworkAddressFamily, NetworkConnectionCloseEvent,
    NetworkConnectionFailureEvent, NetworkConnectionOpenEvent, NetworkProcessIdentity,
    NetworkProtocol, SignalEnvelope, SignalPayload, TraceConfidence, TraceCorrelationKind,
};
use std::collections::BTreeMap;
use tokio::sync::mpsc;

#[tokio::test]
async fn network_close_generates_network_inferred_service_interaction_span() {
    let generator = TraceCorrelationGenerator::default();
    let signal = network_close_signal("203.0.113.10", 443, 1_000, 3_500, true);

    let outputs = observe(&generator, &signal).await;

    assert_eq!(outputs.len(), 1);
    let SignalPayload::ServiceInteractionSpanObservation(span) = &outputs[0].payload else {
        panic!("expected service interaction span");
    };
    assert_eq!(span.name, "tcp client");
    assert_eq!(span.trace_id, None);
    assert_eq!(span.span_id, None);
    assert_eq!(span.parent_span_id, None);
    assert_eq!(span.start_unix_nanos, 1_000);
    assert_eq!(span.end_unix_nanos, Some(3_500));
    assert_eq!(span.duration_nanos, Some(2_500));
    assert_eq!(span.correlation_kind, TraceCorrelationKind::NetworkInferred);
    assert_eq!(span.confidence, TraceConfidence::Medium);
    assert_eq!(span.source.workload, Some(kubernetes_context()));
    assert_eq!(span.source.container, Some(container_context()));
    assert_eq!(span.source.address, Some("10.0.0.5".to_string()));
    assert_eq!(span.destination.address, Some("203.0.113.10".to_string()));
    assert_eq!(span.destination.port, Some(443));
    assert_eq!(span.process.as_ref().map(|process| process.pid), Some(42));
}

#[tokio::test]
async fn failed_connection_generates_error_interaction_span() {
    let generator = TraceCorrelationGenerator::default();
    let signal = network_failure_signal("203.0.113.10", 443, 4_000, 111, true);

    let outputs = observe(&generator, &signal).await;

    assert_eq!(outputs.len(), 1);
    let SignalPayload::ServiceInteractionSpanObservation(span) = &outputs[0].payload else {
        panic!("expected service interaction span");
    };
    assert_eq!(span.start_unix_nanos, 4_000);
    assert_eq!(span.end_unix_nanos, Some(4_000));
    assert_eq!(span.duration_nanos, Some(0));
    assert_eq!(span.error_type, Some("errno_111".to_string()));
    assert_eq!(span.correlation_kind, TraceCorrelationKind::NetworkInferred);
}

#[tokio::test]
async fn failed_connection_without_attribution_emits_warning() {
    let generator = TraceCorrelationGenerator::default();
    let signal = network_failure_signal("203.0.113.10", 443, 4_000, 111, false);

    let outputs = observe(&generator, &signal).await;

    assert_eq!(outputs.len(), 2);
    assert!(outputs.iter().any(|signal| {
        matches!(
            &signal.payload,
            SignalPayload::ServiceInteractionSpanObservation(span)
                if span.error_type == Some("errno_111".to_string())
        )
    }));
    assert!(outputs.iter().any(|signal| {
        matches!(
            &signal.payload,
            SignalPayload::TraceCorrelationWarning(warning)
                if warning.source_signal_kind == "network_connection_failure"
        )
    }));
}

#[tokio::test]
async fn dependency_edge_generates_service_path_observation() {
    let generator = TraceCorrelationGenerator::default();
    let signal = dependency_edge_signal("203.0.113.10", Some(443), None, 2);

    let outputs = observe(&generator, &signal).await;

    assert_eq!(outputs.len(), 1);
    let SignalPayload::TraceServicePathObservation(path) = &outputs[0].payload else {
        panic!("expected trace service path");
    };
    assert_low_cardinality_path_key(&path.path_key);
    assert_eq!(path.observations, 2);
    assert_eq!(path.first_seen_unix_nanos, 1_000);
    assert_eq!(path.last_seen_unix_nanos, 2_000);
    assert_eq!(
        path.correlation_kind,
        TraceCorrelationKind::DependencyInferred
    );
    assert_eq!(path.confidence, TraceConfidence::Low);
}

#[tokio::test]
async fn dns_response_generates_domain_service_path_when_successful() {
    let generator = TraceCorrelationGenerator::default();
    let signal = dns_response_signal("API.Example.COM.", DnsResponseCode::NoError);

    let outputs = observe(&generator, &signal).await;

    assert_eq!(outputs.len(), 1);
    let SignalPayload::TraceServicePathObservation(path) = &outputs[0].payload else {
        panic!("expected trace service path");
    };
    assert_low_cardinality_path_key(&path.path_key);
    assert_eq!(path.destination.domain, Some("api.example.com".to_string()));
    assert_eq!(path.destination.address, None);
    assert_eq!(path.protocol, NetworkProtocol::Udp);
    assert_eq!(
        path.correlation_kind,
        TraceCorrelationKind::DependencyInferred
    );
}

#[tokio::test]
async fn malformed_or_oversized_dns_domains_do_not_generate_service_paths() {
    let generator = TraceCorrelationGenerator::default();

    for query_name in [
        "api..example.com",
        "bad label.example.com",
        "bad_label.example.com",
        "-bad.example.com",
        "bad-.example.com",
        &format!("{}.example.com", "a".repeat(64)),
        &format!("{}.example.com", "a".repeat(254)),
    ] {
        let signal = dns_response_signal(query_name, DnsResponseCode::NoError);

        let outputs = observe(&generator, &signal).await;

        assert!(outputs.is_empty(), "{query_name:?}");
    }
}

#[tokio::test]
async fn missing_attribution_emits_warning_without_failing() {
    let generator = TraceCorrelationGenerator::default();
    let signal = network_close_signal("203.0.113.10", 443, 1_000, 3_500, false);

    let outputs = observe(&generator, &signal).await;

    assert_eq!(outputs.len(), 2);
    assert!(outputs.iter().any(|signal| {
        matches!(
            &signal.payload,
            SignalPayload::ServiceInteractionSpanObservation(span)
                if span.source.workload.is_none() && span.source.container.is_none()
        )
    }));
    assert!(outputs.iter().any(|signal| {
        matches!(
            &signal.payload,
            SignalPayload::TraceCorrelationWarning(warning)
                if warning.warning_type == "missing_attribution"
        )
    }));
}

#[tokio::test]
async fn deterministic_aggregation_uses_stable_path_key() {
    let generator = TraceCorrelationGenerator::default();
    let first = dependency_edge_signal("203.0.113.10", Some(443), None, 1);
    let second = dependency_edge_signal("203.0.113.10", Some(443), None, 3);

    let first_outputs = observe(&generator, &first).await;
    let second_outputs = observe(&generator, &second).await;

    let first_key = service_path_key(&first_outputs);
    let second_key = service_path_key(&second_outputs);

    assert_low_cardinality_path_key(&first_key);
    assert_eq!(first_key, "trace-path:042d517c13d070d1");
    assert_eq!(second_key, first_key);
}

#[tokio::test]
async fn dns_service_path_counts_each_distinct_response() {
    let generator = TraceCorrelationGenerator::default();
    let first = dns_response_signal_at("api.example.com.", DnsResponseCode::NoError, 1_500);
    let second = dns_response_signal_at("api.example.com.", DnsResponseCode::NoError, 1_600);

    let first_outputs = observe(&generator, &first).await;
    let second_outputs = observe(&generator, &second).await;

    let SignalPayload::TraceServicePathObservation(first_path) = &first_outputs[0].payload else {
        panic!("expected first trace service path");
    };
    let SignalPayload::TraceServicePathObservation(second_path) = &second_outputs[0].payload else {
        panic!("expected second trace service path");
    };
    assert_eq!(first_path.observations, 1);
    assert_eq!(second_path.observations, 2);
    assert_eq!(second_path.first_seen_unix_nanos, 1_500);
    assert_eq!(second_path.last_seen_unix_nanos, 1_600);
}

#[tokio::test]
async fn service_path_key_distinguishes_recreated_pods_by_uid() {
    let generator = TraceCorrelationGenerator::default();
    let first = dependency_edge_signal_with_workload(
        "203.0.113.10",
        Some(443),
        None,
        1,
        kubernetes_context_with_uid("api-123", Some("pod-uid-a")),
    );
    let second = dependency_edge_signal_with_workload(
        "203.0.113.10",
        Some(443),
        None,
        1,
        kubernetes_context_with_uid("api-123", Some("pod-uid-b")),
    );

    let first_outputs = observe(&generator, &first).await;
    let second_outputs = observe(&generator, &second).await;

    let first_key = service_path_key(&first_outputs);
    let second_key = service_path_key(&second_outputs);
    assert_low_cardinality_path_key(&first_key);
    assert_low_cardinality_path_key(&second_key);
    assert_ne!(first_key, second_key);
}

#[tokio::test]
async fn bounded_state_suppresses_new_paths_after_limit() {
    let generator = TraceCorrelationGenerator::with_limits(1, 32, 32);
    let first = dependency_edge_signal("203.0.113.10", Some(443), None, 1);
    let second = dependency_edge_signal("198.51.100.20", Some(5432), None, 1);

    let first_outputs = observe(&generator, &first).await;
    let second_outputs = observe(&generator, &second).await;

    assert_eq!(first_outputs.len(), 1);
    assert!(second_outputs.is_empty());
}

#[tokio::test]
async fn duplicate_network_close_is_suppressed() {
    let generator = TraceCorrelationGenerator::default();
    let signal = network_close_signal("203.0.113.10", 443, 1_000, 3_500, true);

    let first = observe(&generator, &signal).await;
    let second = observe(&generator, &signal).await;

    assert_eq!(first.len(), 1);
    assert!(second.is_empty());
}

#[tokio::test]
async fn bounded_interaction_dedupe_evicts_oldest_inserted_fingerprint() {
    let generator = TraceCorrelationGenerator::with_limits(8, 2, 8);
    let first = network_close_signal("203.0.113.10", 443, 1_000, 3_500, true);
    let second = network_close_signal("198.51.100.20", 443, 2_000, 4_500, true);
    let third = network_close_signal("192.0.2.30", 443, 3_000, 5_500, true);

    assert_eq!(observe(&generator, &first).await.len(), 1);
    assert_eq!(observe(&generator, &second).await.len(), 1);
    assert_eq!(observe(&generator, &third).await.len(), 1);

    assert!(observe(&generator, &second).await.is_empty());
    assert_eq!(observe(&generator, &first).await.len(), 1);
}

#[tokio::test]
async fn bounded_warning_dedupe_evicts_oldest_inserted_fingerprint() {
    let generator = TraceCorrelationGenerator::with_limits(8, 8, 2);
    let first = network_close_signal_with_fd("203.0.113.10", 443, 1_000, 3_500, false, Some(7));
    let second = network_close_signal_with_fd("198.51.100.20", 443, 2_000, 4_500, false, Some(7));
    let third = network_close_signal_with_fd("192.0.2.30", 443, 3_000, 5_500, false, Some(7));

    assert_eq!(warning_count(&observe(&generator, &first).await), 1);
    assert_eq!(warning_count(&observe(&generator, &second).await), 1);
    assert_eq!(warning_count(&observe(&generator, &third).await), 1);

    let repeated_second =
        network_close_signal_with_fd("198.51.100.20", 443, 2_000, 4_500, false, Some(8));
    let repeated_first =
        network_close_signal_with_fd("203.0.113.10", 443, 1_000, 3_500, false, Some(8));
    assert_eq!(
        warning_count(&observe(&generator, &repeated_second).await),
        0
    );
    assert_eq!(
        warning_count(&observe(&generator, &repeated_first).await),
        1
    );
}

#[tokio::test]
async fn open_only_network_event_does_not_infer_span() {
    let generator = TraceCorrelationGenerator::default();
    let signal = network_open_signal("203.0.113.10", 443, true);

    let outputs = observe(&generator, &signal).await;

    assert!(outputs.is_empty());
}

async fn observe(
    generator: &TraceCorrelationGenerator,
    signal: &SignalEnvelope,
) -> Vec<SignalEnvelope> {
    let (tx, mut rx) = mpsc::channel(8);
    generator
        .observe(signal, &tx)
        .await
        .expect("generator succeeds");
    drop(tx);

    let mut outputs = Vec::new();
    while let Some(output) = rx.recv().await {
        outputs.push(output);
    }
    outputs
}

fn service_path_key(outputs: &[SignalEnvelope]) -> String {
    outputs
        .iter()
        .find_map(|signal| match &signal.payload {
            SignalPayload::TraceServicePathObservation(path) => Some(path.path_key.clone()),
            _ => None,
        })
        .expect("service path emitted")
}

fn assert_low_cardinality_path_key(path_key: &str) {
    assert!(path_key.starts_with("trace-path:"));
    assert!(!path_key.contains("203.0.113.10"));
    assert!(!path_key.contains("api.example.com"));
    assert!(!path_key.contains("api-123"));
    assert!(!path_key.contains("pod-uid"));
}

fn warning_count(outputs: &[SignalEnvelope]) -> usize {
    outputs
        .iter()
        .filter(|signal| matches!(&signal.payload, SignalPayload::TraceCorrelationWarning(_)))
        .count()
}

fn network_open_signal(remote_address: &str, remote_port: u16, attributed: bool) -> SignalEnvelope {
    let (container, kubernetes) = attribution(attributed);
    SignalEnvelope::network_connection_open(
        "source.test",
        Some("node-a".to_string()),
        NetworkConnectionOpenEvent {
            process: network_process(),
            protocol: NetworkProtocol::Tcp,
            address_family: NetworkAddressFamily::Ipv4,
            local_address: Some("10.0.0.5".to_string()),
            local_port: Some(43512),
            remote_address: remote_address.to_string(),
            remote_port,
            fd: Some(7),
            timestamp_unix_nanos: 1_000,
            container,
            kubernetes,
        },
    )
}

fn network_close_signal(
    remote_address: &str,
    remote_port: u16,
    opened_at: u64,
    closed_at: u64,
    attributed: bool,
) -> SignalEnvelope {
    network_close_signal_with_fd(
        remote_address,
        remote_port,
        opened_at,
        closed_at,
        attributed,
        Some(7),
    )
}

fn network_close_signal_with_fd(
    remote_address: &str,
    remote_port: u16,
    opened_at: u64,
    closed_at: u64,
    attributed: bool,
    fd: Option<i32>,
) -> SignalEnvelope {
    let (container, kubernetes) = attribution(attributed);
    SignalEnvelope::network_connection_close(
        "source.test",
        Some("node-a".to_string()),
        NetworkConnectionCloseEvent {
            process: network_process(),
            protocol: NetworkProtocol::Tcp,
            address_family: NetworkAddressFamily::Ipv4,
            local_address: Some("10.0.0.5".to_string()),
            local_port: Some(43512),
            remote_address: remote_address.to_string(),
            remote_port,
            fd,
            opened_at_unix_nanos: Some(opened_at),
            closed_at_unix_nanos: closed_at,
            duration_nanos: Some(closed_at.saturating_sub(opened_at)),
            bytes_sent: None,
            bytes_received: None,
            container,
            kubernetes,
        },
    )
}

fn network_failure_signal(
    remote_address: &str,
    remote_port: u16,
    timestamp: u64,
    errno: i32,
    attributed: bool,
) -> SignalEnvelope {
    let (container, kubernetes) = attribution(attributed);
    SignalEnvelope::network_connection_failure(
        "source.test",
        Some("node-a".to_string()),
        NetworkConnectionFailureEvent {
            process: network_process(),
            protocol: NetworkProtocol::Tcp,
            address_family: NetworkAddressFamily::Ipv4,
            remote_address: remote_address.to_string(),
            remote_port,
            fd: Some(7),
            errno,
            timestamp_unix_nanos: timestamp,
            container,
            kubernetes,
        },
    )
}

fn dependency_edge_signal(
    address: &str,
    port: Option<u16>,
    domain: Option<&str>,
    observations: u64,
) -> SignalEnvelope {
    dependency_edge_signal_with_workload(address, port, domain, observations, kubernetes_context())
}

fn dependency_edge_signal_with_workload(
    address: &str,
    port: Option<u16>,
    domain: Option<&str>,
    observations: u64,
    workload: KubernetesContext,
) -> SignalEnvelope {
    SignalEnvelope::dependency_edge(
        "generator.dependency_graph",
        Some("node-a".to_string()),
        DependencyEdgeEvent {
            source: DependencyEndpoint {
                owner_name: None,
                owner_type: None,
                workload: Some(workload),
                container: Some(container_context()),
                address: None,
                port: None,
                domain: None,
            },
            destination: DependencyEndpoint {
                owner_name: None,
                owner_type: None,
                workload: None,
                container: None,
                address: Some(address.to_string()),
                port,
                domain: domain.map(str::to_string),
            },
            protocol: NetworkProtocol::Tcp,
            observations,
            first_seen_unix_nanos: 1_000,
            last_seen_unix_nanos: 2_000,
        },
    )
}

fn dns_response_signal(query_name: &str, response_code: DnsResponseCode) -> SignalEnvelope {
    dns_response_signal_at(query_name, response_code, 1_500)
}

fn dns_response_signal_at(
    query_name: &str,
    response_code: DnsResponseCode,
    timestamp_unix_nanos: u64,
) -> SignalEnvelope {
    SignalEnvelope::dns_response(
        "source.test",
        Some("node-a".to_string()),
        DnsResponseEvent {
            process: network_process(),
            query_name: query_name.to_string(),
            query_type: DnsQueryType::A,
            transaction_id: None,
            response_code,
            latency_nanos: Some(15_000),
            transport_protocol: NetworkProtocol::Udp,
            server_address: Some("10.96.0.10".to_string()),
            server_port: Some(53),
            timestamp_unix_nanos,
            container: Some(container_context()),
            kubernetes: Some(kubernetes_context()),
        },
    )
}

fn attribution(attributed: bool) -> (Option<ContainerContext>, Option<KubernetesContext>) {
    if attributed {
        (Some(container_context()), Some(kubernetes_context()))
    } else {
        (None, None)
    }
}

fn network_process() -> NetworkProcessIdentity {
    NetworkProcessIdentity {
        pid: 42,
        ppid: Some(1),
        uid: Some(1000),
        command: "api".to_string(),
        executable: Some("/app/api".to_string()),
        cgroup_id: None,
    }
}

fn container_context() -> ContainerContext {
    ContainerContext {
        container_id: "container-a".to_string(),
        runtime: Some("containerd".to_string()),
    }
}

fn kubernetes_context() -> KubernetesContext {
    kubernetes_context_with_uid("api-123", Some("pod-uid"))
}

fn kubernetes_context_with_uid(pod_name: &str, pod_uid: Option<&str>) -> KubernetesContext {
    KubernetesContext {
        namespace: "default".to_string(),
        pod_name: pod_name.to_string(),
        pod_uid: pod_uid.map(str::to_string),
        container_name: Some("api".to_string()),
        node_name: Some("node-a".to_string()),
        labels: BTreeMap::new(),
    }
}
