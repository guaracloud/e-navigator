use e_navigator_core::Generator;
use e_navigator_generators::PeerFlowMetricsGenerator;
use e_navigator_signals::{
    MetricAggregationWindow, NetworkAddressFamily, NetworkFlowDirection, NetworkFlowEndpoint,
    NetworkFlowSummaryEvent, NetworkProtocol, SignalEnvelope, SignalPayload,
};
use std::time::Duration;

#[test]
fn enriched_flow_emits_bounded_peer_byte_metric() {
    let generator = PeerFlowMetricsGenerator::with_limit(8);
    let signal = SignalEnvelope::network_flow_summary(
        "processor.container_attribution",
        Some("node-a".to_string()),
        NetworkFlowSummaryEvent {
            source: workload_endpoint("shop", "shop/checkout", "deployment"),
            destination: workload_endpoint("payments", "payments/api", "service"),
            protocol: NetworkProtocol::Tcp,
            address_family: NetworkAddressFamily::Ipv4,
            bytes: 512,
            packets: None,
            direction: NetworkFlowDirection::Egress,
            first_seen_unix_nanos: 100,
            last_seen_unix_nanos: 200,
        },
    );

    let outputs = generator
        .observe_immediate(&signal)
        .expect("peer-flow generator is synchronous")
        .expect("peer-flow generation succeeds");

    let metric = outputs
        .iter()
        .find_map(|signal| match &signal.payload {
            SignalPayload::NetworkPeerFlowMetric(metric) => Some(metric),
            _ => None,
        })
        .expect("peer-aware flow metric exists");
    assert_eq!(metric.metric_name, "network.peer.flow.bytes");
    assert_eq!(metric.unit, "By");
    assert_eq!(metric.value, 512);
    assert!(!metric.overflow);
    assert_eq!(
        metric.window,
        MetricAggregationWindow {
            start_unix_nanos: 100,
            end_unix_nanos: 200,
        }
    );
    assert_eq!(metric.protocol, NetworkProtocol::Tcp);
    assert_eq!(metric.address_family, NetworkAddressFamily::Ipv4);
    assert_eq!(metric.direction, NetworkFlowDirection::Egress);
    assert_eq!(metric.source.namespace, "shop");
    assert_eq!(metric.source.owner_name, "shop/checkout");
    assert_eq!(metric.source.owner_type, "deployment");
    assert_eq!(metric.destination.namespace, "payments");
    assert_eq!(metric.destination.owner_name, "payments/api");
    assert_eq!(metric.destination.owner_type, "service");
}

#[test]
fn udp_ipv6_flow_retains_transport_and_address_family_identity() {
    let generator = PeerFlowMetricsGenerator::with_limit(8);
    let mut signal = peer_flow_signal(
        "shop",
        "shop/checkout",
        "payments",
        "payments/api",
        256,
        100,
        200,
    );
    let SignalPayload::NetworkFlowSummary(flow) = &mut signal.payload else {
        panic!("fixture is a flow summary");
    };
    flow.protocol = NetworkProtocol::Udp;
    flow.address_family = NetworkAddressFamily::Ipv6;

    let outputs = generator
        .observe_immediate(&signal)
        .expect("peer-flow generator is synchronous")
        .expect("peer-flow generation succeeds");
    let metric = peer_metric(&outputs);
    assert!(metric.is_some(), "peer-aware flow metric exists");
    let Some(metric) = metric else {
        return;
    };

    assert_eq!(metric.protocol, NetworkProtocol::Udp);
    assert_eq!(metric.address_family, NetworkAddressFamily::Ipv6);
}

#[test]
fn repeated_flow_updates_the_same_cumulative_series() {
    let generator = PeerFlowMetricsGenerator::with_limit(8);
    let first = peer_flow_signal(
        "shop",
        "shop/checkout",
        "payments",
        "payments/api",
        512,
        100,
        200,
    );
    let second = peer_flow_signal(
        "shop",
        "shop/checkout",
        "payments",
        "payments/api",
        128,
        250,
        300,
    );

    generator
        .observe_immediate(&first)
        .expect("peer-flow generator is synchronous")
        .expect("first peer-flow generation succeeds");
    let outputs = generator
        .observe_immediate(&second)
        .expect("peer-flow generator is synchronous")
        .expect("second peer-flow generation succeeds");

    let metric = peer_metric(&outputs);
    assert!(metric.is_some(), "peer-aware flow metric exists");
    let Some(metric) = metric else {
        return;
    };
    assert_eq!(metric.value, 640);
    assert_eq!(metric.window.start_unix_nanos, 100);
    assert_eq!(metric.window.end_unix_nanos, 300);
    assert!(!metric.overflow);
}

#[test]
fn identical_peers_on_different_hosts_remain_distinct_series() {
    let generator = PeerFlowMetricsGenerator::with_limit(8);
    let node_a = peer_flow_signal(
        "shop",
        "shop/checkout",
        "payments",
        "payments/api",
        512,
        100,
        200,
    );
    let mut node_b = node_a.clone();
    node_b.host = Some("node-b".to_string());

    generator
        .observe_immediate(&node_a)
        .expect("peer-flow generator is synchronous")
        .expect("node-a generation succeeds");
    let outputs = generator
        .observe_immediate(&node_b)
        .expect("peer-flow generator is synchronous")
        .expect("node-b generation succeeds");

    let metric = peer_metric(&outputs);
    assert!(metric.is_some(), "peer-aware flow metric exists");
    let Some(metric) = metric else {
        return;
    };
    assert_eq!(metric.value, 512);
    assert_eq!(outputs[0].host.as_deref(), Some("node-b"));
}

#[test]
fn cardinality_overflow_preserves_bytes_in_a_bounded_fallback_series() {
    let generator = PeerFlowMetricsGenerator::with_limit(1);
    let exact = peer_flow_signal(
        "shop",
        "shop/checkout",
        "payments",
        "payments/api",
        512,
        100,
        200,
    );
    let first_overflow = peer_flow_signal(
        "shop",
        "shop/catalog",
        "payments",
        "payments/api",
        128,
        300,
        400,
    );
    let second_overflow = peer_flow_signal(
        "shop",
        "shop/search",
        "payments",
        "payments/api",
        64,
        500,
        600,
    );

    for signal in [&exact, &first_overflow] {
        generator
            .observe_immediate(signal)
            .expect("peer-flow generator is synchronous")
            .expect("peer-flow generation succeeds");
    }
    let outputs = generator
        .observe_immediate(&second_overflow)
        .expect("peer-flow generator is synchronous")
        .expect("overflow generation succeeds");

    let metric = peer_metric(&outputs);
    assert!(metric.is_some(), "peer-aware flow metric exists");
    let Some(metric) = metric else {
        return;
    };
    assert!(metric.overflow);
    assert_eq!(metric.value, 192);
    assert_eq!(metric.source.namespace, "__other__");
    assert_eq!(metric.source.owner_name, "__other__");
    assert_eq!(metric.destination.owner_type, "__other__");
    assert_eq!(metric.window.start_unix_nanos, 300);
    assert_eq!(metric.window.end_unix_nanos, 600);
}

#[test]
fn idle_exact_series_are_reclaimed_for_new_peer_identities() {
    let generator =
        PeerFlowMetricsGenerator::with_limit_and_idle_timeout(1, Duration::from_nanos(100));
    let exact = peer_flow_signal(
        "shop",
        "shop/checkout",
        "payments",
        "payments/api",
        512,
        100,
        200,
    );
    let before_expiry = peer_flow_signal(
        "shop",
        "shop/catalog",
        "payments",
        "payments/api",
        32,
        250,
        250,
    );
    let after_expiry = peer_flow_signal(
        "shop",
        "shop/catalog",
        "payments",
        "payments/api",
        64,
        301,
        301,
    );

    generator
        .observe_immediate(&exact)
        .expect("peer-flow generator is synchronous")
        .expect("exact peer-flow generation succeeds");
    let overflow = generator
        .observe_immediate(&before_expiry)
        .expect("peer-flow generator is synchronous")
        .expect("pre-expiry generation succeeds");
    let reclaimed = generator
        .observe_immediate(&after_expiry)
        .expect("peer-flow generator is synchronous")
        .expect("post-expiry generation succeeds");

    let overflow = peer_metric(&overflow).expect("overflow metric exists before expiry");
    assert!(overflow.overflow);
    assert_eq!(overflow.value, 32);
    let reclaimed = peer_metric(&reclaimed).expect("reclaimed exact metric exists");
    assert!(!reclaimed.overflow);
    assert_eq!(reclaimed.value, 64);
    assert_eq!(reclaimed.source.owner_name, "shop/catalog");
    assert_eq!(reclaimed.window.start_unix_nanos, 301);
}

#[test]
fn zero_byte_active_flow_heartbeat_refreshes_an_existing_exact_series() {
    let generator =
        PeerFlowMetricsGenerator::with_limit_and_idle_timeout(1, Duration::from_nanos(100));
    let exact = peer_flow_signal(
        "shop",
        "shop/checkout",
        "payments",
        "payments/api",
        512,
        100,
        200,
    );
    let heartbeat = peer_flow_signal(
        "shop",
        "shop/checkout",
        "payments",
        "payments/api",
        0,
        250,
        250,
    );
    let contender = peer_flow_signal(
        "shop",
        "shop/catalog",
        "payments",
        "payments/api",
        64,
        320,
        320,
    );

    generator
        .observe_immediate(&exact)
        .expect("peer-flow generator is synchronous")
        .expect("exact peer-flow generation succeeds");
    let heartbeat_output = generator
        .observe_immediate(&heartbeat)
        .expect("peer-flow generator is synchronous")
        .expect("heartbeat generation succeeds");
    let contender_output = generator
        .observe_immediate(&contender)
        .expect("peer-flow generator is synchronous")
        .expect("contender generation succeeds");

    let heartbeat_metric = peer_metric(&heartbeat_output).expect("heartbeat metric exists");
    assert_eq!(heartbeat_metric.value, 512);
    assert_eq!(heartbeat_metric.window.end_unix_nanos, 250);
    assert!(!heartbeat_metric.overflow);
    let contender_metric = peer_metric(&contender_output).expect("contender metric exists");
    assert!(contender_metric.overflow);
    assert_eq!(contender_metric.value, 64);
}

#[test]
fn incomplete_peer_identity_does_not_create_a_misleading_series() {
    let generator = PeerFlowMetricsGenerator::with_limit(8);
    let mut signal = peer_flow_signal(
        "shop",
        "shop/checkout",
        "payments",
        "payments/api",
        512,
        100,
        200,
    );
    let SignalPayload::NetworkFlowSummary(flow) = &mut signal.payload else {
        panic!("fixture is a flow summary");
    };
    flow.destination.owner_type = None;

    let outputs = generator
        .observe_immediate(&signal)
        .expect("peer-flow generator is synchronous")
        .expect("peer-flow generation succeeds");

    assert!(outputs.is_empty());
}

fn peer_flow_signal(
    source_namespace: &str,
    source_owner: &str,
    destination_namespace: &str,
    destination_owner: &str,
    bytes: u64,
    first_seen_unix_nanos: u64,
    last_seen_unix_nanos: u64,
) -> SignalEnvelope {
    SignalEnvelope::network_flow_summary(
        "processor.container_attribution",
        Some("node-a".to_string()),
        NetworkFlowSummaryEvent {
            source: workload_endpoint(source_namespace, source_owner, "deployment"),
            destination: workload_endpoint(destination_namespace, destination_owner, "service"),
            protocol: NetworkProtocol::Tcp,
            address_family: NetworkAddressFamily::Ipv4,
            bytes,
            packets: None,
            direction: NetworkFlowDirection::Egress,
            first_seen_unix_nanos,
            last_seen_unix_nanos,
        },
    )
}

fn peer_metric(outputs: &[SignalEnvelope]) -> Option<&e_navigator_signals::NetworkPeerFlowMetric> {
    outputs.iter().find_map(|signal| match &signal.payload {
        SignalPayload::NetworkPeerFlowMetric(metric) => Some(metric),
        _ => None,
    })
}

fn workload_endpoint(namespace: &str, owner_name: &str, owner_type: &str) -> NetworkFlowEndpoint {
    NetworkFlowEndpoint {
        address: None,
        port: None,
        namespace: Some(namespace.to_string()),
        owner_name: Some(owner_name.to_string()),
        owner_type: Some(owner_type.to_string()),
        container: None,
        kubernetes: None,
    }
}
