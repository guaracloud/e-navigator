use e_navigator_signals::{
    DnsCounterMetric, DnsLatencyMetric, MetricAggregationWindow, NetworkAddressFamily,
    NetworkCounterMetric, NetworkDurationMetric, NetworkGaugeMetric, NetworkProtocol,
    ResourceCounterMetric, ResourceGaugeMetric, SignalEnvelope, SignalPayload,
};
use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OtelMetricKind {
    Sum,
    Gauge,
    HistogramSummary,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "type", content = "value")]
pub enum OtelMetricValue {
    U64(u64),
    I64(i64),
    Summary {
        count: u64,
        sum_nanos: u64,
        min_nanos: u64,
        max_nanos: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OtelMetricRecord {
    pub name: String,
    pub unit: String,
    pub kind: OtelMetricKind,
    pub value: OtelMetricValue,
    pub window: MetricAggregationWindow,
    pub resource: BTreeMap<String, serde_json::Value>,
    pub attributes: BTreeMap<String, serde_json::Value>,
}

pub fn format_otel_metric_record(signal: &SignalEnvelope) -> Option<OtelMetricRecord> {
    match &signal.payload {
        SignalPayload::NetworkCounterMetric(metric) => Some(network_counter_record(signal, metric)),
        SignalPayload::NetworkDurationMetric(metric) => {
            Some(network_duration_record(signal, metric))
        }
        SignalPayload::NetworkGaugeMetric(metric) => Some(network_gauge_record(signal, metric)),
        SignalPayload::DnsCounterMetric(metric) => Some(dns_counter_record(signal, metric)),
        SignalPayload::DnsLatencyMetric(metric) => Some(dns_latency_record(signal, metric)),
        SignalPayload::ResourceGaugeMetric(metric) => Some(resource_gauge_record(signal, metric)),
        SignalPayload::ResourceCounterMetric(metric) => {
            Some(resource_counter_record(signal, metric))
        }
        _ => None,
    }
}

fn network_counter_record(
    signal: &SignalEnvelope,
    metric: &NetworkCounterMetric,
) -> OtelMetricRecord {
    let mut attributes = network_attributes(
        metric.protocol,
        metric.address_family,
        metric.remote_address.as_deref(),
        metric.remote_port,
    );
    if let Some(errno) = metric.errno {
        attributes.insert("error.type".to_string(), serde_json::json!(errno));
    }

    OtelMetricRecord {
        name: metric.metric_name.clone(),
        unit: metric.unit.clone(),
        kind: OtelMetricKind::Sum,
        value: OtelMetricValue::U64(metric.value),
        window: metric.window.clone(),
        resource: resource_attributes(
            signal,
            metric.container.as_ref(),
            metric.kubernetes.as_ref(),
        ),
        attributes,
    }
}

fn network_duration_record(
    signal: &SignalEnvelope,
    metric: &NetworkDurationMetric,
) -> OtelMetricRecord {
    OtelMetricRecord {
        name: metric.metric_name.clone(),
        unit: metric.unit.clone(),
        kind: OtelMetricKind::HistogramSummary,
        value: OtelMetricValue::Summary {
            count: metric.count,
            sum_nanos: metric.sum_nanos,
            min_nanos: metric.min_nanos,
            max_nanos: metric.max_nanos,
        },
        window: metric.window.clone(),
        resource: resource_attributes(
            signal,
            metric.container.as_ref(),
            metric.kubernetes.as_ref(),
        ),
        attributes: network_attributes(
            metric.protocol,
            metric.address_family,
            metric.remote_address.as_deref(),
            metric.remote_port,
        ),
    }
}

fn network_gauge_record(signal: &SignalEnvelope, metric: &NetworkGaugeMetric) -> OtelMetricRecord {
    OtelMetricRecord {
        name: metric.metric_name.clone(),
        unit: metric.unit.clone(),
        kind: OtelMetricKind::Gauge,
        value: OtelMetricValue::I64(metric.value),
        window: metric.window.clone(),
        resource: resource_attributes(
            signal,
            metric.container.as_ref(),
            metric.kubernetes.as_ref(),
        ),
        attributes: network_attributes(
            metric.protocol,
            metric.address_family,
            metric.remote_address.as_deref(),
            metric.remote_port,
        ),
    }
}

fn dns_counter_record(signal: &SignalEnvelope, metric: &DnsCounterMetric) -> OtelMetricRecord {
    OtelMetricRecord {
        name: metric.metric_name.clone(),
        unit: metric.unit.clone(),
        kind: OtelMetricKind::Sum,
        value: OtelMetricValue::U64(metric.value),
        window: metric.window.clone(),
        resource: resource_attributes(
            signal,
            metric.container.as_ref(),
            metric.kubernetes.as_ref(),
        ),
        attributes: dns_attributes(metric.query_name.as_deref(), metric.response_code),
    }
}

fn dns_latency_record(signal: &SignalEnvelope, metric: &DnsLatencyMetric) -> OtelMetricRecord {
    OtelMetricRecord {
        name: metric.metric_name.clone(),
        unit: metric.unit.clone(),
        kind: OtelMetricKind::HistogramSummary,
        value: OtelMetricValue::Summary {
            count: metric.count,
            sum_nanos: metric.sum_nanos,
            min_nanos: metric.min_nanos,
            max_nanos: metric.max_nanos,
        },
        window: metric.window.clone(),
        resource: resource_attributes(
            signal,
            metric.container.as_ref(),
            metric.kubernetes.as_ref(),
        ),
        attributes: dns_attributes(metric.query_name.as_deref(), metric.response_code),
    }
}

fn resource_gauge_record(
    signal: &SignalEnvelope,
    metric: &ResourceGaugeMetric,
) -> OtelMetricRecord {
    OtelMetricRecord {
        name: metric.metric_name.clone(),
        unit: metric.unit.clone(),
        kind: OtelMetricKind::Gauge,
        value: OtelMetricValue::I64(metric.value),
        window: metric.window.clone(),
        resource: resource_metric_resource_attributes(signal, metric),
        attributes: resource_metric_attributes(
            &metric.metric_name,
            &metric.attributes,
            metric.process.as_ref(),
            metric.cgroup.as_ref(),
        ),
    }
}

fn resource_counter_record(
    signal: &SignalEnvelope,
    metric: &ResourceCounterMetric,
) -> OtelMetricRecord {
    OtelMetricRecord {
        name: metric.metric_name.clone(),
        unit: metric.unit.clone(),
        kind: OtelMetricKind::Sum,
        value: OtelMetricValue::U64(metric.value),
        window: metric.window.clone(),
        resource: resource_counter_resource_attributes(signal, metric),
        attributes: resource_metric_attributes(
            &metric.metric_name,
            &metric.attributes,
            metric.process.as_ref(),
            metric.cgroup.as_ref(),
        ),
    }
}

fn resource_attributes(
    signal: &SignalEnvelope,
    container: Option<&e_navigator_signals::ContainerContext>,
    kubernetes: Option<&e_navigator_signals::KubernetesContext>,
) -> BTreeMap<String, serde_json::Value> {
    let mut resource = BTreeMap::new();
    if let Some(host) = &signal.host {
        resource.insert("host.name".to_string(), serde_json::json!(host));
    }
    if let Some(container) = container {
        resource.insert(
            "container.id".to_string(),
            serde_json::json!(container.container_id),
        );
        if let Some(runtime) = &container.runtime {
            resource.insert("container.runtime".to_string(), serde_json::json!(runtime));
        }
    }
    if let Some(kubernetes) = kubernetes {
        resource.insert(
            "k8s.namespace.name".to_string(),
            serde_json::json!(kubernetes.namespace),
        );
        resource.insert(
            "k8s.pod.name".to_string(),
            serde_json::json!(kubernetes.pod_name),
        );
        if let Some(uid) = &kubernetes.pod_uid {
            resource.insert("k8s.pod.uid".to_string(), serde_json::json!(uid));
        }
        if let Some(container_name) = &kubernetes.container_name {
            resource.insert(
                "k8s.container.name".to_string(),
                serde_json::json!(container_name),
            );
        }
        if let Some(node_name) = &kubernetes.node_name {
            resource.insert("k8s.node.name".to_string(), serde_json::json!(node_name));
        }
    }
    resource
}

fn resource_metric_resource_attributes(
    signal: &SignalEnvelope,
    metric: &ResourceGaugeMetric,
) -> BTreeMap<String, serde_json::Value> {
    let mut resource = resource_attributes(
        signal,
        metric.resource.container.as_ref(),
        metric.resource.kubernetes.as_ref(),
    );
    if let Some(host) = &metric.resource.host_name {
        resource.insert("host.name".to_string(), serde_json::json!(host));
    }
    resource
}

fn resource_counter_resource_attributes(
    signal: &SignalEnvelope,
    metric: &ResourceCounterMetric,
) -> BTreeMap<String, serde_json::Value> {
    let mut resource = resource_attributes(
        signal,
        metric.resource.container.as_ref(),
        metric.resource.kubernetes.as_ref(),
    );
    if let Some(host) = &metric.resource.host_name {
        resource.insert("host.name".to_string(), serde_json::json!(host));
    }
    resource
}

fn resource_metric_attributes(
    metric_name: &str,
    attributes: &[e_navigator_signals::ResourceMetricAttribute],
    process: Option<&e_navigator_signals::ProcessResourceContext>,
    cgroup: Option<&e_navigator_signals::CgroupResourceContext>,
) -> BTreeMap<String, serde_json::Value> {
    let mut mapped = BTreeMap::new();
    for attribute in attributes {
        let key = resource_attribute_key(metric_name, &attribute.key, &attribute.value);
        mapped.insert(key.to_string(), serde_json::json!(attribute.value.clone()));
    }
    if let Some(process) = process {
        mapped.insert("process.pid".to_string(), serde_json::json!(process.pid));
        if let Some(ppid) = process.ppid {
            mapped.insert("process.parent_pid".to_string(), serde_json::json!(ppid));
        }
        mapped.insert(
            "process.command".to_string(),
            serde_json::json!(process.command.clone()),
        );
    }
    if let Some(cgroup) = cgroup {
        mapped.insert(
            "linux.cgroup.path".to_string(),
            serde_json::json!(cgroup.cgroup_path.clone()),
        );
    }
    mapped
}

fn resource_attribute_key<'a>(metric_name: &str, key: &'a str, value: &str) -> &'a str {
    match (metric_name, key, value) {
        ("system.cpu.time", "state", _) | ("container.cpu.time", "state", _) => "cpu.mode",
        ("process.cpu.time", "state", _) => "process.cpu.state",
        ("system.disk.io", "state", _) | ("system.disk.operations", "state", _) => {
            "disk.io.direction"
        }
        ("system.disk.io", "device", _) | ("system.disk.operations", "device", _) => {
            "system.device"
        }
        ("system.filesystem.usage", "mountpoint", _)
        | ("system.filesystem.available", "mountpoint", _)
        | ("system.filesystem.limit", "mountpoint", _) => "system.filesystem.mountpoint",
        _ => key,
    }
}

fn network_attributes(
    protocol: Option<NetworkProtocol>,
    address_family: Option<NetworkAddressFamily>,
    remote_address: Option<&str>,
    remote_port: Option<u16>,
) -> BTreeMap<String, serde_json::Value> {
    let mut attributes = BTreeMap::new();
    if let Some(protocol) = protocol {
        attributes.insert(
            "net.transport".to_string(),
            serde_json::json!(protocol_name(protocol)),
        );
    }
    if let Some(address_family) = address_family {
        attributes.insert(
            "network.type".to_string(),
            serde_json::json!(address_family_name(address_family)),
        );
    }
    if let Some(remote_address) = remote_address {
        attributes.insert(
            "server.address".to_string(),
            serde_json::json!(remote_address),
        );
    }
    if let Some(remote_port) = remote_port {
        attributes.insert("server.port".to_string(), serde_json::json!(remote_port));
    }
    attributes
}

fn dns_attributes(
    query_name: Option<&str>,
    response_code: Option<e_navigator_signals::DnsResponseCode>,
) -> BTreeMap<String, serde_json::Value> {
    let mut attributes = BTreeMap::new();
    if let Some(query_name) = query_name {
        attributes.insert(
            "dns.question.name".to_string(),
            serde_json::json!(query_name),
        );
    }
    if let Some(response_code) = response_code {
        attributes.insert(
            "dns.response_code".to_string(),
            serde_json::json!(format!("{response_code:?}").to_ascii_lowercase()),
        );
    }
    attributes
}

fn protocol_name(protocol: NetworkProtocol) -> &'static str {
    match protocol {
        NetworkProtocol::Tcp => "tcp",
        NetworkProtocol::Udp => "udp",
        _ => "other",
    }
}

fn address_family_name(address_family: NetworkAddressFamily) -> &'static str {
    match address_family {
        NetworkAddressFamily::Ipv4 => "ipv4",
        NetworkAddressFamily::Ipv6 => "ipv6",
        _ => "other",
    }
}

#[cfg(test)]
mod tests {
    use e_navigator_signals::{
        MetricAggregationWindow, NetworkCounterMetric, SignalEnvelope, SignalPayload,
    };

    use super::*;

    #[test]
    fn formats_network_counter_metric_as_stable_otel_record() {
        let signal = SignalEnvelope::network_counter_metric(
            "generator.network_metrics",
            Some("node-a".to_string()),
            NetworkCounterMetric {
                metric_name: "network.connection.open.count".to_string(),
                unit: "{connection}".to_string(),
                value: 2,
                window: MetricAggregationWindow {
                    start_unix_nanos: 100,
                    end_unix_nanos: 200,
                },
                process: None,
                protocol: Some(e_navigator_signals::NetworkProtocol::Tcp),
                address_family: Some(e_navigator_signals::NetworkAddressFamily::Ipv4),
                local_address: None,
                local_port: None,
                remote_address: Some("203.0.113.10".to_string()),
                remote_port: Some(443),
                errno: None,
                container: None,
                kubernetes: None,
            },
        );

        let record = format_otel_metric_record(&signal).expect("metric formats");
        let json = serde_json::to_value(&record).expect("record serializes");

        assert_eq!(record.name, "network.connection.open.count");
        assert_eq!(record.kind, OtelMetricKind::Sum);
        assert_eq!(record.unit, "{connection}");
        assert_eq!(record.value, OtelMetricValue::U64(2));
        assert_eq!(json["attributes"]["net.transport"], "tcp");
        assert_eq!(json["attributes"]["server.address"], "203.0.113.10");
        assert_eq!(json["attributes"]["server.port"], 443);
        assert_eq!(json["window"]["start_unix_nanos"], 100);
    }

    #[test]
    fn ignores_non_metric_signals() {
        let signal = SignalEnvelope::dependency_edge(
            "generator.test",
            None,
            e_navigator_signals::DependencyEdgeEvent {
                source: e_navigator_signals::DependencyEndpoint {
                    workload: None,
                    container: None,
                    address: None,
                    port: None,
                    domain: None,
                },
                destination: e_navigator_signals::DependencyEndpoint {
                    workload: None,
                    container: None,
                    address: None,
                    port: None,
                    domain: Some("api.example.com".to_string()),
                },
                protocol: e_navigator_signals::NetworkProtocol::Udp,
                observations: 1,
                first_seen_unix_nanos: 100,
                last_seen_unix_nanos: 100,
            },
        );

        assert_eq!(format_otel_metric_record(&signal), None);
        assert!(!matches!(
            signal.payload,
            SignalPayload::NetworkCounterMetric(_)
        ));
    }

    #[test]
    fn formats_resource_gauge_metric_as_stable_otel_record() {
        let signal = SignalEnvelope::resource_gauge_metric(
            "generator.resource_metrics",
            Some("node-a".to_string()),
            e_navigator_signals::ResourceGaugeMetric {
                metric_name: "system.memory.available".to_string(),
                unit: "By".to_string(),
                value: 4096,
                window: MetricAggregationWindow {
                    start_unix_nanos: 100,
                    end_unix_nanos: 200,
                },
                resource: e_navigator_signals::ResourceContext {
                    host_name: Some("node-a".to_string()),
                    container: None,
                    kubernetes: None,
                },
                process: None,
                cgroup: None,
                attributes: vec![e_navigator_signals::ResourceMetricAttribute {
                    key: "state".to_string(),
                    value: "available".to_string(),
                }],
            },
        );

        let record = format_otel_metric_record(&signal).expect("resource metric formats");

        assert_eq!(record.name, "system.memory.available");
        assert_eq!(record.kind, OtelMetricKind::Gauge);
        assert_eq!(record.value, OtelMetricValue::I64(4096));
        assert_eq!(record.resource["host.name"], "node-a");
        assert_eq!(record.attributes["state"], "available");
    }

    #[test]
    fn formats_resource_counter_metric_with_process_scope() {
        let signal = SignalEnvelope::resource_counter_metric(
            "generator.resource_metrics",
            Some("node-a".to_string()),
            e_navigator_signals::ResourceCounterMetric {
                metric_name: "process.cpu.time".to_string(),
                unit: "ns".to_string(),
                value: 400,
                window: MetricAggregationWindow {
                    start_unix_nanos: 100,
                    end_unix_nanos: 200,
                },
                resource: e_navigator_signals::ResourceContext {
                    host_name: Some("node-a".to_string()),
                    container: None,
                    kubernetes: None,
                },
                process: Some(e_navigator_signals::ProcessResourceContext {
                    pid: 42,
                    ppid: Some(1),
                    uid: Some(1000),
                    command: "api".to_string(),
                    executable: Some("/app/api".to_string()),
                    container: None,
                    kubernetes: None,
                }),
                cgroup: Some(e_navigator_signals::CgroupResourceContext {
                    cgroup_path: "/kubepods.slice/pod123/container.scope".to_string(),
                    container: None,
                    kubernetes: None,
                }),
                attributes: vec![e_navigator_signals::ResourceMetricAttribute {
                    key: "state".to_string(),
                    value: "total".to_string(),
                }],
            },
        );

        let record = format_otel_metric_record(&signal).expect("resource counter formats");

        assert_eq!(record.name, "process.cpu.time");
        assert_eq!(record.kind, OtelMetricKind::Sum);
        assert_eq!(record.value, OtelMetricValue::U64(400));
        assert_eq!(record.attributes["process.cpu.state"], "total");
        assert_eq!(record.attributes["process.pid"], 42);
        assert_eq!(record.attributes["process.parent_pid"], 1);
        assert_eq!(record.attributes["process.command"], "api");
        assert_eq!(
            record.attributes["linux.cgroup.path"],
            "/kubepods.slice/pod123/container.scope"
        );
    }
}
