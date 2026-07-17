use e_navigator_signals::{
    DnsCounterMetric, DnsLatencyMetric, MetricAggregationWindow, NetworkAddressFamily,
    NetworkCounterMetric, NetworkDurationMetric, NetworkGaugeMetric, NetworkProtocol,
    ResourceCounterMetric, ResourceGaugeMetric, SignalEnvelope, SignalPayload,
};
use serde::Serialize;
use std::collections::BTreeMap;

const MAX_METRIC_STRING_BYTES: usize = 256;
const MAX_METRIC_ATTRIBUTE_KEY_BYTES: usize = 128;
const MAX_METRIC_ATTRIBUTES: usize = 16;

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
    let mut record = match &signal.payload {
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
    }?;
    mirror_metric_identity_attributes(&mut record);
    Some(record)
}

fn mirror_metric_identity_attributes(record: &mut OtelMetricRecord) {
    // Some otherwise conforming OTLP-to-Prometheus pipelines require an
    // explicit resource-to-telemetry conversion step. Preserve the canonical
    // resource attributes and also mirror only the bounded identity fields
    // into the data point so independent node/workload series cannot collide
    // when that collector option is absent.
    const IDENTITY_KEYS: &[&str] = &[
        "host.name",
        "container.id",
        "container.runtime",
        "k8s.namespace.name",
        "k8s.pod.name",
        "k8s.pod.uid",
        "k8s.container.name",
        "k8s.node.name",
    ];

    for key in IDENTITY_KEYS {
        if let Some(value) = record.resource.get(*key) {
            record
                .attributes
                .entry((*key).to_string())
                .or_insert_with(|| value.clone());
        }
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
        name: bounded_metric_string(&metric.metric_name),
        unit: bounded_metric_string(&metric.unit),
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
        name: bounded_metric_string(&metric.metric_name),
        unit: bounded_metric_string(&metric.unit),
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
        name: bounded_metric_string(&metric.metric_name),
        unit: bounded_metric_string(&metric.unit),
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
        name: bounded_metric_string(&metric.metric_name),
        unit: bounded_metric_string(&metric.unit),
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
        name: bounded_metric_string(&metric.metric_name),
        unit: bounded_metric_string(&metric.unit),
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
        name: bounded_metric_string(&metric.metric_name),
        unit: bounded_metric_string(&metric.unit),
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
        name: bounded_metric_string(&metric.metric_name),
        unit: bounded_metric_string(&metric.unit),
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
        insert_resource_string(&mut resource, "host.name", host);
    }
    if let Some(container) = container {
        insert_resource_string(&mut resource, "container.id", &container.container_id);
        if let Some(runtime) = &container.runtime {
            insert_resource_string(&mut resource, "container.runtime", runtime);
        }
    }
    if let Some(kubernetes) = kubernetes {
        insert_resource_string(&mut resource, "k8s.namespace.name", &kubernetes.namespace);
        insert_resource_string(&mut resource, "k8s.pod.name", &kubernetes.pod_name);
        if let Some(uid) = &kubernetes.pod_uid {
            insert_resource_string(&mut resource, "k8s.pod.uid", uid);
        }
        if let Some(container_name) = &kubernetes.container_name {
            insert_resource_string(&mut resource, "k8s.container.name", container_name);
        }
        if let Some(node_name) = &kubernetes.node_name {
            insert_resource_string(&mut resource, "k8s.node.name", node_name);
        }
    }
    resource
}

fn insert_resource_string(
    resource: &mut BTreeMap<String, serde_json::Value>,
    key: &'static str,
    value: &str,
) {
    resource.insert(key.to_string(), bounded_json_string(value));
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
        insert_resource_string(&mut resource, "host.name", host);
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
        insert_resource_string(&mut resource, "host.name", host);
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
    for attribute in attributes.iter().take(MAX_METRIC_ATTRIBUTES) {
        if !metric_attribute_allowed(&attribute.key) {
            continue;
        }
        let key = resource_attribute_key(metric_name, &attribute.key, &attribute.value);
        insert_attribute_string(&mut mapped, key, &attribute.value);
    }
    if let Some(process) = process {
        mapped.insert("process.pid".to_string(), serde_json::json!(process.pid));
        if let Some(ppid) = process.ppid {
            mapped.insert("process.parent_pid".to_string(), serde_json::json!(ppid));
        }
        mapped.insert(
            "process.command".to_string(),
            bounded_json_string(&process.command),
        );
    }
    if let Some(cgroup) = cgroup {
        mapped.insert(
            "linux.cgroup.path".to_string(),
            bounded_json_string(&cgroup.cgroup_path),
        );
    }
    mapped
}

fn insert_attribute_string(
    attributes: &mut BTreeMap<String, serde_json::Value>,
    key: impl Into<String>,
    value: &str,
) {
    let key = key.into();
    attributes.insert(
        truncate_utf8(&key, MAX_METRIC_ATTRIBUTE_KEY_BYTES),
        bounded_json_string(value),
    );
}

fn metric_attribute_allowed(key: &str) -> bool {
    const AUTH_FRAGMENT: &str = concat!("au", "th");
    const SENSITIVE_FRAGMENTS: &[&str] = &[
        "authorization",
        AUTH_FRAGMENT,
        "token",
        "password",
        "passwd",
        "secret",
        "credential",
        "api_key",
        "api-key",
        "apikey",
        "api-token",
        "cookie",
        "private_key",
        "jwt",
    ];

    !SENSITIVE_FRAGMENTS
        .iter()
        .any(|sensitive| contains_ascii_case_insensitive(key, sensitive))
}

fn contains_ascii_case_insensitive(haystack: &str, needle: &str) -> bool {
    haystack
        .as_bytes()
        .windows(needle.len())
        .any(|window| window.eq_ignore_ascii_case(needle.as_bytes()))
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
        insert_attribute_string(&mut attributes, "server.address", remote_address);
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
        insert_attribute_string(&mut attributes, "dns.question.name", query_name);
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

fn bounded_json_string(value: &str) -> serde_json::Value {
    serde_json::json!(truncate_utf8(value, MAX_METRIC_STRING_BYTES))
}

fn bounded_metric_string(value: &str) -> String {
    truncate_utf8(value, MAX_METRIC_STRING_BYTES)
}

fn truncate_utf8(value: &str, max_bytes: usize) -> String {
    if value.len() <= max_bytes {
        return value.to_string();
    }

    let mut end = max_bytes;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_string()
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
    fn mirrors_bounded_resource_identity_into_metric_attributes() {
        let signal = SignalEnvelope::network_counter_metric(
            "generator.network_metrics",
            Some("node-a".to_string()),
            NetworkCounterMetric {
                metric_name: "network.flow.bytes".to_string(),
                unit: "By".to_string(),
                value: 4096,
                window: MetricAggregationWindow {
                    start_unix_nanos: 100,
                    end_unix_nanos: 200,
                },
                process: None,
                protocol: Some(e_navigator_signals::NetworkProtocol::Tcp),
                address_family: Some(e_navigator_signals::NetworkAddressFamily::Ipv4),
                local_address: None,
                local_port: None,
                remote_address: None,
                remote_port: None,
                errno: None,
                container: Some(e_navigator_signals::ContainerContext {
                    container_id: "container-a".to_string(),
                    runtime: Some("containerd".to_string()),
                }),
                kubernetes: Some(e_navigator_signals::KubernetesContext {
                    namespace: "proj-paid".to_string(),
                    pod_name: "api-0".to_string(),
                    pod_uid: Some("pod-uid-a".to_string()),
                    container_name: Some("api".to_string()),
                    node_name: Some("node-a".to_string()),
                    labels: BTreeMap::new(),
                }),
            },
        );

        let record = format_otel_metric_record(&signal).expect("metric formats");

        for key in [
            "host.name",
            "container.id",
            "container.runtime",
            "k8s.namespace.name",
            "k8s.pod.name",
            "k8s.pod.uid",
            "k8s.container.name",
            "k8s.node.name",
        ] {
            assert_eq!(record.attributes[key], record.resource[key]);
        }
    }

    #[test]
    fn formats_flow_byte_metric_without_endpoint_attributes() {
        let signal = SignalEnvelope::network_counter_metric(
            "generator.network_metrics",
            Some("node-a".to_string()),
            NetworkCounterMetric {
                metric_name: "network.flow.bytes".to_string(),
                unit: "By".to_string(),
                value: 4096,
                window: MetricAggregationWindow {
                    start_unix_nanos: 100,
                    end_unix_nanos: 200,
                },
                process: None,
                protocol: Some(e_navigator_signals::NetworkProtocol::Tcp),
                address_family: Some(e_navigator_signals::NetworkAddressFamily::Ipv4),
                local_address: None,
                local_port: None,
                remote_address: None,
                remote_port: None,
                errno: None,
                container: None,
                kubernetes: None,
            },
        );

        let record = format_otel_metric_record(&signal).expect("metric formats");
        let json = serde_json::to_value(&record).expect("record serializes");

        assert_eq!(record.name, "network.flow.bytes");
        assert_eq!(record.unit, "By");
        assert_eq!(record.value, OtelMetricValue::U64(4096));
        assert_eq!(json["attributes"]["net.transport"], "tcp");
        assert_eq!(json["attributes"]["network.type"], "ipv4");
        assert!(json["attributes"].get("server.address").is_none());
        assert!(json["attributes"].get("server.port").is_none());
    }

    #[test]
    fn bounds_network_and_dns_metric_string_attributes() {
        const MAX_VALUE_BYTES: usize = 256;

        let long_value = "m".repeat(MAX_VALUE_BYTES + 64);
        let network = SignalEnvelope::network_counter_metric(
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
                remote_address: Some(long_value.clone()),
                remote_port: Some(443),
                errno: None,
                container: None,
                kubernetes: None,
            },
        );
        let dns = SignalEnvelope::dns_counter_metric(
            "generator.dns_metrics",
            Some("node-a".to_string()),
            e_navigator_signals::DnsCounterMetric {
                metric_name: "dns.query.count".to_string(),
                unit: "{query}".to_string(),
                value: 1,
                window: MetricAggregationWindow {
                    start_unix_nanos: 100,
                    end_unix_nanos: 200,
                },
                query_name: Some(long_value),
                query_type: None,
                response_code: None,
                server_address: None,
                server_port: None,
                container: None,
                kubernetes: None,
            },
        );

        let network_record = format_otel_metric_record(&network).expect("network metric formats");
        let dns_record = format_otel_metric_record(&dns).expect("dns metric formats");

        assert_eq!(
            network_record.attributes["server.address"]
                .as_str()
                .map(str::len),
            Some(MAX_VALUE_BYTES)
        );
        assert_eq!(
            dns_record.attributes["dns.question.name"]
                .as_str()
                .map(str::len),
            Some(MAX_VALUE_BYTES)
        );
    }

    #[test]
    fn bounds_metric_name_and_unit_strings() {
        const MAX_VALUE_BYTES: usize = 256;

        let signal = SignalEnvelope::network_counter_metric(
            "generator.network_metrics",
            Some("node-a".to_string()),
            NetworkCounterMetric {
                metric_name: "n".repeat(MAX_VALUE_BYTES + 64),
                unit: "u".repeat(MAX_VALUE_BYTES + 64),
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
                remote_address: None,
                remote_port: None,
                errno: None,
                container: None,
                kubernetes: None,
            },
        );

        let record = format_otel_metric_record(&signal).expect("metric formats");

        assert_eq!(record.name.len(), MAX_VALUE_BYTES);
        assert_eq!(record.unit.len(), MAX_VALUE_BYTES);
    }

    #[test]
    fn bounds_metric_attribute_keys() {
        const MAX_KEY_BYTES: usize = 128;

        let long_key = "k".repeat(MAX_KEY_BYTES + 64);
        let signal = SignalEnvelope::resource_gauge_metric(
            "generator.resource_metrics",
            Some("node-a".to_string()),
            e_navigator_signals::ResourceGaugeMetric {
                metric_name: "custom.resource.metric".to_string(),
                unit: "1".to_string(),
                value: 1,
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
                    key: long_key,
                    value: "value".to_string(),
                }],
            },
        );

        let record = format_otel_metric_record(&signal).expect("resource metric formats");
        let key = record
            .attributes
            .keys()
            .find(|key| key.starts_with('k'))
            .expect("bounded attribute key exists");

        assert_eq!(key.len(), MAX_KEY_BYTES);
    }

    #[test]
    fn bounds_custom_resource_metric_attributes_while_preserving_identity() {
        let attributes = (0..(MAX_METRIC_ATTRIBUTES + 4))
            .map(|index| e_navigator_signals::ResourceMetricAttribute {
                key: format!("custom.attribute.{index}"),
                value: "value".to_string(),
            })
            .collect();
        let signal = SignalEnvelope::resource_gauge_metric(
            "generator.resource_metrics",
            Some("node-a".to_string()),
            e_navigator_signals::ResourceGaugeMetric {
                metric_name: "custom.resource.metric".to_string(),
                unit: "1".to_string(),
                value: 1,
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
                attributes,
            },
        );

        let record = format_otel_metric_record(&signal).expect("resource metric formats");

        assert_eq!(record.attributes.len(), MAX_METRIC_ATTRIBUTES + 1);
        assert_eq!(record.attributes["host.name"], "node-a");
        assert!(record.attributes.contains_key("custom.attribute.15"));
        assert!(!record.attributes.contains_key("custom.attribute.16"));
    }

    #[test]
    fn filters_sensitive_resource_metric_attributes() {
        let signal = SignalEnvelope::resource_gauge_metric(
            "generator.resource_metrics",
            Some("node-a".to_string()),
            e_navigator_signals::ResourceGaugeMetric {
                metric_name: "custom.resource.metric".to_string(),
                unit: "1".to_string(),
                value: 1,
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
                attributes: vec![
                    e_navigator_signals::ResourceMetricAttribute {
                        key: "x-api-key".to_string(),
                        value: "secret-token".to_string(),
                    },
                    e_navigator_signals::ResourceMetricAttribute {
                        key: "custom.attribute".to_string(),
                        value: "visible".to_string(),
                    },
                ],
            },
        );

        let record = format_otel_metric_record(&signal).expect("resource metric formats");

        assert!(!record.attributes.contains_key("x-api-key"));
        assert!(
            !record
                .attributes
                .values()
                .any(|value| value.as_str() == Some("secret-token"))
        );
        assert_eq!(
            record
                .attributes
                .get("custom.attribute")
                .and_then(serde_json::Value::as_str),
            Some("visible")
        );
    }

    #[test]
    fn ignores_non_metric_signals() {
        let signal = SignalEnvelope::dependency_edge(
            "generator.test",
            None,
            e_navigator_signals::DependencyEdgeEvent {
                source: e_navigator_signals::DependencyEndpoint {
                    owner_name: None,
                    owner_type: None,
                    workload: None,
                    container: None,
                    address: None,
                    port: None,
                    domain: None,
                },
                destination: e_navigator_signals::DependencyEndpoint {
                    owner_name: None,
                    owner_type: None,
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
    fn bounds_metric_resource_and_scope_strings() {
        const MAX_VALUE_BYTES: usize = 256;

        let long_value = "r".repeat(MAX_VALUE_BYTES + 64);
        let container = e_navigator_signals::ContainerContext {
            container_id: long_value.clone(),
            runtime: Some(long_value.clone()),
        };
        let mut labels = BTreeMap::new();
        labels.insert("app".to_string(), "api".to_string());
        let kubernetes = e_navigator_signals::KubernetesContext {
            namespace: long_value.clone(),
            pod_name: long_value.clone(),
            pod_uid: Some(long_value.clone()),
            container_name: Some(long_value.clone()),
            node_name: Some(long_value.clone()),
            labels,
        };
        let signal = SignalEnvelope::resource_counter_metric(
            "generator.resource_metrics",
            Some(long_value.clone()),
            e_navigator_signals::ResourceCounterMetric {
                metric_name: "process.cpu.time".to_string(),
                unit: "ns".to_string(),
                value: 400,
                window: MetricAggregationWindow {
                    start_unix_nanos: 100,
                    end_unix_nanos: 200,
                },
                resource: e_navigator_signals::ResourceContext {
                    host_name: Some(long_value.clone()),
                    container: Some(container.clone()),
                    kubernetes: Some(kubernetes.clone()),
                },
                process: Some(e_navigator_signals::ProcessResourceContext {
                    pid: 42,
                    ppid: Some(1),
                    uid: Some(1000),
                    command: long_value.clone(),
                    executable: Some("/app/api".to_string()),
                    container: Some(container),
                    kubernetes: Some(kubernetes),
                }),
                cgroup: Some(e_navigator_signals::CgroupResourceContext {
                    cgroup_path: long_value.clone(),
                    container: None,
                    kubernetes: None,
                }),
                attributes: vec![e_navigator_signals::ResourceMetricAttribute {
                    key: "state".to_string(),
                    value: long_value,
                }],
            },
        );

        let record = format_otel_metric_record(&signal).expect("resource counter formats");

        for key in [
            "host.name",
            "container.id",
            "container.runtime",
            "k8s.namespace.name",
            "k8s.pod.name",
            "k8s.pod.uid",
            "k8s.container.name",
            "k8s.node.name",
        ] {
            assert_eq!(
                record.resource[key].as_str().map(str::len),
                Some(MAX_VALUE_BYTES)
            );
        }
        for key in ["process.cpu.state", "process.command", "linux.cgroup.path"] {
            assert_eq!(
                record.attributes[key].as_str().map(str::len),
                Some(MAX_VALUE_BYTES)
            );
        }
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
