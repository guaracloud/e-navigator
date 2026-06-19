use e_navigator_signals::{CompatibilityCounterMetric, MetricAggregationWindow, SignalEnvelope};
use e_navigator_sinks::{
    OtelMetricKind, OtelMetricValue, format_otel_metric_record,
    format_prometheus_compatibility_metric,
};
use std::collections::BTreeMap;

#[test]
fn compatibility_metric_formats_for_otlp_metric_boundary() {
    let signal = compatibility_signal();

    let record = format_otel_metric_record(&signal).expect("metric formats");

    assert_eq!(record.name, "beyla_network_flow_bytes_total");
    assert_eq!(record.unit, "By");
    assert_eq!(record.kind, OtelMetricKind::Sum);
    assert_eq!(record.value, OtelMetricValue::U64(4096));
    assert_eq!(record.attributes["k8s_src_namespace"], "proj-paid");
    assert_eq!(record.attributes["k8s_dst_namespace"], "proj-paid");
    assert_eq!(record.attributes["k8s_src_owner_name"], "api");
    assert_eq!(record.attributes["k8s_dst_owner_name"], "redis");
    assert!(!record.attributes.contains_key("src_address"));
    assert!(!record.attributes.contains_key("dst_port"));
}

#[test]
fn compatibility_metric_formats_for_prometheus_scrape_boundary() {
    let signal = compatibility_signal();

    let line = format_prometheus_compatibility_metric(&signal).expect("metric formats");

    assert_eq!(line.name, "beyla_network_flow_bytes_total");
    assert_eq!(line.value, 4096);
    assert_eq!(line.labels["k8s_src_owner_type"], "deployment");
    assert_eq!(line.labels["k8s_dst_owner_type"], "statefulset");
}

fn compatibility_signal() -> SignalEnvelope {
    SignalEnvelope::compatibility_counter_metric(
        "generator.guara_compat",
        Some("node-a".to_string()),
        CompatibilityCounterMetric {
            metric_name: "beyla_network_flow_bytes_total".to_string(),
            unit: "By".to_string(),
            value: 4096,
            window: MetricAggregationWindow {
                start_unix_nanos: 1,
                end_unix_nanos: 2,
            },
            labels: BTreeMap::from([
                ("k8s_src_namespace".to_string(), "proj-paid".to_string()),
                ("k8s_src_owner_name".to_string(), "api".to_string()),
                ("k8s_src_owner_type".to_string(), "deployment".to_string()),
                ("k8s_dst_namespace".to_string(), "proj-paid".to_string()),
                ("k8s_dst_owner_name".to_string(), "redis".to_string()),
                ("k8s_dst_owner_type".to_string(), "statefulset".to_string()),
            ]),
        },
    )
}
