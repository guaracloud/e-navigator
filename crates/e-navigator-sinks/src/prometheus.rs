use e_navigator_signals::{CompatibilityCounterMetric, SignalEnvelope, SignalPayload};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrometheusMetricLine {
    pub name: String,
    pub labels: BTreeMap<String, String>,
    pub value: u64,
}

pub fn format_prometheus_compatibility_metric(
    signal: &SignalEnvelope,
) -> Option<PrometheusMetricLine> {
    match &signal.payload {
        SignalPayload::CompatibilityCounterMetric(metric) => Some(metric_line(metric)),
        _ => None,
    }
}

pub fn render_prometheus_text(metrics: &[PrometheusMetricLine]) -> String {
    let mut output = String::new();
    for metric in metrics {
        output.push_str(&metric.name);
        if !metric.labels.is_empty() {
            output.push('{');
            for (index, (key, value)) in metric.labels.iter().enumerate() {
                if index > 0 {
                    output.push(',');
                }
                output.push_str(key);
                output.push_str("=\"");
                output.push_str(&escape_label_value(value));
                output.push('"');
            }
            output.push('}');
        }
        output.push(' ');
        output.push_str(&metric.value.to_string());
        output.push('\n');
    }
    output
}

fn metric_line(metric: &CompatibilityCounterMetric) -> PrometheusMetricLine {
    PrometheusMetricLine {
        name: metric.metric_name.clone(),
        labels: metric.labels.clone(),
        value: metric.value,
    }
}

fn escape_label_value(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('\n', "\\n")
        .replace('"', "\\\"")
}

#[cfg(test)]
mod tests {
    use super::*;
    use e_navigator_signals::{CompatibilityCounterMetric, MetricAggregationWindow};

    #[test]
    fn renders_beyla_compatibility_counter_with_stable_labels() {
        let signal = SignalEnvelope::compatibility_counter_metric(
            "generator.guara_compat",
            Some("node-a".to_string()),
            CompatibilityCounterMetric {
                metric_name: "beyla_network_flow_bytes_total".to_string(),
                unit: "By".to_string(),
                value: 2048,
                window: MetricAggregationWindow {
                    start_unix_nanos: 1,
                    end_unix_nanos: 2,
                },
                labels: BTreeMap::from([
                    ("k8s_dst_namespace".to_string(), "proj-a".to_string()),
                    ("k8s_dst_owner_name".to_string(), "redis".to_string()),
                    ("k8s_dst_owner_type".to_string(), "statefulset".to_string()),
                    ("k8s_src_namespace".to_string(), "proj-a".to_string()),
                    ("k8s_src_owner_name".to_string(), "api".to_string()),
                    ("k8s_src_owner_type".to_string(), "deployment".to_string()),
                ]),
            },
        );

        let line = format_prometheus_compatibility_metric(&signal).expect("metric formats");
        let rendered = render_prometheus_text(&[line]);

        assert_eq!(
            rendered,
            "beyla_network_flow_bytes_total{k8s_dst_namespace=\"proj-a\",k8s_dst_owner_name=\"redis\",k8s_dst_owner_type=\"statefulset\",k8s_src_namespace=\"proj-a\",k8s_src_owner_name=\"api\",k8s_src_owner_type=\"deployment\"} 2048\n"
        );
    }
}
