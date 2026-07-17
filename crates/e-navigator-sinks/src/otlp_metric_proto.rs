use crate::{
    ExporterError, OtelMetricKind, OtelMetricRecord, OtelMetricValue, otlp_common::key_values,
};
use opentelemetry_proto::tonic::{
    collector::metrics::v1::ExportMetricsServiceRequest,
    common::v1::InstrumentationScope,
    metrics::v1::{
        AggregationTemporality, Gauge, Metric, NumberDataPoint, ResourceMetrics, ScopeMetrics, Sum,
        Summary, SummaryDataPoint, metric, number_data_point, summary_data_point,
    },
    resource::v1::Resource,
};
use prost::Message;
use std::collections::BTreeMap;

pub(crate) fn encode_metric_export_request(
    records: &[OtelMetricRecord],
) -> Result<Vec<u8>, ExporterError> {
    let records = coalesce_metric_series(records)?;
    let resource_metrics = records.iter().map(resource_metrics_from_record).collect();
    let request = ExportMetricsServiceRequest { resource_metrics };
    let mut bytes = Vec::with_capacity(request.encoded_len());
    request
        .encode(&mut bytes)
        .map_err(|err| ExporterError::Encode(err.to_string()))?;
    Ok(bytes)
}

fn coalesce_metric_series(
    records: &[OtelMetricRecord],
) -> Result<Vec<OtelMetricRecord>, ExporterError> {
    let mut latest = BTreeMap::new();
    for record in records {
        let key = metric_series_key(record)?;
        match latest.entry(key) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(record.clone());
            }
            std::collections::btree_map::Entry::Occupied(mut entry) => {
                if record.window.end_unix_nanos >= entry.get().window.end_unix_nanos {
                    entry.insert(record.clone());
                }
            }
        }
    }
    Ok(latest.into_values().collect())
}

pub(crate) fn metric_series_key(record: &OtelMetricRecord) -> Result<String, ExporterError> {
    // Prometheus identifies a series by its translated name and labels. Keep
    // the OTLP resource in the key as well: identity attributes are mirrored
    // into the data point today, while receivers may also promote resources.
    // Metric kind is deliberately excluded because changing it does not create
    // a distinct Prometheus series.
    serde_json::to_string(&(
        &record.name,
        &record.unit,
        &record.resource,
        &record.attributes,
    ))
    .map_err(|err| ExporterError::Encode(err.to_string()))
}

fn resource_metrics_from_record(record: &OtelMetricRecord) -> ResourceMetrics {
    ResourceMetrics {
        resource: Some(Resource {
            attributes: key_values(&record.resource),
            dropped_attributes_count: 0,
            entity_refs: Vec::new(),
        }),
        scope_metrics: vec![ScopeMetrics {
            scope: Some(InstrumentationScope {
                name: "e-navigator".to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
                attributes: Vec::new(),
                dropped_attributes_count: 0,
            }),
            metrics: vec![metric_from_record(record)],
            schema_url: String::new(),
        }],
        schema_url: String::new(),
    }
}

fn metric_from_record(record: &OtelMetricRecord) -> Metric {
    Metric {
        name: record.name.clone(),
        description: String::new(),
        unit: record.unit.clone(),
        metadata: Vec::new(),
        data: Some(metric_data(record)),
    }
}

fn metric_data(record: &OtelMetricRecord) -> metric::Data {
    match (&record.kind, &record.value) {
        (OtelMetricKind::Gauge, value) => metric::Data::Gauge(Gauge {
            data_points: vec![number_point(record, value)],
        }),
        (OtelMetricKind::Sum, value) => metric::Data::Sum(Sum {
            data_points: vec![number_point(record, value)],
            aggregation_temporality: AggregationTemporality::Cumulative as i32,
            is_monotonic: true,
        }),
        (
            OtelMetricKind::HistogramSummary,
            OtelMetricValue::Summary {
                count,
                sum_nanos,
                min_nanos,
                max_nanos,
            },
        ) => metric::Data::Summary(Summary {
            data_points: vec![SummaryDataPoint {
                attributes: key_values(&record.attributes),
                start_time_unix_nano: record.window.start_unix_nanos,
                time_unix_nano: record.window.end_unix_nanos,
                count: *count,
                sum: *sum_nanos as f64,
                quantile_values: vec![
                    summary_data_point::ValueAtQuantile {
                        quantile: 0.0,
                        value: *min_nanos as f64,
                    },
                    summary_data_point::ValueAtQuantile {
                        quantile: 1.0,
                        value: *max_nanos as f64,
                    },
                ],
                flags: 0,
            }],
        }),
        (OtelMetricKind::HistogramSummary, value) => metric::Data::Gauge(Gauge {
            data_points: vec![number_point(record, value)],
        }),
    }
}

fn number_point(record: &OtelMetricRecord, value: &OtelMetricValue) -> NumberDataPoint {
    NumberDataPoint {
        attributes: key_values(&record.attributes),
        start_time_unix_nano: record.window.start_unix_nanos,
        time_unix_nano: record.window.end_unix_nanos,
        exemplars: Vec::new(),
        flags: 0,
        value: Some(number_value(value)),
    }
}

fn number_value(value: &OtelMetricValue) -> number_data_point::Value {
    match value {
        OtelMetricValue::U64(value) => match i64::try_from(*value) {
            Ok(value) => number_data_point::Value::AsInt(value),
            Err(_) => number_data_point::Value::AsDouble(*value as f64),
        },
        OtelMetricValue::I64(value) => number_data_point::Value::AsInt(*value),
        OtelMetricValue::Summary { sum_nanos, .. } => {
            number_data_point::Value::AsDouble(*sum_nanos as f64)
        }
    }
}

#[cfg(test)]
mod tests {
    use e_navigator_signals::MetricAggregationWindow;

    use super::*;

    #[test]
    fn coalesces_cumulative_series_to_latest_window() {
        let first = metric_record("node-a", 1, 100);
        let latest = metric_record("node-a", 2, 200);

        let records = coalesce_metric_series(&[first, latest.clone()]).expect("coalesces");

        assert_eq!(records, vec![latest]);
    }

    #[test]
    fn preserves_independent_resource_series() {
        let first = metric_record("node-a", 1, 100);
        let second = metric_record("node-b", 1, 100);

        let records = coalesce_metric_series(&[first, second]).expect("coalesces");

        assert_eq!(records.len(), 2);
    }

    #[test]
    fn encodes_counter_records_as_cumulative_sums() {
        let record = metric_record("node-a", 2, 200);

        let metric::Data::Sum(sum) = metric_data(&record) else {
            panic!("counter must encode as sum");
        };

        assert_eq!(
            sum.aggregation_temporality,
            AggregationTemporality::Cumulative as i32
        );
        assert!(sum.is_monotonic);
    }

    fn metric_record(host: &str, value: u64, timestamp: u64) -> OtelMetricRecord {
        OtelMetricRecord {
            name: "network.connection.open.count".to_string(),
            unit: "{connection}".to_string(),
            kind: OtelMetricKind::Sum,
            value: OtelMetricValue::U64(value),
            window: MetricAggregationWindow {
                start_unix_nanos: 100,
                end_unix_nanos: timestamp,
            },
            resource: BTreeMap::from([("host.name".to_string(), serde_json::json!(host))]),
            attributes: BTreeMap::from([("net.transport".to_string(), serde_json::json!("tcp"))]),
        }
    }
}
