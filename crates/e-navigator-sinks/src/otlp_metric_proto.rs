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

pub(crate) fn encode_metric_export_request(
    records: &[OtelMetricRecord],
) -> Result<Vec<u8>, ExporterError> {
    let resource_metrics = records.iter().map(resource_metrics_from_record).collect();
    let request = ExportMetricsServiceRequest { resource_metrics };
    let mut bytes = Vec::with_capacity(request.encoded_len());
    request
        .encode(&mut bytes)
        .map_err(|err| ExporterError::Encode(err.to_string()))?;
    Ok(bytes)
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
            aggregation_temporality: AggregationTemporality::Delta as i32,
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
