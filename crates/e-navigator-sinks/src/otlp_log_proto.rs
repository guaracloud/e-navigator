use crate::{
    ExporterError, exporter::ExportResponseAck, otlp_common::key_values,
    otlp_trace_proto::hex_to_bytes,
};
use e_navigator_signals::{ApplicationLogObservation, LogStream};
use opentelemetry_proto::tonic::{
    collector::logs::v1::{ExportLogsServiceRequest, ExportLogsServiceResponse},
    common::v1::{AnyValue, InstrumentationScope, any_value},
    logs::v1::{LogRecord, ResourceLogs, ScopeLogs},
    resource::v1::Resource,
};
use prost::Message;
use serde_json::{Value, json};
use std::collections::BTreeMap;

// Private worker input prevents raw native bodies entering this queue.
#[derive(Clone)]
pub(crate) struct ExportLogRecord {
    resource: BTreeMap<String, Value>,
    record: LogRecord,
}
impl std::fmt::Debug for ExportLogRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExportLogRecord").finish_non_exhaustive()
    }
}
pub(crate) fn format_log_record(
    log: &ApplicationLogObservation,
    host: Option<&str>,
) -> Option<ExportLogRecord> {
    let processed = log.processing.as_ref()?;
    if log.body.as_ref().is_some_and(|b| b.len() > 32768)
        || processed.attributes.len() > 32
        || processed
            .attributes
            .iter()
            .any(|(k, v)| k.len() > 64 || v.len() > 256)
        || processed
            .severity_text
            .as_ref()
            .is_some_and(|v| v.len() > 256)
        || [
            &log.namespace,
            &log.pod_name,
            &log.pod_uid,
            &log.container_name,
        ]
        .iter()
        .any(|v| v.is_empty() || v.len() > 256)
        || processed
            .workload_name
            .as_ref()
            .is_some_and(|v| v.len() > 256)
        || processed
            .workload_kind
            .as_ref()
            .is_some_and(|v| v.len() > 256)
    {
        return None;
    }
    let time = utc_nanos(&log.timestamp)?;
    let resource = BTreeMap::from([
        ("k8s.namespace.name".into(), json!(log.namespace)),
        ("k8s.pod.name".into(), json!(log.pod_name)),
        ("k8s.pod.uid".into(), json!(log.pod_uid)),
        ("k8s.container.name".into(), json!(log.container_name)),
        (
            "k8s.container.restart_count".into(),
            json!(log.restart_count),
        ),
        ("service.name".into(), json!(log.container_name)),
        ("service.namespace".into(), json!(log.namespace)),
    ]);
    let mut resource = resource;
    if let Some(name) = &processed.workload_name {
        resource.insert("e.navigator.workload.name".into(), json!(name));
        resource.insert("service.name".into(), json!(name));
    }
    if let Some(kind) = &processed.workload_kind {
        resource.insert("e.navigator.workload.kind".into(), json!(kind));
    }
    if let Some(host) = host {
        resource.insert("host.name".into(), json!(host));
    }
    let mut attributes = BTreeMap::from([
        (
            "e.navigator.log.workload_attributed".into(),
            json!(processed.workload_name.is_some()),
        ),
        (
            "log.iostream".into(),
            json!(match log.stream {
                LogStream::Stdout => "stdout",
                LogStream::Stderr => "stderr",
            }),
        ),
        ("e.navigator.log.truncated".into(), json!(log.truncated)),
        ("e.navigator.log.incomplete".into(), json!(log.incomplete)),
        (
            "e.navigator.log.invalid_utf8".into(),
            json!(log.invalid_utf8),
        ),
        ("e.navigator.log.body_bytes".into(), json!(log.body_bytes)),
        (
            "e.navigator.log.processing".into(),
            json!(processed.outcome),
        ),
    ]);
    // Application fields have a separate namespace and cannot overwrite resource/loss facts.
    for (key, value) in &processed.attributes {
        attributes.insert(format!("e.navigator.log.field.{key}"), json!(value));
    }
    let severity_text = processed.severity_text.clone().unwrap_or_default();
    let severity_number = match severity_text.to_ascii_uppercase().as_str() {
        "TRACE" => 1,
        "DEBUG" => 5,
        "INFO" | "INFORMATION" => 9,
        "WARN" | "WARNING" => 13,
        "ERROR" => 17,
        "FATAL" | "CRITICAL" => 21,
        _ => 0,
    };
    let trace_id = processed
        .trace_id
        .as_deref()
        .and_then(|v| hex_to_bytes(v, 16))
        .unwrap_or_default();
    let span_id = if trace_id.is_empty() {
        vec![]
    } else {
        processed
            .span_id
            .as_deref()
            .and_then(|v| hex_to_bytes(v, 8))
            .unwrap_or_default()
    };
    Some(ExportLogRecord {
        resource,
        record: LogRecord {
            time_unix_nano: time,
            observed_time_unix_nano: log.observed_at_unix_nanos,
            severity_text,
            severity_number,
            body: log.body.as_ref().map(|v| AnyValue {
                value: Some(any_value::Value::StringValue(v.clone())),
            }),
            attributes: key_values(&attributes),
            trace_id,
            span_id,
            ..Default::default()
        },
    })
}
pub(crate) fn encode_log_export_request(
    records: &[ExportLogRecord],
) -> Result<Vec<u8>, ExporterError> {
    let resource_logs = records
        .iter()
        .map(|record| ResourceLogs {
            resource: Some(Resource {
                attributes: key_values(&record.resource),
                ..Default::default()
            }),
            scope_logs: vec![ScopeLogs {
                scope: Some(InstrumentationScope {
                    name: "e-navigator".into(),
                    ..Default::default()
                }),
                log_records: vec![record.record.clone()],
                ..Default::default()
            }],
            ..Default::default()
        })
        .collect();
    Ok(ExportLogsServiceRequest { resource_logs }.encode_to_vec())
}
pub(crate) fn decode_log_export_response(body: &[u8]) -> Result<ExportResponseAck, ExporterError> {
    let response = ExportLogsServiceResponse::decode(body)
        .map_err(|_| ExporterError::InvalidResponse("invalid log response".into()))?;
    let Some(partial) = response.partial_success else {
        return Ok(ExportResponseAck::default());
    };
    let rejected_items = u64::try_from(partial.rejected_log_records)
        .map_err(|_| ExporterError::InvalidResponse("negative rejected_log_records".into()))?;
    Ok(ExportResponseAck {
        rejected_items,
        warning: !partial.error_message.is_empty(),
    })
}

// CRI uses UTC RFC3339, with up to nine fractional digits. No local timezone or floating point.
fn utc_nanos(value: &str) -> Option<u64> {
    let b = value.as_bytes();
    if !(20..=30).contains(&b.len())
        || b[4] != b'-'
        || b[7] != b'-'
        || b[10] != b'T'
        || b[13] != b':'
        || b[16] != b':'
        || b.last() != Some(&b'Z')
    {
        return None;
    }
    let number = |start, end| -> Option<u64> {
        b.get(start..end)?.iter().try_fold(0u64, |n, c| {
            c.is_ascii_digit().then(|| n * 10 + u64::from(c - b'0'))
        })
    };
    let (year, month, day, hour, minute, second) = (
        number(0, 4)?,
        number(5, 7)?,
        number(8, 10)?,
        number(11, 13)?,
        number(14, 16)?,
        number(17, 19)?,
    );
    if year < 1970 || month == 0 || month > 12 || hour > 23 || minute > 59 || second > 59 {
        return None;
    }
    let leap = |y: u64| y.is_multiple_of(4) && (!y.is_multiple_of(100) || y.is_multiple_of(400));
    let months = [
        31,
        if leap(year) { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    if day == 0 || day > months[usize::try_from(month - 1).ok()?] {
        return None;
    }
    let prior = year - 1;
    let leaps = prior / 4 - prior / 100 + prior / 400 - (1969 / 4 - 1969 / 100 + 1969 / 400);
    let days = (year - 1970) * 365
        + leaps
        + months[..usize::try_from(month - 1).ok()?]
            .iter()
            .sum::<u64>()
        + day
        - 1;
    let fraction = if b.len() == 20 {
        0
    } else {
        if b[19] != b'.' || b.len() < 22 {
            return None;
        }
        number(20, b.len() - 1)? * 10u64.pow(u32::try_from(30 - b.len()).ok()?)
    };
    (days * 86400 + hour * 3600 + minute * 60 + second)
        .checked_mul(1_000_000_000)?
        .checked_add(fraction)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn preserves_fractional_utc_time_and_rejects_invalid_or_unrepresentable_dates() {
        assert_eq!(utc_nanos("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(utc_nanos("1970-01-01T00:00:00.1Z"), Some(100_000_000));
        assert_eq!(
            utc_nanos("2000-02-29T00:00:00.000000001Z"),
            Some(951782400000000001)
        );
        assert_eq!(
            utc_nanos("2026-10-11T00:00:00.123456789Z"),
            Some(1791676800123456789)
        );
        assert_eq!(utc_nanos("2554-07-21T23:34:33.709551615Z"), Some(u64::MAX));
        for date in [
            "2554-07-21T23:34:33.709551616Z",
            "2026-02-29T00:00:00Z",
            "2026-10-11T24:00:00Z",
            "2026-10-11T00:00:60Z",
            "2026-10-11T00:00:00.Z",
            "2026-10-11T00:00:00.1234567890Z",
            "1969-12-31T00:00:00Z",
            "2026-10-11T00:00:00+01:00",
            "not-a-time",
        ] {
            assert_eq!(utc_nanos(date), None, "{date}");
        }
    }
    #[test]
    fn log_acknowledgement_never_discloses_backend_text() {
        use opentelemetry_proto::tonic::collector::logs::v1::ExportLogsPartialSuccess;
        let response = ExportLogsServiceResponse {
            partial_success: Some(ExportLogsPartialSuccess {
                rejected_log_records: -1,
                error_message: "private response".into(),
            }),
        }
        .encode_to_vec();
        let result = decode_log_export_response(&response);
        assert!(result.is_err());
        assert!(!format!("{result:?}").contains("private response"));
        assert!(decode_log_export_response(&[255, 255]).is_err());
    }
}
