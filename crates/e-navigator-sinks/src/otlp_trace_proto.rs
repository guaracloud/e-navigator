use crate::{
    ExporterError, OtelSpanStatus, OtelTraceRecord, OtelTraceRecordKind, otlp_common::key_values,
};
use opentelemetry_proto::tonic::{
    collector::trace::v1::ExportTraceServiceRequest,
    common::v1::InstrumentationScope,
    resource::v1::Resource,
    trace::v1::{ResourceSpans, ScopeSpans, Span, Status, span, status},
};
use prost::Message;

pub(crate) fn trace_record_has_valid_ids(record: &OtelTraceRecord) -> bool {
    record
        .trace_id
        .as_deref()
        .and_then(|trace_id| hex_to_bytes(trace_id, 16))
        .is_some()
        && record
            .span_id
            .as_deref()
            .and_then(|span_id| hex_to_bytes(span_id, 8))
            .is_some()
}

pub(crate) fn encode_trace_export_request(
    records: &[OtelTraceRecord],
) -> Result<Vec<u8>, ExporterError> {
    let resource_spans = records
        .iter()
        .filter_map(resource_spans_from_record)
        .collect::<Vec<_>>();
    let request = ExportTraceServiceRequest { resource_spans };
    let mut bytes = Vec::with_capacity(request.encoded_len());
    request
        .encode(&mut bytes)
        .map_err(|err| ExporterError::Encode(err.to_string()))?;
    Ok(bytes)
}

fn resource_spans_from_record(record: &OtelTraceRecord) -> Option<ResourceSpans> {
    let span = span_from_record(record)?;
    Some(ResourceSpans {
        resource: Some(Resource {
            attributes: key_values(&record.resource),
            dropped_attributes_count: 0,
            entity_refs: Vec::new(),
        }),
        scope_spans: vec![ScopeSpans {
            scope: Some(InstrumentationScope {
                name: "e-navigator".to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
                attributes: Vec::new(),
                dropped_attributes_count: 0,
            }),
            spans: vec![span],
            schema_url: String::new(),
        }],
        schema_url: String::new(),
    })
}

fn span_from_record(record: &OtelTraceRecord) -> Option<Span> {
    let trace_id = hex_to_bytes(record.trace_id.as_deref()?, 16)?;
    let span_id = hex_to_bytes(record.span_id.as_deref()?, 8)?;
    let parent_span_id = record
        .parent_span_id
        .as_deref()
        .and_then(|parent| hex_to_bytes(parent, 8))
        .unwrap_or_default();

    Some(Span {
        trace_id,
        span_id,
        trace_state: String::new(),
        parent_span_id,
        flags: 0,
        name: record.name.clone(),
        kind: span_kind(&record.kind) as i32,
        start_time_unix_nano: record.start_unix_nanos,
        end_time_unix_nano: record.end_unix_nanos.unwrap_or(record.start_unix_nanos),
        attributes: key_values(&record.attributes),
        dropped_attributes_count: 0,
        events: Vec::new(),
        dropped_events_count: 0,
        links: Vec::new(),
        dropped_links_count: 0,
        status: record.status.as_ref().map(status_from_record),
    })
}

fn status_from_record(status: &OtelSpanStatus) -> Status {
    match status {
        OtelSpanStatus::Error { message } => Status {
            message: message.clone(),
            code: status::StatusCode::Error as i32,
        },
    }
}

fn span_kind(kind: &OtelTraceRecordKind) -> span::SpanKind {
    match kind {
        OtelTraceRecordKind::RequestSpan => span::SpanKind::Server,
        OtelTraceRecordKind::ServiceInteraction => span::SpanKind::Client,
        OtelTraceRecordKind::Span
        | OtelTraceRecordKind::ServicePath
        | OtelTraceRecordKind::CorrelationWarning
        | OtelTraceRecordKind::RequestWarning => span::SpanKind::Internal,
    }
}

fn hex_to_bytes(value: &str, expected_len: usize) -> Option<Vec<u8>> {
    if value.len() != expected_len * 2 {
        return None;
    }

    let mut bytes = Vec::with_capacity(expected_len);
    for chunk in value.as_bytes().chunks_exact(2) {
        let high = hex_digit(chunk[0])?;
        let low = hex_digit(chunk[1])?;
        bytes.push((high << 4) | low);
    }
    Some(bytes)
}

fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}
