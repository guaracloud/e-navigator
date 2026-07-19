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
use serde_json::Value;
use std::collections::BTreeMap;

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
    let resource_spans = resource_spans_from_records(records);
    let request = ExportTraceServiceRequest { resource_spans };
    let mut bytes = Vec::with_capacity(request.encoded_len());
    request
        .encode(&mut bytes)
        .map_err(|err| ExporterError::Encode(err.to_string()))?;
    Ok(bytes)
}

fn resource_spans_from_records(records: &[OtelTraceRecord]) -> Vec<ResourceSpans> {
    let mut groups: Vec<(&BTreeMap<String, Value>, Vec<Span>)> = Vec::new();
    for record in records {
        let Some(span) = span_from_record(record) else {
            continue;
        };
        if let Some(index) = groups
            .iter()
            .position(|(resource, _)| *resource == &record.resource)
        {
            groups[index].1.push(span);
        } else {
            groups.push((&record.resource, vec![span]));
        }
    }

    groups
        .into_iter()
        .map(|(resource, spans)| resource_spans(resource, spans))
        .collect()
}

fn resource_spans(resource: &BTreeMap<String, Value>, spans: Vec<Span>) -> ResourceSpans {
    ResourceSpans {
        resource: Some(Resource {
            attributes: key_values(resource),
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
            spans,
            schema_url: String::new(),
        }],
        schema_url: String::new(),
    }
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
        kind: span_kind(record) as i32,
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

fn span_kind(record: &OtelTraceRecord) -> span::SpanKind {
    match &record.kind {
        OtelTraceRecordKind::RequestSpan
            if record
                .attributes
                .get("e.navigator.protocol.capture.role")
                .and_then(serde_json::Value::as_str)
                == Some("client") =>
        {
            span::SpanKind::Client
        }
        OtelTraceRecordKind::RequestSpan => span::SpanKind::Server,
        OtelTraceRecordKind::ServiceInteraction => span::SpanKind::Client,
        OtelTraceRecordKind::Span
        | OtelTraceRecordKind::ServicePath
        | OtelTraceRecordKind::CorrelationWarning
        | OtelTraceRecordKind::RequestWarning
        | OtelTraceRecordKind::NetworkFlowWarning
        | OtelTraceRecordKind::ProfilingWarning => span::SpanKind::Internal,
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
    if bytes.iter().all(|byte| *byte == 0) {
        return None;
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

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest;

    use super::*;

    #[test]
    fn rejects_all_zero_trace_and_span_ids() {
        let mut record = trace_record();
        record.trace_id = Some("00000000000000000000000000000000".to_string());
        assert!(!trace_record_has_valid_ids(&record));

        record.trace_id = Some("4bf92f3577b34da6a3ce929d0e0e4736".to_string());
        record.span_id = Some("0000000000000000".to_string());
        assert!(!trace_record_has_valid_ids(&record));
    }

    #[test]
    fn drops_all_zero_parent_span_id() {
        let mut record = trace_record();
        record.parent_span_id = Some("0000000000000000".to_string());

        let bytes = encode_trace_export_request(&[record]).expect("trace request encodes");
        let request =
            ExportTraceServiceRequest::decode(bytes.as_slice()).expect("trace request decodes");
        let span = &request.resource_spans[0].scope_spans[0].spans[0];

        assert!(span.parent_span_id.is_empty());
    }

    #[test]
    fn request_capture_role_selects_client_or_server_span_kind() {
        let server = trace_record();
        assert_eq!(span_kind(&server), span::SpanKind::Server);

        let mut client = trace_record();
        client.attributes.insert(
            "e.navigator.protocol.capture.role".to_string(),
            serde_json::json!("client"),
        );
        assert_eq!(span_kind(&client), span::SpanKind::Client);
    }

    #[test]
    fn groups_equal_resources_without_losing_or_merging_spans() {
        let mut first = trace_record();
        first
            .resource
            .insert("service.name".to_string(), serde_json::json!("api"));
        let mut second = first.clone();
        second.span_id = Some("10f067aa0ba902b7".to_string());
        let mut third = first.clone();
        third.span_id = Some("20f067aa0ba902b7".to_string());
        third
            .resource
            .insert("service.name".to_string(), serde_json::json!("worker"));

        let bytes =
            encode_trace_export_request(&[first, second, third]).expect("trace request encodes");
        let request =
            ExportTraceServiceRequest::decode(bytes.as_slice()).expect("trace request decodes");

        assert_eq!(request.resource_spans.len(), 2);
        assert_eq!(request.resource_spans[0].scope_spans[0].spans.len(), 2);
        assert_eq!(request.resource_spans[1].scope_spans[0].spans.len(), 1);
        assert_eq!(
            request
                .resource_spans
                .iter()
                .flat_map(|resource| &resource.scope_spans)
                .flat_map(|scope| &scope.spans)
                .count(),
            3
        );
    }

    fn trace_record() -> OtelTraceRecord {
        OtelTraceRecord {
            name: "request".to_string(),
            kind: OtelTraceRecordKind::RequestSpan,
            status: None,
            trace_id: Some("4bf92f3577b34da6a3ce929d0e0e4736".to_string()),
            span_id: Some("00f067aa0ba902b7".to_string()),
            parent_span_id: None,
            start_unix_nanos: 1_000,
            end_unix_nanos: Some(2_000),
            duration_nanos: Some(1_000),
            resource: BTreeMap::new(),
            attributes: BTreeMap::new(),
        }
    }
}
