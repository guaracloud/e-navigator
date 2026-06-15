use e_navigator_signals::{ProtocolKind, TraceAttribute};

use crate::{
    ProtocolExtractionConfig,
    trace_context::{TraceContext, parse_traceparent},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedHttpRequest {
    pub protocol: ProtocolKind,
    pub method: Option<String>,
    pub trace_context: Option<TraceContext>,
    pub traceparent: Option<String>,
    pub tracestate: Option<String>,
    pub warning: Option<String>,
    pub attributes: Vec<TraceAttribute>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpExtraction {
    HeadersTooLong,
    InvalidUtf8,
    RequestLineTooLong,
    MalformedRequestLine,
}

pub fn parse_http_request(
    bytes: &[u8],
    config: &ProtocolExtractionConfig,
) -> Result<ParsedHttpRequest, HttpExtraction> {
    let header_end = header_end(bytes, config.max_header_bytes)?;
    let header_bytes = &bytes[..header_end];
    let header_text = std::str::from_utf8(header_bytes).map_err(|_| HttpExtraction::InvalidUtf8)?;
    let mut lines = header_text.split("\r\n");
    let request_line = lines.next().ok_or(HttpExtraction::MalformedRequestLine)?;
    if request_line.len() > config.max_request_line_bytes {
        return Err(HttpExtraction::RequestLineTooLong);
    }
    let method = parse_method(request_line)?;
    let mut traceparent = None;
    let mut tracestate = None;

    for line in lines {
        if line.is_empty() {
            break;
        }
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let key = key.trim();
        let value = value.trim();
        if key.eq_ignore_ascii_case("traceparent") {
            traceparent = Some(value.to_string());
        } else if key.eq_ignore_ascii_case("tracestate")
            && value.len() <= config.max_tracestate_bytes
        {
            tracestate = Some(value.to_string());
        }
    }

    let (trace_context, warning) = match traceparent.as_deref() {
        Some(value) => match parse_traceparent(value) {
            Ok(context) => (Some(context), None),
            Err(_) => (None, Some("malformed_trace_context".to_string())),
        },
        None => (None, Some("missing_trace_context".to_string())),
    };

    let mut attributes = Vec::new();
    if config.max_attributes > 0
        && let Some(method) = &method
    {
        attributes.push(TraceAttribute {
            key: "http.request.method".to_string(),
            value: method.clone(),
        });
    }

    Ok(ParsedHttpRequest {
        protocol: ProtocolKind::Http,
        method,
        trace_context,
        traceparent,
        tracestate,
        warning,
        attributes,
    })
}

fn header_end(bytes: &[u8], max_header_bytes: usize) -> Result<usize, HttpExtraction> {
    let limit = bytes.len().min(max_header_bytes.saturating_add(1));
    for index in 0..limit.saturating_sub(3) {
        if bytes[index..index + 4] == *b"\r\n\r\n" {
            if index + 4 > max_header_bytes {
                return Err(HttpExtraction::HeadersTooLong);
            }
            return Ok(index + 2);
        }
    }
    Err(HttpExtraction::HeadersTooLong)
}

fn parse_method(request_line: &str) -> Result<Option<String>, HttpExtraction> {
    let mut fields = request_line.split_whitespace();
    let Some(method) = fields.next() else {
        return Err(HttpExtraction::MalformedRequestLine);
    };
    if fields.next().is_none() || fields.next().is_none() {
        return Err(HttpExtraction::MalformedRequestLine);
    }
    if method.is_empty()
        || !method
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte == b'-')
    {
        return Ok(None);
    }
    Ok(Some(method.to_string()))
}
