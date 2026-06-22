use e_navigator_signals::{ProtocolKind, TraceAttribute};

use crate::{
    ProtocolExtractionConfig,
    trace_context::{TraceContext, parse_traceparent},
};

const MAX_HTTP_TARGET_PATH_ATTRIBUTE_BYTES: usize = 256;

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
    let request_line = parse_request_line(request_line)?;
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
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "http.request.method",
        request_line.method.as_deref(),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "url.path",
        request_line.path.as_deref(),
    );

    Ok(ParsedHttpRequest {
        protocol: ProtocolKind::Http,
        method: request_line.method,
        trace_context,
        traceparent,
        tracestate,
        warning,
        attributes,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedRequestLine {
    method: Option<String>,
    path: Option<String>,
}

fn push_attribute(
    attributes: &mut Vec<TraceAttribute>,
    max_attributes: usize,
    key: &str,
    value: Option<&str>,
) {
    if attributes.len() >= max_attributes {
        return;
    }
    if let Some(value) = value {
        attributes.push(TraceAttribute {
            key: key.to_string(),
            value: value.to_string(),
        });
    }
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

fn parse_request_line(request_line: &str) -> Result<ParsedRequestLine, HttpExtraction> {
    let mut fields = request_line.split_whitespace();
    let Some(method) = fields.next() else {
        return Err(HttpExtraction::MalformedRequestLine);
    };
    let Some(target) = fields.next() else {
        return Err(HttpExtraction::MalformedRequestLine);
    };
    if fields.next().is_none() {
        return Err(HttpExtraction::MalformedRequestLine);
    }
    let method = if method.is_empty()
        || !method
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte == b'-')
    {
        None
    } else {
        Some(method.to_string())
    };
    let path = method.as_ref().and_then(|_| request_target_path(target));
    Ok(ParsedRequestLine { method, path })
}

fn request_target_path(target: &str) -> Option<String> {
    if !target.starts_with('/') || target.bytes().any(|byte| byte.is_ascii_control()) {
        return None;
    }
    let end = target.find(['?', '#']).unwrap_or(target.len());
    let path = &target[..end];
    if path.is_empty() || path.len() > MAX_HTTP_TARGET_PATH_ATTRIBUTE_BYTES {
        return None;
    }
    Some(path.to_string())
}
