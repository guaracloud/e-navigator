use e_navigator_signals::{ProtocolKind, TraceAttribute};

use crate::{
    ProtocolExtractionConfig,
    trace_context::{TraceContext, parse_traceparent},
};

const MAX_HTTP_TARGET_PATH_ATTRIBUTE_BYTES: usize = 256;
const MAX_HTTP_REQUEST_ID_ATTRIBUTE_BYTES: usize = 128;
const MAX_HTTP_SERVER_ADDRESS_ATTRIBUTE_BYTES: usize = 253;

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedHttpResponse {
    pub protocol: ProtocolKind,
    pub status_code: u16,
    pub attributes: Vec<TraceAttribute>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpExtraction {
    HeadersTooLong,
    InvalidUtf8,
    RequestLineTooLong,
    MalformedRequestLine,
    ResponseLineTooLong,
    MalformedResponseLine,
    InvalidStatusCode,
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
    let mut request_id = None;
    let mut host_authority = request_line.authority;

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
        } else if is_request_id_header(key) {
            request_id = bounded_request_id(value);
        } else if key.eq_ignore_ascii_case("host") {
            host_authority = bounded_host_authority(value);
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
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "http.request.id",
        request_id.as_deref(),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "server.address",
        host_authority
            .as_ref()
            .map(|authority| authority.address.as_str()),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "server.port",
        host_authority
            .as_ref()
            .and_then(|authority| authority.port.as_deref()),
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

pub fn parse_http_response(
    bytes: &[u8],
    config: &ProtocolExtractionConfig,
) -> Result<ParsedHttpResponse, HttpExtraction> {
    let header_end = header_end(bytes, config.max_header_bytes)?;
    let header_bytes = &bytes[..header_end];
    let header_text = std::str::from_utf8(header_bytes).map_err(|_| HttpExtraction::InvalidUtf8)?;
    let mut lines = header_text.split("\r\n");
    let status_line = lines.next().ok_or(HttpExtraction::MalformedResponseLine)?;
    if status_line.len() > config.max_request_line_bytes {
        return Err(HttpExtraction::ResponseLineTooLong);
    }
    let status_code = parse_status_line(status_line)?;

    let mut attributes = Vec::new();
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "http.response.status_code",
        Some(&status_code.to_string()),
    );

    Ok(ParsedHttpResponse {
        protocol: ProtocolKind::Http,
        status_code,
        attributes,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedRequestLine {
    method: Option<String>,
    path: Option<String>,
    authority: Option<HostAuthority>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct HostAuthority {
    address: String,
    port: Option<String>,
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
    let Some(version) = fields.next() else {
        return Err(HttpExtraction::MalformedRequestLine);
    };
    if !is_http1_version(version) || fields.next().is_some() {
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
    let (path, authority) = if let Some(method) = method.as_deref() {
        request_target_context(method, target)
    } else {
        (None, None)
    };
    Ok(ParsedRequestLine {
        method,
        path,
        authority,
    })
}

fn parse_status_line(status_line: &str) -> Result<u16, HttpExtraction> {
    let mut fields = status_line.split_whitespace();
    let Some(version) = fields.next() else {
        return Err(HttpExtraction::MalformedResponseLine);
    };
    if !is_http1_version(version) {
        return Err(HttpExtraction::MalformedResponseLine);
    }
    let Some(status_code) = fields.next() else {
        return Err(HttpExtraction::MalformedResponseLine);
    };
    if status_code.len() != 3 || !status_code.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(HttpExtraction::InvalidStatusCode);
    }
    let status_code = status_code
        .parse::<u16>()
        .map_err(|_| HttpExtraction::InvalidStatusCode)?;
    if !(100..=599).contains(&status_code) {
        return Err(HttpExtraction::InvalidStatusCode);
    }
    Ok(status_code)
}

fn is_http1_version(value: &str) -> bool {
    matches!(value, "HTTP/1.0" | "HTTP/1.1")
}

fn request_target_context(method: &str, target: &str) -> (Option<String>, Option<HostAuthority>) {
    if target.starts_with('/') {
        return (request_target_path(target), None);
    }

    if let Some(remainder) = target.strip_prefix("http://") {
        return absolute_form_target_context(remainder);
    }
    if let Some(remainder) = target.strip_prefix("https://") {
        return absolute_form_target_context(remainder);
    }
    if method == "CONNECT" {
        return (None, bounded_host_authority(target));
    }

    (None, None)
}

fn absolute_form_target_context(remainder: &str) -> (Option<String>, Option<HostAuthority>) {
    let split_at = remainder.find(['/', '?', '#']).unwrap_or(remainder.len());
    let authority = &remainder[..split_at];
    let Some(authority) = bounded_host_authority(authority) else {
        return (None, None);
    };

    let target_path = if split_at < remainder.len() {
        let rest = &remainder[split_at..];
        if rest.starts_with('/') { rest } else { "/" }
    } else {
        "/"
    };

    (request_target_path(target_path), Some(authority))
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

fn is_request_id_header(key: &str) -> bool {
    key.eq_ignore_ascii_case("x-request-id") || key.eq_ignore_ascii_case("request-id")
}

fn bounded_request_id(value: &str) -> Option<String> {
    if value.is_empty()
        || value.len() > MAX_HTTP_REQUEST_ID_ATTRIBUTE_BYTES
        || value.bytes().any(|byte| byte.is_ascii_control())
    {
        return None;
    }
    Some(value.to_string())
}

fn bounded_host_authority(value: &str) -> Option<HostAuthority> {
    if value.is_empty()
        || value.contains('@')
        || value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte == b'/' || byte == b'\\')
    {
        return None;
    }

    let (address, port) = if let Some(rest) = value.strip_prefix('[') {
        let (address, remainder) = rest.split_once(']')?;
        let port = if remainder.is_empty() {
            None
        } else {
            Some(remainder.strip_prefix(':')?)
        };
        (address, port)
    } else if let Some((address, port)) = value.split_once(':') {
        if port.contains(':') {
            return None;
        }
        (address, Some(port))
    } else {
        (value, None)
    };

    if address.is_empty()
        || address.len() > MAX_HTTP_SERVER_ADDRESS_ATTRIBUTE_BYTES
        || address.bytes().any(|byte| byte.is_ascii_whitespace())
    {
        return None;
    }

    let port = match port {
        Some(port) if bounded_port(port).is_some() => Some(port.to_string()),
        Some(_) => return None,
        None => None,
    };

    Some(HostAuthority {
        address: address.to_string(),
        port,
    })
}

fn bounded_port(value: &str) -> Option<u16> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    value.parse().ok()
}
