use e_navigator_signals::{ProtocolKind, TraceAttribute};

use crate::{
    ProtocolExtractionConfig,
    trace_context::{TraceContext, parse_traceparent},
};

const MAX_GRPC_SERVICE_ATTRIBUTE_BYTES: usize = 128;
const MAX_GRPC_METHOD_ATTRIBUTE_BYTES: usize = 128;
const MAX_GRPC_CONTENT_TYPE_ATTRIBUTE_BYTES: usize = 64;
const MAX_GRPC_AUTHORITY_ATTRIBUTE_BYTES: usize = 253;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedGrpcRequest {
    pub protocol: ProtocolKind,
    pub method: Option<String>,
    pub trace_context: Option<TraceContext>,
    pub traceparent: Option<String>,
    pub tracestate: Option<String>,
    pub warning: Option<String>,
    pub attributes: Vec<TraceAttribute>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrpcExtraction {
    HeadersTooLong,
    InvalidUtf8,
    MissingGrpcContentType,
}

pub fn parse_grpc_request_headers(
    bytes: &[u8],
    config: &ProtocolExtractionConfig,
) -> Result<ParsedGrpcRequest, GrpcExtraction> {
    if bytes.len() > config.max_header_bytes {
        return Err(GrpcExtraction::HeadersTooLong);
    }
    let header_text = std::str::from_utf8(bytes).map_err(|_| GrpcExtraction::InvalidUtf8)?;
    let mut method = None;
    let mut path = None;
    let mut authority = None;
    let mut content_type = None;
    let mut traceparent = None;
    let mut tracestate = None;

    for line in header_text.lines() {
        let line = line.trim_end_matches('\r');
        if line.is_empty() {
            break;
        }
        let Some((key, value)) = split_header_line(line) else {
            continue;
        };
        let value = value.trim();
        match key.trim().to_ascii_lowercase().as_str() {
            ":method" => method = bounded_http2_method(value),
            ":path" => path = bounded_grpc_path(value),
            ":authority" | "host" => authority = bounded_authority(value),
            "content-type" if is_grpc_content_type(value) => {
                content_type = bounded_content_type(value)
            }
            "traceparent" => traceparent = Some(value.to_string()),
            "tracestate" if value.len() <= config.max_tracestate_bytes => {
                tracestate = Some(value.to_string());
            }
            _ => {}
        }
    }

    let Some(content_type) = content_type else {
        return Err(GrpcExtraction::MissingGrpcContentType);
    };

    let (trace_context, warning) = match traceparent.as_deref() {
        Some(value) => match parse_traceparent(value) {
            Ok(context) => (Some(context), None),
            Err(_) => (None, Some("malformed_trace_context".to_string())),
        },
        None => (None, Some("missing_trace_context".to_string())),
    };

    let (service, rpc_method) = path
        .as_deref()
        .and_then(split_grpc_path)
        .unwrap_or((None, None));
    let mut attributes = Vec::new();
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "rpc.system",
        Some("grpc"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "rpc.service",
        service.as_deref(),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "rpc.method",
        rpc_method.as_deref(),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "http.request.method",
        method.as_deref(),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "rpc.grpc.content_type",
        Some(content_type.as_str()),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "server.address",
        authority
            .as_ref()
            .map(|authority| authority.address.as_str()),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "server.port",
        authority
            .as_ref()
            .and_then(|authority| authority.port.as_deref()),
    );

    Ok(ParsedGrpcRequest {
        protocol: ProtocolKind::Grpc,
        method: rpc_method.or(method),
        trace_context,
        traceparent,
        tracestate,
        warning,
        attributes,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Authority {
    address: String,
    port: Option<String>,
}

fn split_header_line(line: &str) -> Option<(&str, &str)> {
    if let Some(rest) = line.strip_prefix(':') {
        let split_at = rest.find(':')?;
        return Some((&line[..split_at + 1], &rest[split_at + 1..]));
    }
    line.split_once(':')
}

fn bounded_http2_method(value: &str) -> Option<String> {
    if value.is_empty()
        || value.len() > 32
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte == b'-')
    {
        return None;
    }
    Some(value.to_string())
}

fn bounded_grpc_path(value: &str) -> Option<String> {
    if !value.starts_with('/')
        || value.len() > MAX_GRPC_SERVICE_ATTRIBUTE_BYTES + MAX_GRPC_METHOD_ATTRIBUTE_BYTES + 2
        || value.bytes().any(|byte| byte.is_ascii_control())
    {
        return None;
    }
    Some(value.to_string())
}

fn split_grpc_path(path: &str) -> Option<(Option<String>, Option<String>)> {
    let path = path.strip_prefix('/')?;
    let (service, method) = path.rsplit_once('/')?;
    if service.is_empty()
        || method.is_empty()
        || service.len() > MAX_GRPC_SERVICE_ATTRIBUTE_BYTES
        || method.len() > MAX_GRPC_METHOD_ATTRIBUTE_BYTES
        || !service.bytes().all(grpc_name_byte_allowed)
        || !method.bytes().all(grpc_name_byte_allowed)
    {
        return None;
    }
    Some((Some(service.to_string()), Some(method.to_string())))
}

fn grpc_name_byte_allowed(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')
}

fn is_grpc_content_type(value: &str) -> bool {
    let value = value.to_ascii_lowercase();
    value == "application/grpc" || value.starts_with("application/grpc+")
}

fn bounded_content_type(value: &str) -> Option<String> {
    if value.is_empty()
        || value.len() > MAX_GRPC_CONTENT_TYPE_ATTRIBUTE_BYTES
        || value.bytes().any(|byte| byte.is_ascii_control())
    {
        return None;
    }
    Some(value.to_ascii_lowercase())
}

fn bounded_authority(value: &str) -> Option<Authority> {
    if value.is_empty()
        || value.len() > MAX_GRPC_AUTHORITY_ATTRIBUTE_BYTES
        || value.bytes().any(|byte| byte.is_ascii_control())
    {
        return None;
    }
    let (address, port) = split_authority(value);
    if address.is_empty() {
        return None;
    }
    Some(Authority {
        address: address.to_string(),
        port: port.map(ToString::to_string),
    })
}

fn split_authority(value: &str) -> (&str, Option<&str>) {
    if let Some((host, port)) = value.rsplit_once(':')
        && !host.contains(':')
        && !port.is_empty()
        && port.bytes().all(|byte| byte.is_ascii_digit())
    {
        return (host, Some(port));
    }
    (value, None)
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
