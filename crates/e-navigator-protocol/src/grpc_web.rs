//! Bounded gRPC-Web envelope parsing over HTTP/1.
//!
//! Both binary and base64 text modes are supported. The parser retains only
//! envelope counts, RPC identity, and trailer status; protobuf or JSON
//! message payloads are neither interpreted nor returned.

use std::borrow::Cow;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use e_navigator_signals::{ProtocolKind, TraceAttribute};

use crate::{
    ProtocolExtractionConfig,
    http::{ParsedHttpRequest, parse_http_request, parse_http_response},
    trace_context::TraceContext,
};

pub const MAX_GRPC_WEB_FRAMES: usize = 64;
const MAX_GRPC_WEB_CONTENT_TYPE_BYTES: usize = 64;
const MAX_CHUNK_SIZE_DIGITS: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrpcWebWireMode {
    Binary,
    Text,
}

impl GrpcWebWireMode {
    pub fn name(self) -> &'static str {
        match self {
            Self::Binary => "binary",
            Self::Text => "text",
        }
    }
}

/// Metadata derived from the bounded sequence of gRPC-Web envelopes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GrpcWebEnvelopeSummary {
    pub wire_mode: GrpcWebWireMode,
    pub frame_count: usize,
    pub message_count: usize,
    pub compressed_message_count: usize,
    pub trailer_count: usize,
    pub grpc_status: Option<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedGrpcWebRequest {
    pub protocol: ProtocolKind,
    pub method: Option<String>,
    pub trace_context: Option<TraceContext>,
    pub warning: Option<String>,
    pub attributes: Vec<TraceAttribute>,
    pub summary: GrpcWebEnvelopeSummary,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedGrpcWebResponse {
    pub protocol: ProtocolKind,
    pub status_code: u16,
    pub attributes: Vec<TraceAttribute>,
    pub summary: GrpcWebEnvelopeSummary,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrpcWebExtraction {
    HeadersTooLong,
    MalformedRequest,
    InvalidContentType,
    InvalidBodyFraming,
    BodyTooLong,
    InvalidBase64,
    TooManyFrames,
    TruncatedEnvelope,
    InvalidEnvelopeFlag,
    TrailerNotLast,
    InvalidTrailer,
    MissingGrpcStatus,
    InvalidGrpcStatus,
}

/// Parses a gRPC-Web HTTP/1 request. Non-gRPC-Web requests return `Ok(None)`.
pub fn parse_grpc_web_request(
    bytes: &[u8],
    config: &ProtocolExtractionConfig,
) -> Result<Option<ParsedGrpcWebRequest>, GrpcWebExtraction> {
    let headers = Headers::parse(bytes, config.max_header_bytes)?;
    let Some(wire_mode) = grpc_web_wire_mode(headers.value(b"content-type"))? else {
        return Ok(None);
    };
    let mut fields = ascii_fields(headers.first_line);
    if fields.next() != Some(b"POST".as_slice())
        || fields.next().is_none()
        || !fields
            .next()
            .is_some_and(|version| version.starts_with(b"HTTP/1."))
        || fields.next().is_some()
    {
        return Err(GrpcWebExtraction::MalformedRequest);
    }

    let parsed_http =
        parse_http_request(bytes, config).map_err(|_| GrpcWebExtraction::MalformedRequest)?;
    let entity = entity_body(bytes, &headers, config.max_header_bytes)?;
    let decoded = decode_entity(entity, wire_mode, config.max_header_bytes)?;
    let summary = parse_envelopes(&decoded, wire_mode, config.max_header_bytes, false)?;
    let (service, rpc_method) = rpc_identity(&parsed_http);
    let mut attributes = Vec::new();
    push_attribute(&mut attributes, config.max_attributes, "rpc.system", "grpc");
    if let Some(service) = service.as_deref() {
        push_attribute(
            &mut attributes,
            config.max_attributes,
            "rpc.service",
            service,
        );
    }
    if let Some(method) = rpc_method.as_deref() {
        push_attribute(&mut attributes, config.max_attributes, "rpc.method", method);
    }
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "rpc.grpc.transport",
        "grpc_web",
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "rpc.grpc.web.mode",
        wire_mode.name(),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "rpc.grpc.web.message_count",
        &summary.message_count.to_string(),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "rpc.grpc.web.compressed_message_count",
        &summary.compressed_message_count.to_string(),
    );
    append_unique_attributes(
        &mut attributes,
        &parsed_http.attributes,
        config.max_attributes,
    );

    Ok(Some(ParsedGrpcWebRequest {
        protocol: ProtocolKind::Grpc,
        method: rpc_method.or(parsed_http.method),
        trace_context: parsed_http.trace_context,
        warning: parsed_http.warning,
        attributes,
        summary,
    }))
}

/// Parses a gRPC-Web HTTP/1 response and its mandatory in-body trailer.
/// Non-gRPC-Web responses return `Ok(None)`.
pub fn parse_grpc_web_response(
    bytes: &[u8],
    config: &ProtocolExtractionConfig,
) -> Result<Option<ParsedGrpcWebResponse>, GrpcWebExtraction> {
    let headers = Headers::parse(bytes, config.max_header_bytes)?;
    let Some(wire_mode) = grpc_web_wire_mode(headers.value(b"content-type"))? else {
        return Ok(None);
    };
    let parsed_http =
        parse_http_response(bytes, config).map_err(|_| GrpcWebExtraction::MalformedRequest)?;
    let entity = entity_body(bytes, &headers, config.max_header_bytes)?;
    let decoded = decode_entity(entity, wire_mode, config.max_header_bytes)?;
    let summary = parse_envelopes(&decoded, wire_mode, config.max_header_bytes, true)?;
    let status_code = summary
        .grpc_status
        .ok_or(GrpcWebExtraction::MissingGrpcStatus)?;
    let mut attributes = Vec::new();
    push_attribute(&mut attributes, config.max_attributes, "rpc.system", "grpc");
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "rpc.grpc.transport",
        "grpc_web",
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "rpc.grpc.web.mode",
        wire_mode.name(),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "rpc.grpc.web.message_count",
        &summary.message_count.to_string(),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "rpc.grpc.status_code",
        &status_code.to_string(),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "http.response.status_code",
        &parsed_http.status_code.to_string(),
    );

    Ok(Some(ParsedGrpcWebResponse {
        protocol: ProtocolKind::Grpc,
        status_code,
        attributes,
        summary,
    }))
}

/// Parses a raw binary or text-mode envelope body. This is public so fuzz
/// targets can exercise the message parser independently of HTTP framing.
pub fn parse_grpc_web_envelopes(
    body: &[u8],
    wire_mode: GrpcWebWireMode,
    max_body_bytes: usize,
    require_status: bool,
) -> Result<GrpcWebEnvelopeSummary, GrpcWebExtraction> {
    let decoded = decode_entity(Cow::Borrowed(body), wire_mode, max_body_bytes)?;
    parse_envelopes(&decoded, wire_mode, max_body_bytes, require_status)
}

fn decode_entity<'a>(
    body: Cow<'a, [u8]>,
    wire_mode: GrpcWebWireMode,
    max_body_bytes: usize,
) -> Result<Cow<'a, [u8]>, GrpcWebExtraction> {
    if body.len() > max_body_bytes {
        return Err(GrpcWebExtraction::BodyTooLong);
    }
    if wire_mode == GrpcWebWireMode::Binary {
        return Ok(body);
    }
    let mut decoded = Vec::with_capacity(body.len().saturating_mul(3) / 4);
    let mut chunks = body.chunks_exact(4);
    for quartet in &mut chunks {
        let mut output = [0_u8; 3];
        let written = STANDARD
            .decode_slice(quartet, &mut output)
            .map_err(|_| GrpcWebExtraction::InvalidBase64)?;
        if decoded.len().saturating_add(written) > max_body_bytes {
            return Err(GrpcWebExtraction::BodyTooLong);
        }
        decoded.extend_from_slice(&output[..written]);
    }
    if !chunks.remainder().is_empty() {
        return Err(GrpcWebExtraction::InvalidBase64);
    }
    Ok(Cow::Owned(decoded))
}

fn parse_envelopes(
    bytes: &[u8],
    wire_mode: GrpcWebWireMode,
    max_body_bytes: usize,
    require_status: bool,
) -> Result<GrpcWebEnvelopeSummary, GrpcWebExtraction> {
    if bytes.len() > max_body_bytes {
        return Err(GrpcWebExtraction::BodyTooLong);
    }
    let mut cursor = 0_usize;
    let mut frame_count = 0_usize;
    let mut message_count = 0_usize;
    let mut compressed_message_count = 0_usize;
    let mut trailer_count = 0_usize;
    let mut grpc_status = None;
    while cursor < bytes.len() {
        frame_count += 1;
        if frame_count > MAX_GRPC_WEB_FRAMES {
            return Err(GrpcWebExtraction::TooManyFrames);
        }
        if bytes.len().saturating_sub(cursor) < 5 {
            return Err(GrpcWebExtraction::TruncatedEnvelope);
        }
        let flags = bytes[cursor];
        let declared_len = u32::from_be_bytes([
            bytes[cursor + 1],
            bytes[cursor + 2],
            bytes[cursor + 3],
            bytes[cursor + 4],
        ]) as usize;
        let payload_start = cursor + 5;
        let payload_end = payload_start
            .checked_add(declared_len)
            .ok_or(GrpcWebExtraction::BodyTooLong)?;
        if payload_end > bytes.len() {
            return Err(GrpcWebExtraction::TruncatedEnvelope);
        }
        match flags {
            0x00 => message_count += 1,
            0x01 => {
                message_count += 1;
                compressed_message_count += 1;
            }
            0x80 => {
                trailer_count += 1;
                if trailer_count > 1 || payload_end != bytes.len() {
                    return Err(GrpcWebExtraction::TrailerNotLast);
                }
                grpc_status = Some(parse_trailer_status(&bytes[payload_start..payload_end])?);
            }
            _ => return Err(GrpcWebExtraction::InvalidEnvelopeFlag),
        }
        cursor = payload_end;
    }
    if require_status && grpc_status.is_none() {
        return Err(GrpcWebExtraction::MissingGrpcStatus);
    }
    Ok(GrpcWebEnvelopeSummary {
        wire_mode,
        frame_count,
        message_count,
        compressed_message_count,
        trailer_count,
        grpc_status,
    })
}

fn parse_trailer_status(bytes: &[u8]) -> Result<u16, GrpcWebExtraction> {
    let text = std::str::from_utf8(bytes).map_err(|_| GrpcWebExtraction::InvalidTrailer)?;
    let mut status = None;
    for line in text.split("\r\n") {
        if line.is_empty() {
            continue;
        }
        let Some((name, value)) = line.split_once(':') else {
            return Err(GrpcWebExtraction::InvalidTrailer);
        };
        if name.trim().eq_ignore_ascii_case("grpc-status") {
            let parsed = value
                .trim()
                .parse::<u16>()
                .map_err(|_| GrpcWebExtraction::InvalidGrpcStatus)?;
            if parsed > 16 {
                return Err(GrpcWebExtraction::InvalidGrpcStatus);
            }
            status = Some(parsed);
        }
    }
    status.ok_or(GrpcWebExtraction::MissingGrpcStatus)
}

fn grpc_web_wire_mode(
    content_type: Option<&[u8]>,
) -> Result<Option<GrpcWebWireMode>, GrpcWebExtraction> {
    let Some(content_type) = content_type else {
        return Ok(None);
    };
    let media_type = trim_ascii(
        content_type
            .split(|byte| *byte == b';')
            .next()
            .unwrap_or(content_type),
    );
    if media_type.len() > MAX_GRPC_WEB_CONTENT_TYPE_BYTES {
        return Err(GrpcWebExtraction::InvalidContentType);
    }
    let lower = media_type.to_ascii_lowercase();
    if lower == b"application/grpc-web-text" || lower.starts_with(b"application/grpc-web-text+") {
        return Ok(Some(GrpcWebWireMode::Text));
    }
    if lower == b"application/grpc-web" || lower.starts_with(b"application/grpc-web+") {
        return Ok(Some(GrpcWebWireMode::Binary));
    }
    Ok(None)
}

fn rpc_identity(request: &ParsedHttpRequest) -> (Option<String>, Option<String>) {
    let path = request
        .attributes
        .iter()
        .find(|attribute| attribute.key == "url.path")
        .map(|attribute| attribute.value.as_str());
    let Some(path) = path.and_then(|path| path.strip_prefix('/')) else {
        return (None, None);
    };
    let Some((service, method)) = path.split_once('/') else {
        return (None, None);
    };
    if service.is_empty() || method.is_empty() || method.contains('/') {
        return (None, None);
    }
    (Some(service.to_string()), Some(method.to_string()))
}

fn push_attribute(
    attributes: &mut Vec<TraceAttribute>,
    max_attributes: usize,
    key: &str,
    value: &str,
) {
    if attributes.len() < max_attributes {
        attributes.push(TraceAttribute {
            key: key.to_string(),
            value: value.to_string(),
        });
    }
}

fn append_unique_attributes(
    attributes: &mut Vec<TraceAttribute>,
    candidates: &[TraceAttribute],
    max_attributes: usize,
) {
    for candidate in candidates {
        if attributes.len() >= max_attributes {
            break;
        }
        if !attributes
            .iter()
            .any(|attribute| attribute.key == candidate.key)
        {
            attributes.push(candidate.clone());
        }
    }
}

#[derive(Debug)]
struct Headers<'a> {
    first_line: &'a [u8],
    lines: &'a [u8],
    body_offset: usize,
}

impl<'a> Headers<'a> {
    fn parse(bytes: &'a [u8], max_header_bytes: usize) -> Result<Self, GrpcWebExtraction> {
        let scan_len = bytes.len().min(max_header_bytes.saturating_add(1));
        let Some(end) = bytes[..scan_len]
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
        else {
            return Err(GrpcWebExtraction::HeadersTooLong);
        };
        let body_offset = end + 4;
        if body_offset > max_header_bytes {
            return Err(GrpcWebExtraction::HeadersTooLong);
        }
        let block = &bytes[..end];
        let first_end = block
            .windows(2)
            .position(|window| window == b"\r\n")
            .unwrap_or(block.len());
        let lines = if first_end == block.len() {
            &block[block.len()..]
        } else {
            &block[first_end + 2..]
        };
        Ok(Self {
            first_line: &block[..first_end],
            lines,
            body_offset,
        })
    }

    fn value(&self, name: &[u8]) -> Option<&'a [u8]> {
        self.lines.split(|byte| *byte == b'\n').find_map(|line| {
            let line = line.strip_suffix(b"\r").unwrap_or(line);
            let colon = line.iter().position(|byte| *byte == b':')?;
            trim_ascii(&line[..colon])
                .eq_ignore_ascii_case(name)
                .then(|| trim_ascii(&line[colon + 1..]))
        })
    }
}

fn entity_body<'a>(
    bytes: &'a [u8],
    headers: &Headers<'_>,
    max_body_bytes: usize,
) -> Result<Cow<'a, [u8]>, GrpcWebExtraction> {
    let body = bytes
        .get(headers.body_offset..)
        .ok_or(GrpcWebExtraction::InvalidBodyFraming)?;
    if headers
        .value(b"transfer-encoding")
        .is_some_and(|value| token_contains(value, b"chunked"))
    {
        return dechunk(body, max_body_bytes).map(Cow::Owned);
    }
    if let Some(value) = headers.value(b"content-length") {
        let length =
            parse_decimal(trim_ascii(value)).ok_or(GrpcWebExtraction::InvalidBodyFraming)?;
        if length > max_body_bytes {
            return Err(GrpcWebExtraction::BodyTooLong);
        }
        if body.len() < length {
            return Err(GrpcWebExtraction::InvalidBodyFraming);
        }
        return Ok(Cow::Borrowed(&body[..length]));
    }
    if body.len() > max_body_bytes {
        return Err(GrpcWebExtraction::BodyTooLong);
    }
    Ok(Cow::Borrowed(body))
}

fn dechunk(bytes: &[u8], max_body_bytes: usize) -> Result<Vec<u8>, GrpcWebExtraction> {
    let mut decoded = Vec::new();
    let mut cursor = 0_usize;
    loop {
        let remaining = bytes
            .get(cursor..)
            .ok_or(GrpcWebExtraction::InvalidBodyFraming)?;
        let line_end = remaining
            .windows(2)
            .position(|window| window == b"\r\n")
            .ok_or(GrpcWebExtraction::InvalidBodyFraming)?;
        let token = remaining[..line_end]
            .split(|byte| *byte == b';')
            .next()
            .unwrap_or_default();
        if token.is_empty() || token.len() > MAX_CHUNK_SIZE_DIGITS {
            return Err(GrpcWebExtraction::InvalidBodyFraming);
        }
        let chunk_len = parse_hex(token).ok_or(GrpcWebExtraction::InvalidBodyFraming)?;
        cursor = cursor
            .checked_add(line_end + 2)
            .ok_or(GrpcWebExtraction::BodyTooLong)?;
        if chunk_len == 0 {
            if bytes.get(cursor..cursor + 2) != Some(b"\r\n".as_slice()) {
                return Err(GrpcWebExtraction::InvalidBodyFraming);
            }
            return Ok(decoded);
        }
        if decoded.len().saturating_add(chunk_len) > max_body_bytes {
            return Err(GrpcWebExtraction::BodyTooLong);
        }
        let end = cursor
            .checked_add(chunk_len)
            .ok_or(GrpcWebExtraction::BodyTooLong)?;
        let chunk = bytes
            .get(cursor..end)
            .ok_or(GrpcWebExtraction::InvalidBodyFraming)?;
        if bytes.get(end..end + 2) != Some(b"\r\n".as_slice()) {
            return Err(GrpcWebExtraction::InvalidBodyFraming);
        }
        decoded.extend_from_slice(chunk);
        cursor = end + 2;
    }
}

fn token_contains(value: &[u8], expected: &[u8]) -> bool {
    value
        .split(|byte| *byte == b',')
        .map(trim_ascii)
        .any(|token| token.eq_ignore_ascii_case(expected))
}

fn ascii_fields(value: &[u8]) -> impl Iterator<Item = &[u8]> {
    value
        .split(u8::is_ascii_whitespace)
        .filter(|field| !field.is_empty())
}

fn trim_ascii(mut value: &[u8]) -> &[u8] {
    while value.first().is_some_and(u8::is_ascii_whitespace) {
        value = &value[1..];
    }
    while value.last().is_some_and(u8::is_ascii_whitespace) {
        value = &value[..value.len() - 1];
    }
    value
}

fn parse_decimal(bytes: &[u8]) -> Option<usize> {
    if bytes.is_empty() || bytes.len() > 10 {
        return None;
    }
    bytes.iter().try_fold(0_usize, |value, byte| {
        byte.is_ascii_digit()
            .then(|| value.checked_mul(10)?.checked_add(usize::from(byte - b'0')))
            .flatten()
    })
}

fn parse_hex(bytes: &[u8]) -> Option<usize> {
    bytes.iter().try_fold(0_usize, |value, byte| {
        let digit = match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            b'A'..=b'F' => byte - b'A' + 10,
            _ => return None,
        };
        value.checked_mul(16)?.checked_add(usize::from(digit))
    })
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    fn message(payload: &[u8]) -> Vec<u8> {
        let mut frame = vec![0];
        frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        frame.extend_from_slice(payload);
        frame
    }

    fn trailer(status: u16) -> Vec<u8> {
        let payload = format!("grpc-status: {status}\r\n");
        let mut frame = vec![0x80];
        frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        frame.extend_from_slice(payload.as_bytes());
        frame
    }

    fn http_message(content_type: &str, body: &[u8], response: bool) -> Vec<u8> {
        let start = if response {
            "HTTP/1.1 200 OK"
        } else {
            "POST /demo.Echo/Call HTTP/1.1"
        };
        let mut bytes = format!(
            "{start}\r\nHost: example.test\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n\r\n",
            body.len()
        )
        .into_bytes();
        bytes.extend_from_slice(body);
        bytes
    }

    #[test]
    fn parses_binary_request_without_exporting_payload() {
        let body = message(b"secret protobuf bytes");
        let request = http_message("application/grpc-web+proto", &body, false);
        let parsed = parse_grpc_web_request(&request, &ProtocolExtractionConfig::default())
            .expect("valid request")
            .expect("grpc-web");
        assert_eq!(parsed.protocol, ProtocolKind::Grpc);
        assert_eq!(parsed.method.as_deref(), Some("Call"));
        assert_eq!(parsed.summary.message_count, 1);
        assert!(
            parsed
                .attributes
                .iter()
                .all(|attribute| !attribute.value.contains("secret"))
        );
    }

    #[test]
    fn parses_text_response_with_in_body_status() {
        let mut binary = message(b"reply");
        binary.extend_from_slice(&trailer(0));
        let encoded = STANDARD.encode(binary);
        let response = http_message("application/grpc-web-text+proto", encoded.as_bytes(), true);
        let parsed = parse_grpc_web_response(&response, &ProtocolExtractionConfig::default())
            .expect("valid response")
            .expect("grpc-web");
        assert_eq!(parsed.status_code, 0);
        assert_eq!(parsed.summary.message_count, 1);
        assert_eq!(parsed.summary.trailer_count, 1);
    }

    #[test]
    fn accepts_concatenated_padded_text_segments() {
        let first = STANDARD.encode(message(b"a"));
        let second = STANDARD.encode(message(b"bc"));
        let combined = format!("{first}{second}");
        let summary =
            parse_grpc_web_envelopes(combined.as_bytes(), GrpcWebWireMode::Text, 4096, false)
                .expect("concatenated base64 segments");
        assert_eq!(summary.message_count, 2);
    }

    #[test]
    fn rejects_trailer_before_message_end() {
        let mut body = trailer(0);
        body.extend_from_slice(&message(b"late"));
        assert_eq!(
            parse_grpc_web_envelopes(&body, GrpcWebWireMode::Binary, 4096, true),
            Err(GrpcWebExtraction::TrailerNotLast)
        );
    }

    #[test]
    fn dechunking_is_bounded() {
        let body = message(b"abc");
        let mut chunked = format!("{:x}\r\n", body.len()).into_bytes();
        chunked.extend_from_slice(&body);
        chunked.extend_from_slice(b"\r\n0\r\n\r\n");
        let mut request = b"POST /demo.Echo/Call HTTP/1.1\r\nContent-Type: application/grpc-web\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
        request.extend_from_slice(&chunked);
        let parsed = parse_grpc_web_request(&request, &ProtocolExtractionConfig::default())
            .expect("valid chunked request")
            .expect("grpc-web");
        assert_eq!(parsed.summary.message_count, 1);
    }

    proptest! {
        #[test]
        fn arbitrary_bodies_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..2048)) {
            let _ = parse_grpc_web_envelopes(
                &bytes,
                GrpcWebWireMode::Binary,
                1024,
                false,
            );
            let _ = parse_grpc_web_envelopes(
                &bytes,
                GrpcWebWireMode::Text,
                1024,
                true,
            );
        }

        #[test]
        fn valid_binary_messages_round_trip(payload in proptest::collection::vec(any::<u8>(), 0..512)) {
            let frame = message(&payload);
            let summary = parse_grpc_web_envelopes(
                &frame,
                GrpcWebWireMode::Binary,
                1024,
                false,
            );
            prop_assert_eq!(summary.map(|summary| summary.message_count), Ok(1));
        }
    }
}
