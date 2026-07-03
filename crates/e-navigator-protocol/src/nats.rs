use e_navigator_signals::{ProtocolKind, TraceAttribute};

use crate::ProtocolExtractionConfig;

const MAX_NATS_OPERATION_BYTES: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedNatsCommand {
    pub protocol: ProtocolKind,
    pub operation: Option<String>,
    pub warning: Option<String>,
    pub attributes: Vec<TraceAttribute>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedNatsResponse {
    pub protocol: ProtocolKind,
    pub status_code: String,
    pub error_type: Option<String>,
    pub attributes: Vec<TraceAttribute>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatsExtraction {
    FrameTooLong,
    InvalidUtf8,
    MalformedFrame,
    PayloadTooLong,
    UnsupportedCommand,
}

pub fn parse_nats_command(
    bytes: &[u8],
    config: &ProtocolExtractionConfig,
) -> Result<ParsedNatsCommand, NatsExtraction> {
    if bytes.len() > config.max_header_bytes {
        return Err(NatsExtraction::FrameTooLong);
    }
    let line_end = line_end(bytes, 0).ok_or(NatsExtraction::MalformedFrame)?;
    if line_end > config.max_request_line_bytes {
        return Err(NatsExtraction::FrameTooLong);
    }
    let line = std::str::from_utf8(&bytes[..line_end]).map_err(|_| NatsExtraction::InvalidUtf8)?;
    let parsed = parse_control_line(line, bytes, line_end + 2, config.max_header_bytes)?;

    let mut attributes = Vec::new();
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.system",
        Some("nats"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.operation",
        parsed.operation.as_deref(),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.nats.subject_present",
        parsed.subject_present.then_some("true"),
    );

    Ok(ParsedNatsCommand {
        protocol: ProtocolKind::Nats,
        operation: parsed.operation,
        warning: None,
        attributes,
    })
}

pub fn parse_nats_response(
    bytes: &[u8],
    config: &ProtocolExtractionConfig,
) -> Result<ParsedNatsResponse, NatsExtraction> {
    if bytes.len() > config.max_header_bytes {
        return Err(NatsExtraction::FrameTooLong);
    }
    let line_end = line_end(bytes, 0).ok_or(NatsExtraction::MalformedFrame)?;
    if line_end > config.max_request_line_bytes {
        return Err(NatsExtraction::FrameTooLong);
    }
    let line = std::str::from_utf8(&bytes[..line_end]).map_err(|_| NatsExtraction::InvalidUtf8)?;
    let response = parse_response_line(line)?;

    let mut attributes = Vec::new();
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.system",
        Some("nats"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "messaging.nats.status_code",
        Some(response.status_code),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "error.type",
        response.error_type,
    );

    Ok(ParsedNatsResponse {
        protocol: ProtocolKind::Nats,
        status_code: response.status_code.to_string(),
        error_type: response.error_type.map(str::to_string),
        attributes,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NatsCommand {
    operation: Option<String>,
    subject_present: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct NatsResponse {
    status_code: &'static str,
    error_type: Option<&'static str>,
}

fn parse_response_line(line: &str) -> Result<NatsResponse, NatsExtraction> {
    let fields = line.split_ascii_whitespace().collect::<Vec<_>>();
    match fields.as_slice() {
        ["+OK"] => Ok(NatsResponse {
            status_code: "OK",
            error_type: None,
        }),
        ["-ERR", ..] if fields.len() > 1 => Ok(NatsResponse {
            status_code: "ERR",
            error_type: Some("nats_error"),
        }),
        [..] => Err(NatsExtraction::UnsupportedCommand),
    }
}

fn parse_control_line(
    line: &str,
    bytes: &[u8],
    payload_start: usize,
    max_frame_bytes: usize,
) -> Result<NatsCommand, NatsExtraction> {
    let fields = line.split_ascii_whitespace().collect::<Vec<_>>();
    let Some(command) = fields.first() else {
        return Err(NatsExtraction::MalformedFrame);
    };
    let operation = bounded_operation(command);
    let Some(command) = operation.as_deref() else {
        return Err(NatsExtraction::UnsupportedCommand);
    };

    let subject_present = match command {
        "PUB" => {
            let payload_bytes = pub_payload_len(&fields)?;
            validate_payload(bytes, payload_start, payload_bytes, max_frame_bytes)?;
            true
        }
        "HPUB" => {
            let (header_bytes, total_bytes) = hpub_lengths(&fields)?;
            if header_bytes > total_bytes {
                return Err(NatsExtraction::MalformedFrame);
            }
            validate_payload(bytes, payload_start, total_bytes, max_frame_bytes)?;
            true
        }
        "MSG" => {
            let payload_bytes = msg_payload_len(&fields)?;
            validate_payload(bytes, payload_start, payload_bytes, max_frame_bytes)?;
            true
        }
        "HMSG" => {
            let (header_bytes, total_bytes) = hmsg_lengths(&fields)?;
            if header_bytes > total_bytes {
                return Err(NatsExtraction::MalformedFrame);
            }
            validate_payload(bytes, payload_start, total_bytes, max_frame_bytes)?;
            true
        }
        "SUB" => {
            if !(3..=4).contains(&fields.len()) {
                return Err(NatsExtraction::MalformedFrame);
            }
            true
        }
        "UNSUB" => {
            if !(2..=3).contains(&fields.len()) {
                return Err(NatsExtraction::MalformedFrame);
            }
            false
        }
        "CONNECT" | "INFO" => {
            if fields.len() < 2 {
                return Err(NatsExtraction::MalformedFrame);
            }
            false
        }
        "PING" | "PONG" | "+OK" => {
            if fields.len() != 1 {
                return Err(NatsExtraction::MalformedFrame);
            }
            false
        }
        "-ERR" => {
            if fields.len() < 2 {
                return Err(NatsExtraction::MalformedFrame);
            }
            false
        }
        _ => return Err(NatsExtraction::UnsupportedCommand),
    };

    Ok(NatsCommand {
        operation: Some(command.to_ascii_lowercase()),
        subject_present,
    })
}

fn pub_payload_len(fields: &[&str]) -> Result<usize, NatsExtraction> {
    match fields {
        [_, _, payload_bytes] | [_, _, _, payload_bytes] => parse_payload_len(payload_bytes),
        _ => Err(NatsExtraction::MalformedFrame),
    }
}

fn hpub_lengths(fields: &[&str]) -> Result<(usize, usize), NatsExtraction> {
    match fields {
        [_, _, header_bytes, total_bytes] | [_, _, _, header_bytes, total_bytes] => Ok((
            parse_payload_len(header_bytes)?,
            parse_payload_len(total_bytes)?,
        )),
        _ => Err(NatsExtraction::MalformedFrame),
    }
}

fn msg_payload_len(fields: &[&str]) -> Result<usize, NatsExtraction> {
    match fields {
        [_, _, _, payload_bytes] | [_, _, _, _, payload_bytes] => parse_payload_len(payload_bytes),
        _ => Err(NatsExtraction::MalformedFrame),
    }
}

fn hmsg_lengths(fields: &[&str]) -> Result<(usize, usize), NatsExtraction> {
    match fields {
        [_, _, _, header_bytes, total_bytes] | [_, _, _, _, header_bytes, total_bytes] => Ok((
            parse_payload_len(header_bytes)?,
            parse_payload_len(total_bytes)?,
        )),
        _ => Err(NatsExtraction::MalformedFrame),
    }
}

fn parse_payload_len(value: &str) -> Result<usize, NatsExtraction> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(NatsExtraction::MalformedFrame);
    }
    value
        .parse::<usize>()
        .map_err(|_| NatsExtraction::PayloadTooLong)
}

fn validate_payload(
    bytes: &[u8],
    payload_start: usize,
    payload_bytes: usize,
    max_frame_bytes: usize,
) -> Result<(), NatsExtraction> {
    if payload_bytes > max_frame_bytes {
        return Err(NatsExtraction::PayloadTooLong);
    }
    let payload_end = payload_start
        .checked_add(payload_bytes)
        .ok_or(NatsExtraction::PayloadTooLong)?;
    let frame_end = payload_end
        .checked_add(2)
        .ok_or(NatsExtraction::PayloadTooLong)?;
    if frame_end > max_frame_bytes {
        return Err(NatsExtraction::FrameTooLong);
    }
    if frame_end > bytes.len() || bytes.get(payload_end..frame_end) != Some(b"\r\n") {
        return Err(NatsExtraction::MalformedFrame);
    }
    Ok(())
}

fn bounded_operation(value: &str) -> Option<String> {
    if value.is_empty()
        || value.len() > MAX_NATS_OPERATION_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte == b'+' || byte == b'-')
    {
        return None;
    }
    Some(value.to_string())
}

fn line_end(bytes: &[u8], start: usize) -> Option<usize> {
    if start >= bytes.len() {
        return None;
    }
    bytes[start..]
        .windows(2)
        .position(|window| window == b"\r\n")
        .map(|offset| start + offset)
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
