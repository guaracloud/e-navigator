use e_navigator_signals::{ProtocolKind, TraceAttribute};

use crate::ProtocolExtractionConfig;

const MONGODB_OP_QUERY: i32 = 2004;
const MONGODB_OP_REPLY: i32 = 1;
const MONGODB_OP_MSG: i32 = 2013;
const OP_MSG_KIND_BODY: u8 = 0;
const OP_MSG_KIND_SEQUENCE: u8 = 1;
const MAX_MONGODB_OPERATION_BYTES: usize = 128;
const MAX_MONGODB_NAMESPACE_BYTES: usize = 256;
const MAX_MONGODB_REPLY_DOCUMENTS: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedMongodbCommand {
    pub protocol: ProtocolKind,
    pub operation: Option<String>,
    pub warning: Option<String>,
    pub attributes: Vec<TraceAttribute>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedMongodbResponse {
    pub protocol: ProtocolKind,
    pub status_code: String,
    pub error_type: Option<String>,
    pub attributes: Vec<TraceAttribute>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MongodbExtraction {
    FrameTooLong,
    InvalidUtf8,
    MalformedFrame,
    DocumentTooLong,
    UnsupportedOpcode,
    MissingStatus,
}

pub fn parse_mongodb_message(
    bytes: &[u8],
    config: &ProtocolExtractionConfig,
) -> Result<ParsedMongodbCommand, MongodbExtraction> {
    if bytes.len() > config.max_header_bytes {
        return Err(MongodbExtraction::FrameTooLong);
    }
    let frame = frame_body(bytes, config.max_header_bytes)?;
    let operation = match frame.opcode {
        MONGODB_OP_MSG => parse_op_msg_command(frame.body, config.max_request_line_bytes)?,
        MONGODB_OP_QUERY => parse_op_query_command(frame.body, config.max_request_line_bytes)?,
        _ => return Err(MongodbExtraction::UnsupportedOpcode),
    };

    let mut attributes = Vec::new();
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "db.system",
        Some("mongodb"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "db.operation",
        operation.as_deref(),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "db.mongodb.opcode",
        Some(opcode_name(frame.opcode)),
    );

    Ok(ParsedMongodbCommand {
        protocol: ProtocolKind::Mongodb,
        operation,
        warning: None,
        attributes,
    })
}

pub fn parse_mongodb_response(
    bytes: &[u8],
    config: &ProtocolExtractionConfig,
) -> Result<ParsedMongodbResponse, MongodbExtraction> {
    if bytes.len() > config.max_header_bytes {
        return Err(MongodbExtraction::FrameTooLong);
    }
    let frame = frame_body(bytes, config.max_header_bytes)?;
    let response = match frame.opcode {
        MONGODB_OP_MSG => parse_op_msg_response(frame.body, config.max_request_line_bytes)?,
        MONGODB_OP_REPLY => parse_op_reply_response(frame.body, config.max_request_line_bytes)?,
        _ => return Err(MongodbExtraction::UnsupportedOpcode),
    };
    let status_code = match (response.ok, response.code) {
        (Some(false), Some(code)) if code < 0 => return Err(MongodbExtraction::MalformedFrame),
        (Some(false), Some(code)) => code.to_string(),
        (Some(false), None) => "0".to_string(),
        (Some(true), _) => "1".to_string(),
        (None, _) => return Err(MongodbExtraction::MissingStatus),
    };
    let error_type = response
        .ok
        .is_some_and(|ok| !ok)
        .then(|| status_code.clone());

    let mut attributes = Vec::new();
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "db.system",
        Some("mongodb"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "db.response.status_code",
        Some(&status_code),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "error.type",
        error_type.as_deref(),
    );

    Ok(ParsedMongodbResponse {
        protocol: ProtocolKind::Mongodb,
        status_code,
        error_type,
        attributes,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MongodbFrame<'a> {
    opcode: i32,
    body: &'a [u8],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MongodbResponse {
    ok: Option<bool>,
    code: Option<i32>,
}

fn frame_body(bytes: &[u8], max_frame_bytes: usize) -> Result<MongodbFrame<'_>, MongodbExtraction> {
    if bytes.len() < 16 {
        return Err(MongodbExtraction::MalformedFrame);
    }
    let message_len = read_i32_le(bytes, 0)? as isize;
    if message_len < 16 {
        return Err(MongodbExtraction::MalformedFrame);
    }
    let message_len = message_len as usize;
    if message_len > max_frame_bytes {
        return Err(MongodbExtraction::FrameTooLong);
    }
    if bytes.len() < message_len {
        return Err(MongodbExtraction::MalformedFrame);
    }
    Ok(MongodbFrame {
        opcode: read_i32_le(bytes, 12)?,
        body: &bytes[16..message_len],
    })
}

fn parse_op_msg_command(
    body: &[u8],
    max_document_bytes: usize,
) -> Result<Option<String>, MongodbExtraction> {
    let document = op_msg_body_document(body, max_document_bytes)?;
    document_command_name(document)
}

fn parse_op_query_command(
    body: &[u8],
    max_document_bytes: usize,
) -> Result<Option<String>, MongodbExtraction> {
    if body.len() < 13 {
        return Err(MongodbExtraction::MalformedFrame);
    }
    let mut cursor = 4;
    let _namespace = read_cstring(body, &mut cursor, MAX_MONGODB_NAMESPACE_BYTES)?;
    if body.len().saturating_sub(cursor) < 8 {
        return Err(MongodbExtraction::MalformedFrame);
    }
    cursor += 8;
    let document = read_document(body, &mut cursor, max_document_bytes)?;
    if cursor != body.len() {
        return Err(MongodbExtraction::MalformedFrame);
    }
    document_command_name(document)
}

fn parse_op_msg_response(
    body: &[u8],
    max_document_bytes: usize,
) -> Result<MongodbResponse, MongodbExtraction> {
    let document = op_msg_body_document(body, max_document_bytes)?;
    document_response_status(document)
}

fn parse_op_reply_response(
    body: &[u8],
    max_document_bytes: usize,
) -> Result<MongodbResponse, MongodbExtraction> {
    if body.len() < 20 {
        return Err(MongodbExtraction::MalformedFrame);
    }
    let number_returned = read_i32_le(body, 16)?;
    if number_returned <= 0 {
        return Err(MongodbExtraction::MissingStatus);
    }
    let number_returned = number_returned as usize;
    if number_returned > MAX_MONGODB_REPLY_DOCUMENTS {
        return Err(MongodbExtraction::DocumentTooLong);
    }

    let mut cursor = 20;
    let first_document = read_document(body, &mut cursor, max_document_bytes)?;
    let response = document_response_status(first_document)?;
    for _ in 1..number_returned {
        let _ = read_document(body, &mut cursor, max_document_bytes)?;
    }
    if cursor != body.len() {
        return Err(MongodbExtraction::MalformedFrame);
    }
    Ok(response)
}

fn op_msg_body_document(
    body: &[u8],
    max_document_bytes: usize,
) -> Result<&[u8], MongodbExtraction> {
    if body.len() < 5 {
        return Err(MongodbExtraction::MalformedFrame);
    }
    let mut cursor = 4;
    let mut body_document = None;
    while cursor < body.len() {
        let kind = body[cursor];
        cursor += 1;
        match kind {
            OP_MSG_KIND_BODY => {
                let document = read_document(body, &mut cursor, max_document_bytes)?;
                if body_document.replace(document).is_some() {
                    return Err(MongodbExtraction::MalformedFrame);
                }
            }
            OP_MSG_KIND_SEQUENCE => {
                skip_document_sequence(body, &mut cursor, max_document_bytes)?;
            }
            _ => return Err(MongodbExtraction::MalformedFrame),
        }
    }
    body_document.ok_or(MongodbExtraction::MalformedFrame)
}

fn skip_document_sequence(
    bytes: &[u8],
    cursor: &mut usize,
    max_document_bytes: usize,
) -> Result<(), MongodbExtraction> {
    if bytes.len().saturating_sub(*cursor) < 4 {
        return Err(MongodbExtraction::MalformedFrame);
    }
    let sequence_len = read_i32_le(bytes, *cursor)? as isize;
    if sequence_len < 5 {
        return Err(MongodbExtraction::MalformedFrame);
    }
    let sequence_len = sequence_len as usize;
    if sequence_len > max_document_bytes {
        return Err(MongodbExtraction::DocumentTooLong);
    }
    let end = cursor
        .checked_add(sequence_len)
        .ok_or(MongodbExtraction::MalformedFrame)?;
    if end > bytes.len() {
        return Err(MongodbExtraction::MalformedFrame);
    }
    *cursor = end;
    Ok(())
}

fn read_document<'a>(
    bytes: &'a [u8],
    cursor: &mut usize,
    max_document_bytes: usize,
) -> Result<&'a [u8], MongodbExtraction> {
    if bytes.len().saturating_sub(*cursor) < 5 {
        return Err(MongodbExtraction::MalformedFrame);
    }
    let document_len = read_i32_le(bytes, *cursor)? as isize;
    if document_len < 5 {
        return Err(MongodbExtraction::MalformedFrame);
    }
    let document_len = document_len as usize;
    if document_len > max_document_bytes {
        return Err(MongodbExtraction::DocumentTooLong);
    }
    let end = cursor
        .checked_add(document_len)
        .ok_or(MongodbExtraction::MalformedFrame)?;
    if end > bytes.len() || bytes[end - 1] != 0 {
        return Err(MongodbExtraction::MalformedFrame);
    }
    let document = &bytes[*cursor..end];
    *cursor = end;
    Ok(document)
}

fn document_command_name(document: &[u8]) -> Result<Option<String>, MongodbExtraction> {
    if document.len() < 6 {
        return Err(MongodbExtraction::MalformedFrame);
    }
    let mut cursor = 4;
    if document[cursor] == 0 {
        return Ok(None);
    }
    cursor += 1;
    let key = read_cstring(document, &mut cursor, MAX_MONGODB_OPERATION_BYTES)?;
    if key.is_empty() || key.bytes().any(|byte| !is_command_key_byte(byte)) {
        return Ok(None);
    }
    Ok(Some(key.to_ascii_lowercase()))
}

fn document_response_status(document: &[u8]) -> Result<MongodbResponse, MongodbExtraction> {
    if document.len() < 5 {
        return Err(MongodbExtraction::MalformedFrame);
    }
    let mut cursor = 4;
    let mut response = MongodbResponse {
        ok: None,
        code: None,
    };
    while cursor < document.len() - 1 {
        let value_type = document[cursor];
        cursor += 1;
        let key = read_cstring(document, &mut cursor, MAX_MONGODB_OPERATION_BYTES)?;
        match (key, value_type) {
            ("ok", 0x01) => response.ok = Some(read_f64_le(document, &mut cursor)? != 0.0),
            ("ok", 0x08) => response.ok = Some(read_bool(document, &mut cursor)?),
            ("ok", 0x10) => response.ok = Some(read_i32_le_cursor(document, &mut cursor)? != 0),
            ("ok", 0x12) => response.ok = Some(read_i64_le(document, &mut cursor)? != 0),
            ("code", 0x10) => response.code = Some(read_i32_le_cursor(document, &mut cursor)?),
            _ => skip_bson_value(document, &mut cursor, value_type)?,
        }
    }
    if cursor != document.len() - 1 || document[cursor] != 0 {
        return Err(MongodbExtraction::MalformedFrame);
    }
    Ok(response)
}

fn read_cstring<'a>(
    bytes: &'a [u8],
    cursor: &mut usize,
    max_bytes: usize,
) -> Result<&'a str, MongodbExtraction> {
    let Some(end_offset) = bytes[*cursor..].iter().position(|byte| *byte == 0) else {
        return Err(MongodbExtraction::MalformedFrame);
    };
    if end_offset > max_bytes {
        return Err(MongodbExtraction::DocumentTooLong);
    }
    let start = *cursor;
    let end = start + end_offset;
    let value =
        std::str::from_utf8(&bytes[start..end]).map_err(|_| MongodbExtraction::InvalidUtf8)?;
    *cursor = end + 1;
    Ok(value)
}

fn skip_bson_value(
    bytes: &[u8],
    cursor: &mut usize,
    value_type: u8,
) -> Result<(), MongodbExtraction> {
    match value_type {
        0x01 | 0x09 | 0x11 | 0x12 => skip_bytes(bytes, cursor, 8),
        0x02 | 0x0d | 0x0e => skip_bson_string(bytes, cursor),
        0x03 | 0x04 | 0x0f => skip_bson_document(bytes, cursor),
        0x05 => skip_bson_binary(bytes, cursor),
        0x06 | 0x0a | 0x7f | 0xff => Ok(()),
        0x07 => skip_bytes(bytes, cursor, 12),
        0x08 => skip_bytes(bytes, cursor, 1),
        0x0b => {
            skip_bson_cstring(bytes, cursor)?;
            skip_bson_cstring(bytes, cursor)
        }
        0x0c => {
            skip_bson_string(bytes, cursor)?;
            skip_bytes(bytes, cursor, 12)
        }
        0x10 => skip_bytes(bytes, cursor, 4),
        0x13 => skip_bytes(bytes, cursor, 16),
        _ => Err(MongodbExtraction::MalformedFrame),
    }
}

fn skip_bson_string(bytes: &[u8], cursor: &mut usize) -> Result<(), MongodbExtraction> {
    let len = read_i32_le_cursor(bytes, cursor)? as isize;
    if len <= 0 {
        return Err(MongodbExtraction::MalformedFrame);
    }
    let len = len as usize;
    let end = cursor
        .checked_add(len)
        .ok_or(MongodbExtraction::MalformedFrame)?;
    if end > bytes.len() || bytes[end - 1] != 0 {
        return Err(MongodbExtraction::MalformedFrame);
    }
    *cursor = end;
    Ok(())
}

fn skip_bson_document(bytes: &[u8], cursor: &mut usize) -> Result<(), MongodbExtraction> {
    let len = read_i32_le(bytes, *cursor)? as isize;
    if len < 5 {
        return Err(MongodbExtraction::MalformedFrame);
    }
    let len = len as usize;
    let end = cursor
        .checked_add(len)
        .ok_or(MongodbExtraction::MalformedFrame)?;
    if end > bytes.len() || bytes[end - 1] != 0 {
        return Err(MongodbExtraction::MalformedFrame);
    }
    *cursor = end;
    Ok(())
}

fn skip_bson_binary(bytes: &[u8], cursor: &mut usize) -> Result<(), MongodbExtraction> {
    let len = read_i32_le_cursor(bytes, cursor)? as isize;
    if len < 0 {
        return Err(MongodbExtraction::MalformedFrame);
    }
    skip_bytes(bytes, cursor, 1)?;
    skip_bytes(bytes, cursor, len as usize)
}

fn skip_bson_cstring(bytes: &[u8], cursor: &mut usize) -> Result<(), MongodbExtraction> {
    let _ = read_cstring(bytes, cursor, MAX_MONGODB_OPERATION_BYTES)?;
    Ok(())
}

fn skip_bytes(bytes: &[u8], cursor: &mut usize, len: usize) -> Result<(), MongodbExtraction> {
    let end = cursor
        .checked_add(len)
        .ok_or(MongodbExtraction::MalformedFrame)?;
    if end > bytes.len() {
        return Err(MongodbExtraction::MalformedFrame);
    }
    *cursor = end;
    Ok(())
}

fn read_bool(bytes: &[u8], cursor: &mut usize) -> Result<bool, MongodbExtraction> {
    let value = *bytes
        .get(*cursor)
        .ok_or(MongodbExtraction::MalformedFrame)?;
    *cursor += 1;
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(MongodbExtraction::MalformedFrame),
    }
}

fn read_f64_le(bytes: &[u8], cursor: &mut usize) -> Result<f64, MongodbExtraction> {
    let end = cursor
        .checked_add(8)
        .ok_or(MongodbExtraction::MalformedFrame)?;
    let raw = bytes
        .get(*cursor..end)
        .ok_or(MongodbExtraction::MalformedFrame)?;
    *cursor = end;
    Ok(f64::from_le_bytes([
        raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7],
    ]))
}

fn read_i32_le_cursor(bytes: &[u8], cursor: &mut usize) -> Result<i32, MongodbExtraction> {
    let value = read_i32_le(bytes, *cursor)?;
    *cursor = cursor
        .checked_add(4)
        .ok_or(MongodbExtraction::MalformedFrame)?;
    Ok(value)
}

fn read_i64_le(bytes: &[u8], cursor: &mut usize) -> Result<i64, MongodbExtraction> {
    let end = cursor
        .checked_add(8)
        .ok_or(MongodbExtraction::MalformedFrame)?;
    let raw = bytes
        .get(*cursor..end)
        .ok_or(MongodbExtraction::MalformedFrame)?;
    *cursor = end;
    Ok(i64::from_le_bytes([
        raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7],
    ]))
}

fn read_i32_le(bytes: &[u8], offset: usize) -> Result<i32, MongodbExtraction> {
    let end = offset
        .checked_add(4)
        .ok_or(MongodbExtraction::MalformedFrame)?;
    let raw = bytes
        .get(offset..end)
        .ok_or(MongodbExtraction::MalformedFrame)?;
    Ok(i32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]))
}

fn is_command_key_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'.'
}

fn opcode_name(opcode: i32) -> &'static str {
    match opcode {
        MONGODB_OP_MSG => "op_msg",
        MONGODB_OP_QUERY => "op_query",
        _ => "unknown",
    }
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
