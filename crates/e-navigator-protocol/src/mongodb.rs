use e_navigator_signals::{ProtocolKind, TraceAttribute};

use crate::ProtocolExtractionConfig;

const MONGODB_OP_QUERY: i32 = 2004;
const MONGODB_OP_MSG: i32 = 2013;
const OP_MSG_KIND_BODY: u8 = 0;
const OP_MSG_KIND_SEQUENCE: u8 = 1;
const MAX_MONGODB_OPERATION_BYTES: usize = 128;
const MAX_MONGODB_NAMESPACE_BYTES: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedMongodbCommand {
    pub protocol: ProtocolKind,
    pub operation: Option<String>,
    pub warning: Option<String>,
    pub attributes: Vec<TraceAttribute>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MongodbExtraction {
    FrameTooLong,
    InvalidUtf8,
    MalformedFrame,
    DocumentTooLong,
    UnsupportedOpcode,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MongodbFrame<'a> {
    opcode: i32,
    body: &'a [u8],
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
    if body.len() < 5 {
        return Err(MongodbExtraction::MalformedFrame);
    }
    let mut cursor = 4;
    while cursor < body.len() {
        let kind = body[cursor];
        cursor += 1;
        match kind {
            OP_MSG_KIND_BODY => {
                let document = read_document(body, &mut cursor, max_document_bytes)?;
                return document_command_name(document);
            }
            OP_MSG_KIND_SEQUENCE => {
                skip_document_sequence(body, &mut cursor, max_document_bytes)?;
            }
            _ => return Err(MongodbExtraction::MalformedFrame),
        }
    }
    Err(MongodbExtraction::MalformedFrame)
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
