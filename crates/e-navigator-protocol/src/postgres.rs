use e_navigator_signals::{ProtocolKind, TraceAttribute};

use crate::ProtocolExtractionConfig;

const MAX_POSTGRES_OPERATION_BYTES: usize = 64;
const MAX_POSTGRES_STATEMENT_NAME_BYTES: usize = 128;
const POSTGRES_SQLSTATE_BYTES: usize = 5;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedPostgresQuery {
    pub protocol: ProtocolKind,
    pub operation: Option<String>,
    pub warning: Option<String>,
    pub attributes: Vec<TraceAttribute>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedPostgresResponse {
    pub protocol: ProtocolKind,
    pub status_code: String,
    pub error_type: String,
    pub attributes: Vec<TraceAttribute>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PostgresExtraction {
    FrameTooLong,
    InvalidUtf8,
    MalformedFrame,
    QueryTooLong,
    UnsupportedMessage,
    MissingSqlstate,
}

pub fn parse_postgres_message(
    bytes: &[u8],
    config: &ProtocolExtractionConfig,
) -> Result<ParsedPostgresQuery, PostgresExtraction> {
    if bytes.len() > config.max_header_bytes {
        return Err(PostgresExtraction::FrameTooLong);
    }
    if bytes.len() < 5 {
        return Err(PostgresExtraction::MalformedFrame);
    }

    let body = frame_body(bytes, config.max_header_bytes)?;
    let query = match bytes[0] {
        b'Q' => parse_simple_query(body, config.max_request_line_bytes)?,
        b'P' => parse_parse_message(body, config.max_request_line_bytes)?,
        _ => return Err(PostgresExtraction::UnsupportedMessage),
    };
    let operation = postgres_operation(query);

    let mut attributes = Vec::new();
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "db.system",
        Some("postgresql"),
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
        "db.postgresql.message.type",
        Some(message_type_name(bytes[0])),
    );

    Ok(ParsedPostgresQuery {
        protocol: ProtocolKind::Postgresql,
        operation,
        warning: None,
        attributes,
    })
}

pub fn parse_postgres_error_response(
    bytes: &[u8],
    config: &ProtocolExtractionConfig,
) -> Result<ParsedPostgresResponse, PostgresExtraction> {
    if bytes.len() > config.max_header_bytes {
        return Err(PostgresExtraction::FrameTooLong);
    }
    if bytes.len() < 5 {
        return Err(PostgresExtraction::MalformedFrame);
    }
    if bytes[0] != b'E' {
        return Err(PostgresExtraction::UnsupportedMessage);
    }

    let body = frame_body(bytes, config.max_header_bytes)?;
    let status_code = postgres_sqlstate(body)?.ok_or(PostgresExtraction::MissingSqlstate)?;
    let error_type = status_code.clone();

    let mut attributes = Vec::new();
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "db.system",
        Some("postgresql"),
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
        Some(&error_type),
    );

    Ok(ParsedPostgresResponse {
        protocol: ProtocolKind::Postgresql,
        status_code,
        error_type,
        attributes,
    })
}

fn frame_body(bytes: &[u8], max_frame_bytes: usize) -> Result<&[u8], PostgresExtraction> {
    let declared_len = u32::from_be_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]) as usize;
    if declared_len < 4 {
        return Err(PostgresExtraction::MalformedFrame);
    }
    let total_len = declared_len
        .checked_add(1)
        .ok_or(PostgresExtraction::MalformedFrame)?;
    if total_len > max_frame_bytes {
        return Err(PostgresExtraction::FrameTooLong);
    }
    if bytes.len() < total_len {
        return Err(PostgresExtraction::MalformedFrame);
    }
    Ok(&bytes[5..total_len])
}

fn postgres_sqlstate(body: &[u8]) -> Result<Option<String>, PostgresExtraction> {
    let mut cursor = 0;
    while cursor < body.len() {
        let field_type = body[cursor];
        cursor += 1;
        if field_type == 0 {
            return Ok(None);
        }
        if field_type == b'C' {
            let value = parse_cstring(body, &mut cursor, POSTGRES_SQLSTATE_BYTES)?;
            if value.len() != POSTGRES_SQLSTATE_BYTES
                || !value.bytes().all(|byte| byte.is_ascii_alphanumeric())
            {
                return Err(PostgresExtraction::MalformedFrame);
            }
            return Ok(Some(value.to_string()));
        }
        skip_cstring(body, &mut cursor)?;
    }
    Err(PostgresExtraction::MalformedFrame)
}

fn skip_cstring(bytes: &[u8], cursor: &mut usize) -> Result<(), PostgresExtraction> {
    let Some(end_offset) = bytes[*cursor..].iter().position(|byte| *byte == 0) else {
        return Err(PostgresExtraction::MalformedFrame);
    };
    *cursor += end_offset + 1;
    Ok(())
}

fn parse_simple_query(body: &[u8], max_query_bytes: usize) -> Result<&str, PostgresExtraction> {
    let mut cursor = 0;
    let query = parse_cstring(body, &mut cursor, max_query_bytes)?;
    if cursor != body.len() {
        return Err(PostgresExtraction::MalformedFrame);
    }
    Ok(query)
}

fn parse_parse_message(body: &[u8], max_query_bytes: usize) -> Result<&str, PostgresExtraction> {
    let mut cursor = 0;
    let _statement_name = parse_cstring(body, &mut cursor, MAX_POSTGRES_STATEMENT_NAME_BYTES)?;
    let query = parse_cstring(body, &mut cursor, max_query_bytes)?;
    if body.len().saturating_sub(cursor) < 2 {
        return Err(PostgresExtraction::MalformedFrame);
    }
    let parameter_count = u16::from_be_bytes([body[cursor], body[cursor + 1]]) as usize;
    cursor += 2;
    let oid_bytes = parameter_count
        .checked_mul(4)
        .ok_or(PostgresExtraction::MalformedFrame)?;
    if body.len().saturating_sub(cursor) != oid_bytes {
        return Err(PostgresExtraction::MalformedFrame);
    }
    Ok(query)
}

fn parse_cstring<'a>(
    bytes: &'a [u8],
    cursor: &mut usize,
    max_bytes: usize,
) -> Result<&'a str, PostgresExtraction> {
    let Some(end_offset) = bytes[*cursor..].iter().position(|byte| *byte == 0) else {
        return Err(PostgresExtraction::MalformedFrame);
    };
    if end_offset > max_bytes {
        return Err(PostgresExtraction::QueryTooLong);
    }
    let start = *cursor;
    let end = start + end_offset;
    let value =
        std::str::from_utf8(&bytes[start..end]).map_err(|_| PostgresExtraction::InvalidUtf8)?;
    *cursor = end + 1;
    Ok(value)
}

fn postgres_operation(query: &str) -> Option<String> {
    let query = skip_sql_prefix(query);
    let end = query
        .bytes()
        .take_while(|byte| byte.is_ascii_alphabetic())
        .count();
    if end == 0 || end > MAX_POSTGRES_OPERATION_BYTES {
        return None;
    }
    Some(query[..end].to_ascii_uppercase())
}

fn skip_sql_prefix(mut query: &str) -> &str {
    loop {
        query = query.trim_start_matches(|ch: char| ch.is_ascii_whitespace());
        if let Some(rest) = query.strip_prefix("--") {
            if let Some(next_line) = rest.find('\n') {
                query = &rest[next_line + 1..];
                continue;
            }
            return "";
        }
        if let Some(rest) = query.strip_prefix("/*") {
            if let Some(comment_end) = rest.find("*/") {
                query = &rest[comment_end + 2..];
                continue;
            }
            return "";
        }
        return query;
    }
}

fn message_type_name(message_type: u8) -> &'static str {
    match message_type {
        b'Q' => "query",
        b'P' => "parse",
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
