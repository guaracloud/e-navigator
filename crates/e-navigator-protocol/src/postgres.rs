use e_navigator_signals::{ProtocolKind, TraceAttribute};

use crate::ProtocolExtractionConfig;

const MAX_POSTGRES_OPERATION_BYTES: usize = 64;
const MAX_POSTGRES_STATEMENT_NAME_BYTES: usize = 128;
const MAX_POSTGRES_BIND_ITEMS: usize = 1024;
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
    pub error_type: Option<String>,
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
        b'B' => parse_bind_message(body, config.max_request_line_bytes)?,
        b'D' => parse_describe_message(body)?,
        b'C' => parse_close_message(body)?,
        b'E' => parse_execute_message(body)?,
        b'F' => parse_function_call_message(body, config.max_request_line_bytes)?,
        b'd' => parse_copy_data_message(body),
        b'c' => parse_copy_done_message(body)?,
        b'f' => parse_copy_fail_message(body, config.max_request_line_bytes)?,
        b'p' => parse_password_message(body, config.max_request_line_bytes)?,
        b'S' => parse_sync_message(body)?,
        b'H' => parse_flush_message(body)?,
        b'X' => parse_terminate_message(body)?,
        _ => return Err(PostgresExtraction::UnsupportedMessage),
    };
    let operation = match bytes[0] {
        b'B' => Some("BIND".to_string()),
        b'D' => Some("DESCRIBE".to_string()),
        b'C' => Some("CLOSE".to_string()),
        b'E' => Some("EXECUTE".to_string()),
        b'F' => Some("FUNCTION_CALL".to_string()),
        b'd' => Some("COPY_DATA".to_string()),
        b'c' => Some("COPY_DONE".to_string()),
        b'f' => Some("COPY_FAIL".to_string()),
        b'p' => Some("PASSWORD".to_string()),
        b'S' => Some("SYNC".to_string()),
        b'H' => Some("FLUSH".to_string()),
        b'X' => Some("TERMINATE".to_string()),
        _ => postgres_operation(query),
    };

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
    let response = parse_postgres_response(bytes, config)?;
    if response.error_type.is_none() {
        return Err(PostgresExtraction::UnsupportedMessage);
    }
    Ok(response)
}

pub fn parse_postgres_response(
    bytes: &[u8],
    config: &ProtocolExtractionConfig,
) -> Result<ParsedPostgresResponse, PostgresExtraction> {
    if bytes.len() > config.max_header_bytes {
        return Err(PostgresExtraction::FrameTooLong);
    }
    if bytes.len() < 5 {
        return Err(PostgresExtraction::MalformedFrame);
    }

    let body = frame_body(bytes, config.max_header_bytes)?;
    match bytes[0] {
        b'1' | b'2' | b'3' | b'I' | b'n' | b's' => {
            postgres_empty_ok_response(body, config.max_attributes)
        }
        b'C' => postgres_command_complete_response(body, config),
        b'D' => postgres_data_row_response(body, config),
        b'E' => postgres_error_response(body, config.max_attributes),
        b'N' => postgres_notice_response(body, config.max_attributes),
        b'R' => postgres_authentication_response(body, config),
        b'S' => postgres_parameter_status_response(body, config),
        b'T' => postgres_row_description_response(body, config),
        b'Z' => postgres_ready_for_query_response(body, config.max_attributes),
        _ => Err(PostgresExtraction::UnsupportedMessage),
    }
}

fn postgres_empty_ok_response(
    body: &[u8],
    max_attributes: usize,
) -> Result<ParsedPostgresResponse, PostgresExtraction> {
    if !body.is_empty() {
        return Err(PostgresExtraction::MalformedFrame);
    }
    let status_code = "OK".to_string();
    Ok(ParsedPostgresResponse {
        protocol: ProtocolKind::Postgresql,
        attributes: postgres_response_attributes(&status_code, None, max_attributes),
        status_code,
        error_type: None,
    })
}

fn postgres_command_complete_response(
    body: &[u8],
    config: &ProtocolExtractionConfig,
) -> Result<ParsedPostgresResponse, PostgresExtraction> {
    let mut cursor = 0;
    let _tag = parse_cstring(body, &mut cursor, config.max_request_line_bytes)?;
    if cursor != body.len() {
        return Err(PostgresExtraction::MalformedFrame);
    }
    let status_code = "OK".to_string();
    Ok(ParsedPostgresResponse {
        protocol: ProtocolKind::Postgresql,
        attributes: postgres_response_attributes(&status_code, None, config.max_attributes),
        status_code,
        error_type: None,
    })
}

fn postgres_data_row_response(
    body: &[u8],
    config: &ProtocolExtractionConfig,
) -> Result<ParsedPostgresResponse, PostgresExtraction> {
    let mut cursor = 0;
    let column_count = read_u16_be_cursor(body, &mut cursor)? as usize;
    if column_count > MAX_POSTGRES_BIND_ITEMS {
        return Err(PostgresExtraction::QueryTooLong);
    }
    for _ in 0..column_count {
        let value_len = read_i32_be_cursor(body, &mut cursor)?;
        if value_len == -1 {
            continue;
        }
        if value_len < 0 {
            return Err(PostgresExtraction::MalformedFrame);
        }
        let value_len = value_len as usize;
        if value_len > config.max_request_line_bytes {
            return Err(PostgresExtraction::QueryTooLong);
        }
        skip_bytes(body, &mut cursor, value_len)?;
    }
    if cursor != body.len() {
        return Err(PostgresExtraction::MalformedFrame);
    }

    let status_code = "OK".to_string();
    Ok(ParsedPostgresResponse {
        protocol: ProtocolKind::Postgresql,
        attributes: postgres_response_attributes(&status_code, None, config.max_attributes),
        status_code,
        error_type: None,
    })
}

fn postgres_parameter_status_response(
    body: &[u8],
    config: &ProtocolExtractionConfig,
) -> Result<ParsedPostgresResponse, PostgresExtraction> {
    let mut cursor = 0;
    let _parameter_name = parse_cstring(body, &mut cursor, config.max_request_line_bytes)?;
    let _parameter_value = parse_cstring(body, &mut cursor, config.max_request_line_bytes)?;
    if cursor != body.len() {
        return Err(PostgresExtraction::MalformedFrame);
    }
    let status_code = "OK".to_string();
    Ok(ParsedPostgresResponse {
        protocol: ProtocolKind::Postgresql,
        attributes: postgres_response_attributes(&status_code, None, config.max_attributes),
        status_code,
        error_type: None,
    })
}

fn postgres_row_description_response(
    body: &[u8],
    config: &ProtocolExtractionConfig,
) -> Result<ParsedPostgresResponse, PostgresExtraction> {
    let mut cursor = 0;
    let field_count = read_u16_be_cursor(body, &mut cursor)? as usize;
    if field_count > MAX_POSTGRES_BIND_ITEMS {
        return Err(PostgresExtraction::QueryTooLong);
    }
    for _ in 0..field_count {
        let _field_name = parse_cstring(body, &mut cursor, config.max_request_line_bytes)?;
        skip_bytes(body, &mut cursor, 18)?;
    }
    if cursor != body.len() {
        return Err(PostgresExtraction::MalformedFrame);
    }

    let status_code = "OK".to_string();
    Ok(ParsedPostgresResponse {
        protocol: ProtocolKind::Postgresql,
        attributes: postgres_response_attributes(&status_code, None, config.max_attributes),
        status_code,
        error_type: None,
    })
}

fn postgres_ready_for_query_response(
    body: &[u8],
    max_attributes: usize,
) -> Result<ParsedPostgresResponse, PostgresExtraction> {
    if body.len() != 1 {
        return Err(PostgresExtraction::MalformedFrame);
    }
    let (transaction_status, status_code, error_type) = match body[0] {
        b'I' => ("idle", "OK", None),
        b'T' => ("transaction", "OK", None),
        b'E' => (
            "failed_transaction",
            "FAILED_TRANSACTION",
            Some("postgresql_failed_transaction"),
        ),
        _ => return Err(PostgresExtraction::MalformedFrame),
    };
    let mut attributes = postgres_response_attributes(status_code, error_type, max_attributes);
    push_attribute(
        &mut attributes,
        max_attributes,
        "db.postgresql.transaction.status",
        Some(transaction_status),
    );

    Ok(ParsedPostgresResponse {
        protocol: ProtocolKind::Postgresql,
        status_code: status_code.to_string(),
        error_type: error_type.map(str::to_string),
        attributes,
    })
}

fn postgres_error_response(
    body: &[u8],
    max_attributes: usize,
) -> Result<ParsedPostgresResponse, PostgresExtraction> {
    let status_code = postgres_sqlstate(body)?.ok_or(PostgresExtraction::MissingSqlstate)?;
    let error_type = Some(status_code.clone());

    Ok(ParsedPostgresResponse {
        protocol: ProtocolKind::Postgresql,
        attributes: postgres_response_attributes(
            &status_code,
            error_type.as_deref(),
            max_attributes,
        ),
        status_code,
        error_type,
    })
}

fn postgres_notice_response(
    body: &[u8],
    max_attributes: usize,
) -> Result<ParsedPostgresResponse, PostgresExtraction> {
    let status_code = postgres_sqlstate(body)?.ok_or(PostgresExtraction::MissingSqlstate)?;

    Ok(ParsedPostgresResponse {
        protocol: ProtocolKind::Postgresql,
        attributes: postgres_response_attributes(&status_code, None, max_attributes),
        status_code,
        error_type: None,
    })
}

fn postgres_authentication_response(
    body: &[u8],
    config: &ProtocolExtractionConfig,
) -> Result<ParsedPostgresResponse, PostgresExtraction> {
    let mut cursor = 0;
    let auth_code = read_u32_be_cursor(body, &mut cursor)?;
    match auth_code {
        0 | 2 | 3 | 6 | 7 | 9 => {
            if cursor != body.len() {
                return Err(PostgresExtraction::MalformedFrame);
            }
        }
        5 => skip_bytes(body, &mut cursor, 4)?,
        8 | 11 | 12 => {
            cursor = body.len();
        }
        10 => {
            parse_authentication_sasl_mechanisms(body, &mut cursor, config.max_request_line_bytes)?
        }
        _ => return Err(PostgresExtraction::UnsupportedMessage),
    }
    if cursor != body.len() {
        return Err(PostgresExtraction::MalformedFrame);
    }

    let status_code = if auth_code == 0 {
        "OK"
    } else {
        "AUTHENTICATION_REQUIRED"
    }
    .to_string();
    Ok(ParsedPostgresResponse {
        protocol: ProtocolKind::Postgresql,
        attributes: postgres_response_attributes(&status_code, None, config.max_attributes),
        status_code,
        error_type: None,
    })
}

fn parse_authentication_sasl_mechanisms(
    bytes: &[u8],
    cursor: &mut usize,
    max_mechanism_bytes: usize,
) -> Result<(), PostgresExtraction> {
    loop {
        let mechanism = parse_cstring(bytes, cursor, max_mechanism_bytes)?;
        if mechanism.is_empty() {
            return Ok(());
        }
    }
}

fn postgres_response_attributes(
    status_code: &str,
    error_type: Option<&str>,
    max_attributes: usize,
) -> Vec<TraceAttribute> {
    let mut attributes = Vec::new();
    push_attribute(
        &mut attributes,
        max_attributes,
        "db.system",
        Some("postgresql"),
    );
    push_attribute(
        &mut attributes,
        max_attributes,
        "db.response.status_code",
        Some(status_code),
    );
    push_attribute(&mut attributes, max_attributes, "error.type", error_type);
    attributes
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
            if value.len() != POSTGRES_SQLSTATE_BYTES || !value.bytes().all(is_sqlstate_byte) {
                return Err(PostgresExtraction::MalformedFrame);
            }
            return Ok(Some(value.to_string()));
        }
        skip_cstring(body, &mut cursor)?;
    }
    Err(PostgresExtraction::MalformedFrame)
}

fn is_sqlstate_byte(byte: u8) -> bool {
    byte.is_ascii_digit() || byte.is_ascii_uppercase()
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

fn parse_bind_message(body: &[u8], max_parameter_bytes: usize) -> Result<&str, PostgresExtraction> {
    let mut cursor = 0;
    let _portal_name = parse_cstring(body, &mut cursor, MAX_POSTGRES_STATEMENT_NAME_BYTES)?;
    let _statement_name = parse_cstring(body, &mut cursor, MAX_POSTGRES_STATEMENT_NAME_BYTES)?;

    let parameter_format_count = read_u16_be_cursor(body, &mut cursor)? as usize;
    if parameter_format_count > MAX_POSTGRES_BIND_ITEMS {
        return Err(PostgresExtraction::QueryTooLong);
    }
    skip_bytes(body, &mut cursor, parameter_format_count.saturating_mul(2))?;

    let parameter_count = read_u16_be_cursor(body, &mut cursor)? as usize;
    if parameter_count > MAX_POSTGRES_BIND_ITEMS {
        return Err(PostgresExtraction::QueryTooLong);
    }
    for _ in 0..parameter_count {
        let parameter_len = read_i32_be_cursor(body, &mut cursor)?;
        if parameter_len == -1 {
            continue;
        }
        if parameter_len < -1 {
            return Err(PostgresExtraction::MalformedFrame);
        }
        let parameter_len = parameter_len as usize;
        if parameter_len > max_parameter_bytes {
            return Err(PostgresExtraction::QueryTooLong);
        }
        skip_bytes(body, &mut cursor, parameter_len)?;
    }

    let result_format_count = read_u16_be_cursor(body, &mut cursor)? as usize;
    if result_format_count > MAX_POSTGRES_BIND_ITEMS {
        return Err(PostgresExtraction::QueryTooLong);
    }
    skip_bytes(body, &mut cursor, result_format_count.saturating_mul(2))?;
    if cursor != body.len() {
        return Err(PostgresExtraction::MalformedFrame);
    }
    Ok("BIND")
}

fn parse_describe_message(body: &[u8]) -> Result<&str, PostgresExtraction> {
    parse_named_statement_or_portal_target(body)?;
    Ok("DESCRIBE")
}

fn parse_close_message(body: &[u8]) -> Result<&str, PostgresExtraction> {
    parse_named_statement_or_portal_target(body)?;
    Ok("CLOSE")
}

fn parse_named_statement_or_portal_target(body: &[u8]) -> Result<(), PostgresExtraction> {
    if body.is_empty() {
        return Err(PostgresExtraction::MalformedFrame);
    }
    if !matches!(body[0], b'S' | b'P') {
        return Err(PostgresExtraction::MalformedFrame);
    }
    let mut cursor = 1;
    let _name = parse_cstring(body, &mut cursor, MAX_POSTGRES_STATEMENT_NAME_BYTES)?;
    if cursor != body.len() {
        return Err(PostgresExtraction::MalformedFrame);
    }
    Ok(())
}

fn parse_execute_message(body: &[u8]) -> Result<&str, PostgresExtraction> {
    let mut cursor = 0;
    let _portal_name = parse_cstring(body, &mut cursor, MAX_POSTGRES_STATEMENT_NAME_BYTES)?;
    if body.len().saturating_sub(cursor) != 4 {
        return Err(PostgresExtraction::MalformedFrame);
    }
    let _max_rows = i32::from_be_bytes([
        body[cursor],
        body[cursor + 1],
        body[cursor + 2],
        body[cursor + 3],
    ]);
    Ok("EXECUTE")
}

fn parse_function_call_message(
    body: &[u8],
    max_argument_bytes: usize,
) -> Result<&str, PostgresExtraction> {
    let mut cursor = 0;
    skip_bytes(body, &mut cursor, 4)?;

    let argument_format_count = read_u16_be_cursor(body, &mut cursor)? as usize;
    if argument_format_count > MAX_POSTGRES_BIND_ITEMS {
        return Err(PostgresExtraction::QueryTooLong);
    }
    skip_bytes(body, &mut cursor, argument_format_count.saturating_mul(2))?;

    let argument_count = read_u16_be_cursor(body, &mut cursor)? as usize;
    if argument_count > MAX_POSTGRES_BIND_ITEMS {
        return Err(PostgresExtraction::QueryTooLong);
    }
    for _ in 0..argument_count {
        let argument_len = read_i32_be_cursor(body, &mut cursor)?;
        if argument_len == -1 {
            continue;
        }
        if argument_len < -1 {
            return Err(PostgresExtraction::MalformedFrame);
        }
        let argument_len = argument_len as usize;
        if argument_len > max_argument_bytes {
            return Err(PostgresExtraction::QueryTooLong);
        }
        skip_bytes(body, &mut cursor, argument_len)?;
    }

    let result_format_count = read_u16_be_cursor(body, &mut cursor)? as usize;
    if result_format_count > MAX_POSTGRES_BIND_ITEMS {
        return Err(PostgresExtraction::QueryTooLong);
    }
    skip_bytes(body, &mut cursor, result_format_count.saturating_mul(2))?;
    if cursor != body.len() {
        return Err(PostgresExtraction::MalformedFrame);
    }
    Ok("FUNCTION_CALL")
}

fn parse_copy_data_message(_body: &[u8]) -> &'static str {
    "COPY_DATA"
}

fn parse_copy_done_message(body: &[u8]) -> Result<&str, PostgresExtraction> {
    if !body.is_empty() {
        return Err(PostgresExtraction::MalformedFrame);
    }
    Ok("COPY_DONE")
}

fn parse_copy_fail_message(
    body: &[u8],
    max_error_message_bytes: usize,
) -> Result<&str, PostgresExtraction> {
    let mut cursor = 0;
    let _message = parse_cstring(body, &mut cursor, max_error_message_bytes)?;
    if cursor != body.len() {
        return Err(PostgresExtraction::MalformedFrame);
    }
    Ok("COPY_FAIL")
}

fn parse_password_message(
    body: &[u8],
    max_password_bytes: usize,
) -> Result<&str, PostgresExtraction> {
    let mut cursor = 0;
    let _password = parse_cstring(body, &mut cursor, max_password_bytes)?;
    if cursor != body.len() {
        return Err(PostgresExtraction::MalformedFrame);
    }
    Ok("PASSWORD")
}

fn parse_sync_message(body: &[u8]) -> Result<&str, PostgresExtraction> {
    if !body.is_empty() {
        return Err(PostgresExtraction::MalformedFrame);
    }
    Ok("SYNC")
}

fn parse_flush_message(body: &[u8]) -> Result<&str, PostgresExtraction> {
    if !body.is_empty() {
        return Err(PostgresExtraction::MalformedFrame);
    }
    Ok("FLUSH")
}

fn parse_terminate_message(body: &[u8]) -> Result<&str, PostgresExtraction> {
    if !body.is_empty() {
        return Err(PostgresExtraction::MalformedFrame);
    }
    Ok("TERMINATE")
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

fn read_u16_be_cursor(bytes: &[u8], cursor: &mut usize) -> Result<u16, PostgresExtraction> {
    let end = cursor
        .checked_add(2)
        .ok_or(PostgresExtraction::MalformedFrame)?;
    let raw = bytes
        .get(*cursor..end)
        .ok_or(PostgresExtraction::MalformedFrame)?;
    *cursor = end;
    Ok(u16::from_be_bytes([raw[0], raw[1]]))
}

fn read_u32_be_cursor(bytes: &[u8], cursor: &mut usize) -> Result<u32, PostgresExtraction> {
    let end = cursor
        .checked_add(4)
        .ok_or(PostgresExtraction::MalformedFrame)?;
    let raw = bytes
        .get(*cursor..end)
        .ok_or(PostgresExtraction::MalformedFrame)?;
    *cursor = end;
    Ok(u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]))
}

fn read_i32_be_cursor(bytes: &[u8], cursor: &mut usize) -> Result<i32, PostgresExtraction> {
    let end = cursor
        .checked_add(4)
        .ok_or(PostgresExtraction::MalformedFrame)?;
    let raw = bytes
        .get(*cursor..end)
        .ok_or(PostgresExtraction::MalformedFrame)?;
    *cursor = end;
    Ok(i32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]))
}

fn skip_bytes(bytes: &[u8], cursor: &mut usize, len: usize) -> Result<(), PostgresExtraction> {
    let end = cursor
        .checked_add(len)
        .ok_or(PostgresExtraction::MalformedFrame)?;
    if end > bytes.len() {
        return Err(PostgresExtraction::MalformedFrame);
    }
    *cursor = end;
    Ok(())
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
        b'B' => "bind",
        b'D' => "describe",
        b'C' => "close",
        b'E' => "execute",
        b'F' => "function_call",
        b'd' => "copy_data",
        b'c' => "copy_done",
        b'f' => "copy_fail",
        b'p' => "password",
        b'S' => "sync",
        b'H' => "flush",
        b'X' => "terminate",
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
