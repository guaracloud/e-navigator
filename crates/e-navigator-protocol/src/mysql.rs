use e_navigator_signals::{ProtocolKind, TraceAttribute};

use crate::ProtocolExtractionConfig;

const MYSQL_COM_QUERY: u8 = 0x03;
const MYSQL_COM_PING: u8 = 0x0e;
const MYSQL_COM_STMT_PREPARE: u8 = 0x16;
const MYSQL_COM_STMT_EXECUTE: u8 = 0x17;
const MYSQL_OK_PACKET: u8 = 0x00;
const MYSQL_EOF_PACKET: u8 = 0xfe;
const MYSQL_ERR_PACKET: u8 = 0xff;
const MAX_MYSQL_OPERATION_BYTES: usize = 64;
const MYSQL_SQLSTATE_BYTES: usize = 5;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedMysqlCommand {
    pub protocol: ProtocolKind,
    pub operation: Option<String>,
    pub warning: Option<String>,
    pub attributes: Vec<TraceAttribute>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedMysqlResponse {
    pub protocol: ProtocolKind,
    pub status_code: String,
    pub error_type: Option<String>,
    pub attributes: Vec<TraceAttribute>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MysqlExtraction {
    PacketTooLong,
    InvalidUtf8,
    MalformedPacket,
    QueryTooLong,
    UnsupportedCommand,
    UnsupportedResponse,
}

pub fn parse_mysql_command(
    bytes: &[u8],
    config: &ProtocolExtractionConfig,
) -> Result<ParsedMysqlCommand, MysqlExtraction> {
    if bytes.len() > config.max_header_bytes {
        return Err(MysqlExtraction::PacketTooLong);
    }
    if bytes.len() < 5 {
        return Err(MysqlExtraction::MalformedPacket);
    }

    let payload = packet_payload(bytes, config.max_header_bytes)?;
    let command = payload[0];
    let operation = match command {
        MYSQL_COM_QUERY | MYSQL_COM_STMT_PREPARE => {
            let query = parse_query_bytes(&payload[1..], config.max_request_line_bytes)?;
            mysql_operation(query)
        }
        MYSQL_COM_STMT_EXECUTE => mysql_stmt_execute_operation(payload)?,
        MYSQL_COM_PING => mysql_ping_operation(payload)?,
        _ => return Err(MysqlExtraction::UnsupportedCommand),
    };

    let mut attributes = Vec::new();
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "db.system",
        Some("mysql"),
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
        "db.mysql.command",
        Some(command_name(command)),
    );

    Ok(ParsedMysqlCommand {
        protocol: ProtocolKind::Mysql,
        operation,
        warning: None,
        attributes,
    })
}

pub fn parse_mysql_error_response(
    bytes: &[u8],
    config: &ProtocolExtractionConfig,
) -> Result<ParsedMysqlResponse, MysqlExtraction> {
    let response = parse_mysql_response(bytes, config)?;
    if response.error_type.is_none() {
        return Err(MysqlExtraction::UnsupportedResponse);
    }
    Ok(response)
}

pub fn parse_mysql_response(
    bytes: &[u8],
    config: &ProtocolExtractionConfig,
) -> Result<ParsedMysqlResponse, MysqlExtraction> {
    if bytes.len() > config.max_header_bytes {
        return Err(MysqlExtraction::PacketTooLong);
    }
    if bytes.len() < 5 {
        return Err(MysqlExtraction::MalformedPacket);
    }

    let payload = packet_payload(bytes, config.max_header_bytes)?;
    match payload[0] {
        MYSQL_OK_PACKET => Ok(mysql_ok_response(config.max_attributes)),
        MYSQL_EOF_PACKET if matches!(payload.len(), 1 | 5) => {
            Ok(mysql_eof_response(config.max_attributes))
        }
        MYSQL_EOF_PACKET => Err(MysqlExtraction::UnsupportedResponse),
        MYSQL_ERR_PACKET => mysql_error_response(payload, config.max_attributes),
        _ => Err(MysqlExtraction::UnsupportedResponse),
    }
}

fn mysql_ok_response(max_attributes: usize) -> ParsedMysqlResponse {
    let status_code = "OK".to_string();
    ParsedMysqlResponse {
        protocol: ProtocolKind::Mysql,
        status_code: status_code.clone(),
        error_type: None,
        attributes: mysql_response_attributes(&status_code, None, max_attributes),
    }
}

fn mysql_stmt_execute_operation(payload: &[u8]) -> Result<Option<String>, MysqlExtraction> {
    if payload.len() < 10 {
        return Err(MysqlExtraction::MalformedPacket);
    }
    Ok(Some("EXECUTE".to_string()))
}

fn mysql_ping_operation(payload: &[u8]) -> Result<Option<String>, MysqlExtraction> {
    if payload.len() != 1 {
        return Err(MysqlExtraction::MalformedPacket);
    }
    Ok(Some("PING".to_string()))
}

fn mysql_eof_response(max_attributes: usize) -> ParsedMysqlResponse {
    let status_code = "EOF".to_string();
    ParsedMysqlResponse {
        protocol: ProtocolKind::Mysql,
        status_code: status_code.clone(),
        error_type: None,
        attributes: mysql_response_attributes(&status_code, None, max_attributes),
    }
}

fn mysql_error_response(
    payload: &[u8],
    max_attributes: usize,
) -> Result<ParsedMysqlResponse, MysqlExtraction> {
    if payload.len() < 3 {
        return Err(MysqlExtraction::MalformedPacket);
    }
    let vendor_code = u16::from_le_bytes([payload[1], payload[2]]).to_string();
    let sqlstate = mysql_sqlstate(payload)?;
    let status_code = match sqlstate {
        Some(sqlstate) => format!("{sqlstate}/{vendor_code}"),
        None => vendor_code,
    };
    let error_type = Some(status_code.clone());

    Ok(ParsedMysqlResponse {
        protocol: ProtocolKind::Mysql,
        attributes: mysql_response_attributes(&status_code, error_type.as_deref(), max_attributes),
        status_code,
        error_type,
    })
}

fn mysql_response_attributes(
    status_code: &str,
    error_type: Option<&str>,
    max_attributes: usize,
) -> Vec<TraceAttribute> {
    let mut attributes = Vec::new();
    push_attribute(&mut attributes, max_attributes, "db.system", Some("mysql"));
    push_attribute(
        &mut attributes,
        max_attributes,
        "db.response.status_code",
        Some(status_code),
    );
    push_attribute(&mut attributes, max_attributes, "error.type", error_type);
    attributes
}

fn packet_payload(bytes: &[u8], max_packet_bytes: usize) -> Result<&[u8], MysqlExtraction> {
    let payload_len =
        usize::from(bytes[0]) | (usize::from(bytes[1]) << 8) | (usize::from(bytes[2]) << 16);
    let total_len = payload_len
        .checked_add(4)
        .ok_or(MysqlExtraction::MalformedPacket)?;
    if total_len > max_packet_bytes {
        return Err(MysqlExtraction::PacketTooLong);
    }
    if payload_len == 0 || bytes.len() < total_len {
        return Err(MysqlExtraction::MalformedPacket);
    }
    Ok(&bytes[4..total_len])
}

fn mysql_sqlstate(payload: &[u8]) -> Result<Option<&str>, MysqlExtraction> {
    if payload.len() < 4 || payload[3] != b'#' {
        return Ok(None);
    }
    let end = 4 + MYSQL_SQLSTATE_BYTES;
    if payload.len() < end {
        return Err(MysqlExtraction::MalformedPacket);
    }
    let sqlstate =
        std::str::from_utf8(&payload[4..end]).map_err(|_| MysqlExtraction::InvalidUtf8)?;
    if !sqlstate.bytes().all(is_sqlstate_byte) {
        return Err(MysqlExtraction::MalformedPacket);
    }
    Ok(Some(sqlstate))
}

fn is_sqlstate_byte(byte: u8) -> bool {
    byte.is_ascii_digit() || byte.is_ascii_uppercase()
}

fn parse_query_bytes(bytes: &[u8], max_query_bytes: usize) -> Result<&str, MysqlExtraction> {
    if bytes.len() > max_query_bytes {
        return Err(MysqlExtraction::QueryTooLong);
    }
    std::str::from_utf8(bytes).map_err(|_| MysqlExtraction::InvalidUtf8)
}

fn mysql_operation(query: &str) -> Option<String> {
    let query = skip_sql_prefix(query);
    let end = query
        .bytes()
        .take_while(|byte| byte.is_ascii_alphabetic())
        .count();
    if end == 0 || end > MAX_MYSQL_OPERATION_BYTES {
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
        if let Some(rest) = query.strip_prefix('#') {
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

fn command_name(command: u8) -> &'static str {
    match command {
        MYSQL_COM_QUERY => "query",
        MYSQL_COM_PING => "ping",
        MYSQL_COM_STMT_PREPARE => "stmt_prepare",
        MYSQL_COM_STMT_EXECUTE => "stmt_execute",
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
