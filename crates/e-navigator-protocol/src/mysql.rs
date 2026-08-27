use e_navigator_signals::{ProtocolKind, TraceAttribute};

use crate::ProtocolExtractionConfig;

mod lifecycle;

pub use lifecycle::{
    MysqlClientPacketProgress, MysqlLogicalPacketProgress, MysqlResponseLifecycle,
    MysqlResponseProgress,
};

const MYSQL_COM_QUIT: u8 = 0x01;
const MYSQL_COM_INIT_DB: u8 = 0x02;
const MYSQL_COM_QUERY: u8 = 0x03;
const MYSQL_COM_PING: u8 = 0x0e;
const MYSQL_COM_STMT_PREPARE: u8 = 0x16;
const MYSQL_COM_STMT_EXECUTE: u8 = 0x17;
const MYSQL_COM_STMT_SEND_LONG_DATA: u8 = 0x18;
const MYSQL_COM_STMT_CLOSE: u8 = 0x19;
const MYSQL_COM_STMT_RESET: u8 = 0x1a;
const MYSQL_COM_STMT_FETCH: u8 = 0x1c;
const MYSQL_COM_RESET_CONNECTION: u8 = 0x1f;
const MYSQL_OK_PACKET: u8 = 0x00;
const MYSQL_EOF_PACKET: u8 = 0xfe;
const MYSQL_ERR_PACKET: u8 = 0xff;
const MYSQL_LOCAL_INFILE_PACKET: u8 = 0xfb;
const MAX_MYSQL_OPERATION_BYTES: usize = 64;
const MAX_MYSQL_RESULT_COLUMNS: u64 = 4096;
const MYSQL_SQLSTATE_BYTES: usize = 5;
const MYSQL_SERVER_MORE_RESULTS_EXISTS: u16 = 0x0008;
const MYSQL_SERVER_STATUS_CURSOR_EXISTS: u16 = 0x0040;
const MYSQL_PACKET_HEADER_BYTES: usize = 4;

/// Maximum payload carried by one physical MySQL packet. A payload with this
/// exact length continues the same logical message in the next packet.
pub const MYSQL_MAX_PHYSICAL_PAYLOAD_BYTES: usize = 0x00ff_ffff;

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
    UnexpectedSequence,
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
    let command = *payload.first().ok_or(MysqlExtraction::MalformedPacket)?;
    let operation = match command {
        MYSQL_COM_QUERY | MYSQL_COM_STMT_PREPARE => {
            let query = parse_query_bytes(&payload[1..], config.max_request_line_bytes)?;
            mysql_operation(query)
        }
        MYSQL_COM_QUIT => mysql_fixed_length_operation(payload, 1, "QUIT")?,
        MYSQL_COM_INIT_DB => mysql_init_db_operation(payload, config.max_request_line_bytes)?,
        MYSQL_COM_STMT_EXECUTE => mysql_stmt_execute_operation(payload)?,
        MYSQL_COM_STMT_SEND_LONG_DATA => {
            mysql_stmt_send_long_data_operation(payload, config.max_request_line_bytes)?
        }
        MYSQL_COM_STMT_CLOSE => mysql_fixed_length_operation(payload, 5, "CLOSE")?,
        MYSQL_COM_STMT_RESET => mysql_fixed_length_operation(payload, 5, "RESET")?,
        MYSQL_COM_STMT_FETCH => mysql_fixed_length_operation(payload, 9, "FETCH")?,
        MYSQL_COM_RESET_CONNECTION => mysql_fixed_length_operation(payload, 1, "RESET_CONNECTION")?,
        MYSQL_COM_PING => mysql_ping_operation(payload)?,
        _ => return Err(MysqlExtraction::UnsupportedCommand),
    };

    Ok(parsed_mysql_command(command, operation, config))
}

/// Parses the bounded prefix of the first physical packet in a multi-packet
/// MySQL command.
///
/// Only the command byte and a bounded SQL operation token are inspected.
/// The unseen command body is neither required nor retained. This entry point
/// accepts only the protocol-defined maximum physical payload, which prevents
/// an ordinary truncated packet from being promoted to a logical command.
pub fn parse_mysql_command_prefix(
    prefix: &[u8],
    declared_total_len: u64,
    config: &ProtocolExtractionConfig,
) -> Result<ParsedMysqlCommand, MysqlExtraction> {
    if prefix.len() > config.max_header_bytes {
        return Err(MysqlExtraction::PacketTooLong);
    }
    let (sequence, payload_len, payload_prefix) = packet_prefix_parts(prefix, declared_total_len)?;
    if sequence != 0 {
        return Err(MysqlExtraction::UnexpectedSequence);
    }
    if payload_len != MYSQL_MAX_PHYSICAL_PAYLOAD_BYTES {
        return Err(MysqlExtraction::MalformedPacket);
    }
    let command = *payload_prefix
        .first()
        .ok_or(MysqlExtraction::MalformedPacket)?;
    let operation = mysql_large_command_operation(command, payload_prefix)?;
    Ok(parsed_mysql_command(command, operation, config))
}

fn parsed_mysql_command(
    command: u8,
    operation: Option<String>,
    config: &ProtocolExtractionConfig,
) -> ParsedMysqlCommand {
    let mut attributes = Vec::new();
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "db.system.name",
        Some("mysql"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "db.operation.name",
        operation.as_deref(),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "db.mysql.command",
        Some(command_name(command)),
    );

    ParsedMysqlCommand {
        protocol: ProtocolKind::Mysql,
        operation,
        warning: None,
        attributes,
    }
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
    match payload.first().copied() {
        Some(MYSQL_OK_PACKET) if is_ok_packet(payload) => {
            Ok(mysql_ok_response(config.max_attributes))
        }
        Some(MYSQL_OK_PACKET) => Err(MysqlExtraction::UnsupportedResponse),
        Some(MYSQL_EOF_PACKET) if is_ok_packet(payload) => {
            Ok(mysql_ok_response(config.max_attributes))
        }
        Some(MYSQL_EOF_PACKET) if matches!(payload.len(), 1 | 5) => {
            Ok(mysql_eof_response(config.max_attributes))
        }
        Some(MYSQL_EOF_PACKET) => Err(MysqlExtraction::UnsupportedResponse),
        Some(MYSQL_ERR_PACKET) => mysql_error_response(payload, config.max_attributes),
        _ => Err(MysqlExtraction::UnsupportedResponse),
    }
}

fn is_ok_packet(payload: &[u8]) -> bool {
    let minimum_len = match payload.first() {
        Some(&MYSQL_OK_PACKET) => 7,
        Some(&MYSQL_EOF_PACKET) => 9,
        _ => return false,
    };
    if payload.len() < minimum_len {
        return false;
    }
    let Ok((_, after_affected_rows)) = read_length_encoded_integer(payload, 1) else {
        return false;
    };
    let Ok((_, after_last_insert_id)) = read_length_encoded_integer(payload, after_affected_rows)
    else {
        return false;
    };
    after_last_insert_id
        .checked_add(4)
        .is_some_and(|fixed_fields_end| fixed_fields_end <= payload.len())
}

fn is_eof_packet(payload: &[u8]) -> bool {
    payload.first() == Some(&MYSQL_EOF_PACKET) && payload.len() < 9
}

fn mysql_status_flags(payload: &[u8]) -> Option<u16> {
    if is_eof_packet(payload) {
        return (payload.len() >= 5).then(|| u16::from_le_bytes([payload[3], payload[4]]));
    }
    if !is_ok_packet(payload) {
        return None;
    }
    let (_, after_affected_rows) = read_length_encoded_integer(payload, 1).ok()?;
    let (_, after_last_insert_id) =
        read_length_encoded_integer(payload, after_affected_rows).ok()?;
    let status_end = after_last_insert_id.checked_add(2)?;
    let status = payload.get(after_last_insert_id..status_end)?;
    Some(u16::from_le_bytes([status[0], status[1]]))
}

fn is_text_resultset_row(payload: &[u8], columns: u64) -> bool {
    let Ok(columns) = usize::try_from(columns) else {
        return false;
    };
    let mut cursor = 0;
    for _ in 0..columns {
        let Some(marker) = payload.get(cursor).copied() else {
            return false;
        };
        if marker == MYSQL_LOCAL_INFILE_PACKET {
            cursor += 1;
            continue;
        }
        let Ok((value_len, value_start)) = read_length_encoded_integer(payload, cursor) else {
            return false;
        };
        let Ok(value_len) = usize::try_from(value_len) else {
            return false;
        };
        let Some(value_end) = value_start.checked_add(value_len) else {
            return false;
        };
        if value_end > payload.len() {
            return false;
        }
        cursor = value_end;
    }
    cursor == payload.len()
}

fn validate_column_definition_41(
    payload: &[u8],
    max_component_bytes: usize,
) -> Result<(), MysqlExtraction> {
    let mut cursor = 0;
    for _ in 0..6 {
        let (component_len, component_start) = read_length_encoded_integer(payload, cursor)?;
        let component_len =
            usize::try_from(component_len).map_err(|_| MysqlExtraction::MalformedPacket)?;
        if component_len > max_component_bytes {
            return Err(MysqlExtraction::QueryTooLong);
        }
        cursor = component_start
            .checked_add(component_len)
            .filter(|end| *end <= payload.len())
            .ok_or(MysqlExtraction::MalformedPacket)?;
    }

    let (fixed_fields_len, fixed_fields_start) = read_length_encoded_integer(payload, cursor)?;
    if fixed_fields_len != 0x0c {
        return Err(MysqlExtraction::MalformedPacket);
    }
    let fixed_fields_end = fixed_fields_start
        .checked_add(12)
        .ok_or(MysqlExtraction::MalformedPacket)?;
    if fixed_fields_end != payload.len() {
        return Err(MysqlExtraction::MalformedPacket);
    }
    Ok(())
}

fn read_length_encoded_integer(
    bytes: &[u8],
    cursor: usize,
) -> Result<(u64, usize), MysqlExtraction> {
    let marker = *bytes.get(cursor).ok_or(MysqlExtraction::MalformedPacket)?;
    match marker {
        0x00..=0xfa => Ok((u64::from(marker), cursor + 1)),
        0xfc => read_fixed_width_integer(bytes, cursor + 1, 2),
        0xfd => read_fixed_width_integer(bytes, cursor + 1, 3),
        0xfe => read_fixed_width_integer(bytes, cursor + 1, 8),
        0xfb | 0xff => Err(MysqlExtraction::MalformedPacket),
    }
}

fn read_fixed_width_integer(
    bytes: &[u8],
    start: usize,
    width: usize,
) -> Result<(u64, usize), MysqlExtraction> {
    let end = start
        .checked_add(width)
        .ok_or(MysqlExtraction::MalformedPacket)?;
    let value = bytes
        .get(start..end)
        .ok_or(MysqlExtraction::MalformedPacket)?;
    let mut decoded = 0_u64;
    for (index, byte) in value.iter().enumerate() {
        decoded |= u64::from(*byte) << (index * 8);
    }
    Ok((decoded, end))
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

fn mysql_init_db_operation(
    payload: &[u8],
    max_schema_bytes: usize,
) -> Result<Option<String>, MysqlExtraction> {
    if payload.len() < 2 {
        return Err(MysqlExtraction::MalformedPacket);
    }
    let _schema = parse_query_bytes(&payload[1..], max_schema_bytes)?;
    Ok(Some("INIT_DB".to_string()))
}

fn mysql_stmt_send_long_data_operation(
    payload: &[u8],
    max_parameter_bytes: usize,
) -> Result<Option<String>, MysqlExtraction> {
    if payload.len() < 7 {
        return Err(MysqlExtraction::MalformedPacket);
    }
    if payload[7..].len() > max_parameter_bytes {
        return Err(MysqlExtraction::QueryTooLong);
    }
    Ok(Some("SEND_LONG_DATA".to_string()))
}

fn mysql_fixed_length_operation(
    payload: &[u8],
    expected_len: usize,
    operation: &str,
) -> Result<Option<String>, MysqlExtraction> {
    if payload.len() != expected_len {
        return Err(MysqlExtraction::MalformedPacket);
    }
    Ok(Some(operation.to_string()))
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
    push_attribute(
        &mut attributes,
        max_attributes,
        "db.system.name",
        Some("mysql"),
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

fn packet_payload(bytes: &[u8], max_packet_bytes: usize) -> Result<&[u8], MysqlExtraction> {
    packet_parts(bytes, max_packet_bytes).map(|(_, payload)| payload)
}

pub(crate) fn packet_prefix_parts(
    prefix: &[u8],
    declared_total_len: u64,
) -> Result<(u8, usize, &[u8]), MysqlExtraction> {
    if prefix.len() < MYSQL_PACKET_HEADER_BYTES {
        return Err(MysqlExtraction::MalformedPacket);
    }
    let payload_len = mysql_payload_len(prefix);
    let total_len = payload_len
        .checked_add(MYSQL_PACKET_HEADER_BYTES)
        .ok_or(MysqlExtraction::MalformedPacket)?;
    if total_len as u64 != declared_total_len || prefix.len() > total_len {
        return Err(MysqlExtraction::MalformedPacket);
    }
    Ok((prefix[3], payload_len, &prefix[MYSQL_PACKET_HEADER_BYTES..]))
}

fn packet_parts(bytes: &[u8], max_packet_bytes: usize) -> Result<(u8, &[u8]), MysqlExtraction> {
    if bytes.len() < 4 {
        return Err(MysqlExtraction::MalformedPacket);
    }
    let payload_len = mysql_payload_len(bytes);
    let total_len = payload_len
        .checked_add(4)
        .ok_or(MysqlExtraction::MalformedPacket)?;
    if total_len > max_packet_bytes {
        return Err(MysqlExtraction::PacketTooLong);
    }
    if bytes.len() < total_len {
        return Err(MysqlExtraction::MalformedPacket);
    }
    Ok((bytes[3], &bytes[4..total_len]))
}

fn mysql_payload_len(bytes: &[u8]) -> usize {
    usize::from(bytes[0]) | (usize::from(bytes[1]) << 8) | (usize::from(bytes[2]) << 16)
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

pub(crate) fn mysql_large_command_operation(
    command: u8,
    payload_prefix: &[u8],
) -> Result<Option<String>, MysqlExtraction> {
    match command {
        MYSQL_COM_QUERY | MYSQL_COM_STMT_PREPARE => {
            Ok(mysql_operation_prefix(&payload_prefix[1..]))
        }
        MYSQL_COM_INIT_DB if payload_prefix.len() >= 2 => Ok(Some("INIT_DB".to_string())),
        MYSQL_COM_STMT_EXECUTE if payload_prefix.len() >= 10 => Ok(Some("EXECUTE".to_string())),
        MYSQL_COM_STMT_SEND_LONG_DATA if payload_prefix.len() >= 7 => {
            Ok(Some("SEND_LONG_DATA".to_string()))
        }
        MYSQL_COM_INIT_DB | MYSQL_COM_STMT_EXECUTE | MYSQL_COM_STMT_SEND_LONG_DATA => {
            Err(MysqlExtraction::MalformedPacket)
        }
        _ => Err(MysqlExtraction::UnsupportedCommand),
    }
}

fn mysql_operation_prefix(mut query: &[u8]) -> Option<String> {
    loop {
        query = &query[query
            .iter()
            .take_while(|byte| byte.is_ascii_whitespace())
            .count()..];
        if query.starts_with(b"--") || query.starts_with(b"#") {
            let newline = query.iter().position(|byte| *byte == b'\n')?;
            query = &query[newline + 1..];
            continue;
        }
        if query.starts_with(b"/*") {
            let comment_end = query.windows(2).position(|pair| pair == b"*/")?;
            query = &query[comment_end + 2..];
            continue;
        }
        let end = query
            .iter()
            .take_while(|byte| byte.is_ascii_alphabetic())
            .count();
        if end == 0 || end == query.len() || end > MAX_MYSQL_OPERATION_BYTES {
            return None;
        }
        return std::str::from_utf8(&query[..end])
            .ok()
            .map(str::to_ascii_uppercase);
    }
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
        MYSQL_COM_QUIT => "quit",
        MYSQL_COM_INIT_DB => "init_db",
        MYSQL_COM_QUERY => "query",
        MYSQL_COM_PING => "ping",
        MYSQL_COM_STMT_PREPARE => "stmt_prepare",
        MYSQL_COM_STMT_EXECUTE => "stmt_execute",
        MYSQL_COM_STMT_SEND_LONG_DATA => "stmt_send_long_data",
        MYSQL_COM_STMT_CLOSE => "stmt_close",
        MYSQL_COM_STMT_RESET => "stmt_reset",
        MYSQL_COM_STMT_FETCH => "stmt_fetch",
        MYSQL_COM_RESET_CONNECTION => "reset_connection",
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
