use e_navigator_signals::{ProtocolKind, TraceAttribute};

use crate::ProtocolExtractionConfig;

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

/// Bounded state for one MySQL command response.
///
/// MySQL resets the packet sequence to zero for each command and starts its
/// response at sequence one. Result sets then span column metadata, rows, and
/// a terminal EOF/OK packet. This tracker deliberately retains the request on
/// malformed, missing, or out-of-order packets so callers never attach an
/// outcome to the wrong command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MysqlResponseLifecycle {
    kind: MysqlResponseKind,
    phase: MysqlResponsePhase,
    next_sequence: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MysqlResponseKind {
    Command,
    BinaryResultset,
    NoResponse,
    StatementFetch,
    StatementPrepare,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MysqlResponsePhase {
    Initial,
    Columns {
        remaining: u64,
        total: u64,
    },
    Rows {
        columns: u64,
        metadata_terminated: bool,
    },
    PrepareParameters {
        remaining: u16,
        columns: u16,
    },
    PrepareParameterTerminator {
        columns: u16,
    },
    PrepareColumns {
        remaining: u16,
    },
    PrepareFinalTerminator,
    StatementFetchRows,
}

/// Observable progress of one MySQL command response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MysqlResponseProgress {
    Continue,
    Complete(ParsedMysqlResponse),
}

impl MysqlResponseLifecycle {
    /// Creates response state from one complete command packet.
    pub fn from_request(
        bytes: &[u8],
        config: &ProtocolExtractionConfig,
    ) -> Result<Self, MysqlExtraction> {
        if bytes.len() > config.max_header_bytes {
            return Err(MysqlExtraction::PacketTooLong);
        }
        let (sequence, payload) = packet_parts(bytes, config.max_header_bytes)?;
        if sequence != 0 {
            return Err(MysqlExtraction::UnexpectedSequence);
        }
        let command = *payload.first().ok_or(MysqlExtraction::MalformedPacket)?;
        let kind = match command {
            MYSQL_COM_STMT_PREPARE => MysqlResponseKind::StatementPrepare,
            MYSQL_COM_STMT_EXECUTE => MysqlResponseKind::BinaryResultset,
            MYSQL_COM_STMT_FETCH => MysqlResponseKind::StatementFetch,
            MYSQL_COM_QUIT | MYSQL_COM_STMT_SEND_LONG_DATA | MYSQL_COM_STMT_CLOSE => {
                MysqlResponseKind::NoResponse
            }
            _ => MysqlResponseKind::Command,
        };
        Ok(Self {
            kind,
            phase: MysqlResponsePhase::Initial,
            next_sequence: 1,
        })
    }

    /// Whether the command's protocol lifecycle includes a server response.
    pub fn expects_response(&self) -> bool {
        self.kind != MysqlResponseKind::NoResponse
    }

    /// Consumes one complete MySQL packet without retaining its payload.
    pub fn observe_packet(
        &mut self,
        bytes: &[u8],
        config: &ProtocolExtractionConfig,
    ) -> Result<MysqlResponseProgress, MysqlExtraction> {
        if bytes.len() > config.max_header_bytes {
            return Err(MysqlExtraction::PacketTooLong);
        }
        let (sequence, payload) = packet_parts(bytes, config.max_header_bytes)?;
        if sequence != self.next_sequence {
            return Err(MysqlExtraction::UnexpectedSequence);
        }

        let transition = response_transition(self.kind, self.phase, payload, bytes, config)?;
        self.next_sequence = self.next_sequence.wrapping_add(1);
        match transition {
            MysqlResponseTransition::Continue(phase) => {
                self.phase = phase;
                Ok(MysqlResponseProgress::Continue)
            }
            MysqlResponseTransition::MoreResults => {
                self.phase = MysqlResponsePhase::Initial;
                Ok(MysqlResponseProgress::Continue)
            }
            MysqlResponseTransition::Complete(response) => {
                Ok(MysqlResponseProgress::Complete(response))
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum MysqlResponseTransition {
    Continue(MysqlResponsePhase),
    MoreResults,
    Complete(ParsedMysqlResponse),
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
        MYSQL_OK_PACKET if is_ok_packet(payload) => Ok(mysql_ok_response(config.max_attributes)),
        MYSQL_OK_PACKET => Err(MysqlExtraction::UnsupportedResponse),
        MYSQL_EOF_PACKET if is_ok_packet(payload) => Ok(mysql_ok_response(config.max_attributes)),
        MYSQL_EOF_PACKET if matches!(payload.len(), 1 | 5) => {
            Ok(mysql_eof_response(config.max_attributes))
        }
        MYSQL_EOF_PACKET => Err(MysqlExtraction::UnsupportedResponse),
        MYSQL_ERR_PACKET => mysql_error_response(payload, config.max_attributes),
        _ => Err(MysqlExtraction::UnsupportedResponse),
    }
}

fn response_transition(
    kind: MysqlResponseKind,
    phase: MysqlResponsePhase,
    payload: &[u8],
    packet: &[u8],
    config: &ProtocolExtractionConfig,
) -> Result<MysqlResponseTransition, MysqlExtraction> {
    if payload.first() == Some(&MYSQL_ERR_PACKET) {
        return terminal_transition(packet, payload, config);
    }

    match phase {
        MysqlResponsePhase::Initial => {
            if kind == MysqlResponseKind::StatementPrepare {
                return prepare_initial_transition(payload, config);
            }
            if kind == MysqlResponseKind::StatementFetch {
                if is_eof_packet(payload) || payload.first() == Some(&MYSQL_EOF_PACKET) {
                    return terminal_transition(packet, payload, config);
                }
                if payload.first() == Some(&MYSQL_OK_PACKET) {
                    return Ok(MysqlResponseTransition::Continue(
                        MysqlResponsePhase::StatementFetchRows,
                    ));
                }
                return Err(MysqlExtraction::UnsupportedResponse);
            }
            if is_ok_packet(payload) || is_eof_packet(payload) {
                return terminal_transition(packet, payload, config);
            }
            if payload.first() == Some(&MYSQL_LOCAL_INFILE_PACKET) {
                return Err(MysqlExtraction::UnsupportedResponse);
            }
            let (columns, consumed) = read_length_encoded_integer(payload, 0)?;
            if consumed != payload.len() || columns == 0 || columns > MAX_MYSQL_RESULT_COLUMNS {
                return Err(MysqlExtraction::UnsupportedResponse);
            }
            Ok(MysqlResponseTransition::Continue(
                MysqlResponsePhase::Columns {
                    remaining: columns,
                    total: columns,
                },
            ))
        }
        MysqlResponsePhase::Columns { remaining, total } => {
            validate_column_definition_41(payload, config.max_request_line_bytes)?;
            let remaining = remaining
                .checked_sub(1)
                .ok_or(MysqlExtraction::MalformedPacket)?;
            let phase = if remaining == 0 {
                MysqlResponsePhase::Rows {
                    columns: total,
                    metadata_terminated: false,
                }
            } else {
                MysqlResponsePhase::Columns { remaining, total }
            };
            Ok(MysqlResponseTransition::Continue(phase))
        }
        MysqlResponsePhase::Rows {
            columns,
            metadata_terminated,
        } => {
            if !metadata_terminated && is_eof_packet(payload) {
                if kind == MysqlResponseKind::BinaryResultset
                    && mysql_status_flags(payload)
                        .is_some_and(|flags| flags & MYSQL_SERVER_STATUS_CURSOR_EXISTS != 0)
                {
                    return terminal_transition(packet, payload, config);
                }
                return Ok(MysqlResponseTransition::Continue(
                    MysqlResponsePhase::Rows {
                        columns,
                        metadata_terminated: true,
                    },
                ));
            }

            if kind == MysqlResponseKind::BinaryResultset
                && payload.first() == Some(&MYSQL_OK_PACKET)
            {
                return Ok(MysqlResponseTransition::Continue(
                    MysqlResponsePhase::Rows {
                        columns,
                        metadata_terminated: true,
                    },
                ));
            }

            if is_text_resultset_row(payload, columns) {
                return Ok(MysqlResponseTransition::Continue(
                    MysqlResponsePhase::Rows {
                        columns,
                        metadata_terminated: true,
                    },
                ));
            }

            if is_ok_packet(payload) || is_eof_packet(payload) {
                return terminal_transition(packet, payload, config);
            }
            Err(MysqlExtraction::UnsupportedResponse)
        }
        MysqlResponsePhase::PrepareParameters { remaining, columns } => {
            validate_column_definition_41(payload, config.max_request_line_bytes)?;
            let remaining = remaining
                .checked_sub(1)
                .ok_or(MysqlExtraction::MalformedPacket)?;
            let phase = if remaining == 0 {
                MysqlResponsePhase::PrepareParameterTerminator { columns }
            } else {
                MysqlResponsePhase::PrepareParameters { remaining, columns }
            };
            Ok(MysqlResponseTransition::Continue(phase))
        }
        MysqlResponsePhase::PrepareParameterTerminator { columns } => {
            if !is_eof_packet(payload) {
                return Err(MysqlExtraction::UnsupportedResponse);
            }
            if columns == 0 {
                terminal_transition(packet, payload, config)
            } else {
                Ok(MysqlResponseTransition::Continue(
                    MysqlResponsePhase::PrepareColumns { remaining: columns },
                ))
            }
        }
        MysqlResponsePhase::PrepareColumns { remaining } => {
            validate_column_definition_41(payload, config.max_request_line_bytes)?;
            let remaining = remaining
                .checked_sub(1)
                .ok_or(MysqlExtraction::MalformedPacket)?;
            let phase = if remaining == 0 {
                MysqlResponsePhase::PrepareFinalTerminator
            } else {
                MysqlResponsePhase::PrepareColumns { remaining }
            };
            Ok(MysqlResponseTransition::Continue(phase))
        }
        MysqlResponsePhase::PrepareFinalTerminator => {
            if !is_eof_packet(payload) && !is_ok_packet(payload) {
                return Err(MysqlExtraction::UnsupportedResponse);
            }
            terminal_transition(packet, payload, config)
        }
        MysqlResponsePhase::StatementFetchRows => {
            if is_eof_packet(payload) || payload.first() == Some(&MYSQL_EOF_PACKET) {
                terminal_transition(packet, payload, config)
            } else if payload.first() == Some(&MYSQL_OK_PACKET) {
                Ok(MysqlResponseTransition::Continue(
                    MysqlResponsePhase::StatementFetchRows,
                ))
            } else {
                Err(MysqlExtraction::UnsupportedResponse)
            }
        }
    }
}

fn prepare_initial_transition(
    payload: &[u8],
    config: &ProtocolExtractionConfig,
) -> Result<MysqlResponseTransition, MysqlExtraction> {
    if payload.first() != Some(&MYSQL_OK_PACKET) || payload.len() < 10 {
        return Err(MysqlExtraction::UnsupportedResponse);
    }
    if payload[9] != 0 || payload.len() == 11 {
        return Err(MysqlExtraction::MalformedPacket);
    }
    if !matches!(payload.len(), 10 | 12) {
        return Err(MysqlExtraction::UnsupportedResponse);
    }
    let columns = u16::from_le_bytes([payload[5], payload[6]]);
    let parameters = u16::from_le_bytes([payload[7], payload[8]]);
    if parameters > 0 {
        return Ok(MysqlResponseTransition::Continue(
            MysqlResponsePhase::PrepareParameters {
                remaining: parameters,
                columns,
            },
        ));
    }
    if columns > 0 {
        return Ok(MysqlResponseTransition::Continue(
            MysqlResponsePhase::PrepareColumns { remaining: columns },
        ));
    }
    Ok(MysqlResponseTransition::Complete(mysql_ok_response(
        config.max_attributes,
    )))
}

fn terminal_transition(
    packet: &[u8],
    payload: &[u8],
    config: &ProtocolExtractionConfig,
) -> Result<MysqlResponseTransition, MysqlExtraction> {
    let response = parse_mysql_response(packet, config)?;
    if mysql_status_flags(payload)
        .is_some_and(|flags| flags & MYSQL_SERVER_MORE_RESULTS_EXISTS != 0)
    {
        Ok(MysqlResponseTransition::MoreResults)
    } else {
        Ok(MysqlResponseTransition::Complete(response))
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

fn packet_parts(bytes: &[u8], max_packet_bytes: usize) -> Result<(u8, &[u8]), MysqlExtraction> {
    if bytes.len() < 4 {
        return Err(MysqlExtraction::MalformedPacket);
    }
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
    Ok((bytes[3], &bytes[4..total_len]))
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
