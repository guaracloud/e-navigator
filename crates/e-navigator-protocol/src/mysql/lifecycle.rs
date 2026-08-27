use super::{
    MAX_MYSQL_RESULT_COLUMNS, MYSQL_COM_QUIT, MYSQL_COM_STMT_CLOSE, MYSQL_COM_STMT_EXECUTE,
    MYSQL_COM_STMT_FETCH, MYSQL_COM_STMT_PREPARE, MYSQL_COM_STMT_SEND_LONG_DATA, MYSQL_EOF_PACKET,
    MYSQL_ERR_PACKET, MYSQL_LOCAL_INFILE_PACKET, MYSQL_MAX_PHYSICAL_PAYLOAD_BYTES, MYSQL_OK_PACKET,
    MYSQL_SERVER_MORE_RESULTS_EXISTS, MYSQL_SERVER_STATUS_CURSOR_EXISTS, MysqlExtraction,
    ParsedMysqlResponse, ProtocolExtractionConfig, is_eof_packet, is_ok_packet,
    is_text_resultset_row, mysql_large_command_operation, mysql_ok_response, mysql_status_flags,
    packet_parts, packet_prefix_parts, parse_mysql_response, read_length_encoded_integer,
    validate_column_definition_41,
};

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
    request_continuation: bool,
    response_continuation: bool,
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
    LocalInfileUpload,
    LocalInfileTerminal,
}

/// Observable progress of one MySQL command response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MysqlResponseProgress {
    Continue,
    Complete(ParsedMysqlResponse),
}

/// Progress while the client streams a `LOCAL INFILE` body. File bytes are
/// never parsed or retained; only the physical packet header is consumed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MysqlClientPacketProgress {
    Continue,
    UploadComplete,
}

/// Progress through physical packets that form one large logical MySQL
/// message. The packet bodies are never retained.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MysqlLogicalPacketProgress {
    Continue,
    Complete,
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
        Ok(Self {
            kind: response_kind(command),
            phase: MysqlResponsePhase::Initial,
            next_sequence: 1,
            request_continuation: false,
            response_continuation: false,
        })
    }

    /// Creates response state from the bounded first-packet prefix of a large
    /// logical command. Only a sequence-zero maximum-sized physical packet is
    /// accepted; ordinary truncation remains unsupported.
    pub fn from_request_prefix(
        prefix: &[u8],
        declared_total_len: u64,
        config: &ProtocolExtractionConfig,
    ) -> Result<Self, MysqlExtraction> {
        if prefix.len() > config.max_header_bytes {
            return Err(MysqlExtraction::PacketTooLong);
        }
        let (sequence, payload_len, payload_prefix) =
            packet_prefix_parts(prefix, declared_total_len)?;
        if sequence != 0 {
            return Err(MysqlExtraction::UnexpectedSequence);
        }
        if payload_len != MYSQL_MAX_PHYSICAL_PAYLOAD_BYTES {
            return Err(MysqlExtraction::MalformedPacket);
        }
        let command = *payload_prefix
            .first()
            .ok_or(MysqlExtraction::MalformedPacket)?;
        let _operation = mysql_large_command_operation(command, payload_prefix)?;
        Ok(Self {
            kind: response_kind(command),
            phase: MysqlResponsePhase::Initial,
            next_sequence: 1,
            request_continuation: true,
            response_continuation: false,
        })
    }

    /// Whether the command's protocol lifecycle includes a server response.
    #[must_use]
    pub fn expects_response(&self) -> bool {
        self.kind != MysqlResponseKind::NoResponse
    }

    /// Consumes one complete MySQL packet without retaining its payload.
    pub fn observe_packet(
        &mut self,
        bytes: &[u8],
        config: &ProtocolExtractionConfig,
    ) -> Result<MysqlResponseProgress, MysqlExtraction> {
        if self.request_continuation {
            return Err(MysqlExtraction::UnsupportedResponse);
        }
        if bytes.len() > config.max_header_bytes {
            return Err(MysqlExtraction::PacketTooLong);
        }
        let (sequence, payload) = packet_parts(bytes, config.max_header_bytes)?;
        if sequence != self.next_sequence {
            return Err(MysqlExtraction::UnexpectedSequence);
        }

        if self.response_continuation {
            self.next_sequence = self.next_sequence.wrapping_add(1);
            self.response_continuation = payload.len() == MYSQL_MAX_PHYSICAL_PAYLOAD_BYTES;
            return Ok(MysqlResponseProgress::Continue);
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

    /// Consumes a bounded continuation packet for the current large logical
    /// request. The expected response sequence advances with every physical
    /// request packet, as required by the MySQL packet protocol.
    pub fn observe_request_continuation(
        &mut self,
        prefix: &[u8],
        declared_total_len: u64,
    ) -> Result<MysqlLogicalPacketProgress, MysqlExtraction> {
        if !self.request_continuation {
            return Err(MysqlExtraction::UnsupportedResponse);
        }
        let (sequence, payload_len, _) = packet_prefix_parts(prefix, declared_total_len)?;
        if sequence != self.next_sequence {
            return Err(MysqlExtraction::UnexpectedSequence);
        }
        self.next_sequence = self.next_sequence.wrapping_add(1);
        if payload_len == MYSQL_MAX_PHYSICAL_PAYLOAD_BYTES {
            Ok(MysqlLogicalPacketProgress::Continue)
        } else {
            self.request_continuation = false;
            Ok(MysqlLogicalPacketProgress::Complete)
        }
    }

    /// Consumes the bounded prefix of a maximum-sized physical response
    /// packet. Large packets are accepted only where row payloads are legal;
    /// metadata, errors, and terminals still require complete parsing.
    pub fn observe_response_prefix(
        &mut self,
        prefix: &[u8],
        declared_total_len: u64,
    ) -> Result<MysqlResponseProgress, MysqlExtraction> {
        if self.request_continuation {
            return Err(MysqlExtraction::UnsupportedResponse);
        }
        let (sequence, payload_len, _) = packet_prefix_parts(prefix, declared_total_len)?;
        if sequence != self.next_sequence {
            return Err(MysqlExtraction::UnexpectedSequence);
        }
        if payload_len != MYSQL_MAX_PHYSICAL_PAYLOAD_BYTES {
            return Err(MysqlExtraction::UnsupportedResponse);
        }
        if !self.response_continuation
            && !matches!(
                self.phase,
                MysqlResponsePhase::Rows { .. } | MysqlResponsePhase::StatementFetchRows
            )
        {
            return Err(MysqlExtraction::UnsupportedResponse);
        }
        self.next_sequence = self.next_sequence.wrapping_add(1);
        self.response_continuation = true;
        Ok(MysqlResponseProgress::Continue)
    }

    /// Whether more physical request packets belong to this logical command.
    #[must_use]
    pub fn owns_request_continuation(&self) -> bool {
        self.request_continuation
    }

    /// Whether more physical response packets belong to one logical row.
    #[must_use]
    pub fn owns_response_continuation(&self) -> bool {
        self.response_continuation
    }

    /// Consumes a client-side `LOCAL INFILE` packet from its bounded prefix.
    ///
    /// `declared_total_len` is the complete physical packet length reported
    /// by stream reassembly. This permits correlation of file chunks larger
    /// than the capture prefix without inspecting or retaining their bodies.
    pub fn observe_client_packet(
        &mut self,
        prefix: &[u8],
        declared_total_len: u64,
    ) -> Result<MysqlClientPacketProgress, MysqlExtraction> {
        if self.phase != MysqlResponsePhase::LocalInfileUpload || prefix.len() < 4 {
            return Err(MysqlExtraction::UnsupportedResponse);
        }
        let payload_len =
            usize::from(prefix[0]) | (usize::from(prefix[1]) << 8) | (usize::from(prefix[2]) << 16);
        let total_len = payload_len
            .checked_add(4)
            .ok_or(MysqlExtraction::MalformedPacket)?;
        if total_len as u64 != declared_total_len || prefix.len() > total_len {
            return Err(MysqlExtraction::MalformedPacket);
        }
        if prefix[3] != self.next_sequence {
            return Err(MysqlExtraction::UnexpectedSequence);
        }

        self.next_sequence = self.next_sequence.wrapping_add(1);
        if payload_len == 0 {
            self.phase = MysqlResponsePhase::LocalInfileTerminal;
            Ok(MysqlClientPacketProgress::UploadComplete)
        } else {
            Ok(MysqlClientPacketProgress::Continue)
        }
    }

    /// Whether the lifecycle currently owns client file-data packets.
    #[must_use]
    pub fn expects_local_infile_data(&self) -> bool {
        self.phase == MysqlResponsePhase::LocalInfileUpload
    }

    /// Whether client packets still belong to this command's upload cycle.
    /// This remains true after the zero-length terminator so unexpected extra
    /// file packets cannot be misclassified as new commands.
    #[must_use]
    pub fn owns_local_infile_client_packets(&self) -> bool {
        matches!(
            self.phase,
            MysqlResponsePhase::LocalInfileUpload | MysqlResponsePhase::LocalInfileTerminal
        )
    }
}

fn response_kind(command: u8) -> MysqlResponseKind {
    match command {
        MYSQL_COM_STMT_PREPARE => MysqlResponseKind::StatementPrepare,
        MYSQL_COM_STMT_EXECUTE => MysqlResponseKind::BinaryResultset,
        MYSQL_COM_STMT_FETCH => MysqlResponseKind::StatementFetch,
        MYSQL_COM_QUIT | MYSQL_COM_STMT_SEND_LONG_DATA | MYSQL_COM_STMT_CLOSE => {
            MysqlResponseKind::NoResponse
        }
        _ => MysqlResponseKind::Command,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum MysqlResponseTransition {
    Continue(MysqlResponsePhase),
    MoreResults,
    Complete(ParsedMysqlResponse),
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
                if kind != MysqlResponseKind::Command {
                    return Err(MysqlExtraction::UnsupportedResponse);
                }
                return Ok(MysqlResponseTransition::Continue(
                    MysqlResponsePhase::LocalInfileUpload,
                ));
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
        MysqlResponsePhase::LocalInfileUpload => Err(MysqlExtraction::UnsupportedResponse),
        MysqlResponsePhase::LocalInfileTerminal => {
            if is_ok_packet(payload) || is_eof_packet(payload) {
                terminal_transition(packet, payload, config)
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

#[cfg(test)]
mod tests {
    use super::*;

    fn packet(sequence: u8, payload: &[u8]) -> Vec<u8> {
        let payload_len = u32::try_from(payload.len()).expect("test payload length fits u32");
        let length = payload_len.to_le_bytes();
        let mut packet = vec![length[0], length[1], length[2], sequence];
        packet.extend_from_slice(payload);
        packet
    }

    fn request(command: u8) -> Vec<u8> {
        packet(0, &[command])
    }

    fn column_definition() -> Vec<u8> {
        let mut payload = Vec::new();
        for value in [
            b"def".as_slice(),
            b"db",
            b"table",
            b"table",
            b"name",
            b"name",
        ] {
            payload.push(u8::try_from(value.len()).expect("test component length fits u8"));
            payload.extend_from_slice(value);
        }
        payload.extend_from_slice(&[0x0c, 0x21, 0x00, 0, 0, 0, 0, 0xfd, 0, 0, 0, 0, 0]);
        payload
    }

    #[test]
    fn parameter_only_prepare_completes_at_parameter_terminator() {
        let config = ProtocolExtractionConfig::default();
        let mut lifecycle =
            MysqlResponseLifecycle::from_request(&request(MYSQL_COM_STMT_PREPARE), &config)
                .expect("prepare request starts lifecycle");

        assert_eq!(
            lifecycle.observe_packet(
                &packet(1, &[0x00, 7, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0]),
                &config,
            ),
            Ok(MysqlResponseProgress::Continue)
        );
        assert_eq!(
            lifecycle.observe_packet(&packet(2, &column_definition()), &config),
            Ok(MysqlResponseProgress::Continue)
        );
        assert!(matches!(
            lifecycle.observe_packet(&packet(3, &[0xfe, 0, 0, 2, 0]), &config),
            Ok(MysqlResponseProgress::Complete(_))
        ));
    }

    #[test]
    fn cursor_execute_completes_at_metadata_cursor_terminator() {
        let config = ProtocolExtractionConfig::default();
        let mut lifecycle =
            MysqlResponseLifecycle::from_request(&request(MYSQL_COM_STMT_EXECUTE), &config)
                .expect("execute request starts lifecycle");

        assert_eq!(
            lifecycle.observe_packet(&packet(1, &[1]), &config),
            Ok(MysqlResponseProgress::Continue)
        );
        assert_eq!(
            lifecycle.observe_packet(&packet(2, &column_definition()), &config),
            Ok(MysqlResponseProgress::Continue)
        );
        assert!(matches!(
            lifecycle.observe_packet(&packet(3, &[0xfe, 0, 0, 0x42, 0]), &config),
            Ok(MysqlResponseProgress::Complete(_))
        ));
    }

    #[test]
    fn malformed_column_metadata_does_not_advance_sequence() {
        let config = ProtocolExtractionConfig::default();
        let mut lifecycle =
            MysqlResponseLifecycle::from_request(&request(MYSQL_COM_STMT_EXECUTE), &config)
                .expect("execute request starts lifecycle");
        assert_eq!(
            lifecycle.observe_packet(&packet(1, &[1]), &config),
            Ok(MysqlResponseProgress::Continue)
        );
        assert_eq!(
            lifecycle.observe_packet(&packet(2, b"not-column-metadata"), &config),
            Err(MysqlExtraction::MalformedPacket)
        );
        assert_eq!(
            lifecycle.observe_packet(&packet(2, &column_definition()), &config),
            Ok(MysqlResponseProgress::Continue)
        );
    }

    #[test]
    fn prepare_header_accepts_only_complete_supported_layouts() {
        let config = ProtocolExtractionConfig::default();
        for payload in [
            vec![0x00, 7, 0, 0, 0, 0, 0, 0, 0, 0],
            vec![0x00, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        ] {
            let mut lifecycle =
                MysqlResponseLifecycle::from_request(&request(MYSQL_COM_STMT_PREPARE), &config)
                    .expect("prepare request starts lifecycle");
            assert!(matches!(
                lifecycle.observe_packet(&packet(1, &payload), &config),
                Ok(MysqlResponseProgress::Complete(_))
            ));
        }

        for payload in [
            vec![0x00, 7, 0, 0, 0, 0, 0, 0, 0],
            vec![0x00, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            vec![0x00, 7, 0, 0, 0, 0, 0, 0, 0, 1],
            vec![0x00, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        ] {
            let mut lifecycle =
                MysqlResponseLifecycle::from_request(&request(MYSQL_COM_STMT_PREPARE), &config)
                    .expect("prepare request starts lifecycle");
            assert!(
                lifecycle
                    .observe_packet(&packet(1, &payload), &config)
                    .is_err()
            );
        }
    }

    #[test]
    fn truncated_protocol_41_ok_packet_is_rejected() {
        let result = parse_mysql_response(
            &packet(1, &[MYSQL_OK_PACKET, 0, 0]),
            &ProtocolExtractionConfig::default(),
        );

        assert_eq!(result, Err(MysqlExtraction::UnsupportedResponse));
    }
}
