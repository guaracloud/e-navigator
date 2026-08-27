use super::*;

/// Per-connection MySQL handshake, authentication, and compression state.
#[derive(Debug)]
pub(super) struct MysqlConnectionState {
    phase: MysqlConnectionPhase,
    compression: Option<MysqlCompressedTransport>,
    limits: StreamDecodeLimits,
}

impl MysqlConnectionState {
    pub(super) fn new(limits: StreamDecodeLimits) -> Self {
        Self {
            phase: MysqlConnectionPhase::Unknown,
            compression: None,
            limits,
        }
    }

    pub(super) fn is_opaque(&self) -> bool {
        self.phase == MysqlConnectionPhase::Opaque
    }

    pub(super) fn is_compressed(&self) -> bool {
        self.compression.is_some()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MysqlConnectionPhase {
    Unknown,
    AwaitClientHandshake {
        server: MysqlServerGreeting,
    },
    Authenticating {
        algorithm: MysqlCompressionAlgorithm,
        next_sequence: u8,
        server_verified: bool,
    },
    Command,
    Opaque,
}

#[derive(Debug)]
struct MysqlCompressedTransport {
    request_decoder: ProtocolStreamDecoder,
    response_decoder: ProtocolStreamDecoder,
    request_frame_started_unix_nanos: Option<u64>,
    response_frame_started_unix_nanos: Option<u64>,
    next_sequence: u8,
}

impl MysqlCompressedTransport {
    fn new(limits: StreamDecodeLimits) -> Self {
        Self {
            request_decoder: ProtocolStreamDecoder::new(
                StreamProtocol::Mysql,
                StreamDirection::Request,
                limits,
            ),
            response_decoder: ProtocolStreamDecoder::new(
                StreamProtocol::Mysql,
                StreamDirection::Response,
                limits,
            ),
            request_frame_started_unix_nanos: None,
            response_frame_started_unix_nanos: None,
            next_sequence: 0,
        }
    }
}

/// Decodes the negotiated MySQL compression layer into the existing bounded
/// ordinary-packet reassembler. Any missing bytes, decompression mismatch, or
/// compressed sequence ambiguity makes the connection opaque; a later frame
/// is never guessed back into alignment.
pub(super) fn decode_mysql_compressed_transport_frames(
    stream: &mut ConnectionStream,
    frames: &[StreamFrame],
    is_request_direction: bool,
    input_started_unix_nanos: u64,
    decoded_frames: &mut Vec<StreamFrame>,
    decoded_frame_started_unix_nanos: &mut Option<u64>,
    counters: &mut ProtocolRegistryCounters,
) -> bool {
    for frame in frames {
        let bytes = match frame {
            StreamFrame::Complete(bytes) => bytes,
            StreamFrame::Truncated { .. } => {
                counters.truncated_frames += 1;
                mark_mysql_transport_opaque(stream, counters);
                return false;
            }
            StreamFrame::ProtocolSwitch { .. } => {
                counters.unparsed_frames += 1;
                mark_mysql_transport_opaque(stream, counters);
                return false;
            }
        };

        let max_payload_bytes = stream
            .mysql
            .as_ref()
            .map_or(0, |mysql| mysql.limits.max_buffered_bytes);
        let packet = match decode_mysql_compressed_packet(bytes, max_payload_bytes) {
            Ok(packet) => packet,
            Err(_) => {
                mark_mysql_transport_opaque(stream, counters);
                return false;
            }
        };

        let exchange_idle = stream.in_flight.is_empty()
            && stream.mysql.as_ref().is_some_and(|mysql| {
                mysql.compression.as_ref().is_some_and(|transport| {
                    transport.request_decoder.buffered_bytes() == 0
                        && transport.response_decoder.buffered_bytes() == 0
                })
            });
        let Some(transport) = stream
            .mysql
            .as_mut()
            .and_then(|mysql| mysql.compression.as_mut())
        else {
            mark_mysql_transport_opaque(stream, counters);
            return false;
        };
        let reset_for_new_command =
            is_request_direction && exchange_idle && packet.sequence_id == 0;
        if packet.sequence_id != transport.next_sequence && !reset_for_new_command {
            mark_mysql_transport_opaque(stream, counters);
            return false;
        }
        transport.next_sequence = packet.sequence_id.wrapping_add(1);
        let (decoder, pending_frame_started) = if is_request_direction {
            (
                &mut transport.request_decoder,
                &mut transport.request_frame_started_unix_nanos,
            )
        } else {
            (
                &mut transport.response_decoder,
                &mut transport.response_frame_started_unix_nanos,
            )
        };
        let frame_started_unix_nanos = pending_frame_started.unwrap_or(input_started_unix_nanos);
        let complete_frames_before = decoder.stats().complete_frames;
        let decoded_frames_before = decoded_frames.len();
        decoder.push_chunk(&packet.payload, packet.payload.len() as u64, decoded_frames);
        if decoded_frames.len() > decoded_frames_before
            && decoded_frame_started_unix_nanos.is_none()
        {
            *decoded_frame_started_unix_nanos = Some(frame_started_unix_nanos);
        }
        *pending_frame_started = if decoder.buffered_bytes() == 0 {
            None
        } else if decoder.stats().complete_frames > complete_frames_before {
            Some(input_started_unix_nanos)
        } else {
            Some(frame_started_unix_nanos)
        };
        counters.mysql_compressed_packets += 1;
    }
    true
}

fn mark_mysql_transport_opaque(
    stream: &mut ConnectionStream,
    counters: &mut ProtocolRegistryCounters,
) {
    mark_mysql_connection_opaque(stream);
    counters.mysql_compression_failures += 1;
}

fn mark_mysql_handshake_opaque(
    stream: &mut ConnectionStream,
    counters: &mut ProtocolRegistryCounters,
) {
    mark_mysql_connection_opaque(stream);
    counters.mysql_handshake_failures += 1;
}

fn mark_mysql_connection_opaque(stream: &mut ConnectionStream) {
    if let Some(mysql) = stream.mysql.as_mut() {
        mysql.phase = MysqlConnectionPhase::Opaque;
        mysql.compression = None;
    }
}

pub(super) fn handle_mysql_connection_request_frame(
    stream: &mut ConnectionStream,
    frame: &StreamFrame,
    extraction: &ProtocolExtractionConfig,
    counters: &mut ProtocolRegistryCounters,
) -> bool {
    let Some(phase) = stream.mysql.as_ref().map(|mysql| mysql.phase) else {
        return false;
    };
    match phase {
        MysqlConnectionPhase::Command => false,
        MysqlConnectionPhase::Opaque => true,
        MysqlConnectionPhase::Unknown => {
            let StreamFrame::Complete(bytes) = frame else {
                if matches!(frame, StreamFrame::Truncated { .. }) {
                    if let Some(mysql) = stream.mysql.as_mut() {
                        mysql.phase = MysqlConnectionPhase::Command;
                    }
                    return false;
                }
                mark_mysql_handshake_opaque(stream, counters);
                return true;
            };
            match parse_mysql_client_handshake_response(bytes, extraction.max_header_bytes) {
                Ok(client) => {
                    begin_mysql_authentication(stream, client, None, counters);
                    true
                }
                Err(_) => {
                    if parse_mysql_packet_metadata(bytes, extraction.max_header_bytes)
                        .is_ok_and(|metadata| metadata.sequence_id == 0)
                        && let Some(mysql) = stream.mysql.as_mut()
                    {
                        mysql.phase = MysqlConnectionPhase::Command;
                    }
                    false
                }
            }
        }
        MysqlConnectionPhase::AwaitClientHandshake { server } => {
            let StreamFrame::Complete(bytes) = frame else {
                mark_mysql_handshake_opaque(stream, counters);
                return true;
            };
            match parse_mysql_client_handshake_response(bytes, extraction.max_header_bytes) {
                Ok(client) => begin_mysql_authentication(stream, client, Some(server), counters),
                Err(_) => mark_mysql_handshake_opaque(stream, counters),
            }
            true
        }
        MysqlConnectionPhase::Authenticating { next_sequence, .. } => {
            let StreamFrame::Complete(bytes) = frame else {
                mark_mysql_handshake_opaque(stream, counters);
                return true;
            };
            let Ok(metadata) = parse_mysql_packet_metadata(bytes, extraction.max_header_bytes)
            else {
                mark_mysql_handshake_opaque(stream, counters);
                return true;
            };
            if metadata.sequence_id != next_sequence {
                mark_mysql_handshake_opaque(stream, counters);
                return true;
            }
            if let Some(mysql) = stream.mysql.as_mut()
                && let MysqlConnectionPhase::Authenticating { next_sequence, .. } = &mut mysql.phase
            {
                *next_sequence = next_sequence.wrapping_add(1);
            }
            counters.mysql_auth_packets += 1;
            true
        }
    }
}

pub(super) fn handle_mysql_connection_response_frame(
    stream: &mut ConnectionStream,
    frame: &StreamFrame,
    extraction: &ProtocolExtractionConfig,
    counters: &mut ProtocolRegistryCounters,
) -> bool {
    let Some(phase) = stream.mysql.as_ref().map(|mysql| mysql.phase) else {
        return false;
    };
    match phase {
        MysqlConnectionPhase::Command => false,
        MysqlConnectionPhase::Opaque => true,
        MysqlConnectionPhase::Unknown => {
            let StreamFrame::Complete(bytes) = frame else {
                return false;
            };
            let Ok(server) = parse_mysql_server_greeting(bytes, extraction.max_header_bytes) else {
                return false;
            };
            if let Some(mysql) = stream.mysql.as_mut() {
                mysql.phase = MysqlConnectionPhase::AwaitClientHandshake { server };
            }
            counters.mysql_server_greetings += 1;
            true
        }
        MysqlConnectionPhase::AwaitClientHandshake { .. } => {
            mark_mysql_handshake_opaque(stream, counters);
            true
        }
        MysqlConnectionPhase::Authenticating {
            next_sequence,
            algorithm,
            server_verified,
        } => {
            let StreamFrame::Complete(bytes) = frame else {
                mark_mysql_handshake_opaque(stream, counters);
                return true;
            };
            let Ok(metadata) = parse_mysql_packet_metadata(bytes, extraction.max_header_bytes)
            else {
                mark_mysql_handshake_opaque(stream, counters);
                return true;
            };
            if metadata.sequence_id != next_sequence {
                mark_mysql_handshake_opaque(stream, counters);
                return true;
            }
            counters.mysql_auth_packets += 1;
            match metadata.first_payload_byte {
                Some(0x00)
                    if parse_mysql_response(bytes, extraction)
                        .is_ok_and(|response| response.error_type.is_none()) =>
                {
                    activate_mysql_compression(stream, algorithm, server_verified, counters);
                }
                Some(0xff)
                    if parse_mysql_response(bytes, extraction)
                        .is_ok_and(|response| response.error_type.is_some()) =>
                {
                    mark_mysql_connection_opaque(stream);
                }
                Some(0x01 | 0xfe) => {
                    if let Some(mysql) = stream.mysql.as_mut()
                        && let MysqlConnectionPhase::Authenticating { next_sequence, .. } =
                            &mut mysql.phase
                    {
                        *next_sequence = next_sequence.wrapping_add(1);
                    }
                }
                _ => mark_mysql_handshake_opaque(stream, counters),
            }
            true
        }
    }
}

fn begin_mysql_authentication(
    stream: &mut ConnectionStream,
    client: MysqlClientHandshakeResponse,
    server: Option<MysqlServerGreeting>,
    counters: &mut ProtocolRegistryCounters,
) {
    let (algorithm, server_verified) = server.map_or_else(
        || (mysql_requested_compression(client), false),
        |server| (negotiate_mysql_compression(server, client), true),
    );
    if let Some(mysql) = stream.mysql.as_mut() {
        mysql.phase = MysqlConnectionPhase::Authenticating {
            algorithm,
            next_sequence: client.sequence_id.wrapping_add(1),
            server_verified,
        };
    }
    counters.mysql_client_handshakes += 1;
}

fn activate_mysql_compression(
    stream: &mut ConnectionStream,
    algorithm: MysqlCompressionAlgorithm,
    server_verified: bool,
    counters: &mut ProtocolRegistryCounters,
) {
    let Some(mysql) = stream.mysql.as_mut() else {
        return;
    };
    if !server_verified && algorithm != MysqlCompressionAlgorithm::Disabled {
        mysql.phase = MysqlConnectionPhase::Opaque;
        counters.mysql_compression_unverified_rejections += 1;
        return;
    }
    match algorithm {
        MysqlCompressionAlgorithm::Disabled => {
            mysql.phase = MysqlConnectionPhase::Command;
        }
        MysqlCompressionAlgorithm::Zlib => {
            mysql.phase = MysqlConnectionPhase::Command;
            mysql.compression = Some(MysqlCompressedTransport::new(mysql.limits));
            stream
                .request_decoder
                .switch_protocol(StreamProtocol::MysqlCompressed);
            stream
                .response_decoder
                .switch_protocol(StreamProtocol::MysqlCompressed);
            stream.request_segments = None;
            stream.response_segments = None;
            stream.request_frame_started_unix_nanos = None;
            stream.response_frame_started_unix_nanos = None;
            counters.mysql_compression_zlib_connections += 1;
        }
        MysqlCompressionAlgorithm::Zstd => {
            mysql.phase = MysqlConnectionPhase::Opaque;
            counters.mysql_compression_zstd_rejections += 1;
        }
    }
}
