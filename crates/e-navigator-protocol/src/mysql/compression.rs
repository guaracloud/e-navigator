use flate2::{Decompress, FlushDecompress, Status};

use super::{MysqlExtraction, packet_parts};

const MYSQL_PACKET_HEADER_BYTES: usize = 4;
const MYSQL_COMPRESSED_PACKET_HEADER_BYTES: usize = 7;
const MYSQL_PROTOCOL_VERSION_10: u8 = 10;
const MYSQL_CLIENT_COMPRESS: u32 = 1 << 5;
const MYSQL_CLIENT_PROTOCOL_41: u32 = 1 << 9;
const MYSQL_CLIENT_ZSTD_COMPRESSION_ALGORITHM: u32 = 1 << 26;
const MYSQL_HANDSHAKE_RESPONSE_FIXED_BYTES: usize = 32;

/// Compression negotiated for a MySQL connection after authentication.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MysqlCompressionAlgorithm {
    Disabled,
    Zlib,
    Zstd,
}

/// Capability subset retained from the server's protocol-v10 greeting.
///
/// Authentication data, server versions, usernames, and plugin values are
/// deliberately not retained.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MysqlServerGreeting {
    pub capabilities: u32,
}

/// Capability subset retained from a protocol-4.1 client response.
///
/// Authentication data, usernames, database names, and plugin values are
/// deliberately not retained.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MysqlClientHandshakeResponse {
    pub sequence_id: u8,
    pub capabilities: u32,
}

/// One decoded MySQL compressed-protocol payload. The payload is still a
/// bounded byte stream of ordinary MySQL packets and may contain a partial
/// packet or multiple packets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MysqlCompressedPacket {
    pub sequence_id: u8,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MysqlCompressionExtraction {
    PacketTooLong,
    MalformedPacket,
    MalformedHandshake,
    UnexpectedSequence,
    UnsupportedProtocol,
    DecompressionFailed,
    LengthMismatch,
}

/// Parses a complete protocol-v10 server greeting without retaining any
/// authentication or identity fields.
pub fn parse_mysql_server_greeting(
    bytes: &[u8],
    max_packet_bytes: usize,
) -> Result<MysqlServerGreeting, MysqlCompressionExtraction> {
    let (sequence_id, payload) = exact_packet_parts(bytes, max_packet_bytes)?;
    if sequence_id != 0 {
        return Err(MysqlCompressionExtraction::UnexpectedSequence);
    }
    if payload.first() != Some(&MYSQL_PROTOCOL_VERSION_10) {
        return Err(MysqlCompressionExtraction::UnsupportedProtocol);
    }

    let version_end = payload
        .get(1..)
        .and_then(|version| version.iter().position(|byte| *byte == 0))
        .map(|relative| relative + 1)
        .ok_or(MysqlCompressionExtraction::MalformedHandshake)?;
    if version_end == 1 {
        return Err(MysqlCompressionExtraction::MalformedHandshake);
    }

    let fixed_start = version_end
        .checked_add(1)
        .ok_or(MysqlCompressionExtraction::MalformedHandshake)?;
    // connection id (4), auth prefix (8), filler (1), lower capabilities
    // (2), charset (1), status (2), upper capabilities (2), auth length
    // (1), and reserved bytes (10).
    let fixed_end = fixed_start
        .checked_add(31)
        .ok_or(MysqlCompressionExtraction::MalformedHandshake)?;
    let fixed = payload
        .get(fixed_start..fixed_end)
        .ok_or(MysqlCompressionExtraction::MalformedHandshake)?;
    if fixed[12] != 0 || fixed[21..31].iter().any(|byte| *byte != 0) {
        return Err(MysqlCompressionExtraction::MalformedHandshake);
    }

    let lower = u16::from_le_bytes([fixed[13], fixed[14]]);
    let upper = u16::from_le_bytes([fixed[18], fixed[19]]);
    let capabilities = u32::from(lower) | (u32::from(upper) << 16);
    if capabilities & MYSQL_CLIENT_PROTOCOL_41 == 0 {
        return Err(MysqlCompressionExtraction::UnsupportedProtocol);
    }

    Ok(MysqlServerGreeting { capabilities })
}

/// Parses a complete protocol-4.1 HandshakeResponse packet. The exact
/// 32-byte SSLRequest prefix is rejected because it does not prove the final
/// client capability set or authentication transition.
pub fn parse_mysql_client_handshake_response(
    bytes: &[u8],
    max_packet_bytes: usize,
) -> Result<MysqlClientHandshakeResponse, MysqlCompressionExtraction> {
    let (sequence_id, payload) = exact_packet_parts(bytes, max_packet_bytes)?;
    if !matches!(sequence_id, 1 | 2) {
        return Err(MysqlCompressionExtraction::UnexpectedSequence);
    }
    if payload.len() <= MYSQL_HANDSHAKE_RESPONSE_FIXED_BYTES
        || payload[9..MYSQL_HANDSHAKE_RESPONSE_FIXED_BYTES]
            .iter()
            .any(|byte| *byte != 0)
        || !payload[MYSQL_HANDSHAKE_RESPONSE_FIXED_BYTES..].contains(&0)
    {
        return Err(MysqlCompressionExtraction::MalformedHandshake);
    }

    let capabilities = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);
    if capabilities & MYSQL_CLIENT_PROTOCOL_41 == 0 {
        return Err(MysqlCompressionExtraction::UnsupportedProtocol);
    }
    Ok(MysqlClientHandshakeResponse {
        sequence_id,
        capabilities,
    })
}

/// Chooses the mutually advertised compression algorithm. The classic zlib
/// capability wins when both zlib and zstd were advertised, matching the
/// MySQL protocol's negotiation rule.
#[must_use]
pub fn negotiate_mysql_compression(
    server: MysqlServerGreeting,
    client: MysqlClientHandshakeResponse,
) -> MysqlCompressionAlgorithm {
    let mutual = server.capabilities & client.capabilities;
    if mutual & MYSQL_CLIENT_COMPRESS != 0 {
        MysqlCompressionAlgorithm::Zlib
    } else if mutual & MYSQL_CLIENT_ZSTD_COMPRESSION_ALGORITHM != 0 {
        MysqlCompressionAlgorithm::Zstd
    } else {
        MysqlCompressionAlgorithm::Disabled
    }
}

/// Decodes exactly one complete compressed-protocol frame.
///
/// Both the wire payload and the declared decoded payload are bounded by
/// `max_payload_bytes`. A zero decoded length means the frame payload was sent
/// uncompressed. Zlib output must consume the entire input and match the exact
/// three-byte decoded length; concatenated streams and decompression bombs are
/// rejected.
pub fn decode_mysql_compressed_packet(
    bytes: &[u8],
    max_payload_bytes: usize,
) -> Result<MysqlCompressedPacket, MysqlCompressionExtraction> {
    if bytes.len() < MYSQL_COMPRESSED_PACKET_HEADER_BYTES {
        return Err(MysqlCompressionExtraction::MalformedPacket);
    }
    let compressed_len = read_u24_le(&bytes[..3]);
    let total_len = compressed_len
        .checked_add(MYSQL_COMPRESSED_PACKET_HEADER_BYTES)
        .ok_or(MysqlCompressionExtraction::MalformedPacket)?;
    if total_len != bytes.len() || compressed_len == 0 {
        return Err(MysqlCompressionExtraction::MalformedPacket);
    }
    if compressed_len > max_payload_bytes {
        return Err(MysqlCompressionExtraction::PacketTooLong);
    }

    let sequence_id = bytes[3];
    let uncompressed_len = read_u24_le(&bytes[4..7]);
    let compressed = &bytes[MYSQL_COMPRESSED_PACKET_HEADER_BYTES..];
    if uncompressed_len == 0 {
        return Ok(MysqlCompressedPacket {
            sequence_id,
            payload: compressed.to_vec(),
        });
    }
    if uncompressed_len > max_payload_bytes {
        return Err(MysqlCompressionExtraction::PacketTooLong);
    }

    let output_capacity = uncompressed_len
        .checked_add(1)
        .ok_or(MysqlCompressionExtraction::PacketTooLong)?;
    let mut payload = Vec::with_capacity(output_capacity);
    let mut decompressor = Decompress::new(true);
    let status = decompressor
        .decompress_vec(compressed, &mut payload, FlushDecompress::Finish)
        .map_err(|_| MysqlCompressionExtraction::DecompressionFailed)?;
    if status != Status::StreamEnd
        || decompressor.total_in() != compressed.len() as u64
        || payload.len() != uncompressed_len
    {
        return Err(MysqlCompressionExtraction::LengthMismatch);
    }

    Ok(MysqlCompressedPacket {
        sequence_id,
        payload,
    })
}

fn exact_packet_parts(
    bytes: &[u8],
    max_packet_bytes: usize,
) -> Result<(u8, &[u8]), MysqlCompressionExtraction> {
    let (sequence_id, payload) =
        packet_parts(bytes, max_packet_bytes).map_err(|error| match error {
            MysqlExtraction::PacketTooLong => MysqlCompressionExtraction::PacketTooLong,
            _ => MysqlCompressionExtraction::MalformedPacket,
        })?;
    if payload.len().saturating_add(MYSQL_PACKET_HEADER_BYTES) != bytes.len() {
        return Err(MysqlCompressionExtraction::MalformedPacket);
    }
    Ok((sequence_id, payload))
}

fn read_u24_le(bytes: &[u8]) -> usize {
    usize::from(bytes[0]) | (usize::from(bytes[1]) << 8) | (usize::from(bytes[2]) << 16)
}
