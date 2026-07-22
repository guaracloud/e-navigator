//! Bounded WebSocket upgrade and frame-metadata parsing.
//!
//! The parser validates RFC 6455 framing but never copies or exports frame
//! payload bytes. It is deliberately extension-free: an upgrade that
//! negotiates extensions is rejected because RSV semantics would otherwise
//! be ambiguous without connection-specific extension state.

use base64::{Engine as _, engine::general_purpose::STANDARD};

/// Maximum encoded handshake value accepted by the stateless parser.
pub const MAX_WEBSOCKET_HANDSHAKE_VALUE_BYTES: usize = 256;

/// Logical direction used to enforce RFC 6455 masking rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WebSocketDirection {
    ClientToServer,
    ServerToClient,
}

/// Valid application or control opcode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WebSocketOpcode {
    Continuation,
    Text,
    Binary,
    Close,
    Ping,
    Pong,
}

impl WebSocketOpcode {
    pub fn name(self) -> &'static str {
        match self {
            Self::Continuation => "continuation",
            Self::Text => "text",
            Self::Binary => "binary",
            Self::Close => "close",
            Self::Ping => "ping",
            Self::Pong => "pong",
        }
    }

    fn from_wire(value: u8) -> Option<Self> {
        match value {
            0x0 => Some(Self::Continuation),
            0x1 => Some(Self::Text),
            0x2 => Some(Self::Binary),
            0x8 => Some(Self::Close),
            0x9 => Some(Self::Ping),
            0xa => Some(Self::Pong),
            _ => None,
        }
    }

    fn is_control(self) -> bool {
        matches!(self, Self::Close | Self::Ping | Self::Pong)
    }
}

/// Metadata retained for one frame. Payload bytes are intentionally absent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WebSocketFrameMetadata {
    pub fin: bool,
    pub opcode: WebSocketOpcode,
    pub masked: bool,
    pub payload_len: u64,
    pub header_len: usize,
    pub capture_complete: bool,
}

/// Result of determining a frame boundary from a bounded prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WebSocketFrameBoundary {
    NeedMoreBytes,
    Frame { total_len: usize },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WebSocketExtraction {
    HeadersTooLong,
    MalformedHandshake,
    UnsupportedExtensions,
    NeedMoreBytes,
    InvalidReservedBits,
    InvalidOpcode,
    InvalidMasking,
    InvalidLengthEncoding,
    FragmentedControlFrame,
    ControlFrameTooLarge,
    FrameTooLarge,
    TruncatedFrame,
}

/// Detects and validates an extension-free HTTP/1 WebSocket upgrade request.
/// Ordinary HTTP requests return `Ok(false)`.
pub fn is_websocket_upgrade_request(
    bytes: &[u8],
    max_header_bytes: usize,
) -> Result<bool, WebSocketExtraction> {
    let headers = parse_headers(bytes, max_header_bytes)?;
    let mut request_fields = ascii_fields(headers.first_line);
    let request_is_get = request_fields.next() == Some(b"GET".as_slice())
        && request_fields.next().is_some()
        && request_fields
            .next()
            .is_some_and(|version| version == b"HTTP/1.1")
        && request_fields.next().is_none();
    let upgrade = headers.value(b"upgrade");
    let connection = headers.value(b"connection");
    let key = headers.value(b"sec-websocket-key");
    let version = headers.value(b"sec-websocket-version");
    let extensions = headers.value(b"sec-websocket-extensions");
    let mentions_websocket = upgrade.is_some_and(|value| token_contains(value, b"websocket"))
        || key.is_some()
        || version.is_some();
    if !mentions_websocket {
        return Ok(false);
    }
    if extensions.is_some() {
        return Err(WebSocketExtraction::UnsupportedExtensions);
    }
    if !request_is_get
        || !upgrade.is_some_and(|value| token_contains(value, b"websocket"))
        || !connection.is_some_and(|value| token_contains(value, b"upgrade"))
        || version.map(trim_ascii) != Some(b"13".as_slice())
        || !key.is_some_and(valid_client_key)
    {
        return Err(WebSocketExtraction::MalformedHandshake);
    }
    Ok(true)
}

/// Detects and validates an extension-free HTTP/1 101 WebSocket response.
/// Ordinary HTTP responses return `Ok(false)`.
pub fn is_websocket_upgrade_response(
    bytes: &[u8],
    max_header_bytes: usize,
) -> Result<bool, WebSocketExtraction> {
    let headers = parse_headers(bytes, max_header_bytes)?;
    let mut response_fields = ascii_fields(headers.first_line);
    let is_switching = response_fields
        .next()
        .is_some_and(|version| version.starts_with(b"HTTP/1."))
        && response_fields.next() == Some(b"101".as_slice());
    let upgrade = headers.value(b"upgrade");
    let connection = headers.value(b"connection");
    let accept = headers.value(b"sec-websocket-accept");
    let extensions = headers.value(b"sec-websocket-extensions");
    let mentions_websocket = is_switching
        || upgrade.is_some_and(|value| token_contains(value, b"websocket"))
        || accept.is_some();
    if !mentions_websocket {
        return Ok(false);
    }
    if extensions.is_some() {
        return Err(WebSocketExtraction::UnsupportedExtensions);
    }
    if !is_switching
        || !upgrade.is_some_and(|value| token_contains(value, b"websocket"))
        || !connection.is_some_and(|value| token_contains(value, b"upgrade"))
        || !accept.is_some_and(valid_server_accept)
    {
        return Err(WebSocketExtraction::MalformedHandshake);
    }
    Ok(true)
}

/// Determines the exact encoded frame length while enforcing direction,
/// minimal-length, control-frame, and hard-size rules.
pub fn websocket_frame_boundary(
    bytes: &[u8],
    direction: WebSocketDirection,
    max_frame_bytes: usize,
) -> Result<WebSocketFrameBoundary, WebSocketExtraction> {
    let Some(header) = parse_frame_header(bytes, direction)? else {
        return Ok(WebSocketFrameBoundary::NeedMoreBytes);
    };
    let payload_len =
        usize::try_from(header.payload_len).map_err(|_| WebSocketExtraction::FrameTooLarge)?;
    let total_len = header
        .header_len
        .checked_add(payload_len)
        .ok_or(WebSocketExtraction::FrameTooLarge)?;
    if total_len > max_frame_bytes {
        return Err(WebSocketExtraction::FrameTooLarge);
    }
    Ok(WebSocketFrameBoundary::Frame { total_len })
}

/// Parses metadata from a complete frame or from a known-truncated frame
/// prefix. No payload bytes are returned.
pub fn parse_websocket_frame(
    bytes: &[u8],
    direction: WebSocketDirection,
    max_frame_bytes: usize,
    capture_complete: bool,
) -> Result<WebSocketFrameMetadata, WebSocketExtraction> {
    let Some(header) = parse_frame_header(bytes, direction)? else {
        return Err(WebSocketExtraction::NeedMoreBytes);
    };
    let total_len = header
        .header_len
        .checked_add(
            usize::try_from(header.payload_len).map_err(|_| WebSocketExtraction::FrameTooLarge)?,
        )
        .ok_or(WebSocketExtraction::FrameTooLarge)?;
    if total_len > max_frame_bytes {
        return Err(WebSocketExtraction::FrameTooLarge);
    }
    if capture_complete && bytes.len() < total_len {
        return Err(WebSocketExtraction::TruncatedFrame);
    }
    Ok(WebSocketFrameMetadata {
        fin: header.fin,
        opcode: header.opcode,
        masked: header.masked,
        payload_len: header.payload_len,
        header_len: header.header_len,
        capture_complete,
    })
}

#[derive(Debug, Clone, Copy)]
struct FrameHeader {
    fin: bool,
    opcode: WebSocketOpcode,
    masked: bool,
    payload_len: u64,
    header_len: usize,
}

fn parse_frame_header(
    bytes: &[u8],
    direction: WebSocketDirection,
) -> Result<Option<FrameHeader>, WebSocketExtraction> {
    if bytes.len() < 2 {
        return Ok(None);
    }
    let fin = bytes[0] & 0x80 != 0;
    if bytes[0] & 0x70 != 0 {
        return Err(WebSocketExtraction::InvalidReservedBits);
    }
    let opcode =
        WebSocketOpcode::from_wire(bytes[0] & 0x0f).ok_or(WebSocketExtraction::InvalidOpcode)?;
    let masked = bytes[1] & 0x80 != 0;
    let expected_mask = direction == WebSocketDirection::ClientToServer;
    if masked != expected_mask {
        return Err(WebSocketExtraction::InvalidMasking);
    }

    let length_tag = bytes[1] & 0x7f;
    let (payload_len, extension_len) = match length_tag {
        0..=125 => (u64::from(length_tag), 0),
        126 => {
            if bytes.len() < 4 {
                return Ok(None);
            }
            let value = u64::from(u16::from_be_bytes([bytes[2], bytes[3]]));
            if value < 126 {
                return Err(WebSocketExtraction::InvalidLengthEncoding);
            }
            (value, 2)
        }
        127 => {
            if bytes.len() < 10 {
                return Ok(None);
            }
            if bytes[2] & 0x80 != 0 {
                return Err(WebSocketExtraction::InvalidLengthEncoding);
            }
            let value = u64::from_be_bytes([
                bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7], bytes[8], bytes[9],
            ]);
            if value < 65_536 {
                return Err(WebSocketExtraction::InvalidLengthEncoding);
            }
            (value, 8)
        }
        _ => return Err(WebSocketExtraction::InvalidLengthEncoding),
    };
    if opcode.is_control() && !fin {
        return Err(WebSocketExtraction::FragmentedControlFrame);
    }
    if opcode.is_control() && payload_len > 125 {
        return Err(WebSocketExtraction::ControlFrameTooLarge);
    }
    let header_len = 2 + extension_len + usize::from(masked) * 4;
    if bytes.len() < header_len {
        return Ok(None);
    }
    Ok(Some(FrameHeader {
        fin,
        opcode,
        masked,
        payload_len,
        header_len,
    }))
}

#[derive(Debug)]
struct Headers<'a> {
    first_line: &'a [u8],
    lines: &'a [u8],
}

impl<'a> Headers<'a> {
    fn value(&self, name: &[u8]) -> Option<&'a [u8]> {
        self.lines.split(|byte| *byte == b'\n').find_map(|line| {
            let line = line.strip_suffix(b"\r").unwrap_or(line);
            let colon = line.iter().position(|byte| *byte == b':')?;
            header_name_eq(&line[..colon], name).then(|| trim_ascii(&line[colon + 1..]))
        })
    }
}

fn parse_headers(
    bytes: &[u8],
    max_header_bytes: usize,
) -> Result<Headers<'_>, WebSocketExtraction> {
    let scan_len = bytes.len().min(max_header_bytes.saturating_add(1));
    let Some(end) = bytes[..scan_len]
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
    else {
        return Err(WebSocketExtraction::HeadersTooLong);
    };
    if end + 4 > max_header_bytes {
        return Err(WebSocketExtraction::HeadersTooLong);
    }
    let block = &bytes[..end];
    let first_end = block
        .windows(2)
        .position(|window| window == b"\r\n")
        .unwrap_or(block.len());
    let lines = if first_end == block.len() {
        &block[block.len()..]
    } else {
        &block[first_end + 2..]
    };
    Ok(Headers {
        first_line: &block[..first_end],
        lines,
    })
}

fn valid_client_key(value: &[u8]) -> bool {
    valid_base64_value(value, 16)
}

fn valid_server_accept(value: &[u8]) -> bool {
    valid_base64_value(value, 20)
}

fn valid_base64_value(value: &[u8], expected_len: usize) -> bool {
    let value = trim_ascii(value);
    if value.is_empty() || value.len() > MAX_WEBSOCKET_HANDSHAKE_VALUE_BYTES {
        return false;
    }
    STANDARD
        .decode(value)
        .is_ok_and(|decoded| decoded.len() == expected_len)
}

fn token_contains(value: &[u8], needle: &[u8]) -> bool {
    value
        .split(|byte| *byte == b',')
        .map(trim_ascii)
        .any(|token| token.eq_ignore_ascii_case(needle))
}

fn header_name_eq(value: &[u8], expected: &[u8]) -> bool {
    value.eq_ignore_ascii_case(expected)
}

fn ascii_fields(value: &[u8]) -> impl Iterator<Item = &[u8]> {
    value
        .split(u8::is_ascii_whitespace)
        .filter(|field| !field.is_empty())
}

fn trim_ascii(mut value: &[u8]) -> &[u8] {
    while value.first().is_some_and(u8::is_ascii_whitespace) {
        value = &value[1..];
    }
    while value.last().is_some_and(u8::is_ascii_whitespace) {
        value = &value[..value.len() - 1];
    }
    value
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    const REQUEST: &[u8] = b"GET /chat HTTP/1.1\r\nHost: example.test\r\nUpgrade: websocket\r\nConnection: keep-alive, Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
    const RESPONSE: &[u8] = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n";

    #[test]
    fn validates_extension_free_upgrade_pair() {
        assert_eq!(is_websocket_upgrade_request(REQUEST, 4096), Ok(true));
        assert_eq!(is_websocket_upgrade_response(RESPONSE, 4096), Ok(true));
        assert_eq!(
            is_websocket_upgrade_request(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n", 4096),
            Ok(false)
        );
    }

    #[test]
    fn rejects_extension_negotiation() {
        let request = b"GET / HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Extensions: permessage-deflate\r\n\r\n";
        assert_eq!(
            is_websocket_upgrade_request(request, 4096),
            Err(WebSocketExtraction::UnsupportedExtensions)
        );
    }

    #[test]
    fn parses_metadata_without_returning_payload() {
        let frame = [0x81, 0x85, 1, 2, 3, 4, 9, 8, 7, 6, 5];
        assert_eq!(
            websocket_frame_boundary(&frame, WebSocketDirection::ClientToServer, 1024),
            Ok(WebSocketFrameBoundary::Frame { total_len: 11 })
        );
        let parsed = parse_websocket_frame(&frame, WebSocketDirection::ClientToServer, 1024, true)
            .expect("valid frame");
        assert_eq!(parsed.opcode, WebSocketOpcode::Text);
        assert_eq!(parsed.payload_len, 5);
        assert_eq!(parsed.header_len, 6);
        assert!(parsed.capture_complete);
    }

    #[test]
    fn accepts_metadata_from_a_known_truncated_payload() {
        let prefix = [0x82, 126, 0, 200];
        let parsed =
            parse_websocket_frame(&prefix, WebSocketDirection::ServerToClient, 4096, false)
                .expect("header is complete");
        assert_eq!(parsed.payload_len, 200);
        assert!(!parsed.capture_complete);
    }

    #[test]
    fn rejects_nonminimal_and_invalid_control_frames() {
        assert_eq!(
            websocket_frame_boundary(
                &[0x81, 126, 0, 125],
                WebSocketDirection::ServerToClient,
                1024,
            ),
            Err(WebSocketExtraction::InvalidLengthEncoding)
        );
        assert_eq!(
            websocket_frame_boundary(&[0x09, 0], WebSocketDirection::ServerToClient, 1024,),
            Err(WebSocketExtraction::FragmentedControlFrame)
        );
    }

    proptest! {
        #[test]
        fn arbitrary_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
            let _ = websocket_frame_boundary(
                &bytes,
                WebSocketDirection::ClientToServer,
                4096,
            );
            let _ = parse_websocket_frame(
                &bytes,
                WebSocketDirection::ServerToClient,
                4096,
                false,
            );
            let _ = is_websocket_upgrade_request(&bytes, 1024);
            let _ = is_websocket_upgrade_response(&bytes, 1024);
        }

        #[test]
        fn valid_small_server_frames_round_trip(payload in proptest::collection::vec(any::<u8>(), 0..126)) {
            let mut frame = vec![0x82, payload.len() as u8];
            frame.extend_from_slice(&payload);
            let boundary = websocket_frame_boundary(
                &frame,
                WebSocketDirection::ServerToClient,
                1024,
            );
            prop_assert_eq!(boundary, Ok(WebSocketFrameBoundary::Frame { total_len: frame.len() }));
        }
    }
}
