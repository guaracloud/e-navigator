//! Bounded HTTP/2 frame and HPACK header-block parsing.
//!
//! Decodes HTTP/2 frame headers and HPACK header blocks captured from
//! socket payloads. Only a fixed whitelist of low-cardinality header
//! semantics is exported (method, path, authority, status, gRPC status);
//! every other header is decoded for HPACK state integrity and discarded.
//! The decoder is connection-scoped: a decode failure poisons the decoder
//! because the dynamic table can no longer be trusted.

use std::collections::VecDeque;

use e_navigator_signals::{ProtocolKind, TraceAttribute};

use crate::{
    ProtocolExtractionConfig,
    trace_context::{TraceContext, parse_traceparent, validate_tracestate},
};

pub const HTTP2_CONNECTION_PREFACE: &[u8; 24] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
pub const HTTP2_FRAME_HEADER_BYTES: usize = 9;
pub const HTTP2_FRAME_TYPE_DATA: u8 = 0x0;
pub const HTTP2_FRAME_TYPE_HEADERS: u8 = 0x1;
pub const HTTP2_FRAME_TYPE_RST_STREAM: u8 = 0x3;
pub const HTTP2_FRAME_TYPE_SETTINGS: u8 = 0x4;
pub const HTTP2_FRAME_TYPE_GOAWAY: u8 = 0x7;
pub const HTTP2_FRAME_TYPE_WINDOW_UPDATE: u8 = 0x8;
pub const HTTP2_FRAME_TYPE_CONTINUATION: u8 = 0x9;
pub const HTTP2_FLAG_END_STREAM: u8 = 0x1;
pub const HTTP2_FLAG_END_HEADERS: u8 = 0x4;
pub const HTTP2_FLAG_PADDED: u8 = 0x8;
pub const HTTP2_FLAG_PRIORITY: u8 = 0x20;

const MAX_HPACK_HEADERS_PER_BLOCK: usize = 64;
const MAX_HPACK_NAME_BYTES: usize = 128;
const MAX_HPACK_VALUE_BYTES: usize = 1024;
const MAX_HPACK_DYNAMIC_TABLE_BYTES: usize = 64 * 1024;
const DEFAULT_HPACK_DYNAMIC_TABLE_BYTES: usize = 4096;
const HPACK_ENTRY_OVERHEAD_BYTES: usize = 32;
const MAX_HPACK_INT_CONTINUATION_BYTES: usize = 5;
const HUFFMAN_EOS_SYMBOL: u16 = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Http2FrameHeader {
    pub length: usize,
    pub frame_type: u8,
    pub flags: u8,
    pub stream_id: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Http2Extraction {
    MalformedFrame,
    HeadersTooLong,
    InvalidHpack,
    InvalidHuffman,
    DecoderPoisoned,
    UnsupportedFrame,
    ContinuationExpected,
    UnexpectedContinuation,
    ContinuationStreamMismatch,
    InvalidStatusCode,
}

/// Parses a 9-byte HTTP/2 frame header.
pub fn parse_http2_frame_header(bytes: &[u8]) -> Result<Http2FrameHeader, Http2Extraction> {
    if bytes.len() < HTTP2_FRAME_HEADER_BYTES {
        return Err(Http2Extraction::MalformedFrame);
    }
    let length =
        (usize::from(bytes[0]) << 16) | (usize::from(bytes[1]) << 8) | usize::from(bytes[2]);
    Ok(Http2FrameHeader {
        length,
        frame_type: bytes[3],
        flags: bytes[4],
        stream_id: u32::from_be_bytes([bytes[5] & 0x7f, bytes[6], bytes[7], bytes[8]]),
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedHttp2Request {
    pub protocol: ProtocolKind,
    pub stream_id: u32,
    pub method: Option<String>,
    pub trace_context: Option<TraceContext>,
    pub warning: Option<String>,
    pub attributes: Vec<TraceAttribute>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedHttp2Response {
    pub protocol: ProtocolKind,
    pub stream_id: u32,
    pub status_code: Option<u16>,
    pub error_type: Option<String>,
    pub warning: Option<String>,
    pub attributes: Vec<TraceAttribute>,
}

/// A complete, bounded HPACK header block assembled from one HEADERS frame
/// and any required CONTINUATION frames. `header` retains the initial
/// HEADERS semantics, including END_STREAM, and always carries END_HEADERS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssembledHttp2HeaderBlock {
    pub header: Http2FrameHeader,
    pub block: Vec<u8>,
}

#[derive(Debug)]
struct PendingHttp2HeaderBlock {
    header: Http2FrameHeader,
    block: Vec<u8>,
}

/// Connection-direction-scoped state for HTTP/2 header block reassembly.
///
/// HTTP/2 forbids any interleaving frame between a HEADERS frame without
/// END_HEADERS and its final CONTINUATION. Violations discard the partial
/// block so bytes from different streams can never be fed into HPACK.
#[derive(Debug, Default)]
pub struct Http2HeaderBlockAssembler {
    pending: Option<PendingHttp2HeaderBlock>,
}

impl Http2HeaderBlockAssembler {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_pending(&self) -> bool {
        self.pending.is_some()
    }

    pub fn reset(&mut self) {
        self.pending = None;
    }

    /// Accepts one complete HTTP/2 frame. Non-header frames return `None`
    /// when no block is pending. A completed block is returned only after
    /// END_HEADERS, with the total encoded bytes bounded by
    /// `max_header_bytes`.
    pub fn push_frame(
        &mut self,
        header: &Http2FrameHeader,
        payload: &[u8],
        max_header_bytes: usize,
    ) -> Result<Option<AssembledHttp2HeaderBlock>, Http2Extraction> {
        match header.frame_type {
            HTTP2_FRAME_TYPE_HEADERS => {
                if self.pending.take().is_some() {
                    return Err(Http2Extraction::ContinuationExpected);
                }
                if header.stream_id == 0 {
                    return Err(Http2Extraction::MalformedFrame);
                }
                let block = headers_frame_block(header, payload)?;
                if block.len() > max_header_bytes {
                    return Err(Http2Extraction::HeadersTooLong);
                }
                if header.flags & HTTP2_FLAG_END_HEADERS != 0 {
                    let mut assembled_header = *header;
                    assembled_header.flags &= !(HTTP2_FLAG_PADDED | HTTP2_FLAG_PRIORITY);
                    assembled_header.length = block.len();
                    return Ok(Some(AssembledHttp2HeaderBlock {
                        header: assembled_header,
                        block: block.to_vec(),
                    }));
                }
                self.pending = Some(PendingHttp2HeaderBlock {
                    header: *header,
                    block: block.to_vec(),
                });
                Ok(None)
            }
            HTTP2_FRAME_TYPE_CONTINUATION => {
                let Some(mut pending) = self.pending.take() else {
                    return Err(Http2Extraction::UnexpectedContinuation);
                };
                if header.stream_id == 0 || header.stream_id != pending.header.stream_id {
                    return Err(Http2Extraction::ContinuationStreamMismatch);
                }
                let assembled_len = pending
                    .block
                    .len()
                    .checked_add(payload.len())
                    .ok_or(Http2Extraction::HeadersTooLong)?;
                if assembled_len > max_header_bytes {
                    return Err(Http2Extraction::HeadersTooLong);
                }
                pending.block.extend_from_slice(payload);
                if header.flags & HTTP2_FLAG_END_HEADERS == 0 {
                    self.pending = Some(pending);
                    return Ok(None);
                }
                pending.header.flags |= HTTP2_FLAG_END_HEADERS;
                pending.header.flags &= !(HTTP2_FLAG_PADDED | HTTP2_FLAG_PRIORITY);
                pending.header.length = pending.block.len();
                Ok(Some(AssembledHttp2HeaderBlock {
                    header: pending.header,
                    block: pending.block,
                }))
            }
            _ if self.pending.take().is_some() => Err(Http2Extraction::ContinuationExpected),
            _ => Ok(None),
        }
    }
}

/// Connection-scoped HPACK decoding state for one stream direction.
#[derive(Debug)]
pub struct HpackDecoder {
    dynamic: VecDeque<(String, String)>,
    dynamic_bytes: usize,
    max_dynamic_bytes: usize,
    poisoned: bool,
}

impl Default for HpackDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl HpackDecoder {
    pub fn new() -> Self {
        Self {
            dynamic: VecDeque::new(),
            dynamic_bytes: 0,
            max_dynamic_bytes: DEFAULT_HPACK_DYNAMIC_TABLE_BYTES,
            poisoned: false,
        }
    }

    pub fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    /// Decodes one complete HPACK header block into bounded name/value
    /// pairs. On any error the decoder poisons itself because the dynamic
    /// table may have diverged from the encoder.
    pub fn decode_header_block(
        &mut self,
        block: &[u8],
    ) -> Result<Vec<(String, String)>, Http2Extraction> {
        if self.poisoned {
            return Err(Http2Extraction::DecoderPoisoned);
        }
        match self.decode_block_inner(block) {
            Ok(headers) => Ok(headers),
            Err(err) => {
                self.poisoned = true;
                Err(err)
            }
        }
    }

    fn decode_block_inner(
        &mut self,
        block: &[u8],
    ) -> Result<Vec<(String, String)>, Http2Extraction> {
        let mut headers = Vec::new();
        let mut cursor = 0;
        while cursor < block.len() {
            if headers.len() >= MAX_HPACK_HEADERS_PER_BLOCK {
                return Err(Http2Extraction::HeadersTooLong);
            }
            let first = block[cursor];
            if first & 0x80 != 0 {
                // Indexed header field.
                let index = decode_integer(block, &mut cursor, 7)?;
                headers.push(self.indexed_entry(index)?);
            } else if first & 0xc0 == 0x40 {
                // Literal with incremental indexing.
                let (name, value) = self.decode_literal(block, &mut cursor, 6)?;
                self.insert_dynamic(name.clone(), value.clone());
                headers.push((name, value));
            } else if first & 0xe0 == 0x20 {
                // Dynamic table size update.
                let size = decode_integer(block, &mut cursor, 5)?;
                let size = size as usize;
                if size > MAX_HPACK_DYNAMIC_TABLE_BYTES {
                    return Err(Http2Extraction::InvalidHpack);
                }
                self.max_dynamic_bytes = size;
                self.evict_to_limit();
            } else {
                // Literal without indexing (0000) or never indexed (0001).
                let (name, value) = self.decode_literal(block, &mut cursor, 4)?;
                headers.push((name, value));
            }
        }
        Ok(headers)
    }

    fn indexed_entry(&self, index: u32) -> Result<(String, String), Http2Extraction> {
        entry_at(&self.dynamic, index).ok_or(Http2Extraction::InvalidHpack)
    }

    fn decode_literal(
        &mut self,
        block: &[u8],
        cursor: &mut usize,
        prefix_bits: u8,
    ) -> Result<(String, String), Http2Extraction> {
        let name_index = decode_integer(block, cursor, prefix_bits)?;
        let name = if name_index == 0 {
            decode_string(block, cursor, MAX_HPACK_NAME_BYTES)?
        } else {
            entry_at(&self.dynamic, name_index)
                .ok_or(Http2Extraction::InvalidHpack)?
                .0
        };
        let value = decode_string(block, cursor, MAX_HPACK_VALUE_BYTES)?;
        Ok((name, value))
    }

    fn insert_dynamic(&mut self, name: String, value: String) {
        let entry_bytes = name.len() + value.len() + HPACK_ENTRY_OVERHEAD_BYTES;
        if entry_bytes > self.max_dynamic_bytes {
            // An entry larger than the table clears it (RFC 7541 4.4).
            self.dynamic.clear();
            self.dynamic_bytes = 0;
            return;
        }
        self.dynamic.push_front((name, value));
        self.dynamic_bytes += entry_bytes;
        self.evict_to_limit();
    }

    fn evict_to_limit(&mut self) {
        while self.dynamic_bytes > self.max_dynamic_bytes {
            let Some((name, value)) = self.dynamic.pop_back() else {
                self.dynamic_bytes = 0;
                return;
            };
            self.dynamic_bytes = self
                .dynamic_bytes
                .saturating_sub(name.len() + value.len() + HPACK_ENTRY_OVERHEAD_BYTES);
        }
    }
}

fn entry_at(dynamic: &VecDeque<(String, String)>, index: u32) -> Option<(String, String)> {
    if index == 0 {
        return None;
    }
    let index = index as usize;
    if index <= HPACK_STATIC_TABLE.len() {
        let (name, value) = HPACK_STATIC_TABLE[index - 1];
        return Some((name.to_string(), value.to_string()));
    }
    dynamic.get(index - HPACK_STATIC_TABLE.len() - 1).cloned()
}

fn decode_integer(
    block: &[u8],
    cursor: &mut usize,
    prefix_bits: u8,
) -> Result<u32, Http2Extraction> {
    if *cursor >= block.len() {
        return Err(Http2Extraction::InvalidHpack);
    }
    let mask = (1u32 << prefix_bits) - 1;
    let mut value = u32::from(block[*cursor]) & mask;
    *cursor += 1;
    if value < mask {
        return Ok(value);
    }

    let mut shift = 0u32;
    for _ in 0..MAX_HPACK_INT_CONTINUATION_BYTES {
        if *cursor >= block.len() {
            return Err(Http2Extraction::InvalidHpack);
        }
        let byte = block[*cursor];
        *cursor += 1;
        let addend = u32::from(byte & 0x7f)
            .checked_shl(shift)
            .ok_or(Http2Extraction::InvalidHpack)?;
        value = value
            .checked_add(addend)
            .ok_or(Http2Extraction::InvalidHpack)?;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
        shift += 7;
    }
    Err(Http2Extraction::InvalidHpack)
}

fn decode_string(
    block: &[u8],
    cursor: &mut usize,
    max_bytes: usize,
) -> Result<String, Http2Extraction> {
    if *cursor >= block.len() {
        return Err(Http2Extraction::InvalidHpack);
    }
    let huffman = block[*cursor] & 0x80 != 0;
    let length = decode_integer(block, cursor, 7)? as usize;
    let end = cursor
        .checked_add(length)
        .ok_or(Http2Extraction::InvalidHpack)?;
    if end > block.len() {
        return Err(Http2Extraction::InvalidHpack);
    }
    let raw = &block[*cursor..end];
    *cursor = end;

    let bytes = if huffman {
        huffman_decode(raw, max_bytes)?
    } else {
        if raw.len() > max_bytes {
            return Err(Http2Extraction::HeadersTooLong);
        }
        raw.to_vec()
    };
    String::from_utf8(bytes).map_err(|_| Http2Extraction::InvalidHpack)
}

fn huffman_decode(input: &[u8], max_bytes: usize) -> Result<Vec<u8>, Http2Extraction> {
    let mut output = Vec::new();
    let mut code: u32 = 0;
    let mut code_bits: u8 = 0;
    for byte in input {
        for bit_index in (0..8).rev() {
            code = (code << 1) | u32::from((byte >> bit_index) & 1);
            code_bits += 1;
            if let Some(symbol) = huffman_symbol(code, code_bits) {
                if symbol == HUFFMAN_EOS_SYMBOL {
                    return Err(Http2Extraction::InvalidHuffman);
                }
                if output.len() >= max_bytes {
                    return Err(Http2Extraction::HeadersTooLong);
                }
                output.push(symbol as u8);
                code = 0;
                code_bits = 0;
            } else if code_bits >= 30 {
                return Err(Http2Extraction::InvalidHuffman);
            }
        }
    }
    // Remaining bits must be a prefix of EOS: all ones, at most 7 bits.
    if code_bits > 7 || code != (1u32 << code_bits) - 1 {
        return Err(Http2Extraction::InvalidHuffman);
    }
    Ok(output)
}

fn huffman_symbol(code: u32, code_bits: u8) -> Option<u16> {
    for (position, length) in HUFFMAN_LENGTHS.iter().enumerate() {
        if *length != code_bits {
            continue;
        }
        let first_code = HUFFMAN_FIRST_CODE[position];
        let count = u32::from(HUFFMAN_COUNT[position]);
        if code >= first_code && code < first_code + count {
            let index = usize::from(HUFFMAN_FIRST_INDEX[position]) + (code - first_code) as usize;
            return Some(HUFFMAN_SYMBOLS[index]);
        }
        return None;
    }
    None
}

/// Extracts the HPACK header block from a HEADERS frame payload, honoring
/// padding and priority flags.
pub fn headers_frame_block<'frame>(
    header: &Http2FrameHeader,
    payload: &'frame [u8],
) -> Result<&'frame [u8], Http2Extraction> {
    if header.frame_type != HTTP2_FRAME_TYPE_HEADERS {
        return Err(Http2Extraction::UnsupportedFrame);
    }
    let mut start = 0;
    let mut end = payload.len();
    if header.flags & HTTP2_FLAG_PADDED != 0 {
        if payload.is_empty() {
            return Err(Http2Extraction::MalformedFrame);
        }
        let pad = usize::from(payload[0]);
        start += 1;
        end = end
            .checked_sub(pad)
            .ok_or(Http2Extraction::MalformedFrame)?;
    }
    if header.flags & HTTP2_FLAG_PRIORITY != 0 {
        start += 5;
    }
    if start > end {
        return Err(Http2Extraction::MalformedFrame);
    }
    Ok(&payload[start..end])
}

/// Parses a request-direction HEADERS frame into bounded semantics.
pub fn parse_http2_request_headers_frame(
    decoder: &mut HpackDecoder,
    header: &Http2FrameHeader,
    payload: &[u8],
    config: &ProtocolExtractionConfig,
) -> Result<ParsedHttp2Request, Http2Extraction> {
    if header.flags & HTTP2_FLAG_END_HEADERS == 0 {
        return Err(Http2Extraction::ContinuationExpected);
    }
    let block = headers_frame_block(header, payload)?;
    if block.len() > config.max_header_bytes {
        return Err(Http2Extraction::HeadersTooLong);
    }
    let mut warning = None;
    let headers = decoder.decode_header_block(block)?;

    let mut method = None;
    let mut path: Option<&str> = None;
    let mut authority: Option<&str> = None;
    let mut grpc = false;
    let mut traceparent: Option<&str> = None;
    let mut tracestate_valid = false;
    for (name, value) in &headers {
        match name.as_str() {
            ":method" => method = Some(value.clone()),
            ":path" => path = Some(value.as_str()),
            ":authority" => authority = Some(value.as_str()),
            "content-type" => grpc = value.starts_with("application/grpc"),
            "traceparent" => traceparent = Some(value.as_str()),
            "tracestate" => {
                tracestate_valid = validate_tracestate(value, config.max_tracestate_bytes).is_ok();
            }
            _ => {}
        }
    }

    let path_only = path.map(strip_target);
    let mut attributes = Vec::new();
    if grpc {
        let (service, rpc_method) = path_only
            .as_deref()
            .map(split_grpc_path)
            .unwrap_or((None, None));
        push_attribute(
            &mut attributes,
            config.max_attributes,
            "rpc.system",
            Some("grpc"),
        );
        push_attribute(
            &mut attributes,
            config.max_attributes,
            "rpc.service",
            service.as_deref(),
        );
        push_attribute(
            &mut attributes,
            config.max_attributes,
            "rpc.method",
            rpc_method.as_deref(),
        );
    } else {
        push_attribute(
            &mut attributes,
            config.max_attributes,
            "http.request.method",
            method.as_deref(),
        );
        push_attribute(
            &mut attributes,
            config.max_attributes,
            "url.path",
            path_only.as_deref(),
        );
    }
    let (server_address, server_port) = authority.map(split_authority).unwrap_or((None, None));
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "server.address",
        server_address.as_deref(),
    );
    if tracestate_valid {
        push_attribute(
            &mut attributes,
            config.max_attributes,
            "e.navigator.trace.tracestate",
            Some("validated_discarded"),
        );
    }

    let trace_context = traceparent.and_then(|value| match parse_traceparent(value) {
        Ok(context) => Some(context),
        Err(_) => {
            warning = Some("malformed_trace_context".to_string());
            None
        }
    });
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "server.port",
        server_port.as_deref(),
    );

    Ok(ParsedHttp2Request {
        protocol: if grpc {
            ProtocolKind::Grpc
        } else {
            ProtocolKind::Http
        },
        stream_id: header.stream_id,
        method,
        trace_context,
        warning,
        attributes,
    })
}

/// Parses a response-direction HEADERS frame into bounded status semantics.
pub fn parse_http2_response_headers_frame(
    decoder: &mut HpackDecoder,
    header: &Http2FrameHeader,
    payload: &[u8],
    config: &ProtocolExtractionConfig,
) -> Result<ParsedHttp2Response, Http2Extraction> {
    if header.flags & HTTP2_FLAG_END_HEADERS == 0 {
        return Err(Http2Extraction::ContinuationExpected);
    }
    let block = headers_frame_block(header, payload)?;
    if block.len() > config.max_header_bytes {
        return Err(Http2Extraction::HeadersTooLong);
    }
    let warning = None;
    let headers = decoder.decode_header_block(block)?;

    let mut status_code = None;
    let mut grpc_status: Option<&str> = None;
    for (name, value) in &headers {
        match name.as_str() {
            ":status" => {
                status_code = Some(
                    value
                        .parse::<u16>()
                        .map_err(|_| Http2Extraction::InvalidStatusCode)?,
                );
            }
            "grpc-status" => grpc_status = Some(value.as_str()),
            _ => {}
        }
    }

    let mut attributes = Vec::new();
    let status_text = status_code.map(|code| code.to_string());
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "http.response.status_code",
        status_text.as_deref(),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "rpc.grpc.status_code",
        grpc_status,
    );
    let error_type = match (grpc_status, status_code) {
        (Some(status), _) if status != "0" && status.parse::<u8>().is_ok() => {
            Some(status.to_string())
        }
        (None, Some(code)) if code >= 500 => Some(code.to_string()),
        _ => None,
    };
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "error.type",
        error_type.as_deref(),
    );

    Ok(ParsedHttp2Response {
        protocol: if grpc_status.is_some() {
            ProtocolKind::Grpc
        } else {
            ProtocolKind::Http
        },
        stream_id: header.stream_id,
        status_code,
        error_type,
        warning,
        attributes,
    })
}

fn strip_target(target: &str) -> String {
    let end = target.find(['?', '#']).unwrap_or(target.len());
    target[..end].to_string()
}

fn split_grpc_path(path: &str) -> (Option<String>, Option<String>) {
    let trimmed = path.strip_prefix('/').unwrap_or(path);
    let mut parts = trimmed.splitn(2, '/');
    let service = parts.next().filter(|part| !part.is_empty());
    let method = parts.next().filter(|part| !part.is_empty());
    (
        service.map(ToString::to_string),
        method.map(ToString::to_string),
    )
}

fn split_authority(authority: &str) -> (Option<String>, Option<String>) {
    match authority.rsplit_once(':') {
        Some((address, port))
            if port.chars().all(|byte| byte.is_ascii_digit()) && !port.is_empty() =>
        {
            (Some(address.to_string()), Some(port.to_string()))
        }
        _ => (Some(authority.to_string()), None),
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

const HUFFMAN_LENGTHS: [u8; 21] = [
    5, 6, 7, 8, 10, 11, 12, 13, 14, 15, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 30,
];
const HUFFMAN_FIRST_CODE: [u32; 21] = [
    0, 20, 92, 248, 1016, 2042, 4090, 8184, 16380, 32764, 524272, 1048550, 2097116, 4194258,
    8388568, 16777194, 33554412, 67108832, 134217694, 268435426, 1073741820,
];
const HUFFMAN_FIRST_INDEX: [u16; 21] = [
    0, 10, 36, 68, 74, 79, 82, 84, 90, 92, 95, 98, 106, 119, 145, 174, 186, 190, 205, 224, 253,
];
const HUFFMAN_COUNT: [u16; 21] = [
    10, 26, 32, 6, 5, 3, 2, 6, 2, 3, 3, 8, 13, 26, 29, 12, 4, 15, 19, 29, 4,
];
const HUFFMAN_SYMBOLS: [u16; 257] = [
    48, 49, 50, 97, 99, 101, 105, 111, 115, 116, 32, 37, 45, 46, 47, 51, 52, 53, 54, 55, 56, 57,
    61, 65, 95, 98, 100, 102, 103, 104, 108, 109, 110, 112, 114, 117, 58, 66, 67, 68, 69, 70, 71,
    72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 89, 106, 107, 113, 118, 119,
    120, 121, 122, 38, 42, 44, 59, 88, 90, 33, 34, 40, 41, 63, 39, 43, 124, 35, 62, 0, 36, 64, 91,
    93, 126, 94, 125, 60, 96, 123, 92, 195, 208, 128, 130, 131, 162, 184, 194, 224, 226, 153, 161,
    167, 172, 176, 177, 179, 209, 216, 217, 227, 229, 230, 129, 132, 133, 134, 136, 146, 154, 156,
    160, 163, 164, 169, 170, 173, 178, 181, 185, 186, 187, 189, 190, 196, 198, 228, 232, 233, 1,
    135, 137, 138, 139, 140, 141, 143, 147, 149, 150, 151, 152, 155, 157, 158, 165, 166, 168, 174,
    175, 180, 182, 183, 188, 191, 197, 231, 239, 9, 142, 144, 145, 148, 159, 171, 206, 215, 225,
    236, 237, 199, 207, 234, 235, 192, 193, 200, 201, 202, 205, 210, 213, 218, 219, 238, 240, 242,
    243, 255, 203, 204, 211, 212, 214, 221, 222, 223, 241, 244, 245, 246, 247, 248, 250, 251, 252,
    253, 254, 2, 3, 4, 5, 6, 7, 8, 11, 12, 14, 15, 16, 17, 18, 19, 20, 21, 23, 24, 25, 26, 27, 28,
    29, 30, 31, 127, 220, 249, 10, 13, 22, 256,
];

const HPACK_STATIC_TABLE: [(&str, &str); 61] = [
    (":authority", ""),
    (":method", "GET"),
    (":method", "POST"),
    (":path", "/"),
    (":path", "/index.html"),
    (":scheme", "http"),
    (":scheme", "https"),
    (":status", "200"),
    (":status", "204"),
    (":status", "206"),
    (":status", "304"),
    (":status", "400"),
    (":status", "404"),
    (":status", "500"),
    ("accept-charset", ""),
    ("accept-encoding", "gzip, deflate"),
    ("accept-language", ""),
    ("accept-ranges", ""),
    ("accept", ""),
    ("access-control-allow-origin", ""),
    ("age", ""),
    ("allow", ""),
    ("authorization", ""),
    ("cache-control", ""),
    ("content-disposition", ""),
    ("content-encoding", ""),
    ("content-language", ""),
    ("content-length", ""),
    ("content-location", ""),
    ("content-range", ""),
    ("content-type", ""),
    ("cookie", ""),
    ("date", ""),
    ("etag", ""),
    ("expect", ""),
    ("expires", ""),
    ("from", ""),
    ("host", ""),
    ("if-match", ""),
    ("if-modified-since", ""),
    ("if-none-match", ""),
    ("if-range", ""),
    ("if-unmodified-since", ""),
    ("last-modified", ""),
    ("link", ""),
    ("location", ""),
    ("max-forwards", ""),
    ("proxy-authenticate", ""),
    ("proxy-authorization", ""),
    ("range", ""),
    ("referer", ""),
    ("refresh", ""),
    ("retry-after", ""),
    ("server", ""),
    ("set-cookie", ""),
    ("strict-transport-security", ""),
    ("transfer-encoding", ""),
    ("user-agent", ""),
    ("vary", ""),
    ("via", ""),
    ("www-authenticate", ""),
];

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(input: &str) -> Vec<u8> {
        (0..input.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&input[index..index + 2], 16).expect("hex"))
            .collect()
    }

    #[test]
    fn frame_header_parses_length_type_flags_stream() {
        let bytes = [0x00, 0x00, 0x0c, 0x01, 0x05, 0x80, 0x00, 0x00, 0x03];
        let header = parse_http2_frame_header(&bytes).expect("frame header parses");
        assert_eq!(header.length, 12);
        assert_eq!(header.frame_type, HTTP2_FRAME_TYPE_HEADERS);
        assert_eq!(header.flags, 0x05);
        // Reserved bit is masked off.
        assert_eq!(header.stream_id, 3);
    }

    #[test]
    fn continuation_frames_reassemble_before_hpack_decode() {
        let mut assembler = Http2HeaderBlockAssembler::new();
        let headers = Http2FrameHeader {
            length: 1,
            frame_type: HTTP2_FRAME_TYPE_HEADERS,
            flags: HTTP2_FLAG_END_STREAM,
            stream_id: 1,
        };
        assert_eq!(assembler.push_frame(&headers, &[0x82], 16), Ok(None));
        assert!(assembler.is_pending());

        let middle = Http2FrameHeader {
            length: 0,
            frame_type: HTTP2_FRAME_TYPE_CONTINUATION,
            flags: 0,
            stream_id: 1,
        };
        assert_eq!(assembler.push_frame(&middle, &[], 16), Ok(None));

        let continuation = Http2FrameHeader {
            length: 1,
            frame_type: HTTP2_FRAME_TYPE_CONTINUATION,
            flags: HTTP2_FLAG_END_HEADERS,
            stream_id: 1,
        };
        let assembled = assembler
            .push_frame(&continuation, &[0x84], 16)
            .expect("continuation is valid")
            .expect("header block is complete");
        assert_eq!(assembled.block, vec![0x82, 0x84]);
        assert_eq!(
            assembled.header.flags,
            HTTP2_FLAG_END_STREAM | HTTP2_FLAG_END_HEADERS,
        );
        assert!(!assembler.is_pending());

        let parsed = parse_http2_request_headers_frame(
            &mut HpackDecoder::new(),
            &assembled.header,
            &assembled.block,
            &ProtocolExtractionConfig::default(),
        )
        .expect("assembled block parses");
        assert_eq!(parsed.method.as_deref(), Some("GET"));
    }

    #[test]
    fn continuation_stream_mismatch_discards_partial_block() {
        let mut assembler = Http2HeaderBlockAssembler::new();
        let headers = Http2FrameHeader {
            length: 1,
            frame_type: HTTP2_FRAME_TYPE_HEADERS,
            flags: 0,
            stream_id: 1,
        };
        assert_eq!(assembler.push_frame(&headers, &[0x82], 16), Ok(None));
        let wrong_stream = Http2FrameHeader {
            length: 1,
            frame_type: HTTP2_FRAME_TYPE_CONTINUATION,
            flags: HTTP2_FLAG_END_HEADERS,
            stream_id: 3,
        };
        assert_eq!(
            assembler.push_frame(&wrong_stream, &[0x84], 16),
            Err(Http2Extraction::ContinuationStreamMismatch),
        );
        assert!(!assembler.is_pending());

        let complete = Http2FrameHeader {
            length: 2,
            frame_type: HTTP2_FRAME_TYPE_HEADERS,
            flags: HTTP2_FLAG_END_HEADERS,
            stream_id: 5,
        };
        assert!(
            assembler
                .push_frame(&complete, &[0x82, 0x84], 16)
                .expect("fresh block is accepted")
                .is_some(),
        );
    }

    #[test]
    fn interleaved_or_oversized_header_blocks_fail_closed() {
        let mut assembler = Http2HeaderBlockAssembler::new();
        let headers = Http2FrameHeader {
            length: 2,
            frame_type: HTTP2_FRAME_TYPE_HEADERS,
            flags: 0,
            stream_id: 1,
        };
        assert_eq!(assembler.push_frame(&headers, &[0x82, 0x84], 2), Ok(None));
        let data = Http2FrameHeader {
            length: 0,
            frame_type: HTTP2_FRAME_TYPE_DATA,
            flags: 0,
            stream_id: 1,
        };
        assert_eq!(
            assembler.push_frame(&data, &[], 2),
            Err(Http2Extraction::ContinuationExpected),
        );
        assert!(!assembler.is_pending());

        assert_eq!(assembler.push_frame(&headers, &[0x82, 0x84], 2), Ok(None));
        let continuation = Http2FrameHeader {
            length: 1,
            frame_type: HTTP2_FRAME_TYPE_CONTINUATION,
            flags: HTTP2_FLAG_END_HEADERS,
            stream_id: 1,
        };
        assert_eq!(
            assembler.push_frame(&continuation, &[0x00], 2),
            Err(Http2Extraction::HeadersTooLong),
        );
        assert!(!assembler.is_pending());
    }

    #[test]
    fn incomplete_header_frame_does_not_poison_hpack_decoder() {
        let mut decoder = HpackDecoder::new();
        let incomplete = Http2FrameHeader {
            length: 1,
            frame_type: HTTP2_FRAME_TYPE_HEADERS,
            flags: 0,
            stream_id: 1,
        };
        assert_eq!(
            parse_http2_request_headers_frame(
                &mut decoder,
                &incomplete,
                &[0xff],
                &ProtocolExtractionConfig::default(),
            ),
            Err(Http2Extraction::ContinuationExpected),
        );
        assert_eq!(
            decoder.decode_header_block(&[0x82, 0x84]),
            Ok(vec![
                (":method".to_string(), "GET".to_string()),
                (":path".to_string(), "/".to_string()),
            ]),
        );
    }

    #[test]
    fn rfc7541_c4_huffman_requests_decode() {
        let mut decoder = HpackDecoder::new();
        let first = hex("828684418cf1e3c2e5f23a6ba0ab90f4ff");
        let headers = decoder.decode_header_block(&first).expect("C.4.1 decodes");
        assert_eq!(
            headers,
            vec![
                (":method".to_string(), "GET".to_string()),
                (":scheme".to_string(), "http".to_string()),
                (":path".to_string(), "/".to_string()),
                (":authority".to_string(), "www.example.com".to_string()),
            ],
        );

        // C.4.2 second request reuses the dynamic table entry.
        let second = hex("828684be5886a8eb10649cbf");
        let headers = decoder.decode_header_block(&second).expect("C.4.2 decodes");
        assert_eq!(headers[3].0, ":authority");
        assert_eq!(headers[3].1, "www.example.com");
        assert_eq!(
            headers[4],
            ("cache-control".to_string(), "no-cache".to_string())
        );

        // C.4.3 third request.
        let third = hex("828785bf408825a849e95ba97d7f8925a849e95bb8e8b4bf");
        let headers = decoder.decode_header_block(&third).expect("C.4.3 decodes");
        assert_eq!(headers[0], (":method".to_string(), "GET".to_string()));
        assert_eq!(headers[1], (":scheme".to_string(), "https".to_string()));
        assert_eq!(headers[2], (":path".to_string(), "/index.html".to_string()));
        assert_eq!(
            headers[4],
            ("custom-key".to_string(), "custom-value".to_string()),
        );
    }

    #[test]
    fn rfc7541_c6_huffman_response_decodes() {
        let mut decoder = HpackDecoder::new();
        let first = hex(
            "488264025885aec3771a4b6196d07abe941054d444a8200595040b8166e082a62d1bff6e919d29ad171863c78f0b97c8e9ae82ae43d3",
        );
        let headers = decoder.decode_header_block(&first).expect("C.6.1 decodes");
        assert_eq!(headers[0], (":status".to_string(), "302".to_string()));
        assert_eq!(
            headers[1],
            ("cache-control".to_string(), "private".to_string())
        );
        assert_eq!(
            headers[2],
            (
                "date".to_string(),
                "Mon, 21 Oct 2013 20:13:21 GMT".to_string(),
            ),
        );
        assert_eq!(
            headers[3],
            (
                "location".to_string(),
                "https://www.example.com".to_string()
            ),
        );
    }

    #[test]
    fn request_headers_frame_extracts_bounded_semantics() {
        let mut decoder = HpackDecoder::new();
        let block = hex("828684418cf1e3c2e5f23a6ba0ab90f4ff");
        let header = Http2FrameHeader {
            length: block.len(),
            frame_type: HTTP2_FRAME_TYPE_HEADERS,
            flags: HTTP2_FLAG_END_HEADERS,
            stream_id: 1,
        };
        let parsed = parse_http2_request_headers_frame(
            &mut decoder,
            &header,
            &block,
            &ProtocolExtractionConfig::default(),
        )
        .expect("request frame parses");

        assert_eq!(parsed.protocol, ProtocolKind::Http);
        assert_eq!(parsed.stream_id, 1);
        assert_eq!(parsed.method.as_deref(), Some("GET"));
        assert!(parsed.warning.is_none());
        assert!(
            parsed
                .attributes
                .iter()
                .any(|attribute| attribute.key == "url.path" && attribute.value == "/"),
        );
        assert!(
            parsed
                .attributes
                .iter()
                .any(|attribute| attribute.key == "server.address"
                    && attribute.value == "www.example.com"),
        );
    }

    #[test]
    fn grpc_request_headers_extract_service_and_method() {
        let mut decoder = HpackDecoder::new();
        // :method POST, :path /checkout.v1.CheckoutService/GetCart,
        // content-type application/grpc, all literal without indexing.
        let mut block = vec![0x83]; // :method: POST (static index 3)
        block.push(0x04); // literal, indexed name :path (4)
        let path = b"/checkout.v1.CheckoutService/GetCart?token=secret";
        block.push(path.len() as u8);
        block.extend_from_slice(path);
        block.push(0x0f); // literal, indexed name 31 (content-type)
        block.push(31 - 15);
        let content_type = b"application/grpc+proto";
        block.push(content_type.len() as u8);
        block.extend_from_slice(content_type);

        let header = Http2FrameHeader {
            length: block.len(),
            frame_type: HTTP2_FRAME_TYPE_HEADERS,
            flags: HTTP2_FLAG_END_HEADERS,
            stream_id: 5,
        };
        let parsed = parse_http2_request_headers_frame(
            &mut decoder,
            &header,
            &block,
            &ProtocolExtractionConfig::default(),
        )
        .expect("grpc request parses");

        assert_eq!(parsed.protocol, ProtocolKind::Grpc);
        assert!(
            parsed
                .attributes
                .iter()
                .any(|attribute| attribute.key == "rpc.service"
                    && attribute.value == "checkout.v1.CheckoutService"),
        );
        assert!(
            parsed
                .attributes
                .iter()
                .any(|attribute| attribute.key == "rpc.method" && attribute.value == "GetCart"),
        );
        // The query string must never be exported.
        assert!(
            !parsed
                .attributes
                .iter()
                .any(|attribute| attribute.value.contains("secret")),
        );
    }

    #[test]
    fn response_headers_frame_extracts_status() {
        let mut decoder = HpackDecoder::new();
        let block = hex(
            "488264025885aec3771a4b6196d07abe941054d444a8200595040b8166e082a62d1bff6e919d29ad171863c78f0b97c8e9ae82ae43d3",
        );
        let header = Http2FrameHeader {
            length: block.len(),
            frame_type: HTTP2_FRAME_TYPE_HEADERS,
            flags: HTTP2_FLAG_END_HEADERS,
            stream_id: 1,
        };
        let parsed = parse_http2_response_headers_frame(
            &mut decoder,
            &header,
            &block,
            &ProtocolExtractionConfig::default(),
        )
        .expect("response frame parses");

        assert_eq!(parsed.status_code, Some(302));
        assert_eq!(parsed.error_type, None);
        // Location header values are never exported.
        assert!(
            !parsed
                .attributes
                .iter()
                .any(|attribute| attribute.value.contains("example.com")),
        );
    }

    #[test]
    fn padded_headers_frame_strips_padding() {
        let block = hex("828684418cf1e3c2e5f23a6ba0ab90f4ff");
        let mut payload = vec![2u8];
        payload.extend_from_slice(&block);
        payload.extend_from_slice(&[0, 0]);
        let header = Http2FrameHeader {
            length: payload.len(),
            frame_type: HTTP2_FRAME_TYPE_HEADERS,
            flags: HTTP2_FLAG_END_HEADERS | HTTP2_FLAG_PADDED,
            stream_id: 1,
        };
        let assembled = Http2HeaderBlockAssembler::new()
            .push_frame(&header, &payload, 64)
            .expect("padded frame is valid")
            .expect("header block is complete");
        assert_eq!(assembled.block, block);
        assert_eq!(assembled.header.flags, HTTP2_FLAG_END_HEADERS);
        let parsed = parse_http2_request_headers_frame(
            &mut HpackDecoder::new(),
            &assembled.header,
            &assembled.block,
            &ProtocolExtractionConfig::default(),
        )
        .expect("padded frame parses");
        assert_eq!(parsed.method.as_deref(), Some("GET"));
    }

    #[test]
    fn decode_failure_poisons_decoder() {
        let mut decoder = HpackDecoder::new();
        // Index 200 does not exist.
        let bad = [0xff, 0x49];
        assert!(decoder.decode_header_block(&bad).is_err());
        let good = hex("828684418cf1e3c2e5f23a6ba0ab90f4ff");
        assert_eq!(
            decoder.decode_header_block(&good),
            Err(Http2Extraction::DecoderPoisoned),
        );
    }

    #[test]
    fn oversized_headers_are_rejected() {
        let mut decoder = HpackDecoder::new();
        // A literal value longer than the value bound.
        let mut block = vec![0x04]; // literal, indexed name :path
        block.push(0x7f); // length prefix 127, continuation follows
        block.push(0xff);
        block.push(0x10); // 127 + (127 + 16*128) huge
        assert!(decoder.decode_header_block(&block).is_err());
    }

    #[test]
    fn decoder_never_panics_on_arbitrary_bytes() {
        for seed in 0..=u8::MAX {
            let bytes: Vec<u8> = (0..48u8)
                .map(|index| seed.wrapping_add(index.wrapping_mul(7)))
                .collect();
            let mut decoder = HpackDecoder::new();
            let _ = decoder.decode_header_block(&bytes);
            let _ = parse_http2_frame_header(&bytes);
            let header = Http2FrameHeader {
                length: bytes.len(),
                frame_type: HTTP2_FRAME_TYPE_HEADERS,
                flags: seed,
                stream_id: 1,
            };
            let mut decoder = HpackDecoder::new();
            let _ = parse_http2_request_headers_frame(
                &mut decoder,
                &header,
                &bytes,
                &ProtocolExtractionConfig::default(),
            );
            let mut decoder = HpackDecoder::new();
            let _ = parse_http2_response_headers_frame(
                &mut decoder,
                &header,
                &bytes,
                &ProtocolExtractionConfig::default(),
            );
        }
    }
}
