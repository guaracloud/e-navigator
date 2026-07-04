//! Bounded request-stream reassembly for socket payload capture.
//!
//! Runtime capture delivers, per syscall, a bounded payload prefix plus the
//! total syscall length. This module turns those chunks back into complete
//! protocol frames for the stateless per-message parsers, with explicit
//! accounting for every byte it could not reconstruct: uncaptured syscall
//! tails, frames larger than the reassembly bound, and desynchronized
//! streams are counted and skipped, never guessed.

const MAX_FRAME_LENGTH_DIGITS: usize = 10;
const MAX_REDIS_BOUNDARY_ITEMS: usize = 1024;

/// Application protocol carried by a captured request stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamProtocol {
    Kafka,
    Mongodb,
    Mysql,
    Nats,
    Postgresql,
    Redis,
}

/// Direction of a captured stream relative to the observed client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamDirection {
    /// Client-to-server bytes (requests/commands).
    Request,
    /// Server-to-client bytes (responses).
    Response,
}

/// Bounds applied to stream reassembly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamDecodeLimits {
    /// Maximum bytes buffered while waiting for a frame to complete.
    pub max_buffered_bytes: usize,
    /// Sanity cap on a declared frame length; larger declarations are
    /// treated as stream desynchronization.
    pub max_frame_bytes: usize,
    /// Maximum complete frames extracted from a single pushed chunk.
    pub max_frames_per_chunk: usize,
}

impl Default for StreamDecodeLimits {
    fn default() -> Self {
        Self {
            max_buffered_bytes: 8 * 1024,
            max_frame_bytes: 64 * 1024 * 1024,
            max_frames_per_chunk: 64,
        }
    }
}

/// Where the next frame ends relative to the start of the buffered bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameBoundary {
    /// Not enough bytes buffered to determine the frame end.
    NeedMoreBytes,
    /// The frame spans `total_len` bytes from the buffer start.
    Frame { total_len: usize },
    /// The buffered bytes cannot start a valid frame for this protocol.
    Invalid,
}

/// A frame recovered from a captured request stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamFrame {
    /// A fully reassembled frame ready for a per-message parser.
    Complete(Vec<u8>),
    /// A frame whose length is known but whose body could not be captured
    /// within bounds; only the available prefix is provided.
    Truncated { prefix: Vec<u8>, declared_len: u64 },
}

/// Counters describing everything the decoder did not reconstruct.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StreamDecodeStats {
    pub complete_frames: u64,
    pub truncated_frames: u64,
    pub invalid_frames: u64,
    pub resyncs: u64,
    pub skipped_bytes: u64,
    pub dropped_buffer_bytes: u64,
}

/// Reassembles one direction of one connection into protocol frames.
#[derive(Debug)]
pub struct ProtocolStreamDecoder {
    protocol: StreamProtocol,
    direction: StreamDirection,
    limits: StreamDecodeLimits,
    buffer: Vec<u8>,
    pending_skip: u64,
    resync: bool,
    stats: StreamDecodeStats,
}

impl ProtocolStreamDecoder {
    pub fn new(
        protocol: StreamProtocol,
        direction: StreamDirection,
        limits: StreamDecodeLimits,
    ) -> Self {
        Self {
            protocol,
            direction,
            limits,
            buffer: Vec::new(),
            pending_skip: 0,
            resync: false,
            stats: StreamDecodeStats::default(),
        }
    }

    pub fn protocol(&self) -> StreamProtocol {
        self.protocol
    }

    pub fn stats(&self) -> StreamDecodeStats {
        self.stats
    }

    /// Number of bytes currently buffered while waiting for a frame end.
    pub fn buffered_bytes(&self) -> usize {
        self.buffer.len()
    }

    /// Feed one captured chunk. `captured` holds the bytes actually copied
    /// from the syscall buffer and `chunk_total_len` the full syscall length;
    /// any difference is an uncaptured gap immediately after `captured`.
    /// Complete and truncated frames are appended to `frames`.
    pub fn push_chunk(
        &mut self,
        captured: &[u8],
        chunk_total_len: u64,
        frames: &mut Vec<StreamFrame>,
    ) {
        let chunk_total_len = chunk_total_len.max(captured.len() as u64);
        if self.resync {
            self.begin_resync();
        }

        let visible = match self.consume_pending_skip(captured, chunk_total_len) {
            Some(visible) => visible,
            None => return,
        };
        let mut gap = chunk_total_len - captured.len() as u64;
        gap += self.buffer_visible(visible);
        self.extract_frames(gap, frames);
    }

    fn begin_resync(&mut self) {
        self.buffer.clear();
        self.pending_skip = 0;
        self.resync = false;
        self.stats.resyncs += 1;
    }

    /// Applies any pending skip to the incoming chunk. Returns the visible
    /// bytes remaining after the skip, or `None` if the chunk is consumed.
    fn consume_pending_skip<'chunk>(
        &mut self,
        captured: &'chunk [u8],
        chunk_total_len: u64,
    ) -> Option<&'chunk [u8]> {
        if self.pending_skip == 0 {
            return Some(captured);
        }
        if self.pending_skip >= chunk_total_len {
            self.pending_skip -= chunk_total_len;
            self.stats.skipped_bytes += chunk_total_len;
            return None;
        }

        let skip = self.pending_skip;
        self.stats.skipped_bytes += skip;
        self.pending_skip = 0;
        if (skip as usize) < captured.len() {
            return Some(&captured[skip as usize..]);
        }

        // The skip ends inside the uncaptured tail of this chunk, so the
        // next frame boundary was never captured.
        self.resync = true;
        None
    }

    /// Appends visible bytes to the reassembly buffer, converting anything
    /// beyond the buffer bound into additional uncaptured gap.
    fn buffer_visible(&mut self, visible: &[u8]) -> u64 {
        let space = self
            .limits
            .max_buffered_bytes
            .saturating_sub(self.buffer.len());
        if visible.len() <= space {
            self.buffer.extend_from_slice(visible);
            return 0;
        }

        let dropped = (visible.len() - space) as u64;
        self.buffer.extend_from_slice(&visible[..space]);
        self.stats.dropped_buffer_bytes += dropped;
        dropped
    }

    fn extract_frames(&mut self, mut gap: u64, frames: &mut Vec<StreamFrame>) {
        for _ in 0..self.limits.max_frames_per_chunk {
            match frame_boundary(
                self.protocol,
                self.direction,
                &self.buffer,
                self.limits.max_frame_bytes,
            ) {
                FrameBoundary::Frame { total_len } if total_len <= self.buffer.len() => {
                    frames.push(StreamFrame::Complete(self.buffer[..total_len].to_vec()));
                    self.buffer.drain(..total_len);
                    self.stats.complete_frames += 1;
                    if self.buffer.is_empty() && gap == 0 {
                        return;
                    }
                }
                FrameBoundary::Frame { total_len } => {
                    self.finish_partial_frame(total_len, gap, frames);
                    return;
                }
                FrameBoundary::NeedMoreBytes => {
                    self.finish_unknown_boundary(gap);
                    return;
                }
                FrameBoundary::Invalid => {
                    self.stats.invalid_frames += 1;
                    self.buffer.clear();
                    self.resync = true;
                    return;
                }
            }
        }

        // Frame budget for this chunk exhausted. Without a trailing gap the
        // remaining buffered frames simply carry over to the next chunk;
        // with one, the stream position past the buffer is unknown.
        if gap > 0 {
            gap = 0;
            let _ = gap;
            self.buffer.clear();
            self.resync = true;
        }
    }

    /// The buffer holds a frame prefix with a known total length that cannot
    /// be completed (uncaptured tail or larger than the buffer bound).
    fn finish_partial_frame(&mut self, total_len: usize, gap: u64, frames: &mut Vec<StreamFrame>) {
        if gap == 0 && total_len <= self.limits.max_buffered_bytes {
            // Completable: wait for the next contiguous chunk.
            return;
        }

        let buffered = self.buffer.len() as u64;
        let remaining = total_len as u64 - buffered;
        frames.push(StreamFrame::Truncated {
            prefix: std::mem::take(&mut self.buffer),
            declared_len: total_len as u64,
        });
        self.stats.truncated_frames += 1;
        if gap > remaining {
            // The gap extends past this frame's end into unknown frames.
            self.resync = true;
        } else {
            self.pending_skip = remaining - gap;
        }
    }

    /// The buffered bytes do not yet reveal a frame boundary.
    fn finish_unknown_boundary(&mut self, gap: u64) {
        if gap > 0 {
            // The frame continues into bytes that were never captured.
            if !self.buffer.is_empty() {
                self.stats.dropped_buffer_bytes += self.buffer.len() as u64;
            }
            self.buffer.clear();
            self.resync = true;
            return;
        }
        if self.buffer.len() >= self.limits.max_buffered_bytes {
            // The buffer can never grow enough to reveal the boundary.
            self.stats.dropped_buffer_bytes += self.buffer.len() as u64;
            self.buffer.clear();
            self.resync = true;
        }
    }
}

/// Determines where the request frame starting at `bytes[0]` ends.
pub fn request_frame_boundary(
    protocol: StreamProtocol,
    bytes: &[u8],
    max_frame_bytes: usize,
) -> FrameBoundary {
    frame_boundary(protocol, StreamDirection::Request, bytes, max_frame_bytes)
}

/// Determines where the frame starting at `bytes[0]` ends.
pub fn frame_boundary(
    protocol: StreamProtocol,
    direction: StreamDirection,
    bytes: &[u8],
    max_frame_bytes: usize,
) -> FrameBoundary {
    if bytes.is_empty() {
        return FrameBoundary::NeedMoreBytes;
    }
    match (protocol, direction) {
        (StreamProtocol::Kafka, _) => kafka_boundary(bytes, max_frame_bytes),
        (StreamProtocol::Mongodb, _) => mongodb_boundary(bytes, max_frame_bytes),
        (StreamProtocol::Mysql, _) => mysql_boundary(bytes, max_frame_bytes),
        (StreamProtocol::Nats, StreamDirection::Request) => nats_boundary(bytes, max_frame_bytes),
        (StreamProtocol::Nats, StreamDirection::Response) => {
            nats_response_boundary(bytes, max_frame_bytes)
        }
        (StreamProtocol::Postgresql, _) => postgres_boundary(bytes, max_frame_bytes),
        (StreamProtocol::Redis, StreamDirection::Request) => redis_boundary(bytes, max_frame_bytes),
        (StreamProtocol::Redis, StreamDirection::Response) => {
            redis_response_boundary(bytes, max_frame_bytes)
        }
    }
}

fn checked_frame(total_len: usize, max_frame_bytes: usize) -> FrameBoundary {
    if total_len > max_frame_bytes {
        return FrameBoundary::Invalid;
    }
    FrameBoundary::Frame { total_len }
}

fn kafka_boundary(bytes: &[u8], max_frame_bytes: usize) -> FrameBoundary {
    if bytes.len() < 4 {
        return FrameBoundary::NeedMoreBytes;
    }
    let declared = i32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    if declared <= 0 {
        return FrameBoundary::Invalid;
    }
    match (declared as usize).checked_add(4) {
        Some(total_len) => checked_frame(total_len, max_frame_bytes),
        None => FrameBoundary::Invalid,
    }
}

fn mongodb_boundary(bytes: &[u8], max_frame_bytes: usize) -> FrameBoundary {
    if bytes.len() < 4 {
        return FrameBoundary::NeedMoreBytes;
    }
    let declared = i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    if declared < 16 {
        return FrameBoundary::Invalid;
    }
    checked_frame(declared as usize, max_frame_bytes)
}

fn mysql_boundary(bytes: &[u8], max_frame_bytes: usize) -> FrameBoundary {
    if bytes.len() < 4 {
        return FrameBoundary::NeedMoreBytes;
    }
    let payload_len =
        usize::from(bytes[0]) | (usize::from(bytes[1]) << 8) | (usize::from(bytes[2]) << 16);
    if payload_len == 0 {
        return FrameBoundary::Invalid;
    }
    checked_frame(payload_len + 4, max_frame_bytes)
}

fn postgres_boundary(bytes: &[u8], max_frame_bytes: usize) -> FrameBoundary {
    if bytes[0] == 0 {
        // Untagged startup-style message: 4-byte length including itself.
        if bytes.len() < 4 {
            return FrameBoundary::NeedMoreBytes;
        }
        let declared = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
        if declared < 8 {
            return FrameBoundary::Invalid;
        }
        return checked_frame(declared, max_frame_bytes);
    }
    if !bytes[0].is_ascii_alphabetic() {
        return FrameBoundary::Invalid;
    }
    if bytes.len() < 5 {
        return FrameBoundary::NeedMoreBytes;
    }
    let declared = u32::from_be_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]) as usize;
    if declared < 4 {
        return FrameBoundary::Invalid;
    }
    match declared.checked_add(1) {
        Some(total_len) => checked_frame(total_len, max_frame_bytes),
        None => FrameBoundary::Invalid,
    }
}

fn nats_boundary(bytes: &[u8], max_frame_bytes: usize) -> FrameBoundary {
    let line_cap = bytes.len().min(max_frame_bytes);
    let Some(line_len) = find_crlf(&bytes[..line_cap]) else {
        if bytes.len() >= max_frame_bytes {
            return FrameBoundary::Invalid;
        }
        return FrameBoundary::NeedMoreBytes;
    };
    let Ok(line) = std::str::from_utf8(&bytes[..line_len]) else {
        return FrameBoundary::Invalid;
    };
    let mut tokens = line.split_ascii_whitespace();
    let Some(verb) = tokens.next() else {
        return FrameBoundary::Invalid;
    };
    let line_total = line_len + 2;
    let payload_len = if verb.eq_ignore_ascii_case("pub") || verb.eq_ignore_ascii_case("hpub") {
        let Some(size_token) = tokens.last() else {
            return FrameBoundary::Invalid;
        };
        if size_token.len() > MAX_FRAME_LENGTH_DIGITS {
            return FrameBoundary::Invalid;
        }
        match size_token.parse::<usize>() {
            Ok(size) => Some(size),
            Err(_) => return FrameBoundary::Invalid,
        }
    } else if verb.eq_ignore_ascii_case("connect")
        || verb.eq_ignore_ascii_case("sub")
        || verb.eq_ignore_ascii_case("unsub")
        || verb.eq_ignore_ascii_case("ping")
        || verb.eq_ignore_ascii_case("pong")
    {
        None
    } else {
        return FrameBoundary::Invalid;
    };

    let total_len = match payload_len {
        Some(size) => match line_total
            .checked_add(size)
            .and_then(|len| len.checked_add(2))
        {
            Some(total) => total,
            None => return FrameBoundary::Invalid,
        },
        None => line_total,
    };
    checked_frame(total_len, max_frame_bytes)
}

fn redis_boundary(bytes: &[u8], max_frame_bytes: usize) -> FrameBoundary {
    if bytes[0] != b'*' {
        // Inline command: a single CRLF-terminated line.
        let line_cap = bytes.len().min(max_frame_bytes);
        let Some(line_len) = find_crlf(&bytes[..line_cap]) else {
            if bytes.len() >= max_frame_bytes {
                return FrameBoundary::Invalid;
            }
            return FrameBoundary::NeedMoreBytes;
        };
        return checked_frame(line_len + 2, max_frame_bytes);
    }

    let mut cursor = 1;
    let item_count = match read_decimal_line(bytes, &mut cursor) {
        DecimalLine::Value(value) => value,
        DecimalLine::NeedMoreBytes => return FrameBoundary::NeedMoreBytes,
        DecimalLine::Invalid => return FrameBoundary::Invalid,
    };
    if item_count == 0 || item_count > MAX_REDIS_BOUNDARY_ITEMS as u64 {
        return FrameBoundary::Invalid;
    }

    for _ in 0..item_count {
        if cursor >= bytes.len() {
            if cursor > max_frame_bytes {
                return FrameBoundary::Invalid;
            }
            return FrameBoundary::NeedMoreBytes;
        }
        if bytes[cursor] != b'$' {
            return FrameBoundary::Invalid;
        }
        cursor += 1;
        let bulk_len = match read_decimal_line(bytes, &mut cursor) {
            DecimalLine::Value(value) => value,
            DecimalLine::NeedMoreBytes => return FrameBoundary::NeedMoreBytes,
            DecimalLine::Invalid => return FrameBoundary::Invalid,
        };
        let Some(next) = cursor
            .checked_add(bulk_len as usize)
            .and_then(|end| end.checked_add(2))
        else {
            return FrameBoundary::Invalid;
        };
        cursor = next;
        if cursor > max_frame_bytes {
            return FrameBoundary::Invalid;
        }
    }
    checked_frame(cursor, max_frame_bytes)
}

fn nats_response_boundary(bytes: &[u8], max_frame_bytes: usize) -> FrameBoundary {
    let line_cap = bytes.len().min(max_frame_bytes);
    let Some(line_len) = find_crlf(&bytes[..line_cap]) else {
        if bytes.len() >= max_frame_bytes {
            return FrameBoundary::Invalid;
        }
        return FrameBoundary::NeedMoreBytes;
    };
    let Ok(line) = std::str::from_utf8(&bytes[..line_len]) else {
        return FrameBoundary::Invalid;
    };
    let mut tokens = line.split_ascii_whitespace();
    let Some(verb) = tokens.next() else {
        return FrameBoundary::Invalid;
    };
    let line_total = line_len + 2;
    let payload_len = if verb.eq_ignore_ascii_case("msg") || verb.eq_ignore_ascii_case("hmsg") {
        let Some(size_token) = tokens.last() else {
            return FrameBoundary::Invalid;
        };
        if size_token.len() > MAX_FRAME_LENGTH_DIGITS {
            return FrameBoundary::Invalid;
        }
        match size_token.parse::<usize>() {
            Ok(size) => Some(size),
            Err(_) => return FrameBoundary::Invalid,
        }
    } else if verb.eq_ignore_ascii_case("+ok")
        || verb.eq_ignore_ascii_case("-err")
        || verb.eq_ignore_ascii_case("ping")
        || verb.eq_ignore_ascii_case("pong")
        || verb.eq_ignore_ascii_case("info")
    {
        None
    } else {
        return FrameBoundary::Invalid;
    };

    let total_len = match payload_len {
        Some(size) => match line_total
            .checked_add(size)
            .and_then(|len| len.checked_add(2))
        {
            Some(total) => total,
            None => return FrameBoundary::Invalid,
        },
        None => line_total,
    };
    checked_frame(total_len, max_frame_bytes)
}

const MAX_RESP_VALUE_DEPTH: usize = 4;

fn redis_response_boundary(bytes: &[u8], max_frame_bytes: usize) -> FrameBoundary {
    let mut cursor = 0;
    match resp_value_end(bytes, &mut cursor, max_frame_bytes, MAX_RESP_VALUE_DEPTH) {
        RespWalk::Complete => checked_frame(cursor, max_frame_bytes),
        RespWalk::NeedMoreBytes => {
            if bytes.len() >= max_frame_bytes {
                return FrameBoundary::Invalid;
            }
            FrameBoundary::NeedMoreBytes
        }
        RespWalk::Invalid => FrameBoundary::Invalid,
    }
}

enum RespWalk {
    Complete,
    NeedMoreBytes,
    Invalid,
}

/// Walks one RESP2/RESP3 value starting at `*cursor` and advances the cursor
/// past it. Bounded by `max_frame_bytes`, item counts, and nesting depth.
fn resp_value_end(
    bytes: &[u8],
    cursor: &mut usize,
    max_frame_bytes: usize,
    depth: usize,
) -> RespWalk {
    if depth == 0 {
        return RespWalk::Invalid;
    }
    if *cursor >= max_frame_bytes {
        return RespWalk::Invalid;
    }
    if *cursor >= bytes.len() {
        return RespWalk::NeedMoreBytes;
    }

    let type_byte = bytes[*cursor];
    *cursor += 1;
    match type_byte {
        // Line-delimited scalars.
        b'+' | b'-' | b':' | b'#' | b',' | b'(' | b'_' => {
            let remaining = &bytes[*cursor..bytes.len().min(max_frame_bytes)];
            match find_crlf(remaining) {
                Some(line_len) => {
                    *cursor += line_len + 2;
                    RespWalk::Complete
                }
                None => {
                    if bytes.len() >= max_frame_bytes {
                        RespWalk::Invalid
                    } else {
                        RespWalk::NeedMoreBytes
                    }
                }
            }
        }
        // Length-prefixed blobs (bulk string, verbatim string, bulk error).
        b'$' | b'=' | b'!' => {
            let length = match read_signed_decimal_line(bytes, cursor) {
                SignedDecimalLine::Value(value) => value,
                SignedDecimalLine::NeedMoreBytes => return RespWalk::NeedMoreBytes,
                SignedDecimalLine::Invalid => return RespWalk::Invalid,
            };
            if length < 0 {
                // Null bulk value: no blob follows.
                return RespWalk::Complete;
            }
            let Some(end) = cursor
                .checked_add(length as usize)
                .and_then(|end| end.checked_add(2))
            else {
                return RespWalk::Invalid;
            };
            if end > max_frame_bytes {
                return RespWalk::Invalid;
            }
            if end > bytes.len() {
                return RespWalk::NeedMoreBytes;
            }
            *cursor = end;
            RespWalk::Complete
        }
        // Aggregates: array, set, push, map (map counts pairs).
        b'*' | b'~' | b'>' | b'%' => {
            let count = match read_signed_decimal_line(bytes, cursor) {
                SignedDecimalLine::Value(value) => value,
                SignedDecimalLine::NeedMoreBytes => return RespWalk::NeedMoreBytes,
                SignedDecimalLine::Invalid => return RespWalk::Invalid,
            };
            if count < 0 {
                // Null aggregate.
                return RespWalk::Complete;
            }
            let count = count as usize;
            if count > MAX_REDIS_BOUNDARY_ITEMS {
                return RespWalk::Invalid;
            }
            let items = if type_byte == b'%' {
                match count.checked_mul(2) {
                    Some(items) if items <= MAX_REDIS_BOUNDARY_ITEMS => items,
                    _ => return RespWalk::Invalid,
                }
            } else {
                count
            };
            for _ in 0..items {
                match resp_value_end(bytes, cursor, max_frame_bytes, depth - 1) {
                    RespWalk::Complete => {}
                    other => return other,
                }
            }
            RespWalk::Complete
        }
        _ => RespWalk::Invalid,
    }
}

enum DecimalLine {
    Value(u64),
    NeedMoreBytes,
    Invalid,
}

/// Reads a CRLF-terminated decimal with optional leading minus starting at
/// `*cursor` and advances the cursor past the CRLF.
fn read_signed_decimal_line(bytes: &[u8], cursor: &mut usize) -> SignedDecimalLine {
    let negative = if *cursor < bytes.len() && bytes[*cursor] == b'-' {
        *cursor += 1;
        true
    } else {
        false
    };
    match read_decimal_line(bytes, cursor) {
        DecimalLine::Value(value) => {
            let signed = value as i64;
            SignedDecimalLine::Value(if negative { -signed } else { signed })
        }
        DecimalLine::NeedMoreBytes => SignedDecimalLine::NeedMoreBytes,
        DecimalLine::Invalid => SignedDecimalLine::Invalid,
    }
}

enum SignedDecimalLine {
    Value(i64),
    NeedMoreBytes,
    Invalid,
}

/// Reads a CRLF-terminated non-negative decimal starting at `*cursor` and
/// advances the cursor past the CRLF.
fn read_decimal_line(bytes: &[u8], cursor: &mut usize) -> DecimalLine {
    let mut value: u64 = 0;
    let mut digits = 0;
    let mut index = *cursor;
    loop {
        if index >= bytes.len() {
            return if digits > MAX_FRAME_LENGTH_DIGITS {
                DecimalLine::Invalid
            } else {
                DecimalLine::NeedMoreBytes
            };
        }
        match bytes[index] {
            byte @ b'0'..=b'9' => {
                digits += 1;
                if digits > MAX_FRAME_LENGTH_DIGITS {
                    return DecimalLine::Invalid;
                }
                value = value * 10 + u64::from(byte - b'0');
                index += 1;
            }
            b'\r' => {
                if digits == 0 || index + 1 >= bytes.len() {
                    return if digits == 0 {
                        DecimalLine::Invalid
                    } else {
                        DecimalLine::NeedMoreBytes
                    };
                }
                if bytes[index + 1] != b'\n' {
                    return DecimalLine::Invalid;
                }
                *cursor = index + 2;
                return DecimalLine::Value(value);
            }
            _ => return DecimalLine::Invalid,
        }
    }
}

fn find_crlf(bytes: &[u8]) -> Option<usize> {
    bytes.windows(2).position(|pair| pair == b"\r\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decoder(protocol: StreamProtocol) -> ProtocolStreamDecoder {
        ProtocolStreamDecoder::new(
            protocol,
            StreamDirection::Request,
            StreamDecodeLimits::default(),
        )
    }

    fn kafka_frame(body: &[u8]) -> Vec<u8> {
        let mut frame = (body.len() as i32).to_be_bytes().to_vec();
        frame.extend_from_slice(body);
        frame
    }

    fn push(decoder: &mut ProtocolStreamDecoder, chunk: &[u8]) -> Vec<StreamFrame> {
        let mut frames = Vec::new();
        decoder.push_chunk(chunk, chunk.len() as u64, &mut frames);
        frames
    }

    #[test]
    fn kafka_boundary_reads_length_prefix() {
        let frame = kafka_frame(&[0, 3, 0, 9, 0, 0, 0, 1]);
        assert_eq!(
            request_frame_boundary(StreamProtocol::Kafka, &frame, 1024),
            FrameBoundary::Frame {
                total_len: frame.len()
            },
        );
        assert_eq!(
            request_frame_boundary(StreamProtocol::Kafka, &frame[..3], 1024),
            FrameBoundary::NeedMoreBytes,
        );
        assert_eq!(
            request_frame_boundary(StreamProtocol::Kafka, &[0, 0, 0, 0], 1024),
            FrameBoundary::Invalid,
        );
    }

    #[test]
    fn kafka_boundary_rejects_oversized_declaration() {
        let frame = kafka_frame(&[0; 8]);
        assert_eq!(
            request_frame_boundary(StreamProtocol::Kafka, &frame, 8),
            FrameBoundary::Invalid,
        );
    }

    #[test]
    fn mongodb_boundary_reads_little_endian_length() {
        let mut frame = 20_i32.to_le_bytes().to_vec();
        frame.extend_from_slice(&[0; 16]);
        assert_eq!(
            request_frame_boundary(StreamProtocol::Mongodb, &frame, 1024),
            FrameBoundary::Frame { total_len: 20 },
        );
        assert_eq!(
            request_frame_boundary(StreamProtocol::Mongodb, &8_i32.to_le_bytes(), 1024),
            FrameBoundary::Invalid,
        );
    }

    #[test]
    fn mysql_boundary_reads_packet_header() {
        let frame = [1, 0, 0, 0, 0x0e];
        assert_eq!(
            request_frame_boundary(StreamProtocol::Mysql, &frame, 1024),
            FrameBoundary::Frame { total_len: 5 },
        );
        assert_eq!(
            request_frame_boundary(StreamProtocol::Mysql, &[0, 0, 0, 0], 1024),
            FrameBoundary::Invalid,
        );
    }

    #[test]
    fn postgres_boundary_handles_tagged_and_startup_frames() {
        let mut query = vec![b'Q'];
        query.extend_from_slice(&9_u32.to_be_bytes());
        query.extend_from_slice(&b"SELECT 1\0"[..5]);
        assert_eq!(
            request_frame_boundary(StreamProtocol::Postgresql, &query, 1024),
            FrameBoundary::Frame { total_len: 10 },
        );

        let mut startup = 8_u32.to_be_bytes().to_vec();
        startup.extend_from_slice(&196_608_u32.to_be_bytes());
        assert_eq!(
            request_frame_boundary(StreamProtocol::Postgresql, &startup, 1024),
            FrameBoundary::Frame { total_len: 8 },
        );

        assert_eq!(
            request_frame_boundary(StreamProtocol::Postgresql, &[0xff, 0, 0, 0, 4], 1024),
            FrameBoundary::Invalid,
        );
    }

    #[test]
    fn nats_boundary_includes_pub_payload() {
        let frame = b"PUB updates 5\r\nhello\r\n";
        assert_eq!(
            request_frame_boundary(StreamProtocol::Nats, frame, 1024),
            FrameBoundary::Frame {
                total_len: frame.len()
            },
        );
        assert_eq!(
            request_frame_boundary(StreamProtocol::Nats, b"PING\r\n", 1024),
            FrameBoundary::Frame { total_len: 6 },
        );
        assert_eq!(
            request_frame_boundary(StreamProtocol::Nats, b"PUB updates", 1024),
            FrameBoundary::NeedMoreBytes,
        );
        assert_eq!(
            request_frame_boundary(StreamProtocol::Nats, b"BOGUS updates\r\n", 1024),
            FrameBoundary::Invalid,
        );
    }

    #[test]
    fn redis_boundary_walks_bulk_strings() {
        let frame = b"*2\r\n$3\r\nGET\r\n$3\r\nkey\r\n";
        assert_eq!(
            request_frame_boundary(StreamProtocol::Redis, frame, 1024),
            FrameBoundary::Frame {
                total_len: frame.len()
            },
        );
        assert_eq!(
            request_frame_boundary(StreamProtocol::Redis, &frame[..10], 1024),
            FrameBoundary::NeedMoreBytes,
        );
        assert_eq!(
            request_frame_boundary(StreamProtocol::Redis, b"PING\r\n", 1024),
            FrameBoundary::Frame { total_len: 6 },
        );
        assert_eq!(
            request_frame_boundary(StreamProtocol::Redis, b"*2\r\n+OK\r\n", 1024),
            FrameBoundary::Invalid,
        );
    }

    #[test]
    fn decoder_extracts_pipelined_frames() {
        let mut decoder = decoder(StreamProtocol::Kafka);
        let mut chunk = kafka_frame(&[0, 3, 0, 9, 0, 0, 0, 1]);
        chunk.extend_from_slice(&kafka_frame(&[0, 18, 0, 4, 0, 0, 0, 2]));
        let frames = push(&mut decoder, &chunk);
        assert_eq!(frames.len(), 2);
        assert_eq!(decoder.stats().complete_frames, 2);
        assert_eq!(decoder.buffered_bytes(), 0);
    }

    #[test]
    fn decoder_reassembles_split_frames() {
        let mut decoder = decoder(StreamProtocol::Kafka);
        let frame = kafka_frame(&[0, 3, 0, 9, 0, 0, 0, 1]);
        assert!(push(&mut decoder, &frame[..5]).is_empty());
        let frames = push(&mut decoder, &frame[5..]);
        assert_eq!(frames, vec![StreamFrame::Complete(frame)]);
    }

    #[test]
    fn decoder_skips_uncaptured_frame_tail() {
        let mut decoder = decoder(StreamProtocol::Kafka);
        let frame = kafka_frame(&[0; 512]);
        let mut frames = Vec::new();
        // Only the first 64 bytes of the 516-byte syscall were captured.
        decoder.push_chunk(&frame[..64], frame.len() as u64, &mut frames);
        assert_eq!(frames.len(), 1);
        match &frames[0] {
            StreamFrame::Truncated {
                prefix,
                declared_len,
            } => {
                assert_eq!(prefix.as_slice(), &frame[..64]);
                assert_eq!(*declared_len, frame.len() as u64);
            }
            other => panic!("expected truncated frame, got {other:?}"),
        }
        assert_eq!(decoder.stats().truncated_frames, 1);

        // The stream continues cleanly at the next frame boundary.
        let next = kafka_frame(&[0, 3, 0, 9, 0, 0, 0, 7]);
        let frames = push(&mut decoder, &next);
        assert_eq!(frames, vec![StreamFrame::Complete(next)]);
        assert_eq!(decoder.stats().resyncs, 0);
    }

    #[test]
    fn decoder_skips_frame_continuation_across_chunks() {
        let mut decoder = decoder(StreamProtocol::Kafka);
        let frame = kafka_frame(&[0; 1024]);
        let mut frames = Vec::new();
        // 64 captured of 516; the remaining 512 arrive as a separate
        // fully-captured chunk that must be skipped, not parsed.
        decoder.push_chunk(&frame[..64], 516, &mut frames);
        assert_eq!(frames.len(), 1);
        decoder.push_chunk(&frame[516..1028], 512, &mut frames);
        assert_eq!(frames.len(), 1);
        assert_eq!(decoder.stats().skipped_bytes, 512);
    }

    #[test]
    fn decoder_resyncs_after_invalid_bytes() {
        let mut decoder = decoder(StreamProtocol::Kafka);
        let frames = push(&mut decoder, &[0, 0, 0, 0, 1, 2, 3]);
        assert!(frames.is_empty());
        assert_eq!(decoder.stats().invalid_frames, 1);

        let frame = kafka_frame(&[0, 3, 0, 9, 0, 0, 0, 1]);
        let frames = push(&mut decoder, &frame);
        assert_eq!(frames, vec![StreamFrame::Complete(frame)]);
        assert_eq!(decoder.stats().resyncs, 1);
    }

    #[test]
    fn decoder_emits_truncated_frame_beyond_buffer_bound() {
        let limits = StreamDecodeLimits {
            max_buffered_bytes: 64,
            ..StreamDecodeLimits::default()
        };
        let mut decoder =
            ProtocolStreamDecoder::new(StreamProtocol::Kafka, StreamDirection::Request, limits);
        let frame = kafka_frame(&[0; 256]);
        let mut frames = Vec::new();
        decoder.push_chunk(&frame[..128], frame.len() as u64, &mut frames);
        assert_eq!(frames.len(), 1);
        match &frames[0] {
            StreamFrame::Truncated {
                prefix,
                declared_len,
            } => {
                assert_eq!(prefix.len(), 64);
                assert_eq!(*declared_len, frame.len() as u64);
            }
            other => panic!("expected truncated frame, got {other:?}"),
        }
    }

    #[test]
    fn decoder_desyncs_when_boundary_lost_in_gap() {
        let mut decoder = decoder(StreamProtocol::Redis);
        let mut frames = Vec::new();
        // A partial inline command whose terminator was never captured.
        decoder.push_chunk(b"GET some-key", 64, &mut frames);
        assert!(frames.is_empty());

        let frames = push(&mut decoder, b"PING\r\n");
        assert_eq!(frames, vec![StreamFrame::Complete(b"PING\r\n".to_vec())]);
        assert_eq!(decoder.stats().resyncs, 1);
    }

    #[test]
    fn decoder_handles_redis_pipeline_across_chunks() {
        let mut decoder = decoder(StreamProtocol::Redis);
        let pipeline = b"*1\r\n$4\r\nPING\r\n*2\r\n$3\r\nGET\r\n$3\r\nkey\r\n";
        let (first, second) = pipeline.split_at(20);
        let frames = push(&mut decoder, first);
        assert_eq!(frames.len(), 1);
        let frames = push(&mut decoder, second);
        assert_eq!(frames.len(), 1);
        assert_eq!(decoder.stats().complete_frames, 2);
    }

    #[test]
    fn decoder_counts_skip_consuming_whole_chunks() {
        let mut decoder = decoder(StreamProtocol::Mongodb);
        let declared = 4096_u64;
        let mut header = (declared as i32).to_le_bytes().to_vec();
        header.extend_from_slice(&[0; 60]);
        let mut frames = Vec::new();
        decoder.push_chunk(&header, 256, &mut frames);
        assert_eq!(frames.len(), 1);
        // Remaining 3840 bytes of the frame arrive as opaque chunks.
        decoder.push_chunk(&[0; 256], 2048, &mut frames);
        decoder.push_chunk(&[0; 256], 1792, &mut frames);
        assert_eq!(frames.len(), 1);
        assert_eq!(decoder.stats().skipped_bytes, declared - 64 - (256 - 64));

        let mut next = 20_i32.to_le_bytes().to_vec();
        next.extend_from_slice(&[0; 16]);
        let frames = push(&mut decoder, &next);
        assert_eq!(frames.len(), 1);
    }

    #[test]
    fn redis_response_boundary_walks_resp_values() {
        let cases: [(&[u8], FrameBoundary); 8] = [
            (b"+OK\r\n", FrameBoundary::Frame { total_len: 5 }),
            (b"-ERR unknown\r\n", FrameBoundary::Frame { total_len: 14 }),
            (b":42\r\n", FrameBoundary::Frame { total_len: 5 }),
            (b"$5\r\nhello\r\n", FrameBoundary::Frame { total_len: 11 }),
            (b"$-1\r\n", FrameBoundary::Frame { total_len: 5 }),
            (
                b"*2\r\n$1\r\na\r\n:9\r\n",
                FrameBoundary::Frame { total_len: 15 },
            ),
            (
                b"%1\r\n+key\r\n+value\r\n",
                FrameBoundary::Frame { total_len: 18 },
            ),
            (b"$5\r\nhel", FrameBoundary::NeedMoreBytes),
        ];
        for (bytes, expected) in cases {
            assert_eq!(
                frame_boundary(
                    StreamProtocol::Redis,
                    StreamDirection::Response,
                    bytes,
                    1024
                ),
                expected,
                "case {:?}",
                String::from_utf8_lossy(bytes),
            );
        }
        assert_eq!(
            frame_boundary(
                StreamProtocol::Redis,
                StreamDirection::Response,
                b"?bogus\r\n",
                1024,
            ),
            FrameBoundary::Invalid,
        );
    }

    #[test]
    fn redis_response_boundary_bounds_nesting_depth() {
        // Five levels of nesting exceeds MAX_RESP_VALUE_DEPTH.
        let deep = b"*1\r\n*1\r\n*1\r\n*1\r\n*1\r\n+x\r\n";
        assert_eq!(
            frame_boundary(StreamProtocol::Redis, StreamDirection::Response, deep, 1024),
            FrameBoundary::Invalid,
        );
    }

    #[test]
    fn nats_response_boundary_includes_msg_payload() {
        let msg = b"MSG updates 1 5\r\nhello\r\n";
        assert_eq!(
            frame_boundary(StreamProtocol::Nats, StreamDirection::Response, msg, 1024),
            FrameBoundary::Frame {
                total_len: msg.len()
            },
        );
        assert_eq!(
            frame_boundary(
                StreamProtocol::Nats,
                StreamDirection::Response,
                b"+OK\r\n",
                1024
            ),
            FrameBoundary::Frame { total_len: 5 },
        );
        assert_eq!(
            frame_boundary(
                StreamProtocol::Nats,
                StreamDirection::Response,
                b"-ERR 'Unknown Subject'\r\n",
                1024,
            ),
            FrameBoundary::Frame { total_len: 24 },
        );
        assert_eq!(
            frame_boundary(
                StreamProtocol::Nats,
                StreamDirection::Response,
                b"PUB updates 5\r\n",
                1024,
            ),
            FrameBoundary::Invalid,
        );
    }

    #[test]
    fn response_decoder_extracts_pipelined_responses() {
        let mut decoder = ProtocolStreamDecoder::new(
            StreamProtocol::Redis,
            StreamDirection::Response,
            StreamDecodeLimits::default(),
        );
        let mut frames = Vec::new();
        let chunk = b"$5\r\nhello\r\n+PONG\r\n";
        decoder.push_chunk(chunk, chunk.len() as u64, &mut frames);
        assert_eq!(
            frames,
            vec![
                StreamFrame::Complete(b"$5\r\nhello\r\n".to_vec()),
                StreamFrame::Complete(b"+PONG\r\n".to_vec()),
            ],
        );
    }

    #[test]
    fn boundary_never_panics_on_arbitrary_bytes() {
        let protocols = [
            StreamProtocol::Kafka,
            StreamProtocol::Mongodb,
            StreamProtocol::Mysql,
            StreamProtocol::Nats,
            StreamProtocol::Postgresql,
            StreamProtocol::Redis,
        ];
        for protocol in protocols {
            for seed in 0..=u8::MAX {
                let bytes: Vec<u8> = (0..32).map(|index| seed.wrapping_add(index)).collect();
                let _ = request_frame_boundary(protocol, &bytes, 1024);
                let mut decoder = ProtocolStreamDecoder::new(
                    protocol,
                    StreamDirection::Request,
                    StreamDecodeLimits::default(),
                );
                let mut frames = Vec::new();
                decoder.push_chunk(&bytes, bytes.len() as u64 + u64::from(seed), &mut frames);
                decoder.push_chunk(&bytes, bytes.len() as u64, &mut frames);
            }
        }
    }
}
