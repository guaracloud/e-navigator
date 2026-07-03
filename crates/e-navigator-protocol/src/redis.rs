use e_navigator_signals::{ProtocolKind, TraceAttribute};

use crate::ProtocolExtractionConfig;

const MAX_REDIS_COMMAND_BYTES: usize = 64;
const MAX_REDIS_BULK_STRING_BYTES: usize = 1024;
const MAX_REDIS_ARRAY_ITEMS: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedRedisCommand {
    pub protocol: ProtocolKind,
    pub command: Option<String>,
    pub warning: Option<String>,
    pub attributes: Vec<TraceAttribute>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedisExtraction {
    FrameTooLong,
    InvalidUtf8,
    MalformedFrame,
    BulkStringTooLong,
    UnsupportedFrame,
}

pub fn parse_redis_command(
    bytes: &[u8],
    config: &ProtocolExtractionConfig,
) -> Result<ParsedRedisCommand, RedisExtraction> {
    if bytes.len() > config.max_header_bytes {
        return Err(RedisExtraction::FrameTooLong);
    }
    if bytes.is_empty() {
        return Err(RedisExtraction::MalformedFrame);
    }

    let frame = if bytes[0] == b'*' {
        parse_resp_array(bytes)?
    } else {
        parse_inline_command(bytes, config.max_request_line_bytes)?
    };
    let command = bounded_command(frame.command.as_deref());
    let mut attributes = Vec::new();
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "db.system",
        Some("redis"),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "db.operation",
        command.as_deref(),
    );
    let argument_count = frame.argument_count.to_string();
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "db.redis.argument.count",
        Some(&argument_count),
    );
    push_attribute(
        &mut attributes,
        config.max_attributes,
        "db.redis.key_present",
        frame.key_present.then_some("true"),
    );

    Ok(ParsedRedisCommand {
        protocol: ProtocolKind::Redis,
        command,
        warning: None,
        attributes,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RedisFrame {
    command: Option<String>,
    argument_count: usize,
    key_present: bool,
}

fn parse_resp_array(bytes: &[u8]) -> Result<RedisFrame, RedisExtraction> {
    let mut cursor = 1;
    let item_count = parse_decimal_line(bytes, &mut cursor)?;
    if item_count <= 0 || item_count as usize > MAX_REDIS_ARRAY_ITEMS {
        return Err(RedisExtraction::MalformedFrame);
    }

    let mut command = None;
    for index in 0..item_count as usize {
        let item = parse_bulk_string(bytes, &mut cursor)?;
        if index == 0 {
            command = Some(item);
        }
    }

    Ok(RedisFrame {
        command,
        argument_count: item_count.saturating_sub(1) as usize,
        key_present: item_count > 1,
    })
}

fn parse_bulk_string(bytes: &[u8], cursor: &mut usize) -> Result<String, RedisExtraction> {
    if bytes.get(*cursor) != Some(&b'$') {
        return Err(RedisExtraction::UnsupportedFrame);
    }
    *cursor += 1;
    let len = parse_decimal_line(bytes, cursor)?;
    if len < 0 {
        return Err(RedisExtraction::MalformedFrame);
    }
    let len = len as usize;
    if len > MAX_REDIS_BULK_STRING_BYTES {
        return Err(RedisExtraction::BulkStringTooLong);
    }

    let end = cursor
        .checked_add(len)
        .ok_or(RedisExtraction::MalformedFrame)?;
    if end + 2 > bytes.len() || bytes.get(end..end + 2) != Some(b"\r\n") {
        return Err(RedisExtraction::MalformedFrame);
    }
    let value =
        std::str::from_utf8(&bytes[*cursor..end]).map_err(|_| RedisExtraction::InvalidUtf8)?;
    *cursor = end + 2;
    Ok(value.to_string())
}

fn parse_inline_command(
    bytes: &[u8],
    max_request_line_bytes: usize,
) -> Result<RedisFrame, RedisExtraction> {
    let end = line_end(bytes, 0).ok_or(RedisExtraction::MalformedFrame)?;
    if end > max_request_line_bytes {
        return Err(RedisExtraction::FrameTooLong);
    }
    let line = std::str::from_utf8(&bytes[..end]).map_err(|_| RedisExtraction::InvalidUtf8)?;
    let mut fields = line.split_ascii_whitespace();
    let command = fields.next().ok_or(RedisExtraction::MalformedFrame)?;
    let argument_count = fields.count();
    Ok(RedisFrame {
        command: Some(command.to_string()),
        argument_count,
        key_present: argument_count > 0,
    })
}

fn parse_decimal_line(bytes: &[u8], cursor: &mut usize) -> Result<isize, RedisExtraction> {
    let end = line_end(bytes, *cursor).ok_or(RedisExtraction::MalformedFrame)?;
    let value =
        std::str::from_utf8(&bytes[*cursor..end]).map_err(|_| RedisExtraction::InvalidUtf8)?;
    if value.is_empty()
        || value == "-"
        || !value
            .bytes()
            .enumerate()
            .all(|(index, byte)| byte.is_ascii_digit() || (index == 0 && byte == b'-'))
    {
        return Err(RedisExtraction::MalformedFrame);
    }
    *cursor = end + 2;
    value
        .parse::<isize>()
        .map_err(|_| RedisExtraction::MalformedFrame)
}

fn line_end(bytes: &[u8], start: usize) -> Option<usize> {
    if start >= bytes.len() {
        return None;
    }
    bytes[start..]
        .windows(2)
        .position(|window| window == b"\r\n")
        .map(|offset| start + offset)
}

fn bounded_command(value: Option<&str>) -> Option<String> {
    let value = value?;
    if value.is_empty()
        || value.len() > MAX_REDIS_COMMAND_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphabetic() || byte == b'_')
    {
        return None;
    }
    Some(value.to_ascii_uppercase())
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
