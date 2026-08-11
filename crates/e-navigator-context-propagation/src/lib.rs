#![no_std]
//! Allocation-free contracts shared by the host and eBPF HTTP context
//! propagation paths.

pub const MAX_PROPAGATION_HEADER_BYTES: usize = 1024;
pub const TRACEPARENT_HEADER_BYTES: usize = 70;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct TraceContext {
    pub trace_id: [u8; 16],
    pub span_id: [u8; 8],
    pub trace_flags: u8,
}

impl TraceContext {
    pub fn new(trace_id: [u8; 16], span_id: [u8; 8], trace_flags: u8) -> Option<Self> {
        if all_zero(&trace_id) || all_zero(&span_id) {
            return None;
        }
        Some(Self {
            trace_id,
            span_id,
            trace_flags,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PropagationDecision {
    Inject { insert_at: usize },
    Bypass(PropagationBypass),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PropagationBypass {
    Empty,
    HeadersTooLarge,
    IncompleteHeaders,
    NotHttp1,
    UnsupportedMethod,
    ExistingTraceparent,
    ProtocolUpgrade,
    BodyBearing,
    TrailingData,
}

pub fn plan_http1_propagation(message: &[u8]) -> PropagationDecision {
    let (request_line_end, header_end) = match http1_boundaries(message) {
        Ok(boundaries) => boundaries,
        Err(reason) => return PropagationDecision::Bypass(reason),
    };
    if header_end != message.len() {
        return PropagationDecision::Bypass(PropagationBypass::TrailingData);
    }
    if let Err(reason) = validate_request_line(&message[..request_line_end]) {
        return PropagationDecision::Bypass(reason);
    }

    let mut line_start = request_line_end + 2;
    while line_start + 2 <= header_end {
        let Some(relative_end) = find_crlf(&message[line_start..header_end]) else {
            return PropagationDecision::Bypass(PropagationBypass::IncompleteHeaders);
        };
        let line_end = line_start + relative_end;
        if line_end == line_start {
            break;
        }
        let line = &message[line_start..line_end];
        let Some(colon) = find_byte(line, b':') else {
            return PropagationDecision::Bypass(PropagationBypass::NotHttp1);
        };
        let name = &line[..colon];
        let value = trim_ows(&line[colon + 1..]);
        if !valid_field_name(name) || !valid_field_value(value) {
            return PropagationDecision::Bypass(PropagationBypass::NotHttp1);
        }
        if ascii_eq_ignore_case(name, b"traceparent") {
            return PropagationDecision::Bypass(PropagationBypass::ExistingTraceparent);
        }
        if ascii_eq_ignore_case(name, b"upgrade")
            || (ascii_eq_ignore_case(name, b"connection") && contains_upgrade_token(value))
        {
            return PropagationDecision::Bypass(PropagationBypass::ProtocolUpgrade);
        }
        if ascii_eq_ignore_case(name, b"transfer-encoding")
            || (ascii_eq_ignore_case(name, b"content-length") && value != b"0")
        {
            return PropagationDecision::Bypass(PropagationBypass::BodyBearing);
        }
        line_start = line_end + 2;
    }

    PropagationDecision::Inject {
        insert_at: request_line_end + 2,
    }
}

pub fn extract_traceparent(message: &[u8]) -> Option<TraceContext> {
    let (request_line_end, header_end) = http1_boundaries(message).ok()?;
    validate_request_line(&message[..request_line_end]).ok()?;
    let mut line_start = request_line_end + 2;
    while line_start + 2 <= header_end {
        let relative_end = find_crlf(&message[line_start..header_end])?;
        let line_end = line_start + relative_end;
        if line_end == line_start {
            return None;
        }
        let line = &message[line_start..line_end];
        let colon = find_byte(line, b':')?;
        if ascii_eq_ignore_case(&line[..colon], b"traceparent") {
            return parse_traceparent_value(trim_ows(&line[colon + 1..]));
        }
        line_start = line_end + 2;
    }
    None
}

pub fn format_traceparent_header(context: TraceContext) -> [u8; TRACEPARENT_HEADER_BYTES] {
    let mut output = [0_u8; TRACEPARENT_HEADER_BYTES];
    output[..16].copy_from_slice(b"traceparent: 00-");
    write_hex(&context.trace_id, &mut output[16..48]);
    output[48] = b'-';
    write_hex(&context.span_id, &mut output[49..65]);
    output[65] = b'-';
    output[66] = hex_digit(context.trace_flags >> 4);
    output[67] = hex_digit(context.trace_flags & 0x0f);
    output[68] = b'\r';
    output[69] = b'\n';
    output
}

fn http1_boundaries(message: &[u8]) -> Result<(usize, usize), PropagationBypass> {
    if message.is_empty() {
        return Err(PropagationBypass::Empty);
    }
    if message.len() > MAX_PROPAGATION_HEADER_BYTES {
        return Err(PropagationBypass::HeadersTooLarge);
    }
    let request_line_end = find_crlf(message).ok_or(PropagationBypass::IncompleteHeaders)?;
    let mut index = request_line_end + 2;
    while index + 1 < message.len() {
        if message[index] == b'\r' && message[index + 1] == b'\n' {
            return Ok((request_line_end, index + 2));
        }
        let relative_end =
            find_crlf(&message[index..]).ok_or(PropagationBypass::IncompleteHeaders)?;
        index += relative_end + 2;
    }
    Err(PropagationBypass::IncompleteHeaders)
}

fn validate_request_line(line: &[u8]) -> Result<(), PropagationBypass> {
    let first_space = find_byte(line, b' ').ok_or(PropagationBypass::NotHttp1)?;
    let remaining = &line[first_space + 1..];
    let second_space = find_byte(remaining, b' ').ok_or(PropagationBypass::NotHttp1)?;
    let method = &line[..first_space];
    let target = &remaining[..second_space];
    let version = &remaining[second_space + 1..];
    if method.is_empty()
        || method.len() > 16
        || target.is_empty()
        || !target.iter().all(|byte| (0x21..=0x7e).contains(byte))
        || !method
            .iter()
            .all(|byte| byte.is_ascii_uppercase() || *byte == b'-')
        || find_byte(version, b' ').is_some()
    {
        return Err(PropagationBypass::NotHttp1);
    }
    if method == b"CONNECT" || method == b"PRI" {
        return Err(PropagationBypass::UnsupportedMethod);
    }
    if version != b"HTTP/1.1" && version != b"HTTP/1.0" {
        return Err(PropagationBypass::NotHttp1);
    }
    Ok(())
}

fn valid_field_name(name: &[u8]) -> bool {
    !name.is_empty()
        && name.iter().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

fn valid_field_value(value: &[u8]) -> bool {
    value
        .iter()
        .all(|byte| *byte == b'\t' || *byte >= 0x20 && *byte != 0x7f)
}

fn parse_traceparent_value(value: &[u8]) -> Option<TraceContext> {
    if value.len() != 55 || &value[..3] != b"00-" || value[35] != b'-' || value[52] != b'-' {
        return None;
    }
    let mut trace_id = [0_u8; 16];
    let mut span_id = [0_u8; 8];
    parse_hex(&value[3..35], &mut trace_id)?;
    parse_hex(&value[36..52], &mut span_id)?;
    let high = parse_hex_digit(value[53])?;
    let low = parse_hex_digit(value[54])?;
    TraceContext::new(trace_id, span_id, (high << 4) | low)
}

fn parse_hex(input: &[u8], output: &mut [u8]) -> Option<()> {
    if input.len() != output.len() * 2 {
        return None;
    }
    let mut index = 0;
    while index < output.len() {
        let high = parse_hex_digit(input[index * 2])?;
        let low = parse_hex_digit(input[index * 2 + 1])?;
        output[index] = (high << 4) | low;
        index += 1;
    }
    Some(())
}

fn write_hex(input: &[u8], output: &mut [u8]) {
    let mut index = 0;
    while index < input.len() {
        output[index * 2] = hex_digit(input[index] >> 4);
        output[index * 2 + 1] = hex_digit(input[index] & 0x0f);
        index += 1;
    }
}

const fn parse_hex_digit(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

const fn hex_digit(value: u8) -> u8 {
    if value < 10 {
        b'0' + value
    } else {
        b'a' + (value - 10)
    }
}

fn contains_upgrade_token(value: &[u8]) -> bool {
    let mut start = 0;
    while start <= value.len() {
        let relative_end = find_byte(&value[start..], b',').unwrap_or(value.len() - start);
        let token = trim_ows(&value[start..start + relative_end]);
        if ascii_eq_ignore_case(token, b"upgrade") {
            return true;
        }
        if start + relative_end >= value.len() {
            break;
        }
        start += relative_end + 1;
    }
    false
}

fn trim_ows(mut value: &[u8]) -> &[u8] {
    while value
        .first()
        .is_some_and(|byte| *byte == b' ' || *byte == b'\t')
    {
        value = &value[1..];
    }
    while value
        .last()
        .is_some_and(|byte| *byte == b' ' || *byte == b'\t')
    {
        value = &value[..value.len() - 1];
    }
    value
}

fn ascii_eq_ignore_case(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .all(|(left, right)| left.eq_ignore_ascii_case(right))
}

fn find_crlf(value: &[u8]) -> Option<usize> {
    let mut index = 0;
    while index + 1 < value.len() {
        if value[index] == b'\r' && value[index + 1] == b'\n' {
            return Some(index);
        }
        index += 1;
    }
    None
}

fn find_byte(value: &[u8], expected: u8) -> Option<usize> {
    let mut index = 0;
    while index < value.len() {
        if value[index] == expected {
            return Some(index);
        }
        index += 1;
    }
    None
}

fn all_zero(value: &[u8]) -> bool {
    value.iter().all(|byte| *byte == 0)
}
