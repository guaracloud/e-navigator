#![no_std]
//! Allocation-free contracts shared by the host and eBPF HTTP context
//! propagation paths.

pub const MAX_PROPAGATION_HEADER_BYTES: usize = 1024;
pub const TRACEPARENT_HEADER_BYTES: usize = 70;
pub const MAX_TRACESTATE_BYTES: usize = 512;

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
    OrphanTracestate,
    ProtocolUpgrade,
    UnsupportedTransferEncoding,
    InvalidContentLength,
    AmbiguousContentLength,
    TrailingData,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TraceStateError {
    MalformedHttp1,
    TooLong,
    TooManyMembers,
    InvalidKey,
    InvalidValue,
    DuplicateKey,
}

pub fn plan_http1_propagation(message: &[u8]) -> PropagationDecision {
    let (request_line_end, header_end) = match http1_boundaries(message) {
        Ok(boundaries) => boundaries,
        Err(reason) => return PropagationDecision::Bypass(reason),
    };
    let Some(request_line) = message.get(..request_line_end) else {
        return PropagationDecision::Bypass(PropagationBypass::NotHttp1);
    };
    if let Err(reason) = validate_request_line(request_line) {
        return PropagationDecision::Bypass(reason);
    }

    let mut content_length = None;
    let mut saw_tracestate = false;
    let mut line_start = request_line_end + 2;
    while line_start + 2 <= header_end {
        let Some(header_tail) = message.get(line_start..header_end) else {
            return PropagationDecision::Bypass(PropagationBypass::NotHttp1);
        };
        let Some(relative_end) = find_crlf(header_tail) else {
            return PropagationDecision::Bypass(PropagationBypass::IncompleteHeaders);
        };
        let line_end = line_start + relative_end;
        if line_end == line_start {
            break;
        }
        let Some(line) = message.get(line_start..line_end) else {
            return PropagationDecision::Bypass(PropagationBypass::NotHttp1);
        };
        let Some(colon) = find_byte(line, b':') else {
            return PropagationDecision::Bypass(PropagationBypass::NotHttp1);
        };
        let Some(name) = line.get(..colon) else {
            return PropagationDecision::Bypass(PropagationBypass::NotHttp1);
        };
        let Some(raw_value) = line.get(colon + 1..) else {
            return PropagationDecision::Bypass(PropagationBypass::NotHttp1);
        };
        let value = trim_ows(raw_value);
        if !valid_field_name(name) || !valid_field_value(value) {
            return PropagationDecision::Bypass(PropagationBypass::NotHttp1);
        }
        if ascii_eq_ignore_case(name, b"traceparent") {
            return PropagationDecision::Bypass(PropagationBypass::ExistingTraceparent);
        }
        if ascii_eq_ignore_case(name, b"tracestate") {
            saw_tracestate = true;
        }
        if ascii_eq_ignore_case(name, b"upgrade")
            || (ascii_eq_ignore_case(name, b"connection") && contains_upgrade_token(value))
        {
            return PropagationDecision::Bypass(PropagationBypass::ProtocolUpgrade);
        }
        if ascii_eq_ignore_case(name, b"transfer-encoding") {
            return PropagationDecision::Bypass(PropagationBypass::UnsupportedTransferEncoding);
        }
        if ascii_eq_ignore_case(name, b"content-length") {
            if content_length.is_some() {
                return PropagationDecision::Bypass(PropagationBypass::AmbiguousContentLength);
            }
            let Some(parsed) = parse_content_length(value) else {
                return PropagationDecision::Bypass(PropagationBypass::InvalidContentLength);
            };
            content_length = Some(parsed);
        }
        line_start = line_end + 2;
    }

    let Some(body_bytes_in_message) = message.len().checked_sub(header_end) else {
        return PropagationDecision::Bypass(PropagationBypass::NotHttp1);
    };
    if content_length.map_or(body_bytes_in_message != 0, |declared| {
        body_bytes_in_message > declared
    }) {
        return PropagationDecision::Bypass(PropagationBypass::TrailingData);
    }
    if saw_tracestate {
        return PropagationDecision::Bypass(PropagationBypass::OrphanTracestate);
    }

    PropagationDecision::Inject {
        insert_at: request_line_end + 2,
    }
}

pub fn extract_traceparent(message: &[u8]) -> Option<TraceContext> {
    let (request_line_end, header_end) = http1_boundaries(message).ok()?;
    validate_request_line(message.get(..request_line_end)?).ok()?;
    let mut line_start = request_line_end + 2;
    while line_start + 2 <= header_end {
        let relative_end = find_crlf(message.get(line_start..header_end)?)?;
        let line_end = line_start + relative_end;
        if line_end == line_start {
            return None;
        }
        let line = message.get(line_start..line_end)?;
        let colon = find_byte(line, b':')?;
        let name = line.get(..colon)?;
        let value = line.get(colon + 1..)?;
        if ascii_eq_ignore_case(name, b"traceparent") {
            return parse_traceparent_value(trim_ows(value));
        }
        line_start = line_end + 2;
    }
    None
}

/// Copies a valid W3C `tracestate` value into a verifier-bounded caller-owned
/// buffer. Multiple HTTP fields are combined in wire order as required by the
/// HTTP binding. The opaque member values and member order are preserved.
pub fn copy_tracestate(
    message: &[u8],
    output: &mut [u8; MAX_TRACESTATE_BYTES],
) -> Result<Option<usize>, TraceStateError> {
    let (request_line_end, header_end) =
        http1_boundaries(message).map_err(|_| TraceStateError::MalformedHttp1)?;
    validate_request_line(
        message
            .get(..request_line_end)
            .ok_or(TraceStateError::MalformedHttp1)?,
    )
    .map_err(|_| TraceStateError::MalformedHttp1)?;

    let mut found = false;
    let mut output_len = 0_usize;
    let mut line_start = request_line_end + 2;
    while line_start + 2 <= header_end {
        let relative_end = find_crlf(
            message
                .get(line_start..header_end)
                .ok_or(TraceStateError::MalformedHttp1)?,
        )
        .ok_or(TraceStateError::MalformedHttp1)?;
        let line_end = line_start + relative_end;
        if line_end == line_start {
            break;
        }
        let line = message
            .get(line_start..line_end)
            .ok_or(TraceStateError::MalformedHttp1)?;
        let colon = find_byte(line, b':').ok_or(TraceStateError::MalformedHttp1)?;
        let name = line.get(..colon).ok_or(TraceStateError::MalformedHttp1)?;
        let value = trim_ows(
            line.get(colon + 1..)
                .ok_or(TraceStateError::MalformedHttp1)?,
        );
        if !valid_field_name(name) || !valid_field_value(value) {
            return Err(TraceStateError::MalformedHttp1);
        }
        if ascii_eq_ignore_case(name, b"tracestate") {
            if found {
                *output.get_mut(output_len).ok_or(TraceStateError::TooLong)? = b',';
                output_len += 1;
            }
            let end = output_len
                .checked_add(value.len())
                .filter(|end| *end <= MAX_TRACESTATE_BYTES)
                .ok_or(TraceStateError::TooLong)?;
            let destination = output
                .get_mut(output_len..end)
                .ok_or(TraceStateError::TooLong)?;
            for (destination, source) in destination.iter_mut().zip(value.iter().copied()) {
                *destination = source;
            }
            output_len = end;
            found = true;
        }
        line_start = line_end + 2;
    }

    if !found {
        return Ok(None);
    }
    validate_tracestate(output.get(..output_len).ok_or(TraceStateError::TooLong)?)?;
    Ok(Some(output_len))
}

/// Validates the W3C Trace Context list grammar without allocation.
pub fn validate_tracestate(value: &[u8]) -> Result<(), TraceStateError> {
    if value.len() > MAX_TRACESTATE_BYTES {
        return Err(TraceStateError::TooLong);
    }
    if value.is_empty() {
        return Err(TraceStateError::InvalidValue);
    }

    let mut member_start = 0_usize;
    let mut members = 0_usize;
    loop {
        members += 1;
        if members > 32 {
            return Err(TraceStateError::TooManyMembers);
        }
        let remaining = value
            .get(member_start..)
            .ok_or(TraceStateError::InvalidValue)?;
        let relative_end = find_byte(remaining, b',').unwrap_or(remaining.len());
        let member_end = member_start + relative_end;
        let member = trim_ows(
            value
                .get(member_start..member_end)
                .ok_or(TraceStateError::InvalidValue)?,
        );
        if member.is_empty() {
            return Err(TraceStateError::InvalidValue);
        }
        let equals = find_byte(member, b'=').ok_or(TraceStateError::InvalidKey)?;
        let key = member.get(..equals).ok_or(TraceStateError::InvalidKey)?;
        let member_value = member
            .get(equals + 1..)
            .ok_or(TraceStateError::InvalidValue)?;
        if !valid_tracestate_key(key) {
            return Err(TraceStateError::InvalidKey);
        }
        if !valid_tracestate_value(member_value) {
            return Err(TraceStateError::InvalidValue);
        }
        if tracestate_key_seen_before(value, member_start, key) {
            return Err(TraceStateError::DuplicateKey);
        }
        if member_end == value.len() {
            break;
        }
        member_start = member_end + 1;
    }
    Ok(())
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
    while index <= message.len() {
        let remaining = message
            .get(index..)
            .ok_or(PropagationBypass::IncompleteHeaders)?;
        let relative_end = find_crlf(remaining).ok_or(PropagationBypass::IncompleteHeaders)?;
        if relative_end == 0 {
            return Ok((request_line_end, index + 2));
        }
        index += relative_end + 2;
    }
    Err(PropagationBypass::IncompleteHeaders)
}

fn validate_request_line(line: &[u8]) -> Result<(), PropagationBypass> {
    let first_space = find_byte(line, b' ').ok_or(PropagationBypass::NotHttp1)?;
    let remaining = line
        .get(first_space + 1..)
        .ok_or(PropagationBypass::NotHttp1)?;
    let second_space = find_byte(remaining, b' ').ok_or(PropagationBypass::NotHttp1)?;
    let method = line.get(..first_space).ok_or(PropagationBypass::NotHttp1)?;
    let target = remaining
        .get(..second_space)
        .ok_or(PropagationBypass::NotHttp1)?;
    let version = remaining
        .get(second_space + 1..)
        .ok_or(PropagationBypass::NotHttp1)?;
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

fn valid_tracestate_key(key: &[u8]) -> bool {
    let Some(at) = find_byte(key, b'@') else {
        return key.len() <= 256
            && key.first().is_some_and(u8::is_ascii_lowercase)
            && key.iter().copied().all(valid_tracestate_key_byte);
    };
    let Some(system) = key.get(at + 1..) else {
        return false;
    };
    if find_byte(system, b'@').is_some() {
        return false;
    }
    let Some(tenant) = key.get(..at) else {
        return false;
    };
    !tenant.is_empty()
        && tenant.len() <= 241
        && tenant
            .first()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && tenant.iter().copied().all(valid_tracestate_key_byte)
        && !system.is_empty()
        && system.len() <= 14
        && system.first().is_some_and(u8::is_ascii_lowercase)
        && system.iter().copied().all(valid_tracestate_key_byte)
}

fn valid_tracestate_key_byte(byte: u8) -> bool {
    byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-' | b'*' | b'/')
}

fn valid_tracestate_value(value: &[u8]) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value.last().is_some_and(|byte| *byte != b' ')
        && value
            .iter()
            .all(|byte| (0x20..=0x7e).contains(byte) && *byte != b',' && *byte != b'=')
}

fn tracestate_key_seen_before(value: &[u8], current_start: usize, key: &[u8]) -> bool {
    let mut member_start = 0_usize;
    while member_start < current_start {
        let Some(remaining) = value.get(member_start..current_start) else {
            return false;
        };
        let relative_end = find_byte(remaining, b',').unwrap_or(remaining.len());
        let member_end = member_start + relative_end;
        let Some(member) = value.get(member_start..member_end) else {
            return false;
        };
        let member = trim_ows(member);
        if let Some(equals) = find_byte(member, b'=')
            && member.get(..equals).is_some_and(|existing| existing == key)
        {
            return true;
        }
        member_start = member_end.saturating_add(1);
    }
    false
}

fn parse_traceparent_value(value: &[u8]) -> Option<TraceContext> {
    if value.len() != 55
        || value.get(..3)? != b"00-"
        || value.get(35).copied()? != b'-'
        || value.get(52).copied()? != b'-'
    {
        return None;
    }
    let mut trace_id = [0_u8; 16];
    let mut span_id = [0_u8; 8];
    parse_hex(value.get(3..35)?, &mut trace_id)?;
    parse_hex(value.get(36..52)?, &mut span_id)?;
    let high = parse_hex_digit(value.get(53).copied()?)?;
    let low = parse_hex_digit(value.get(54).copied()?)?;
    TraceContext::new(trace_id, span_id, (high << 4) | low)
}

fn parse_content_length(value: &[u8]) -> Option<usize> {
    if value.is_empty() {
        return None;
    }
    let mut parsed = 0_usize;
    for byte in value {
        if !byte.is_ascii_digit() {
            return None;
        }
        // The planner only compares this value with a message bounded to
        // `MAX_PROPAGATION_HEADER_BYTES`. Capping larger values avoids a
        // target-dependent wide-multiply helper that BPF cannot call while
        // retaining the exact framing decision for every eligible message.
        if parsed <= MAX_PROPAGATION_HEADER_BYTES {
            parsed = parsed * 10 + (byte - b'0') as usize;
            if parsed > MAX_PROPAGATION_HEADER_BYTES {
                parsed = MAX_PROPAGATION_HEADER_BYTES + 1;
            }
        }
    }
    Some(parsed)
}

fn parse_hex(input: &[u8], output: &mut [u8]) -> Option<()> {
    if input.len() != output.len().checked_mul(2)? {
        return None;
    }
    let mut pairs = input.chunks_exact(2);
    for destination in output {
        let pair = pairs.next()?;
        let high = parse_hex_digit(pair.first().copied()?)?;
        let low = parse_hex_digit(pair.get(1).copied()?)?;
        *destination = (high << 4) | low;
    }
    pairs.remainder().is_empty().then_some(())
}

fn write_hex(input: &[u8], output: &mut [u8]) {
    for (source, pair) in input.iter().copied().zip(output.chunks_exact_mut(2)) {
        if let Some(high) = pair.first_mut() {
            *high = hex_digit(source >> 4);
        }
        if let Some(low) = pair.get_mut(1) {
            *low = hex_digit(source & 0x0f);
        }
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
        let Some(remaining) = value.get(start..) else {
            return false;
        };
        let relative_end = find_byte(remaining, b',').unwrap_or(remaining.len());
        let Some(token) = remaining.get(..relative_end) else {
            return false;
        };
        let token = trim_ows(token);
        if ascii_eq_ignore_case(token, b"upgrade") {
            return true;
        }
        if relative_end >= remaining.len() {
            break;
        }
        start += relative_end + 1;
    }
    false
}

fn trim_ows(value: &[u8]) -> &[u8] {
    let start = value
        .iter()
        .position(|byte| *byte != b' ' && *byte != b'\t')
        .unwrap_or(value.len());
    let end = value
        .iter()
        .rposition(|byte| *byte != b' ' && *byte != b'\t')
        .map_or(start, |index| index + 1);
    value.get(start..end).unwrap_or(&[])
}

fn ascii_eq_ignore_case(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .all(|(left, right)| left.eq_ignore_ascii_case(right))
}

fn find_crlf(value: &[u8]) -> Option<usize> {
    let mut previous_was_cr = false;
    for (index, byte) in value.iter().copied().enumerate() {
        // An iterator keeps this scanner panic-free even when the BPF target's
        // optimizer cannot relate adjacent integer indexes. A bounds-panic
        // shim is not a valid BPF subprogram terminator.
        if previous_was_cr && byte == b'\n' {
            return index.checked_sub(1);
        }
        previous_was_cr = byte == b'\r';
    }
    None
}

fn find_byte(value: &[u8], expected: u8) -> Option<usize> {
    for (index, byte) in value.iter().copied().enumerate() {
        if byte == expected {
            return Some(index);
        }
    }
    None
}

fn all_zero(value: &[u8]) -> bool {
    value.iter().all(|byte| *byte == 0)
}
