#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceContext {
    pub version: String,
    pub trace_id: String,
    pub span_id: String,
    pub flags: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TraceContextError {
    Malformed,
    InvalidHex,
    ReservedVersion,
    AllZeroTraceId,
    AllZeroSpanId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TraceStateError {
    TooLong,
    TooManyMembers,
    InvalidKey,
    InvalidValue,
    DuplicateKey,
}

pub fn parse_traceparent(value: &str) -> Result<TraceContext, TraceContextError> {
    let mut parts = value.split('-');
    let version = parts.next().ok_or(TraceContextError::Malformed)?;
    let trace_id = parts.next().ok_or(TraceContextError::Malformed)?;
    let span_id = parts.next().ok_or(TraceContextError::Malformed)?;
    let flags = parts.next().ok_or(TraceContextError::Malformed)?;
    if parts.next().is_some()
        || version.len() != 2
        || trace_id.len() != 32
        || span_id.len() != 16
        || flags.len() != 2
    {
        return Err(TraceContextError::Malformed);
    }
    if !is_lower_hex(version)
        || !is_lower_hex(trace_id)
        || !is_lower_hex(span_id)
        || !is_lower_hex(flags)
    {
        return Err(TraceContextError::InvalidHex);
    }
    if version == "ff" {
        return Err(TraceContextError::ReservedVersion);
    }
    if is_all_zero(trace_id) {
        return Err(TraceContextError::AllZeroTraceId);
    }
    if is_all_zero(span_id) {
        return Err(TraceContextError::AllZeroSpanId);
    }

    Ok(TraceContext {
        version: version.to_ascii_lowercase(),
        trace_id: trace_id.to_ascii_lowercase(),
        span_id: span_id.to_ascii_lowercase(),
        flags: flags.to_ascii_lowercase(),
    })
}

/// Validates W3C Trace Context `tracestate` without retaining or decoding
/// vendor values. Callers may forward the original value only through a
/// contract that explicitly permits it; E-Navigator records validity and
/// discards the opaque value at its signal boundary.
pub fn validate_tracestate(value: &str, max_bytes: usize) -> Result<(), TraceStateError> {
    if value.len() > max_bytes.min(512) {
        return Err(TraceStateError::TooLong);
    }

    let mut keys = std::collections::BTreeSet::new();
    let mut members = 0_usize;
    for raw_member in value.split(',') {
        members += 1;
        if members > 32 {
            return Err(TraceStateError::TooManyMembers);
        }
        let member = raw_member.trim_matches([' ', '\t']);
        if member.is_empty() {
            continue;
        }
        let Some((key, member_value)) = member.split_once('=') else {
            return Err(TraceStateError::InvalidKey);
        };
        if !valid_tracestate_key(key) {
            return Err(TraceStateError::InvalidKey);
        }
        if !keys.insert(key) {
            return Err(TraceStateError::DuplicateKey);
        }
        if member_value.is_empty()
            || member_value.len() > 256
            || member_value.ends_with(' ')
            || !member_value
                .bytes()
                .all(|byte| (0x20..=0x7e).contains(&byte) && byte != b',' && byte != b'=')
        {
            return Err(TraceStateError::InvalidValue);
        }
    }
    Ok(())
}

fn valid_tracestate_key(key: &str) -> bool {
    !key.is_empty()
        && key.len() <= 256
        && valid_key_start(key.as_bytes()[0])
        && key.bytes().all(valid_key_byte)
}

fn valid_key_start(byte: u8) -> bool {
    byte.is_ascii_lowercase() || byte.is_ascii_digit()
}

fn valid_key_byte(byte: u8) -> bool {
    byte.is_ascii_lowercase()
        || byte.is_ascii_digit()
        || matches!(byte, b'_' | b'-' | b'*' | b'/' | b'@')
}

fn is_lower_hex(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_all_zero(value: &str) -> bool {
    value.bytes().all(|byte| byte == b'0')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tracestate_accepts_bounded_w3c_members() {
        assert_eq!(
            validate_tracestate("vendor=value,tenant@system=opaque-1", 512),
            Ok(())
        );
        assert_eq!(validate_tracestate("0vendor=value,,\t", 512), Ok(()));
    }

    #[test]
    fn tracestate_rejects_duplicates_invalid_values_and_excess_members() {
        assert_eq!(
            validate_tracestate("vendor=one,vendor=two", 512),
            Err(TraceStateError::DuplicateKey)
        );
        assert_eq!(
            validate_tracestate("Vendor=value", 512),
            Err(TraceStateError::InvalidKey)
        );
        assert_eq!(
            validate_tracestate("vendor=has=equals", 512),
            Err(TraceStateError::InvalidValue)
        );
        let too_many = (0..33)
            .map(|index| format!("v{index}=x"))
            .collect::<Vec<_>>()
            .join(",");
        assert_eq!(
            validate_tracestate(&too_many, 512),
            Err(TraceStateError::TooManyMembers)
        );
    }
}
