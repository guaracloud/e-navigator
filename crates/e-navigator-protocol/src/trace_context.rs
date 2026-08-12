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
    if value.len() > max_bytes {
        return Err(TraceStateError::TooLong);
    }
    e_navigator_context_propagation::validate_tracestate(value.as_bytes()).map_err(|error| {
        match error {
            e_navigator_context_propagation::TraceStateError::TooLong => TraceStateError::TooLong,
            e_navigator_context_propagation::TraceStateError::TooManyMembers => {
                TraceStateError::TooManyMembers
            }
            e_navigator_context_propagation::TraceStateError::InvalidKey => {
                TraceStateError::InvalidKey
            }
            e_navigator_context_propagation::TraceStateError::InvalidValue
            | e_navigator_context_propagation::TraceStateError::MalformedHttp1 => {
                TraceStateError::InvalidValue
            }
            e_navigator_context_propagation::TraceStateError::DuplicateKey => {
                TraceStateError::DuplicateKey
            }
        }
    })
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
        assert_eq!(validate_tracestate("vendor=value", 512), Ok(()));
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
        for value in [
            "",
            "0vendor=value",
            ",vendor=value",
            "vendor=value,",
            "a=1,,b=2",
        ] {
            assert!(
                validate_tracestate(value, 512).is_err(),
                "accepted {value:?}"
            );
        }
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
