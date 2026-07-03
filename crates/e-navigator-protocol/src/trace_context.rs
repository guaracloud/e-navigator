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

fn is_lower_hex(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_all_zero(value: &str) -> bool {
    value.bytes().all(|byte| byte == b'0')
}
