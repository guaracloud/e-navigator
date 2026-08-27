use super::*;

#[repr(C)]
struct BpfHttpHeaderState {
    request: *const u8,
    header_hash: u64,
    len: u32,
    total_len: u32,
    start: u32,
    component_len: u32,
    content_length: u32,
    header_end: u32,
    phase: u8,
    field_kind: u8,
    result: u8,
    content_length_name: bool,
    transfer_encoding_name: bool,
    ending_headers: bool,
    saw_content_length: bool,
    saw_transfer_encoding: bool,
    value_started: bool,
    value_trailing_ows: bool,
}

#[repr(C)]
struct BpfHttpChunkedState {
    request: *const u8,
    trailer_hash: u64,
    start: u32,
    len: u32,
    chunk_size: u32,
    chunk_remaining: u32,
    component_len: u32,
    phase: u8,
    result: u8,
    size_started: bool,
    extension_started: bool,
    ending_trailers: bool,
}

#[inline(never)]
fn bpf_http1_headers(event: &RawHttpRequestEvent, insert_at: u16) -> Option<u32> {
    let start = u32::from(insert_at);
    if start >= event.request_len {
        return None;
    }
    let mut state = BpfHttpHeaderState {
        request: event.request.as_ptr(),
        header_hash: HTTP_FNV_OFFSET,
        len: event.request_len,
        total_len: event.request_total_len,
        start,
        component_len: 0,
        content_length: 0,
        header_end: 0,
        phase: HTTP_PARSE_HEADER_NAME,
        field_kind: HTTP_FIELD_OTHER,
        result: HTTP_PLAN_PENDING,
        content_length_name: true,
        transfer_encoding_name: true,
        ending_headers: false,
        saw_content_length: false,
        saw_transfer_encoding: false,
        value_started: false,
        value_trailing_ows: false,
    };
    let callback = bpf_http_header_step as *const () as *mut c_void;
    let context = (&mut state as *mut BpfHttpHeaderState).cast::<c_void>();
    let remaining = event.request_len - start;
    let loops = unsafe { bpf_loop(remaining, callback, context, 0) };
    if loops < 0 || state.result != HTTP_PLAN_VALID {
        return None;
    }
    Some(
        state.header_end
            | if state.saw_transfer_encoding {
                HTTP_HEADER_PLAN_CHUNKED
            } else {
                0
            },
    )
}

unsafe extern "C" fn bpf_http_header_step(relative: u64, context: *mut c_void) -> i64 {
    let state = unsafe { &mut *context.cast::<BpfHttpHeaderState>() };
    let index = u64::from(state.start) + relative;
    if index >= u64::from(state.len) || index >= HTTP_REQUEST_BYTES as u64 {
        state.result = HTTP_PLAN_INVALID;
        return 1;
    }
    let byte = unsafe { *state.request.add(index as usize) };
    let phase = state.phase & 7;
    if phase == HTTP_PARSE_HEADER_NAME {
        if byte == b'\r' {
            if state.component_len != 0 {
                state.result = HTTP_PLAN_INVALID;
                return 1;
            }
            state.ending_headers = true;
            state.phase = HTTP_PARSE_HEADER_LF;
        } else if byte == b':' {
            if state.component_len == 0
                || bpf_http_header_requires_bypass(state.component_len, state.header_hash)
            {
                state.result = HTTP_PLAN_INVALID;
                return 1;
            }
            state.field_kind = if state.component_len == 14 && state.content_length_name {
                HTTP_FIELD_CONTENT_LENGTH
            } else if state.component_len == 17 && state.transfer_encoding_name {
                HTTP_FIELD_TRANSFER_ENCODING
            } else {
                HTTP_FIELD_OTHER
            };
            if (state.field_kind == HTTP_FIELD_CONTENT_LENGTH && state.saw_content_length)
                || (state.field_kind == HTTP_FIELD_TRANSFER_ENCODING && state.saw_transfer_encoding)
            {
                state.result = HTTP_PLAN_INVALID;
                return 1;
            }
            state.phase = HTTP_PARSE_HEADER_VALUE;
            state.component_len = 0;
            state.value_started = false;
            state.value_trailing_ows = false;
        } else {
            if !bpf_http_field_name_byte(byte) {
                state.result = HTTP_PLAN_INVALID;
                return 1;
            }
            let lowercase = byte.to_ascii_lowercase();
            state.header_hash =
                (state.header_hash ^ u64::from(lowercase)).wrapping_mul(HTTP_FNV_PRIME);
            state.content_length_name = state.content_length_name
                && lowercase == bpf_content_length_name_byte(state.component_len);
            state.transfer_encoding_name = state.transfer_encoding_name
                && lowercase == bpf_transfer_encoding_name_byte(state.component_len);
            state.component_len += 1;
        }
    } else if phase == HTTP_PARSE_HEADER_VALUE {
        if byte == b'\r' {
            if state.field_kind == HTTP_FIELD_CONTENT_LENGTH {
                if !state.value_started {
                    state.result = HTTP_PLAN_INVALID;
                    return 1;
                }
                state.saw_content_length = true;
            } else if state.field_kind == HTTP_FIELD_TRANSFER_ENCODING {
                if !state.value_started || state.component_len != 7 {
                    state.result = HTTP_PLAN_INVALID;
                    return 1;
                }
                state.saw_transfer_encoding = true;
            }
            state.ending_headers = false;
            state.phase = HTTP_PARSE_HEADER_LF;
        } else {
            if !bpf_http_field_value_byte(byte) {
                state.result = HTTP_PLAN_INVALID;
                return 1;
            }
            if state.field_kind == HTTP_FIELD_CONTENT_LENGTH {
                let ows = byte == b' ' || byte == b'\t';
                if ows {
                    if state.value_started {
                        state.value_trailing_ows = true;
                    }
                } else {
                    if state.value_trailing_ows || !byte.is_ascii_digit() {
                        state.result = HTTP_PLAN_INVALID;
                        return 1;
                    }
                    state.value_started = true;
                    let Some(content_length) = state
                        .content_length
                        .checked_mul(10)
                        .and_then(|value| value.checked_add(u32::from(byte - b'0')))
                    else {
                        state.result = HTTP_PLAN_INVALID;
                        return 1;
                    };
                    state.content_length = content_length;
                }
            } else if state.field_kind == HTTP_FIELD_TRANSFER_ENCODING {
                let ows = byte == b' ' || byte == b'\t';
                if ows {
                    if state.value_started {
                        state.value_trailing_ows = true;
                    }
                } else {
                    if state.value_trailing_ows
                        || state.component_len >= 7
                        || byte.to_ascii_lowercase()
                            != bpf_transfer_encoding_value_byte(state.component_len)
                    {
                        state.result = HTTP_PLAN_INVALID;
                        return 1;
                    }
                    state.value_started = true;
                    state.component_len += 1;
                }
            }
        }
    } else if phase == HTTP_PARSE_HEADER_LF {
        if byte != b'\n' {
            state.result = HTTP_PLAN_INVALID;
            return 1;
        }
        if state.ending_headers {
            let header_end = index + 1;
            if u64::from(state.total_len) < header_end {
                state.result = HTTP_PLAN_INVALID;
                return 1;
            }
            state.header_end = header_end as u32;
            if state.saw_transfer_encoding {
                if state.saw_content_length
                    || (state.total_len > state.len && header_end != u64::from(state.len))
                {
                    state.result = HTTP_PLAN_INVALID;
                    return 1;
                }
                state.result = HTTP_PLAN_VALID;
                return 1;
            }
            let body_bytes = u64::from(state.total_len) - header_end;
            if (!state.saw_content_length && body_bytes != 0)
                || (state.saw_content_length && body_bytes > u64::from(state.content_length))
            {
                state.result = HTTP_PLAN_INVALID;
                return 1;
            }
            state.result = HTTP_PLAN_VALID;
            return 1;
        }
        state.phase = HTTP_PARSE_HEADER_NAME;
        state.component_len = 0;
        state.header_hash = HTTP_FNV_OFFSET;
        state.content_length_name = true;
        state.transfer_encoding_name = true;
    } else {
        state.result = HTTP_PLAN_INVALID;
        return 1;
    }
    0
}

#[inline(never)]
fn bpf_http1_chunked_body(event: &RawHttpRequestEvent, header_end: u32) -> bool {
    if header_end > event.request_len {
        return false;
    }
    if header_end == event.request_len {
        return true;
    }
    let mut state = BpfHttpChunkedState {
        request: event.request.as_ptr(),
        trailer_hash: HTTP_FNV_OFFSET,
        start: header_end,
        len: event.request_len,
        chunk_size: 0,
        chunk_remaining: 0,
        component_len: 0,
        phase: HTTP_CHUNK_SIZE,
        result: HTTP_PLAN_PENDING,
        size_started: false,
        extension_started: false,
        ending_trailers: false,
    };
    let callback = bpf_http_chunked_body_step as *const () as *mut c_void;
    let context = (&mut state as *mut BpfHttpChunkedState).cast::<c_void>();
    let remaining = event.request_len - header_end;
    let loops = unsafe { bpf_loop(remaining, callback, context, 0) };
    loops >= 0 && state.result != HTTP_PLAN_INVALID
}

unsafe extern "C" fn bpf_http_chunked_body_step(relative: u64, context: *mut c_void) -> i64 {
    let state = unsafe { &mut *context.cast::<BpfHttpChunkedState>() };
    let index = u64::from(state.start) + relative;
    if index >= u64::from(state.len) || index >= HTTP_REQUEST_BYTES as u64 {
        state.result = HTTP_PLAN_INVALID;
        return 1;
    }
    let byte = unsafe { *state.request.add(index as usize) };
    let phase = state.phase & 15;
    if phase == HTTP_CHUNK_SIZE {
        if let Some(digit) = bpf_http_hex_digit(byte) {
            let Some(chunk_size) = state
                .chunk_size
                .checked_mul(16)
                .and_then(|value| value.checked_add(u32::from(digit)))
            else {
                state.result = HTTP_PLAN_INVALID;
                return 1;
            };
            state.chunk_size = chunk_size;
            state.size_started = true;
        } else if byte == b';' {
            if !state.size_started {
                state.result = HTTP_PLAN_INVALID;
                return 1;
            }
            state.phase = HTTP_CHUNK_EXTENSION;
            state.extension_started = false;
        } else if byte == b'\r' {
            if !state.size_started {
                state.result = HTTP_PLAN_INVALID;
                return 1;
            }
            state.phase = HTTP_CHUNK_SIZE_LF;
        } else {
            state.result = HTTP_PLAN_INVALID;
            return 1;
        }
    } else if phase == HTTP_CHUNK_EXTENSION {
        if byte == b'\r' {
            if !state.extension_started {
                state.result = HTTP_PLAN_INVALID;
                return 1;
            }
            state.phase = HTTP_CHUNK_SIZE_LF;
        } else if bpf_http_field_value_byte(byte) {
            state.extension_started = true;
        } else {
            state.result = HTTP_PLAN_INVALID;
            return 1;
        }
    } else if phase == HTTP_CHUNK_SIZE_LF {
        if byte != b'\n' {
            state.result = HTTP_PLAN_INVALID;
            return 1;
        }
        if state.chunk_size == 0 {
            state.phase = HTTP_CHUNK_TRAILER_NAME;
            state.component_len = 0;
            state.trailer_hash = HTTP_FNV_OFFSET;
            state.ending_trailers = false;
        } else {
            state.chunk_remaining = state.chunk_size;
            state.phase = HTTP_CHUNK_DATA;
        }
    } else if phase == HTTP_CHUNK_DATA {
        if state.chunk_remaining == 0 {
            state.result = HTTP_PLAN_INVALID;
            return 1;
        }
        state.chunk_remaining -= 1;
        if state.chunk_remaining == 0 {
            state.phase = HTTP_CHUNK_DATA_CR;
        }
    } else if phase == HTTP_CHUNK_DATA_CR {
        if byte != b'\r' {
            state.result = HTTP_PLAN_INVALID;
            return 1;
        }
        state.phase = HTTP_CHUNK_DATA_LF;
    } else if phase == HTTP_CHUNK_DATA_LF {
        if byte != b'\n' {
            state.result = HTTP_PLAN_INVALID;
            return 1;
        }
        state.phase = HTTP_CHUNK_SIZE;
        state.chunk_size = 0;
        state.size_started = false;
        state.extension_started = false;
    } else if phase == HTTP_CHUNK_TRAILER_NAME {
        if byte == b'\r' {
            if state.component_len != 0 {
                state.result = HTTP_PLAN_INVALID;
                return 1;
            }
            state.ending_trailers = true;
            state.phase = HTTP_CHUNK_TRAILER_LF;
        } else if byte == b':' {
            if state.component_len == 0
                || (state.component_len == 11 && state.trailer_hash == HTTP_TRACEPARENT_HASH)
                || (state.component_len == 10 && state.trailer_hash == HTTP_TRACESTATE_HASH)
            {
                state.result = HTTP_PLAN_INVALID;
                return 1;
            }
            state.ending_trailers = false;
            state.phase = HTTP_CHUNK_TRAILER_VALUE;
        } else if bpf_http_field_name_byte(byte) {
            let lowercase = byte.to_ascii_lowercase();
            state.trailer_hash =
                (state.trailer_hash ^ u64::from(lowercase)).wrapping_mul(HTTP_FNV_PRIME);
            state.component_len = state.component_len.saturating_add(1);
        } else {
            state.result = HTTP_PLAN_INVALID;
            return 1;
        }
    } else if phase == HTTP_CHUNK_TRAILER_VALUE {
        if byte == b'\r' {
            state.ending_trailers = false;
            state.phase = HTTP_CHUNK_TRAILER_LF;
        } else if !bpf_http_field_value_byte(byte) {
            state.result = HTTP_PLAN_INVALID;
            return 1;
        }
    } else if phase == HTTP_CHUNK_TRAILER_LF {
        if byte != b'\n' {
            state.result = HTTP_PLAN_INVALID;
            return 1;
        }
        if state.ending_trailers {
            state.result = if index + 1 == u64::from(state.len) {
                HTTP_PLAN_VALID
            } else {
                HTTP_PLAN_INVALID
            };
            return 1;
        }
        state.phase = HTTP_CHUNK_TRAILER_NAME;
        state.component_len = 0;
        state.trailer_hash = HTTP_FNV_OFFSET;
    } else {
        state.result = HTTP_PLAN_INVALID;
        return 1;
    }
    0
}

/// Runs the byte state machine through `bpf_loop`, which verifies the parser
/// body once rather than multiplying its state space by the 1,024-byte bound.
#[inline(never)]
pub(super) fn plan_bpf_http1_propagation_loop(event: &RawHttpRequestEvent) -> Option<u16> {
    if event.request_len == 0 || event.request_len as usize > HTTP_REQUEST_BYTES {
        return None;
    }
    let insert_at = bpf_http1_request_line(event)?;
    let header_plan = bpf_http1_headers(event, insert_at)?;
    if header_plan & HTTP_HEADER_PLAN_CHUNKED != 0 {
        let header_end = header_plan & !HTTP_HEADER_PLAN_CHUNKED;
        if event.request_total_len != event.request_len
            || !bpf_http1_chunked_body(event, header_end)
        {
            return None;
        }
    }
    Some(insert_at)
}
