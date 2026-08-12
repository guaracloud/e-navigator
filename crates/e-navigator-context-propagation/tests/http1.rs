use e_navigator_context_propagation::{
    MAX_TRACESTATE_BYTES, PropagationBypass, PropagationDecision, TRACEPARENT_HEADER_BYTES,
    TraceContext, TraceStateError, copy_tracestate, extract_traceparent, format_traceparent_header,
    plan_http1_propagation, validate_tracestate,
};
use proptest::prelude::*;

const TRACE_ID: [u8; 16] = [
    0x4b, 0xf9, 0x2f, 0x35, 0x77, 0xb3, 0x4d, 0xa6, 0xa3, 0xce, 0x92, 0x9d, 0x0e, 0x0e, 0x47, 0x36,
];
const SPAN_ID: [u8; 8] = [0x00, 0xf0, 0x67, 0xaa, 0x0b, 0xa9, 0x02, 0xb7];

#[test]
fn plans_insertion_immediately_after_a_complete_http1_request_line() {
    let request = b"GET /orders HTTP/1.1\r\nHost: orders\r\nAccept: */*\r\n\r\n";

    assert_eq!(
        plan_http1_propagation(request),
        PropagationDecision::Inject { insert_at: 22 }
    );
}

#[test]
fn preserves_an_existing_traceparent_case_insensitively() {
    let request = b"GET / HTTP/1.1\r\nTraceParent: 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01\r\n\r\n";

    assert_eq!(
        plan_http1_propagation(request),
        PropagationDecision::Bypass(PropagationBypass::ExistingTraceparent)
    );
}

#[test]
fn bypasses_orphan_tracestate_instead_of_associating_it_with_a_new_trace() {
    let request = b"GET / HTTP/1.1\r\ntracestate: vendor=opaque\r\n\r\n";

    assert_eq!(
        plan_http1_propagation(request),
        PropagationDecision::Bypass(PropagationBypass::OrphanTracestate)
    );
}

#[test]
fn permits_content_length_bodies_when_the_current_message_cannot_cross_the_boundary() {
    for request in [
        b"POST /orders HTTP/1.1\r\nHost: api\r\nContent-Length: 4\r\n\r\ndata".as_slice(),
        b"POST /orders HTTP/1.1\r\nHost: api\r\nContent-Length: 4\r\n\r\nda".as_slice(),
        b"POST /orders HTTP/1.1\r\nHost: api\r\nContent-Length: 4\r\n\r\n".as_slice(),
    ] {
        assert_eq!(
            plan_http1_propagation(request),
            PropagationDecision::Inject { insert_at: 23 }
        );
    }
}

#[test]
fn bypasses_fragmented_upgraded_tunneled_and_ambiguously_framed_messages() {
    for (request, reason) in [
        (
            b"GET / HTTP/1.1\r\nHost: api\r\n".as_slice(),
            PropagationBypass::IncompleteHeaders,
        ),
        (
            b"GET /chat HTTP/1.1\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n".as_slice(),
            PropagationBypass::ProtocolUpgrade,
        ),
        (
            b"CONNECT api:443 HTTP/1.1\r\nHost: api\r\n\r\n".as_slice(),
            PropagationBypass::UnsupportedMethod,
        ),
        (
            b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n".as_slice(),
            PropagationBypass::UnsupportedTransferEncoding,
        ),
        (
            b"POST / HTTP/1.1\r\nContent-Length: four\r\n\r\n".as_slice(),
            PropagationBypass::InvalidContentLength,
        ),
        (
            b"POST / HTTP/1.1\r\nContent-Length: 4\r\nContent-Length: 4\r\n\r\ndata".as_slice(),
            PropagationBypass::AmbiguousContentLength,
        ),
        (
            b"POST / HTTP/1.1\r\nContent-Length: 4\r\n\r\ndataGET /next HTTP/1.1\r\n\r\n"
                .as_slice(),
            PropagationBypass::TrailingData,
        ),
        (
            b"POST / HTTP/1.1\r\nHost: api\r\n\r\ndata".as_slice(),
            PropagationBypass::TrailingData,
        ),
    ] {
        assert_eq!(
            plan_http1_propagation(request),
            PropagationDecision::Bypass(reason)
        );
    }
}

#[test]
fn bypasses_malformed_header_names_and_control_bearing_lines() {
    for request in [
        b"GET / HTTP/1.1\r\nBad Header: value\r\n\r\n".as_slice(),
        b"GET / HTTP/1.1\r\n: value\r\n\r\n".as_slice(),
        b"GET / HTTP/1.1\r\nHost: api\nInjected: value\r\n\r\n".as_slice(),
    ] {
        assert_eq!(
            plan_http1_propagation(request),
            PropagationDecision::Bypass(PropagationBypass::NotHttp1)
        );
    }
}

#[test]
fn formats_and_extracts_the_exact_w3c_context() {
    let context = TraceContext::new(TRACE_ID, SPAN_ID, 1).expect("context is valid");
    let header = format_traceparent_header(context);

    assert_eq!(header.len(), TRACEPARENT_HEADER_BYTES);
    assert_eq!(
        &header,
        b"traceparent: 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01\r\n"
    );

    let mut request = b"GET / HTTP/1.1\r\n".to_vec();
    request.extend_from_slice(&header);
    request.extend_from_slice(b"Host: api\r\n\r\n");
    assert_eq!(extract_traceparent(&request), Some(context));
}

#[test]
fn rejects_zero_ids_and_noncanonical_traceparent_values() {
    assert_eq!(TraceContext::new([0; 16], SPAN_ID, 1), None);
    assert_eq!(TraceContext::new(TRACE_ID, [0; 8], 1), None);

    for request in [
        b"GET / HTTP/1.1\r\ntraceparent: 00-4BF92F3577B34DA6A3CE929D0E0E4736-00f067aa0ba902b7-01\r\n\r\n".as_slice(),
        b"GET / HTTP/1.1\r\ntraceparent: 01-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01\r\n\r\n".as_slice(),
        b"GET / HTTP/1.1\r\ntraceparent: 00-00000000000000000000000000000000-00f067aa0ba902b7-01\r\n\r\n".as_slice(),
    ] {
        assert_eq!(extract_traceparent(request), None);
    }
}

#[test]
fn validates_and_combines_w3c_tracestate_fields_in_wire_order() {
    let request = b"GET / HTTP/1.1\r\ntraceparent: 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01\r\ntracestate: rojo=00f067aa0ba902b7\r\nTraceState: congo=t61rcWkgMzE\r\n\r\n";
    let mut output = [0_u8; MAX_TRACESTATE_BYTES];

    let len = copy_tracestate(request, &mut output)
        .expect("valid tracestate")
        .expect("tracestate present");

    assert_eq!(&output[..len], b"rojo=00f067aa0ba902b7,congo=t61rcWkgMzE");
    assert_eq!(validate_tracestate(&output[..len]), Ok(()));
}

#[test]
fn rejects_invalid_tracestate_without_invalidating_traceparent() {
    for (value, reason) in [
        (
            b"vendor=one,vendor=two".as_slice(),
            TraceStateError::DuplicateKey,
        ),
        (b"Vendor=value".as_slice(), TraceStateError::InvalidKey),
        (b"0vendor=value".as_slice(), TraceStateError::InvalidKey),
        (
            b"vendor=has=equals".as_slice(),
            TraceStateError::InvalidValue,
        ),
        (b"vendor= ".as_slice(), TraceStateError::InvalidValue),
        (b"".as_slice(), TraceStateError::InvalidValue),
        (b",vendor=value".as_slice(), TraceStateError::InvalidValue),
        (b"vendor=value,".as_slice(), TraceStateError::InvalidValue),
        (b"a=1,,b=2".as_slice(), TraceStateError::InvalidValue),
    ] {
        assert_eq!(validate_tracestate(value), Err(reason));
    }

    let too_many = (0..33)
        .map(|index| format!("v{index}=x"))
        .collect::<Vec<_>>()
        .join(",");
    assert_eq!(
        validate_tracestate(too_many.as_bytes()),
        Err(TraceStateError::TooManyMembers)
    );

    let mut oversized = [b'a'; MAX_TRACESTATE_BYTES + 1];
    oversized[6] = b'=';
    assert_eq!(
        validate_tracestate(&oversized),
        Err(TraceStateError::TooLong)
    );

    let request = b"GET / HTTP/1.1\r\ntraceparent: 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01\r\ntracestate: vendor=one,vendor=two\r\n\r\n";
    let mut output = [0_u8; MAX_TRACESTATE_BYTES];
    assert_eq!(
        copy_tracestate(request, &mut output),
        Err(TraceStateError::DuplicateKey)
    );
    assert_eq!(
        extract_traceparent(request),
        TraceContext::new(TRACE_ID, SPAN_ID, 1)
    );
}

proptest! {
    #[test]
    fn bounded_parsers_are_panic_free_for_arbitrary_wire_bytes(message in prop::collection::vec(any::<u8>(), 0..=1200)) {
        let _ = plan_http1_propagation(&message);
        let _ = extract_traceparent(&message);
        let _ = validate_tracestate(&message);
        let mut output = [0_u8; MAX_TRACESTATE_BYTES];
        let _ = copy_tracestate(&message, &mut output);
    }
}
