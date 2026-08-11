use e_navigator_context_propagation::{
    PropagationBypass, PropagationDecision, TRACEPARENT_HEADER_BYTES, TraceContext,
    extract_traceparent, format_traceparent_header, plan_http1_propagation,
};

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
fn bypasses_fragmented_upgraded_tunneled_and_body_bearing_messages() {
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
            b"POST / HTTP/1.1\r\nContent-Length: 4\r\n\r\n".as_slice(),
            PropagationBypass::BodyBearing,
        ),
        (
            b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n".as_slice(),
            PropagationBypass::BodyBearing,
        ),
        (
            b"POST / HTTP/1.1\r\nContent-Length: 4\r\n\r\ndata".as_slice(),
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
