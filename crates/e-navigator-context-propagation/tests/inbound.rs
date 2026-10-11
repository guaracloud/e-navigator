use e_navigator_context_propagation::valid_inbound_http1_request;

const CONTEXT: &str = "traceparent: 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01\r\n";

#[test]
fn only_one_complete_framed_request_can_establish_an_inbound_owner() {
    for framing in [
        "\r\n",
        "Content-Length: 4\r\n\r\ndata",
        "Transfer-Encoding: chunked\r\n\r\n4\r\ndata\r\n0\r\n\r\n",
    ] {
        let request = format!("POST / HTTP/1.1\r\n{CONTEXT}{framing}");
        assert!(
            valid_inbound_http1_request(request.as_bytes()),
            "{framing:?}"
        );
    }
    for framing in [
        "\r\nGET /other HTTP/1.1\r\n\r\n",
        "Content-Length: 4\r\n\r\nda",
        "Content-Length: 4\r\n\r\ndataGET /other HTTP/1.1\r\n\r\n",
        "Content-Length: 4\r\nContent-Length: 4\r\n\r\ndata",
        "Content-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\ndata",
        "Transfer-Encoding: chunked\r\n\r\n4\r\ndata\r\n",
        "Transfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /other HTTP/1.1\r\n\r\n",
        "Connection: upgrade\r\nUpgrade: websocket\r\n\r\n",
        "Connection: keep-alive, UpGrade\r\n\r\n",
        "Host: unfinished",
    ] {
        let request = format!("POST / HTTP/1.1\r\n{CONTEXT}{framing}");
        assert!(
            !valid_inbound_http1_request(request.as_bytes()),
            "{framing:?}"
        );
    }
}
