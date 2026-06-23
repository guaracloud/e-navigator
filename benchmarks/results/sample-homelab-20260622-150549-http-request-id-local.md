# Homelab Sample: HTTP Request ID Local Proof

Run: `20260622-150549-http-request-id-local`

Scope: local parser proof only. No Kubernetes deployment was required for this
slice.

Feature slice:

- HTTP fixture parser extracts `X-Request-ID` or `Request-ID` into
  `http.request.id`.
- Request ID values are bounded to 128 bytes.
- Oversized request ID values are dropped.
- Authorization and Cookie header values are not copied into request
  attributes.
- Existing request correlation preserves bounded request attributes on generated
  request spans.

Local proof:

- `cargo test --locked -p e-navigator-protocol extracts_bounded_http_request_id_without_secret_headers -- --nocapture`
- `cargo test --locked -p e-navigator-protocol -- --nocapture`
- `cargo test --locked -p e-navigator-generators request_span_preserves_bounded_request_id_attribute -- --nocapture`
- `cargo fmt --all -- --check`
- `scripts/quality.sh`

Observed expected signal behavior:

- Parser attributes include `http.request.method = GET`.
- Parser attributes include `url.path = /checkout/123` when attribute budget
  allows it.
- Parser attributes include `http.request.id = req-12345` for a bounded
  `X-Request-ID` header.
- Parser attributes do not include `Bearer secret` or `session=secret`.
- Parser attributes do not include `http.request.id` for a 129-byte request ID.
- `generator.request_correlation` emits request spans that retain bounded
  `http.request.id`.

Not proven:

- Live HTTP/gRPC parsing from real traffic.
- Route-template extraction such as `/checkout/{id}`.
- Retry or application error extraction.
- Request ID extraction from live Kubernetes traffic.
- trace backend, Alloy, OTLP collector, external profile backend, or storage compatibility.
- Reduced overhead or reduced privilege.
