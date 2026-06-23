# Homelab Sample: HTTP Request Path Local Proof

Run: `20260622-144636-http-request-path-local`

Scope: local parser and generator proof only. No Kubernetes deployment was
required for this slice.

Feature slice:

- HTTP fixture parser extracts an origin-form request target path into a bounded
  `url.path` attribute.
- Query and fragment values are not copied into request attributes.
- Request correlation keeps bounded request attributes on generated request
  spans.
- Request dedupe treats spanless same-timestamp requests with different
  `url.path` values as distinct observations.

Local proof:

- `cargo test --locked -p e-navigator-protocol extracts_http_request_path_without_query_or_fragment -- --nocapture`
- `cargo test --locked -p e-navigator-generators duplicate_suppression_distinguishes_spanless_request_paths -- --nocapture`
- `cargo test --locked -p e-navigator-protocol -- --nocapture`
- `cargo test --locked -p e-navigator-generators -- --nocapture`
- `cargo fmt --all -- --check`

Observed expected signal behavior:

- Parser attributes include `http.request.method = GET`.
- Parser attributes include `url.path = /checkout/123`.
- Parser attributes do not include `token=secret` or `frag` from the request
  target.
- `generator.request_correlation` emits request spans that retain `url.path`.
- Dedupe does not suppress a spanless `/orders/456` request merely because a
  spanless `/checkout/123` request at the same timestamp was already observed.

Not proven:

- Live HTTP/gRPC parsing from real traffic.
- Route-template extraction such as `/checkout/{id}`.
- Retry, application error, or request-ID extraction.
- Kubernetes runtime behavior.
- trace backend, Alloy, OTLP collector, external profile backend, or storage compatibility.
- Reduced overhead or reduced privilege.
