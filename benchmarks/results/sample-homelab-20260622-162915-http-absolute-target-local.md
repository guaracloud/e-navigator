# Homelab Sample: HTTP Absolute Target Local Proof

Run: `20260622-162915-http-absolute-target-local`

Scope: local parser proof only. No Kubernetes deployment was required for this
slice.

Feature slice:

- HTTP fixture parser extracts an absolute-form request target path into
  `url.path`.
- Valid absolute-form `http://` and `https://` authorities are extracted into
  `server.address`.
- Numeric absolute-form authority ports are extracted into `server.port`.
- Unsupported schemes, malformed userinfo authorities, invalid ports,
  out-of-range ports, and oversized authorities are dropped.
- Authorization and Cookie header values, query strings, and fragments are not
  copied into request attributes.

Local proof:

- `cargo test --locked -p e-navigator-protocol absolute_form -- --nocapture`
- `cargo test --locked -p e-navigator-protocol -- --nocapture`

Observed expected signal behavior:

- Parser attributes include `url.path = /orders/123` for
  `GET https://checkout.example.com:8443/orders/123?token=secret#frag HTTP/1.1`.
- Parser attributes include `server.address = checkout.example.com` for the
  same absolute-form request target.
- Parser attributes include `server.port = 8443` for the same absolute-form
  request target.
- Parser attributes do not include `Bearer secret`, `session=secret`, `secret`,
  or `frag`.
- Parser attributes do not include `url.path`, `server.address`, or
  `server.port` for `ftp://checkout.example.com/orders/123`,
  `https://user:pass@checkout.example.com/orders/123`,
  non-numeric ports, ports greater than `65535`, or a 254-byte authority host.

Not proven:

- Live HTTP/gRPC parsing from real traffic.
- Production service-topology extraction from live Kubernetes traffic.
- Route-template extraction such as `/checkout/{id}`.
- Retry, application error, or live request-ID extraction.
- Tempo, Alloy, OTLP collector, Pyroscope, or storage compatibility.
- Reduced overhead or reduced privilege.
