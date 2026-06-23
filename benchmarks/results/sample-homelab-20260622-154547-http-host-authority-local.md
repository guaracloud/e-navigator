# Homelab Sample: HTTP Host Authority Local Proof

Run: `20260622-154547-http-host-authority-local`

Scope: local parser proof only. No Kubernetes deployment was required for this
slice.

Feature slice:

- HTTP fixture parser extracts a valid `Host` authority into `server.address`.
- Numeric Host authority ports are extracted into `server.port`.
- Malformed userinfo authorities, invalid ports, out-of-range ports, and
  oversized host values are dropped.
- Authorization and Cookie header values are not copied into request
  attributes.

Local proof:

- `cargo test --locked -p e-navigator-protocol http_host_authority -- --nocapture`
- `cargo test --locked -p e-navigator-protocol -- --nocapture`
- `cargo fmt --all -- --check`

Observed expected signal behavior:

- Parser attributes include `server.address = checkout.example.com` for
  `Host: checkout.example.com:8443`.
- Parser attributes include `server.port = 8443` for
  `Host: checkout.example.com:8443`.
- Parser attributes do not include `Bearer secret` or `session=secret`.
- Parser attributes do not include `server.address` or `server.port` for
  `user:pass@checkout.example.com`, non-numeric ports, ports greater than
  `65535`, or a 254-byte host value.

Not proven:

- Live HTTP/gRPC parsing from real traffic.
- Production service-topology extraction from live Kubernetes traffic.
- Route-template extraction such as `/checkout/{id}`.
- Retry, application error, or live request-ID extraction.
- trace backend, Alloy, OTLP collector, external profile backend, or storage compatibility.
- Reduced overhead or reduced privilege.
