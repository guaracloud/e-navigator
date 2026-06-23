# Homelab HTTP Three-Iovec Bounded Proof 20260623-033542

## Scope

- Context: `staging`
- Namespace: `e-navigator-bench`
- Commit: `30c202690ad7ff5282ed355bda54af8b28eca7b8`
- Image tag: `ghcr.io/e-navigator/e-navigator:sha-30c2026`
- Image index digest:
  `sha256:6dfffd7dd40a76a1c18573c8a4f85677518228a2c45ac8a4ee042f30ad11d000`
- Linux amd64 digest:
  `sha256:2d17c1e7aeccc59c3ac73ef7b32684b9215b8b0db4f138376b0f0f32ef24778c`
- Baseline restored digest:
  `sha256:90b571bf89ac36c1432a503ad9b9add7abd7604579533c1912201568db1d5bfc`
- Raw evidence directory:
  `benchmarks/results/raw/20260623-033542-http-three-iovec-bounded-live/`

## Build And Publication

- Local TDD first failed the HTTP request capture guard because the BPF and
  userspace event shape did not yet expose an explicit 96-byte iovec slot
  bound.
- Commit `30c2026` kept three fixed HTTP iovec slots, changed the per-slot
  bound to 96 bytes, derived the raw request buffer from that bound, and kept
  userspace compaction aligned with the BPF event shape.
- Focused guard and decoder tests passed.
- Full local gate passed: `scripts/quality.sh`.
- GitHub CI run `28006891441`: success.
- GitHub image publication run `28006891438`: success.

## Live Run

- Preflight confirmed `kubectl config current-context` was `staging`.
- All live Kubernetes actions were limited to namespace `e-navigator-bench`.
- Baseline before test: Helm revision 93, digest
  `sha256:90b571bf89ac36c1432a503ad9b9add7abd7604579533c1912201568db1d5bfc`,
  DaemonSet `2/2` Ready.
- Test rollout: Helm revision 94 with `source.aya_http` and
  `generator.request_correlation` enabled.
- Test image:
  `ghcr.io/e-navigator/e-navigator@sha256:6dfffd7dd40a76a1c18573c8a4f85677518228a2c45ac8a4ee042f30ad11d000`.
- The DaemonSet rolled out and stayed `2/2` Ready with zero restarts.
- JSON stdout showed `protocol_request_observation` from `source.aya_http` and
  `request_span_observation` from `generator.request_correlation` after the
  rollout, proving the previous verifier-load blocker was gone for the bounded
  image.

## Workloads

- Three-iovec proof job: `http-iovec3-033542`, pinned to `homelab-02`.
  - Path: `/proof/iovec3-033542`.
  - Workload log: `three_iovec_requests=80 ok=80 errors=0`.
  - Proof iovec lengths: `(24, 27, 71)`, all under the 96-byte slot bound.
  - Request data was split as request line, Host header, then request-ID/run
    headers plus terminator across three separate `os.writev` buffers.
- Two-iovec control job: `http-iovec2-033542`, pinned to `homelab-02`.
  - Path: `/proof/i2diag-033542`.
  - Workload log: `two_iovec_requests=20 ok=20 errors=0`.

## Observed Signals

Filtered E-Navigator JSON stdout contained:

- Three-iovec proof path:
  - 80 `protocol_request_observation` records from `source.aya_http`.
  - 80 `request_span_observation` records from
    `generator.request_correlation`.
  - 80 unique `i3-proof-*` request IDs.
  - All 160 measured proof records included Kubernetes namespace
    `e-navigator-bench`, pod `http-iovec3-033542-gsbxx`, and container
    `workload`.
- Two-iovec control path:
  - 20 `protocol_request_observation` records.
  - 20 `request_span_observation` records.

## Cleanup And Restore

- Deleted Jobs `http-iovec3-033542` and `http-iovec2-033542` from
  `e-navigator-bench`.
- During cleanup the `staging` API briefly returned connection-refused and
  not-ready responses; a bounded retry loop waited for API readiness before
  deleting the Jobs and rolling back.
- Rolled Helm back to revision 95, described by Helm as rollback to revision
  93.
- Verified final DaemonSet image:
  `ghcr.io/e-navigator/e-navigator@sha256:90b571bf89ac36c1432a503ad9b9add7abd7604579533c1912201568db1d5bfc`.
- Verified final DaemonSet `2/2` Ready with zero restarts.
- Verified both temporary proof Jobs were absent.

## Proof Status

Proven:

- The bounded three-slot HTTP `writev` BPF program loads on the observed
  homelab kernel.
- Bounded outbound client-side cleartext HTTP request capture from three
  separate `writev` iovec slots on the observed `homelab-02` Python workload.
- Request-span generation from those three-slot captured HTTP records.
- Request ID and Host extraction when request-line, Host, and request-ID bytes
  are split across three separate iovec slots within the 96-byte per-slot
  bound.
- Kubernetes pod/container attribution for all measured three-iovec proof
  records after attribution warmup.

Not proven:

- Symmetric controlled-client coverage across both homelab nodes.
- More than three HTTP iovec slots, chunks larger than 96 bytes per slot, TLS,
  gRPC, inbound server-side parsing, status-code extraction, route templates,
  retries, application errors, or production replacement readiness.
