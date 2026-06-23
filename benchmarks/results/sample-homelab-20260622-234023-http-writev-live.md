# Homelab HTTP Writev Proof 20260622-234023

## Scope

- Context: `staging`
- Namespace: `e-navigator-bench`
- Commit: `fb9a6d1`
- Image tag: `ghcr.io/e-navigator/e-navigator:sha-fb9a6d1`
- Image index digest:
  `sha256:dec316f7c02504ce99e0500e423adc35398482756f634e915fe14f421d2924e0`
- Linux amd64 digest:
  `sha256:2c984944dee476bfdb27ecaa473277152a4f7b304a0ed99d24b867a90dbba751`
- Baseline restored digest:
  `sha256:90b571bf89ac36c1432a503ad9b9add7abd7604579533c1912201568db1d5bfc`

## Build And Publication

- Local TDD guard failed first on missing `tracepoint_http_writev_enter`, then
  passed after implementation.
- Targeted checks passed:
  - `tests/http_request_capture_guard_test.sh`
  - `cargo fmt --all -- --check`
  - `cargo test --locked -p e-navigator-sources-ebpf-aya http::tests`
- Full local gate passed: `scripts/quality.sh`
- GitHub CI run `27991365112`: success
- GitHub image publication run `27991365123`: success

## Live Run

- Preflight confirmed `kubectl config current-context` was `staging`.
- Helm baseline before test: revision 53, digest
  `sha256:90b571bf89ac36c1432a503ad9b9add7abd7604579533c1912201568db1d5bfc`,
  DaemonSet `2/2` Ready.
- Test rollout: Helm revision 54 with `source.aya_http` and
  `generator.request_correlation` enabled.
- Test image:
  `ghcr.io/e-navigator/e-navigator@sha256:2c984944dee476bfdb27ecaa473277152a4f7b304a0ed99d24b867a90dbba751`
- DaemonSet rollout completed and stayed `2/2` Ready with zero restarts.

## Workload

- Server pod:
  `e-nav-http-writev-20260622-234023-server-64646ddc55-v2ghg`
- Client pod:
  `e-nav-http-writev-20260622-234023-client-msdw5`
- Node: `homelab-02`
- Client pod UID: `f7b5fd5d-94e8-44b7-951e-528f37e3384a`
- Client pod IP: `10.42.134.37`
- Client container ID:
  `containerd://255ca4621dbb91612fc30550e0ff432c115de132c0c8dcc3b24f99cef3db0a27`
- Client log:
  - `controlled_http_writev_ok=120`
  - `controlled_http_writev_errors=0`

The client used Python `os.writev` with the complete HTTP request in the first
iovec. This proves the current bounded writev path for complete first-iovec
HTTP requests; it does not prove reassembly of HTTP headers split across
multiple iovecs.

## Observed Signals

Filtered E-Navigator JSON stdout from the `homelab-02` DaemonSet pod contained:

- 120 `protocol_request_observation` records from `source.aya_http` for
  `/proof/http-writev-20260622-234023`.
- 120 `request_span_observation` records from
  `generator.request_correlation` for the same path.
- 101 protocol records and 101 request-span records included Kubernetes
  attribution for namespace `e-navigator-bench`, pod
  `e-nav-http-writev-20260622-234023-client-msdw5`, and container `client`.
- The attributed records carried:
  - method `GET`
  - trace ID `aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`
  - span ID `bbbbbbbbbbbbbbbb`
  - request IDs `http-writev-20260622-234023-19` through
    `http-writev-20260622-234023-119`

The first 19 protocol/request-span pairs had the same trace context and request
path but no Kubernetes fields yet. The proof claim uses the 101 attributed
pairs as the controlled workload attribution evidence.

## Cleanup And Restore

- Deleted temporary Job, Deployment, and Service in `e-navigator-bench`.
- Rolled Helm back to revision 55, described by Helm as rollback to revision 53.
- Verified final DaemonSet image:
  `ghcr.io/e-navigator/e-navigator@sha256:90b571bf89ac36c1432a503ad9b9add7abd7604579533c1912201568db1d5bfc`
- Verified DaemonSet `2/2` Ready.
- Verified no temporary workload resources remained for label
  `app=e-nav-http-writev-20260622-234023`.

## Proof Status

Proven:

- Bounded outbound client-side cleartext HTTP request capture from `writev` on
  the observed `homelab-02` client.
- Request-span generation from captured writev HTTP records.
- Traceparent and request ID extraction on the observed controlled workload.
- Kubernetes pod/container attribution after attribution warm-up for 101 of the
  120 controlled requests.

Not proven:

- Symmetric controlled-client coverage across both homelab nodes.
- TLS, gRPC, inbound server-side parsing, status-code extraction, route
  templates, retries, application errors, or production replacement readiness.
- HTTP header assembly when a single request is split across multiple iovecs.
