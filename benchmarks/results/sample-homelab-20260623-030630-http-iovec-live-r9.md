# Homelab HTTP Split Iovec Proof 20260623-030630

## Scope

- Context: `staging`
- Namespace: `e-navigator-bench`
- Commit: `7ac7ef2dc8b2fa14a25590d8bd85cb5328321591`
- Image tag: `ghcr.io/e-navigator/e-navigator:sha-7ac7ef2`
- Image index digest:
  `sha256:c8fe0da75d741e2ce2993e7006d5384fe6f76904e4d00b10e8fbdc30bc7c5c48`
- Linux amd64 digest:
  `sha256:7967acb8ca974c6e0fbdd578c33d1229bfb04b8112ebbc7c546eccaea3b99818`
- Baseline restored digest:
  `sha256:90b571bf89ac36c1432a503ad9b9add7abd7604579533c1912201568db1d5bfc`
- Raw evidence directory:
  `benchmarks/results/raw/20260623-030630-http-iovec-live-r9/`

## Build And Publication

- Local TDD guard failed first on dynamic HTTP request slices in the split-iovec
  helper, then passed after replacing the generic indexed helper with explicit
  slot-specific copy helpers.
- Docker builder object inspection for the final local object found no
  `.text.unlikely.` section and no `panic` or bounds-check symbols.
- Full local gate passed: `scripts/quality.sh`.
- GitHub CI run `27999145227`: success.
- GitHub image publication run `27999145243`: success.

## Live Run

- Preflight confirmed `pwd` was `/Users/victorbona/Daedalus/e-navigator` and
  `kubectl config current-context` was `staging`.
- Helm baseline before test: revision 71, digest
  `sha256:90b571bf89ac36c1432a503ad9b9add7abd7604579533c1912201568db1d5bfc`,
  DaemonSet `2/2` Ready.
- Test rollout: Helm revision 72 with `source.aya_http` and
  `generator.request_correlation` enabled.
- Test image:
  `ghcr.io/e-navigator/e-navigator@sha256:7967acb8ca974c6e0fbdd578c33d1229bfb04b8112ebbc7c546eccaea3b99818`.
- DaemonSet rollout completed and stayed `2/2` Ready with zero restarts.
- Startup-log scan found none of the previous verifier-failure markers:
  `BPF_PROG_LOAD`, `Invalid argument`, `last insn`, `processed 0 insns`, or
  `module_failed`.

## Workloads

- First split-iovec job: `http-iovec-r9`, pinned to `homelab-02`.
  - Path: `/proof/http-iovec-r9-20260623-030630`.
  - Workload log: `split_iovec_requests=80 ok=80 errors=0`.
  - The HTTP request line was split across two iovecs:
    `GET /proof/http-iovec-r9-20260623-030630` and then
    ` HTTP/1.1` plus headers.
- Paced attribution job: `http-iovec-r9b`, pinned to `homelab-02`.
  - Path: `/proof/http-iovec-r9b-20260623-030630`.
  - Warmup log: `warmup_requests=20 warmup_ok=20`.
  - Proof log: `split_iovec_requests=80 ok=80 errors=0`.
  - Proof pod: `http-iovec-r9b-dptfg`.
  - The measured proof requests used the same split boundary as the first job.

## Observed Signals

Filtered E-Navigator JSON stdout contained:

- First job:
  - 80 `protocol_request_observation` records from `source.aya_http`.
  - 80 `request_span_observation` records from
    `generator.request_correlation`.
  - 80 unique `http.request.id` values.
  - These first-job proof records carried container IDs but no Kubernetes
    namespace/pod/container fields.
- Paced attribution job:
  - 80 `protocol_request_observation` records from `source.aya_http`.
  - 80 `request_span_observation` records from
    `generator.request_correlation`.
  - 80 unique `http.request.id` values.
  - All 160 proof-path records included Kubernetes attribution for namespace
    `e-navigator-bench`, pod `http-iovec-r9b-dptfg`, and container `workload`.
- Warmup path:
  - 20 protocol/request-span pairs were observed.
  - The first pair lacked Kubernetes fields; the remaining 19 pairs included
    namespace `e-navigator-bench`, pod `http-iovec-r9b-dptfg`, and container
    `workload`.

## Cleanup And Restore

- Deleted Jobs `http-iovec-r9` and `http-iovec-r9b` from
  `e-navigator-bench`.
- Rolled Helm back to revision 73, described by Helm as rollback to revision
  71.
- Verified final DaemonSet image:
  `ghcr.io/e-navigator/e-navigator@sha256:90b571bf89ac36c1432a503ad9b9add7abd7604579533c1912201568db1d5bfc`.
- Verified final DaemonSet `2/2` Ready with zero restarts.
- Verified both temporary proof Jobs were absent.

## Proof Status

Proven:

- Bounded outbound client-side cleartext HTTP request capture from a request
  line split across the first two `writev` iovecs on the observed
  `homelab-02` client.
- Request-span generation from those captured split-iovec HTTP records.
- Request ID and Host header extraction when the headers are in the second
  iovec.
- Kubernetes pod/container attribution after attribution warmup for all 80
  measured paced proof requests.
- The `7ac7ef2` BPF object loaded in the homelab DaemonSet without the previous
  verifier failure.

Not proven:

- Symmetric controlled-client coverage across both homelab nodes.
- More than two HTTP iovec slots, chunks larger than the configured bounded
  slot size, TLS, gRPC, inbound server-side parsing, status-code extraction,
  route templates, retries, application errors, or production replacement
  readiness.
