# Homelab Sample: HTTP Fallback Peer Boundary

Run: `20260623-122906-http-fallback-peer-live`

Raw evidence lives under
`benchmarks/results/raw/20260623-122906-http-fallback-peer-live/`.

Scope: `staging` context, `e-navigator-bench` namespace only.

Image:

- Git SHA: `ef7487465a0a7aa51e3a1d4d971a99875a19de9b`
- Tag: `ghcr.io/guaracloud/e-navigator:sha-ef74874`
- Image index digest:
  `sha256:e7a8bde9969b8f643433a55b3bb0ca658fc9013e97e09f428331b134cd418591`
- Linux/amd64 digest:
  `sha256:674f2c50139bde031c09d840ec4d7ee497780dd2504b7b9469ce72b98de1aed6`

Deployment:

- Local `scripts/quality.sh` passed before commit.
- CI run `28025951181` passed, including Rust checks, Docker smoke,
  Kubernetes/Helm checks, and supply-chain checks.
- Image publish run `28025951829` succeeded.
- Baseline before test: Helm revision `123`, described by Helm as
  `Rollback to 121`.
- First test rollout, revision `124`, failed because the run values omitted
  `imagePullSecrets`; the homelab pod pull returned GHCR `403 Forbidden`.
- Rollback to revision `123` completed as revision `125`, and the corrected
  values added `ghcr-e-navigator-pull`.
- Successful test rollout: Helm revision `126`.
- Runtime config enabled `source.aya_http`, `source.aya_network`,
  `processor.container_attribution`, `generator.request_correlation`,
  `generator.network_metrics`, `sink.json_stdout`, and
  `sink.prometheus_http`.
- HTTP source diagnostics were enabled with
  `E_NAVIGATOR_SOURCE_DIAGNOSTICS=true`.

Controlled workloads:

- Job `http-fallback-peer-20260623-122906-h01` pinned to `homelab-01`.
  - Pod: `http-fallback-peer-20260623-122906-h01-8l8xl`
  - Path: `/proof/http-fallback-20260623-122906-h01`
  - Host header: `fallback-h01.example.test:18083`
  - Workload log: `ok=80/80`
- Job `http-fallback-peer-20260623-122906-h02` pinned to `homelab-02`.
  - Pod: `http-fallback-peer-20260623-122906-h02-k2h59`
  - Path: `/proof/http-fallback-20260623-122906-h02`
  - Host header: `fallback-h02.example.test:18083`
  - Workload log: `ok=80/80`

Observed signals:

- Captured JSON stdout contained zero exact-path
  `protocol_request_observation` records for either proof path.
- Captured JSON stdout contained zero exact-path
  `request_span_observation` records for either proof path.
- Captured JSON stdout contained no decoded records with the fallback Host
  header domains.
- JSON stdout did contain Kubernetes-attributed network records for the proof
  pods: 236 `network_connection_open`, 236 `network_connection_close`, 236
  `network_duration_metric`, 434 `network_gauge_metric`, 864
  `network_counter_metric`, and 156 `network_connection_failure` rows.
- Direct `/metrics` from the E-Navigator pods exposed Kubernetes-attributed
  workload network counters:
  - `homelab-01`: `network_connection_open_count=109`,
    `network_traffic_destination_count=109`,
    `network_connection_duration_count=109`.
  - `homelab-02`: `network_connection_open_count=79`,
    `network_traffic_destination_count=79`,
    `network_connection_duration_count=79`.
- The HTTP diagnostic logger emitted live stage counters that included the new
  fallback buckets. Captured lines included nonzero
  `fallback_candidate`, `fallback_non_http_start`, and
  `fallback_output_attempt`; one line reported
  `fallback_candidate=109405`, `fallback_non_http_start=108488`, and
  `fallback_output_attempt=916`.

Cleanup:

- Deleted both proof Jobs with the run label
  `e-navigator.guara.cloud/proof-run=20260623-122906-http-fallback-peer-live`.
- Rolled Helm release `e-navigator-bench` back to revision `125`; Helm recorded
  final revision `127` as `Rollback to 125`.
- Final label-scoped inventory reported no resources in `e-navigator-bench`.
- Final DaemonSet state was `2/2` Ready on baseline image digest
  `sha256:90b571bf89ac36c1432a503ad9b9add7abd7604579533c1912201568db1d5bfc`.
- Final `kubectl config current-context` remained `staging`.

Outcome: `partial`.

Proven:

- The fallback HTTP source counters load and emit from a live homelab
  DaemonSet.
- The new fallback path attempted bounded output for live active-connection
  misses.
- The controlled proof workloads completed and produced Kubernetes-attributed
  network observations and direct Prometheus metrics.
- The GHCR pull-secret requirement for digest-pinned homelab rollouts is
  captured by the failed revision `124` and corrected revision `126`.

Not proven:

- Exact-path controlled-client HTTP protocol capture for the fallback workload.
- Request-span generation for the fallback workload.
- Host-derived fallback peer context in live output.
- Symmetric controlled-client HTTP protocol coverage across both homelab nodes.
- TLS, gRPC, inbound server-side parsing, status-code extraction, route
  templates, retries, application errors, more than three iovec slots, chunks
  larger than 96 bytes per slot, or broader multi-iovec HTTP header assembly.
- Non-root operation, capability reduction, or removal of `CAP_SYS_ADMIN`.
- Production replacement readiness.
