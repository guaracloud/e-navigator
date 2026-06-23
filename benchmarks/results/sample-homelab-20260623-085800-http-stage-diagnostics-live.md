# Homelab Sample: HTTP Stage Diagnostics Boundary

Run: `20260623-085800-http-stage-diagnostics-live`

Raw evidence lives under
`benchmarks/results/raw/20260623-085800-http-stage-diagnostics-live/`.

Scope: `staging` context, `e-navigator-bench` namespace only.

Image:

- Git SHA: `8ed766a01580a007279f081452c800e9c6a9aa99`
- Tag: `ghcr.io/e-navigator/e-navigator:sha-8ed766a`
- Image index digest:
  `sha256:87010498798c297c6ddd7f1f3672c312824b76281ff944f3d6f5697ba218f8bb`
- Linux/amd64 digest:
  `sha256:c616e55ff011e5145648cf6e54231a7b43368600753ed75e8da5a36e24d3ee81`

Deployment:

- CI run `28023920841` passed, including Rust checks, Docker smoke,
  Kubernetes/Helm checks, and supply-chain checks.
- Image publish run `28023920824` succeeded.
- Baseline before test: Helm revision `121`, described by Helm as
  `Rollback to 119`.
- Test rollout: Helm revision `122`.
- Runtime config enabled `source.aya_http`, `source.aya_network`,
  `processor.container_attribution`, `generator.request_correlation`,
  `generator.network_metrics`, `sink.json_stdout`, and
  `sink.prometheus_http`.
- HTTP source diagnostics were enabled with
  `E_NAVIGATOR_SOURCE_DIAGNOSTICS=true`.

Controlled workloads:

- Job `http-stage-085800-h02` pinned to `homelab-02`.
  - Pod: `http-stage-085800-h02-pjb5z`
  - Pod IP: `10.42.134.11`
  - Path: `/proof/iovec3-stage-085800-h02`
  - Workload log: `warmup_ok=30`, `three_iovec_requests=80 ok=80 errors=0`
  - Proof iovec lengths: `(34, 30, 88)`
- Job `http-stage-085800-h01` pinned to `homelab-01`.
  - Pod: `http-stage-085800-h01-gvrdz`
  - Pod IP: `10.42.248.244`
  - Path: `/proof/iovec3-stage-085800-h01`
  - Workload log: `warmup_ok=30`, `three_iovec_requests=80 ok=80 errors=0`
  - Proof iovec lengths: `(34, 30, 88)`

Observed signals:

- The run produced six `source diagnostic http stage counters` log lines.
- The latest captured diagnostic counter line reported
  `writev_enter=27`, `copy_success=1168`, `output_attempt=1168`, and
  `active_connection_miss=10116`.
- JSON stdout contained zero exact-path `protocol_request_observation` records
  for `/proof/iovec3-stage-085800-h01` and
  `/proof/iovec3-stage-085800-h02`.
- JSON stdout contained zero exact-path `request_span_observation` records for
  the same two paths.
- JSON stdout contained zero rows attributed to either controlled workload pod.
- Direct `/metrics` scrape through `kubectl port-forward` exposed eight
  Kubernetes-attributed metric rows for each controlled workload pod.
- Direct `/metrics` exposed `network_connection_open_count`,
  `network_protocol_connection_open_count`,
  `network_traffic_destination_count`, and `network_connection_duration_count`
  at value `109` for each controlled workload pod.

Cleanup:

- Deleted Jobs `http-stage-085800-h02` and `http-stage-085800-h01`.
- During cleanup, the homelab API briefly returned connection-refused and
  `etcdserver: leader changed` errors; the scoped cleanup was retried after the
  control plane recovered.
- Rolled Helm release `e-navigator-bench` back to revision `121`; Helm recorded
  final revision `123` as `Rollback to 121`.
- Final label-scoped inventory for `e-nav-run=20260623-085800` reported no
  resources in `e-navigator-bench`.
- Final DaemonSet state was `2/2` Ready on baseline image digest
  `sha256:90b571bf89ac36c1432a503ad9b9add7abd7604579533c1912201568db1d5bfc`.
- Final `kubectl config current-context` remained `staging`.

Outcome: `partial`.

Proven:

- The new HTTP source diagnostic stage counters load and emit from a live
  homelab DaemonSet with `source.aya_http` enabled.
- The diagnostic counters show live HTTP write/copy/output stages and a large
  `active_connection_miss` bucket during this workload window.
- Both controlled workload pods produced Kubernetes-attributed network metrics
  in direct E-Navigator `/metrics` output.

Not proven:

- Exact-path controlled-client HTTP protocol capture in this diagnostic run.
- Request-span generation for either controlled workload in this diagnostic
  run.
- Symmetric controlled-client HTTP coverage across both homelab nodes.
- Whether every `active_connection_miss` belongs to the controlled workload;
  the counter is stage-level source diagnostics, not per-pod attribution.
- TLS, gRPC, inbound server-side parsing, status-code extraction, route
  templates, retries, application errors, more than three iovec slots, chunks
  larger than 96 bytes per slot, or broader multi-iovec HTTP header assembly.
- Non-root operation, capability reduction, or removal of `CAP_SYS_ADMIN`.
- Production replacement readiness.
