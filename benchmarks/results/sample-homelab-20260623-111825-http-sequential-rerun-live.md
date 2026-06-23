# Homelab Sample: HTTP Sequential Three-Iovec Rerun Boundary

Run: `20260623-111825-http-sequential-rerun-live`

Raw evidence lives under
`benchmarks/results/raw/20260623-111825-http-sequential-rerun-live/`.

Scope: `staging` context, `e-navigator-bench` namespace only.

Image:

- Git SHA: `90111f5730a431ed9dbf61629afc69230b1b0ae2`
- Tag: `ghcr.io/e-navigator/e-navigator:sha-90111f5`
- Image index digest:
  `sha256:deafa27690d9c987ae1ffe5d72bfdfc909547549fb51407919727bab958d2072`
- Linux/amd64 digest:
  `sha256:7cbf02d0480ee542ed0201e6533801285c05ac7124c9298b5366087c59fa88ab`

Deployment:

- Baseline before test: Helm revision `119`, described by Helm as
  `Rollback to 117`.
- Test rollout: Helm revision `120`.
- Runtime config enabled `source.aya_http`, `source.aya_network`,
  `processor.container_attribution`, `generator.request_correlation`,
  `generator.network_metrics`, `sink.json_stdout`, and
  `sink.prometheus_http`.
- DNS, exec, host resource, trace, profiling, runtime security, E-Navigator
  compatibility, and OTLP modules were disabled for this proof.

Controlled workloads:

- Job `http-seq-111825-h02` pinned to `homelab-02`.
  - Pod: `http-seq-111825-h02-wf697`
  - Pod IP: `10.42.134.6`
  - Path: `/proof/iovec3-seq-111825-h02`
  - Workload log: `warmup_ok=30`, `three_iovec_requests=80 ok=80 errors=0`
  - Proof iovec lengths: `(32, 28, 87)`
- Job `http-seq-111825-h01` pinned to `homelab-01`.
  - Pod: `http-seq-111825-h01-tgtbm`
  - Pod IP: `10.42.248.220`
  - Path: `/proof/iovec3-seq-111825-h01`
  - Workload log: `warmup_ok=30`, `three_iovec_requests=80 ok=80 errors=0`
  - Proof iovec lengths: `(32, 28, 87)`

Observed signals:

- The sequential `homelab-02` control produced:
  - 80 exact-path `protocol_request_observation` records for
    `/proof/iovec3-seq-111825-h02`.
  - 80 exact-path `request_span_observation` records for the same path.
  - Direct homelab-02 `/metrics` network counters for the workload pod at
    value `109`.
- The matching `homelab-01` workload produced:
  - zero exact-path `protocol_request_observation` records for
    `/proof/iovec3-seq-111825-h01`.
  - zero exact-path `request_span_observation` records for the same path.
  - zero JSON stdout signal rows attributed to pod `http-seq-111825-h01-tgtbm`.
  - Direct homelab-01 `/metrics` network counters for the workload pod at
    value `110`.

Cleanup:

- Deleted Jobs `http-seq-111825-h02` and `http-seq-111825-h01`.
- Rolled Helm release `e-navigator-bench` back to revision `119`; Helm recorded
  final revision `121` as `Rollback to 119`.
- Final label-scoped inventory for `e-nav-run=20260623-111825` reported no
  resources in `e-navigator-bench`.
- Final DaemonSet state was `2/2` Ready on baseline image digest
  `sha256:90b571bf89ac36c1432a503ad9b9add7abd7604579533c1912201568db1d5bfc`.
- Final `kubectl config current-context` remained `staging`.

Outcome: `partial`.

Proven:

- The same sequential three-iovec workload shape still produces bounded
  cleartext HTTP capture and request-span generation for the observed
  `homelab-02` workload.
- The matching `homelab-01` workload still produces Kubernetes-attributed
  network metrics for this shape.

Not proven:

- Homelab-01 controlled-client HTTP protocol capture or request-span
  generation.
- Symmetric controlled-client HTTP coverage across both homelab nodes.
- TLS, gRPC, inbound server-side parsing, status-code extraction, route
  templates, retries, application errors, more than three iovec slots, chunks
  larger than 96 bytes per slot, or broader multi-iovec HTTP header assembly.
- Non-root operation, capability reduction, or removal of `CAP_SYS_ADMIN`.
- Production replacement readiness.
