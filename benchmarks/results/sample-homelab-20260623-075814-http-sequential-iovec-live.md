# Homelab Sample: HTTP Sequential Three-Iovec Boundary

Run: `20260623-075814-http-sequential-iovec-live`

Raw evidence lives under
`benchmarks/results/raw/20260623-075814-http-sequential-iovec-live/`.

Scope: `staging` context, `e-navigator-bench` namespace only.

Image:

- Git SHA: `90111f5730a431ed9dbf61629afc69230b1b0ae2`
- Tag: `ghcr.io/guaracloud/e-navigator:sha-90111f5`
- Image index digest:
  `sha256:deafa27690d9c987ae1ffe5d72bfdfc909547549fb51407919727bab958d2072`
- Linux/amd64 digest:
  `sha256:7cbf02d0480ee542ed0201e6533801285c05ac7124c9298b5366087c59fa88ab`
- CI run: `28020995828`
- Image publish run: `28020995805`

Local proof before deployment:

- `cargo run --quiet --locked -p e-navigator-cli -- --config benchmarks/results/raw/20260623-075814-http-sequential-iovec-live/http-sequential-config.toml --validate-config`
- `helm lint charts/e-navigator`
- `helm template e-navigator-bench charts/e-navigator --namespace e-navigator-bench -f benchmarks/results/raw/20260623-075814-http-sequential-iovec-live/http-sequential-values.yaml --set-file config.toml=benchmarks/results/raw/20260623-075814-http-sequential-iovec-live/http-sequential-config.toml | kubeconform -strict -summary -`
- `kubectl apply --dry-run=client --context staging -n e-navigator-bench -f .../http-sequential-h02-workload.yaml`
- `kubectl apply --dry-run=client --context staging -n e-navigator-bench -f .../http-sequential-h01-workload.yaml`
- `git diff --check`

Deployment:

- Baseline before test: Helm revision `117`, described by Helm as
  `Rollback to 115`, with DaemonSet `2/2` Ready on digest
  `sha256:90b571bf89ac36c1432a503ad9b9add7abd7604579533c1912201568db1d5bfc`.
- Test rollout: Helm revision `118`.
- Runtime config enabled `source.aya_http`, `source.aya_network`,
  `processor.container_attribution`, `generator.request_correlation`,
  `generator.network_metrics`, `sink.json_stdout`, and
  `sink.prometheus_http`.
- DNS, exec, host resource, trace, profiling, runtime security, Guara
  compatibility, and OTLP modules were disabled for this proof.
- Both E-Navigator pods stayed Ready and reported `Seccomp: 2`,
  `NoNewPrivs: 1`, UID `0`, and `CapEff: 000001c401283004`.

Controlled workloads:

- Job `http-seq-075814-h02` pinned to `homelab-02`.
  - Pod: `http-seq-075814-h02-c95v4`
  - Pod IP: `10.42.134.3`
  - Path: `/proof/iovec3-seq-075814-h02`
  - Workload log: `warmup_ok=30`, `three_iovec_requests=80 ok=80 errors=0`
  - Proof iovec lengths: `(32, 28, 87)`
- Job `http-seq-075814-h01` pinned to `homelab-01`.
  - Pod: `http-seq-075814-h01-vv6r2`
  - Pod IP: `10.42.248.235`
  - Path: `/proof/iovec3-seq-075814-h01`
  - Workload log: `warmup_ok=30`, `three_iovec_requests=80 ok=80 errors=0`
  - Proof iovec lengths: `(32, 28, 87)`

Observed signals:

- The sequential `homelab-02` control produced:
  - 80 exact-path `protocol_request_observation` records for
    `/proof/iovec3-seq-075814-h02`.
  - 80 exact-path `request_span_observation` records for the same path.
  - 80 unique `i3-seq-h02-proof-*` request IDs.
  - Kubernetes namespace `e-navigator-bench`, pod
    `http-seq-075814-h02-c95v4`, and container `workload` on every measured
    exact-path record.
  - Direct homelab-02 `/metrics` network counters for the workload pod at
    value `109`.
- The sequential `homelab-01` workload produced:
  - zero exact-path `protocol_request_observation` records for
    `/proof/iovec3-seq-075814-h01`.
  - zero exact-path `request_span_observation` records for the same path.
  - zero unique measured proof request IDs in JSON stdout.
  - zero JSON stdout signal rows attributed to pod `http-seq-075814-h01-vv6r2`.
  - Direct homelab-01 `/metrics` network counters for the workload pod at
    value `109`.
- No new apiserver or Calico warnings occurred during the sequential workload
  window. Older warnings from the previous diagnostic run were still present in
  namespace event history.

Cleanup:

- Deleted Jobs `http-seq-075814-h02` and `http-seq-075814-h01`.
- Rolled Helm release `e-navigator-bench` back to revision `117`; Helm recorded
  final revision `119` as `Rollback to 117`.
- Final label-scoped inventory for `e-nav-run=20260623-075814` reported no
  resources in `e-navigator-bench`.
- Final DaemonSet state was `2/2` Ready on baseline image digest
  `sha256:90b571bf89ac36c1432a503ad9b9add7abd7604579533c1912201568db1d5bfc`.
- Final `kubectl config current-context` remained `staging`.

Outcome: `partial`.

Proven:

- The current pushed image still proves bounded three-iovec cleartext HTTP
  capture and request-span generation for the observed sequential `homelab-02`
  workload under chart `RuntimeDefault` seccomp.
- The same sequential shape on `homelab-01` produced Kubernetes-attributed
  network metrics at the expected aggregate count, so homelab-01 controlled
  workload network-metric capture is present for this shape.

Not proven:

- Homelab-01 controlled-client HTTP protocol capture or request-span
  generation.
- Symmetric controlled-client HTTP coverage across both homelab nodes.
- TLS, gRPC, inbound server-side parsing, status-code extraction, route
  templates, retries, application errors, more than three iovec slots, chunks
  larger than 96 bytes per slot, or broader multi-iovec HTTP header assembly.
- Non-root operation, capability reduction, or removal of `CAP_SYS_ADMIN`.
- Production replacement readiness.
