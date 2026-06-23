# Homelab Sample: HTTP Symmetric Three-Iovec Boundary

Run: `20260623-072108-http-symmetric-iovec-live`

Raw evidence lives under
`benchmarks/results/raw/20260623-072108-http-symmetric-iovec-live/`.

Scope: `staging` context, `e-navigator-bench` namespace only.

Image:

- Git SHA: `416e88c7c0c7b1fac8fe48339954b9381f178809`
- Tag: `ghcr.io/e-navigator/e-navigator:sha-416e88c`
- Image index digest:
  `sha256:2b6094593c71313f9e2a50cc24fb4247e975243d4c86bd9c0d60a94a27eabd0a`
- Linux/amd64 digest:
  `sha256:5559bb295d564bfec92faea753cd2789768ed100fa632d7e204e49fd718eb58e`
- CI run for the image commit: `28018931005`
- Image publish run for the image commit: `28018931011`

Local proof before deployment:

- `cargo run --quiet --locked -p e-navigator-cli -- --config benchmarks/results/raw/20260623-072108-http-symmetric-iovec-live/http-symmetric-config.toml --validate-config`
- `helm lint charts/e-navigator`
- `helm template e-navigator-bench charts/e-navigator --namespace e-navigator-bench -f benchmarks/results/raw/20260623-072108-http-symmetric-iovec-live/http-symmetric-values.yaml --set-file config.toml=benchmarks/results/raw/20260623-072108-http-symmetric-iovec-live/http-symmetric-config.toml | kubeconform -strict -summary -`
- `kubectl apply --dry-run=client --context staging -n e-navigator-bench -f benchmarks/results/raw/20260623-072108-http-symmetric-iovec-live/http-symmetric-workloads.yaml`
- `git diff --check`

Deployment:

- Baseline before test: Helm revision `113`, described by Helm as
  `Rollback to 111`, with DaemonSet `2/2` Ready.
- Test rollout: Helm revision `114`.
- Runtime config enabled `source.aya_http`, `source.aya_network`,
  `processor.container_attribution`, `generator.request_correlation`,
  `generator.network_metrics`, `sink.json_stdout`, and
  `sink.prometheus_http`.
- DNS, exec, host resource, trace, profiling, runtime security, E-Navigator
  compatibility, and OTLP modules were disabled for this proof.
- Both E-Navigator pods stayed Ready and reported `Seccomp: 2`,
  `NoNewPrivs: 1`, UID `0`, and `CapEff: 000001c401283004`.

Controlled workloads:

- Job `http-iovec3-sym-072108-h01` pinned to `homelab-01`.
  - Pod: `http-iovec3-sym-072108-h01-7xwvf`
  - Pod IP: `10.42.248.241`
  - Path: `/proof/iovec3-sym-072108-h01`
  - Workload log: `warmup_ok=20`, `three_iovec_requests=80 ok=80 errors=0`
  - Proof iovec lengths: `(32, 27, 87)`
- Job `http-iovec3-sym-072108-h02` pinned to `homelab-02`.
  - Pod: `http-iovec3-sym-072108-h02-9ntx6`
  - Pod IP: `10.42.134.59`
  - Path: `/proof/iovec3-sym-072108-h02`
  - Workload log: `warmup_ok=20`, `three_iovec_requests=80 ok=80 errors=0`
  - Proof iovec lengths: `(32, 27, 87)`

Observed signals:

- `homelab-02` produced 160 measured proof records:
  - 80 `protocol_request_observation` records from `source.aya_http`
  - 80 `request_span_observation` records from
    `generator.request_correlation`
  - 80 unique `i3-sym-h02-proof-*` request IDs
  - all 160 measured records had Kubernetes namespace `e-navigator-bench`,
    pod `http-iovec3-sym-072108-h02-9ntx6`, and container `workload`
- `homelab-02` also exposed direct `/metrics` controlled workload counters:
  `network_connection_open_count`, `network_protocol_connection_open_count`,
  `network_traffic_destination_count`, and
  `network_connection_duration_count` at value `100` for the workload pod.
- `homelab-01` produced zero exact-path `protocol_request_observation` or
  `request_span_observation` records for `/proof/iovec3-sym-072108-h01`.
- `homelab-01` also produced zero network-source or network-metric records for
  pod `http-iovec3-sym-072108-h01-7xwvf`, and direct `/metrics` contained no
  controlled workload series for that pod.
- `homelab-01` was not idle or failed globally: its logs contained ambient
  HTTP/network activity, source telemetry reported `source.aya_http`
  `sent_signals=534`, `lost_perf_events=0`, and `source.aya_network`
  `sent_signals=1237`, `lost_perf_events=0`.

Cleanup:

- Deleted Jobs `http-iovec3-sym-072108-h01` and
  `http-iovec3-sym-072108-h02`.
- Rolled Helm release `e-navigator-bench` back to revision `113`; Helm recorded
  final revision `115` as `Rollback to 113`.
- Final DaemonSet state was `2/2` Ready on baseline image
  `ghcr.io/e-navigator/e-navigator@sha256:90b571bf89ac36c1432a503ad9b9add7abd7604579533c1912201568db1d5bfc`.
- Final label-scoped inventory for `e-nav-run=20260623-072108` reported no
  resources in `e-navigator-bench`.

Outcome: `partial`.

Proven:

- The bounded three-slot outbound cleartext HTTP `writev` path still works on
  the observed `homelab-02` workload under chart `RuntimeDefault` seccomp.
- Request-span generation from those captured HTTP records still works on
  `homelab-02`.
- Kubernetes pod/container attribution was present on every measured
  `homelab-02` proof record.
- Direct Prometheus HTTP metrics on the observed `homelab-02` agent exposed
  Kubernetes-attributed aggregate network counters for the controlled workload.

Not proven:

- Symmetric controlled-client HTTP capture across both homelab nodes.
- Controlled workload network or HTTP capture for the observed `homelab-01`
  three-iovec Python workload, even though the workload completed successfully.
- TLS, gRPC, inbound server-side parsing, status-code extraction, route
  templates, retries, application errors, more than three iovec slots, chunks
  larger than 96 bytes per slot, or broader multi-iovec HTTP header assembly.
- Non-root operation, capability reduction, or removal of `CAP_SYS_ADMIN`.
- Production replacement readiness.
