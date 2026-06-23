# Homelab Sample: HTTP Homelab-01 Diagnostics Boundary

Run: `20260623-073736-http-homelab01-diagnostics-live`

Raw evidence lives under
`benchmarks/results/raw/20260623-073736-http-homelab01-diagnostics-live/`.

Scope: `staging` context, `e-navigator-bench` namespace only.

Image:

- Git SHA: `d83e5bf4737ac25c6b55bb7c0cef391ca0427677`
- Tag: `ghcr.io/e-navigator/e-navigator:sha-d83e5bf`
- Image index digest:
  `sha256:5dffedd5d3d23942cff39c4943c4ff6a7be76cef1673b29dedfe6abb535927b5`

Local proof before deployment:

- `cargo run --quiet --locked -p e-navigator-cli -- --config benchmarks/results/raw/20260623-073736-http-homelab01-diagnostics-live/http-homelab01-diagnostics-config.toml --validate-config`
- `helm lint charts/e-navigator`
- `helm template e-navigator-bench charts/e-navigator --namespace e-navigator-bench -f benchmarks/results/raw/20260623-073736-http-homelab01-diagnostics-live/http-homelab01-diagnostics-values.yaml --set-file config.toml=benchmarks/results/raw/20260623-073736-http-homelab01-diagnostics-live/http-homelab01-diagnostics-config.toml | kubeconform -strict -summary -`
- `kubectl apply --dry-run=client --context staging -n e-navigator-bench -f benchmarks/results/raw/20260623-073736-http-homelab01-diagnostics-live/http-homelab01-diagnostics-workloads.yaml`
- `git diff --check`

Deployment:

- Baseline before test: Helm revision `115`, described by Helm as
  `Rollback to 113`, with DaemonSet `2/2` Ready on digest
  `sha256:90b571bf89ac36c1432a503ad9b9add7abd7604579533c1912201568db1d5bfc`.
- Test rollout: Helm revision `116`.
- Runtime config enabled `source.aya_http`, `source.aya_network`,
  `processor.container_attribution`, `generator.request_correlation`,
  `generator.network_metrics`, `sink.json_stdout`, and
  `sink.prometheus_http`.
- DNS, exec, host resource, trace, profiling, runtime security, E-Navigator
  compatibility, and OTLP modules were disabled for this proof.
- Both E-Navigator pods stayed Ready and reported `Seccomp: 2`,
  `NoNewPrivs: 1`, UID `0`, and `CapEff: 000001c401283004`.

Controlled workloads:

- Job `http-diag-073736-h01-self-iovec` pinned to `homelab-01`.
  - Pod: `http-diag-073736-h01-self-iovec-xhvs8`
  - Pod IP: `10.42.248.232`
  - Path: `/proof/h01-self-iovec-073736`
  - Workload log: `warmup_ok=20`, `three_iovec_requests=60 ok=60 errors=0`
  - Proof iovec lengths: `(32, 39, 91)`
- Job `http-diag-073736-h01-self-sendall` pinned to `homelab-01`.
  - Pod: `http-diag-073736-h01-self-sendall-6jkvb`
  - Pod IP: `10.42.248.204`
  - Path: `/proof/h01-self-sendall-073736`
  - Workload log: `warmup_ok=20`, `sendall_requests=60 ok=60 errors=0`
- Job `http-diag-073736-h01-split-iovec` pinned to `homelab-01`.
  - Pod: `http-diag-073736-h01-split-iovec-ds6ss`
  - Target service: `http-diag-073736-h01-server.e-navigator-bench.svc.cluster.local:18085`
  - Path: `/proof/h01-split-iovec-073736`
  - Workload log: `warmup_ok=20`, `three_iovec_requests=60 ok=60 errors=0`
  - Proof iovec lengths: `(33, 40, 93)`
- Job `http-diag-073736-h02-self-iovec` pinned to `homelab-02`.
  - Pod: `http-diag-073736-h02-self-iovec-nf2m8`
  - Pod IP during initial inventory: `10.42.134.2`
  - Path: `/proof/h02-self-iovec-073736`
  - Workload log: `warmup_ok=20`, `three_iovec_requests=60 ok=60 errors=0`
  - Proof iovec lengths: `(32, 39, 91)`

Observed signals:

- Direct homelab-01 `/metrics` exposed Kubernetes-attributed controlled
  workload network counters for all three homelab-01 diagnostic shapes:
  - `http-diag-073736-h01-self-iovec-xhvs8`: open, protocol-open,
    destination, and duration counts at `60`.
  - `http-diag-073736-h01-self-sendall-6jkvb`: open, protocol-open,
    destination, and duration counts at `67`.
  - `http-diag-073736-h01-split-iovec-ds6ss`: open, protocol-open,
    destination, and duration counts at `95`.
- Captured JSON stdout contained zero exact-path `protocol_request_observation`
  or `request_span_observation` records for all four proof paths.
- Captured JSON stdout also contained zero Kubernetes-pod signal rows for the
  controlled workload pod names in this run.
- The homelab-02 control workload completed cleanly but did not produce
  exact-path protocol/request-span records in this diagnostic run, so this run
  cannot be used as a fresh positive HTTP capture proof.
- Events recorded transient `staging` API readiness/refusal and Calico sandbox
  teardown warnings on homelab-01 during the workload window. The workloads
  still completed successfully.

Cleanup:

- Deleted the run-labeled Jobs, server Pod, and Service.
- Rolled Helm release `e-navigator-bench` back to revision `115`; Helm recorded
  final revision `117` as `Rollback to 115`.
- Final label-scoped inventory for `e-nav-run=20260623-073736` reported no
  resources in `e-navigator-bench`.
- Final DaemonSet state was `2/2` Ready on baseline image digest
  `sha256:90b571bf89ac36c1432a503ad9b9add7abd7604579533c1912201568db1d5bfc`.
- Final `kubectl config current-context` remained `staging`.

Outcome: `partial`.

Proven:

- The previous `homelab-01` result of zero controlled workload network metrics
  was not stable across shapes. In this run, homelab-01 produced
  Kubernetes-attributed direct `/metrics` network counters for self-connect
  `writev`, self-connect `sendall`, and split client/server `writev`
  workloads.
- E-Navigator stayed Ready on both homelab nodes under chart `RuntimeDefault`
  seccomp while those workloads ran.

Not proven:

- Homelab-01 controlled-client HTTP protocol capture or request-span generation.
- Fresh homelab-02 positive HTTP protocol capture in this diagnostic run.
- Symmetric controlled-client HTTP coverage across both homelab nodes.
- TLS, gRPC, inbound server-side parsing, status-code extraction, route
  templates, retries, application errors, more than three iovec slots, chunks
  larger than 96 bytes per slot, or broader multi-iovec HTTP header assembly.
- Non-root operation, capability reduction, or removal of `CAP_SYS_ADMIN`.
- Production replacement readiness.
