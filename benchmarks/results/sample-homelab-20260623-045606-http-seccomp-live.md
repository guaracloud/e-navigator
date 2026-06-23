# Homelab Sample: HTTP Three-Iovec Capture Under RuntimeDefault Seccomp

Run: `20260623-045606-http-seccomp-live`

Raw evidence lives under
`benchmarks/results/raw/20260623-045606-http-seccomp-live/`.

Scope: `staging` context, `e-navigator-bench` namespace only.

Image:

- Git SHA: `643ea37`
- Tag: `ghcr.io/e-navigator/e-navigator:sha-643ea37`
- Image index digest:
  `sha256:56a1148e6ef6016d9af490a8b4e03a8d9c47b8ac7b541eebb905d300bc96c500`
- Linux/amd64 digest:
  `sha256:19b5e418a410178e9ea91ab9156f3f91dc488767c73accd9ba2afb6cc3d32b1a`
- CI run: `28010852166`
- Image publish run: `28010852178`

Local proof before deployment:

- `cargo run --quiet --locked -p e-navigator-cli -- --config benchmarks/results/raw/20260623-045606-http-seccomp-live/http-seccomp-config.toml --validate-config`
- `helm lint charts/e-navigator`
- `helm template e-navigator-bench charts/e-navigator --namespace e-navigator-bench -f benchmarks/results/raw/20260623-045606-http-seccomp-live/http-seccomp-values.yaml --set-file config.toml=benchmarks/results/raw/20260623-045606-http-seccomp-live/http-seccomp-config.toml | kubeconform -strict -summary -`
- `kubectl apply --dry-run=client --context staging -n e-navigator-bench -f benchmarks/results/raw/20260623-045606-http-seccomp-live/three-iovec-workload.yaml`
- `git diff --check`

Deployment:

- Baseline before test: Helm revision `101`, described by Helm as
  `Rollback to 99`, with DaemonSet `2/2` Ready.
- Test rollout: Helm revision `102`.
- The rendered manifest used `seccompProfile.type: RuntimeDefault` and image
  `ghcr.io/e-navigator/e-navigator@sha256:56a1148e6ef6016d9af490a8b4e03a8d9c47b8ac7b541eebb905d300bc96c500`.
- Runtime config enabled `source.aya_http`, `source.aya_network`,
  `processor.container_attribution`, `generator.request_correlation`,
  `generator.network_metrics`, `sink.json_stdout`, and
  `sink.prometheus_http`.
- DNS, exec, host resource, trace, profiling, runtime security, E-Navigator
  compatibility, and OTLP modules were disabled for this proof.

Runtime security posture:

- DaemonSet state after upgrade: `2 desired`, `2 ready`.
- Runtime pods:
  - `e-navigator-bench-crb8s` on `homelab-01`
  - `e-navigator-bench-9qh55` on `homelab-02`
- `/proc/1/status` inside both pods reported:
  - `Uid: 0 0 0 0`
  - `Gid: 0 0 0 0`
  - `CapEff: 000001c401283004`
  - `NoNewPrivs: 1`
  - `Seccomp: 2`
- Precise failure-marker searches over startup and workload-window logs found
  zero `module failed`, `Error:`, `verifier`, `permission denied`,
  `operation not permitted`, `sink write failed`, or panic markers.

Controlled workload:

- Job: `http-iovec3-seccomp-045606`, pinned to `homelab-02`.
- Pod: `http-iovec3-seccomp-045606-z4g7j`, IP `10.42.134.41`.
- Path: `/proof/iovec3-seccomp-045606`.
- Workload output:
  - `warmup_requests=20 warmup_ok=20`
  - `three_iovec_requests=80 ok=80 errors=0`
  - `proof_iovec_lengths=(32, 27, 87)`
- Request data was split across three `os.writev` buffers: request line, Host
  header, and request ID/run headers plus terminator. All proof buffers stayed
  below the 96-byte per-slot bound.

Observed signals:

- Captured E-Navigator JSON stdout contained 160 measured proof records:
  - 80 `protocol_request_observation` records from `source.aya_http`
  - 80 `request_span_observation` records from
    `generator.request_correlation`
- The proof set contained 80 unique `i3-seccomp-proof-*` request IDs.
- All 160 measured proof records included Kubernetes namespace
  `e-navigator-bench`, pod `http-iovec3-seccomp-045606-z4g7j`, and container
  `workload`.
- Direct homelab-02 `/healthz` returned `ok`, `/readyz` returned `ready`, and
  `/metrics` returned 60 lines.
- Direct homelab-02 `/metrics` exposed controlled workload counters with
  Kubernetes labels, including `network_connection_open_count`,
  `network_protocol_connection_open_count`,
  `network_traffic_destination_count`, and
  `network_connection_duration_count` at value `99`.

Cleanup:

- Deleted Job `http-iovec3-seccomp-045606`.
- Rolled Helm release `e-navigator-bench` back to revision `101`; Helm recorded
  final revision `103` as `Rollback to 101`.
- Final DaemonSet state was `2/2` Ready on baseline image
  `ghcr.io/e-navigator/e-navigator@sha256:90b571bf89ac36c1432a503ad9b9add7abd7604579533c1912201568db1d5bfc`.
- Final label-scoped inventory for `e-nav-run=20260623-045606` reported no
  resources in `e-navigator-bench`.

Outcome: `proven`.

Proven:

- Bounded three-slot outbound cleartext HTTP `writev` capture still works under
  kernel-applied `Seccomp: 2` on the observed homelab rollout.
- Request-span generation from those captured HTTP records still works under
  that seccomp profile.
- Kubernetes pod/container attribution was present on every measured proof
  record after the workload warmup.
- Direct Prometheus HTTP metrics on the observed homelab-02 agent exposed
  Kubernetes-attributed aggregate network counters for the controlled workload.

Not proven:

- Symmetric controlled-client HTTP capture across both homelab nodes.
- TLS, gRPC, inbound server-side parsing, status-code extraction, route
  templates, retries, application errors, more than three iovec slots, chunks
  larger than 96 bytes per slot, or broader multi-iovec HTTP header assembly.
- RuntimeDefault compatibility for DNS source mode.
- Non-root operation, capability reduction, or removal of `CAP_SYS_ADMIN`.
- Production replacement readiness.
