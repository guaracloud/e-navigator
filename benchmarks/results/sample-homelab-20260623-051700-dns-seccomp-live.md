# Homelab Sample: DNS Connected-UDP Capture Under RuntimeDefault Seccomp

Run: `20260623-051700-dns-seccomp-live`

Raw evidence lives under
`benchmarks/results/raw/20260623-051700-dns-seccomp-live/`.

Scope: `staging` context, `e-navigator-bench` namespace only.

Image:

- Git SHA: `beec11d`
- Tag: `ghcr.io/e-navigator/e-navigator:sha-beec11d`
- Image index digest:
  `sha256:be48be97397513d7fad29a80cca7d81ed2be990ec5652de5c2a13b9860ff5013`
- Linux/amd64 digest:
  `sha256:f49e01fcb204420b1ef1bcfbc365b461941a049403c95f8a3ee95d9df0cc3b25`

Local proof before deployment:

- `cargo run --quiet --locked -p e-navigator-cli -- --config benchmarks/results/raw/20260623-051700-dns-seccomp-live/dns-seccomp-config.toml --validate-config`
- `helm lint charts/e-navigator`
- `helm template e-navigator-bench charts/e-navigator --namespace e-navigator-bench -f benchmarks/results/raw/20260623-051700-dns-seccomp-live/dns-seccomp-values.yaml --set-file config.toml=benchmarks/results/raw/20260623-051700-dns-seccomp-live/dns-seccomp-config.toml | kubeconform -strict -summary -`
- `kubectl apply --dry-run=client --context staging -n e-navigator-bench -f benchmarks/results/raw/20260623-051700-dns-seccomp-live/dns-connected-udp-seccomp-workload.yaml`
- `git diff --check`

Deployment:

- Baseline before test: Helm revision `103`, described by Helm as
  `Rollback to 101`, with DaemonSet `2/2` Ready.
- Test rollout: Helm revision `104`.
- Runtime config enabled `source.aya_dns`, `source.aya_network`,
  `processor.container_attribution`, `generator.dns_metrics`,
  `generator.network_metrics`, `sink.json_stdout`, and
  `sink.prometheus_http`.
- Exec, HTTP, host resource, trace, profiling, runtime security, E-Navigator
  compatibility, and OTLP modules were disabled for this proof.

Runtime security posture:

- DaemonSet state after upgrade: `2 desired`, `2 ready`.
- Runtime pods:
  - `e-navigator-bench-jqz9x` on `homelab-01`
  - `e-navigator-bench-54bmj` on `homelab-02`
- `/proc/1/status` inside both pods reported:
  - `Uid: 0 0 0 0`
  - `Gid: 0 0 0 0`
  - `CapEff: 000001c401283004`
  - `NoNewPrivs: 1`
  - `Seccomp: 2`
- Precise failure-marker searches over startup and workload-window logs found
  zero `verifier`, `permission denied`, `operation not permitted`,
  `module failed`, `sink write failed`, or panic markers.

Controlled workloads:

- Initial Job `dns-seccomp-051700` used Python `socket.send`/`recv`, completed
  120/120 measured DNS responses with zero errors, but produced no matching
  controlled-client DNS records.
- Follow-up Job `dns-seccomp-051700-r3` used `os.write`/`os.read` incorrectly
  with a nonblocking fd and failed with `Errno 11`; this is workload failure
  evidence only.
- Final Job `dns-seccomp-051700-r4` used connected UDP plus `os.write`,
  `select`, and `os.read`, pinned to `homelab-02`.
- Pod: `dns-seccomp-051700-r4-86x9c`, IP `10.42.134.45`.
- Workload output:
  - `warmup=30`
  - `proof=120`
  - `ok=120`
  - `errors=0`

Observed signals:

- Captured homelab-02 E-Navigator JSON stdout from the final r4 window
  contained 1,804 DNS records:
  - 581 `dns_query`
  - 214 `dns_response`
  - 795 `dns_counter_metric`
  - 214 `dns_latency_metric`
- For controlled pod `dns-seccomp-051700-r4-86x9c`, the parsed signal window
  contained:
  - 148 attributed `dns_query` records
  - 148 attributed `dns_response` records
  - 296 attributed `dns_counter_metric` records
  - 148 attributed `dns_latency_metric` records
- The first two controlled query/response pairs were container-attributed but
  had `kubernetes: null` before the attribution cache warmed.
- Controlled records used `server_address = 10.43.0.10` and `server_port = 53`
  for:
  - `kubernetes.default.svc.cluster.local`
  - `e-navigator-bench.e-navigator-bench.svc.cluster.local`
- Direct homelab-02 `/healthz` returned `ok`, `/readyz` returned `ready`, and
  `/metrics` returned 121 lines, including DNS metric series.

Cleanup:

- Deleted all resources labeled `e-nav-run=20260623-051700`.
- Rolled Helm release `e-navigator-bench` back to revision `103`; Helm recorded
  final revision `105` as `Rollback to 103`.
- Final DaemonSet state was `2/2` Ready on baseline image
  `ghcr.io/e-navigator/e-navigator@sha256:90b571bf89ac36c1432a503ad9b9add7abd7604579533c1912201568db1d5bfc`.
- Final label-scoped inventory for `e-nav-run=20260623-051700` reported no
  resources in `e-navigator-bench`.

Outcome: `proven` for the observed homelab-02 connected-UDP DNS `write`/`read`
path under kernel-applied `Seccomp: 2`.

Proven:

- `source.aya_dns` and `generator.dns_metrics` load and emit live DNS records
  under chart `RuntimeDefault` seccomp on both homelab nodes.
- The observed homelab-02 connected-UDP Python `os.write`/`os.read` DNS client
  path emitted controlled `dns_query`, `dns_response`, `dns_counter_metric`,
  and `dns_latency_metric` records.
- Kubernetes pod/container attribution was present for 148 controlled
  query/response pairs after the attribution warmup.

Not proven:

- Symmetric controlled-client DNS capture across both homelab nodes.
- Lossless DNS event capture.
- Full DNS syscall/path coverage; `socket.send`/`recv` was not controlled-proof
  positive in this run.
- DNS replacement readiness.
- Non-root operation, capability reduction, or removal of `CAP_SYS_ADMIN`.
- Production replacement readiness.
