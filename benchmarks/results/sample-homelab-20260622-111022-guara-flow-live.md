# Homelab Sample: Guara L4 Flow Slice

Runs:

- `20260622-111022-guara-flow-live`
- `20260622-111448-guara-flow-python-client-live`

Scope: `staging` context, `e-navigator-bench` namespace only.

Image:

- Git SHA: `762561f1c7756637d14116213c781aa002f89a67`
- Tag: `ghcr.io/guaracloud/e-navigator:sha-762561f`
- Image index digest: `sha256:0aa3ff78df749d74973e1801b976c4e72aa351d1a4b0a758a85d148ae333c070`
- Deployed amd64 digest: `sha256:d520fd8b7bd0a4042c31513034d43f716b75407a888b47468f19ca3504629a5a`
- GitHub CI run: `27957831033`
- GitHub image publish run: `27957831092`

Deployment evidence:

- Helm release: `e-navigator-bench`
- Helm revision after the main rollout: `41`
- DaemonSet pods: `e-navigator-bench-xrsdw` on `homelab-01` and `e-navigator-bench-pgrw2` on `homelab-02`
- Both DaemonSet pods used `ghcr.io/guaracloud/e-navigator@sha256:d520fd8b7bd0a4042c31513034d43f716b75407a888b47468f19ca3504629a5a`

Local proof before deployment:

- `cargo test --locked -p e-navigator-sources-ebpf-aya network -- --nocapture`
- `cargo test --locked -p e-navigator-generators network_flow -- --nocapture`
- `cargo test --locked -p e-navigator-processors network_flow_summary_enriches_destination_from_pod_ip_cache -- --nocapture`
- `cargo test --locked -p e-navigator-runner generated -- --nocapture`
- `cargo fmt --all -- --check`
- `cargo clippy --locked --workspace --all-targets --exclude e-navigator-ebpf-programs -- -D warnings`
- `cargo test --locked --workspace --exclude e-navigator-ebpf-programs`
- `cargo run --locked -p e-navigator-cli -- --source synthetic`
- `helm lint charts/e-navigator`
- `helm template e-navigator charts/e-navigator`
- `docker build -f Containerfile -t e-navigator:flow-live .`
- `tests/smoke_docker.sh e-navigator:flow-live`
- `scripts/quality.sh`
- `git diff --check`

Main live run `20260622-111022-guara-flow-live`:

- Two BusyBox server pods and two BusyBox client pods ran in `e-navigator-bench`.
- Client pods completed 180 HTTP requests each, 360 total, against `10.42.248.254:8080`.
- Captured signal counts included 332 `network_connection_close`, 234 byte-bearing close records, 53 `network_flow_summary`, and 0 `beyla_network_flow_bytes_total` JSON signals.
- Direct `/healthz` and `/readyz` were captured from both DaemonSet pods.
- Direct `/metrics` exposed network metrics, but no `beyla_network_flow_bytes_total`.
- CPU/RSS samples showed `e-navigator-bench-xrsdw` at `17m`-`23m` CPU and `26Mi`-`27Mi` RSS, and `e-navigator-bench-pgrw2` at `6m` CPU and `20Mi` RSS during the sample window.
- Temporary workload pods were deleted.

Follow-up live run `20260622-111448-guara-flow-python-client-live`:

- Two Python client pods stayed alive after socket reads to test attribution timing.
- Client pods reported 80 requests each, 160 total, against `10.42.248.240:8080`.
- Captured signal counts included 853 `network_connection_close`, 400 `network_flow_summary`, and 0 `beyla_network_flow_bytes_total` JSON signals.
- Server-IP records for the controlled Python workload were captured as `EINPROGRESS` connection failures, not byte-bearing closes.
- Controlled evidence counts were 0 byte-bearing closes, 0 controlled `network_flow_summary` rows, and 0 Beyla JSON signals.
- Temporary workload pods were deleted.

Outcome: `partial`.

Proven:

- The pushed image runs on both homelab nodes from the recorded GHCR digest.
- Live Aya network close records can carry `bytes_sent` and `bytes_received`.
- `generator.network_metrics` can emit live `network_flow_summary` records from byte-bearing close events.

Not proven:

- Controlled workload `network_flow_summary` with pod/container attribution.
- Direct or Prometheus `beyla_network_flow_bytes_total` export from live traffic.
- Byte accounting completeness for nonblocking connect paths.
- Prometheus API query evidence for this slice.

Non-claims:

- No Beyla replacement claim.
- No production-ready claim.
- No reduced-overhead claim.
- No reduced-privilege claim.
- No byte-accuracy claim beyond the observed read/write close counters.
