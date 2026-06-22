# Homelab Sample: Guara Nonblocking Connect Slice

Run: `20260622-122803-guara-einprogress-live`

Scope: `staging` context, `e-navigator-bench` namespace only.

Image:

- Git SHA: `622e1aa11e0d079d826ee9a763e238838d8ccbf4`
- Tag: `ghcr.io/guaracloud/e-navigator:sha-622e1aa`
- Image index digest: `sha256:419225ee6fb4287665aa8403f63cd02096bd890ad6b8aafef3bd0750c45b3cde`
- Deployed amd64 digest: `sha256:90b571bf89ac36c1432a503ad9b9add7abd7604579533c1912201568db1d5bfc`
- GitHub image publish run: `27963701892`

Deployment evidence:

- Helm release: `e-navigator-bench`
- Helm revision after rollout: `42`
- DaemonSet pods: `e-navigator-bench-q4lrq` on `homelab-01` and `e-navigator-bench-qvwpg` on `homelab-02`
- Both DaemonSet pods used `ghcr.io/guaracloud/e-navigator@sha256:90b571bf89ac36c1432a503ad9b9add7abd7604579533c1912201568db1d5bfc`
- Both DaemonSet pods were Ready with zero restarts after rollout and after cleanup.

Local proof before deployment:

- `bash tests/network_einprogress_guard_test.sh`
- `cargo test --locked -p e-navigator-sources-ebpf-aya network -- --nocapture`
- `cargo test --locked -p e-navigator-generators network_flow -- --nocapture`
- `cargo fmt --all -- --check`
- `git diff --check`
- `cargo clippy --locked --workspace --all-targets --exclude e-navigator-ebpf-programs -- -D warnings`
- `cargo test --locked --workspace --exclude e-navigator-ebpf-programs`
- `cargo run --locked -p e-navigator-cli -- --source synthetic`
- `E_NAVIGATOR_SKIP_SUPPLY_CHAIN=1 E_NAVIGATOR_SKIP_DOCKER=1 E_NAVIGATOR_SKIP_KUBERNETES=1 scripts/quality.sh`
- `scripts/quality.sh`

Live workload:

- Two Python server pods and two Python nonblocking client pods ran in `e-navigator-bench`, pinned one server/client pair per homelab node.
- Server IPs were `10.42.248.200` on `homelab-01` and `10.42.134.6` on `homelab-02`.
- Client pods reported 120 successful requests each, 240 total, with no application failures.
- Captured E-Navigator stdout contained controlled records for `10.42.134.6:8080` on `homelab-02`: 120 `network_connection_open`, 120 `network_connection_close`, 120 `network_duration_metric`, 240 `network_counter_metric`, and 184 `network_gauge_metric`.
- Controlled `10.42.134.6:8080` stdout records had 0 `network_connection_failure` and 0 errno 115 failures.
- Controlled stdout records had 0 byte-bearing closes, 0 controlled `network_flow_summary` rows, and 0 `beyla_network_flow_bytes_total` JSON signals.
- Captured stdout did not contain controlled records for the successful `homelab-01` client target `10.42.248.200:8080`.
- Direct `/healthz` returned `ok`; direct `/readyz` returned `ready`.
- Direct `/metrics` had 68 lines and exposed homelab-02 aggregate controlled-client counters, including `network_connection_open_count{container_runtime="containerd",host_name="homelab-02",net_transport="tcp",network_type="ipv4"} 120` and matching duration count 120.
- Direct `/metrics` contained no `beyla_network_flow_bytes_total` lines and no controlled-address labels.
- Temporary workload pods were deleted.

Outcome: `partial`.

Proven:

- The pushed image runs on both homelab nodes from the recorded GHCR digest.
- The nonblocking Python client success path no longer appears as `EINPROGRESS` failure-only records for the observed homelab-02 target.
- The Prometheus HTTP sink surfaced aggregate controlled-client network counters for the observed homelab-02 container runtime path.

Not proven:

- Controlled workload byte-bearing close records for the nonblocking clients.
- Controlled workload `network_flow_summary`.
- Direct or Prometheus `beyla_network_flow_bytes_total` export from controlled live traffic.
- Homelab-01 stdout capture for the successful controlled client target.
- Kubernetes pod/container attribution for the controlled Python client records.

Non-claims:

- No Beyla replacement claim.
- No production-ready claim.
- No reduced-overhead claim.
- No reduced-privilege claim.
- No byte-accuracy claim for nonblocking connect paths.
