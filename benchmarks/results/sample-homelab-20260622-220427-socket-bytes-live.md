# Homelab Sample: Socket Send/Recv Byte Accounting

Run: `20260622-220427-socket-bytes-live`

Scope: `staging` context, `e-navigator-bench` namespace only.

Image:

- Git SHA: `86b3fce`
- Tag: `ghcr.io/e-navigator/e-navigator:sha-86b3fce`
- Image index digest: `sha256:f37e493cee570c4e5c4aae64a8f148bf4e1ae8c7893ddc617756f4b7c106da75`
- Deployed amd64 digest: `sha256:72acf600c86be7b9a2a0c4ca8ae905e065232e26125e1cdf575f515c53668a48`
- GitHub Actions: CI run `27986601097` and publish-images run `27986601025` succeeded.

Local proof before deployment:

- `bash tests/network_socket_io_guard_test.sh` failed before the fix.
- `bash tests/network_socket_io_guard_test.sh`
- `bash tests/dns_connected_udp_guard_test.sh`
- `cargo fmt --all -- --check`
- `cargo test --locked -p e-navigator-sources-ebpf-aya -p e-navigator-generators`
- `cargo build --locked -p e-navigator-sources-ebpf-aya`
- `cargo clippy --locked --workspace --all-targets --exclude e-navigator-ebpf-programs -- -D warnings`
- `scripts/quality.sh`

Deployment evidence:

- Helm baseline revision before the successful proof was `47`.
- Helm revision `48` rolled `sha-86b3fce` into the DaemonSet.
- DaemonSet pods `e-navigator-bench-jmb52` on `homelab-01` and
  `e-navigator-bench-mp7cf` on `homelab-02` were Ready with zero restarts and
  used `ghcr.io/e-navigator/e-navigator@sha256:72acf600c86be7b9a2a0c4ca8ae905e065232e26125e1cdf575f515c53668a48`.
- Direct `/healthz` returned `ok`; direct `/readyz` returned `ready`;
  `/metrics` returned 257 lines.
- trace backendrary workload pods were deleted.
- Helm revision `49` rolled the release back to revision `47`; the restored
  DaemonSet rolled out successfully.

Live workload:

- Two Python socket server pods and two Python nonblocking client pods ran in
  `e-navigator-bench`, pinned one server/client pair per homelab node.
- Server IPs were `10.42.248.216` on `homelab-01` and `10.42.134.22` on
  `homelab-02`.
- Both clients completed 120 requests with no application failures.
- Client logs reported `bytes_out=29160` and `bytes_in=164640` on each node.
- Captured E-Navigator stdout contained 120 controlled `network_connection_close`
  records for observed target `10.42.134.22:8080` on `homelab-02`.
- All 120 observed controlled close records were byte-bearing, each with
  `bytes_sent=243` and `bytes_received=1372`.
- Captured E-Navigator stdout had 0 controlled Kubernetes-attributed close
  records, 0 controlled `network_flow_summary` records, and 0
  `network_flow_bytes` JSON signals.
- Direct `/metrics` exposed aggregate container-runtime network counters for the
  controlled traffic path, including `network_connection_open_count`,
  `network_traffic_destination_count`, and `network_connection_duration_count`
  at `120`.
- Direct `/metrics` contained 0 `network_flow_bytes` lines.

Outcome: `partial`.

Proven:

- The pushed image runs on both homelab nodes from the recorded GHCR digest.
- Socket send/recv byte accounting works for the observed controlled
  nonblocking Python client path: `network_connection_close` records now carry
  nonzero `bytes_sent` and `bytes_received`.
- Direct Prometheus HTTP health, readiness, and metrics exposure stayed healthy
  during the proof.

Not proven:

- Symmetric controlled-client stdout capture across both nodes.
- Kubernetes pod/container attribution for the controlled Python client closes.
- Controlled `network_flow_summary`; the generator still requires Kubernetes
  attribution on close events.
- Direct or Prometheus `network_flow_bytes` export from controlled
  live traffic.

Non-claims:

- No external flow agent replacement claim.
- No production-ready claim.
- No reduced-overhead claim.
- No reduced-privilege claim.
- No byte-accuracy claim beyond the observed controlled socket path.
