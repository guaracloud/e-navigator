# Homelab Sample: New Container Kubernetes Attribution Refresh

Run: `20260622-192821-new-container-attribution-live`

Scope: `staging` context, `e-navigator-bench` namespace only.

Image:

- Git SHA: `dd67a3b`
- Tag: `ghcr.io/e-navigator/e-navigator:sha-dd67a3b`
- Image index digest: `sha256:42d61e6f63d6276e6c8932aff6dc38a803ca32c4cd74ce83c5495afdb65bb0c4`
- Deployed amd64 digest: `sha256:5082072c88fb2b525a5d860484cd1bf16a4c2d2870af2d31ff9bdb08819a638d`
- GitHub Actions: CI run `27988083319` and publish-images run `27988083329` succeeded.

Local proof before deployment:

- Focused regression test failed before the fix:
  `cargo test --locked -p e-navigator-processors refreshes_kubernetes_metadata_for_new_container_miss_after_successful_refresh -- --nocapture`
- `cargo test --locked -p e-navigator-processors refreshes_kubernetes_metadata_for_new_container_miss_after_successful_refresh -- --nocapture`
- `cargo test --locked -p e-navigator-processors retries_kubernetes_metadata_refresh_after_requested_container_miss -- --nocapture`
- `cargo test --locked -p e-navigator-processors kubernetes_refresh_is_single_flight_for_concurrent_misses -- --nocapture`
- `cargo fmt --all -- --check`
- `cargo test --locked -p e-navigator-processors -p e-navigator-generators`
- `cargo clippy --locked -p e-navigator-processors --all-targets -- -D warnings`
- `git diff --check`
- `scripts/quality.sh`

Deployment evidence:

- Preflight verified local path `/Users/victorbona/Daedalus/e-navigator`,
  current context `staging`, namespace `e-navigator-bench`, and homelab nodes
  `homelab-01` and `homelab-02`.
- Helm baseline revision before the proof was `49`.
- Helm revision `50` rolled `sha-dd67a3b` into the DaemonSet.
- DaemonSet pods `e-navigator-bench-24h7w` on `homelab-01` and
  `e-navigator-bench-7qwbz` on `homelab-02` were Ready with zero restarts and
  used `ghcr.io/e-navigator/e-navigator@sha256:5082072c88fb2b525a5d860484cd1bf16a4c2d2870af2d31ff9bdb08819a638d`.
- trace backendrary proof workloads were deleted.
- Helm rollback restored revision `49`; restored DaemonSet pods used
  `ghcr.io/e-navigator/e-navigator@sha256:90b571bf89ac36c1432a503ad9b9add7abd7604579533c1912201568db1d5bfc`.
- No resources remained with label
  `e-navigator-proof-run=20260622-192821-new-container-attribution-live`.

Live workload:

- A Python HTTP server and Python client Job ran in `e-navigator-bench`, both
  pinned to `homelab-02` with the homelab control-plane toleration.
- The first workload attempt was Pending because it lacked the control-plane
  toleration; it was deleted without traffic evidence and replaced by r2.
- Server pod: `e-nav-attrib-192821-r2-server-6b88544-q9pq7`, IP
  `10.42.134.26`.
- Client pod: `e-nav-attrib-192821-r2-client-2zq4g`, IP `10.42.134.27`.
- Server Service: `e-nav-attrib-192821-r2-server`, ClusterIP `10.43.208.245`.
- Client completed 1,594 HTTP requests with 0 errors.
- Captured E-Navigator stdout contained 34 controlled byte-bearing
  `network_connection_close` records for the client pod, all with container and
  Kubernetes attribution.
- Captured E-Navigator stdout contained 34 controlled `network_flow_summary`
  records for the same client pod.
- Direct `/metrics` on the homelab-02 E-Navigator pod contained
  Kubernetes-attributed aggregate client counters at 1,574 for
  `network_connection_open_count`, `network_traffic_destination_count`, and
  `network_connection_duration_count`.
- Captured E-Navigator stdout contained 0 `network_flow_bytes` JSON
  signals.
- Direct `/metrics` contained 0 `network_flow_bytes` lines.

Outcome: `partial`.

Proven:

- The pushed image runs on both homelab nodes from the recorded GHCR digest.
- Newly created controlled workload containers can refresh Kubernetes metadata
  after a previous successful cache refresh.
- Byte-bearing controlled `network_connection_close` records can carry
  Kubernetes attribution for the new Python client container.
- Controlled `network_flow_summary` records can be generated from those
  Kubernetes-attributed byte-bearing close records.
- Direct Prometheus HTTP metrics can expose Kubernetes-attributed aggregate
  counters for the controlled client pod.

Not proven:

- `network_flow_bytes` export from the controlled workload.
- Prometheus-server API query proof; no Prometheus server service exists inside
  `e-navigator-bench`.
- Symmetric controlled-client capture across both homelab nodes.
- external flow agent replacement readiness.

Non-claims:

- No external flow agent replacement claim.
- No production-ready claim.
- No reduced-overhead claim.
- No reduced-privilege claim.
- No E-Navigator `namespace-*` tenant-scope proof.
