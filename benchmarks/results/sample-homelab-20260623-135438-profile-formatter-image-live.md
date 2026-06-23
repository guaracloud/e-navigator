# Homelab Sample: Profile Formatter Image Rollout

Run: `20260623-135438`

Raw evidence lives under `benchmarks/results/20260623-135438/`.

Scope: guarded collection-only homelab validation after manually upgrading the
benchmark release to the pushed profile-formatter image. No temporary proof
workload, Collector, or Prometheus API port-forward was created for this run.

Preflight and rollout:

- `kubectl config current-context` returned `staging`.
- The only touched namespace was `e-navigator-bench`.
- GitHub CI run `28031028689` passed for commit `6c04aaa`.
- GitHub `publish-images` run `28031029226` passed for commit `6c04aaa`.
- Published tag: `ghcr.io/guaracloud/e-navigator:sha-6c04aaa`.
- Published index digest:
  `sha256:dc2461ddf38253bf0d51668d7e28c515b44f56173a2bd4c1ad8cfbec7ecc5744`.
- Published linux/amd64 digest:
  `sha256:3abcd8d1c9b9b890801eeab94252f8cc507cd0dba665ddcc449cf409275b90d0`.
- Helm revision `129` rolled out with image
  `ghcr.io/guaracloud/e-navigator@sha256:3abcd8d1c9b9b890801eeab94252f8cc507cd0dba665ddcc449cf409275b90d0`.

Collector note:

- `run-metadata.txt` records the collector script's default required image
  intent. The actual live image for this run is proven by `helm-values.txt`,
  `helm-manifest.txt`, `daemonset.txt`, `daemonset-yaml.txt`, and `events.txt`.

Observed evidence:

- DaemonSet `e-navigator-bench` was `2/2` Ready on `homelab-01` and
  `homelab-02`.
- Events recorded two successful pulls of the new linux/amd64 digest.
- Direct `/healthz` returned `HTTP/1.1 200 OK` with body `ok`.
- Direct `/readyz` returned `HTTP/1.1 200 OK` with body `ready`.
- Direct `/metrics` returned `HTTP/1.1 200 OK` and 233 metric lines across
  9 network metric families.
- JSON stdout counts from the captured logs:
  - 924 `network_counter_metric`
  - 445 `network_gauge_metric`
  - 309 `network_connection_open`
  - 295 `network_duration_metric`
  - 295 `network_connection_close`
  - 210 `network_flow_summary`
- Ten resource samples showed:
  - `homelab-01` pod `e-navigator-bench-59d6x`: 39m-50m CPU, 23Mi-26Mi.
  - `homelab-02` pod `e-navigator-bench-5xmrf`: 10m-23m CPU, 19Mi.
- Both pods reported UID/GID 0, `NoNewPrivs: 1`, `Seccomp: 0`, and the same
  effective capability set including `CAP_SYS_ADMIN`.
- No precise E-Navigator log markers matched sink write failure, panic,
  verifier, permission, or load-failure patterns.

Outcome: `partial`.

Proven:

- The pushed `sha-6c04aaa` image rolled out on the homelab benchmark release
  and kept the default network/Prometheus HTTP runtime healthy in the observed
  collection window.

Not proven:

- Live profile formatter behavior. The baseline release did not enable
  `source.aya_cpu_profile`, `generator.profiling`, `sink.otlp_http`, or a
  Pyroscope/profile export path, and the captured logs contained zero profile
  records.
- Prometheus server scrape/queryability. No Prometheus API URL/service was
  configured for this collection.
- `beyla_network_flow_bytes_total`; direct `/metrics` contained zero such
  lines.
- Reduced privilege, reduced overhead, profile storage, Pyroscope write
  transport, symbolization, or production-readiness claims.
