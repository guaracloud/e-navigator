# Homelab Sample: Published Prometheus Formatter Image

Run: `20260623-131846`

Raw evidence lives under `benchmarks/results/20260623-131846/`.

Scope: guarded homelab validation on Kubernetes context `staging`, namespace
`e-navigator-bench`, after deploying the published formatter-change image.

Preconditions:

- Git commit: `5469a11`
- CI run: `28028794649`, success
- Image publication run: `28028794673`, success
- Published tag: `ghcr.io/e-navigator/e-navigator:sha-5469a11`
- Image index digest:
  `sha256:e5e7226fbbfce4ebb894dd3de5000c72f8f82e50eba520c72267b923f0bbe780`
- Linux amd64 digest:
  `sha256:2de950aece9580dcb5c896d5df386899d12f76ccfd34b97535a34d8a3edc8738`

Live action:

- Helm release `e-navigator-bench` was upgraded in namespace
  `e-navigator-bench` from revision `127` to revision `128`.
- The upgrade preserved the existing runtime values and changed only the image
  tag/digest to the published `sha-5469a11` digest.
- The release was not rolled back; revision `128` remained deployed after the
  collection.

Observed evidence:

- DaemonSet `e-navigator-bench` rolled out successfully and stayed `2/2` Ready
  on `homelab-01` and `homelab-02`.
- The live DaemonSet image was
  `ghcr.io/e-navigator/e-navigator@sha256:2de950aece9580dcb5c896d5df386899d12f76ccfd34b97535a34d8a3edc8738`.
- Direct Prometheus HTTP probes through the service returned `200 OK` for
  `/healthz`, `/readyz`, and `/metrics`.
- Direct `/metrics` exposed 40 metric lines across 8 network metric families.
- JSON stdout logs contained:
  - 481 `network_connection_open` records;
  - 429 `network_connection_close` records;
  - 213 `network_flow_summary` records;
  - 1,443 `network_counter_metric` records;
  - 428 `network_duration_metric` records;
  - 736 `network_gauge_metric` records.
- Ten `kubectl top` samples recorded:
  - `homelab-02` pod `e-navigator-bench-628hm`: 10m-26m CPU, 19Mi memory;
  - `homelab-01` pod `e-navigator-bench-q47tl`: 39m-66m CPU, 23Mi-26Mi
    memory.
- Both pods still reported UID/GID `0`, `NoNewPrivs: 1`, `Seccomp: 0`, and
  `CAP_SYS_ADMIN` among other required eBPF capabilities.

Outcome: `partial`.

Proven:

- The published `sha-5469a11` image can roll out on the homelab benchmark
  DaemonSet and keep the existing network-source, network-generator, JSON
  stdout, and direct Prometheus HTTP baseline healthy.

Not proven:

- Prometheus server active-target or query proof; the collector did not have a
  Prometheus API URL or service configured.
- `network_flow_bytes` live export; no controlled native metric-producing
  workload was run and no matching direct `/metrics` or JSON stdout lines were
  observed.
- Reduced privilege, reduced overhead, production exporter throughput, or any
  replacement-readiness claim.
