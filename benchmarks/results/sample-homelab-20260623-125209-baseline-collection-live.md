# Homelab Sample: Baseline Collection Snapshot

Run: `20260623-125209`

Raw evidence lives under `benchmarks/results/20260623-125209/`.

Scope: collection-only live proof on `staging` context,
`e-navigator-bench` namespace only.

Deployment:

- Apply mode was disabled.
- Cleanup mode was disabled.
- The live Helm release was not upgraded or rolled back by this run.
- DaemonSet `e-navigator-bench` was `2/2` Ready.
- Runtime image was
  `ghcr.io/e-navigator/e-navigator@sha256:90b571bf89ac36c1432a503ad9b9add7abd7604579533c1912201568db1d5bfc`.
- Runtime pods were:
  - `e-navigator-bench-q6xjf` on `homelab-01`.
  - `e-navigator-bench-r5ggq` on `homelab-02`.

Observed signals and metrics:

- Captured JSON stdout contained:
  - 497 `network_connection_open` records.
  - 495 `network_connection_close` records.
  - 243 `network_flow_summary` records.
  - 1,489 `network_counter_metric` records.
  - 495 `network_duration_metric` records.
  - 775 `network_gauge_metric` records.
- Direct Prometheus HTTP probes returned `200 OK` for `/healthz`,
  `/readyz`, and `/metrics`.
- Direct `/metrics` exposed 80 metric lines across 8 network metric families:
  `network_connection_active`, `network_connection_duration_count`,
  `network_connection_duration_max_nanos`,
  `network_connection_duration_min_nanos`,
  `network_connection_duration_sum_nanos`, `network_connection_open_count`,
  `network_protocol_connection_open_count`, and
  `network_traffic_destination_count`.
- Prometheus API checks were skipped because no Prometheus API URL or service
  was configured for this collection-only run.

Resource and privilege evidence:

- Ten `kubectl top pods --containers` samples recorded:
  - `e-navigator-bench-q6xjf`: CPU `41m` to `48m`, average `45.7m`;
    memory steady at `31Mi`.
  - `e-navigator-bench-r5ggq`: CPU `9m` to `11m`, average `10.2m`;
    memory `21Mi` to `22Mi`, average `21.3Mi`.
- Both pods reported UID/GID `0`, `NoNewPrivs: 1`, `Seccomp: 0`, and
  `CapEff=000001c401283004`.
- The decoded effective capabilities included `CAP_SYS_ADMIN`,
  `CAP_SYS_PTRACE`, `CAP_NET_ADMIN`, `CAP_NET_RAW`, `CAP_PERFMON`, and
  `CAP_BPF`.

Namespace observations:

- The namespace still contained older completed proof pods and two older
  namespace-local fake collector services from previous runs. They were
  observed but not modified by this collection-only run.

Outcome: `proven` for collection-only baseline readiness, direct Prometheus
HTTP endpoint availability, live network JSON/stdout output, and current
resource/capability posture on the observed DaemonSet revision.

Not proven:

- Prometheus server active-target or query proof.
- Reduced privilege, non-root operation, or RuntimeDefault seccomp on this
  baseline revision.
- Reduced overhead versus another agent or another E-Navigator revision.
- Controlled workload attribution for this run; no workload was created.
