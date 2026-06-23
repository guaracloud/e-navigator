# Homelab Sample: RuntimeDefault Seccomp For E-Navigator DaemonSet

Run:

- `20260623-041434-runtime-default-seccomp-live`

Raw evidence lives under
`benchmarks/results/20260623-041434-runtime-default-seccomp-live/`.

Scope: `staging` context, `e-navigator-bench` namespace only.

Change under proof:

- The chart default container `securityContext` now renders
  `seccompProfile.type: RuntimeDefault`.
- The live proof reused the current release values and baseline image
  `ghcr.io/e-navigator/e-navigator@sha256:90b571bf89ac36c1432a503ad9b9add7abd7604579533c1912201568db1d5bfc`.
- No image or runtime code change was part of this proof.

Local proof before deployment:

- `tests/chart_service_guard_test.sh`
- `helm lint charts/e-navigator`
- `helm template e-navigator charts/e-navigator | kubeconform -strict -summary -`

Live configuration:

- Helm release `e-navigator-bench` was upgraded from revision `97` to revision
  `98` using the local chart plus the pre-upgrade release values.
- The rendered upgrade contained `seccompProfile.type: RuntimeDefault`.
- The release kept the existing `source.aya_network`,
  `generator.network_metrics`, `generator.network_metrics`, `sink.json_stdout`,
  and `sink.prometheus_http` configuration.

Observed evidence:

- DaemonSet `e-navigator-bench` rolled out successfully and stayed `2/2` Ready.
- Runtime pods were:
  - `e-navigator-bench-7htmj` on `homelab-01`
  - `e-navigator-bench-hkszw` on `homelab-02`
- `/proc/1/status` inside both pods reported:
  - `Uid: 0 0 0 0`
  - `Gid: 0 0 0 0`
  - `CapEff: 000001c401283004`
  - `NoNewPrivs: 1`
  - `Seccomp: 2`
- Post-upgrade logs included live `source.aya_network` records from both
  `homelab-01` and `homelab-02`.
- A direct `/metrics` scrape through the namespace Service returned 264 lines,
  including live network metric series.
- Controlled pods `seccomp-net-homelab01-041434` and
  `seccomp-net-homelab02-041434` completed on their pinned nodes, but the
  captured E-Navigator logs did not include those pod names. This run does not
  claim controlled workload attribution.
- Failure-marker search over the post-workload E-Navigator logs found no
  `error`, `failed`, `verifier`, `seccomp`, `permission denied`, or
  `operation not permitted` entries.

Cleanup:

- Deleted the two temporary controlled workload pods.
- Rolled Helm release `e-navigator-bench` back to revision `97`; Helm recorded
  revision `99` as `Rollback to 97`.
- Final DaemonSet state was `2/2` Ready on the baseline image.
- The final rendered live DaemonSet no longer had a `seccompProfile` field,
  matching the pre-test baseline.

Outcome: `proven` for the chart default rendering `RuntimeDefault` seccomp and
for the current homelab E-Navigator DaemonSet starting, staying Ready, and
emitting live network logs and metrics under kernel-applied `Seccomp: 2`.

Not proven:

- Non-root operation.
- Capability reduction.
- Removal of `CAP_SYS_ADMIN`.
- RuntimeDefault seccomp compatibility for every optional source mode,
  especially DNS, HTTP, and CPU profiling.
- Controlled workload attribution during this seccomp proof.
- Production rollout or longer soak.
