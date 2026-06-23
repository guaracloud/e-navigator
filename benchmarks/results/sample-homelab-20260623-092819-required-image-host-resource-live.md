# Homelab Sample: Required Image Host Resource Output

Run:

- `20260623-092819-required-image-host-resource-live`

Raw evidence lives under
`benchmarks/results/raw/20260623-092819-required-image-host-resource-live/`.

Scope: `staging` context, `e-navigator-bench` namespace only.

Image:

- Required benchmark image tag:
  `ghcr.io/e-navigator/e-navigator:sha-8ab271c`
- Image index digest:
  `sha256:249ad67fa8578ade9ecc1279bcf52a52ae6038a342b7c68844ebfd7a38d4e34e`
- Linux/amd64 digest:
  `sha256:ea498be7196ae6fbc3b48f895d49a7bacf7597289ee401dd5254706bae2c17c6`

Local proof before deployment:

- `cargo run --locked -p e-navigator-cli -- --source synthetic --config benchmarks/results/raw/20260623-092819-required-image-host-resource-live/e-navigator.toml --validate-config`
- `helm lint charts/e-navigator -f benchmarks/results/raw/20260623-092819-required-image-host-resource-live/values.yaml`
- `helm template e-navigator-bench charts/e-navigator -n e-navigator-bench -f benchmarks/results/raw/20260623-092819-required-image-host-resource-live/values.yaml`
- `docker run --rm --platform linux/amd64 -v "$PWD/benchmarks/results/raw/20260623-092819-required-image-host-resource-live/e-navigator.toml:/tmp/e-navigator.toml:ro" ghcr.io/e-navigator/e-navigator:sha-8ab271c --source synthetic --config /tmp/e-navigator.toml --validate-config`
- `kubectl --context staging -n e-navigator-bench apply --dry-run=server -f benchmarks/results/raw/20260623-092819-required-image-host-resource-live/rendered.yaml`

Live configuration:

- Helm release `e-navigator-bench` upgraded from revision `109` to revision
  `110`.
- Runtime args were `--source aya-exec --config /etc/e-navigator/e-navigator.toml`.
- The config was kept compatible with the older required image and enabled
  `source.aya_exec`, `source.host_resource`,
  `processor.container_attribution`, `generator.resource_metrics`, and
  `sink.json_stdout`.
- `source.aya_network`, `source.aya_cpu_profile`,
  `generator.network_metrics`, `generator.trace_correlation`,
  `generator.profiling`, `generator.dependency_graph`, and
  `generator.runtime_security` were disabled for this focused run.
- Newer modules and config sections that the required image predates were
  omitted.

Observed evidence:

- DaemonSet `e-navigator-bench` rolled out successfully and stayed `2/2` Ready.
- Runtime pods were:
  - `e-navigator-bench-cmf7v` on `homelab-02`
  - `e-navigator-bench-dd986` on `homelab-01`
- Both pods ran
  `ghcr.io/e-navigator/e-navigator@sha256:249ad67fa8578ade9ecc1279bcf52a52ae6038a342b7c68844ebfd7a38d4e34e`.
- `/proc/1/status` inside both pods reported UID/GID `0`, `NoNewPrivs: 1`,
  `Seccomp: 2`, and `CapEff: 000001c401283004`.
- Captured JSON stdout contained the following signal totals:
  - `3,140` `resource_counter_metric`
  - `2,816` `process_resource_observation`
  - `1,934` `cgroup_cpu_observation`
  - `1,890` `cgroup_pids_observation`
  - `1,890` `cgroup_memory_observation`
  - `1,525` `resource_gauge_metric`
  - `1,292` `process_exit`
  - `528` `exec`
  - `314` `node_disk_io_observation`
  - `22` `node_memory_observation`
  - `22` `node_load_observation`
  - `22` `node_cpu_observation`
- `source.host_resource` emitted node, process, and cgroup observations on both
  homelab nodes:
  - `homelab-01`: `512` process observations, `512` cgroup CPU observations,
    `504` cgroup memory observations, `504` cgroup pids observations, `116`
    disk observations, and `4` each of node CPU, load, and memory observations.
  - `homelab-02`: `2,304` process observations, `1,422` cgroup CPU
    observations, `1,386` cgroup memory observations, `1,386` cgroup pids
    observations, `198` disk observations, and `18` each of node CPU, load, and
    memory observations.
- `generator.resource_metrics` emitted resource gauge and counter metrics on
  both nodes, including `container.cpu.time`, `process.cpu.time`,
  `system.cpu.time`, `system.disk.io`, `system.disk.operations`,
  `container.memory.usage`, `container.process.count`,
  `system.cpu.load_average.milli`, `system.cpu.saturation.*`, and
  `system.memory.*`.
- `kubectl top pods --containers` reported E-Navigator pod samples of `21m/23Mi`
  on `homelab-02` and `25m/39Mi` on `homelab-01`.
- Precise failure-marker search found zero `ModuleFailed`, `PipelineClosed`,
  `permission denied`, `Operation not permitted`, `verifier`, `panicked`, or
  Kubernetes metadata cache refresh failures.
- The log contained `22` host resource warning summary lines. The warning
  summaries did not block node, process, cgroup, or metric output.

Cleanup:

- No workload resources were created for this run.
- Rolled Helm release `e-navigator-bench` back to revision `109`; Helm recorded
  revision `111` as `Rollback to 109`.
- Final DaemonSet state was `2/2` Ready on the baseline image
  `ghcr.io/e-navigator/e-navigator@sha256:90b571bf89ac36c1432a503ad9b9add7abd7604579533c1912201568db1d5bfc`.

Outcome: `proven` for live `source.host_resource` output and
`generator.resource_metrics` output on the required benchmark image
`sha-8ab271c` under kernel-applied RuntimeDefault seccomp on both observed
homelab nodes.

Not proven:

- Prometheus HTTP export on `sha-8ab271c`; the required image predates the
  current `sink.prometheus_http` config path used in later runs.
- DNS, HTTP, profile, OTLP, trace backend, external profile backend, Alloy, or external flow agent compatibility on
  `sha-8ab271c`.
- Warning-free host resource collection.
- Host resource accuracy against an independent node-exporter or cAdvisor
  baseline.
- Lossless process or cgroup enumeration.
- Reduced overhead, non-root operation, capability reduction, or removal of
  `CAP_SYS_ADMIN`.
