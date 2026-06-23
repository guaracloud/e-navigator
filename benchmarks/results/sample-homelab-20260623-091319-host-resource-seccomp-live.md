# Homelab Sample: Host Resource Metrics Under RuntimeDefault Seccomp

Run:

- `20260623-091319-host-resource-seccomp-live`

Raw evidence lives under
`benchmarks/results/raw/20260623-091319-host-resource-seccomp-live/`.

Scope: `staging` context, `e-navigator-bench` namespace only.

Image:

- Git SHA: `ab19ab5c1035d66e797a6358cd6e6f618e169096`
- Tag: `ghcr.io/e-navigator/e-navigator:sha-ab19ab5`
- Image index digest:
  `sha256:15636a27455af55d027ce8b33c23c8f684f4528e94116a1232f73cff5475f40a`
- Linux/amd64 digest:
  `sha256:3fc3fa6d8c17b339adeb66345dd004f2db67327a200182ec49e294a84c57b2c4`
- CI run: `28014978771`
- Image publish run: `28014978420`

Local proof before deployment:

- `cargo test --locked -p e-navigator-sources-host`
- `cargo test --locked -p e-navigator-generators resource_metrics`
- `helm lint charts/e-navigator`
- `helm lint charts/e-navigator -f benchmarks/results/raw/20260623-091319-host-resource-seccomp-live/values.yaml`
- `cargo run --locked -p e-navigator-cli -- --source synthetic --config benchmarks/results/raw/20260623-091319-host-resource-seccomp-live/e-navigator.toml --validate-config`
- `helm template e-navigator-bench charts/e-navigator -n e-navigator-bench -f benchmarks/results/raw/20260623-091319-host-resource-seccomp-live/values.yaml`
- `kubectl --context staging -n e-navigator-bench apply --dry-run=server -f benchmarks/results/raw/20260623-091319-host-resource-seccomp-live/rendered.yaml`

Live configuration:

- Helm release `e-navigator-bench` upgraded from revision `107` to revision
  `108` with chart `RuntimeDefault` seccomp enabled.
- Runtime args were `--source aya-exec --config /etc/e-navigator/e-navigator.toml`.
- `source.host_resource`, `processor.container_attribution`,
  `generator.resource_metrics`, `sink.json_stdout`, and
  `sink.prometheus_http` were enabled.
- `source.aya_exec`, network, DNS, HTTP, CPU profile, trace, request,
  profiling, dependency graph, runtime-security, native export, and OTLP
  modules were disabled for this focused run.
- The host resource sampler used `/host/proc`, `/sys`, and `/host/cgroup` with
  a `5000` millisecond interval.

Observed evidence:

- DaemonSet `e-navigator-bench` rolled out successfully and stayed `2/2` Ready.
- Runtime pods were:
  - `e-navigator-bench-48znv` on `homelab-02`
  - `e-navigator-bench-cd4qf` on `homelab-01`
- Both pods ran
  `ghcr.io/e-navigator/e-navigator@sha256:15636a27455af55d027ce8b33c23c8f684f4528e94116a1232f73cff5475f40a`.
- `/proc/1/status` inside both pods reported UID/GID `0`, `NoNewPrivs: 1`,
  `Seccomp: 2`, and `CapEff: 000001c401283004`.
- Captured JSON stdout contained the following signal totals:
  - `7,443` `resource_counter_metric`
  - `5,120` `process_resource_observation`
  - `3,993` `cgroup_cpu_observation`
  - `3,913` `cgroup_pids_observation`
  - `3,913` `cgroup_memory_observation`
  - `3,413` `resource_gauge_metric`
  - `746` `node_disk_io_observation`
  - `40` `node_memory_observation`
  - `40` `node_load_observation`
  - `40` `node_cpu_observation`
- `source.host_resource` emitted node, process, and cgroup observations on both
  homelab nodes:
  - `homelab-01`: `2,176` process observations, `2,176` cgroup CPU
    observations, `2,142` cgroup memory observations, `2,142` cgroup pids
    observations, `493` disk observations, and `17` each of node CPU, load, and
    memory observations.
  - `homelab-02`: `2,944` process observations, `1,817` cgroup CPU
    observations, `1,771` cgroup memory observations, `1,771` cgroup pids
    observations, `253` disk observations, and `23` each of node CPU, load, and
    memory observations.
- `generator.resource_metrics` emitted resource gauge and counter metrics on
  both nodes, including `system.cpu.time`, `system.disk.io`,
  `system.disk.operations`, `system.memory.available`,
  `system.cpu.load_average.milli`, `process.cpu.time`,
  `process.memory.usage`, `process.open_file_descriptor.count`,
  `container.cpu.time`, `container.memory.usage`, and
  `container.process.count`.
- Direct service checks over a namespace-local port-forward returned
  `/healthz = ok`, `/readyz = ready`, and `163` `/metrics` lines.
- Direct `/metrics` included system, process, and container resource series,
  including Kubernetes-attributed E-Navigator container series for pod
  `e-navigator-bench-48znv` in namespace `e-navigator-bench`.
- `kubectl top pods --containers` reported E-Navigator pod samples of `18m/9Mi`
  on `homelab-02` and `15m/12Mi` on `homelab-01`.
- Precise failure-marker search found zero `ModuleFailed`, `PipelineClosed`,
  `permission denied`, `Operation not permitted`, `verifier`, or `panicked`
  lines.
- The log contained one non-fatal Kubernetes metadata cache refresh warning and
  `40` host resource warning summary lines. The warning summaries did not block
  node, process, cgroup, or metric output.

Cleanup:

- No workload resources were created for this run.
- Rolled Helm release `e-navigator-bench` back to revision `107`; Helm recorded
  revision `109` as `Rollback to 107`.
- Final DaemonSet state was `2/2` Ready on the baseline image
  `ghcr.io/e-navigator/e-navigator@sha256:90b571bf89ac36c1432a503ad9b9add7abd7604579533c1912201568db1d5bfc`.

Outcome: `proven` for host resource node, process, and cgroup observation plus
derived resource metric generation under kernel-applied RuntimeDefault seccomp
on both observed homelab nodes.

Not proven:

- Host resource accuracy against an independent node-exporter or cAdvisor
  baseline.
- Lossless process or cgroup enumeration.
- Warning-free host resource collection.
- Reduced overhead, longer soak behavior, or production cardinality bounds.
- Non-root operation, capability reduction, or removal of `CAP_SYS_ADMIN`.
