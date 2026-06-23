# Failed/Inconclusive Homelab Follow-Up: 20260620-180718

This is a curated summary of the raw artifacts in
`benchmarks/results/20260620-180718-failed-inconclusive-validation/`.

## Scope

- Context: `staging`
- Namespace: `e-navigator-bench`
- Release: `e-navigator-bench`
- Image: `ghcr.io/e-navigator/e-navigator:sha-8ab271c`
- Pull secret: `ghcr-pull-secret` in `e-navigator-bench`
- Observed nodes: `homelab-01` and `homelab-02`
- Cleanup: not run

No credential material is included in this summary.

## Preflight

All requested preflight commands passed before live deployment:

- `cargo fmt --all -- --check`
- `cargo clippy --locked --workspace --all-targets --exclude e-navigator-ebpf-programs -- -D warnings`
- `cargo test --locked --workspace --exclude e-navigator-ebpf-programs`
- `cargo build --locked --workspace --exclude e-navigator-ebpf-programs`
- `helm lint charts/e-navigator`
- `helm template e-navigator charts/e-navigator | kubeconform -strict -summary -`
- `tests/homelab_bench_guard_test.sh`
- `git diff --check`

## Registered Export Capability

Code inspection still found only `sink.json_stdout` as a concrete registered
runtime sink. OTEL metric, trace, Prometheus text, HTTP exporter, and profile
formatting code exists as library and test surfaces, but there is no registered
runtime OTLP, trace backend, Prometheus scrape, external profile backend, or pprof sink in this release.

This is the blocking boundary for OTLP/trace backend/external profile backend/Prometheus export proof:
no sidecar or external transformer was counted as E-Navigator export.

## Service And Prometheus Scrape

The chart and runtime Service expose port `9090`, and the Service had endpoints
for both E-Navigator pods. In-cluster probes to `/`, `/metrics`, `/health`,
`/healthz`, `/ready`, and `/readyz` all failed with connection refused on port
`9090`.

No `ServiceMonitor` or `PodMonitor` existed in `e-navigator-bench`. Rendering
with `serviceMonitor.enabled=true` produces a `ServiceMonitor`, but it was not
installed for this run.

Prometheus read-only queries showed:

- `up{namespace="e-navigator-bench"}` returned an empty vector;
- `series?match[]=up{namespace="e-navigator-bench"}` returned an empty list;
- kubelet/cAdvisor container metrics for E-Navigator were present.

This proves kubelet/cAdvisor resource visibility only. It does not prove
E-Navigator's own Prometheus scrape export.

## OTLP, trace backend, And external profile backend

Read-only observability inspection found Alloy, Prometheus, trace backend, external flow agent, Loki,
and node-exporter services in the homelab stack. Alloy exposes OTLP receivers on
`4317` and `4318`, and trace backend exposes OTLP ports.

E-Navigator still did not export to those surfaces in this run because no
registered runtime OTLP sink exists. trace backend ingestion, OTLP export, and external profile backend
compatibility/export remain not proven.

## Controlled Workload And Runtime Signals

The controlled workload
`e-navigator-bench-workload-180718` ran in `e-navigator-bench` with:

- `app.kubernetes.io/name=e-navigator-bench-workload`
- `app.kubernetes.io/part-of=e-navigator-validation`

It completed successfully after 180 DNS/TCP/HTTP/exec loops. The first bounded
wait timed out before completion, but the second wait observed the job as
complete. Final job duration was about 9m20s with zero pod restarts.

The default E-Navigator log scan found:

| Pattern | Count |
| --- | ---: |
| `source.aya_exec` | 1,035 |
| `source.aya_network` | 1,265 |
| `source.host_resource` | 818 |
| `source.aya_cpu_profile` | 0 |
| DNS signal kinds or DNS fields | 0 |
| workload name/label/pod marker | 0 |
| workload pod IP | 0 |

This proves live exec, network, and host-resource signal emission in this run.
It does not prove DNS runtime capture or controlled workload attribution.

## CPU Profiling

A profile-mode canary switched the chart to `--source aya-cpu-profile` with
`source.aya_cpu_profile` explicitly enabled. In that mode, E-Navigator emitted
18,986 `source.aya_cpu_profile` `profile_sample_observation` records.

That proves the CPU profile source can emit sample records on the homelab when
explicitly configured. The intended controlled CPU workload failed because the
BusyBox shell lacked `SECONDS`; a corrected retry was blocked by a transient
Kubernetes API `ServiceUnavailable` before applying the workload. Therefore
controlled CPU-workload attribution, external profile backend export, pprof export, and OTLP
profile export remain not proven.

The release was restored to default `--source aya-exec` mode after the canary.

## Resource Overhead

`kubectl top pods --containers` was sampled 10 times during the default workload
window:

| Pod | Samples | CPU avg | CPU min | CPU max | Memory avg | Memory min | Memory max |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `e-navigator-bench-cmxkb` | 10 | `13.8m` | `12m` | `18m` | `53Mi` | `53Mi` | `53Mi` |
| `e-navigator-bench-wbncb` | 10 | `35.5m` | `31m` | `41m` | `85Mi` | `85Mi` | `85Mi` |

The chart requested `50m` CPU and `128Mi` memory per pod, with no CPU limit and
a `512Mi` memory limit. Prometheus kubelet/cAdvisor queries also returned
resource metrics for E-Navigator containers, but included old, profile-canary,
and restored pods over the 10-minute window.

No reduced-overhead claim is made because there is still no equivalent
external flow agent/Alloy/trace backend/Prometheus/external profile backend replacement workload and export parity.

## Capabilities And Reduced Privilege

The restored E-Navigator pods ended Ready with zero restarts. Effective process
state for both restored pods showed:

- `CapEff=000001c401283004`
- `CAP_DAC_READ_SEARCH`, `CAP_NET_ADMIN`, `CAP_NET_RAW`, `CAP_SYS_PTRACE`,
  `CAP_SYS_ADMIN`, `CAP_SYS_RESOURCE`, `CAP_SYSLOG`, `CAP_PERFMON`, `CAP_BPF`,
  and `CAP_CHECKPOINT_RESTORE`
- `NoNewPrivs=1`
- `Seccomp=0`
- UID/GID `0`
- read-only host mounts for `/host/proc`, `/host/cgroup`, `/sys/kernel/debug`,
  and `/sys/kernel/tracing`

This does not prove reduced-privilege eBPF hardening. `CAP_SYS_ADMIN` remains
present and seccomp is disabled.

## Replacement-Readiness Matrix

| Target | Status | Evidence boundary |
| --- | --- | --- |
| external flow agent L4 flow replacement | partial | Aya TCP events emitted, but no byte-accurate parity, scrape/export parity, or workload attribution |
| Alloy OTLP collector replacement | not proven | no registered runtime OTLP sink |
| trace backend trace ingestion compatibility | not proven | no legitimate E-Navigator OTLP export path |
| Prometheus scrape/export compatibility | not proven | port `9090` refused connections; no `ServiceMonitor`/`PodMonitor`; Prometheus `up` series empty |
| external profile backend/profile export compatibility | not proven | profile samples emitted, but no external profile backend or pprof exporter |
| DNS runtime capture | not proven | workload performed DNS lookups, but logs contained zero DNS runtime signal evidence |
| CPU profile capture | proven for source emission | profile-mode canary emitted `source.aya_cpu_profile` sample records |
| Workload attribution | not proven | workload completed, but emitted records did not include workload identity markers |
| Reduced privilege | not proven | `CAP_SYS_ADMIN` present and seccomp disabled |
| Reduced overhead | not proven | resource samples captured, but no equivalent replacement baseline |

## Proof Boundary

This run proves:

- homelab context `staging` targeted `homelab-01` and `homelab-02`;
- E-Navigator DaemonSet readiness on both nodes after default rollout and final
  restore;
- live Aya exec, Aya network, and host-resource signal emission;
- CPU profile source emission when explicitly switched to `aya-cpu-profile`;
- short-window `kubectl top` CPU and memory samples;
- kubelet/cAdvisor resource metrics in Prometheus;
- service `9090` connection refusal from inside the cluster;
- absence of `ServiceMonitor`/`PodMonitor` in `e-navigator-bench`;
- effective capabilities, `NoNewPrivs`, seccomp state, UID/GID, and host mounts.

This run does not prove:

- E-Navigator OTLP export to Alloy or trace backend;
- E-Navigator Prometheus scrape export;
- trace backend ingestion;
- external profile backend or pprof export;
- DNS packet capture;
- controlled workload attribution;
- CPU profile attribution to a controlled workload;
- external flow agent, Alloy, trace backend, Prometheus, or external profile backend replacement readiness;
- reduced-overhead or reduced-privilege readiness.
