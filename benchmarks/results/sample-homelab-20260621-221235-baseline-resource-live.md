# Homelab Baseline Resource And Privilege Sample: 20260621-221235

This is a curated summary of the raw artifacts in
`benchmarks/results/20260621-221235-baseline-resource-live/`.

## Scope

- Context: `staging`
- Namespace: `e-navigator-bench`
- Release: `e-navigator-bench`
- Mode: collection-only; no Helm upgrade was applied
- Image observed in live values: `ghcr.io/e-navigator/e-navigator:sha-5c417c0`
- Required image for the broader objective:
  `ghcr.io/e-navigator/e-navigator:sha-8ab271c`
- Image substitution: yes, because the live homelab release was running
  `sha-5c417c0`
- Pull secret in live Helm values: `ghcr-e-navigator-pull`
- Nodes observed: `homelab-01` and `homelab-02`

## Result

The run records a current baseline snapshot for resource usage, Prometheus
resource queries, and privilege posture. It does not prove reduced overhead or
reduced privilege.

What was recorded:

- The DaemonSet was already rolled out and `2/2` Ready.
- Live pods were:
  - `e-navigator-bench-hd5lq` on `homelab-01`
  - `e-navigator-bench-m4cg4` on `homelab-02`
- `/healthz` returned HTTP 200 with `ok`.
- `/readyz` returned HTTP 200 with `ready`.
- `/metrics` returned HTTP 200 and 335 captured response lines.
- The Service exposed endpoints `10.42.134.44:9090` and
  `10.42.248.173:9090`.
- ServiceMonitor `e-navigator-bench` existed; no PodMonitor existed in the
  namespace.
- Prometheus active-target evidence included both E-Navigator targets with
  `health=up` and empty `lastError`.
- Prometheus query `up{namespace="e-navigator-bench"}` returned both pods with
  value `1`.
- Prometheus query `{namespace="e-navigator-bench"}` returned 1,640 current
  series.
- Direct metrics included 30 `network_connection_open_count` occurrences and
  35 `network_connection_failure_count` occurrences.
- Captured logs included source and generator activity:
  - `source.aya_exec`: 441 occurrences
  - `source.aya_network`: 918 occurrences
  - `source.host_resource`: 552 occurrences
  - `generator.resource_metrics`: 341 occurrences
  - `generator.network_metrics`: 781 occurrences
  - `generator.trace_correlation`: 947 occurrences
  - `generator.runtime_security`: 5 occurrences
- No `sink write failed` lines were found in the captured log window.

## Resource Samples

`kubectl top pods --containers` was sampled 10 times at 3-second intervals.

- `e-navigator-bench-hd5lq`: 10 samples, CPU `34m` to `42m`, memory `47Mi`
- `e-navigator-bench-m4cg4`: 10 samples, CPU `12m`, memory `36Mi`

Prometheus resource queries were also recorded:

- `rate(container_cpu_usage_seconds_total[5m])`:
  - `e-navigator-bench-hd5lq`: `0.03835472217026554`
  - `e-navigator-bench-m4cg4`: `0.012299961816262044`
- `container_memory_working_set_bytes`:
  - `e-navigator-bench-hd5lq`: `50733056`
  - `e-navigator-bench-m4cg4`: `39145472`
- `kube_pod_container_resource_requests`:
  - both pods requested `0.05` CPU cores and `134217728` memory bytes
- `kube_pod_container_resource_limits`:
  - both pods had memory limit `536870912` bytes

These samples are a point-in-time baseline only. They are not a reduced-overhead
claim because no equivalent baseline agent comparison was captured in this run.

## Privilege Evidence

Rendered security context and `/proc/1/status` evidence recorded:

- `privileged: false`
- `allowPrivilegeEscalation: false`
- `readOnlyRootFilesystem: true`
- `runAsUser: 0`
- `runAsNonRoot: false`
- `NoNewPrivs: 1`
- `Seccomp: 0`
- `CapEff=000001c401283004` on both pods

Decoded effective capabilities on both pods:

- `CAP_DAC_READ_SEARCH`
- `CAP_NET_ADMIN`
- `CAP_NET_RAW`
- `CAP_SYS_PTRACE`
- `CAP_SYS_ADMIN`
- `CAP_SYS_RESOURCE`
- `CAP_SYSLOG`
- `CAP_PERFMON`
- `CAP_BPF`
- `CAP_CHECKPOINT_RESTORE`

Because the pods still run as UID 0, keep `CAP_SYS_ADMIN`, and report
`Seccomp: 0`, this run explicitly does not prove reduced-privilege eBPF
operation.

## Cleanup

No cleanup was requested or performed. This collection-only run did not create
new workload or Helm resources.

Older evidence resources from previous runs remained present in the namespace.

## Proof Boundary

This run proves that the current homelab release was Ready, scraped by
Prometheus, producing live source/generator logs, and had recorded resource and
capability evidence.

This run does not prove:

- reduced overhead;
- reduced privilege;
- external flow agent replacement readiness;
- trace backend, external profile backend, Alloy, or production collector compatibility;
- runtime DNS packet capture;
- live `network_flow_bytes` export;
- a clean namespace free of older proof resources.
