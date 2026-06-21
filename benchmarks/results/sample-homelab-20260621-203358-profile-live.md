# Homelab CPU Profile Live Validation Summary: 20260621-203358

Curated summary for raw local artifacts under
`benchmarks/results/20260621-203358-profile-live/`.

## Scope

- Context: `staging`
- Namespace: `e-navigator-bench`
- Release: `e-navigator-bench`
- Required image: `ghcr.io/guaracloud/e-navigator:sha-8ab271c`
- Configured image: `ghcr.io/guaracloud/e-navigator:sha-5c417c0`
- Image substitution: yes
- Pull secret: namespace GHCR pull secret configured
- Source mode: `aya-cpu-profile`
- Controlled workload: `e-navigator-bench-profile-20260621-203358`
- Cleanup: not run

## Proven

- The profile-mode DaemonSet rolled out on both homelab nodes.
- Final logs contained 10,284 `source.aya_cpu_profile`
  `profile_sample_observation` records.
- Final logs contained 10,271 `generator.profiling`
  `profiling_session_observation` records.
- Mid-run logs contained 274 controlled workload profile sample records and 274
  controlled workload profiling session records.
- Controlled workload profile evidence included namespace, pod name, pod UID,
  container name, node name, bounded labels, containerd container ID, process
  PID, command, UID, and cgroup ID.
- The controlled workload completed.
- Ten `kubectl top pods --containers` samples were captured.
- Capability capture showed the profile-mode pods still ran as root with
  `CAP_SYS_ADMIN`, `NoNewPrivs: 1`, and `Seccomp: 0`.
- The release was restored to the working Prometheus-enabled `aya-exec` config.

## Not Proven

- Function symbolization beyond bounded raw IP stack frames.
- pprof, Pyroscope, OTLP profile export, profile storage, or flamegraph UI.
- Reduced privilege.
- Reduced overhead versus an equivalent baseline.

## Resource Samples

During profile mode, ten samples showed:

| Pod | CPU range | Memory range |
| --- | --- | --- |
| `e-navigator-bench-75zfn` | `172m`-`174m` | `31Mi`-`34Mi` |
| `e-navigator-bench-dgtng` | `125m`-`128m` | `23Mi` |

These samples are runtime observations only. They do not prove reduced overhead
without an equivalent baseline.

## Evidence

- Config validation: `validate-config.txt`
- Rollout: `rollout.txt`
- Controlled workload: `profile-workload.yaml`, `workload-apply.txt`,
  `workload-wait.txt`, `workload-logs.txt`
- Profile logs: `logs-midrun.txt`, `logs.txt`
- Capabilities: `proc-status.txt`, `capability-decode.txt`
- Resource samples: `top-pods-10-samples.txt`
- Restore proof: `restore-rollout.txt`, `pods-after-restore.txt`
