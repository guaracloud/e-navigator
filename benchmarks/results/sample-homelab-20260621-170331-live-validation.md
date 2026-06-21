# Homelab Live Validation Summary: 20260621-170331

Curated summary for raw artifacts under
`benchmarks/results/20260621-170331-live-validation/`.

## Scope

- Context: `staging`
- Namespace: `e-navigator-bench`
- Image: `ghcr.io/guaracloud/e-navigator:sha-8ab271c`
- Pull secret: not used
- Cleanup: not run

The required image predates the current local checkout's registered
`source.aya_dns`, `sink.prometheus_http`, and `sink.otlp_http` runtime config.
The live config was kept compatible with that image, so local tests for those
newer surfaces are not upgraded to live proof by this run.

## Proven

- DaemonSet rolled out on `homelab-01` and `homelab-02`.
- Controlled default workload completed.
- Default runtime logs contained 1,561 `source.aya_exec`, 2,004
  `source.aya_network`, and 1,064 `source.host_resource` matches.
- Controlled workload exec/network and derived records included Kubernetes
  namespace, pod name, pod UID, container name, node name, bounded labels, and
  containerd container ID.
- Default runtime logs contained network/resource/dependency/trace/security
  derived records.
- Explicit profile mode emitted 16,494 `source.aya_cpu_profile` records and
  5,552 profiling session observations.
- Ten `kubectl top pods --containers` samples were captured.
- Final capability capture showed `CAP_SYS_ADMIN` present and seccomp disabled.

## Not Proven

- Runtime DNS capture: workload performed DNS lookups, but logs contained zero
  `dns_query` or `dns_response` records.
- Prometheus export: no Service, Endpoints, ServiceMonitor, or PodMonitor existed
  in `e-navigator-bench`.
- OTLP, Tempo, Pyroscope, and pprof export: no live E-Navigator export path was
  configured or observed.
- Controlled CPU-workload attribution: the profile workload completed, but its
  identity was absent from profile logs.
- Reduced overhead and reduced privilege.
- Beyla, Alloy, Tempo, Prometheus, or Pyroscope replacement readiness.

## Resource Samples

| Pod | Samples | CPU avg | CPU min | CPU max | Memory avg |
| --- | ---: | ---: | ---: | ---: | ---: |
| `e-navigator-bench-4sztj` | 10 | `37.2m` | `33m` | `39m` | `50Mi` |
| `e-navigator-bench-d6t4p` | 10 | `12.9m` | `12m` | `15m` | `36Mi` |

## Final State

The release was restored to default `aya-exec` mode after the profile canary.
No cleanup was run.
