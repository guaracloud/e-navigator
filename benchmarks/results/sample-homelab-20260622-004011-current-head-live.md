# Homelab Current-Head Live Sample: 20260622-004011

Raw evidence lives under
`benchmarks/results/20260622-004011-current-head-live/`.

This run validated the current pushed `main` image after the docs-only evidence
commit. The previous runtime proof used `sha-d3167e3`; this run rolled the
current head image `sha-c89f345` to the homelab and collected a fresh live
proof slice.

## Target

- Kubernetes context: `staging`
- Namespace: `e-navigator-bench`
- Helm release: `e-navigator-bench`
- Commit: `c89f345`
- Image: `ghcr.io/e-navigator/e-navigator:sha-c89f345`
- Image index digest:
  `sha256:cd2300e3ed149c6d32e71dd25d70b96443b2f2bfb43443f2bcd1b18b1623a473`
- Linux/amd64 manifest digest:
  `sha256:96e7ed5710bdb58273f41945cbaf402cce04a148a2d2f8541f0e9c02672e81f0`
- Prior live image: `ghcr.io/e-navigator/e-navigator:sha-d3167e3`

`c89f345` changed documentation and curated evidence only relative to
`d3167e3`; the runtime code was unchanged, but this run still proves the
published current-head image rolls and runs on the homelab.

## Rollout

Helm revision 35 deployed `sha-c89f345`. Final pod state:

| Pod | Node | Image ID | Restarts | Ready |
| --- | --- | --- | --- | --- |
| `e-navigator-bench-rczmn` | `homelab-02` | `ghcr.io/e-navigator/e-navigator@sha256:cd2300e3ed149c6d32e71dd25d70b96443b2f2bfb43443f2bcd1b18b1623a473` | `0` | `true` |
| `e-navigator-bench-rjxnz` | `homelab-01` | `ghcr.io/e-navigator/e-navigator@sha256:cd2300e3ed149c6d32e71dd25d70b96443b2f2bfb43443f2bcd1b18b1623a473` | `0` | `true` |

The table above intentionally records the observed image ID string from
Kubernetes. The expected current-head image index digest is listed in the target
section.

## Controlled Workload

A timestamped copy of `benchmarks/k8s/workload.yaml` created
`job/e-nav-current-head-workload-20260622-004011`. The first
`kubectl wait --timeout=180s` timed out, but immediate follow-up inspection
showed the Job completed successfully:

- completion: `1/1`
- duration: `3m6s`
- pod: `e-nav-current-head-workload-20260622-004011-4wh25`
- node: `homelab-01`
- container exit code: `0`

No manual cleanup was performed. The workload manifest carries
`ttlSecondsAfterFinished: 300`.

## JSON Stdout Evidence

An eight-minute log window from both E-Navigator pods contained `19098` lines
and zero sink-failure lines. Parsed JSON signal source counts:

```text
4852 generator.trace_correlation
4310 generator.network_metrics
3366 source.aya_network
3028 source.aya_exec
1616 source.host_resource
1342 generator.resource_metrics
 474 generator.dependency_graph
  45 generator.runtime_security
```

Notable parsed signal kind counts:

```text
3652 network_counter_metric
3112 service_interaction_span_observation
2890 network_connection_failure
2220 process_exit
1266 trace_correlation_warning
 808 exec
 474 trace_service_path_observation
 474 dependency_edge
 254 network_connection_open
 222 network_connection_close
  45 runtime_security_finding
```

The stdout log search did not find the controlled workload pod name, job prefix,
container ID, or command marker. This run therefore does not prove controlled
workload attribution in JSON stdout.

## Prometheus Evidence

Direct service checks returned:

- `/healthz`: `ok`
- `/readyz`: `ready`
- `/metrics`: `348` lines

Direct `/metrics` included current-head controlled workload attribution:

- `network_connection_open_count` for
  `k8s_namespace_name="e-navigator-bench"` and
  `k8s_pod_name="e-nav-current-head-workload-20260622-004011-4wh25"` with value
  `167`
- `network_connection_failure_count` for the same workload pod with value `1`

Homelab Prometheus API queries returned:

- `up{namespace="e-navigator-bench"}`: `2` targets, both `1`
- `network_connection_open_count{namespace="e-navigator-bench"}`: `38` series
- `network_connection_open_count{k8s_namespace_name="e-navigator-bench"}`:
  `1` series for the controlled workload pod
- `network_connection_failure_count{k8s_namespace_name="e-navigator-bench"}`:
  `1` series for the controlled workload pod
- `{job=~".*e-navigator.*"}`: `486` series

## Resource And Capability Snapshot

Ten `kubectl top pods --containers` samples showed:

- `e-navigator-bench-rczmn`: `12m`-`17m` CPU, `36Mi`-`37Mi` memory
- `e-navigator-bench-rjxnz`: `36m`-`39m` CPU, `51Mi` memory

Both live containers reported UID/GID `0`, `NoNewPrivs: 1`, `Seccomp: 0`, and:

```text
CapEff: 000001c401283004
CAP_DAC_READ_SEARCH,CAP_NET_ADMIN,CAP_NET_RAW,CAP_SYS_PTRACE,CAP_SYS_ADMIN,CAP_SYS_RESOURCE,CAP_SYSLOG,CAP_PERFMON,CAP_BPF,CAP_CHECKPOINT_RESTORE
```

This remains privilege posture evidence only. It is not reduced-privilege proof.

## Non-Claims

This run does not prove:

- successful upstream OTLP protobuf metrics, traces, or profiles;
- trace backend ingestion;
- external profile backend or pprof export;
- native byte-accurate flow replacement;
- runtime DNS eBPF packet capture;
- controlled workload attribution in JSON stdout;
- reduced overhead versus existing homelab observability agents;
- reduced-privilege Kubernetes eBPF operation.
