# Homelab Published Image Live Sample: 20260622-001716

Raw evidence lives under
`benchmarks/results/20260622-001716-published-image-live/`.

This run pushed the current `main` branch, waited for the GitHub image workflow,
deployed the produced GHCR image to the guarded homelab target, exercised the
real Alloy OTLP failure boundary, restored the baseline config, and collected
live Prometheus, log, resource, and capability evidence.

## Target

- Kubernetes context: `staging`
- Namespace: `e-navigator-bench`
- Helm release: `e-navigator-bench`
- Commit: `d3167e3`
- Image: `ghcr.io/e-navigator/e-navigator:sha-d3167e3`
- Image index digest:
  `sha256:f17ac298132fa75fea50d8f30e3f2d6a5de26d2ab0ad62e69b1a7ec044c64429`
- Linux/amd64 manifest digest:
  `sha256:82b9d5ad6aa5e11099a6b940f0b937c6c40269ebf85525af26b4868f130696a4`
- Publish workflow run: `27922038408`
- CI workflow run: `27922038342`

## Rollout

The pushed image was deployed with Helm and rolled out as a two-node DaemonSet.
After the Alloy failure-boundary test, the release was restored to the baseline
config while keeping image `sha-d3167e3`.

Final restored pods:

| Pod | Node | Image ID | Restarts | Ready |
| --- | --- | --- | --- | --- |
| `e-navigator-bench-w6klr` | `homelab-01` | `ghcr.io/e-navigator/e-navigator@sha256:f17ac298132fa75fea50d8f30e3f2d6a5de26d2ab0ad62e69b1a7ec044c64429` | `0` | `true` |
| `e-navigator-bench-wlsv9` | `homelab-02` | `ghcr.io/e-navigator/e-navigator@sha256:f17ac298132fa75fea50d8f30e3f2d6a5de26d2ab0ad62e69b1a7ec044c64429` | `0` | `true` |

## Real Alloy OTLP Boundary

The run enabled `sink.otlp_http` against real homelab Alloy at
`http://alloy.observability-system.svc.cluster.local:4318/v1/traces`.
Alloy returned HTTP 400 for the current internal-record payload shape. The
pushed image did not crash: both pods stayed Ready with zero restarts, JSON
stdout continued, and Prometheus HTTP remained reachable.

During the Alloy boundary window:

- combined log lines: `15429`
- `sink write failed; dropping signal for this sink` lines: `15162`
- observed sources included `source.aya_network`, `source.aya_exec`,
  `source.host_resource`, `generator.network_metrics`,
  `generator.trace_correlation`, `generator.dependency_graph`, and
  `generator.runtime_security`
- service checks returned `/healthz` = `ok` and `/readyz` = `ready`

This is failure-boundary proof against a real collector surface, not successful
upstream OTLP protobuf ingestion.

## Restored Baseline Evidence

After restoring the baseline config, a 75-second log window from both pods
contained `8863` lines and zero sink-failure lines. Parsed JSON signal source
counts:

```text
2203 generator.network_metrics
2015 generator.trace_correlation
1477 source.aya_network
1126 source.aya_exec
1104 generator.resource_metrics
 552 source.host_resource
 350 generator.dependency_graph
  28 generator.runtime_security
```

Notable parsed signal kind counts:

```text
1756 network_counter_metric
1267 service_interaction_span_observation
1126 network_connection_failure
1104 resource_gauge_metric
 820 process_exit
 350 dependency_edge
 306 exec
 210 network_connection_open
  28 runtime_security_finding
```

The restored Service returned:

- `/healthz`: `ok`
- `/readyz`: `ready`
- `/metrics`: `53` lines, including network and resource series

Prometheus API queries through the homelab Prometheus service returned:

- `up{namespace="e-navigator-bench"}`: `2` targets, both `1`
- `network_connection_open_count`: `25` result series
- `network_connection_failure_count`: `32` result series
- `process_thread_count`: `2` result series
- `container_process_count`: `3` result series
- `{job=~".*e-navigator.*"}`: `323` result series

## Resource And Capability Snapshot

Ten `kubectl top pods --containers` samples showed:

- `e-navigator-bench-w6klr`: `38m`-`42m` CPU, `43Mi` memory
- `e-navigator-bench-wlsv9`: `12m`-`17m` CPU, `35Mi`-`36Mi` memory

Both live containers reported:

```text
CapEff: 000001c401283004
CAP_DAC_READ_SEARCH,CAP_NET_ADMIN,CAP_NET_RAW,CAP_SYS_PTRACE,CAP_SYS_ADMIN,CAP_SYS_RESOURCE,CAP_SYSLOG,CAP_PERFMON,CAP_BPF,CAP_CHECKPOINT_RESTORE
NoNewPrivs: 1
Seccomp: 0
```

This remains a privilege posture snapshot only. It is not reduced-privilege
proof.

## Left In Namespace

No cleanup was performed. Older evidence resources from prior live runs remain
in `e-navigator-bench`. The pinned runtime-security jobs
`e-nav-runtime-security-204845-homelab-01` and
`e-nav-runtime-security-204845-homelab-02` were complete at final inventory.

## Non-Claims

This run does not prove:

- successful upstream OTLP protobuf metrics, traces, or profiles;
- trace backend ingestion;
- external profile backend or pprof export;
- native byte-accurate flow replacement;
- runtime DNS eBPF packet capture;
- reduced overhead versus external flow agent, Alloy, node-exporter, or external profile backend;
- reduced-privilege Kubernetes eBPF operation.
