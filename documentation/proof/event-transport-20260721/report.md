# BPF event transport proof, 2026-07-21

## Decision

RingBuf is the default transport on kernels that positively report support,
with a strict perf-event fallback only when the probe reports unsupported. The
homelab proves that forced RingBuf and forced perf modes both load and carry the
exercised exec and network event families on Linux 6.6.68 with zero observed
transport loss.

The run does not support a RingBuf overhead-win claim. Across three
counterbalanced 180-second runs per arm, RingBuf had 0.56% lower request
throughput, 1.46% higher mean latency, 11.40% higher two-pod agent CPU, and
4.45% lower two-pod RSS than perf. The throughput and latency movements are
small relative to run variance, and the shared cluster had background work.

## Implementation proved

The userspace loader carries two separately built eBPF objects. A kernel
feature probe selects the RingBuf object in `auto` mode. A positive unsupported
result selects the perf object; an indeterminate probe fails startup instead of
guessing. Forced modes are strict. Each retained event map has a typed,
power-of-two capacity from 4 KiB through 16 MiB, with a 256 KiB default.

RingBuf producer output failures increment fixed per-CPU slots in
`EVENT_TRANSPORT_LOSSES`. Userspace polls only the slots owned by its source and
exports cumulative loss and reservation-failure counters. Perf losses continue
to use Aya's `PerfEvent::Lost` path and feed the same aggregate transport-loss
counter. There is no silent transport drop path in the implementation.

The raw event layouts did not change. Existing raw-event fuzz targets and
decoder tests therefore cover the same ABI boundary for both transports; no
second transport-specific decoder was introduced.

## Environment and method

- Context: `homelab`, exclusively.
- Cluster: k3s `v1.30.4+k3s1`, two amd64 NixOS 24.05 nodes, Linux 6.6.68,
  containerd `1.7.20-k3s1`.
- Image: `docker.io/library/e-navigator:gap1-20260721`, OCI manifest
  `sha256:dfea79f89390ed4f306243dedc6f4aecc53c4bb921481bd9ab41e1a930c85035`.
  It was loaded directly into the two homelab nodes and was never pushed.
- Arms: no benchmark E-Navigator release, forced perf, and forced RingBuf.
- Order: `none/perf/ring`, `ring/none/perf`, then `perf/ring/none`.
- Workload: a same-node HTTP/1.1 server and 16-worker connection-heavy client,
  with DNS lookups and short-lived process churn. The benchmark agents enabled
  only `source.aya_exec` and `source.aya_network` among Aya sources.
- Sampling: 36 pod and node resource captures per run at five-second spacing.
  Metrics Server cadence makes adjacent samples correlated.

The complete numeric record is in [runs.json](runs.json), with a readable copy
under `benchmarks/results/sample-event-transport-20260721.md`.

## Runtime results

| Arm | Requests/s mean +/- sd | Mean latency ms +/- sd | Failures/run +/- sd | Agent CPU m +/- sd | Agent RSS MiB +/- sd |
| --- | ---: | ---: | ---: | ---: | ---: |
| no benchmark agent | 41.955000 +/- 0.000000 | 95.316655 +/- 1.789863 | 0.000000 +/- 0.000000 | n/a | n/a |
| perf | 42.073667 +/- 0.205537 | 94.424151 +/- 2.806871 | 4.333333 +/- 3.785939 | 83.991533 +/- 3.585834 | 65.544861 +/- 0.039762 |
| ring | 41.837000 +/- 0.410496 | 95.799402 +/- 3.191258 | 6.333333 +/- 5.507571 | 93.570370 +/- 1.468405 | 62.630423 +/- 0.677374 |

Every completed agent run logged the selected mode from both pods. Periodic
source summaries for both pods reported zero lost transport events, zero perf
losses, zero RingBuf reservation failures, zero invalid samples, and zero send
failures for the enabled exec and network sources. Prometheus snapshots also
reported zero transport loss for the service-selected pod.

The workload's 2-second timeout produced 13 failures across the three perf
runs and 19 across the three ring runs, versus zero in the no-agent arm. The
variation and coarse latency histogram prevent a stronger comparative claim.

## Local Criterion result

Thirty samples, a five-second measurement, and a two-second warmup measured a
contiguous 368-byte userspace handoff:

| Path | 95% estimate |
| --- | ---: |
| perf inline copy | 669.42-670.44 ps |
| RingBuf borrowed record | 297.04-316.02 ps |

This demonstrates the isolated borrowed-record advantage. It excludes kernel
production, notification behavior, task scheduling, decode, and the rest of
the agent, so the live A/B remains authoritative for runtime overhead.

## Boundaries

- No old-kernel homelab node was available. Unit tests prove selection behavior,
  but the automatic perf fallback is not runtime-proven on an old kernel.
- Only exec and network event maps were exercised in this A/B. Both eBPF
  variants build all event maps, and local tests cover map ownership and loss
  slot uniqueness, but the other source families were not re-proven here.
- This is homelab evidence, not production evidence.
- It does not prove lower overhead than perf, Beyla, Alloy, or any production
  stack.

## Cleanup and restore

The disposable workload and Helm release were removed after every run. The
standing Argo CD application was restored to automated prune and self-heal,
reported `Synced` and `Healthy`, and its original digest-pinned DaemonSet was
2/2 Ready. A disposable image-cleaner DaemonSet verified that the locally
imported image reference was absent from both containerd stores, then the
cleaner and empty benchmark namespace were deleted. The local OCI temporary
archive was also removed.
