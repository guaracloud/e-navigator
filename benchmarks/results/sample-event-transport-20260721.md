# Homelab event transport A/B sample, 2026-07-21

This is the committed numeric record for the Gap 1 BPF event-transport run.
The guarded collector's complete per-run bundles remain local under
`benchmarks/results/gap1-event-transport-ab-20260721/`; that directory is
ignored because it contains verbose Kubernetes state and logs. The curated,
machine-readable record is
[`documentation/proof/event-transport-20260721/runs.json`](../../documentation/proof/event-transport-20260721/runs.json).

## Method

- Kubernetes context: `homelab`; no other context was used.
- Nodes: two amd64 NixOS 24.05 nodes, Linux 6.6.68, k3s 1.30.4.
- Arms: no E-Navigator benchmark release, forced `perf_buffer`, and forced
  `ring_buffer`.
- Order: `none/perf/ring`, `ring/none/perf`, then `perf/ring/none`.
- Repetitions: three per arm, 180 seconds each.
- Workload: one same-node Python HTTP/1.1 server plus a 16-worker client. The
  client repeatedly opened connections, issued requests, performed DNS
  resolution, and created short-lived processes. Only the exec and network Aya
  sources were enabled in the benchmark agent.
- Sampling: `kubectl top pods` and `kubectl top nodes` every five seconds while
  the workload ran. Metrics Server repeats values at its own cadence, so these
  samples are observational and correlated.
- Configuration: 256 KiB per retained event map; JSON stdout disabled;
  Prometheus HTTP enabled for native counters.

## Raw run values

Latency percentile values are histogram upper bounds, not interpolated
percentiles. CPU is millicores and memory is MiB. Agent totals sum the two
DaemonSet pods only when both were present in a sample.

| Arm | Run | Requests | Failures | Requests/s | Mean ms | p50 <= ms | p95 <= ms | p99 <= ms | Max ms | Agent CPU | Agent RSS |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| none | 1 | 7,552 | 0 | 41.955 | 96.746306 | 5 | 2,000 | 2,000 | 1,235.593824 | n/a | n/a |
| none | 2 | 7,552 | 0 | 41.955 | 95.894379 | 5 | 2,000 | 2,000 | 1,247.203430 | n/a | n/a |
| none | 3 | 7,552 | 0 | 41.955 | 93.309280 | 5 | 2,000 | 2,000 | 1,230.781559 | n/a | n/a |
| perf | 1 | 7,552 | 6 | 41.955 | 91.900305 | 5 | 2,000 | 2,000 | 2,020.440999 | 87.588235 | 65.558824 |
| perf | 2 | 7,552 | 7 | 41.955 | 97.447090 | 5 | 2,000 | 2,000 | 3,010.098549 | 80.416667 | 65.500000 |
| perf | 3 | 7,616 | 0 | 42.311 | 93.925059 | 5 | 2,000 | 2,000 | 1,230.235009 | 83.969697 | 65.575758 |
| ring | 1 | 7,616 | 6 | 42.311 | 94.890096 | 5 | 2,000 | 2,000 | 2,309.219128 | 94.222222 | 63.388889 |
| ring | 2 | 7,488 | 12 | 41.600 | 99.346627 | 5 | 2,000 | 2,000 | 2,931.390924 | 91.888889 | 62.416667 |
| ring | 3 | 7,488 | 1 | 41.600 | 93.161484 | 5 | 2,000 | 2,000 | 2,030.820427 | 94.600000 | 62.085714 |

## Three-run summaries

Values are arithmetic means with sample standard deviation across the three
run means.

| Arm | Requests/s | Mean latency ms | Failures/run | Agent CPU m | Agent RSS MiB |
| --- | ---: | ---: | ---: | ---: | ---: |
| none | 41.955000 +/- 0.000000 | 95.316655 +/- 1.789863 | 0.000000 +/- 0.000000 | n/a | n/a |
| perf | 42.073667 +/- 0.205537 | 94.424151 +/- 2.806871 | 4.333333 +/- 3.785939 | 83.991533 +/- 3.585834 | 65.544861 +/- 0.039762 |
| ring | 41.837000 +/- 0.410496 | 95.799402 +/- 3.191258 | 6.333333 +/- 5.507571 | 93.570370 +/- 1.468405 | 62.630423 +/- 0.677374 |

Observed RingBuf deltas against perf were -0.562506% requests/s, +1.456461%
mean latency, +11.404527% agent CPU, and -4.446478% agent RSS. All completed
perf and ring runs reported zero transport loss for both enabled Aya sources.
The log stream covered both nodes; the scraped point-in-time Prometheus surface
covered one service-selected pod.

These results do not establish a throughput, latency, or total-overhead win for
RingBuf. The arms are short, the p95/p99 histogram resolution is coarse, and
the shared homelab has unrelated background activity. They prove that both
transports loaded, captured the exercised signal families, exposed their
selected mode and loss counters, and completed a counterbalanced A/B without
observed transport loss.

## Local handoff benchmark

The same worktree was measured with 30 Criterion samples, five seconds of
measurement, and two seconds of warmup:

| Benchmark | 95% estimate |
| --- | ---: |
| `event_transport/perf_buffer_inline_copy` | 669.42-670.44 ps |
| `event_transport/ring_buffer_borrowed_record` | 297.04-316.02 ps |

This isolates one contiguous 368-byte userspace handoff. It does not include
kernel production, notification cadence, decode, scheduling, or the complete
agent, so it is not a runtime-overhead claim.
