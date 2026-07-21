# Homelab network kernel-hook A/B sample, 2026-07-21

This is the committed numeric record for the Gap 2 BTF fexit evaluation. The
guarded collector's verbose per-run Kubernetes state and logs remain local
under `benchmarks/results/gap2-kernel-hook-ab-20260721/`. The normalized
machine-readable record is
[`documentation/proof/kernel-hook-20260721/runs.json`](../../documentation/proof/kernel-hook-20260721/runs.json).

## Method

- Kubernetes context: `homelab`; no other context was used.
- Nodes: two amd64 NixOS 24.05 nodes, Linux 6.6.68, k3s 1.30.4.
- Arms: no benchmark agent, forced syscall tracepoints, and forced BTF fexit.
- Order: `none/tracepoint/fexit`, `fexit/none/tracepoint`, then
  `tracepoint/fexit/none`.
- Repetitions: three per arm, 90 measured seconds each.
- Workload: one Python process pinned to `homelab-01`, using one loopback TCP
  connection and explicit 256-byte `os.write`/`os.read` round trips.
- Sampling: 20 `kubectl top pods` and `kubectl top nodes` captures per run.
- Configuration: network source only, RingBuf fixed, namespace capture filter,
  JSON correctness output, and Prometheus loss counters.

## Raw run values

Latency percentile values are histogram upper bounds. CPU is millicores and
memory is MiB. Agent totals sum the two DaemonSet pods only when both were
present in a sample.

| Arm | Run | Operations | Operations/s | Mean us | p50 <= us | p95 <= us | p99 <= us | Max us | Agent CPU | Agent RSS | Exact bytes | Zero loss |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- | --- |
| none | 1 | 3,530,533 | 39,228.137 | 23.613528 | 50 | 50 | 50 | 6,130.439 | n/a | n/a | n/a | n/a |
| none | 2 | 3,572,017 | 39,689.070 | 23.354489 | 50 | 50 | 50 | 7,565.687 | n/a | n/a | n/a | n/a |
| none | 3 | 3,549,554 | 39,439.483 | 23.433312 | 50 | 50 | 50 | 6,420.531 | n/a | n/a | n/a | n/a |
| tracepoint | 1 | 3,131,005 | 34,788.937 | 26.753750 | 50 | 50 | 50 | 9,263.873 | 14.450000 | 20.000000 | yes | yes |
| tracepoint | 2 | 2,917,284 | 32,414.266 | 28.594189 | 50 | 50 | 100 | 8,527.715 | 11.944444 | 21.833333 | yes | yes |
| tracepoint | 3 | 3,122,383 | 34,693.143 | 26.787174 | 50 | 50 | 50 | 8,890.254 | 15.500000 | 20.000000 | yes | yes |
| fexit | 1 | 3,287,294 | 36,525.485 | 25.347185 | 50 | 50 | 50 | 8,192.949 | 11.150000 | 34.000000 | yes | yes |
| fexit | 2 | 3,300,252 | 36,669.461 | 25.267120 | 50 | 50 | 50 | 8,120.360 | 16.684211 | 35.000000 | yes | yes |
| fexit | 3 | 3,314,082 | 36,823.126 | 25.187901 | 50 | 50 | 50 | 8,275.196 | 14.117647 | 33.000000 | yes | yes |

## Three-run summaries

Values are arithmetic means with sample standard deviation across run means.

| Arm | Operations/s | Mean latency us | Agent CPU m | Agent RSS MiB |
| --- | ---: | ---: | ---: | ---: |
| none | 39,452.230 +/- 230.731 | 23.467 +/- 0.133 | n/a | n/a |
| tracepoint | 33,965.449 +/- 1,344.217 | 27.378 +/- 1.053 | 13.965 +/- 1.827 | 20.611 +/- 1.058 |
| fexit | 36,672.691 +/- 148.847 | 25.267 +/- 0.080 | 13.984 +/- 2.770 | 34.000 +/- 1.000 |

Fexit versus tracepoint measured +7.970576% operations/s, -7.710353% mean
latency, +0.137044% two-pod agent CPU, and about +64.956% two-pod RSS. Against
the no-agent baseline, fexit measured -7.045329% operations/s. The result
supports adopting fexit for this narrow scalar network read/write path, with
the memory tradeoff and old-kernel runtime-proof gap retained as explicit
boundaries.
