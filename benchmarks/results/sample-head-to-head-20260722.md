# Sample Full-Stack Head-To-Head Result (2026-07-22)

Homelab Linux 6.6.68, three repetitions per condition and cumulative signal
stage, 33 validated runs, fixed HTTP, gRPC, Redis, PostgreSQL, and CPU-bound
Python workloads:

| Final stack | Agent CPU m mean +/- sd | Agent RSS MiB mean +/- sd |
| --- | ---: | ---: |
| Beyla plus Alloy profiles | 81.721 +/- 5.618 | 137.131 +/- 4.680 |
| E-Navigator | 117.353 +/- 6.010 | 180.881 +/- 5.079 |

E-Navigator measured 43.601071% more agent CPU and 31.903883% more agent RSS
than Beyla plus Alloy in this scoped final-stage comparison. All 591,030
measured workload operations succeeded. E-Navigator hard-loss counters were
zero; final-stage Beyla metrics left 17 of 14,400 gRPC operations unaccounted;
Alloy collected and forwarded 55 profiles with zero drops or failing sessions,
while recording one empty-stack and one wrong-text-section diagnostic.

This result rejects a lower-overhead claim. It does not establish production,
capacity, long-duration, or universal latency and resource behavior. Full
method, per-run values, variance, raw representative metrics, and cleanup state
are in `documentation/proof/head-to-head-20260722/`.
