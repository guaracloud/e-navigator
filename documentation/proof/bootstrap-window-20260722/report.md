# Capture-Filter Bootstrap-Window Homelab Proof

Date: 2026-07-22

Result: PASS for the scoped Linux 6.6.68 homelab comparison.

## Scope

The guarded campaign compared the preserved 2-second polling behavior with
bounded event-driven cgroup discovery. It ran only on the two-node `homelab`
context, never on production. The exact local candidate was loaded directly
into both nodes and was never pushed to a registry.

The workload was pinned to `homelab-01`, ran as UID 65532, and recorded its
start time before immediately executing a unique probe path every 10
milliseconds for six seconds. The allowlist posture used
`unknown_cgroup = "deny"`, so the first workload-correlated exec signal
measures the observable coverage gap from process start until the cgroup map
allowed the Pod. Each agent arm used two fresh DaemonSet pods.

## Command

```bash
E_NAVIGATOR_HOMELAB_CONFIRM=1 \
E_NAVIGATOR_HOMELAB_IMAGE_REPOSITORY=docker.io/library/e-navigator \
E_NAVIGATOR_HOMELAB_IMAGE_TAG=gap8-bootstrap-amd64 \
benchmarks/runner/homelab-bootstrap-window.sh
```

The harness ran one no-agent correctness control and five repetitions per
agent mode. Order was counterbalanced as polling/event, event/polling,
polling/event, event/polling, and polling/event. Every arm was installed,
collected, analyzed, and removed before the next arm.

## Results

| Mode | Windows, ms | Median, ms | P95, ms | Standard deviation, ms |
| --- | --- | ---: | ---: | ---: |
| Polling | 1186.848, 1148.131, 1216.842, 1007.865, 987.286 | 1148.131 | 1216.842 | 105.194 |
| Event driven | 0.462, 0.443, 0.463, 0.464, 0.487 | 0.463 | 0.487 | 0.016 |

Event-driven discovery reduced the median observed signal window by
1147.667 ms, or 99.959648%, and improved the predeclared p95 comparison. The
no-agent control completed 523 probe attempts with zero failures. Event-driven
runs captured 521 or 522 correlated signals. Polling runs captured 416 to 436
because the initial probes remained denied until the next periodic scan.

Across the five event-driven runs, native accounting recorded 120 discovery
notifications, 116 event reconciliations, and 30 inotify events. Across every
agent run, inotify failures, queue overflows, watch-limit drops, map-application
failures, exec transport loss, perf loss, RingBuf reservation failures, and
userspace send failures were all zero.

The focused local Criterion benchmark measured one-slot coalescing of 64
notifications at 53.112 to 53.664 ns. That number is local hot-path hygiene,
not a homelab or whole-agent overhead result.

## Cleanup And Claim Boundary

After the final arm, the benchmark Helm release was absent, the namespace was
empty, the standing Argo CD application was `Synced/Healthy`, and its
DaemonSet was ready on both nodes.

This proves a much smaller new-Pod coverage window for one non-root exec
workload on this Linux 6.6.68 k3s cluster. It does not prove an instantaneous
policy update, every container runtime or cgroup driver, sustained churn,
production behavior, or immunity to inotify loss. Kubernetes watch delivery,
cgroup traversal, policy evaluation, userspace scheduling, and map updates
remain nonzero. Watcher failures preserve `unknown_cgroup` semantics and fall
back loudly to periodic reconciliation.
