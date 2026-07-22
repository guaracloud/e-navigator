# ADR 0013: Event-Driven Cgroup Discovery

Status: accepted

Date: 2026-07-22

## Context

The capture-filter controller previously scanned the unified cgroup tree every
two seconds. A Kubernetes Pod watch updated identity promptly, but the desired
cgroup map still waited for the next filesystem scan. Each source then waited
up to another second before applying the published map. A new workload
therefore followed `capture_filter.unknown_cgroup` for a few seconds.

That posture is intentionally safe and must not change. Under an allowlist,
`unknown_cgroup = "deny"` creates a temporary coverage gap. Under a denylist,
`unknown_cgroup = "allow"` creates a temporary capture leak. Reducing either
window requires prompt cgroup discovery, prompt map application, bounded loss
recovery, and native accounting.

Linux inotify reports directory creation, deletion, and moves without a new
capability. It is not recursive, can race while a new subtree is being watched,
and its kernel queue can overflow. The kernel documentation recommends adding
watches recursively, scanning a new directory immediately, and rebuilding
state after `IN_Q_OVERFLOW`; see
[inotify(7)](https://man7.org/linux/man-pages/man7/inotify.7.html). The selected
safe Rust wrapper exposes the nonblocking descriptor through Tokio and keeps
the raw event decoder outside E-Navigator; see
[inotify 0.11.4](https://docs.rs/inotify/0.11.4/inotify/).

Fanotify can watch a complete mount or filesystem without per-directory marks,
but those marks require `CAP_SYS_ADMIN`. Its unprivileged mode is limited to
inode marks, which loses the relevant race-free advantage; see
[fanotify_init(2)](https://man7.org/linux/man-pages/man2/fanotify_init.2.html)
and
[fanotify_mark(2)](https://man7.org/linux/man-pages/man2/fanotify_mark.2.html).
That conflicts with the reduced-privilege contract in ADR 0012.

The kernel also exposes the BTF `cgroup_mkdir` tracepoint. A BPF wakeup program
would still need userspace to join the cgroup path with the Kubernetes Pod
snapshot and evaluate policy. It would add another privileged attachment,
kernel-BTF compatibility branch, event transport, and loss surface only to
trigger the same userspace scan. The kernel documents the tracepoint in its
[BPF kfunc examples](https://docs.kernel.org/bpf/kfuncs.html).

## Decision

Use inotify as the default cgroup discovery trigger on Linux and retain the
two-second scan as a loss-recovery boundary.

The implementation has these fixed limits and recovery rules:

- one safe inotify instance per process-wide controller;
- at most 16,384 watched directories, equal to the existing bounded cgroup
  scan limit;
- one 64 KiB userspace event buffer;
- one coalesced pending-refresh slot shared by filesystem and Kubernetes watch
  notifications;
- recursive watch installation before reconciliation for every new subtree;
- explicit counters for events, installed watches, coalesced notifications,
  watch-limit drops, watcher failures, and kernel queue overflows;
- complete watch-set rebuild after queue overflow, moves that invalidate cached
  paths, unmounts, stream failure, or root-watch removal;
- exponential rebuild backoff bounded between 100 milliseconds and two
  seconds;
- a two-second periodic reconciliation even while inotify is healthy.

Map publication wakes every source applier through a condition variable. The
one-second wait remains only a shutdown and loss-recovery boundary. Every
changed desired-map generation records the interval from the earliest
coalesced notification through each source map application. A polling fallback
has no kernel creation timestamp, so it conservatively starts accounting at
the previous reconciliation completion. Native metrics expose observation
count, seconds sum, seconds maximum, and map-application failure count.

`capture_filter.discovery_mode` is a strict typed enum. `event_driven` is the
default. `polling` preserves the previous behavior for compatibility diagnosis
and reproducible A/B proof. Both modes preserve `unknown_cgroup` semantics and
the same unified cgroup v2 requirement.

## Rejected Alternatives

Fanotify mount or filesystem marks are rejected because they would reintroduce
`SYS_ADMIN` into the proven reduced profile. Per-inode fanotify marks retain
the recursive race and provide no material advantage over inotify.

A BPF `cgroup_mkdir` wakeup program is rejected for this iteration because it
adds a privileged, version-sensitive transport without eliminating the
userspace scan or Kubernetes join. It can be reconsidered only if measured
inotify overhead or reliability is inadequate on a supported kernel family.

Reducing the polling interval alone is rejected because it continuously walks
the whole tree, scales cost with cgroup count rather than change rate, and
still leaves a phase-dependent window.

Removing periodic reconciliation is rejected because inotify queues and watch
installation can lose events. The fallback scan is the convergence guarantee.

## Evidence And Consequences

The controller, coalescer, configuration, metrics, and immediate map
publication have unit and property coverage. Recursive watch installation is
tested on Linux, and the coalescer has Criterion coverage. No new E-Navigator
raw-event decoder exists, so no new fuzz target is required; the dependency
owns the checked inotify ABI decoding while the full fuzz-target build remains
part of the gate.

The homelab proof compares the preserved polling mode with event-driven mode
across multiple counterbalanced new-Pod runs and a no-agent workload control.
Its curated evidence is stored in
`documentation/proof/bootstrap-window-20260722/`.

Five Linux 6.6.68 homelab repetitions per mode measured a 1,148.131 ms polling
median and 1,216.842 ms p95, versus a 0.463 ms event-driven median and 0.487 ms
p95. All watcher, map-application, and exec-source loss gates were zero. This
meets the adoption criterion for event-driven discovery while retaining
polling as a diagnostic and loss-recovery path.

This decision reduces but does not eliminate the bootstrap window. Kubernetes
watch delivery, cgroup traversal, userspace scheduling, policy evaluation, and
per-source map updates still take nonzero time. Watch failure degrades loudly
to the periodic scan rather than changing the configured unknown posture.
