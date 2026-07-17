# ADR 0002: Unified Source Supervisor

- Status: accepted
- Date: 2026-07-17

## Context

The v0.1.1 CLI selects one of `aya-exec`, `aya-cpu-profile`, or `synthetic`.
The general mode can start several real sources, but it cannot start CPU
profiling. Every source currently owns its eBPF object and reader lifecycle,
and any source error stops the entire runner. Every source and signal family
also feeds one bounded processing queue.

The production target is one process and one DaemonSet pod per eligible node.
General capture and profiling must run together, while source and destination
failures remain isolated and observable.

## Decision

The CLI gains a default `unified` mode. In that mode every enabled real source
is registered from strict typed configuration. `synthetic` remains a separate
non-privileged validation mode. Legacy single-family modes remain temporarily
available for focused diagnostics and compatibility with existing smoke
scripts; they are not production modes.

The runner is the source supervisor. It owns:

- registration and startup of independently enabled sources;
- a configurable `fail_fast` or `isolate` source-failure policy;
- source lifecycle state transitions and failure accounting;
- coordinated process shutdown and bounded drain deadlines;
- the shared input boundary into the static
  `Source -> Processor -> Generator -> Sink` pipeline.

`fail_fast` preserves the historical behavior and is useful in tests.
`isolate` keeps healthy sources running after one source fails and is the
production policy. A failed source remains failed until process restart unless
a future source-specific restart policy is accepted in another ADR. The
runner must never silently convert a source failure into a clean exit.

The runner keeps these transitions in a process-local registry populated only
from the static module registry. A feedback-safe native telemetry adapter
exports each configured source's running state plus cumulative start,
clean-exit, and failure totals. These lifecycle metrics do not claim that every
optional probe attachment succeeded; attachment health remains source-specific.

Expensive workload discovery and cgroup policy calculation are process-wide.
Sources may maintain independent eBPF maps when kernel object ownership
requires it, but they apply diffs from the same desired workload state. New
probe attachment must not duplicate an already attached probe merely because
another signal family consumes the observation.

Export delivery is not performed on the source supervisor's processing task.
Trace, metric, and profile families have independent bounded queues and
workers. Destination failure may reject or drop that destination's data under
the configured policy, but it cannot stall capture or another family.

## Lifecycle

1. Parse and validate all configuration before loading probes.
2. Start shared controllers and health state.
3. Register enabled static modules in documented order.
4. Start source tasks and mark each `running` when task execution begins;
   source-specific telemetry separately reports attachment coverage.
5. Process signals through processors in registration order and generators in
   registration order, preserving the bounded derived-signal budget.
6. On source exit, record `stopped` or `failed` and apply the selected policy.
7. On SIGINT or SIGTERM, stop admission, ask sources to detach, flush exporter
   queues within the configured deadline, then exit nonzero if required work
   could not be drained.

## Consequences

The unified mode is the only chart default. Focused legacy modes must not
accumulate features unavailable to unified mode. Source health and exporter
health become part of readiness; liveness remains process/deadlock health and
must not restart the pod merely because a backend is unavailable.
