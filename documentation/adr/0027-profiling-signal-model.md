# ADR 0027: Profiling Signal Model

## Status

Accepted.

## Context

Phase 8 added a continuous profiling foundation. Phase 9 adds an explicit privileged CPU profiling source foundation without claiming allocation profiling, lock profiling, pprof export, OTLP profile export, storage, UI, trace/profile correlation, bottleneck analysis, or profile-backend replacement behavior.

## Decision

Represent profiling data as versioned `SignalEnvelope` payloads:

- `profile_sample_observation`
- `profiling_stack_trace_observation`
- `profiling_session_observation`
- `profiling_warning_observation`

Each profiling signal carries explicit `profiling_kind`, `correlation_kind`, `confidence`, host/source context, optional process/container/Kubernetes context, and only observed thread, stack frame, symbol, module, file, and line fields.

Stack frames and attributes are bounded. Raw full stacks are not used as metric keys or low-cardinality labels.

## Consequences

Synthetic, fixture-backed, and observed CPU profile sample signals share the same versioned payloads. Non-privileged validation covers synthetic output and Aya CPU profile event decode fixtures. Live CPU profiling may only be claimed when the explicit privileged source observes samples in a real Linux environment.
