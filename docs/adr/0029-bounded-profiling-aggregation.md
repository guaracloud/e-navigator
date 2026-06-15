# ADR 0029: Bounded Profiling Aggregation

## Status

Accepted.

## Context

Profiling data can become high-cardinality quickly because stacks, symbols, threads, processes, containers, and time windows can explode in combination.

## Decision

Use a statically registered `generator.profiling` module that only derives profiling session/window observations from explicit profile sample signals. It does not infer hot functions, allocation rates, lock contention, or workload bottlenecks from CPU/resource metrics.

The generator uses bounded maps for active windows, seen sample fingerprints, and warning fingerprints. Duplicate samples are suppressed. Window/profile keys are deterministic and opaque.

## Consequences

The generator provides deterministic, low-cardinality profiling foundation output. It evicts the oldest retained window when the configured window bound is reached rather than buffering unbounded data.
