# ADR 0016: Bounded Resource Aggregation

Date: 2026-06-15
Status: Accepted

## Context

Resource signals can create high-cardinality or unbounded state if every process, mount, device, cgroup, or repeated observation becomes a new metric key.

## Decision

E-Navigator adds a statically registered `generator.resource_metrics` with configurable bounded state. It uses deterministic keys, suppresses duplicate observations, emits CPU and disk deltas from counters only after a prior sample exists, and emits gauges only when values are useful or changed.

Metric attributes are intentionally small: state, device, mountpoint, filesystem type, and existing process/container/Kubernetes context where available. The generator does not infer broad ownership or cost attribution from incomplete local files.

## Consequences

Phase 5 provides operationally useful resource metrics while avoiding unbounded in-memory aggregation and noisy duplicate output. Future cost attribution or capacity planning can build on these low-cardinality metrics instead of replacing them.
