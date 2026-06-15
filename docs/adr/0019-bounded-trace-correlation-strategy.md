# ADR 0019: Bounded Trace Correlation Strategy

Date: 2026-06-15
Status: Accepted

## Context

Trace-like correlation can become noisy and high-cardinality if raw network, DNS, and dependency signals are promoted without limits.

## Decision

Add a statically registered `generator.trace_correlation` module. It derives trace-foundation signals from network close/failure events, dependency edges that reach the generator, and successful DNS responses.

The generator:

- emits service interaction spans only when there is observed network close or failure data,
- does not infer request IDs, routes, HTTP methods, status codes, retries, or application errors from TCP alone,
- derives service path observations from direct/upstream dependency-edge data or DNS data,
- keeps service path state, seen interaction fingerprints, and warning fingerprints bounded,
- uses deterministic keys,
- suppresses duplicate observations.

Runtime bounds are configured through `[trace_correlation]`.

## Consequences

Phase 6 produces useful trace-shaped NDJSON in synthetic and non-privileged tests while avoiding unbounded aggregation and broad inference. Full request-level distributed tracing remains future work.
