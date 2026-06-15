# ADR 0020: Trace Attribution Behavior

Date: 2026-06-15
Status: Accepted

## Context

Trace-derived signals must preserve workload context from existing container and Kubernetes attribution, but attribution may be incomplete on a host or in a restricted environment.

## Decision

Trace correlation consumes the already-processed `SignalEnvelope` stream. It preserves process, container, Kubernetes, host, peer, and dependency context from the source signal.

Missing attribution is non-fatal. When a trace-derived network signal lacks both container and Kubernetes context, the generator emits a structured `trace_correlation_warning` instead of failing the pipeline.

No new Kubernetes permissions are required for Phase 6. Existing pod metadata listing remains the attribution boundary.

## Consequences

Trace-derived output is useful when attribution succeeds and explicit when it does not. Operators can distinguish missing context from application behavior without granting broader cluster permissions.
