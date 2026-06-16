# ADR 0018: Trace Signal Model

Date: 2026-06-15
Status: Accepted

## Context

Phase 6 needs trace-shaped signals without pretending E-Navigator can already parse HTTP, gRPC, request IDs, routes, retries, or full distributed trace context from eBPF observations.

## Decision

Add versioned `SignalEnvelope` payloads for:

- `trace_span_observation`,
- `service_interaction_span_observation`,
- `trace_service_path_observation`,
- `trace_correlation_warning`.

Trace IDs, span IDs, and parent span IDs are optional. Synthetic fixtures may include explicit IDs. Network- and dependency-inferred observations must leave those fields empty unless a future source actually observes trace context.

Trace payloads carry the applicable subset of host, process, container, Kubernetes, source/destination, peer, timestamp, duration, correlation kind, confidence, and bounded attributes for each payload kind. Correlation warnings carry warning metadata and correlation kind, but do not pretend to be spans.

## Consequences

Phase 6 establishes a stable trace foundation while remaining honest about observability. Future protocol parsers can fill trace context fields without replacing the Source, Processor, Generator, and Sink architecture.
