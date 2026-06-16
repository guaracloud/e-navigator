# ADR 0024: Bounded Request Correlation Strategy

## Status

Accepted.

## Context

Phase 6 trace correlation emits network-inferred service interactions and dependency paths. Phase 7 needs request spans only when a protocol observation or explicit synthetic fixture supports them.

## Decision

Add `generator.request_correlation` as a statically registered generator. It consumes protocol request observations and emits request span observations plus request correlation warnings. It does not infer HTTP methods, routes, status codes, retries, errors, trace IDs, or span IDs from raw TCP-only data.

The generator keeps bounded seen-request and warning sets, suppresses duplicates, uses deterministic fingerprints, and emits low-cardinality span names. Trace context parsed from a valid observed `traceparent` is marked `observed_trace_context`; protocol observations without usable trace context remain `protocol_observed` or `synthetic` according to their source payload and produce explicit warnings.

## Consequences

The generator prepares for future request tracing, dependency bottleneck analysis, and critical path analysis without replacing the existing Source, Processor, Generator, and Sink architecture. Bounded state can evict old fingerprints, so duplicate suppression is best-effort within configured limits.
