# ADR 0021: Trace Export Mapping

Date: 2026-06-15
Status: Accepted

## Context

Phase 4 added an internal OTEL-compatible metric formatter. Phase 6 needs a similar boundary for trace-foundation signals without claiming production OTLP trace export.

## Decision

Add an internal trace formatter in the sinks crate. It maps trace-foundation `SignalEnvelope` payloads into stable records with:

- record kind,
- trace/span IDs when observed or explicitly synthetic,
- start, end, and duration timestamps,
- resource attributes,
- trace attributes,
- correlation kind and confidence.

JSON stdout remains newline-delimited `SignalEnvelope` JSON. No production OTLP trace exporter is added in Phase 6.

## Consequences

Future OTLP trace, storage, UI, profiling correlation, dependency analysis, and critical path analysis work can use a stable formatting boundary without changing generators. Phase 6 does not claim Tempo replacement behavior.
