# ADR 0026: Request Trace Export Mapping

## Status

Accepted.

## Context

Phase 7 extends the internal OTEL-compatible trace formatter. The project still does not implement production OTLP trace transport or storage.

## Decision

Map request span observations and request correlation warnings to the internal OTEL-compatible trace record boundary. Canonical fields such as `trace.correlation.kind`, `trace.correlation.confidence`, `network.protocol.name`, `http.request.method`, and `http.response.status_code` are formatter-owned and cannot be overwritten by custom attributes.

Custom attributes are bounded by count, key bytes, and value bytes. Sensitive keys containing token, authorization, cookie, password, or secret are filtered.

## Consequences

JSON stdout remains newline-delimited SignalEnvelope JSON. The formatter provides a stable future mapping point for OTLP trace export, but Phase 7 does not claim production OTLP export, trace-backend replacement behavior, UI, storage, or critical path analysis.
