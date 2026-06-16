# ADR 0013: OTEL-Compatible Export Foundation

Date: 2026-06-15
Status: Accepted

## Context

The project vision calls for OpenTelemetry-compatible metrics and signals where practical. Phase 4 should establish a clean export boundary without prematurely implementing and claiming production OTLP export.

## Decision

E-Navigator adds an internal OTEL-compatible metric formatter in the sinks crate. The formatter maps metric `SignalEnvelope` payloads into stable records with:

- metric name,
- unit,
- metric kind,
- value or histogram-compatible summary,
- aggregation window,
- resource attributes,
- metric attributes.

The existing `sink.json_stdout` behavior remains unchanged and continues to emit newline-delimited JSON envelopes. No production OTLP network exporter is added in Phase 4.

## Consequences

Future OTLP, storage, or UI sinks can consume a metric formatting boundary without changing generators. Phase 4 can test naming and attribute stability while avoiding a false claim of full OTLP compatibility.
