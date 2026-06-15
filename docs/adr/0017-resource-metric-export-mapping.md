# ADR 0017: Resource Metric Export Mapping

Date: 2026-06-15
Status: Accepted

## Context

Phase 4 introduced an internal OTEL-compatible metric formatter. Phase 5 needs resource metrics to use the same boundary without implementing production OTLP export.

## Decision

The internal formatter maps `resource_gauge_metric` and `resource_counter_metric` envelopes to stable metric records with name, unit, kind, value, window, resource attributes, and metric attributes.

JSON stdout remains newline-delimited `SignalEnvelope` JSON. No OTLP network exporter, storage backend, UI, profiling export, capacity planning export, or cost-attribution export is added in Phase 5.

## Consequences

Resource metrics share the existing export foundation with network and DNS metrics. Future exporters can use the formatter boundary, while current Phase 5 verification stays honest about what is implemented.
