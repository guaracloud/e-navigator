# ADR 0011: Network Metric Signal Model

Date: 2026-06-15
Status: Accepted

## Context

Phase 4 derives operational network metrics from Phase 3 network events. These metrics need stable versioned envelopes, low-cardinality fields, attribution, and names that can later map to OpenTelemetry without requiring a generator rewrite.

## Decision

E-Navigator represents derived network metrics as versioned signal payloads:

- `network_counter_metric` for connection, failure, traffic destination, and protocol distribution counters.
- `network_duration_metric` for histogram-compatible duration summaries.
- `network_gauge_metric` for active connection gauges when an observed open can be matched to a later close.

Metric payloads carry `metric_name`, `unit`, aggregation window bounds, protocol/address metadata, remote endpoint fields where useful, and container/Kubernetes context when available. The JSON stdout sink continues to emit newline-delimited `SignalEnvelope` values.

## Consequences

Generators can emit stable metric envelopes today, and future storage, UI, or OTLP export code can map those metric envelopes without depending on Aya source details. Phase 4 uses OTEL-aligned names and units where practical, but does not claim full OTLP export.
