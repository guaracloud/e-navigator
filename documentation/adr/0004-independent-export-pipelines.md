# ADR 0004: Independent Export Pipelines and Native Telemetry

Status: accepted

Date: 2026-07-17

## Context

Trace, metric, and profile destinations have independent latency and failure
modes. Performing destination I/O from the shared signal path couples those
modes: an unavailable profile backend can otherwise delay trace delivery and
eventually capture itself. Export health that is reported only through the
same failing exporter also creates a diagnostic feedback loop.

## Decision

Each enabled OTLP family owns one bounded channel and worker. Workers batch by
size or time, apply a bounded retry schedule with jitter, open a circuit after
the configured consecutive-failure threshold, shed new work without blocking,
and drain within a bounded shutdown deadline. No destination request runs on
the shared signal path.

OTLP protobuf bodies may be gzip-compressed on Tokio's blocking pool before
network I/O. Every request attempt, including failures and timeouts, updates a
fixed-bucket native Prometheus latency histogram per signal family.

The workers register their existing atomic counters in a process-local native
telemetry registry. The Prometheus endpoint samples the registry at scrape
time and exposes fixed `e_navigator_export_*` metric names with one bounded
`signal_family` label. Self-observability does not re-enter the signal queue or
OTLP path, so a destination failure cannot suppress its own loss counters.

## Consequences

- A slow or failed family cannot block capture or another exporter family.
- Queue memory is bounded by the per-family configured capacity.
- Accepted data can still be lost after bounded retries; every loss mode has a
  dedicated counter.
- The live native exporter telemetry surface is currently Prometheus. Native
  OTLP self-metric export remains future work because it needs a separate
  feedback-safe path.
- Compression consumes bounded blocking-pool CPU and can increase latency for
  very small batches; operators can select `none` when that tradeoff is not
  beneficial.
