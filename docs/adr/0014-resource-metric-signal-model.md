# ADR 0014: Resource Metric Signal Model

Date: 2026-06-15
Status: Accepted

## Context

Phase 5 needs node, process, and container resource observability without forcing future storage, UI, cost attribution, profiling, or OTLP exporters to parse ad hoc payloads.

## Decision

E-Navigator adds versioned `SignalEnvelope` payloads for node CPU/load/memory/filesystem/disk observations, process resource observations, cgroup CPU/memory/pids/fd observations, and derived resource gauge/counter metrics.

The model carries host, timestamp, aggregation window, metric name, unit, process context, cgroup context, container context, and Kubernetes context when available. Metric names and units stay close to OpenTelemetry conventions where practical, but Phase 5 does not claim full OTLP export.

## Consequences

Resource signals are additive and preserve compatibility with existing exec, process exit, lifecycle, network, DNS, dependency, metric, and security finding signals. Future sinks and storage layers can consume resource metrics without rewriting the source and generator contracts.
