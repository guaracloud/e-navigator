# ADR 0012: Bounded Network Aggregation

Date: 2026-06-15
Status: Accepted

## Context

Network observability can create high-cardinality state if every connection, address, port, process, and DNS name is retained indefinitely. Phase 4 needs useful counters, durations, gauges, and DNS metrics without unbounded memory growth.

## Decision

E-Navigator adds statically registered `generator.network_metrics` and `generator.dns_metrics` modules.

The network metrics generator uses configured limits for metric keys and active connection tracking. It keeps deterministic keys, bounded maps, and duplicate event fingerprints. It emits updated metric signals only when a new observation changes a counter, duration summary, or active connection gauge.

The DNS metrics generator uses a configured domain limit. Domains are normalized conservatively by trimming one trailing dot and lowercasing ASCII names; invalid or over-limit names fall back to aggregate metrics without the domain label. Successful DNS responses can create domain dependency edges, and identical response observations do not repeatedly emit the same edge.

## Consequences

Phase 4 metrics remain operationally useful without unbounded in-memory aggregation. Operators can tune limits in local and Kubernetes config. If a limit is reached, the agent drops or aggregates new high-cardinality labels instead of growing memory without bound.
