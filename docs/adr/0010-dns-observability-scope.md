# ADR 0010: DNS Observability Scope

Date: 2026-06-15
Status: Accepted

## Context

Phase 4 needs DNS intelligence for metrics and dependency enrichment, but DNS packet parsing in eBPF would add a broader parser surface than the current TCP-oriented Aya source. DNS visibility must not introduce unbounded packet reads, verifier-risky stack usage, or broad inference outside available signals.

## Decision

E-Navigator adds versioned DNS query and response signal schemas plus synthetic DNS fixtures in Phase 4.

Runtime Aya DNS packet capture is deferred. The existing `source.aya_network` source remains TCP-oriented and does not inspect DNS payloads. Future DNS capture must stay isolated in the Aya source crate, use fixed-size event structs and bounded buffers, include raw decode tests, and only emit query or response fields that were actually observed.

## Consequences

Generators, sinks, smoke tests, and future export boundaries can be developed against stable DNS envelopes without overclaiming real DNS runtime visibility. Phase 4 can derive DNS metrics from synthetic or future source signals, but production DNS observability is not claimed until a privileged Linux or Kubernetes smoke test exercises the DNS source successfully.
