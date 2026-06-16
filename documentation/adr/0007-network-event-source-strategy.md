# ADR 0007: Network Event Source Strategy

Date: 2026-06-14
Status: Accepted

## Context

Phase 3 needs early network dependency visibility for Linux and Kubernetes workloads without exposing Aya or eBPF details outside the Aya source crate. The source must keep enabled load or attach failures explicit and must avoid unbounded kernel or user memory reads.

## Decision

E-Navigator adds a statically registered `source.aya_network` source in `e-navigator-sources-ebpf-aya`.

The first implementation emits fixed-size TCP-oriented network events from syscall tracepoints:

- connect attempt/open when a connect syscall succeeds,
- connect failure when the connect syscall returns an error,
- fd-close duration for connections observed by the agent.

The eBPF side uses fixed-size event structs, bounded hash maps for pending and active connections, and a perf event array. User-space decode is isolated and unit-tested before conversion into versioned `network_connection_*` envelopes.

The source does not implement DNS packet parsing in Phase 3. It also does not claim full TCP state tracking, packet accounting, retransmits, or distributed tracing.

## Consequences

The source gives useful low-overhead dependency visibility while keeping kernel interaction conservative. It favors explicit failure and typed decode over broad parsing. Future lower-level TCP state probes or DNS visibility can be added behind the same source boundary without changing processors, generators, or sinks.
