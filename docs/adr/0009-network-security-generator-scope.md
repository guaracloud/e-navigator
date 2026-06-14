# ADR 0009: Network Security Generator Scope

Date: 2026-06-14
Status: Accepted

## Context

Phase 3 extends runtime security beyond process execution. Network rules can become noisy quickly, so the first scope must stay narrow, deterministic, and explainable from available signals.

## Decision

The existing `generator.runtime_security` observes network connection open signals in addition to exec signals.

Phase 3 adds two network finding families:

- `network.unexpected_external_connection`: a container opens a connection to an address outside common local, private, link-local, multicast, broadcast, or unspecified ranges.
- `network.kubernetes_api_from_workload`: a non-control-plane workload connects to a configured Kubernetes API address.

Findings include rule ID, severity, matched process details, matched connection details, and available container and Kubernetes attribution.

The generator does not implement broad scan detection, port-sweep heuristics, DNS reputation, or repeated-failure rules in Phase 3. Failed-connection visibility exists at the signal layer, but no repeated-failure finding is emitted until thresholds and state semantics are proven with tighter tests.

## Consequences

The network security scope is intentionally small. It provides useful first findings while avoiding speculative detection. Future policy configuration and allowlists can refine what counts as unexpected external egress.
