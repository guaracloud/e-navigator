# Boundaries

This document is the public source of truth for what E-Navigator does not claim.
It should be read before deploying the project or citing its benchmark/proof
results.

E-Navigator is a pre-release runtime signal plane. It is designed to collect,
attribute, derive, and export bounded runtime signals. It is not yet a complete
observability product.

## In Scope

E-Navigator is designed to provide:

- node-local Linux and Kubernetes runtime observations;
- versioned signal envelopes;
- bounded attribution to host, process, container, and Kubernetes context;
- low-cardinality metrics, dependency edges, request spans, profiling windows,
  and runtime security findings;
- JSON stdout by default;
- opt-in Prometheus HTTP and OTLP HTTP export surfaces;
- explicit evidence boundaries for synthetic, local, Docker, render, and
  privileged runtime proof.

## Explicit Non-Claims

E-Navigator does not currently claim:

- production observability backend behavior;
- trace storage, profile storage, flamegraph UI, dashboards, or query UI;
- pprof export;
- complete live HTTP/gRPC protocol parsing;
- live Kafka protocol capture or request/response matching;
- live NATS protocol capture or request/response matching;
- live MongoDB protocol capture or request/response matching;
- live MySQL protocol capture or request/response matching;
- live PostgreSQL protocol capture or request/response matching;
- live Redis protocol capture or request/response matching;
- TLS payload inspection;
- full TCP state tracking, packet accounting, retransmits, or resets;
- lossless DNS or HTTP capture across every node and workload shape;
- live native `network.flow.bytes` export from traffic after the native metric
  migration;
- production collector/backend compatibility beyond recorded local or
  namespace-local Collector proof;
- reduced overhead versus another observability stack;
- reduced-privilege or non-root eBPF operation;
- complete attribution for every host process, packet, profile sample, or
  runtime security finding.

## Evidence Rules

Do not treat these as interchangeable:

- synthetic CLI output;
- Cargo/unit/golden tests;
- Docker smoke tests;
- Helm rendering or Kubernetes schema checks;
- guarded Linux/Kubernetes runtime proof.

A claim is runtime proven only when a capable Linux host or Kubernetes cluster
recorded the relevant E-Navigator output, pod state, workload output, and
cleanup/restore evidence.

## Security And Data Handling Boundaries

E-Navigator favors bounded data structures and explicit attribution warnings.
Sensitive values must not be added as high-cardinality labels or exported as
raw secrets. Signal schemas and exporters must keep secret-like label filtering
and bounded cardinality intact.

## Operational Boundaries

The current Kubernetes posture still depends on privileged eBPF capabilities for
the live Aya sources. Do not present the chart as reduced-privilege or non-root
until that exact configuration has been implemented and proven on a capable
cluster.

## Benchmark Boundaries

Local Criterion benchmarks are hot-path hygiene and regression tools. They are
not live overhead proof. Runtime overhead claims require a controlled baseline,
resource samples, comparable workload shape, and recorded runtime evidence.
