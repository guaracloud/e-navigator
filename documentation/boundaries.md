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
- profile upload sink to an external profiling backend (a local
  `/debug/pprof/profile` serving endpoint is implemented);
- complete production HTTP/gRPC protocol coverage (bounded HTTP/1 and
  HTTP/2/HPACK request capture with request/response matching is implemented
  and locally proven for Redis and HTTP/2; TLS and CONTINUATION reassembly
  are not covered);
- live Kafka protocol capture proof (capture, reassembly, and request/response
  matching are implemented and unit-tested; only Redis and HTTP/2 are live
  proven);
- live NATS, MongoDB, MySQL, or PostgreSQL protocol capture proof (implemented
  and unit-tested, not yet runtime-proven);
- TLS payload inspection;
- full per-connection TCP state-machine tracking or packet accounting (TCP
  retransmit, reset, and state-transition observation and counting are
  implemented, with resets and state transitions locally proven);
- lossless DNS or HTTP capture across every node and workload shape;
- live native `network.flow.bytes` export from traffic after the native metric
  migration, including flow-attribution warning proof;
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
