# Guara Compatibility Contract

This document defines the compatibility projection required for E-Navigator to
eventually replace Guara Cloud's Beyla DaemonSet and alloy-profiles DaemonSet
with one E-Navigator pod per node. It is a compatibility/export contract, not a
separate runtime architecture.

## Pipeline Boundary

Guara compatibility must stay inside the existing static pipeline:

```text
source.aya_network / source.aya_cpu_profile / request sources
  -> processor.container_attribution
  -> existing generators plus generator.guara_compat
  -> sink-layer exporters
```

Runtime plugin loading, sidecars, a second agent, or a parallel collector are
out of scope.

## L4 Flow Metric

The Beyla-compatible topology metric is:

```text
beyla_network_flow_bytes_total
```

E-Navigator represents byte-accurate L4 observations internally as
`network_flow_summary` signals. `generator.guara_compat` projects those signals
to `compatibility_counter_metric` records named
`beyla_network_flow_bytes_total`.

The exported label set is intentionally limited to the Guara topology contract:

- `k8s_src_namespace`
- `k8s_src_owner_name`
- `k8s_src_owner_type`
- `k8s_dst_namespace`
- `k8s_dst_owner_name`
- `k8s_dst_owner_type`

Raw addresses, ports, packet payloads, request bodies, SQL text, and process
arguments are not part of this compatibility metric. This mirrors Guara's
cardinality firewall for Beyla's `beyla_network_flow_bytes` attributes.

Current implementation status:

- Signal schema and golden coverage exist for `network_flow_summary`.
- Guara projection and Prometheus text formatting exist for
  `beyla_network_flow_bytes_total`.
- Bounded flow-series cardinality and dropped-series accounting exist in the
  projection generator.
- Live Aya byte accounting, active-flow timeout flushing, and cross-node runtime
  dedupe still require privileged Linux or Kubernetes proof.

## Guara Scoping

Compatibility scoping follows Guara's current production collector contract:

- Paid tenant namespaces start with `proj-`.
- Paid tiers are `pro`, `business`, and `enterprise`.
- Catalog-managed sources carrying `guara.cloud/catalog-slug` are excluded from
  source-side collection.
- Build nodes carrying `guara.cloud/role=build` are excluded by packaging.
- Platform-only flows are dropped before compatibility export.

Tenant-to-catalog traffic is preserved for topology when the source is a paid
custom tenant workload and the destination is a catalog workload in the same
project namespace.

## Tempo Service Graph

Tempo-compatible spans must provide resource attributes used by Guara's
service-graph queries:

- `service.name`
- `k8s.namespace.name`
- `k8s.pod.name`
- `k8s.deployment.name` when derivable from stable workload labels

Current implementation status:

- Existing trace/request formatter boundaries preserve `service.name`,
  namespace, pod, and container attributes.
- `k8s.deployment.name` is derived from `app.kubernetes.io/name` or `app` when
  present.
- Full OTLP trace transport, Tempo ingestion proof, live HTTP parsing, gRPC,
  database spans, and W3C propagation are not yet production-proven.

## Pyroscope Profile Identity

Guara's profile API queries CPU profiles by:

```text
process_cpu:cpu:nanoseconds:cpu:nanoseconds
```

Profile records expose that metric identity for CPU profiles and add
Pyroscope-compatible labels:

- `namespace`
- `service_name`
- `catalog_slug`
- `pod`
- `container`
- `node`
- `source=e-navigator`

Current implementation status:

- CPU profile source foundations, profile normalization, profile windows, and
  formatted profile records exist.
- Pyroscope-compatible label formatting and sensitive-attribute filtering exist.
- Symbolization, demangling, Pyroscope write transport, OTLP profile transport,
  and real perf-event parity are not yet proven in this compatibility pass.

## Exporter Boundary

The sink crate now contains reusable HTTP exporter foundations with:

- batching
- timeout
- retry
- bounded queue
- backpressure by dropping newest items when the queue is full
- dropped item counters
- auth/header support
- Rustls HTTP client construction
- local fake-collector tests

This is not yet a full OTLP protobuf implementation. The current Rust ecosystem
and repository dependencies are treated as an internal export boundary until
metrics, traces, and profiles are serialized to the exact upstream OTLP protocol
and verified against a collector.

## Kubernetes Packaging

The Helm chart and static manifests model one E-Navigator DaemonSet pod per
node with:

- explicit Linux capabilities instead of `privileged: true`
- `hostPID: false` by default; profiling can opt in when required and proven
- tracefs, debugfs, procfs, and cgroup host mounts
- build-node exclusion through node affinity
- broad tolerations matching observability DaemonSet scheduling
- feature flags for metrics, traces, profiles, Guara compatibility, and protocol
  probes
- a metrics Service plus optional ServiceMonitor

Reduced-privilege eBPF operation is not privileged-runtime proven until tested
on a capable Linux host or Kubernetes node.
