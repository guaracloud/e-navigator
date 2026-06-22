# Guara Compatibility Contract

This document defines the compatibility projection required for E-Navigator to
eventually replace Guara Cloud's Beyla DaemonSet and alloy-profiles DaemonSet
with one E-Navigator pod per node. It is a compatibility/export contract, not a
separate runtime architecture.

## Pipeline Boundary

Guara compatibility must stay inside the existing static pipeline:

```text
source.aya_network / source.aya_dns / source.aya_cpu_profile / request sources
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
- Homelab run `20260621-220029-guara-compat-live` enabled
  `generator.guara_compat` on `sha-5c417c0` in `staging/e-navigator-bench` and
  proved the current live boundary: the E-Navigator `/metrics` endpoint and
  Prometheus scrape path were healthy and reported other network metrics, but
  `beyla_network_flow_bytes_total` had 0 direct endpoint lines and 0 Prometheus
  query results because no live `network_flow_summary` records were observed.
- Homelab run `20260622-111022-guara-flow-live` deployed pushed image
  `sha-762561f` digest
  `sha256:d520fd8b7bd0a4042c31513034d43f716b75407a888b47468f19ca3504629a5a`
  as Helm revision 41 and proved live close-event byte counters plus ambient
  close-derived `network_flow_summary` output: 234 byte-bearing
  `network_connection_close` records and 53 `network_flow_summary` records were
  captured. The same run did not prove controlled workload flow summaries:
  BusyBox clients on both nodes completed 360 HTTP requests, but their
  byte-bearing close records lacked Kubernetes attribution.
- Homelab run `20260622-111448-guara-flow-python-client-live` kept Python
  client pods alive after 160 controlled socket reads to test attribution timing.
  The server-IP records were captured as `EINPROGRESS` connection failures, not
  byte-bearing closes, and produced 0 controlled `network_flow_summary` rows and
  0 `beyla_network_flow_bytes_total` signals.
- Homelab run `20260622-122803-guara-einprogress-live` deployed pushed image
  `sha-622e1aa` digest
  `sha256:90b571bf89ac36c1432a503ad9b9add7abd7604579533c1912201568db1d5bfc`
  as Helm revision 42 after adding the Linux `-EINPROGRESS` source-path fix.
  The Python clients completed 240 controlled nonblocking socket requests with
  no application failures. Captured stdout proved the observed homelab-02 target
  `10.42.134.6:8080` emitted 120 `network_connection_open` records and 120
  `network_connection_close` records with 0 `network_connection_failure` and 0
  errno 115 failures. Direct `/metrics` also exposed homelab-02 aggregate
  controlled-client counters at 120. The same run did not prove byte-bearing
  controlled closes, controlled `network_flow_summary`,
  `beyla_network_flow_bytes_total`, Kubernetes attribution on the Python client
  records, or stdout capture for the successful homelab-01 target
  `10.42.248.200:8080`.
- Positive `beyla_network_flow_bytes_total` proof still requires a controlled
  byte-bearing flow with Kubernetes attribution and an in-scope Guara
  `proj-*` paid tenant endpoint. The current homelab namespace boundary
  restricts temporary workloads to `e-navigator-bench`, so it cannot by itself
  satisfy the Guara `proj-*` scope rule.

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

The sink crate now contains registered Prometheus HTTP and OTLP HTTP sink
boundaries plus reusable HTTP exporter foundations with:

- batching
- timeout
- retry
- bounded queue
- backpressure by dropping newest items when the queue is full
- dropped item counters
- auth/header support
- Rustls HTTP client construction
- local fake-collector tests

`sink.prometheus_http` serves local `/metrics`, `/healthz`, and `/readyz` tests.
`sink.otlp_http` now sends metric records as OTLP protobuf
`ExportMetricsServiceRequest` payloads and trace records with valid trace/span
IDs as OTLP protobuf `ExportTraceServiceRequest` payloads with
`application/x-protobuf`. Profiles still use the repository's internal JSON
record boundary. Homelab run `20260622-135450-otlp-metric-protobuf-live`
proved pushed image `sha-e7016b5` can deliver synthetic network, DNS, system,
process, and container metrics to a namespace-local OpenTelemetry Collector as
accepted OTLP protobuf. Homelab run
`20260622-160350-otlp-trace-protobuf-live` proved pushed image `sha-c00a7d5`
can deliver synthetic trace/request spans to a namespace-local OpenTelemetry
Collector as accepted OTLP protobuf. Homelab run `20260621-205344-otlp-live`
proved live delivery of the older internal JSON records to a namespace-local
fake collector, including metric, trace, and profile signal families. This is
not yet Tempo, Alloy, Pyroscope, or broad production collector compatibility
proof. Profiles still need upstream OTLP serialization.

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
- an opt-in metrics Service plus optional ServiceMonitor, rendered only when a
  real Prometheus HTTP surface is enabled

Reduced-privilege eBPF operation is not privileged-runtime proven until tested
on a capable Linux host or Kubernetes node.
