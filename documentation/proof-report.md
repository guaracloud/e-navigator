# Proof Report

This report is the curated public evidence summary for E-Navigator. It replaces
the previous chronological sample ledger with a capability-oriented view.

Status vocabulary:

- **Proven:** the stated behavior has direct recorded evidence.
- **Partial:** a useful slice is proven, but nearby production behavior remains
  outside the claim.
- **Not proven:** implementation may exist, but required evidence is missing.
- **Blocked:** the run identified an environmental or version boundary that
  prevents the proof from being completed as attempted.

## Proven Locally

These areas are proven by local tests, fixtures, synthetic runs, Docker smoke,
or chart rendering:

- static module registration and runner fan-out;
- versioned JSON signal envelopes;
- synthetic source pipeline, including sanitized HTTP, Kafka, MongoDB, MySQL,
  NATS, PostgreSQL, and Redis protocol request/span fixtures;
- config validation and packaged config guards;
- procfs, sysfs, cgroup, loadavg, meminfo, diskstats, and process-stat parsing;
- raw userspace decode paths for selected Aya exec/network/profile events;
- bounded DNS/HTTP fixture parsing, Kafka request-header parsing, MongoDB
  wire-message parsing, MySQL command packet parsing, NATS text command
  parsing, PostgreSQL wire-message parsing, and Redis RESP command parsing;
- network, DNS, resource, dependency, request, trace, profiling, and runtime
  security generator behavior, including synthetic protocol request/span flow;
- Prometheus HTTP formatting, health/readiness endpoints, and secret-like label
  filtering;
- OTLP protobuf request encoding plus per-family endpoint routing for metrics,
  traces, and development-status profiles in fake-collector tests;
- Helm rendering, schema checks, and release verification workflow structure.

## Runtime-Proven Slices

Guarded Linux/Kubernetes runs have recorded these slices:

- E-Navigator DaemonSet readiness on the homelab benchmark namespace for
  selected images and configurations.
- Live `source.aya_exec` and `source.aya_network` records from Kubernetes nodes.
- Kubernetes/container attribution on selected exec, network, metric,
  dependency, trace-derived, DNS, HTTP, and profile records.
- Host resource source and resource metric output under selected seccomp
  settings.
- Runtime security findings from observed process and network activity.
- DNS source/generator output for selected UDP DNS paths, including a proven
  `homelab-02` connected-UDP Python client path under RuntimeDefault seccomp.
- Cleartext HTTP request/span capture for selected `homelab-02` client paths
  using bounded `writev`/iovec shapes, including one RuntimeDefault seccomp run.
- CPU profile source/generator output and selected controlled workload
  attribution, including live profile records exported through OTLP profile
  protobuf to a namespace-local OpenTelemetry Collector.
- Prometheus HTTP endpoint reachability and selected live scrape/query evidence
  for E-Navigator metric series.
- Namespace-local OpenTelemetry Collector acceptance for OTLP metric, trace, and
  development-status profile protobuf slices.
- Workload scheduling, workload cleanup, and collector wait behavior for the
  guarded homelab harness.

## Partial Or Not Yet Proven

These areas remain explicitly partial:

- **Native flow byte metric export:** code emits native `network.flow.bytes` and
  Prometheus renders it as `network_flow_bytes`, but positive live native export
  must be rerun after the native metric migration.
- **HTTP capture:** selected `homelab-02` outbound cleartext paths work, but
  symmetric node coverage, inbound parsing, TLS, gRPC, status-code extraction,
  route templates, retries, app errors, and broader iovec shapes are not proven.
- **Kafka protocol observability:** bounded request-header parsing for common
  API keys is locally tested without exporting client IDs, topics, or record
  payloads, but runtime capture, request/response matching, status/error
  extraction, flexible-version body semantics, and live Kafka proof are not
  implemented or proven.
- **MongoDB protocol observability:** bounded `OP_MSG` and command `OP_QUERY`
  parsing is locally tested without exporting raw BSON values or namespaces, but
  runtime capture, request/response matching, status/error extraction, and live
  MongoDB proof are not implemented or proven.
- **NATS protocol observability:** bounded text command parsing for common
  publish, subscribe, message, and control lines is locally tested without
  exporting raw subjects or payloads, but runtime capture, request/response
  matching, status/error extraction, and live NATS proof are not implemented or
  proven.
- **MySQL protocol observability:** bounded `COM_QUERY` and
  `COM_STMT_PREPARE` command parsing is locally tested without exporting raw SQL
  text, but runtime capture, request/response matching, status/error
  extraction, and live MySQL proof are not implemented or proven.
- **PostgreSQL protocol observability:** bounded simple Query and Parse message
  parsing is locally tested without exporting raw SQL text, but runtime capture,
  request/response matching, status/error extraction, and live PostgreSQL proof
  are not implemented or proven.
- **Redis protocol observability:** bounded RESP command parsing is locally
  tested without exporting raw key/value payloads, but runtime capture,
  request/response matching, status/error extraction, and live Redis proof are
  not implemented or proven.
- **DNS capture:** selected UDP paths work, but symmetric all-node capture and
  lossless DNS coverage are not proven.
- **CPU profiling:** selected samples and sessions are proven, but deterministic
  capture for every workload shape, symbolization, pprof, storage, and
  flamegraph rendering are not proven.
- **Exporter infrastructure:** local and namespace-local proof exists, but broad
  production backend/collector compatibility and longer live soaks are not
  proven.
- **Resource and privilege posture:** selected resource samples and seccomp
  slices are proven, but reduced overhead, reduced capabilities, and non-root
  eBPF operation are not proven.

## Blocked Or Version-Boundary Findings

Some proof attempts established useful boundaries rather than positive claims:

- Older benchmark images rejected newer modules such as `source.aya_dns`,
  `sink.prometheus_http`, and `sink.otlp_http`; those are image-vintage
  boundaries, not current-head feature failures.
- The 20260624 OTLP per-family endpoint homelab proof was blocked because the
  checked DaemonSet image was not proven to include the local change and the
  local Docker daemon did not respond for building a current image; local
  fake-collector routing tests remain the evidence for that change.
- Some BPF diagnostic experiments were verifier-hostile on the tested homelab
  kernel and were reverted.
- Some controlled workloads completed successfully but produced no matching
  protocol/profile/DNS records; those remain negative runtime evidence, not
  product claims.

## Publication Rule

Future proof updates should edit this report only after the raw run records
enough evidence to support the exact statement. Nearby capabilities must remain
listed as partial, not proven, or blocked unless they were directly observed.
