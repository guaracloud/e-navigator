# Operations

This guide covers the runtime surfaces needed to operate E-Navigator after a
validated, digest-pinned install. Use the [golden path](golden-path.md) for the
initial production rollout and [Helm install](helm.md) for every setting.

## Health Model

When `sink.prometheus_http`, `[prometheus_http]`, and the matching chart options
are enabled, the HTTP surface exposes:

- `/healthz`, process liveness;
- `/readyz`, readiness of configured runtime surfaces;
- `/metrics`, signal output and native operational telemetry;
- `/debug/pprof/profile`, local pprof profile output when profile rendering is
  enabled.

The chart does not create a separate health server. Do not enable health probes
unless the Prometheus HTTP sink is configured and port `9090` is exposed.

## First Ten Minutes

1. Confirm every desired DaemonSet Pod uses the verified image digest.
2. Confirm `/healthz` and `/readyz` succeed.
3. Confirm source-running state for every enabled source.
4. Confirm the Kubernetes controller is ready and its Pod watch is fresh.
5. Produce one expected event for each enabled capture family.
6. Confirm the intended sink receives it.
7. Confirm source loss, queue drops, invalid records, and backend rejection
   counters remain at zero.
8. Record CPU, resident memory, and application latency against the matched
   no-agent baseline.

## Operational Signals

The native Prometheus registry uses fixed `e_navigator_*` names and bounded
labels. Monitor these categories:

- source running, start, exit, and failure state;
- Aya base initialization and optional attachment readiness;
- decoded, invalid, sent, send-failure, and perf-loss totals;
- Kubernetes controller readiness, watch freshness, relists, failures, and
  unresolved cgroups;
- cgroup discovery mode, inotify failures or overflows, residual bootstrap
  window, and map-application failures;
- OTLP queue depth, drops, retries, response classification, circuit state,
  sent records, and request latency;
- profile dropped samples and profiling warning counts.
- when event-driven profiling is enabled, profile input, output, map/stack
  capture failure, replacement, below-minimum, rate-limited, and transport-loss
  totals.

Use the exact metric names rendered by the current version rather than copying
names from an older dashboard. Version dashboards and alert rules with the
release that introduced or changed them.

## Alerting Priorities

Page or stop a rollout when:

- readiness remains false past the documented startup window;
- a required source exits or its optional target attachments fall below the
  expected coverage;
- source perf loss or send failures increase continuously;
- export queue drops, invalid records, or receiver rejections increase;
- a circuit remains open after the backend recovers;
- Kubernetes workload data becomes stale beyond the controller's bounded
  relist interval;
- node or application overhead crosses the rollout threshold.

Warn, investigate, and capacity-plan when queues stay elevated without loss,
retry rates spike briefly, symbolization coverage declines, or attribution
warnings increase.

## Failure Isolation

The chart selects `source_supervisor.failure_policy = "isolate"`. A failed
source is reported while healthy sources remain active. This prevents one
optional family from removing all coverage, but it also means the process may
stay live with partial visibility. Source-specific alerts are therefore as
important as process health.

Metrics, traces, and profiles use independent OTLP workers. A destination
failure does not block the shared signal path or another family. Accepted data
can still be dropped after bounded retries, and the native counters expose that
loss.

## Backpressure And Capacity

Work from the destination toward the source:

1. Confirm the backend is healthy and accepts the emitted schema.
2. Measure request latency and batch acceptance.
3. Confirm exporter workers have steady-state throughput above production
   input.
4. Size bounded queues for measured bursts and shutdown drain.
5. Narrow capture or reduce sampling when source pressure remains.

Do not treat a larger queue as a throughput fix. It increases memory and time
to loss when the downstream rate is permanently lower.

## Common Diagnostics

| Symptom | Checks |
| --- | --- |
| Pod is live but expected data is missing | Source running state, attachment counts, capture filter decision, node name, cgroup resolution, kernel support |
| Readiness fails immediately | Prometheus sink and chart health options agree, port is bound, required sources initialized |
| One OTLP family is missing | Family toggle, family endpoint, queue drops, circuit state, receiver response |
| CPU rises after enabling protocols | Capture selector scope, explicit port lists, traffic rate, parser limits, reassembly bounds |
| Profiles have unresolved frames | target permissions, supported runtime, ELF symbols, unwind coverage, JIT map availability |
| Off-CPU or lock profiles are sparse | capture-filter scope, minimum duration, per-CPU rate limiting, pending-map/stack failures, supported scheduler layout and futex path |
| Workload identity is stale | Pod watch freshness, full-resource relist freshness, RBAC, API response bounds |
| Shutdown loses accepted data | termination grace, sink shutdown timeout, destination latency, pending queue size |

## Safe Shutdown

The Linux sources handle SIGINT and SIGTERM, stop perf readers, close the
source side, and allow bounded sink drain. Keep the Kubernetes termination
grace period longer than the configured source and sink shutdown timeouts.
Observe pending queue depth and drop counters during rollout before shortening
the grace period.

## Evidence Discipline

A healthy process proves that configured userspace surfaces started. It does
not prove that a privileged probe attached to the intended kernel target or
that a backend retained and queried the data. Record the expected source
signal, sink acceptance, and backend query for every production capability
claim. See [proof report](proof-report.md) and [boundaries](boundaries.md).
