# Standalone Agent Readiness Matrix

This matrix records the read-only reconstruction performed on 2026-07-17 at
`v0.1.1` (`39bf46ac4d0ac3be9d25b1a373d74b70bf4c8da0`). It is an implementation
backlog and proof ledger, not a capability claim.

## Verified baseline

- Repository: clean `main`, equal to `origin/main`, exact tag `v0.1.1`.
- Toolchain: Rust/Cargo 1.96.0 on `aarch64-apple-darwin`.
- Baseline gate: formatting, release-contract validation, and Helm lint
  passed. The first full `scripts/quality.sh` run was interrupted during
  Clippy after unrelated Rust compilation saturated the shared workstation;
  no E-Navigator diagnostic had been emitted.
- Homelab: k3s v1.30.4 on two `linux/amd64` nodes, kernel 6.6.68,
  containerd 1.7.20-k3s1. `homelab-02` has a control-plane `NoSchedule`
  taint. Read-only inspection used explicit `kubectl --context homelab`.
- Existing homelab install: one unrelated v0.1-era DaemonSet pod in
  `e-navigator-system` on `homelab-01`; this task must not mutate it.
- Guara requirements were inspected read-only from its current local `main`.
  That tree was 133 commits ahead of `origin/main` with one user-owned dirty
  documentation file and was not changed.

## Gap matrix

| Capability | Existing implementation | Existing proof level | Missing implementation | Missing proof | Planned commit/phase | Acceptance test |
| --- | --- | --- | --- | --- | --- | --- |
| Unified source supervisor | Default unified mode registers enabled general and CPU sources together; deployed `isolate` policy preserves healthy sources; Linux sources handle SIGTERM and bounded sink drain; one node controller feeds all filter maps and production attribution | Unit, synthetic, lifecycle, partial-failure, shared snapshot, and process-exclusion tests | source health registry | Combined live capture+profile, partial-attach, and termination proof | supervisor | All enabled real sources in one process; injected source failure leaves healthy source running under `isolate` |
| Native contracts | Schema-v1 envelope, bounded fields, confidence and warning families, golden fixtures | Unit and golden JSON | Collector lifecycle/health contract and complete naming policy | Backward fixtures for new stable families | contracts | Every stable kind round-trips; no vendor names in exported native metrics |
| Workload controller | One bounded node-pod API snapshot shared by cgroup filter publication and production attribution; pod UID, container ID/name, pod IP, namespace, node and selected-label indexes | Unit/shared snapshot tests and selected older homelab attribution/filter runs | watch/relist semantics, owner/service indexes, freshness metrics, expired-resource recovery | Churn, watch failure, restart/reschedule proof | workload-controller | Paid-tier/catalog selector stays correct through relist, deletion, IP reuse, and container restart |
| Selector language | Namespace exact/glob; label equality/inequality/existence/non-existence/set membership; bounded OR groups; process/container exclusions; explicit unknown posture and exclude-wins ordering | Unit/property-like cases including the exact Guara expression | per-family policy overrides | Live Guara paid-tier/catalog-exclusion and churn proof | selector | `proj-* AND guara.cloud/tier IN (...) AND guara.cloud/catalog-slug DOES NOT EXIST`; exclude wins |
| Native topology | Connection lifecycle, byte totals, one-sided flow summaries, dependency edges | Unit and selected live output | dual endpoint owner/service attribution, Service/NAT identity, cross-agent dedup identity and confidence | same/cross-node, NAT, IP reuse, dual observation | topology | Expected edge set matches workload oracle without double counting |
| Distributed traces | Traceparent parser, request observations/spans, OTLP trace encoding | Fixture/unit and selected protocol matching | generated nonzero IDs, parent policy, client/server trees, safe propagation, SDK duplicate detection | deterministic multi-hop and live propagation proof | tracing | exact trace tree for missing/valid/malformed context, retries, reuse, partial capture |
| Protocol and TLS | HTTP/1, h2/gRPC, PostgreSQL, MySQL, Redis, MongoDB, Kafka, NATS parsers; OpenSSL/BoringSSL and GnuTLS uprobes | Fixtures/fuzz-build and selected live protocols | server-side breadth, HTTP/2 continuation, correlation gaps, Go/rustls/Node/JVM TLS | live matrix for every claimed runtime | protocol-tls | automated request/status/secret-loss assertions per protocol/runtime |
| Profiling | perf-event sampling in unified mode, native/DWARF unwind, CPython 3.12 walk, ELF symbols, pprof, and pinned OTLP Profiles `v0.3.0`; cumulative sessions are not re-exported | Unit, selected Linux proof, and local direct Pyroscope `1.20.3` ingest/query smoke | Node/V8, JVM/JIT, multi-version CPython and representative real-runtime backend proof | Homelab queryable frames and sustained loss/coverage | profiling | Pyroscope query contains named Rust/C/C++/Go/Node/JVM/Python frames for supported versions |
| Export isolation | Independent metric/trace/profile workers with bounded queues, size/time batches, jittered retries, circuit breaking, shutdown drain, and a live feedback-safe Prometheus telemetry registry | Deterministic fake HTTP failure/overload/recovery tests, Prometheus registry integration test, and local Pyroscope smoke | compression, latency histograms, feedback-safe OTLP self-metrics | Destination failure, saturation, memory-bound and cross-family latency proof | exporters | unavailable profile endpoint does not change trace/metric latency; memory remains bounded |
| Self-observability | Source accounting logs, warnings, Prometheus signal rendering | Unit and selected logs | unified health registry and bounded metrics for controllers, queues, attachments, loss, exports, process use | alert and failure-injection proof | health | every induced blind spot changes a documented native metric/health state |
| Helm/DaemonSet | Linux DaemonSet, config, list-only pod RBAC, host mounts/capabilities, explicit resources, rolling-update bounds, 30s grace, SIGTERM handling, optional real probes, priority field and schema validation | lint/render, kubeconform, lifecycle tests, and prior unrelated homelab install | watch RBAC with controller, canary/rollback and disruption controls | server dry-run, rollout, termination, rollback | packaging | disposable DaemonSet becomes ready, survives backend outage, drains, upgrades, rolls back |
| Performance and soak | Criterion hot paths and older benchmark harness | Local microbench/selected homelab | matched no-agent/reference/E-Navigator trials and resumable soak workflow | thresholds and 24h minimum data | evidence | declared coverage/overhead thresholds pass with manifests and checksums |

## Guara contract to express natively

The shared workload policy must select namespaces matching `proj-*`, require
`guara.cloud/tier` in `starter`, `pro`, `business`, or `enterprise`, and
require `guara.cloud/catalog-slug` not to exist. Exporter and collector
processes are excluded. Profiling uses 10 Hz and needs stable service,
namespace, pod, container, node, and empty catalog identity semantics at the
consumer boundary. Topology needs low-cardinality source/destination workload
owner and namespace dimensions. Traces need W3C context on supported HTTP
paths and safe database/messaging operation attributes without raw values.

These requirements are semantic targets. E-Navigator will use its own names
and schemas; Guara will migrate its queries rather than E-Navigator emitting
collector-specific aliases.
