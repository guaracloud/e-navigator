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
| Unified source supervisor | Static runner can start multiple registered sources; capture-filter computation is shared | Unit, synthetic, selected live sources | General and CPU modes are exclusive; source errors are globally fail-fast; SIGTERM/drain state is incomplete | Combined live capture+profile and partial-failure proof | supervisor | All enabled real sources in one process; injected source failure leaves healthy source running under `isolate` |
| Native contracts | Schema-v1 envelope, bounded fields, confidence and warning families, golden fixtures | Unit and golden JSON | Collector lifecycle/health contract and complete naming policy | Backward fixtures for new stable families | contracts | Every stable kind round-trips; no vendor names in exported native metrics |
| Workload controller | Two bounded node-pod list caches; cgroup diff publication; pod-IP/container indexes | Unit and selected homelab attribution/filter runs | Shared watch/relist controller, owner/service indexes, freshness metrics, expired-resource recovery | Churn, watch failure, restart/reschedule proof | workload-controller | Paid-tier/catalog selector stays correct through relist, deletion, IP reuse, and container restart |
| Selector language | Namespace exact/glob and exact label include/exclude; explicit unknown posture | Unit/property-like cases | inequality, existence, non-existence, set membership, OR groups, process/container exclusions, per-family policies | Guara paid-tier policy proof | selector | `proj-* AND tier IN (...) AND catalog-slug DOES NOT EXIST`; exclude wins |
| Native topology | Connection lifecycle, byte totals, one-sided flow summaries, dependency edges | Unit and selected live output | dual endpoint owner/service attribution, Service/NAT identity, cross-agent dedup identity and confidence | same/cross-node, NAT, IP reuse, dual observation | topology | Expected edge set matches workload oracle without double counting |
| Distributed traces | Traceparent parser, request observations/spans, OTLP trace encoding | Fixture/unit and selected protocol matching | generated nonzero IDs, parent policy, client/server trees, safe propagation, SDK duplicate detection | deterministic multi-hop and live propagation proof | tracing | exact trace tree for missing/valid/malformed context, retries, reuse, partial capture |
| Protocol and TLS | HTTP/1, h2/gRPC, PostgreSQL, MySQL, Redis, MongoDB, Kafka, NATS parsers; OpenSSL/BoringSSL and GnuTLS uprobes | Fixtures/fuzz-build and selected live protocols | server-side breadth, HTTP/2 continuation, correlation gaps, Go/rustls/Node/JVM TLS | live matrix for every claimed runtime | protocol-tls | automated request/status/secret-loss assertions per protocol/runtime |
| Profiling | perf-event sampling, native/DWARF unwind, CPython 3.12 walk, ELF symbols, pprof and OTLP Profiles | Unit and selected Linux proof | Node/V8, JVM/JIT, multi-version CPython, stable window delta export, direct version-pinned Pyroscope proof | queryable representative frames and sustained loss/coverage | profiling | Pyroscope query contains named Rust/C/C++/Go/Node/JVM/Python frames for supported versions |
| Export isolation | Separate in-memory exporters per family, bounds, timeout and simple retries | Fake HTTP server tests | background workers, time batching, jittered backoff, circuit breaker, shutdown flush, production counters | destination failure and saturation proof | exporters | unavailable profile endpoint does not change trace/metric latency; memory remains bounded |
| Self-observability | Source accounting logs, warnings, Prometheus signal rendering | Unit and selected logs | unified health registry and bounded metrics for controllers, queues, attachments, loss, exports, process use | alert and failure-injection proof | health | every induced blind spot changes a documented native metric/health state |
| Helm/DaemonSet | Linux DaemonSet, config, service account, list-only pod RBAC, host mounts, explicit capabilities | lint/render and prior homelab install | real probes, requests/limits, watch RBAC, priority, rollout/canary/rollback controls, schema depth | server dry-run, rollout, termination, rollback | packaging | disposable DaemonSet becomes ready, survives backend outage, drains, upgrades, rolls back |
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
