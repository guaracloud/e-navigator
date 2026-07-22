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
| Unified source supervisor | Default unified mode registers enabled general and CPU sources together; deployed `isolate` policy preserves healthy sources; Linux sources handle SIGTERM and bounded sink drain; one node controller feeds all filter maps and production attribution; bounded native registries expose per-source running state, base initialization, lifecycle/data-path totals, and optional-target readiness/attachment totals | Unit, synthetic, lifecycle, partial-failure, source-health, cumulative-counter, optional-attachment, Linux release-build, shared snapshot, and process-exclusion tests | language-runtime-specific attachment and unwind-coverage detail | Combined live capture+profile, partial-attach, and termination proof | supervisor | All enabled real sources in one process; injected source failure leaves healthy source running under `isolate` |
| Native contracts | Schema-v1 envelope, bounded fields, confidence and warning families, golden fixtures | Unit and golden JSON | Collector lifecycle/health contract and complete naming policy | Backward fixtures for new stable families | contracts | Every stable kind round-trips; no vendor names in exported native metrics |
| Workload controller | One bounded Pod/Service/EndpointSlice API snapshot shared by cgroup filter publication and production attribution; optional cluster-wide Pods with local-first retention; Pod watch/bookmark/relist with expired-version recovery; stable controller owner, ClusterIP and ready EndpointSlice fallback indexes; native freshness/reconciliation/failure/resource-count/cgroup metrics | Unit watch-event, expiration, local-priority, shared snapshot, owner, Service, EndpointSlice, parser and selector tests plus selected older homelab attribution/filter runs | independent Service/EndpointSlice watches | Live cross-node churn, watch interruption, restart/reschedule and five-minute Service-staleness proof | workload-controller | Paid-tier/catalog selector stays correct through relist, deletion, IP reuse, and container restart |
| Selector language | Namespace exact/glob; label equality/inequality/existence/non-existence/set membership; bounded OR groups; process/container exclusions; explicit unknown posture and exclude-wins ordering | Unit/property-like cases including the exact Guara expression | per-family policy overrides | Live Guara paid-tier/catalog-exclusion and churn proof | selector | `proj-* AND guara.cloud/tier IN (...) AND guara.cloud/catalog-slug DOES NOT EXIST`; exclude wins |
| Native topology | Client-owned connection lifecycle and byte totals avoid cross-agent double counting; flow and dependency endpoints resolve cross-node Pods, stable controller owners, Service ClusterIPs, and EndpointSlice-only fallback addresses; OTLP interaction/path records carry qualified source/destination workload owner name and type; ClusterIP never claims one backend Pod | Unit cache, processor, signal-schema and OTLP attribute tests plus selected older live output | explicit flow observation ID/confidence if non-client capture is added | same/cross-node, NAT, IP reuse, churn and backend-query proof | topology | Expected edge set matches workload oracle without double counting |
| Distributed traces | Strict traceparent/tracestate parsing; request observations/spans; role-aware OTLP kinds; server spans get a new child identity under the wire remote parent; outbound contexts owned by existing instrumentation are not re-exported as duplicate E-Navigator client spans | Fixture/unit coverage and a live Tempo query that exposed duplicate client identity before the ownership fix | passive capture cannot inject or transitively re-parent W3C context, so SDK/manual propagation owns observed outbound client spans | deterministic post-fix Tempo proof plus multi-hop HTTP/gRPC, retries, reuse, malformed context, and SDK coexistence | tracing | exact trace tree for missing/valid/malformed context, retries, reuse, partial capture; no duplicate span IDs |
| Protocol and TLS | HTTP/1, h2/gRPC, extension-free WebSocket metadata, binary/text gRPC-Web metadata, PostgreSQL, MySQL, Redis, MongoDB, Kafka, and NATS parsers; opt-in accepted-server capture with bounded bind/accept plus procfs endpoint resolution; bounded same-stream HTTP/2 HEADERS/CONTINUATION reassembly; connection-generation-safe WebSocket transition; version-gated, architecture-checked, preflighted transactional uprobes for dynamically linked OpenSSL 1.1.1/3, GnuTLS ABI 30 standard socket transports, and unstripped Linux/amd64 Go 1.24-1.26 static `crypto/tls`; goroutine-safe Go correlation; fail-closed unknown/incomplete ABI handling; native optional-target, Go, WebSocket, and gRPC-Web metrics | Fixtures, property tests, executed focused fuzzing, local transition/fd-reuse/server-role tests, live OpenSSL 3 and GnuTLS ABI 30 HTTP/1, selected older live protocols, three Go 1.26.4 homelab HTTPS repetitions, and three WebSocket/gRPC-Web homelab repetitions with semantic/native counter parity, a real HTTP/3 negative control, and zero loss | HTTP/3/QUIC semantics, WebSocket extensions/compression/message reconstruction, gRPC-Web protobuf decoding, remaining correlation gaps, BoringSSL, rustls, custom BIO/transports, stripped or non-amd64 Go, and statically bundled Node/JVM TLS are explicit non-goals for this claimed surface | Go 1.24/1.25 runtime proof plus a homelab inbound/outbound matrix for every claimed library and application protocol | protocol-tls | automated request/status/secret-loss assertions per claimed protocol/runtime, with unsupported libraries visibly rejected |
| Profiling | Periodic on-CPU plus opt-in bounded scheduler off-CPU and futex-wait lock profiles in unified mode; weighted session/pprof/OTLP delivery; native/DWARF unwind; exact CPython 3.11/3.12 walks; ELF and conditional target-mount perf-map symbols; cumulative sessions are not re-exported | Unit/fuzz/bench coverage, selected Linux proof, local direct Pyroscope `1.20.3` ingest/query smoke, three guarded CPython 3.11.15 homelab pairs proving named frames and all three modes, and 567 periodic profiles accepted by the standing homelab Pyroscope endpoint with zero worker loss or rejection | allocation profiles, wakeup/lock-owner semantics, automatic Node/V8 and JVM map production, reliable unwind through JIT frames, and representative real-runtime backend proof | Homelab stored-profile query plus Node/JVM named-frame and sustained mixed-load coverage | profiling | backend query contains the expected named frames for each explicitly supported runtime and every loss/coverage gate remains bounded |
| Export isolation | Independent metric/trace/profile workers with bounded queues, size/time batches, optional blocking-pool gzip, bounded latest-value coalescing for cumulative points sharing a receiver millisecond, OTLP partial-success/rejection and retryable/permanent response classification, jittered retries, bounded `Retry-After`, circuit breaking, shutdown drain, fixed-bucket request-latency histograms, and a live feedback-safe Prometheus telemetry registry; missing-context diagnostic records are skipped without inflating invalid-ID counts | Deterministic fake HTTP compression/partial/permanent/retryable/malformed/overload/recovery, cross-batch timestamp coalescing, idle/shutdown terminal-value flushing, high-rate receiver uniqueness, absent-vs-malformed trace-identity tests, Prometheus registry integration test, gzip-enabled local Pyroscope smoke, and live startup-burst evidence | production cross-family latency and compression-ratio baselines | Repeat destination failure/saturation/memory-bound/cross-family latency proof after production queue tuning | exporters | unavailable profile endpoint does not change trace/metric latency; memory remains bounded |
| Self-observability | Source accounting logs and warnings; Prometheus signal rendering; native per-source running/start/exit/failure metrics; Aya base-initialization, cumulative decoded/invalid/sent/send-failure/perf-loss, optional-target discovery/readiness/unsupported/probe/failure/rescan/capacity, profile, Go TLS, WebSocket, and gRPC-Web metrics; native controller readiness/freshness/relist/watch/reconciliation/cgroup metrics; native exporter queue/retry/circuit/drop metrics | Unit, source lifecycle, cumulative/delta counter, optional-attachment/protocol-counter, registry integration, Linux release-build, guarded browser-protocol scrapes, and selected logs | remaining process-specific coverage metrics | alert and failure-injection proof | health | every induced blind spot changes a documented native metric/health state |
| Helm/DaemonSet | Linux DaemonSet, config, Pod/Service/EndpointSlice list/watch RBAC, host mounts/capabilities, explicit resources, rolling-update bounds, 30s grace, SIGTERM handling, optional real probes, priority field and schema validation | lint/render, kubeconform, lifecycle tests, and prior unrelated homelab install | canary/rollback and disruption controls | server dry-run, rollout, termination, rollback | packaging | disposable DaemonSet becomes ready, survives backend outage, drains, upgrades, rolls back |
| Performance and soak | Criterion hot paths, resumable soak collection, and a guarded cumulative no-agent/reference/E-Navigator comparison harness | Local microbenchmarks plus 33 matched homelab runs across HTTP, gRPC, Redis, PostgreSQL, and CPU profiles. The final E-Navigator arm measured 43.601071% more agent CPU and 31.903883% more RSS than Beyla plus Alloy | production tuning thresholds | 24-hour minimum data and production-shaped capacity proof | evidence | declared evidence-integrity gates pass, negative results remain explicit, and manifests/checksums preserve provenance |

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

## Gap-closure addendum, 2026-07-22

- Capture filtering now probes the configured cgroup hierarchy before loading
  sources and accepts only a directly mounted unified v2 root. Legacy v1,
  hybrid, unreadable, and ambiguous roots force deny before attachment and
  expose fixed native diagnostics. Unit fixtures cover every mode. A guarded
  homelab run proved the real v2 arm and fixture-backed legacy failure path with
  zero decoded or sent legacy-arm samples and 3,012 accounted kernel drops.
  Cgroup v1 support remains a deliberate ADR-backed non-claim, and a real
  v1-booted node was not tested.
