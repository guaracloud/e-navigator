# Standalone production acceptance run f20e3b12

## Decision

**IN PROGRESS. GO is not yet declared.**

The controlled functional and failure matrices, matched A/B/C performance
trials, source-controlled homelab cutover, and exercised rollback are complete
and passing. The mandatory uninterrupted E-Navigator-only soak began at
`2026-07-19T01:43:29Z` and cannot pass before `2026-07-20T01:43:29Z`.
Publication to final `main`, final image verification, and run-owned cleanup
remain pending until that interval is complete.

The clock will be restarted if an agent, Tempo, Pyroscope, Alloy, the workload
server, or the workload client is replaced or restarts; if configuration or
image identity changes; or if a monitoring gap makes continuity
unverifiable. A clean point sample is not treated as a soak pass.

## Product boundary and architecture

E-Navigator remains an independent Rust product with statically registered
native contracts:

```text
Aya and host Sources
  -> bounded source supervisor and native signal queue
  -> ordered Processors
  -> ordered Generators
  -> native E-Navigator signal envelopes
  -> independent metric, trace, and profile Sink workers
```

One digest-pinned E-Navigator agent runs on each Linux node. A bounded shared
Kubernetes controller lists and watches Pods, Services, and EndpointSlices,
builds attribution indexes, and publishes selected cgroups to the source-side
filter maps. The accepted capture policy is default-deny and selects `proj-*`
namespaces with a paid Guara tier while excluding catalog workloads, explicit
load generators, exporters, Alloy, Beyla, and E-Navigator itself.

Metrics and traces use standard OTLP HTTP through the existing shared Alloy
gateway. Profiles use OTLP Profiles directly from E-Navigator to Pyroscope.
The Alloy profiling path is absent. Pyroscope remains the profile backend.

No Beyla or Alloy configuration emulation, vendor aliases, compatibility mode,
copied vendor signal names, runtime plugin loading, new query UI, or new
storage backend was introduced.

## Repository and immutable runtime

- Authoritative start: `21a9e7f1734b81d92389f4799ef3d27480dfb51f`
- Acceptance branch: `codex/standalone-production-acceptance`
- Runtime source commit: `e6bc3952715d6ef97a7b4dd581bff8e7c4e2be71`
- Acceptance tag: `ghcr.io/guaracloud/e-navigator:sha-e6bc395`
- OCI index: `sha256:89bbc0b8e42fceda8205387896060c5dfa2c2fdf95d793f9f2a74fe7e3d7cc14`
- Linux/amd64 manifest: `sha256:d7cf0465d44bd637380b175fc32f3296d98eb2e9c0b9b1d59d99d4de24733f5f`
- Linux/amd64 config: `sha256:7611b64b52cac79d47cf9aae4d1cd85addf5d079bd3495deab0940f7f91a7ffd`
- Attestation manifest: `sha256:ca1013fc17b33e227be6f921f9b1f97698dc490247625f89dd141fe488686780`
- Release or version tag created: no

The final `main` image and its GitOps deployment revision are deliberately
left pending until the accepted evidence tree merges through repository
rules.

## Environment

- Kubernetes context: `homelab`
- API server: `https://192.168.50.132:6443`
- Kubernetes: k3s `v1.30.4+k3s1`
- Nodes: `homelab-01`, `homelab-02`
- OS: NixOS 24.05 on Linux amd64
- Kernel: `6.6.68`
- Runtime: containerd `1.7.20-k3s1`
- E-Navigator agents: two, one per node
- Tempo: 2.9.0, persistent local trace storage
- Pyroscope: 1.20.3, 4 GiB Longhorn volume
- Alloy: 1.12.1, retained for logs and OTLP metrics/traces

The exact input and deployed-configuration SHA-256 identities are recorded in
`environment.json`. Ignored fixture manifests contain no credentials and are
represented by hashes rather than copied into the committed proof.

## External blocker repair

### Tempo recovery OOM

The previous proof used the chart's 1 GiB memory ballast under a 2 GiB limit.
That left too little headroom for WAL replay plus the metrics generator and
repeatedly OOM-killed Tempo.

Home-datacenter PR
[#27](https://github.com/vicotrbb/home-datacenter/pull/27) reduced the
ballast to 256 MiB, set a 2 GiB request, and raised the memory limit to 4 GiB.
Tempo recovered, remained Ready with a stable zero restart count through the
functional and performance work, and continued receiving the soak trace rate.
The soak start sample had 221 live traces, 14.98 accepted spans/s, zero refused
spans/s, and zero discard rate for every reason.

### k3s and etcd instability

The former two-member control plane placed etcd on Btrfs alongside storage
workloads. Multi-second ReadIndex/apply latency led to repeated leader loss and
simultaneous server failures.

Home-datacenter PR
[#30](https://github.com/vicotrbb/home-datacenter/pull/30) made
`homelab-02` the sole etcd member and disabled etcd on the workload-heavy
`homelab-01` control-plane server. Both nodes returned Ready, etcd stayed
healthy, and server restart counters remained stable during acceptance.

### Pyroscope volume ownership

The pinned Pyroscope image runs as UID 10001 while the newly provisioned
Longhorn volume was root-owned. The first durable profile write was rejected
with permission denied. Home-datacenter PR
[#32](https://github.com/vicotrbb/home-datacenter/pull/32) added a
source-controlled `runAsUser` and `fsGroup` of 10001. The replacement pod
became Ready, write rejections stopped, and named stack queries succeeded.

## Functional and failure matrices

The machine-readable matrix is in `functional-matrix.json`. Every listed
runtime matrix was backed by controlled fixtures, native telemetry, and final
backend queries rather than unit tests alone.

| Matrix | Result | Acceptance evidence |
| --- | --- | --- |
| HTTP and protocol | PASS | Fragmentation, cross-CPU ordering, bodies, pipelining, gaps, reuse, bounded-map churn, HTTP/2 continuation, gRPC, accepted listeners, vectored I/O, DNS, TCP roles, malformed input; 74,250/74,250 HTTP events, invalid/lost/send failure zero |
| Metrics | PASS | Complete series identity, bounded timestamp state, restart/reset handling, duplicate timestamps zero, out-of-order zero, rejected samples zero |
| Distributed tracing | PASS | Unique IDs, correct server parentage, observed-client ownership, HTTP/gRPC multi-hop, retry/reuse, malformed context, SDK coexistence, cross-node Tempo proof |
| Topology and tenancy | PASS | Pod/owner/Service/EndpointSlice/namespace/container/node identity, restart/reschedule/IP reuse/watch/relist, cross-agent deduplication, namespace/tier/catalog/process/cgroup exclusions, cross-tenant zero |
| Profiling | PASS | Direct OTLP Profiles and useful Pyroscope queries for C, C++, Rust, Go, CPython 3.11/3.12, Node/V8, and JVM; native/JIT frames, refresh and bounds, excluded services zero |
| TLS | PASS | OpenSSL 1.1.1, OpenSSL 3, and GnuTLS ABI 30 over supported HTTP/gRPC; transactional fail-closed attachment; six exact backend matches; parser diagnostics and loss zero |
| Export reliability | PASS | gzip/plain, partial, retryable, permanent, malformed, timeout, saturation, worker close, outage, circuit recovery, shutdown, independent failure domains, bounded queues, final backend receipt |

TLS claims remain deliberately narrow. BoringSSL, Go `crypto/tls`, rustls,
statically bundled Node TLS, JVM JSSE, custom BIOs, and custom GnuTLS
transports are explicit non-claims.

The changes found during the matrices include HTTP/2 continuation reassembly,
accepted-server and existing-listener capture, span-role peer attribution,
container symbol resolution, JVM perf-map naming, CPython 3.11 stack support,
vectored server I/O, cross-CPU ordering, non-HTTP filtering, DNS peer and
timestamp corrections, metric identity/coalescing, capture-policy accounting,
bounded topology output, completed exporter failure coverage, TLS return-value
sign extension, and bounded runtime overhead.

## Matched A/B/C performance

The complete raw trial values and formulas are in `abc-results.json`.

All nine measured trials used the same digest-pinned Python 3.13 client/server,
request mix, node placement, 45-second warm-up, 120-second measurement,
concurrency 32, and fixed 150 RPS offer. The server ran on `homelab-02`; the
excluded client ran on `homelab-01`. The 150 RPS rate is approximately ten
times the observed 14.945 RPS combined target workload rate.

| Condition | Throughput RPS mean | p99 mean | Collector CPU | Collector memory | CPU + GiB |
| --- | ---: | ---: | ---: | ---: | ---: |
| A, no collector | 149.9985 | 22.446 ms | n/a | n/a | n/a |
| B, Beyla + Alloy profiling | 149.9927 | 22.551 ms | 0.01510 cores | 0.36581 GiB | 0.38091 |
| C, E-Navigator | 149.9932 | 22.508 ms | 0.06292 cores | 0.19958 GiB | 0.26249 |

Against condition A, E-Navigator changed throughput by -0.00354% and p99 by
0.27324%. Against condition B, combined CPU-plus-GiB fell by 31.09%. The
contract permits at most 1% throughput regression, at most 2% p99 regression,
and requires at least 25% combined collector reduction. All three gates pass.

E-Navigator decoded, enqueued, exported, and delivered all 74,250 controlled
HTTP traces with zero invalid/lost/drop/retry/rejection counters. The Beyla
reference plateaued at 60,543 of 74,250 expected spans, leaving 13,707
unaccounted (18.46%). That reference loss is recorded rather than normalized
away.

## GitOps cutover and rollback

The source of truth is
[`vicotrbb/home-datacenter`](https://github.com/vicotrbb/home-datacenter).
The exact commit and live reconciliation record is in
`cutover-rollback.json`.

1. PR [#31](https://github.com/vicotrbb/home-datacenter/pull/31)
   added digest-pinned E-Navigator and Pyroscope Argo applications, storage,
   source allow-listing, and operational documentation.
2. PR [#33](https://github.com/vicotrbb/home-datacenter/pull/33)
   removed only the Beyla application and values. Shared Alloy remained.
3. PR [#34](https://github.com/vicotrbb/home-datacenter/pull/34)
   restored the exact Beyla deployment for the bounded rollback drill. Argo
   reached Synced/Healthy, the DaemonSet reached 2/2 Ready with zero restarts,
   both agents attached to the controlled Python workloads, and their scrape
   endpoints exposed nonzero attributed HTTP client/server telemetry.
4. PR [#35](https://github.com/vicotrbb/home-datacenter/pull/35)
   restored the accepted E-Navigator-only state. Argo pruned the Beyla
   application and DaemonSet. Root, E-Navigator, Pyroscope, and Alloy returned
   Synced/Healthy at revision
   `efb17b904a39a576c93fbc6384cfd7d8ebc745a6`.

An older unmanaged E-Navigator canary was separately inventoried by exact
name, ownership, image, ConfigMap, service account, and cluster RBAC, then
removed. The final soak has exactly the two GitOps-owned agents and no second
collector.

## Uninterrupted E-Navigator-only soak

Status: **IN PROGRESS**

- Stabilization began: `2026-07-19T01:37:42Z`
- Clock start: `2026-07-19T01:43:29Z` (epoch `1784425409`)
- Earliest valid end: `2026-07-20T01:43:29Z` (epoch `1784511809`)
- Offered workload: 15 RPS cross-node HTTP/1.1
- Start workload totals: 5,208 scheduled, 5,208 successful, 0 errors
- Five pre-clock one-minute windows: 900 successes, 0 errors each
- Pre-clock p99 range: 26.538 to 27.530 ms

At the frozen boundary:

- both agent scrape targets and the workload target were up;
- all agent, backend, and workload containers were Ready with zero restarts;
- both agents used the accepted OCI index digest;
- HTTP decoded and sent were both 6,767, with invalid, lost, and send failure
  all zero;
- every metric/profile/trace exporter queue was empty;
- every exporter drop, retry, failed-batch, partial, rejected, permanent, and
  invalid-response counter was zero;
- both Kubernetes controllers were Ready, watch failures were zero, and the
  one node-1 API relist failure occurred during startup before the clock;
- Tempo returned traces for the new server pod with correct Kubernetes
  identity, `python` root service, and `http request` server span;
- Pyroscope returned only the soak service plus Pyroscope in the start window,
  with 3.0 seconds of samples, 67 names, 28 levels, and 60 named Python frames.

Prometheus continuously scrapes the agent and workload series. Tempo and
Pyroscope continuously retain backend receipt. An hourly heartbeat attached
to this task checks immutable pod UIDs, restarts, Argo state, collector
absence, scrape continuity, workload rate/errors, HTTP loss, exporter state,
controller freshness, backend queries, resource bounds, and tenant sentinels.

The exact start identities and baseline counters are in `soak-start.json`.
End-boundary values, query-range continuity assertions, and the final soak
decision will be added only after the minimum end boundary.

## Quality and publication

At proof-bearing branch commit
`cf24ff4ff5d3596a719049db9a2b68a112276163`, `scripts/quality.sh` completed
successfully on 2026-07-19. The gate covered formatting, release metadata,
strict workspace Clippy, locked workspace tests, fuzz-crate compilation,
`cargo deny`, `cargo audit`, `cargo machete`, the container build and smoke
test, Helm lint and rendering, strict Kubernetes schema validation, local link
validation, and `git diff --check`. The focused Aya suite separately passed
189 tests with zero failures.

The first complete-gate attempt exposed that the runtime's new `rustix`
dependency edge had not been propagated into `fuzz/Cargo.lock`. The lockfile
was regenerated mechanically in commit `cf24ff4`; the complete rerun then
passed. Because the soak-end evidence, manifest, and checksums do not exist
yet, final post-evidence hygiene remains required before publication. The
ready PR, every required GitHub check, protected merge, post-merge image
workflow, final `main` digest/source match, and corresponding GitOps digest
update also remain pending.

## Cleanup

Final cleanup is pending until the soak and publication checks complete.
Run-owned resources include the controlled fixture namespaces, performance
namespace, soak namespace, acceptance diagnostics, RBAC and Helm state, node
image references, three `/tmp/enav-f20e3b12-*-perf.data` files on
`homelab-02`, the temporarily fetched Nix perf store path, local temporary
files, and owned port forwards. Exact targets will be re-resolved immediately
before deletion. Recovery inputs will be retained only when they are sanitized
and deliberately documented.

## Requirement decision table

| Requirement | Status | Evidence |
| --- | --- | --- |
| Standalone native product boundary | PASS | Static native pipeline; standard OTLP only; no vendor emulation |
| k3s/etcd blocker eliminated | PASS | Home-datacenter PR #30 and stable cluster validation |
| Tempo OOM/drop blocker eliminated | PASS | PR #27; Ready/restarts zero; post-stabilization discard/refusal rate zero |
| HTTP/protocol matrix | PASS | `functional-matrix.json` and controlled exact counts |
| Metrics matrix | PASS | Duplicate/out-of-order/rejection zero and backend queries |
| Distributed tracing matrix | PASS | Ownership regression tests plus exact Tempo queries |
| Topology/tenancy matrix | PASS | r48-r55 fixtures and zero excluded/cross-tenant backend signals |
| Profiling matrix | PASS | Direct Pyroscope queries across required native/runtime families |
| TLS matrix | PASS | OpenSSL 1.1.1/3 and GnuTLS 30 plus fail-closed non-claims |
| Export reliability matrix | PASS | Deterministic failure matrix and live end-to-end receipt |
| Three matched A/B/C trials | PASS | `abc-results.json`; all thresholds pass |
| Source-controlled final cutover | PASS | Home-datacenter PRs #31, #33, #35; Argo Synced/Healthy |
| Bounded rollback exercised | PASS | PR #34, 2/2 Beyla Ready, nonzero attributed telemetry, restore via #35 |
| Uninterrupted 24-hour soak | IN PROGRESS | `soak-start.json`; earliest end `2026-07-20T01:43:29Z` |
| Complete final quality gate | IN PROGRESS | Full `scripts/quality.sh` pass at `cf24ff4`; final post-evidence hygiene remains |
| Ready PR, checks, protected merge | PENDING | Run after soak passes |
| Final main image/source and GitOps digest match | PENDING | Run after protected merge and image publication |
| Owned cleanup complete | PENDING | Run after publication verification |

No GO will be recorded while any row remains in progress or pending.
