# Standalone production acceptance run f20e3b12

## Decision

**STOPPED BY USER BEFORE THE 24-HOUR MINIMUM. GO is not declared.**

The controlled functional and failure matrices, matched A/B/C performance
trials, source-controlled homelab cutover, and exercised rollback completed and
passed. The fifth soak attempt was continuity-valid through the final fixed
sample at `2026-07-20T13:50:00Z`, when the user requested that the soak stop.
That sample represented 79,982 seconds (`22h13m02s`) of accepted continuity,
leaving 6,418 seconds (`1h46m58s`) before the mandatory boundary.

At the final sample, attempt 5 had produced 1,199,700 successful requests since
its baseline with zero workload errors. E-Navigator decoded and sent exactly
the same 1,199,700 HTTP signals. The final full backend heartbeat remained
gap-free, bounded, and free of excluded or cross-tenant signals. Attempts 1
through 4 remain invalidated and contribute zero accepted seconds: stale
run-owned topology in attempt 1, one workload error in attempt 2, three
connection timeouts plus an optional TLS attachment departure in attempt 3,
and non-persistent Pyroscope history in attempt 4.

The hourly automation, disposable fixtures, and owned Kubernetes namespaces
were removed. The production E-Navigator, Pyroscope, Tempo, Alloy, and GitOps
state was preserved. At the stop point no ready PR, protected merge,
final-main image proof, release, or tag had been created. The user later
authorized repository publication as a separate action. That authorization
does not retroactively complete the 24-hour soak or change this decision to GO.

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
- Runtime source commit: `0cd5e9aa517c361875ceb0d2a5a1e564a6fbfdf2`
- Acceptance tag: `ghcr.io/guaracloud/e-navigator:sha-0cd5e9a`
- OCI index: `sha256:62402d21b9cb02d59d63365c7e3716ffa0980bfea42d070b43fed618703a7df9`
- Linux/amd64 manifest: `sha256:ae8b5a7e936f01423d01d42744907b4098ea5818f3d2326fa242b6237f9e6f0c`
- Linux/amd64 config: `sha256:5a3c9c907092a236ad0bbfef13356b70f7cf7da965a4f6babea1b50b5ab76e86`
- Attestation manifest: `sha256:87731e53b59607ef58eb97b7dd208f216b0fb14b70a9b39990b54e9cd0024131`
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
accepted-server capture, listener metadata retention through late admission,
existing-listener capture, span-role peer attribution,
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
| A, no collector | 149.9984 | 22.445 ms | n/a | n/a | n/a |
| B, Beyla + Alloy profiling | 149.9979 | 22.557 ms | 0.01616 cores | 0.35682 GiB | 0.37299 |
| C, E-Navigator | 149.9930 | 22.470 ms | 0.05800 cores | 0.20572 GiB | 0.26372 |

Against condition A, E-Navigator changed throughput by -0.00359% and p99 by
0.11287%. Against condition B, combined CPU-plus-GiB fell by 29.30%. The
contract permits at most 1% throughput regression, at most 2% p99 regression,
and requires at least 25% combined collector reduction. All three gates pass.

E-Navigator decoded, enqueued, exported, and delivered all 74,250 controlled
HTTP traces with zero invalid/lost/drop/retry/rejection counters. It also sent
635 direct profile items and returned useful named Python stacks. The clean
Beyla reference observed 40,889 of 74,250 expected requests, leaving 33,361
unaccounted (44.93%). Earlier B trials that accidentally selected the constant
soak workload were excluded before acceptance and rerun after a fresh reference
restart. The reference loss is recorded rather than normalized away.

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
   application and DaemonSet.
5. PR [#36](https://github.com/vicotrbb/home-datacenter/pull/36)
   pinned the listener-admission repair commit and official OCI index.
6. PR [#37](https://github.com/vicotrbb/home-datacenter/pull/37)
   temporarily isolated the production agents with an impossible node selector
   for the final no-collector and clean reference measurements.
7. PR [#38](https://github.com/vicotrbb/home-datacenter/pull/38)
   removed that selector and restored the exact accepted state. Root,
   E-Navigator, Pyroscope, and Alloy returned Synced/Healthy at revision
   `553e4365710f307cb485e1609a01881a7a9f3bbf`.

An older unmanaged E-Navigator canary was separately inventoried by exact
name, ownership, image, ConfigMap, service account, and cluster RBAC, then
removed. The final soak has exactly the two GitOps-owned agents and no second
collector. Both fixed agents were Ready before the selected server bound its
listener, and the live regression window retained zero protocol-invalid
samples throughout.

## Uninterrupted E-Navigator-only soak

Status: **STOPPED BEFORE MINIMUM DURATION; NOT ACCEPTED AS A 24-HOUR SOAK**

- Attempts 1 through 4: **INVALIDATED**; accepted duration zero
- Attempt 5 start: `2026-07-19T15:36:58Z` (epoch `1784475418`)
- Mandatory end: `2026-07-20T15:36:58Z` (epoch `1784561818`)
- Final proven fixed sample: `2026-07-20T13:50:00Z` (epoch `1784555400`)
- Accepted continuity: 79,982 seconds (`22h13m02s`)
- Missing duration: 6,418 seconds (`1h46m58s`)
- Offered workload: 15 RPS cross-node HTTP/1.1
- Attempt-5 workload delta: 1,199,700 scheduled and successful, zero errors
- Attempt-5 HTTP delta: 1,199,700 decoded and 1,199,700 sent

Through the final complete backend heartbeat at `2026-07-20T13:41:00Z`, all
accepted pod UIDs remained unchanged, every restart count remained zero, both
nodes were Ready, and root-app, E-Navigator, Pyroscope, and Alloy were
Synced/Healthy at the accepted GitOps state. Prometheus retained all three
targets and required series without a continuity gap. Source invalid, lost,
send-failure, optional-capacity, exporter, controller, backend, and excluded
sentinel counters remained at their attempt-5 baselines; queues were empty and
metric/controller/resource state stayed bounded.

Tempo continued to return root `python` / `http request` server spans with the
accepted pod UID, node, method, path, and generated high-confidence identity.
Pyroscope returned 2,649 consecutive 30-second samples from the attempt-5
boundary with zero interior gaps, 36,221,000,000,000 total nanoseconds, 5,090
names, 182 named Python symbols, healthy persistent block maintenance, and
96.08% PVC free space. Client and excluded-namespace Tempo, Pyroscope, and
metric sentinel queries remained empty.

The run was stopped by explicit user request at `2026-07-20T13:53:40Z`. This
is a strong 22-hour continuity result, but it is not the required 24-hour proof
and must never be represented as one.

## Quality and publication

Against source commit
`0cd5e9aa517c361875ceb0d2a5a1e564a6fbfdf2`, `scripts/quality.sh` completed
successfully immediately before the accepted clock on 2026-07-19. The gate
covered formatting, release metadata,
strict workspace Clippy, locked workspace tests, fuzz-crate compilation,
`cargo deny`, `cargo audit`, `cargo machete`, the container build and smoke
test, Helm lint and rendering, strict Kubernetes schema validation, local link
validation, and `git diff --check`. The focused Aya suite passed 191 tests with
zero failures, including both listener-admission cases. The first complete-gate
attempt exposed that the runtime's new `rustix`
dependency edge had not been propagated into `fuzz/Cargo.lock`. The lockfile
was regenerated mechanically in commit `cf24ff4`; complete reruns after the
runtime optimization and listener repair then passed. Because the user stopped
the run before the 24-hour boundary, final end-boundary evidence was not
collected and cannot be reconstructed. The user subsequently authorized a
fresh quality rerun and protected repository publication. Those publication
steps are independent of the stopped acceptance decision; no release or tag is
authorized, and publication cannot turn this result into a 24-hour GO.

The fresh complete `scripts/quality.sh` publication gate passed on 2026-07-20
after the stop record was finalized. It reran the Rust, supply-chain, container,
Helm, Kubernetes, documentation-link, and diff checks listed above with no
failures.

## Cleanup

At user stop, the soak namespace and six other exact-run disposable acceptance,
matrix, profiling, excluded-sentinel, and performance namespaces were deleted.
No matching run-owned namespace, cluster RBAC, or Helm release remained. The
hourly automation was deleted and the Prometheus, Tempo, and Pyroscope port
forwards were terminated. Sanitized proof and recovery inputs were retained.
Potentially shared node image and Nix-store cache entries were not deleted.

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
| Source-controlled final cutover | PASS | Home-datacenter PRs #31, #33, #35, #36, #38; Argo Synced/Healthy |
| Bounded rollback exercised | PASS | PR #34, 2/2 Beyla Ready, nonzero attributed telemetry, restore via #35 |
| Uninterrupted 24-hour soak | STOPPED / NOT ACCEPTED | Attempt 5 stopped at 22h13m02s, 1h46m58s short |
| Complete final quality gate | PASS FOR PUBLICATION | Fresh post-stop `scripts/quality.sh` rerun passed in full |
| Ready PR, checks, protected merge | AUTHORIZED AFTER STOP | Separate repository-publication request; cannot alter the stopped soak result |
| Final main image/source and GitOps digest match | OUTSIDE STOPPED SOAK | No final acceptance claim or GitOps rollout follows from repository publication |
| Owned cleanup complete | PASS FOR KUBERNETES FIXTURES | Seven exact-run disposable namespaces, automation, and port forwards removed |

No GO is recorded because the mandatory 24-hour row was stopped and not
accepted. Later repository publication does not change that fact.
