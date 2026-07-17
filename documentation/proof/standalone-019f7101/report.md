# Standalone observability proof run 019f7101

## 1. Executive decision

**NO-GO for replacing Beyla and the Alloy profiling DaemonSet.**

This branch implements a substantial standalone slice: one E-Navigator process
runs general Aya capture and CPU profiling, workload state is shared, metric,
trace, and profile delivery use independent bounded workers, profiles travel
directly from E-Navigator to Pyroscope over pinned OTLP Profiles, and native
self-observability is available through the Prometheus endpoint. The full local
quality gate passes and the validated homelab slice ran on both amd64 nodes.

Production readiness is still blocked by incomplete distributed trace
parentage/propagation, incomplete Kubernetes topology semantics, limited
TLS/runtime and profiler symbolization coverage, an HTTP server-side decode
loss, a reproduced conditional duplicate-timestamp metric export failure, and
the absence of the required matched performance trials and 24-hour soak.

Proof levels in this report are deliberately separated into local, homelab,
and unproven. Nothing here is production proof.

## 2. Final architecture and lifecycle

The implemented runtime remains statically registered:

```text
Aya and host sources
  -> unified source supervisor (fail-fast or isolate policy)
  -> shared bounded signal queue
  -> ordered processors and generators
  -> native E-Navigator signals
  -> Prometheus native surface
  -> independent OTLP metric worker -> Alloy OTLP receiver -> Prometheus
  -> independent OTLP trace worker  -> Alloy OTLP receiver -> Tempo
  -> independent OTLP profile worker ----------------------> Pyroscope
```

The CLI initializes one node-wide Kubernetes list/watch controller before the
runner starts sources. The controller publishes raw pod snapshots to both
attribution and per-source cgroup filter-map appliers. Each source has explicit
configured/running/start/exit/failure state. With the deployed `isolate`
policy, one source failure does not terminate healthy sources. On SIGTERM, the
runner stops sources, drains bounded work, then shuts down sinks within the
configured deadline.

Metric, trace, and profile workers have distinct queues, batching, timeout,
retry, circuit-breaker, and counters. The direct profile endpoint was
`http://pyroscope-019f7101.e-nav-standalone-019f7101.svc.cluster.local:4040/v1development/profiles`;
Alloy was not in the profile path.

## 3. Native contract summary

- Signal envelopes remain schema version 1 with bounded strings, collections,
  attributes, Kubernetes labels, and sensitive-key filtering.
- Observed, inferred, warning, request-span, service-interaction, topology,
  profile-sample, and profile-session families remain distinct.
- Missing request context now generates deterministic nonzero native trace and
  span IDs without counting absence as invalid input. Malformed declared IDs
  remain observable.
- Metrics use native E-Navigator names. No Beyla aliases, Beyla modes, Alloy
  component emulation, or vendor translation layer were added.
- OTLP metrics preserve host/workload resource identity at data-point scope for
  downstream receivers that do not convert resource attributes automatically.
- OTLP Profiles is pinned to the development `v0.3.0` contract accepted by the
  disposable Pyroscope 1.20.3 backend.
- Native health includes source lifecycle, Aya decoded/invalid/sent/lost
  accounting, workload-controller freshness/watch state, filter decisions,
  and per-family exporter queue/retry/failure/circuit/drop counters.

## 4. Implementation commits

All commits are local and conventional. The runtime image was built from
`b95df9cbba74d1cf7acd2971e17087661bea78b4`; the final implementation-only
HEAD before adding this proof artifact was
`12dfc005316ee7fd0d5856d307dc7aeac021e8d2`.

| Commit | Purpose |
| --- | --- |
| `a405bae` | define standalone native contracts and readiness matrix |
| `512a36e` | introduce the unified source supervisor |
| `46eca7c` | split telemetry families into independent export workers |
| `0fab7e5` | extend the bounded workload selector language |
| `c00a6c1` | generate native request trace identity |
| `6db30ba` | harden DaemonSet lifecycle and probes |
| `0147d6d` | pin direct OTLP Profiles delivery |
| `a519d86` | align the Guara workload label expression |
| `c586466`, `b3b1d32` | enforce process and executable exclusions |
| `c1f1d35` | add the Guara production values preset |
| `a6a56d3` | expose native exporter telemetry |
| `8377dff` | share Kubernetes pod snapshots |
| `cd35489` | add list/watch/relist recovery |
| `a8c47d3`, `425d8b5` | expose supervisor and Aya source health |
| `ec36513` | distinguish absent from malformed trace context |
| `5bd5557` | increase bounded startup queue capacity |
| `11e9071` | bound TCP-stat metric cardinality |
| `9d93068` | preserve metric identity through OTLP |
| `19af9bd` | coalesce cumulative metric series within an export batch |
| `b95df9c` | apply the capture filter to TCP-stat probes |
| `12dfc00` | keep the capture-filter benchmark fixture buildable |

## 5. Files and ADRs

The branch changes 78 files (5,529 insertions, 801 deletions). Principal
surfaces are:

- `documentation/adr/0001-standalone-native-contracts.md`
- `documentation/adr/0002-unified-source-supervisor.md`
- `documentation/adr/0003-direct-otlp-profiles.md`
- `documentation/adr/0004-independent-export-pipelines.md`
- `documentation/adr/0005-shared-kubernetes-workload-controller.md`
- `documentation/standalone-readiness.md`
- `crates/e-navigator-runner/src/runtime.rs` and `source_health.rs`
- `crates/e-navigator-sources-ebpf-aya/src/capture_filter/`
- `crates/e-navigator-sources-ebpf-aya/src/source_telemetry.rs`
- `crates/e-navigator-ebpf-programs/src/main.rs`
- `crates/e-navigator-sinks/src/otlp_http.rs`, `exporter.rs`,
  `native_telemetry.rs`, and the OTLP protobuf encoders
- `charts/e-navigator/values-guara-production.yaml`, templates, and schema

## 6. Local validation

`scripts/quality.sh` passed at `12dfc00`. That includes:

```text
cargo fmt --all -- --check
python3 scripts/release.py check
cargo clippy --locked --workspace --all-targets --exclude e-navigator-ebpf-programs -- -D warnings
cargo test --locked --workspace --exclude e-navigator-ebpf-programs
cargo build --locked --workspace --exclude e-navigator-ebpf-programs
bash scripts/fuzz_check.sh
cargo run --locked -p e-navigator-cli -- --source synthetic
tests/*_guard_test.sh
cargo deny check
cargo audit
cargo machete
docker build -f Containerfile -t e-navigator:local .
docker run --rm e-navigator:local --source synthetic
tests/smoke_docker.sh e-navigator:local
helm lint charts/e-navigator
helm lint charts/e-navigator --values charts/e-navigator/values-guara-production.yaml
helm template e-navigator charts/e-navigator
kubeconform -strict -summary deploy/kubernetes/*.yaml
helm template e-navigator charts/e-navigator | kubeconform -strict -summary -
node website/check-links.mjs
git diff --check
```

The x86_64 release container build also compiled the eBPF programs, and all
seven Aya source families attached and ran on Linux 6.6 without verifier-load
failure. `scripts/fuzz_check.sh` build-checked the configured fuzz targets; no
timed focused fuzz campaign was run.

Focused Criterion results on the shared macOS host:

| Benchmark | Result |
| --- | ---: |
| selector allow | 16.983-17.485 ns, stored-baseline regression |
| selector deny | 12.851-13.238 ns, stored-baseline regression |
| desired map, 150 pods/300 cgroups | 15.637-16.187 us, stored-baseline regression |
| steady map diff | 4.036-4.234 us, stored-baseline regression |
| full-churn map diff | 716-742 ns, stored-baseline regression |
| network metric normalize | 211-220 ns, no detected change |
| network open aggregation | 3.309-3.496 us, improvement |
| network flow-byte aggregation | 3.143-3.256 us, regression |
| bounded exporter enqueue | 1.064-1.126 us |

These local comparisons were not isolated or matched reference trials and are
not acceptance evidence. The selector cost remains tiny relative to its
two-second reconciliation cadence, but the regressions need a controlled rerun.

## 7. Homelab identity, deployment, and cleanup

- Context: `homelab`
- API server: `https://192.168.50.132:6443`
- Server: k3s `v1.30.4+k3s1`
- Nodes: `homelab-01`, `homelab-02`; Linux amd64; kernel `6.6.68`;
  containerd `1.7.20-k3s1`
- Run namespace: `e-nav-standalone-019f7101`
- Fixture namespaces: `proj-enav-019f7101-paid-a`,
  `proj-enav-019f7101-paid-b`, `proj-enav-019f7101-catalog`, and
  `proj-enav-019f7101-unpaid`
- Image tag: `e-navigator:standalone-019f7101-r6-amd64`
- Image manifest digest:
  `sha256:d219618553db30389d5c23b08e9fd0750056969533a6e866e823f1f1ff07eaa5`
- Running image config ID:
  `sha256:d34b52abdc84c87fd1a87c9412e12c1ad4a7df25a9aa7dabc17910a6c2ff0078`
- Chart package SHA-256:
  `bc38aa27b1d648eb86f0f716c6d28f2fbd80aa6b630cbb72452c1fcb348a3a6b`
- Chart source-tree SHA-256:
  `74329aaaca27685589b92941b2d37d7786ad8c6d9930274c7ef9f008728af67a`
- Runtime config SHA-256:
  `0b618bd6b812b1a61fba100fe75f49056de792502a155dfec5d560ab742a4780`
- Final Helm revision: 6, deployed at `2026-07-17T20:54:51Z`
- Proof window: `2026-07-17T20:07:12Z` through
  `2026-07-17T21:09:01Z`
- Final agent pods: one per node, Ready, zero restarts
- Point-in-time agent resources: 80-125 millicores and 278-291 MiB per node

Cleanup is complete. Helm release `e-nav-019f7101`, all five owned namespaces,
the uniquely named ClusterRole/ClusterRoleBinding, fixture workloads,
Pyroscope, loader pods, and all run-tagged node images were removed. All
run-tagged local Docker images plus the quality-gate `e-navigator:local` image
were removed. An unrelated pre-existing `e-navigator:ci-local` image and all
unrelated cluster resources were left untouched. Post-cleanup namespace, pod,
and cluster-RBAC searches for `019f7101` returned no results.

## 8. Functional coverage matrix

| Capability | Current run | Result |
| --- | --- | --- |
| unified exec/network/HTTP/DNS/protocol/TLS/profile/host sources | both nodes | partial pass; all running, no perf loss |
| exact Guara selector | paid, catalog-excluded, unpaid fixtures | pass after TCP-stat source-filter fix |
| cross-node HTTP/1 client/server | Python 3.12 client and server | partial; client clean, server decode loss |
| W3C multi-hop parentage/propagation | not deployed | not proven |
| HTTP/2 and gRPC | local fixtures only | not homelab-proven |
| Redis/PostgreSQL/MySQL/MongoDB/Kafka/NATS | local fixtures/older slices only | not proven by this run |
| OpenSSL and GnuTLS discovery | node libraries | attachments observed; application correctness not asserted |
| Go crypto/tls, rustls, Node/V8, JVM TLS | not deployed | not proven |
| Python 3.12 profiling | paid fixtures | pass with named application/library frames |
| Rust/C/C++/Go profiling | not deployed | not proven by this run |
| Node/V8, JVM/JIT, other CPython profiling | not deployed | not implemented/proven |
| same-node, Service/NAT, ingress/egress topology | not deployed | not proven |
| cross-node workload attribution | paid client/server | partial pass |
| churn, reschedule, scale, IP reuse | rolling agent upgrades only | workload churn not proven |

## 9. Trace, topology, and profile correctness

### Trace

Tempo returned 20 paid-client and 20 paid-server traces and zero traces for
both excluded services. IDs were nonzero. The inspected paid-client trace had
one `GET /` client span and no parent. This proves export and strict workload
selection, but it fails the distributed-tree requirement: client/server spans
were not joined and no propagation or multi-hop parentage was proven.

### Topology and metrics

Prometheus received native `network_*` series carrying host, container,
namespace, pod, pod UID, node, and address-family identity. After r6, the last
excluded TCP-transition sample remained at Unix `1784321711.447`, while the
paid-client sample advanced to `1784322206.439`; after the staleness window,
the excluded query returned no series. Filter maps reported three allowed
cgroups per node, 47/280 denied cgroups, and zero unresolved cgroups.

The run did not prove both endpoint owner/service identity, Service/NAT
resolution, stable cross-agent deduplication, ingress/egress semantics, or pod
IP reuse. Therefore it cannot replace the topology contract consumed from
Beyla.

### Profiles

Pyroscope 1.20.3 accepted direct E-Navigator OTLP Profiles. Label queries
returned only `paid-client-019f7101`, `paid-server-019f7101`, and Pyroscope
itself; excluded workloads were absent. The
`process_cpu:cpu:nanoseconds:cpu:nanoseconds` type was queryable. A paid-client
flamegraph contained named Python 3.12 frames including `<module>`,
`<genexpr>`, `urlopen`, `OpenerDirector.open`, `HTTPConnection.request`,
`_send_request`, `create_connection`, and libc DNS/socket frames.

This is a direct-path Python slice only. The node-01 profiler repeatedly
reported about 798-802 processes beyond the DWARF coverage budget and 363
module rows skipped; node-02 reported 613 skipped module rows. Required native,
Go, Node, JVM, and multi-version Python proof is absent.

## 10. Failure and recovery

Only the owned Pyroscope deployment was scaled to zero. On `homelab-02`:

- profile `sent_total` held at 114 during the outage;
- profile failed batches rose 2 -> 5, retries 6 -> 15, failure drops 9 -> 13,
  the circuit opened once, and circuit-open drops rose 0 -> 15;
- metric sends continued 139,462 -> 171,300 with zero metric failures/drops;
- trace sends continued 2,098 -> 2,595 with zero trace failures/drops;
- all queue depths remained zero and capacity remained 8,192.

After Pyroscope was restored, profile sends rose 118 -> 132 and failure
counters stopped increasing. This proves cross-family isolation and automatic
recovery for one profile-backend outage.

Trace-backend outage, metric-backend outage, slow responses, queue saturation,
watch interruption, partial source attachment failure, malformed live traffic,
and SIGTERM with queued export were not exercised. Graceful rolling replacement
was observed, but shutdown-drain correctness was not measured from retained
old-pod logs.

## 11. Controlled performance comparison

No valid A/B/C comparison was run. Collectors were not co-scheduled for a
comparison, and the existing unrelated Beyla/Alloy resources were not mutated.

| Configuration | Collector CPU/memory | Throughput | p50/p95/p99 | Coverage | Decision |
| --- | --- | --- | --- | --- | --- |
| no collector | not run | not run | not run | n/a | missing |
| Beyla + Alloy profiling | not run | not run | not run | not run | missing |
| E-Navigator | 80-125m, 278-291 MiB point sample only | not measured | not measured | partial functional slice | insufficient |

No claim is made for the 1% throughput, 2% p99, or 25% resource-reduction
thresholds.

## 12. Soak

The entire disposable proof window was about 62 minutes; the final r6 revision
was observed for about 14 minutes before cleanup. This is not a soak. No
24-hour or seven-day evidence exists, and no claim is made about memory slope,
long-term attribution freshness, exporter wedging, cardinality growth, or
symbol-table retention.

## 13. Remaining blockers and next steps

| Blocker | Owner | Attempt/evidence | Next concrete step |
| --- | --- | --- | --- |
| missing distributed tree and propagation | request/trace generators and HTTP/TLS eBPF paths | generated IDs export, but Tempo shows single parentless spans | implement safe client/server W3C propagation with deterministic multi-hop tests, then live HTTP/1 and gRPC chains |
| incomplete native topology | signal model, Kubernetes attribution, network/dependency generators | paid cross-node labels exist; owner/service/NAT/dedup proof absent | add owner/service indexes, dual-endpoint identity and stable observation ID, then Service/NAT/churn oracle tests |
| HTTP server decode loss | Aya HTTP source and eBPF request capture | node-01 repeatedly decoded about 98-100 samples while rejecting 196-200 every 10s | retain bounded stage diagnostics for segmented server reads, fix framing/reassembly, assert zero unexplained invalids |
| conditional duplicate metric samples | OTLP metric encoder/worker and downstream OTLP-to-Prom path | batch coalescing stopped early bursts, but r5 reproduced a 2,000-sample rejection at `2026-07-17T20:53:36Z`; r6's shorter window was clean | identify the colliding native series, enforce one monotonically timestamped point per series across batch boundaries, and run sustained high-rate receiver tests |
| profiler runtime/coverage gaps | CPU unwind, symbolization, profiling generator | Python 3.12 frames queryable; DWARF budgets capped and other runtimes absent | add bounded perf-map/jitdump/runtime adapters and per-runtime coverage metrics, then query named frames for each claimed runtime |
| incomplete TLS matrix | TLS discovery and uprobes | OpenSSL/GnuTLS attachment counts observed only | implement and prove Go/rustls/Node/JVM paths or explicitly scope support lower |
| exporter/self-observability gaps | sinks/native telemetry | isolation/circuit counters proven; compression, latency and partial-response accounting absent | add request/batch latency and partial response metrics plus compression and fake-server coverage |
| performance and soak evidence | benchmark/proof harness | only local microbenchmarks and a resource point sample | build pinned matched A/B/C trials with raw artifacts, then a resumable 24-hour minimum soak |

The r5 duplicate rejection is especially important: r6 did not change exporter
semantics, so its short clean interval does not supersede the reproduced r5
failure.

## 14. Git state

- Branch: `codex/standalone-observability-agent`
- Implementation HEAD before this proof artifact:
  `12dfc005316ee7fd0d5856d307dc7aeac021e8d2`
- Baseline/origin main:
  `39bf46ac4d0ac3be9d25b1a373d74b70bf4c8da0`
- Implementation commits before this artifact: 23
- Worktree was clean before adding this report.
- Guara was inspected read-only and was not changed.
- Nothing was pushed, released, tagged, published, or changed on GitHub.
