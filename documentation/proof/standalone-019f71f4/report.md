# Standalone observability proof run 019f71f4

## Decision

**NO-GO for replacing Beyla and the Alloy profiling DaemonSet.**

This run closed several concrete implementation defects and produced stronger
live evidence, but it did not satisfy the production acceptance contract. The
mandatory matched A/B/C trials and continuous 24-hour soak were not run, the
full functional and failure matrices remain incomplete, profiling is not
proven across every required runtime, and post-fix trace validation was blocked
when the shared Tempo backend entered an OOM crash loop.

The verdict is intentionally not weakened by the local quality pass or by
clean point windows. Nothing in this report is a release or production claim.

## Product boundary and architecture

The implementation remains an independent, statically registered E-Navigator
pipeline:

```text
Aya and host Sources
  -> one bounded supervisor and shared signal queue
  -> ordered Processors
  -> ordered Generators
  -> native E-Navigator signal envelopes
  -> independent metric, trace, and profile Sink workers
```

One E-Navigator process per node runs exec, network, DNS, HTTP, protocol, TLS,
host-resource, and CPU-profile sources. A shared Kubernetes controller lists
and watches Pods, Services, and EndpointSlices, builds bounded owner and
address indexes, publishes attribution snapshots, and drives source-side
cgroup filter maps. The exact run policy selected `proj-*` namespaces with a
paid Guara tier and no catalog slug, then applied process exclusions.

Metric, trace, and profile exports have separate bounded queues, workers,
timeouts, retry state, circuit breakers, and native counters. Profiles went
directly from E-Navigator to disposable Pyroscope 1.20.3 over pinned OTLP
Profiles. The existing Alloy instance remained only in the metric and trace
gateway path; its profiling path was not used. Existing Beyla and Alloy
resources were inventoried but not changed because they were outside the
disposable run.

No Beyla or Alloy compatibility mode, vendor alias, vendored collector code,
runtime plugin loading, new storage backend, or query UI was added.

## Repository and artifacts

- Branch: `codex/standalone-observability-agent`
- Runtime source commit: `4c047d2ddc71f94dd73511ff1f73fb575eebb748`
- `origin/main`: `39bf46ac4d0ac3be9d25b1a373d74b70bf4c8da0`
- Runtime source was 39 local commits ahead of `origin/main` at capture time.
- Nothing was pushed, published, released, or proposed as a pull request.
- Guara Cloud was read-only and was not modified.

New implementation commits after the previous proof were:

| Commit | Change |
| --- | --- |
| `8769c45` | make HTTP request capture connection-aware |
| `2111ba2` | prevent OTLP metric timestamp collisions |
| `10f8070` | preserve distributed trace parentage |
| `9742b8e` | add cluster-aware topology attribution |
| `a3dfcdf` | symbolize published JIT perf maps |
| `5cd76e0` | compress and measure OTLP exports |
| `558ff62` | classify OTLP export responses |
| `7c06f3f` | make TLS attachment fail closed |
| `f4f3c04` | sync the fuzz dependency lockfile |
| `9a8de97` | tolerate empty EndpointSlice endpoint lists |
| `f9c1261` | bound HTTP iovec verifier complexity |
| `33ff3bb` | order segmented HTTP capture across CPUs |
| `2b65650` | isolate HTTP state across reused sockets |
| `918812d` | release completed HTTP reassembly state |
| `4c047d2` | avoid duplicate observed client spans |

The runtime configuration and fixture source were kept under ignored
`target/` paths so no cluster token or secret entered the artifact. Their
SHA-256 values were:

```text
4b5b0c34e888a0faf0edbbfe0c63ec7db88f5cf3598484a57f772f063910b1a1  target/standalone-019f71f4.toml
34d2c0b34b1db2eea29377c918b668a5a23db41c4778b55b9e1bc1c0735e1149  target/standalone-019f71f4-fixtures.yaml
```

## Environment and deployment

- Kubernetes context: `homelab`
- API server: `https://192.168.50.132:6443`
- Kubernetes: k3s `v1.30.4+k3s1`
- Nodes: `homelab-01` and `homelab-02`
- OS/architecture: NixOS 24.05, Linux amd64
- Kernel: `6.6.68`
- Runtime: containerd `1.7.20-k3s1`
- Run namespace creation: `2026-07-18T00:19:28Z`
- Fixture namespace creation: `2026-07-18T00:53:52Z`
- Final Helm revision: 13 at `2026-07-18T02:38:04Z`

The final image was built from a committed clean source tree and loaded only
onto the two run nodes:

```text
tag: e-navigator:standalone-019f71f4-r10-amd64
manifest list: sha256:f9cbbae2bf66e3c63261683d18d5d5512aece65377a2e48972f3cd441e2c7f7f
manifest: sha256:52b3a71e3b6b8485be3ad3dd18da180b7fd8b4860699149af8e2f2ebc721a788
config/running image ID: sha256:2cc9e1cba61e1aa5348f69953e968f7f7936dc1f11bc59daac95607a33cdb897
```

Both final DaemonSet pods were Ready on separate nodes with zero restarts.
A point sample at `2026-07-18T02:44:03Z` was 173-185 millicores and
283-319 MiB per agent. This is not performance acceptance evidence.

## Correctness results

### HTTP framing and bounded connection churn

The run reproduced and fixed four distinct defects: connection-unaware body
state, cross-CPU segment ordering, incomplete iovec capture, and retention of
fully consumed short-lived connections. The last defect explained a delayed
invalid-event cliff: once 4,096 completed socket identities filled the bounded
map, every new connection evicted old state and was counted invalid.

The final fix removes empty completed state immediately while retaining partial
headers and outstanding bodies. The focused suite passed 23 HTTP tests,
including segmented headers, reverse cross-CPU delivery, fixed bodies,
pipelining, capture gaps, fd reuse with a new socket tuple, capacity eviction,
and high-churn complete connections.

Live results crossed the former 4,096-stream threshold twice:

| Image/window | Node | Decoded | Invalid | Send failures | Lost perf events |
| --- | --- | ---: | ---: | ---: | ---: |
| r9, `02:26:38Z`-`02:34:32Z` | homelab-01 | 17,405 | 0 | 0 | 0 |
| r9, same | homelab-02 | 11,430 | 0 | 0 | 0 |
| r10, `02:40:01Z`-`02:44:03Z` | homelab-01 | 8,663 | 0 | 0 | 0 |
| r10, same | homelab-02 | 5,693 | 0 | 0 | 0 |

No bounded-reassembly eviction or raw-invalid diagnostic appeared in either
final pod log. This closes the reproduced HTTP defect, not the 24-hour or full
protocol matrix gate.

### Metric timestamp identity

Logical metric series now include complete resource and data-point identity,
and a bounded timestamp guard prevents same-millisecond collisions across
worker batches. At the end of r9, node 1 had sent 240,297 metric records and
node 2 had sent 156,294, with zero local queue depth, failed batches, retries,
drops, partial responses, rejected items, or invalid responses. Alloy logs from
`2026-07-18T02:23:00Z` contained zero matches for `duplicate timestamp`,
`out of order`, or rejected samples.

This is materially longer and higher-rate than the original startup failure,
but it is still a minutes-long window and cannot replace the mandatory soak.

### Kubernetes selection and topology

The shared controller remained Ready with zero unresolved cgroups. The final
point showed six/three allowed cgroups on the two nodes, 280/47 denied, and no
unresolved cgroups. Profiles and trace resources carried namespace, pod, UID,
container, and node attributes. Owner, Service ClusterIP, and ready
EndpointSlice fallback indexes are covered by unit tests and were present in
live resource attributes.

This run did not complete an oracle-backed matrix for ingress, egress,
cross-agent deduplication, restart/reschedule, IP reuse, and ownership churn.
The topology gate therefore remains open.

### Distributed traces and SDK coexistence

Before the final ownership fix, a Tempo TraceQL query for E-Navigator observed
contexts found trace `3ee5fd06fb6be5a1886e47912cac26e` with nine spans but
only four unique span IDs. Multiple outbound requests reused the propagated
header span ID as an E-Navigator client span. That is invalid OTLP identity and
can duplicate an SDK-owned client span.

Commit `4c047d2` now treats the outbound traceparent span ID as owned by the
instrumentation that injected it. Passive E-Navigator capture does not export
a second client span with that identity. Server captures still create a new
child span under the wire remote parent. The focused 31-test request
correlation suite and the complete repository gate pass this behavior.

Post-fix backend proof could not be completed. Tempo became unready during the
r10 window, the first 30-second query timed out, the next query returned an
empty reply, and Tempo then entered `CrashLoopBackOff`. Therefore the trace
gate remains open. Passive capture also cannot safely inject or transitively
re-parent application W3C context; multi-hop ownership must come from the
application/SDK, and HTTP/gRPC multi-hop, retry, reuse, malformed-context, and
coexistence matrices still require stable backend proof.

### Profiling

Pyroscope 1.20.3 accepted profiles directly from E-Navigator. `LabelValues`
for `service_name` returned only:

```text
backend-019f71f4
loadgen-019f71f4
middle-019f71f4
pyroscope
```

The catalog and unpaid fixtures were absent. A direct
`SelectMergeStacktraces` query for the load generator returned 44.6 seconds of
CPU samples with named Python 3.12 frames including `<module>`, `request`,
`urlopen`, `OpenerDirector.open`, `HTTPConnection.request`,
`HTTPConnection.connect`, `create_connection`, `getaddrinfo`, and libc socket
and DNS frames.

Published perf-map symbols are now bounded and available to target-namespace
symbolization, with coverage/cache/skip counters and tests. Automatic Node/V8
and JVM map production, reliable JIT unwind, multiple CPython versions, and
representative Rust/C/C++/Go/Node/JVM live queries remain unproven. The
profiling matrix is NO-GO.

### TLS

The claimed surface is deliberately narrow: dynamically linked OpenSSL 1.1.1
or 3 with the required classic and `_ex` read/write/fd exports, and GnuTLS ABI
30 using standard integer socket transports. Attachment is architecture- and
version-gated, export-preflighted, transactional, and fail-closed.

The separate focused artifact under
`documentation/proof/standalone-20260717-tls-hardening/` records live OpenSSL 3
and GnuTLS ABI 30 HTTP 200 capture and rejection of an unknown `libssl.so.4`.
BoringSSL, Go `crypto/tls`, rustls, custom BIO/transports, statically bundled
Node TLS, and JVM JSSE are not claimed. A complete homelab protocol/TLS matrix
was not run.

### Export reliability

OTLP HTTP supports optional gzip, fixed-bucket request latency histograms,
partial-success/rejection accounting, retryable/permanent/malformed response
classification, bounded retry and circuit behavior, independent queues, and
bounded shutdown. Deterministic fake-server tests cover these paths.

At `02:44:03Z`, both r10 agents had zero metric/profile/trace queue depth,
failed batches, retries, queue-full drops, worker-closed drops, failure drops,
circuit drops, partial responses, rejected items, permanent responses, or
invalid responses. The agents had sent 131,289/79,739 metrics,
101/114 profiles, and 8,870/6,615 traces.

Those trace counters prove delivery to the configured Alloy OTLP gateway, not
to Tempo. During the Tempo outage, Alloy retried and then dropped trace batches
after exhausting retries. That gateway boundary prevented E-Navigator from
observing the final backend loss and blocked end-to-end acceptance.

## External blockers

The cluster was not stable enough for a continuous proof window:

- Both k3s servers repeatedly lost leader election and restarted. Between
  22:00 and 23:11 local time, homelab-01 failed/restarted at least seven times
  and homelab-02 at least six times. Both failed together at 23:10:26.
- Both servers continuously logged etcd `apply request took too long` and
  `waiting for ReadIndex response took too long`, including multi-second
  reads during the final validation.
- Tempo used a 1 GiB ballast under a 2 GiB memory limit, was OOM-killed with
  exit 137, reached restart count 8, and remained unready/CrashLoopBackOff.
- Alloy logged repeated Tempo deadlines and connection refusals, then dropped
  trace batches after exhausting retries.

Exact failed acceptance commands included:

```text
kubectl --context homelab -n observability-system wait \
  --for=condition=Ready pod/tempo-0 --timeout=90s
error: timed out waiting for the condition on pods/tempo-0

curl --max-time 30 .../api/search ...
curl: (28) Operation timed out after 30007 milliseconds with 0 bytes received

curl --max-time 50 .../api/search ...
curl: (52) Empty reply from server
```

Affected gates are post-fix trace identity/parentage, the complete functional
and failure matrices, repeated A/B/C trials, and the continuous 24-hour soak.
No shared-cluster or backend configuration was changed because it was outside
the disposable run's authority.

## Cleanup

Run teardown completed at `2026-07-18T02:51:11Z`. The Helm release, all five
run namespaces, the run ClusterRole and ClusterRoleBinding, disposable
Pyroscope, loaders, fixtures, and agents are absent. All ten run image
references were removed from both homelab nodes, matching local Docker image
tags and the quality-gate `e-navigator:local` tag were removed, and the three
local port forwards were stopped. Exact post-delete queries returned no
resource, Helm release, RBAC object, node image reference, local image tag, or
listening proof port containing the run ID.

The existing Beyla, Alloy, Tempo, and pre-existing E-Navigator resources were
not changed. The ignored runtime configuration and fixture manifest remain
under `target/` as the bounded resumable inputs required by the recovery
procedure; their hashes are recorded above and neither contains a credential.
They do not affect committed-worktree cleanliness.

## Performance and soak

No matched A/B/C performance trial was completed. Existing Beyla and Alloy
were left untouched, and a valid comparison requires pinned equal-duration
no-collector, reference, and E-Navigator trials with the same load, nodes,
warm-up, sampling, and query windows. The 1% throughput, 2% p99 latency, and
25% combined resource-reduction thresholds are all unproven.

The owned run existed for about 2 hours 25 minutes, but it was interrupted by
collector rollouts, load-generator resets, simultaneous control-plane
restarts, and the Tempo crash loop. It is not a continuous soak. The minimum
24-hour gate remains unstarted and NO-GO.

## Local and packaging validation

The final `scripts/quality.sh` run passed at runtime source commit `4c047d2`.
It included formatting, release-contract checks, strict workspace clippy,
workspace tests and build, fuzz target build checks, synthetic execution,
guard tests, cargo-deny, cargo-audit, cargo-machete, Linux container build and
smoke, Helm lint/render, kubeconform, link checks, and diff hygiene. The
linux/amd64 r10 build also compiled the embedded eBPF programs.

## Requirement decision

| Gate | Decision |
| --- | --- |
| standalone native product boundary | pass for implementation boundary |
| HTTP decode loss and bounded churn | pass for reproduced defect and live point windows |
| duplicate cumulative metric timestamps | partial pass; high-rate window clean, soak missing |
| distributed trace identity and trees | fail; implementation fix passes locally, post-fix backend proof blocked |
| native topology completeness | fail; owner/service foundations exist, full churn/NAT/ingress/egress oracle absent |
| profiling runtime matrix | fail |
| TLS claimed-surface safety | partial pass; focused local proof, full matrix absent |
| exporter failure and shutdown matrix | partial pass |
| zero excluded/cross-tenant telemetry | partial pass for queried profile labels; full matrix absent |
| at least 99% controlled coverage | fail; not measured across the required matrix |
| matched A/B/C thresholds | fail; not run |
| continuous 24-hour soak | fail; not run |
| full local and packaging gate | pass |
| cleanup and clean committed worktree | pass for owned cluster/image state; ignored resumable inputs retained |

## Recovery procedure

1. Stabilize both k3s servers until their service restart counters and leader
   elections remain unchanged and API/etcd readiness is continuous.
2. Repair or resize the existing Tempo deployment so it remains Ready without
   OOM or liveness restarts under the intended trace load; confirm Alloy has no
   retrying or dropped trace batches.
3. Start a fresh unique run from `4c047d2` or its evidence-only descendant,
   rebuild the amd64 image from a clean committed tree, and reapply the checked
   runtime configuration whose SHA-256 is recorded above.
4. Re-run the post-fix SDK/client-span TraceQL assertion, exact multi-hop
   HTTP/gRPC trees, topology/churn oracle, runtime profiling/TLS matrices, and
   failure injections.
5. Run pinned repeated A/B/C trials. Only after they pass, start a new
   uninterrupted 24-hour clock and evaluate loss, queues, cardinality, memory,
   symbol caches, topology freshness, backend queries, and workload SLOs.

The current implementation remains resumable through committed code, image
digests, configuration checksums, and this proof ledger. Production approval
requires every failed or partial gate above to become reproducibly green.
