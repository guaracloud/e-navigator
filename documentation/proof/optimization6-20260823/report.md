# Evidence-Driven Optimization Campaign 6

Dates: 2026-08-23 to 2026-08-24

Status: **RETAINED CPU IMPROVEMENT, OVERALL NO-GO**. Two small hot-path
changes are retained. Against the clean `v0.5.0-rc.4` baseline, final-stage
E-Navigator CPU fell from 106.312703 to 93.732580 millicores, an 11.833132%
reduction. The final 33-arm homelab comparison still measured E-Navigator at
17.387054% more CPU than combined Beyla plus Alloy while using 12.380561%
less RSS. The goal of beating the comparison stack on both CPU and memory is
therefore not met.

No code, image, chart, release, or benchmark result was pushed. The only
cluster used was the `homelab` kubectl context. Temporary benchmark resources
were removed and the standing environment was restored.

## Profile-First Routing

The clean release baseline was profiled before changing code. A fixed-rate
Redis whole-agent run decoded 112,034 source samples, completed 48,000 of
48,000 operations with zero errors, and recorded 3,000 perf samples with no
perf loss. The agent used 88.834741 millicores, 44,748 KiB RSS, and 50,600 KiB
peak RSS. Opening `/proc/<pid>/cgroup` accounted for 31.75% of sampled CPU.

After moving container-context construction to connection creation, the same
profile decoded 112,034 samples, completed all 48,000 operations, and recorded
1,000 perf samples with no loss. The procfs-open hotspot disappeared. The
remaining flat profile was led by SipHash at 4.71%, libc at 3.53%, sensitive
attribute-key checks at 2.75%, allocator work at 2.18%, `BTreeMap` insertion
near 1.29%, Tokio scheduling pieces near 1.1%, gzip at 0.78%, and generated
trace identity at 0.73%.

## Retained Changes

### Construct protocol observation context once per connection

`ProtocolStreamRegistry` previously constructed `ObservationContext` before
every connection-map lookup. For established protocol streams this reopened
and reparsed `/proc/<pid>/cgroup` even though the stream retained the context
created by its first event. Context construction now occurs inside the
existing `HashMap::entry(...).or_insert_with(...)` seam, while discovery-owned
contexts, source-time attribution, stream eviction, and protocol state remain
unchanged.

The permanent `protocol_stream/request_response_match` Criterion benchmark
improved from 2.6724-2.8288 microseconds to 1.0223-1.0576 microseconds. The
estimated mean change was -58.132%, with a 95% interval of -59.469% to
-56.704% and `p = 0`. The regression test now asserts that a matched Redis
request and response on one established connection read its procfs cgroup file
exactly once and preserve the original container attribution.

Three counterbalanced local whole-agent pairs produced:

| Pair | Baseline CPU | Candidate CPU | CPU change | Baseline RSS | Candidate RSS |
| --- | ---: | ---: | ---: | ---: | ---: |
| 1 | 92.078431 m | 48.824433 m | -46.975% | 48,096 KiB | 41,404 KiB |
| 2 | 68.960427 m | 50.118644 m | -27.323% | 42,872 KiB | 45,860 KiB |
| 3 | 67.167740 m | 41.334214 m | -38.461% | 41,940 KiB | 45,352 KiB |

The baseline CPU mean was 76.068866 millicores and the candidate mean was
46.759097 millicores, a 38.530572% reduction from means and a 37.586327%
mean paired reduction. Mean RSS changed from 44,302.667 to 44,205.333 KiB,
-0.219701%. Every arm decoded exactly 112,034 samples and reported zero hard
loss, exporter drops, failed batches, invalid responses, or rejected items.

### Avoid the duplicate full hash in bounded request fingerprints

`BoundedFingerprints::insert_if_new` previously performed `HashSet::contains`
and then `HashSet::insert`, hashing every new request fingerprint twice. It now
inserts first, returns immediately on duplicates, and then performs the same
oldest-entry eviction while `len > max`. The minimum capacity of one,
duplicate result, insertion order, deterministic eviction, and bounds are
unchanged. The release path is one source line shorter.

The permanent `generator/request_correlation_unique_at_capacity` benchmark
improved from 1.3306-1.4517 microseconds to 1.1216-1.1544 microseconds. The
estimated mean change was -10.840%, with a 95% interval of -14.265% to
-7.3425% and `p = 0`. All three bounded request-correlation eviction tests
passed.

The existing duplicate-suppression benchmark also covered the tradeoff from
constructing an `Arc` before insertion. The clean baseline measured
155.25-160.70 nanoseconds and the final code measured 150.64-154.94
nanoseconds. The estimated mean change was -2.0333%, with a 95% interval of
-3.2472% to -0.8885% and `p = 0`; Criterion classified the magnitude as within
its practical noise threshold. This supports a no-regression conclusion, not
an additional performance-win claim.

Three counterbalanced local whole-agent pairs changed CPU by -3.856342%,
-13.317063%, and +9.871764%. The baseline mean was 46.605401 millicores and
the candidate mean was 45.032948 millicores, -3.373971% from means and
-2.433880% as the mean paired change. Mean RSS rose 2.492056%; one pair was
worse on CPU, so the whole-agent result is directional rather than a universal
win. Every arm still decoded exactly 112,034 samples. The arm64 release binary
became 32 bytes smaller.

The final homelab profile-stage E-Navigator CPU mean was 93.732580 millicores,
down 5.598157% from the procfs-only candidate's 99.291049 millicores. During
the same separate campaigns the Beyla plus Alloy reference rose 3.149767%,
from 77.410900 to 79.849163 millicores. This corroborates the focused and
local evidence, but three samples on a shared cluster do not statistically
isolate the second change.

## Rejected Experiment

An allocation-free rewrite of generated trace identity regressed its focused
benchmark by 4.0211%. The function accounted for only 0.73% of the whole-agent
profile, while the rewrite added 25 source lines and 320 release-binary bytes.
It was fully reverted.

## Reproducible Inputs And Method

- Clean baseline source: `2a6d7ac` (`v0.5.0-rc.4`). The candidate is the
  documented uncommitted diff on branch `codex/evidence-optimization-rc4`.
- Baseline image: `docker.io/library/e-navigator:opt6-baseline-amd64`, local
  OCI image ID
  `sha256:8be839ed2794536bb7f38d014c53e43252e3ac3bad03665ef1647a1888fe7c24`.
  Baseline binary SHA-256:
  `3749fe5e541af6ceb3297c7e54984edf2420df790398963965904e2dfff558a2`.
- Procfs-only image: `docker.io/library/e-navigator:opt6-final-amd64`, local
  OCI image ID
  `sha256:1f07e626f89de099f94e5c52ffb903bae08b56137a106870e0cc0ebef541526d`.
  Binary SHA-256:
  `73de0701b2b5b06b114b668c89a526a1c53d345cc0c9549e3caab6f2488ee9d8`.
- Final image: `docker.io/library/e-navigator:opt6-final-v2-amd64`, imported
  OCI index digest
  `sha256:6627504c08704010d0b335405aafe520fd71d9a7a65a6f40fb723df1e613a309`
  and runtime image ID
  `sha256:625a0c819c221aa7bffaf43827ec197111e7779d29f34f541c879b1a4ff8e235`.
  Binary SHA-256:
  `f61579fc5f2d2eaa7d7beadaf6c5833771921ec28358dcfc52acf9a99607bc2a`.
- Workload image: `docker.io/library/e-navigator-head-to-head:opt6-amd64`,
  runtime image ID
  `sha256:d367537d6d186d755911f8039571ae8a0c23c7d7edf0ae61d161b03f59477b7d`.
- Beyla chart 1.16.10 archive SHA-256:
  `f404a525451c1b36ab0a8a98560e20fc4af70f59016518d414ce5fed367855e2`.
  Beyla image:
  `docker.io/grafana/beyla@sha256:133b8d66190f21e20365d9972e1621513ea5e44518fb71e1c3e0180c64815566`.
  Alloy image:
  `docker.io/grafana/alloy@sha256:491b0578c04983fd54fe99b587b6fab4404dc46d0dc16677bd6b00cc1140b308`.
- Cluster: exactly `kubectl --context homelab`, two amd64 NixOS nodes,
  Linux 6.6.68, k3s v1.30.4 with containerd 1.7.20-k3s1. The kubectl 1.36
  client warned that its skew from the 1.30 server exceeds the supported
  plus or minus one minor version.
- Each campaign ran 33 counterbalanced validated arms: three repetitions of
  no collector, E-Navigator, and Beyla plus Alloy across cumulative HTTP,
  gRPC, Redis, PostgreSQL, and 8 requests/second Python profile load. Offered
  rates were 100, 80, 160, 50, and 8 operations/second, with 15 seconds of
  warmup and 45 measured seconds per arm.

The final command was:

```bash
E_NAVIGATOR_HOMELAB_CONFIRM=1 \
E_NAVIGATOR_HEAD_TO_HEAD_RESULTS_DIR=benchmarks/results/optimization6-final-20260824 \
E_NAVIGATOR_HOMELAB_IMAGE_TAG=opt6-final-v2-amd64 \
E_NAVIGATOR_HEAD_TO_HEAD_WORKLOAD_IMAGE=docker.io/library/e-navigator-head-to-head:opt6-amd64 \
benchmarks/runner/homelab-head-to-head.sh
```

All 33 final arms passed without retry. They completed 591,030 of 591,030
measured operations and 197,010 warmup operations with zero workload errors.

## CPU And RSS Results

Values are mean plus or minus sample standard deviation over three final-stage
profile arms. CPU is millicores; RSS is bytes. CV is the coefficient of
variation.

| Campaign | Stack | CPU mean | CPU stdev | CPU CV | RSS mean | RSS stdev | RSS CV |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Clean baseline | E-Navigator | 106.312703 | 2.718569 | 2.557% | 119,028,849.778 | 11,757,054.063 | 9.877% |
| Clean baseline | Beyla plus Alloy | 76.545990 | 0.444073 | 0.580% | 136,470,072.889 | 1,662,150.953 | 1.218% |
| Procfs-only | E-Navigator | 99.291049 | 5.582980 | 5.623% | 122,878,634.667 | 1,665,617.694 | 1.355% |
| Procfs-only | Beyla plus Alloy | 77.410900 | 1.713757 | 2.214% | 145,510,400.000 | 4,247,777.355 | 2.919% |
| Final | E-Navigator | 93.732580 | 4.702499 | 5.017% | 127,035,619.556 | 7,667,371.429 | 6.036% |
| Final | Beyla plus Alloy | 79.849163 | 0.964537 | 1.208% | 144,985,656.889 | 3,881,413.423 | 2.677% |

The clean baseline put E-Navigator at +38.887358% CPU and -12.780255% RSS
versus Beyla plus Alloy. The final candidate reduced the relative CPU deficit
to +17.387054%, a 21.500304 percentage-point improvement, while the RSS result
was -12.380561%. E-Navigator's direct baseline-to-final CPU mean fell
11.833132%. Its RSS mean rose 6.726747%, but baseline and final RSS CVs were
9.877% and 6.036%; this cross-campaign increase is not treated as a proven
regression. The contemporaneous final comparison still shows the memory win.

## Throughput And Latency

Final E-Navigator changes versus the contemporaneous Beyla plus Alloy stack
are percentages. Negative latency is faster. Every final workload family had
zero errors.

| Family | Throughput | p50 latency | p95 latency | p99 latency |
| --- | ---: | ---: | ---: | ---: |
| HTTP | -0.000953% | -1.684982% | -0.279460% | -0.305169% |
| gRPC | -0.000953% | -2.418992% | +3.177216% | -0.805489% |
| Redis | -0.000953% | -7.084309% | -0.273973% | +2.013058% |
| PostgreSQL | -0.000953% | -4.064588% | -1.934150% | -7.851430% |
| Python CPU | -0.000953% | +0.930329% | +0.906410% | -4.547606% |

These short shared-cluster differences do not establish production latency
superiority. They do show that the retained changes did not buy lower CPU by
reducing offered throughput or introducing a broad tail-latency regression.

## Signal Completeness

Across the three final E-Navigator profile arms, the source decoded 169,814
samples and sent 99,288 signals. It decoded and sent 861 profile signals.
The exporter scrape deltas reported 98,427 traces enqueued and 98,434 sent,
plus 861 profiles enqueued and 860 sent. These small opposing differences are
asynchronous scrape-boundary effects. Hard loss was zero for every signal
family, including transport loss, perf loss, RingBuf reservation failure,
invalid samples, source send failures, source failures, queue-full drops,
failure drops, circuit-open drops, worker-closed drops, failed batches,
invalid responses, permanent responses, and rejected items.

One procfs-only candidate attempt failed its unchanged gRPC completeness gate
at 10,799 signals against the 10,800 minimum, despite exact workload success
and zero hard-loss counters. Its raw artifact was preserved; the same arm was
rerun once without changing the gate and passed, and repetition 3 also passed.
The final-v2 campaign did not reproduce the miss and needed no retry.

## Allocation Diagnostics

The allocation probe used a 45-second window inside one 90-second profile arm.
E-Navigator libc `malloc`, `calloc`, `realloc`, `aligned_alloc`, and
`posix_memalign` uprobes recorded:

| Image | Allocation calls | Requested bytes | Profile samples decoded | Source samples decoded |
| --- | ---: | ---: | ---: | ---: |
| Clean baseline | 6,523,110 | 904,274,684 | 417 | 103,266 |
| Procfs-only candidate | 7,114,009 | 1,033,154,681 | 1,360 | 104,232 |

The raw candidate totals are higher, but the candidate captured 3.26 times as
many profile samples. The windows were not matched on sampled profile work, so
they prove neither an allocation improvement nor a regression.

The directional reference window recorded 2,274,990 Beyla `runtime.mallocgc`
calls requesting 287,377,035 bytes. Alloy counters rose by 32,721 allocations
and 9,234,856 allocated bytes, for a directional combined total of 2,307,711
calls and 296,611,891 bytes. Rust libc probes and Go runtime/counter data have
different semantics, and profile output volumes differed, so the cross-runtime
totals are diagnostic only.

The first candidate probe setup timed out while installing `bpftrace` and
performed no measurement; that failed setup artifact was preserved. Successful
probes emitted their totals but also logged tracefs uprobe-detach warnings
because `/sys/kernel/tracing/uprobe_events` was absent. Probe pods were removed.

## Source And Bundle Size

The baseline amd64 release binary was 18,455,144 bytes and the final binary was
18,453,448 bytes, 1,696 bytes smaller. The local image size fell from
38,029,052 to 38,028,049 bytes, 1,003 bytes smaller. The request-fingerprint
release path is one line shorter; total source grows by test-only procfs read
instrumentation and the regression assertion. No compile-time or incremental
target-directory size claim is made.

## Tradeoffs And Non-Claims

- Observation context remains connection-scoped, matching the existing stream
  lifetime. A process whose cgroup attribution changes without a new connection
  keeps the original source-time context for that stream, as it did before.
- Insert-first dedupe can temporarily hold one entry above the configured bound
  between the successful insert and synchronous eviction inside one locked
  call. The bound is restored before the function returns and no await or
  external observation occurs in between. A rejected duplicate also creates a
  temporary `Arc`; the permanent duplicate-path benchmark showed no timing
  regression, but this allocation is a retained tradeoff.
- Local OrbStack perf and whole-agent numbers are directional. The homelab has
  only two nodes and three repetitions per arm. Neither proves universal kernel,
  workload, production, or cloud-node behavior.
- The allocation comparison is not normalized by equivalent profile sample
  work and is not an acceptance result.
- This campaign preserves E-Navigator's existing documented capability and
  boundary contract. It does not prove strict Guara production replacement or
  unsupported kernel/runtime coverage.

## Remaining Bottlenecks

- SipHash and fingerprint construction in request correlation remain the
  largest named userspace hot path.
- Attribute materialization still allocates and copies through parser vectors,
  ordered maps, and OTLP prost values; sensitive-key scans and allocator work
  remain visible.
- Protocol span formatting still incurs ordered-map insertion and string work.
- Tokio wake/scheduling paths and exporter batching remain visible below the
  individual hashing and allocation costs.
- Fast gzip compression is still measurable, though below 1% in this profile.
- Beating the reference CPU mean requires about 13.884 millicores, or 14.812%
  of final E-Navigator CPU, under this exact final workload. No remaining small
  candidate found in this profile safely closes that gap alone.

## Validation And Cleanup

`scripts/quality.sh` passed with no skip variables on the final tree. It covered
formatting, documentation and release checks, strict Clippy, rustdoc warnings,
workspace tests, builds, fuzz checks, repository guards, supply-chain checks,
the container build and smoke, Helm lint and rendering, strict Kubernetes
schema validation, website checks, and diff hygiene.

The final homelab runner restored `root-app` and `e-navigator` to automated
prune plus self-heal, Synced and Healthy. The standing `e-navigator-agent`
DaemonSet returned 2/2 Ready and Available on its original image digest
`ghcr.io/guaracloud/e-navigator@sha256:62402d21b9cb02d59d63365c7e3716ffa0980bfea42d070b43fed618703a7df9`.
No disposable namespaced or cluster-scoped benchmark resources remained. The
temporary privileged image-loader DaemonSet and both node-local image tar files
were deleted after the final image was imported. The imported local benchmark
image remains in node containerd; it was not deployed as the standing agent.

Raw arm, Prometheus, workload, perf, allocation, and local A/B evidence remains
local under ignored `benchmarks/results/optimization6-*` directories.
[`summary.json`](summary.json) is the compact machine-readable result.
