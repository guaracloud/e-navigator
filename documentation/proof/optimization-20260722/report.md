# Evidence-Driven Optimization Campaign

Date: 2026-07-22

Evidence integrity: PASS.

Dual CPU and memory objective: NO-GO.

The optimized E-Navigator candidate used 28.066163% more agent CPU and
64.079030% less agent RSS than pinned Beyla plus Alloy in the corrected final
cumulative arm. The campaign therefore proves a scoped memory advantage but
does not meet the objective of beating the comparison stack on both CPU and
memory. All retained changes preserved the measured signal contract and every
hard-loss gate remained zero.

## Isolation Correction

The earlier `head-to-head-20260722` capture is invalid for comparative claims.
It suspended automation on the child `e-navigator` Argo CD application but
left the automated `root-app` parent able to restore the child and recreate the
standing E-Navigator DaemonSet during benchmark arms.

The corrected harness used here:

- captured both applications and the standing DaemonSet before mutation;
- suspended automation on `root-app` and `e-navigator`;
- deleted the standing `e-navigator-agent` DaemonSet;
- waited ten seconds and asserted the standing DaemonSet remained absent;
- repeated the application and DaemonSet absence assertion before and after
  every benchmark arm;
- restored the exact parent and child automation policy on every exit path;
- waited for both applications to become Synced and Healthy and for the
  standing DaemonSet to return 2/2 Ready.

All 67 isolation assertions, one initial plus two for each of 33 arms, passed
with empty evidence files. The final standing image was the original digest,
`sha256:62402d21b9cb02d59d63365c7e3716ffa0980bfea42d070b43fed618703a7df9`.

## Inputs And Environment

- Source base: `3e60321f74fbd9c9e6d394d7e86d8a5f17c936e0`.
- Frozen runtime and harness patch hash:
  `174fca358dbb3328f7b168d9f6a4fc3f6923ac8a46343269a01395f093339a36`.
- Candidate image: local-only
  `docker.io/library/e-navigator:opt-final5-amd64`, local digest
  `sha256:09dbb50f309d34431572a57f4dfdaaf7161d8cd3b8024b263642b00041688bb9`,
  observed containerd runtime image ID
  `sha256:cc1a3a6921e518c0cdca6d57bec92c77615a71d310e07694ec518dd8723d1e6b`.
- Candidate OCI archive: 37,397,504 bytes, SHA-256
  `d3b6db3ade19c4f14adcc90b779e3f65f0b1b8d5f86b397cd5cbfde033435ac4`.
- Workload image: local-only
  `docker.io/library/e-navigator-head-to-head:opt-campaign-amd64`, local digest
  `sha256:b8d60b8d7bdc48fefb449220ccd91518c9f89b5888d2940b9dfa3ad7bb485182`,
  observed containerd runtime image ID
  `sha256:ec413d0edc90d2ce1e1201be68ad3cca9de1d7ab0f01d56b36f6f28ed5835f96`.
- Beyla: 3.28.0 at image digest
  `sha256:133b8d66190f21e20365d9972e1621513ea5e44518fb71e1c3e0180c64815566`,
  Helm chart 1.16.10 at pinned archive checksum.
- Alloy: 1.18.0 at image digest
  `sha256:491b0578c04983fd54fe99b587b6fab4404dc46d0dc16677bd6b00cc1140b308`.
- Cluster: exactly `homelab`, k3s `v1.30.4+k3s1`, two amd64 NixOS 24.05
  nodes, Linux 6.6.68, containerd `1.7.20-k3s1`.
- Placement: services and collectors on `homelab-02`; load generator and
  opaque OTLP sink on `homelab-01`.
- Candidate and workload images were loaded directly into both node-local
  containerd stores and were never pushed.

## Reproducible Method

Every arm kept all five workloads active at fixed offered rates: HTTP at 100
requests/s, gRPC at 80 calls/s, Redis at 160 operations/s, PostgreSQL at 50
operations/s, and CPU-bound Python at 8 operations/s. Each arm used a
15-second warmup and a 45-second measured interval.

The 33-run matrix contained three no-agent controls and three repetitions of
each cumulative stage for each stack: HTTP, plus gRPC, plus Redis, plus
PostgreSQL, then plus 10 Hz CPU profiles. Collector order was counterbalanced.
The final comparison sums Beyla and Alloy resources and compares that split
stack with the single E-Navigator process.

Prometheus used the same late 30-second interval and a 60-second CPU rate
window for every arm. Agent memory is container RSS. Throughput is a fixed-rate
pacing and correctness check, not a saturation-capacity result. Node series
were recorded but are shared-node container totals, not causal agent overhead.

## Final Resource Result

Values are mean plus or minus sample standard deviation across three runs.
CPU is millicores and memory is MiB of RSS.

| Cumulative stage | Beyla or Beyla plus Alloy CPU | E-Navigator CPU | Beyla or Beyla plus Alloy RSS | E-Navigator RSS |
| --- | ---: | ---: | ---: | ---: |
| HTTP | 27.898294 +/- 1.867604 | 32.438155 +/- 2.089083 | 25.511719 +/- 0.637046 | 11.029948 +/- 0.030033 |
| plus gRPC | 34.747475 +/- 1.151602 | 63.770120 +/- 4.082139 | 27.834201 +/- 2.137823 | 18.043837 +/- 0.178021 |
| plus Redis | 41.558824 +/- 0.831611 | 69.372705 +/- 3.991127 | 25.292101 +/- 0.222520 | 18.467882 +/- 0.293435 |
| plus PostgreSQL | 45.508600 +/- 1.363484 | 91.127337 +/- 4.422200 | 24.538628 +/- 1.201238 | 21.107639 +/- 0.175063 |
| plus profiles | 75.859599 +/- 6.058294 | 97.150478 +/- 4.096372 | 128.862413 +/- 7.335634 | 46.288628 +/- 2.594171 |

The final absolute differences were +21.290879 millicores and -82.573785 MiB
for E-Navigator. Relative to Beyla plus Alloy, those are +28.066163% CPU and
-64.079030% RSS.

The cumulative stage shape matters. E-Navigator used less RSS at every stage.
Its PostgreSQL stage remained the largest CPU separation. Adding profiling to
the PostgreSQL stage cost E-Navigator 6.023141 millicores while adding Alloy to
Beyla cost 30.350999 millicores. The final CPU deficit is therefore primarily
in protocol capture, correlation, formatting, and export rather than the
optimized profile path.

## Throughput And Latency

All 197,010 warmup and 591,030 measured operations succeeded with zero
workload errors. Values below are final-stack means plus or minus sample
standard deviation. Latencies are microseconds.

| Family | Condition | Throughput/s | p50 | p95 | p99 |
| --- | --- | ---: | ---: | ---: | ---: |
| HTTP | no agent | 100.010226 +/- 0.000591 | 1767.000 +/- 13.115 | 6088.000 +/- 353.467 | 6916.000 +/- 35.000 |
| HTTP | Beyla plus Alloy | 100.010123 +/- 0.001114 | 1817.000 +/- 6.000 | 6347.667 +/- 178.262 | 6993.667 +/- 34.948 |
| HTTP | E-Navigator | 100.009620 +/- 0.000785 | 1838.000 +/- 12.166 | 6253.667 +/- 287.243 | 6999.000 +/- 10.440 |
| gRPC | no agent | 80.008181 +/- 0.000473 | 2797.333 +/- 24.947 | 3770.000 +/- 154.522 | 5249.000 +/- 164.794 |
| gRPC | Beyla plus Alloy | 80.008098 +/- 0.000891 | 2937.000 +/- 11.533 | 4078.333 +/- 36.295 | 5333.667 +/- 167.936 |
| gRPC | E-Navigator | 80.007696 +/- 0.000628 | 2977.333 +/- 20.033 | 4470.000 +/- 161.391 | 5798.000 +/- 153.873 |
| Redis | no agent | 160.016361 +/- 0.000946 | 954.667 +/- 7.095 | 1586.000 +/- 64.954 | 2447.333 +/- 228.354 |
| Redis | Beyla plus Alloy | 160.016196 +/- 0.001782 | 1076.000 +/- 13.000 | 1883.667 +/- 15.503 | 2888.667 +/- 15.011 |
| Redis | E-Navigator | 160.015392 +/- 0.001256 | 1041.333 +/- 5.033 | 2006.667 +/- 55.967 | 3071.667 +/- 117.458 |
| PostgreSQL | no agent | 50.005113 +/- 0.000296 | 1092.667 +/- 40.857 | 1972.000 +/- 155.242 | 3481.333 +/- 254.129 |
| PostgreSQL | Beyla plus Alloy | 50.005061 +/- 0.000557 | 1196.000 +/- 36.014 | 2351.667 +/- 21.962 | 3961.667 +/- 177.858 |
| PostgreSQL | E-Navigator | 50.004810 +/- 0.000393 | 1395.333 +/- 48.881 | 2665.000 +/- 117.320 | 3985.667 +/- 36.364 |
| Python CPU | no agent | 8.000818 +/- 0.000047 | 30110.000 +/- 157.617 | 43970.333 +/- 932.543 | 49783.333 +/- 2517.339 |
| Python CPU | Beyla plus Alloy | 8.000810 +/- 0.000089 | 30410.000 +/- 78.886 | 44094.667 +/- 4039.664 | 51954.333 +/- 1701.497 |
| Python CPU | E-Navigator | 8.000770 +/- 0.000063 | 31155.000 +/- 93.920 | 41493.000 +/- 3302.583 | 52031.000 +/- 1959.936 |

E-Navigator versus Beyla plus Alloy final-stack throughput changed by
-0.000503% for each family because every family shares the same measured
interval. Descriptive p99 changes ranged from +0.076259% for HTTP to
+8.705706% for gRPC. Three shared-cluster repetitions do not support a
statistical or universal latency claim.

## Signal Completeness

The three final E-Navigator arms decoded 110,830 source samples and sent 69,482
source signals. Hard loss was zero across invalid samples, userspace send
failures, perf and transport loss, RingBuf reservation failures, profile
capture and state loss, source failures, bounded export queue drops, failed
batches, rejected items, permanent responses, and invalid records.

Asynchronous before and after scrapes recorded 68,621 traces enqueued and
68,624 sent, plus 860 profiles enqueued and 861 sent. These small reversed
differences are scrape-boundary effects across independent counters, not loss.

Beyla accounted for all 18,000 HTTP, 28,800 Redis, and 9,000 PostgreSQL
operations in the three final arms. It left 26 of 14,400 gRPC calls
unaccounted, or 0.180556%. Alloy collected and forwarded 38 profiles with zero
drops and zero failing sessions. These differences remain explicit and do not
change the zero-error workload result.

## Retained Improvements

Each implementation candidate was bounded, tested, and measured before being
retained.

| Change | Measurement | Decision |
| --- | --- | --- |
| Parse unwind rows to the actual kernel row budget and refresh only recently sampled PIDs through a bounded recency tracker | An isolated diagnostic moved from 167.071034 to 151.203696 millicores and from 174.787760 to 50.209635 MiB RSS. Signal volume differed, so CPU is directional; the 71.273941% RSS reduction and bounded-cache tests are the stronger evidence | retained |
| Replace ordered deduplication plus deep queue clones with randomized `HashSet<Arc<T>>` and bounded insertion order | 8,192-entry unique churn improved by 7.3448% in the saved Criterion comparison | retained |
| Drain and move protobuf export batches, restoring failures in original order, and remove `Clone` bounds | Non-clone success, encode-failure, permanent-failure, retry, and order tests pass; aggregate allocator calls fell in the final binary | retained |
| Use gzip level 1 for short-lived OTLP buffers | Same-run 512 KiB Criterion means were 444.83 microseconds at the default level and 95.994 microseconds at level 1, a 78.420071% reduction | retained with payload-size tradeoff |
| Enable thin LTO and one release codegen unit | Two paired diagnostics improved CPU per decoded sample 10.414687% and CPU per sent signal 5.857104%; the release binary shrank from 19,440,560 to 15,802,424 bytes, or 18.714152% | retained with build-time tradeoff |
| Remove lowercase-string allocations from sensitive and reserved attribute checks | Saved Criterion point estimate improved 15.396% while mixed-case security tests preserved filtering | retained |
| Centralize profile-key filtering and expand trace security coverage | Mixed-case authorization and existing secret-key tests pass | retained |
| Stream generated identity formatting directly into the digest | CPU per decoded sample regressed 2.292453% and CPU per sent signal regressed 2.600975% | rejected and fully reverted |

The synthetic 512 KiB gzip fixture grew from 1,877 to 3,694 bytes at level 1,
or 96.803410%. In the first matched live candidate the opaque OTLP sink moved
from 43.701718 to 51.039360 compressed trace bytes per trace, or 16.790281%.
The final proof measured 51.071394 bytes per trace. This is an explicit
CPU-for-bandwidth tradeoff.

## Allocation Evidence

Allocator profiling used a digest-pinned Debian amd64 diagnostic Pod,
bpftrace 0.17.0, host PID visibility, and exactly 45 seconds inside a
20-second warmup plus 90-second workload run. The profiler overhead is excluded
from CPU and RSS claims. E-Navigator counts are requested sizes at libc
`malloc`, `calloc`, `realloc`, `posix_memalign`, and `aligned_alloc` entry
points.

| E-Navigator build | Calls | Requested bytes |
| --- | ---: | ---: |
| clean baseline | 8,509,242 | 925,090,490 |
| optimized final | 5,644,163 | 692,293,775 |
| change | -33.670202% | -25.164751% |

The comparison stack used the same workload window. Beyla's Go
`runtime.mallocgc` probe recorded 2,286,778 calls and 279,494,510 requested
bytes. Alloy runtime counter deltas recorded 31,716 allocations and 9,664,680
bytes. Combined, they recorded 2,318,494 calls and 289,159,190 bytes.
E-Navigator remained 143.440915% higher in calls and 139.416141% higher in
bytes.

This cross-runtime result is descriptive, not a strict allocator equivalence:
the Rust process is measured at libc request entry points, Beyla at a Go
runtime allocation function, and Alloy through Go runtime counters. It is
still sufficient to reject an allocation-efficiency win and to identify the
next optimization target.

## CPU Profiles And Remaining Bottlenecks

The pre-optimization 90-second DWARF profile captured 1,000-plus user-space
cycle samples with zero loss. Its leading self costs included gzip at 9.74%,
malloc at 5.23%, HTTP request reassembly at 2.84%, and free at 2.79%.

The final 60-second 199 Hz profile captured 2,366 user-space cycle samples and
9,775,535,530 approximate event cycles with zero lost samples. Its leading
self costs by symbol were:

- malloc, 5.76%;
- free, 2.78%;
- Aya HTTP source handling, 2.96%;
- gzip compression, 2.17%;
- `BTreeMap::insert`, 2.06%;
- cgroup scanning, 1.22%;
- trace attribute formatting, 1.22%;
- request-correlation output generation, 1.18%;
- SipHash writes, 1.24%;
- generated trace identity, 0.73%.

The profiles use different call-graph modes and durations, so their percentages
are diagnostic rather than a direct statistical A/B. They agree with the
allocation and stage data: the next work should target protocol-event object
construction, resource and peer attribute maps, identity formatting, procfs
symbol formatting, and repeated cgroup traversal. Gzip is materially smaller
but remains visible.

## Tradeoffs And Non-Claims

- Thin LTO and one codegen unit increase release build and link time.
- Gzip level 1 increases compressed bytes in exchange for lower CPU.
- Randomized hashing removes deterministic internal ordering, but no public
  ordering contract exists and insertion-order eviction remains explicit.
- Recently sampled PID tracking can emit initial frame-pointer fallback
  samples before a new PID's unwind table is installed. Membership changes
  wake the refresh loop, and all tables and caches remain bounded.
- The parsed-module cache has no eviction policy. On a long-running node with
  enough binary churn to fill its bounded row budget, newly seen modules fall
  back to frame-pointer unwinding until restart. Bounded cache turnover is a
  follow-up rather than an unmeasured change to this campaign's proven image.
- Allocation diagnostics are not directly comparable across language runtime
  allocation layers and do not contribute CPU or RSS evidence.
- Fixed offered rates do not establish saturation throughput.
- Three repetitions on one shared cluster do not prove production behavior,
  long-duration stability, statistical superiority, or universal latency.

## Validation And Cleanup

Focused unit and integration tests cover bounded unwind parsing and row pools,
recency eviction, non-clone export success and failure restoration, mixed-case
secret filtering, request-correlation behavior, gzip transport, and harness
guards. `scripts/quality.sh` passed with no skip variables and no skipped
gates, including formatting, clippy, tests, release builds, supply-chain
checks, Docker smoke, Kubernetes schema validation, website checks, and diff
hygiene.

All benchmark Deployments, DaemonSets, Jobs, Services, ConfigMaps, RBAC,
profiler Pods, and cluster-scoped resources were removed. All seven campaign
image references were removed from both homelab containerd stores and local
Docker. `root-app` and `e-navigator` returned to automated prune plus self-heal,
Synced and Healthy. The standing DaemonSet returned 2/2 Ready at its original
digest. No production context was touched, and no code or image was pushed or
deployed persistently.

[`summary.json`](summary.json) is the machine-readable result. `SHA256SUMS`
covers every curated artifact in this directory except itself. The full raw
arm, Prometheus, workload, allocator, perf, image, and cleanup capture remains
local under ignored `benchmarks/results/optimization-*` directories.
