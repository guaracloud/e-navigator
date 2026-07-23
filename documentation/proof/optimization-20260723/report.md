# Evidence-Driven Optimization Campaign

Date: 2026-07-23

Status: **NO-GO**. The candidate reduced RSS and allocator activity, but
increased whole-agent CPU. No production optimization from this pass is
retained. The cgroup regression benchmark, its path-boundary test, and this
negative result are retained.

The campaign started from the clean `v0.2.0-rc.2` tree at
`c1cb84b3bf7cb266aee44dae6c6dd54be5fcdbcb`. No image or code was pushed. The
homelab work used only temporary benchmark resources and locally imported
images.

## Evidence Boundary

The 2026-07-22 campaign was invalidated because its Redis connection existed
before collector attachment. None of its comparative results are reused here.
The corrected workload establishes every protocol connection after attachment
and enforces independent HTTP, gRPC, Redis, PostgreSQL, and profile signal
floors:

- [invalidated campaign erratum](../optimization-20260722/ERRATUM.md)
- [corrected workload contract](../optimization-20260722-campaign2/report.md)

This report contains two corrected 33-arm CPU, RSS, throughput, and latency
campaigns plus three allocator diagnostic arms. Both 33-arm analyzers returned
`PASS`; that result means the evidence and correctness gates passed, not that
E-Navigator met the optimization objective.

## Profile-First Routing

The latest qualified 60-second, 199 Hz Linux perf capture guided candidate
selection. It recorded 2,366 user-space cycle samples, zero lost samples, and
9,775,535,530 approximate event cycles. Leading self costs included:

- `malloc`, 5.76%;
- Aya HTTP source handling, 2.96%;
- `free`, 2.78%;
- gzip compression, 2.17%;
- `BTreeMap::insert`, 2.06%;
- SipHash writes, 1.24%;
- cgroup scanning, 1.22%;
- trace attribute formatting, 1.22%;
- request-correlation output generation, 1.18%;
- generated trace identity, 0.73%.

The profile is diagnostic routing evidence. The corrected campaign resource
queries below are the qualification evidence.

## Reproducible Inputs And Method

- Kubernetes: k3s v1.30.4 on two amd64 nodes, Linux 6.6.68.
- Placement: load generator on `homelab-01`; servers and collectors on
  `homelab-02`.
- Beyla: chart 1.16.10, image
  `docker.io/grafana/beyla@sha256:133b8d66190f21e20365d9972e1621513ea5e44518fb71e1c3e0180c64815566`.
- Alloy:
  `docker.io/grafana/alloy@sha256:491b0578c04983fd54fe99b587b6fab4404dc46d0dc16677bd6b00cc1140b308`.
- Baseline E-Navigator OCI archive SHA-256:
  `ca555ebac6036f66dcad7503311a74368683f8f5a9a40a1355fefb55a703cb46`.
  Runtime image ID:
  `sha256:ce8427d1ede03369f260c73e1cd2c875710c4de2f442fae7667c489cdd0a77b6`.
- Candidate E-Navigator OCI archive SHA-256:
  `37fe100e11e5409b3d40e6f28473f3b13f06c567aa01e7e5cf71a5625f6b044d`.
  Runtime image ID:
  `sha256:deb113611d29a1f4cc92556700097b6152a07c217c3a4e6998b1e875392f612d`.
- Corrected workload OCI archive SHA-256:
  `4c4b7ee1039e521b6315e63a0bc78ea5209d062d904779dc80d4a73fcc2a4957`.
  Runtime image ID:
  `sha256:ca166b018d3ce9e9c152055a323f90deb444b0bcd092800426d3b4472416563d`.

Each resource campaign used three counterbalanced repetitions of no-agent
control, E-Navigator, and Beyla stages. Stages accumulated HTTP, gRPC, Redis,
PostgreSQL, and profiling. Each arm used 15 seconds of warmup, 45 seconds of
measurement, and 20 seconds of collector settling. Offered rates were 100,
80, 160, 50, and 8 operations per second respectively.

Across the two campaigns, 394,020 warmup operations and 1,182,060 measured
operations succeeded with zero workload errors. Every one of the 66 arms
passed its independent topology, image identity, workload, signal floor, loss,
export, and resource-evidence checks.

## CPU And RSS

Values are final-stack means across three repetitions. Standard deviations are
shown in parentheses.

| Build | E-Navigator CPU | Beyla plus Alloy CPU | E-Navigator change | E-Navigator RSS | Beyla plus Alloy RSS | E-Navigator change |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| clean baseline | 146.499057m (5.007203m) | 81.234226m (7.542902m) | +80.341543% | 48.546007 MiB (0.719213) | 127.893229 MiB (3.629639) | -62.041769% |
| candidate | 153.003940m (8.908932m) | 74.252625m (3.584579m) | +106.058628% | 47.101128 MiB (2.824644) | 137.662760 MiB (12.633772) | -65.785134% |

Directly comparing E-Navigator candidate with clean baseline:

- CPU increased **4.440222%**.
- RSS decreased **2.976308%**.

The dual objective therefore fails. E-Navigator remained much smaller in
memory but did not beat the combined competitor CPU footprint.

The cumulative E-Navigator stage means show where the CPU gap appears:

| Stage | Baseline CPU | Candidate CPU | Change | Baseline RSS | Candidate RSS | Change |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| HTTP | 30.571586m | 29.134726m | -4.699985% | 10.891493 MiB | 11.017795 MiB | +1.159640% |
| gRPC | 61.200565m | 63.152277m | +3.189042% | 18.029514 MiB | 17.871962 MiB | -0.873857% |
| Redis | 113.968665m | 118.997954m | +4.412870% | 20.262153 MiB | 20.368056 MiB | +0.522663% |
| PostgreSQL | 133.375952m | 133.006575m | -0.276944% | 22.356337 MiB | 22.320313 MiB | -0.161137% |
| Profile | 146.499057m | 153.003940m | +4.440222% | 48.546007 MiB | 47.101128 MiB | -2.976308% |

The comparison stack drifted between campaigns, including -8.594408% CPU and
+7.638818% RSS in the final stack. The direct E-Navigator result is therefore
the safer candidate qualification. Three shared-cluster repetitions support a
descriptive NO-GO, not a universal production estimate.

## Throughput And Latency

The table compares the E-Navigator final-stack means. Throughput is operations
per second and latency is microseconds.

| Family | Baseline throughput | Candidate throughput | Change | Baseline p50/p95/p99 | Candidate p50/p95/p99 | p50/p95/p99 change |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| HTTP | 100.010229995 | 100.009956594 | -0.000273% | 1832.000/6461.333/7010.333 | 1845.000/6462.333/7030.667 | +0.709607%/+0.015477%/+0.290048% |
| gRPC | 80.008183996 | 80.007965275 | -0.000273% | 3051.333/4368.667/5792.000 | 3045.333/4545.667/6414.000 | -0.196635%/+4.051579%/+10.738950% |
| Redis | 160.016367991 | 160.015930550 | -0.000273% | 1151.333/2035.000/3011.667 | 1144.333/2173.333/3593.667 | -0.607991%/+6.797707%/+19.324848% |
| PostgreSQL | 50.005114997 | 50.004978297 | -0.000273% | 1353.000/2483.000/3750.000 | 1368.333/2729.000/4148.333 | +1.133284%/+9.907370%/+10.622222% |
| Python CPU | 8.000818400 | 8.000796528 | -0.000273% | 31454.333/38968.667/53074.000 | 31247.000/45552.000/53158.667 | -0.659157%/+16.893915%/+0.159526% |

Fixed offered rates explain the effectively unchanged throughput. They do not
establish saturation throughput. The tail-latency movements are noisy and
descriptive, but they provide no evidence that the CPU regression purchased a
consistent latency benefit.

## Allocation Evidence

Allocation diagnostics used the same full protocol-plus-profile workload with
20 seconds of warmup and 90 seconds of measurement. bpftrace 0.17.0 observed
one 45-second window wholly inside the measured phase. Each diagnostic arm
completed 35,820 measured operations with zero errors and passed the same
signal checks.

| Build or stack | Measurement layer | Calls | Requested bytes |
| --- | --- | ---: | ---: |
| clean E-Navigator | libc allocation entry points | 6,470,010 | 845,112,415 |
| candidate E-Navigator | libc allocation entry points | 6,279,534 | 794,275,038 |
| candidate change | same layer | -2.943983% | -6.015457% |
| Beyla | Go `runtime.mallocgc` | 2,299,714 | 291,742,377 |
| Alloy | Go runtime counter delta | 25,198 | 8,093,880 |
| Beyla plus Alloy | combined directional reference | 2,324,912 | 299,836,257 |

The clean baseline exceeded the combined directional reference by 178.290533%
in calls and 181.857979% in requested bytes. The candidate still exceeded it
by 170.097707% and 164.902933%.

These layers are not strict allocator equivalents: Rust is measured at libc
request entry points, Beyla at a Go runtime function, and Alloy through Go
runtime counters. The result is useful for direction and bottleneck ranking,
not a language-runtime efficiency theorem. One allocator window per build
also does not support a variance estimate.

## Correctness And Signal Completeness

The final three clean E-Navigator arms decoded 170,547 source samples and sent
99,595 source signals. They enqueued and sent 98,061 traces and 1,533 profiles,
with zero hard loss.

The final three candidate arms decoded 170,855 source samples and sent 99,924
source signals. They enqueued 98,045 traces, sent 98,038 traces, and enqueued
and sent 1,876 profiles, with zero hard loss. The seven-trace difference is an
asynchronous scrape-boundary observation across independent counters, not a
reported drop.

In the clean comparison arms, Beyla accounted for all 18,000 HTTP and 9,000
PostgreSQL operations, 14,384 of 14,400 gRPC operations, and 29,118 Redis
observations for 28,800 operations. Alloy collected and forwarded 35 profiles
with zero drops and zero failing sessions. Candidate-campaign comparison arms
showed the same acceptance outcome.

Focused generator, sink, and Aya source tests passed 521 tests before the
homelab run. The final-tree `scripts/quality.sh` gate passed with no skip
variables and no skipped gates. It covered formatting, documentation and
release checks, strict Clippy, rustdoc warnings, workspace tests, builds, fuzz
checks, configuration and synthetic execution, repository guards,
supply-chain checks, the container build and runtime smoke, Helm lint and
rendering, strict Kubernetes schema validation, website links, and diff
hygiene.

## Candidate Decisions

| Candidate | Local evidence | Whole-agent decision |
| --- | --- | --- |
| Preallocate bounded request-correlation outputs | Criterion improved 13.807% and 10.210% | reverted with candidate bundle |
| Select static client/server OTLP attribute keys | Criterion improved 3.001% and 9.098% | reverted with candidate bundle |
| Borrow cgroup scan paths and defer metadata | controlled Criterion midpoint regressed 25.348%, CI +18.079% to +32.022%, `p = 0.00` | rejected before homelab image |

The first two changes preserved tests and reduced local microbenchmark time,
but the qualified bundle increased whole-agent CPU. Retaining them would
violate the campaign rule to keep only proven product-level improvements.

The cgroup experiment was fully reverted. Its
`capture_filter/cgroup_tree_scan_150pods` benchmark remains as a regression
target. The fixture contains 150 pod cgroups, 150 container leaves, 150
unrelated host cgroups, and four hierarchy roots, and asserts 300 observations.
A direct-child `pod<uid>` test preserves the path-boundary behavior exposed by
the experiment.

## Remaining Bottlenecks

- Protocol capture and correlation remain the dominant stage gap, especially
  Redis and PostgreSQL cumulative CPU.
- Allocation count and requested bytes remain materially above the directional
  combined reference.
- Aya HTTP event construction, attribution copies, `BTreeMap` insertion, trace
  key ownership, identity hashing, and allocator/free paths remain the clearest
  narrow targets.
- Repeated bounded cgroup traversal remains visible, but the obvious path and
  metadata shortcut was slower under controlled measurement.
- Gzip is smaller than in earlier profiles but remains visible.

Future work should isolate one of these paths, require a stable same-session
benchmark win, then repeat the corrected whole-agent campaign before retaining
production code.

## Cleanup And Non-Claims

All benchmark collectors, workloads, RBAC, allocation probes, and image-loader
resources were removed. The three campaign image references were removed from
both node containerd stores. `root-app` and `e-navigator` returned to automated
prune plus self-heal, Synced and Healthy. The standing agent returned 2/2 Ready
at its original digest.

No code or image was pushed. No release was created. No persistent deployment
was performed. Three repetitions, fixed rates, and one shared cluster do not
prove production behavior, saturation throughput, or statistical superiority.

The raw arm, Prometheus, workload, allocator, image, and cleanup evidence
remains local under ignored `benchmarks/results/optimization3-*` directories.
[`summary.json`](summary.json) is the curated machine-readable result.
