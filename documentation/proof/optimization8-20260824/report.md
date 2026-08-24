# Evidence-Driven Optimization Campaign 8

Date: 2026-08-24

Status: **RETAINED FOCUSED WINS, OVERALL CPU NO-GO**. Two small OTLP trace
export changes have direct profile support and statistically significant
focused wins. The fresh 33-arm homelab campaign, however, measured
E-Navigator at 15.545410% more CPU than combined Beyla plus Alloy. E-Navigator
used 6.379006% less RSS, which is useful but does not satisfy the requested
CPU-and-memory replacement target.

Nothing was pushed or persistently deployed. The candidate image was loaded
only into both node-local containerd stores for the temporary campaign. The
harness restored the standing deployment, its original image, and Argo CD
automation after every run.

## Profile-First Scope

The local baseline was commit `2f8c5fc394dcd6f5127404404d52be2663dd4a59`
under Redis at 800 operations/second, with 8 seconds warmup, 5 seconds
attachment settle, and 45 seconds measured time. `perf record` sampled at
997 Hz and captured 1,809 samples with zero lost samples.

Selected self-overhead from that profile was:

| Symbol or stack | Baseline overhead |
| --- | ---: |
| SipHash write, primarily request/warning fingerprints | 3.21% |
| Sensitive attribute-key matching | 2.93% |
| Kernel/Tokio wake-up path | 2.71% |
| `malloc` | 2.49% |
| `cfree` | 1.99% |
| OTLP `hex_to_bytes` | 1.82% |
| `key_values` vector growth through `realloc` | 0.83% |

The trace-ID samples split between required protobuf conversion (0.94%) and
the duplicate enqueue-time validation (0.77%). A separate profile after the
attribute-capacity change no longer contained the `key_values`
`RawVec::reserve` growth stack. Those short profiles are directional:
separate sample sets are useful for locating work, not a statistical A/B.

## Retained Changes

The OTLP attribute materializer now reserves `attributes.len()` entries before
the bounded conversion loop. That is an exact upper bound, remains bounded by
the existing record contracts, and avoids vector growth without changing key
filtering or value conversion.

The sink also stopped decoding trace and span identifiers a second time before
enqueue. `format_otel_trace_record` already validates both identifiers as one
unit, rejects zero or malformed values, and normalizes accepted hexadecimal
text. The enqueue gate now checks that both normalized identifiers are
present. The protobuf encoder still validates and converts public
`OtelTraceRecord` values defensively, so its standalone contract did not
weaken.

This deletes the duplicate validator and its temporary byte vectors from the
runtime path. Regression coverage now verifies all-zero trace and span IDs by
encoding and decoding the protobuf request, covers mixed-case and malformed
decoder inputs, retains the sink telemetry test for declared invalid identity,
and permanently benchmarks a representative protocol-error trace payload.

## Focused Before And After

Criterion used 100 samples. The identity-gate experiment measured the exact
old decode gate and the replacement presence gate, then removed that
overly narrow temporary benchmark. The complete trace-payload benchmark is
permanent.

| Benchmark | Before mean (95% CI) | After mean (95% CI) | Change |
| --- | ---: | ---: | ---: |
| Trace identity enqueue gate | 53.790255 ns (52.930536-54.671921) | 0.384209 ns (0.379494-0.389931) | -99.285728%; 95% change interval -99.301348% to -99.270858%; `p = 0` |
| Complete OTLP protocol-error trace payload | 2.225948 us (2.191239-2.266175) | 2.042134 us (2.018230-2.068207) | -8.257775%; 95% change interval -10.205169% to -6.353444%; `p = 0` |

The complete benchmark exercises record grouping, resource and span
materialization, identifier conversion, attribute conversion, encoded-length
calculation, and protobuf encoding. It is the regression benchmark for the
retained allocation change.

Focused sink validation passed 174 tests: 111 crate unit tests, 34 OTEL trace
integration tests, and 29 profile-format tests.

## Local Whole-Agent Before And After

One clean, exact-binary pair completed 36,000 of 36,000 Redis operations per
arm with zero errors and decoded 84,834 protocol samples per arm.

| Metric | Baseline | Candidate | Change |
| --- | ---: | ---: | ---: |
| Agent CPU | 45.351025 mCPU | 42.103854 mCPU | -7.160083% |
| RSS | 47,696 KiB | 47,808 KiB | +0.234821% |
| RSS high-water mark | 50,488 KiB | 50,532 KiB | +0.087149% |
| Redis p50 | 250 us | 262 us | +4.800000% |
| Redis p95 | 908 us | 1,010 us | +11.233480% |
| Redis p99 | 2,147 us | 2,794 us | +30.135072% |

The baseline and candidate arm64 binary SHA-256 values were respectively
`b3514398d2aa42fff79b4458938fa533f836fe1067eb102963a793a6fd94e9fb`
and
`89c17247968f6d20eda74f42710b2cf81c59a385a6839f43aab9f04e709dc9bf`.

Three later arms were excluded rather than averaged: host-wide `fseventsd`,
an unrelated coverage job, `syspolicyd`, and OrbStack activity produced
41.243-117.116 mCPU observations that were not comparable. The accepted pair
is therefore directional corroboration only. Its latency variation is not
claimed as either a regression or a win.

## Fresh Homelab Comparison

The exact campaign command was:

```bash
env E_NAVIGATOR_HOMELAB_CONFIRM=1 \
  E_NAVIGATOR_HEAD_TO_HEAD_RESULTS_DIR=benchmarks/results/optimization8-final-20260824 \
  E_NAVIGATOR_HOMELAB_IMAGE_TAG=campaign8-final-amd64 \
  E_NAVIGATOR_HEAD_TO_HEAD_WORKLOAD_IMAGE=docker.io/library/e-navigator-head-to-head:opt6-amd64 \
  benchmarks/runner/homelab-head-to-head.sh
```

The campaign ran 33 of 33 validated arms without retry: three counterbalanced
repetitions of no collector, E-Navigator, and Beyla plus Alloy across cumulative
HTTP, gRPC, Redis, PostgreSQL, and Python CPU-profile stages. Each arm used
15 seconds warmup and 45 seconds measured time. All 591,030 measured and
197,010 warmup operations succeeded with zero workload errors.

The two nodes ran Linux 6.6.68, k3s v1.30.4, containerd 1.7.20-k3s1, and amd64.
Beyla chart 1.16.10 resolved to
`docker.io/grafana/beyla@sha256:133b8d66190f21e20365d9972e1621513ea5e44518fb71e1c3e0180c64815566`;
Alloy resolved to
`docker.io/grafana/alloy@sha256:491b0578c04983fd54fe99b587b6fab4404dc46d0dc16677bd6b00cc1140b308`.
The shared workload runtime image ID was
`sha256:d367537d6d186d755911f8039571ae8a0c23c7d7edf0ae61d161b03f59477b7d`.

| Stack | CPU mean | CPU stdev | CPU CV | RSS mean | RSS stdev | RSS CV |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| E-Navigator | 95.116412 mCPU | 2.878526 mCPU | 3.026319% | 128,231,196.444 bytes | 3,092,747.429 bytes | 2.411853% |
| Beyla plus Alloy | 82.319507 mCPU | 2.757120 mCPU | 3.349291% | 136,968,419.556 bytes | 2,596,461.380 bytes | 1.895664% |

E-Navigator therefore used 15.545410% more CPU and 6.379006% less RSS. The
requested example tradeoff (roughly 5-10% more CPU for 20-30% less memory) was
not reached: this run paid more CPU for a materially smaller memory advantage.

### Historical Campaign Delta

Campaign 7 is the closest prior identical-harness snapshot. It is not a
same-time code A/B, so the following table records drift rather than assigning
causality:

| Metric | Campaign 7 | Campaign 8 | Change |
| --- | ---: | ---: | ---: |
| E-Navigator CPU | 96.149058 mCPU | 95.116412 mCPU | -1.074005% |
| Beyla plus Alloy CPU | 76.440016 mCPU | 82.319507 mCPU | +7.691640% |
| E-Navigator CPU gap | +25.783671% | +15.545410% | -10.238261 percentage points |
| E-Navigator RSS | 122,683,392 bytes | 128,231,196.444 bytes | +4.522050% |
| Beyla plus Alloy RSS | 136,827,790.222 bytes | 136,968,419.556 bytes | +0.102778% |
| E-Navigator RSS gap | -10.337372% | -6.379006% | +3.958366 percentage points |

Most of the apparent CPU-gap closure came from reference-stack movement, while
E-Navigator's own CPU mean moved only 1.074005%, within the current campaign's
3.026319% coefficient of variation. The whole 10.238261-point closure is
therefore not attributed to this code.

### Throughput And Latency

Each cell is the three-arm mean shown as E-Navigator / Beyla plus Alloy. The
percentage is E-Navigator relative to the reference; negative latency is
faster.

| Family | Throughput rps | p50 us | p95 us | p99 us |
| --- | ---: | ---: | ---: | ---: |
| HTTP | 100.010583 / 100.010136 (+0.000447%) | 1,802.667 / 1,836.333 (-1.833364%) | 6,448.667 / 6,444.333 (+0.067243%) | 6,979.667 / 6,982.667 (-0.042964%) |
| gRPC | 80.008466 / 80.008109 (+0.000447%) | 2,908.667 / 2,952.333 (-1.479056%) | 4,353 / 4,177 (+4.213550%) | 6,296.333 / 5,848 (+7.666439%) |
| Redis | 160.016933 / 160.016218 (+0.000447%) | 1,065.667 / 1,132.333 (-5.887548%) | 1,961.667 / 2,030 (-3.366174%) | 3,386.667 / 3,398.667 (-0.353080%) |
| PostgreSQL | 50.005291 / 50.005068 (+0.000447%) | 1,150.333 / 1,236 (-6.930960%) | 2,281.333 / 2,408.667 (-5.286466%) | 4,303 / 3,945.667 (+9.056349%) |
| Python CPU | 8.000847 / 8.000811 (+0.000447%) | 30,708.667 / 30,265.667 (+1.463705%) | 47,340.333 / 41,193.333 (+14.922318%) | 52,161.333 / 52,367.667 (-0.394009%) |

Stable offered throughput and zero errors rule out dropped work as the
explanation for the resource result. The short shared-cluster sample does not
establish production latency superiority.

## Signal Completeness

Across the three E-Navigator profile arms, sources decoded 170,504 samples and
sent 99,920 signals. CPU profiling decoded and sent 1,451 samples. Exporters
enqueued 98,469 traces and sent 98,448, and enqueued 1,451 profiles and sent
1,450. The small sent/enqueued differences are asynchronous scrape-boundary
effects.

Hard loss was zero. Invalid trace records, source failures, queue-full drops,
worker-closed drops, retry/circuit/permanent failures, partial successes, and
rejected items were all zero in the gated arms.

## Allocation Diagnostics

Each diagnostic observed 45 seconds inside a separate 90-second profile arm.
The successful runs reported:

| Stack and probe | Allocation calls | Requested bytes |
| --- | ---: | ---: |
| E-Navigator libc uprobes | 6,638,208 | 969,877,909 |
| Beyla Go runtime | 2,284,366 | 288,486,536 |
| Alloy Go metric delta | 22,711 | 4,896,888 |
| Directional Beyla plus Alloy sum | 2,307,077 | 293,383,424 |

Relative to campaign 7, E-Navigator's diagnostic counters moved -3.542487% in
calls and -3.845093% in requested bytes. The directional reference moved
-0.658679% and -0.788661%, respectively. These are separate-run diagnostics,
not isolated code-effect estimates.

The totals are **not cross-runtime comparable**. E-Navigator uses six libc
uprobes, Beyla uses Go `runtime.mallocgc`, and Alloy contributes Go process
metrics. Their 187.732399% call and 230.583745% requested-byte directional gaps
are prioritization signals only.

The first reference attempt timed out after 300 seconds while installing
`bpftrace`, before the benchmark arm started. Its clean retry passed. Both
successful traces printed their counters before post-counter tracefs
`uprobe_events` detach warnings; probe pods were then deleted and the cleanup
gates passed.

## Size And Quality

| Artifact | Baseline | Candidate | Change |
| --- | ---: | ---: | ---: |
| arm64 release binary | 17,192,192 bytes | 17,192,184 bytes | -8 bytes |
| arm64 image | 37,498,764 bytes | 37,497,961 bytes | -803 bytes |
| amd64 release binary | 18,453,400 bytes | 18,452,528 bytes | -872 bytes |
| amd64 image | 38,028,204 bytes | 38,027,818 bytes | -386 bytes |

The final amd64 binary SHA-256 was
`b8ca8ab687a1228eff7a3f8f77f580f51b143566e50210e34ff028a05b30fdca`.
The local candidate image ID was
`sha256:57d277fa71555308119b331a343680a763a491ee301bdf8c49183f094bae680c`;
the homelab runtime resolved it to
`sha256:0f1540fd814b9c57f046fd746a9b59d5522bd59b07accd1aafab2b5857df8cc1`.
No compile-target-directory size claim is made.

`scripts/quality.sh` passed with no skip variables. It covered formatting,
documentation and release checks, strict Clippy, rustdoc warnings, workspace
tests and builds, fuzz and repository guards, supply-chain checks, Docker smoke
validation, Helm and Kubernetes schema validation, website checks, and diff
hygiene.

## Cleanup, Tradeoffs, And Remaining Work

Live verification after the final diagnostic found `root-app` and
`e-navigator` automated, Synced, and Healthy. The original signed standing
image
`ghcr.io/guaracloud/e-navigator@sha256:62402d21b9cb02d59d63365c7e3716ffa0980bfea42d070b43fed618703a7df9`
was back at 2/2 Ready. No disposable namespaced or cluster-scoped resources
remain. The privileged loader and node tar files were removed. Within the
homelab, the candidate image remains only in the two node-local image stores;
it was never selected by the standing DaemonSet.

The changes are retained because they remove duplicated work, preserve the
validation boundary, improve the complete focused payload by 8.257775%, and
slightly shrink both architectures. They do not reclassify replacement
readiness: CPU remains the binding NO-GO, and allocation diagnostics remain
well above the directional reference.

The next profile-driven opportunities are the required string-to-byte trace ID
conversion, OTLP record/map materialization, request-correlation hashing,
allocator traffic, and Tokio exporter wakeups. A binary trace-identity type
could eliminate normalization followed by re-decoding, but it changes a public
record boundary and should be attempted only with contract tests and a fresh
focused benchmark. Export batching or wakeup changes likewise require explicit
latency and loss gates.

Raw local, Criterion, homelab, allocation, Prometheus, and workload artifacts
remain ignored under `benchmarks/results/optimization8-*`,
`benchmarks/results/local-agent-ab/campaign8-*`, and `target/criterion/`.
The compact machine-readable record is [`summary.json`](summary.json).
