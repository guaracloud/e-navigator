# Evidence-Driven Optimization Campaign 9

Dates: 2026-08-24 to 2026-08-25

Status: **RETAINED FOCUSED WIN, OVERALL CPU NO-GO**. A private typed warning
boundary removes allocated warning identity strings and an invariant source
kind from bounded request-warning fingerprints. The exact warning path improved
22.202725% in Criterion, and three clean local whole-agent pairs improved mean
CPU by 7.617767%. The fresh 33-arm homelab campaign, however, measured
E-Navigator at 20.126790% more CPU than combined Beyla plus Alloy while using
17.653951% less RSS. That does not meet the requested CPU-and-memory
replacement target or the example tradeoff of only 5-10% more CPU for 20-30%
less memory.

Nothing was pushed. The candidate image was imported only into both node-local
containerd stores and was never selected by the standing DaemonSet. The
privileged image loader, both node tar files, allocation probes, disposable
benchmark resources, and temporary standing-agent isolation were removed. The
original signed standing image and Argo CD automation were restored and
verified.

## Profile-First Scope

The baseline was local `main` commit
`80dfcafb77ed60e55bc482c8bf0c1f43e23a814f`. The accepted profile ran Redis at
800 operations/second with 8 seconds warmup, 5 seconds attachment settle, and
45 seconds measured time. It completed 36,000 of 36,000 operations with zero
errors, decoded 84,834 protocol samples, reported zero transport and perf loss,
and captured 1,790 `perf` samples with zero lost samples.

The baseline agent used 48.962032 mCPU, 41,736 KiB instantaneous RSS, and
50,712 KiB peak RSS. Selected flat self-overhead was:

| Symbol or stack | Baseline overhead |
| --- | ---: |
| SipHash, split evenly across request and warning fingerprints | 3.46% |
| `malloc` | 3.07% |
| Sensitive attribute-key matching | 2.96% |
| Kernel `wake_up_q` | 2.07% |
| Request `WarningFingerprint` hashing | 1.73% |
| Request fingerprint hashing | 1.73% |
| `eventfd` wakeup | 1.45% |
| `cfree` | 1.40% |

An earlier profile was rejected before selecting work because unrelated host
traffic added 170,495 invalid protocol samples and made procfs/readlink stacks
dominate. A short diagnostic reproduced the contamination. Only the clean
profile above was used to choose the change.

Changing the public `OtelTraceRecord` attribute map was considered and rejected
before implementation because it would expand a private performance experiment
into a public contract migration. The selected warning boundary stayed inside
one generator and preserved the existing signal schema.

## Retained Change And Code Quality

`RequestWarningKind` is now a private, closed enum covering missing or malformed
trace context, missing attribution, detected OpenTelemetry SDK suppression, and
application-owned span suppression. The generator carries that type through
trace-context and suppression decisions, then converts it to the exact existing
public warning code and message only when emitting a signal.

The bounded warning fingerprint now stores the enum directly instead of an
allocated warning-code `String`. It also stops storing an allocated
`source_signal_kind`: this generator accepts only
`ProtocolRequestObservation`, so the source kind is invariant and could not
distinguish fingerprints. Source module, timestamp, PID, Kubernetes ownership,
bounds, oldest-entry eviction, and duplicate behavior remain unchanged.

This makes invalid internal warning strings unrepresentable, deletes the old
unknown-warning fallback, centralizes the public code/message mapping, and
removes redundant hash input and allocations. The tradeoff is 15 net lines in
the runtime source for the typed mapping. Both release binaries nevertheless
shrank. Existing integration cases exercise all five warning kinds and bounded
warning eviction; their shared assertion now also locks the exact public
message and `protocol_request_observation` source kind.

## Focused Before And After

Criterion used the permanent generated-identity request-correlation benchmark,
which exercises the warning path changed here. The unchanged
unique-at-capacity request benchmark acted as a same-process control.

| Benchmark | Before mean (95% CI) | After mean (95% CI) | Change |
| --- | ---: | ---: | ---: |
| Generated identity and warning | 3,296.002 ns (3,210.825-3,385.348) | 2,564.200 ns (2,508.765-2,627.601) | -22.202725%; 95% change interval -24.888257% to -19.344051%; `p = 0` |
| Unique-at-capacity control | 1,416.009 ns (1,379.899-1,456.982) | 1,329.749 ns (1,283.077-1,380.305) | -6.091782%; 95% change interval -10.575993% to -1.698914%; `p = 0` |

The control shows favorable host or binary-layout movement during the run. A
simple differential leaves approximately 16.11 percentage points of candidate
signal, but that subtraction is conservative context rather than a statistical
estimate. The direct whole-agent pairs below are the retention gate.

The post-change profile captured 1,847 samples with zero loss. SipHash fell
from 3.46% to 1.79%, the warning-fingerprint share fell from 1.73% to 0.76%,
and request-fingerprint share fell from 1.73% to 1.03%. `malloc` moved from
3.07% to 2.60%. These separate short profiles are directional hotspot evidence,
not a statistical A/B.

Focused formatting, strict Clippy, and the request-correlation integration
suite pass; the suite has 35 of 35 passing cases.

## Local Whole-Agent Before And After

Five exact-binary pairs ran on the same Linux virtual machine at Redis 800
operations/second, 8 seconds warmup, 5 seconds attachment settle, and 45
seconds measured time. Pairs 2, 3, and 5 were clean and included both execution
orders. Each binary completed 108,000 of 108,000 accepted-pair operations with
zero errors, decoded exactly 84,834 protocol samples per arm, and reported zero
transport, perf, queue, and export loss.

| Metric | Baseline mean | Candidate mean | Change |
| --- | ---: | ---: | ---: |
| Agent CPU | 44.335422 mCPU | 40.958053 mCPU | -7.617767% |
| Instantaneous RSS | 42,878.667 KiB | 43,702.667 KiB | +1.921702% |
| RSS high-water mark | 50,605.333 KiB | 50,337.333 KiB | -0.529588% |
| Redis p50 | 255.000 us | 260.333 us | +2.091503% |
| Redis p95 | 896.000 us | 921.333 us | +2.827381% |
| Redis p99 | 2,802.333 us | 2,767.000 us | -1.260854% |

The three paired CPU changes were -4.563246%, -8.471838%, and -9.591887%.
Instantaneous RSS and short-window latency varied in both directions, so they
are not retained as wins or classified as regressions. Peak RSS was nearly
flat.

Pairs 1 and 4 were excluded symmetrically rather than averaged. Pair 1's
candidate arm measured 170,574 invalid samples and 92.451 mCPU; pair 4's
baseline arm measured 170,488 invalid samples and 89.647 mCPU. Their clean
counterparts were near 42-44 mCPU. This was the same unrelated host protocol
traffic observed in the rejected profile.

The baseline and candidate arm64 binary SHA-256 values were respectively
`89c17247968f6d20eda74f42710b2cf81c59a385a6839f43aab9f04e709dc9bf`
and
`1697121b6719df35296c8312631c1a8f85583cd4a8914f2abc87a1730e4fd4fe`.

## Fresh Homelab Comparison

The exact campaign command was:

```bash
env E_NAVIGATOR_HOMELAB_CONFIRM=1 \
  E_NAVIGATOR_HEAD_TO_HEAD_RESULTS_DIR=benchmarks/results/optimization9-final-20260825 \
  E_NAVIGATOR_HOMELAB_IMAGE_TAG=campaign9-warning-candidate-amd64 \
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
| E-Navigator | 90.173085 mCPU | 0.623998 mCPU | 0.692000% | 116,433,806.222 bytes | 4,406,600.660 bytes | 3.784640% |
| Beyla plus Alloy | 75.064925 mCPU | 3.727863 mCPU | 4.966185% | 141,395,740.444 bytes | 8,420,749.350 bytes | 5.955448% |

E-Navigator therefore used 20.126790% more CPU and 17.653951% less RSS. The
memory result is useful, but CPU exceeds the user's acceptable example range
and memory does not reach its 20-30% example benefit. The combined replacement
decision remains **NO-GO**.

### Historical Campaign Delta

Campaign 8 is the closest identical-harness snapshot. It is not a same-time
code A/B, so this table records whole-environment drift and does not attribute
the movement to the warning change:

| Metric | Campaign 8 | Campaign 9 | Change |
| --- | ---: | ---: | ---: |
| E-Navigator CPU | 95.116412 mCPU | 90.173085 mCPU | -5.197134% |
| Beyla plus Alloy CPU | 82.319507 mCPU | 75.064925 mCPU | -8.812713% |
| E-Navigator CPU gap | +15.545410% | +20.126790% | +4.581380 percentage points |
| E-Navigator RSS | 128,231,196.444 bytes | 116,433,806.222 bytes | -9.200094% |
| Beyla plus Alloy RSS | 136,968,419.556 bytes | 141,395,740.444 bytes | +3.232366% |
| E-Navigator RSS gap | -6.379006% | -17.653951% | -11.274945 percentage points |

Both stacks' CPU means moved, and the reference moved more. That is why the
current CPU gap worsened even though E-Navigator's historical mean fell. Only
the same-session local binary pairs are used to attribute a CPU improvement to
this code.

### Throughput And Latency

Each cell is the three-arm mean shown as E-Navigator / Beyla plus Alloy. The
percentage is E-Navigator relative to the reference; negative latency is
faster.

| Family | Throughput rps | p50 us | p95 us | p99 us |
| --- | ---: | ---: | ---: | ---: |
| HTTP | 100.009435 / 100.009913 (-0.000479%) | 1,783.000 / 1,827.667 (-2.443918%) | 6,421.333 / 6,429.333 (-0.124430%) | 6,963.333 / 6,992.667 (-0.419487%) |
| gRPC | 80.007548 / 80.007931 (-0.000479%) | 2,902.000 / 2,971.333 (-2.333408%) | 4,156.000 / 4,137.667 (+0.443084%) | 6,038.333 / 5,697.000 (+5.991457%) |
| Redis | 160.015095 / 160.015861 (-0.000479%) | 1,049.667 / 1,138.000 (-7.762156%) | 1,892.000 / 1,987.000 (-4.781077%) | 3,230.667 / 3,210.667 (+0.622924%) |
| PostgreSQL | 50.004717 / 50.004957 (-0.000479%) | 1,140.667 / 1,221.000 (-6.579307%) | 2,147.333 / 2,287.333 (-6.120665%) | 3,405.333 / 4,253.000 (-19.931029%) |
| Python CPU | 8.000755 / 8.000793 (-0.000479%) | 30,576.667 / 30,298.333 (+0.918642%) | 40,646.000 / 39,679.333 (+2.436197%) | 53,628.333 / 49,085.333 (+9.255310%) |

Stable offered throughput and zero errors rule out dropped work as the resource
explanation. The short shared-cluster sample does not establish production
latency superiority or regression.

## Signal Completeness

Across the three E-Navigator profile arms, sources decoded 169,685 samples and
sent 99,133 signals. CPU profiling decoded and sent 692 samples. Exporters
enqueued 98,440 traces and sent 98,433, and enqueued and sent 692 profiles. The
seven-trace difference is an asynchronous scrape-boundary effect.

Hard loss, profile capture failures, invalid trace records, source failures,
queue-full drops, worker-closed drops, retry/circuit/permanent failures, partial
successes, and rejected items were zero in the gated arms.

## Allocation Diagnostics

Each diagnostic observed 45 seconds inside a separate 90-second full-profile
arm. Each completed 35,820 of 35,820 measured operations with zero workload
errors. The successful counters were:

| Stack and probe | Allocation calls | Requested bytes |
| --- | ---: | ---: |
| E-Navigator libc uprobes | 6,849,324 | 993,052,457 |
| Beyla Go runtime | 2,289,905 | 289,369,738 |
| Alloy Go metric delta | 27,318 | 7,366,832 |
| Directional Beyla plus Alloy sum | 2,317,223 | 296,736,570 |

Relative to campaign 8, E-Navigator's diagnostic counters moved +3.180316% in
calls and +2.389429% in requested bytes. The directional reference moved
+0.439777% and +1.142923%. These are separate-run diagnostics and do not isolate
this code effect.

The totals are **not cross-runtime comparable**. E-Navigator uses libc uprobes,
Beyla uses Go `runtime.mallocgc`, and Alloy contributes Go process metrics.
Their directional gaps are prioritization signals only. Both successful traces
printed counters before post-counter tracefs `uprobe_events` detach warnings;
probe pods were deleted and all cleanup gates passed.

## Size And Quality

| Artifact | Baseline | Candidate | Change |
| --- | ---: | ---: | ---: |
| arm64 release binary | 17,192,184 bytes | 17,192,024 bytes | -160 bytes |
| arm64 image | 37,497,961 bytes | 37,497,434 bytes | -527 bytes |
| amd64 release binary | 18,452,528 bytes | 18,450,944 bytes | -1,584 bytes |
| amd64 image | 38,027,818 bytes | 38,027,177 bytes | -641 bytes |

The final amd64 binary SHA-256 was
`0e20a58e322b41b71fbe785f2f608b0cbc409512d922621fb09b9691bb66e42b`.
The local amd64 image ID was
`sha256:f43f1a2051d1eb5f42461dbf480c7e22a24e3b0e5b3c8e46db7b99d4472a43a9`;
the homelab runtime resolved it to
`sha256:bd5fe0d0f5dee3e8f5b19ce13a7c698ef62dc951de52810c0c12cd7c40953c8b`.
The imported tar SHA-256 was
`1b4f3cc39fba0454b239375fed8bbe35b42ee93732fbea8ca1c2f7b11bffb839`.

`scripts/quality.sh` passed with no skip variables after the final source,
tests, and documentation were present. It covered formatting, documentation and
release checks, strict Clippy, rustdoc warnings, workspace tests and builds,
fuzz and repository guards, supply-chain checks, Docker smoke validation, Helm
and Kubernetes schema validation, website checks, and diff hygiene.

## Cleanup, Tradeoffs, And Remaining Work

Final read-only verification found `root-app` and `e-navigator` automated,
Synced, and Healthy. The original signed standing image
`ghcr.io/guaracloud/e-navigator@sha256:62402d21b9cb02d59d63365c7e3716ffa0980bfea42d070b43fed618703a7df9`
was 2/2 Ready. No disposable namespaced or cluster-scoped benchmark resources,
allocation probes, loader pods, or host tar files remained. The candidate image
remains only in the two node-local image stores.

The change is retained because it deepens a private boundary, removes invalid
states and redundant runtime work, preserves public signal contracts, improves
the exact path and three clean whole-agent pairs, and shrinks both
architectures. It does not reclassify replacement readiness: CPU remains the
binding NO-GO, and allocation diagnostics remain a large directional hotspot.

The next measured opportunities remain request-fingerprint hashing, allocator
traffic, Tokio exporter wakeups, and OTLP materialization. Changes to public
trace identity or attribute types would be broader contract migrations and
should not be attempted as incidental hot-path edits. Batching or wakeup changes
must retain bounded queues and be gated on latency, completeness, and shutdown
semantics.

Raw local, Criterion, homelab, allocation, Prometheus, workload, and profile
artifacts remain ignored under `benchmarks/results/optimization9-*`,
`benchmarks/results/local-agent-ab/campaign9-*`, and `target/criterion/`. The
compact machine-readable record is [`summary.json`](summary.json).
