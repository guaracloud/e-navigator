# Profiling breadth proof, 2026-07-22

## Decision

E-Navigator supports bounded periodic on-CPU, scheduler-based off-CPU, and
futex-wait lock-contention profiles through `source.aya_cpu_profile`. The
guarded homelab run also promotes CPython 3.11 interpreter unwinding from an
implementation-only claim to runtime-proven support alongside CPython 3.12.

Off-CPU and futex modes are disabled by default. They reuse the existing raw
profile transport, stack normalization and symbolization, Kubernetes
attribution, bounded profiling sessions, pprof endpoint, and OTLP Profiles
worker. Event duration is explicit rather than represented as a fake periodic
sample count.

## Implementation proved

The off-CPU path saves an allowed task's stack at `sched_switch` and completes
it when the same thread is next scheduled. Userspace validates the exact
`next_pid` tracepoint layout before attachment. The lock path accepts only
`FUTEX_WAIT` and `FUTEX_WAIT_BITSET` at raw syscall entry and records duration
plus syscall result at exit. Separate non-preallocated 4,096-entry BPF maps
bound pending state, and process exit removes stale entries.

Both modes have validated minimum-duration and per-CPU rate limits. Native
counters cover inputs, map update failures, state replacements, stack-capture
failures, below-minimum events, rate-limited events, output attempts, and
transport loss. The capture-filter control is seeded before the node-wide
scheduler or raw-syscall hooks attach.

The raw ABI accepts exactly on-CPU with zero weight, off-CPU with a positive
weight, or lock/futex-wait with a positive weight. Event-driven samples carry
`profiling.sample.weight_nanos`; the session generator saturating-adds it, and
pprof and OTLP Profiles encode the duration as nanoseconds.

## Environment and method

- Context: `homelab`, exclusively.
- Cluster: k3s `v1.30.4+k3s1`, two amd64 NixOS 24.05 nodes, Linux 6.6.68,
  containerd `1.7.20-k3s1`.
- Agent image: local-only
  `docker.io/library/e-navigator:gap4-dev-amd64`, manifest
  `sha256:70067da54bd490aba8ca335baea20dd99aac9609917057cc73623f1a2737730e`.
- Workload image: pinned
  `docker.io/library/python@sha256:5c34b355088846dddc8afb7442c20b9433dccdc8d66192dc52c616adeaa106a3`,
  observed as CPython 3.11.15.
- Arms: no benchmark agent and an agent with only the CPU-profile source,
  attribution, profiling generator, JSON output, Prometheus, and pprof.
- Order: `none/profiling`, `profiling/none`, then `none/profiling`.
- Workload: one CPU-bound nested Python call chain, three mutex contenders,
  one lock holder, and two sleepers on `homelab-01` after a ten-second discovery
  window.
- Each measured arm lasted 60 seconds. Profiling used 11 Hz periodic sampling,
  a 1 millisecond off-CPU threshold, a 0.5 millisecond futex threshold, and
  four accepted off-CPU plus four accepted futex samples per second per CPU.
- Capture filtering denied unknown cgroups and allowed only the benchmark
  namespace's `profiling-load` workload while explicitly excluding the agent.
- Collection recorded pod inventory, placement and resources, workload output,
  rendered Helm values and manifest, signals, native Prometheus metrics,
  per-agent pprof protobuf, process capability/mount state, events, and
  cleanup/restore state.

The exact configuration and workload remain executable at
`benchmarks/config/profiling-breadth.toml` and
`benchmarks/k8s/profiling-breadth-workload.yaml`. The guarded orchestration and
fail-closed analyzer are in
`benchmarks/runner/homelab-profiling-breadth.sh` and
`benchmarks/runner/analyze-profiling-breadth.py`.

## Runtime results

Every no-agent run had zero benchmark agent pods. Every profiling run observed
only command `python` and namespace `e-navigator-bench`, contained all three
profile modes and the five expected named Python functions, and served a
non-empty pprof protobuf from the workload node.

| Profiling repetition | on-CPU samples | off-CPU samples | futex-wait samples | named Python samples | off-CPU weight ns | futex weight ns | capture failure rate |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 77 | 349 | 342 | 76 | 2,257,326,353 | 2,245,696,348 | 0.004866% |
| 2 | 19 | 80 | 78 | 18 | 556,668,556 | 547,862,773 | 0.004166% |
| 3 | 204 | 939 | 923 | 201 | 6,046,592,598 | 6,181,678,095 | 0.004523% |

Across the three profiling runs, native counters recorded 796,552 event-driven
inputs, 20,756 output attempts, 364,538 rate-limited events, 411,222 events
below the configured duration threshold, and 36 stack-capture failures. Every
run had zero pending misses, state replacements, aggregate transport loss,
perf loss, and RingBuf reservation failures. The small capture-failure counts
occurred around workload teardown and stayed below the predeclared 0.1% gate.

The representative CPython sample resolves
`profile_leaf -> profile_level_four -> profile_level_three ->
profile_level_two -> profile_level_one -> <module>` above native Python 3.11
runtime frames. Curated on-CPU, off-CPU, and futex examples are in
[representative-samples.json](representative-samples.json). Run-level workload,
resource, signal, weight, and counter values are in [runs.json](runs.json).

## Workload and resource result

| Arm | Busy batches/s mean +/- sd | Two-pod agent CPU m mean +/- sd | Two-pod agent memory MiB mean +/- sd |
| --- | ---: | ---: | ---: |
| no benchmark agent | 4,753.099 +/- 56.078 | n/a | n/a |
| profiling | 4,655.687 +/- 33.739 | 78.162 +/- 13.175 | 205.861 +/- 5.263 |

The profiling arm was 2.049% lower in busy batches per second. This is a
three-run result for one pinned CPython workload on a shared cluster. It does
not establish general profiling, node, mixed-workload, backend, or production
overhead.

## Local validation

- Thirty-eight focused source tests passed, including arbitrary raw
  discriminants, weighted event semantics, exact scheduler layout parsing,
  and CPython 3.11/3.12 code objects.
- Generator and sink tests passed for saturating session weights and weighted
  pprof/OTLP Profiles encoding.
- The raw profile fuzz target executed 1,344,282 inputs in 21 seconds without a
  failure.
- Criterion medians were 1.607 microseconds for on-CPU decode, 1.573
  microseconds for off-CPU, and 1.935 microseconds for futex-wait decode.
- The proof analyzer and homelab confirmation guard have dedicated regression
  tests in the repository quality gate.
- The complete `scripts/quality.sh` gate passed without skips, including both
  embedded eBPF variants in the pinned Linux container build, supply-chain
  checks, Docker smoke, Helm rendering, and Kubernetes schema validation.

These local checks are parser and hot-path hygiene. The guarded cluster run is
the runtime evidence.

## JVM, V8, and remaining boundaries

E-Navigator consumes a bounded `/tmp/perf-<pid>.map` through the target mount
namespace when a workload already publishes one. For Node/V8, operators may
opt into Linux perf output with Node's documented perf flags. For JVMs,
operators may use a separate tool such as `perf-map-agent`. E-Navigator does not
add those flags, attach an agent, generate jitdump, or otherwise mutate target
processes. A map names generated code but does not guarantee reliable unwind
through every opaque JIT frame. No Node or JVM runtime was part of this proof.

Other boundaries:

- lock profiles cover observed futex waits, not spin locks, uncontended locks,
  lock ownership, or every runtime synchronization primitive;
- off-CPU profiles do not identify the wakeup cause;
- allocation profiling is not implemented;
- only CPython 3.11 and 3.12 exact layouts are supported;
- this run did not send profiles to a homelab Pyroscope or OTLP backend;
- automatic perf-map production, broad JIT unwind, and production profiling
  remain non-claims.

## Cleanup and restore

The benchmark Helm release, workloads, loader DaemonSet, and both temporary
Gap 4 image tags were removed from the homelab. The local Docker tags were also
removed. The pre-existing `e-navigator-bench` namespace was retained empty.
The standing Argo CD application reported `Synced` and `Healthy` with automated
prune and self-heal restored. Its original digest-pinned DaemonSet was 2/2
Ready at
`sha256:62402d21b9cb02d59d63365c7e3716ffa0980bfea42d070b43fed618703a7df9`.
The campaign touched no production context.
