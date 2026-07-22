# ADR 0009: Bounded Event-Driven Profiling

Status: accepted

Date: 2026-07-22

## Context

E-Navigator's profiling source sampled on-CPU work with per-CPU perf events.
The signal schema already distinguished CPU, memory, and lock profile kinds,
but only periodic CPU samples were produced. Time blocked off-CPU and time
waiting on contended synchronization are often the more useful explanation for
latency, so the source needed event-driven profiles without creating unbounded
global scheduler or syscall state.

The first non-CPU kind could target allocations or lock contention. Allocation
profiling would require runtime- and allocator-specific probes, object-size
semantics, and versioned language layouts. Linux futex waits provide a narrower
cross-runtime boundary for contended mutexes and condition variables, reuse the
existing user-stack capture, and expose an actual wait duration. Futex coverage
is not universal: spin locks, uncontended locks, runtime-private primitives,
and synchronization that does not wait through `futex(2)` remain invisible.

The source already recognizes CPython 3.11 and 3.12 layouts and consumes
bounded target-mount `/tmp/perf-<pid>.map` files. The public claim covered only
CPython 3.12, and the JIT path needed an explicit ownership boundary. Node can
opt into Linux perf output through its documented `--perf-basic-prof` family
of flags. JVM operators can use tooling such as `perf-map-agent`, which attaches
to a JVM and writes `/tmp/perf-<pid>.map`. Generating either map changes the
target runtime and is not an agent-safe default.

## Decision

Keep periodic on-CPU sampling and add two disabled-by-default event-driven
modes to `source.aya_cpu_profile`:

- `off_cpu_enabled` records an outgoing task at `sched:sched_switch`, then
  emits its saved stack when that thread is next scheduled.
- `lock_enabled` records only `FUTEX_WAIT` and `FUTEX_WAIT_BITSET` entries at
  `raw_syscalls:sys_enter`, then emits the saved stack and syscall result at
  the matching `raw_syscalls:sys_exit`.

Choose futex-wait lock profiling before allocation profiling. It provides one
bounded kernel boundary across CPython, native code, JVM, and V8 processes
without guessing allocator or object semantics. The emitted lock kind means
"observed futex wait", not every lock acquisition or all contention.

The two pending maps are separate, fixed-capacity 4,096-entry non-preallocated
BPF hash maps. A process-exit tracepoint removes abandoned state. Insert
failures and replacement of an existing scoped entry have native counters.
Missing completion state is not counted: `sched_switch` exposes no incoming
task cgroup, and raw `sys_exit` exposes no futex operation, so a miss cannot be
distinguished from deliberately filtered or unrelated activity. Treating that
node-wide noise as scoped loss would be false accounting.

Both modes require a positive minimum duration and a per-CPU output rate cap.
Defaults are 1 millisecond and 64 events per second per CPU, with validated
upper bounds of 60 seconds and 4,096 events per second per CPU. Below-minimum,
rate-limited, stack-capture-failure, map-update-failure, replacement, input,
and output totals are recorded. The capture-filter control word is seeded
before these node-wide high-frequency hooks attach, and every pending entry is
created only after an in-kernel cgroup verdict allows it.

Off-CPU attachment fails closed unless tracefs describes `sched_switch`
`next_pid` at the exact 56-byte offset and four-byte size expected by the eBPF
object. Lock attachment uses an architecture-specific futex syscall number and
fails closed on an unsupported architecture. eBPF load, verifier, map, and
attachment failures remain source-startup failures.

The raw profile ABI now carries explicit profile-kind and profile-mode
discriminants, syscall status, and `weight_nanos`. Userspace accepts only these
three combinations:

- CPU plus on-CPU with zero event weight;
- CPU plus off-CPU with a positive duration;
- lock plus futex-wait with a positive duration.

Every other combination fails decode. Event-driven samples keep
`sample_count = 1`, omit a periodic sampling interval, and carry
`profiling.sample.weight_nanos`. The profiling generator saturating-adds that
duration into `profiling.session.total_weight_nanos`. pprof encodes it as the
sample's nanosecond value, and OTLP Profiles encodes it as sample duration.
The existing stack normalization, symbolization, attribution, bounded session,
pprof, and OTLP workers remain the delivery path.

CPython 3.11 and 3.12 are supported interpreter layouts. Only CPython 3.11 and
3.12 exact layouts are read, and only bounded code-object name, file, and first
line metadata is exported. Unknown versions remain unsupported with coverage
accounting.

For JVM and V8, retain consumer-only perf-map support. E-Navigator reads a
bounded `/tmp/perf-<pid>.map` through the target process's mount namespace when
the workload or its operator has already produced one. It does not attach a JVM
agent, add JVM flags, add Node/V8 flags, create jitdump output, or mutate target
processes. A symbol map can name an instruction pointer but cannot make an
opaque JIT stack reliably unwindable. Named Node/JVM frames therefore remain a
conditional symbolization capability, not automatic runtime coverage.

## Consequences

Event-driven hooks execute on node-wide scheduler and raw-syscall paths, even
though filtering, duration thresholds, and rate caps bound exported work. They
remain opt-in and should be measured against the target workload. The pending
maps can reject entries at capacity; those rejections are visible but the maps
do not evict another task silently.

Off-CPU stacks describe where a thread was switched out, and futex stacks
describe where a wait began. They do not attribute kernel wakeup causes,
lock ownership, allocation lifetime, or every synchronization primitive.
Allocation profiling remains a future, runtime-specific decision.

## Evidence

Thirty-eight source tests cover the extended ABI, weighted semantics,
CPython 3.11 and 3.12 layouts, exact scheduler-layout parsing, arbitrary
discriminants, and bounded symbolization. Generator and sink tests prove
saturating session aggregation plus weighted pprof and OTLP encoding. The raw
profile fuzz target executed 1,344,282 inputs in 21 seconds without a failure.
Criterion measured median raw decode times of 1.607 microseconds for on-CPU,
1.573 microseconds for off-CPU, and 1.935 microseconds for futex-wait fixtures
on the development workstation. These are local decoder results, not live
kernel overhead.

The guarded homelab campaign ran three counterbalanced 60-second no-agent and
profiling pairs against CPython 3.11.15. Every profiling run contained named
CPython frames plus on-CPU, off-CPU, and futex-wait samples, positive duration
weights, a non-empty pprof payload, only the intended namespace and command,
zero pending/replacement/transport-loss counters, and a 0.0042 to 0.0049%
stack-capture failure rate. Mean workload throughput was 2.049% below the
no-agent arm for this shared-cluster workload. The evidence is in
`documentation/proof/profiling-breadth-20260722/`.

## References

- Node.js CLI, Linux perf options:
  <https://nodejs.org/api/cli.html#useful-v8-options>
- JVM perf-map-agent:
  <https://github.com/jvm-profiling-tools/perf-map-agent>
- Linux scheduler tracepoint format on the running kernel:
  `/sys/kernel/tracing/events/sched/sched_switch/format`
