# Profiling parity feasibility

Status: research and implementation boundary

Date: 2026-08-11

## Question

This note evaluates three requested profiling extensions:

1. reliable managed-runtime CPU stack profiling across representative Node/V8,
   HotSpot JVM, CPython, Ruby, PHP, .NET, and other customer runtimes;
2. combined kernel and user stack capture and symbolization; and
3. allocation or heap profiles.

The required product boundary is unchanged. E-Navigator remains a standalone
agent with native contracts. It may implement standard Linux, runtime, pprof,
and OpenTelemetry interfaces, but it must not become an Alloy configuration
emulator, depend on another collector, or silently inject agents into customer
processes.

## Bounded verdict

| Feature | Verdict | Honest scope |
| --- | --- | --- |
| Kernel plus user stacks | **GO now** | Add a separately bounded kernel stack to each eligible CPU, off-CPU, and futex-wait sample, symbolize from the matching host kernel and modules, and preserve the existing user and interpreter frames. Fail visibly when kernel addresses or symbols are unavailable. |
| Managed-runtime CPU stacks | **GO in staged runtime matrices** | A non-intrusive design is technically demonstrated by the OpenTelemetry eBPF profiler, but reliability requires a native E-Navigator descriptor, unwinder, symbolizer, negative detection, and live proof matrix for every runtime version, architecture, and build shape claimed. There is no honest universal `managed runtimes supported` switch. |
| Generic allocation profiling through allocator uprobes | **NO-GO as a cross-runtime or heap claim** | `malloc`-family probes can describe selected native allocator calls. They miss TLABs, runtime arenas, custom allocators, escape-analysis eliminations, and other managed allocations. They also do not describe live heap without correct lifetime tracking. |
| Allocation profiles matching `pyroscope.ebpf` | **Not required for parity** | Current Alloy documentation says `pyroscope.ebpf` collects CPU profiles. Its allocation setting belongs to `pyroscope.java`, which invokes async-profiler against JVM processes. Allocation is a separate product capability, not a missing behavior of the eBPF CPU component. |
| Runtime-native allocation providers | **GO only as explicit opt-in modules** | Add them one runtime at a time, beginning with a precisely named semantic such as sampled allocated bytes. Runtime diagnostics or attachment changes target state, so they must be disabled by default and require operator authorization. |

This means kernel stacks are the only one of the three requests that should be
treated as a bounded implementation item immediately. Managed-runtime breadth
is a program of independently qualified adapters. Allocation profiling first
needs an accepted semantic and attachment policy, not one generic eBPF patch.

Implementation outcome on 2026-08-11: the opt-in kernel-stack slice was
implemented through capture, normalization, symbolization, pprof, OTLP,
accounting, deployment controls, and public documentation. Both eBPF transport
objects built in the pinned Linux container, and a privileged periodic smoke
passed on the local aarch64 OrbStack kernel with combined user/kernel domains
and no raw kernel-address fallback. The scoped evidence is in
[`proof/kernel-stack-20260811/report.md`](../proof/kernel-stack-20260811/report.md).
Managed-runtime breadth and allocation remain at the verdicts above; no
adapter or profile was added under an unsupported semantic.

## What Alloy actually establishes

The current [`pyroscope.ebpf` documentation](https://grafana.com/docs/alloy/latest/reference/components/pyroscope/pyroscope.ebpf/)
states that the component embeds the OpenTelemetry eBPF profiler, collects
stack traces at a configured CPU sample rate, enables kernel frames by default,
and supports HotSpot, .NET, Python, Ruby, PHP, Node/V8, and Perl. It also
documents the host PID namespace, filesystem access, and Linux capabilities
needed by that implementation. The current
[`pyroscope.java` documentation](https://grafana.com/docs/pyroscope/latest/configure-client/grafana-alloy/java/)
separately states that Alloy invokes async-profiler and passes an allocation
sampling configuration through `--alloc`.

Therefore:

- kernel and managed-runtime CPU-stack breadth are relevant comparison goals;
- allocation is not produced by Alloy's eBPF CPU profiler;
- Java allocation profiling changes the target through an attach-based runtime
  profiler, even if no application source change is required; and
- matching information is not the same as copying Alloy configuration, labels,
  process lifecycle, or implementation.

## Managed-runtime design

### Feasible native architecture

The primary technical precedent is the
[`open-telemetry/opentelemetry-ebpf-profiler`](https://github.com/open-telemetry/opentelemetry-ebpf-profiler)
source. Its [profiling internals](https://github.com/open-telemetry/opentelemetry-ebpf-profiler/blob/main/doc/internals.md)
describe a non-intrusive design:

1. userspace detects executable mappings, runtime identity, version, and
   structure layouts;
2. userspace installs only bounded unwind metadata in BPF maps;
3. a perf-event program starts from interrupted registers;
4. statically known unwinders tail-call between native and runtime-specific
   frame walkers as the program counter changes ownership;
5. BPF emits bounded raw frame identities; and
6. userspace performs string and source symbolization, caching, aggregation,
   and export.

That separation fits E-Navigator's existing architecture. It should be
implemented as an E-Navigator-native deep module, not as a vendor compatibility
layer:

```text
process discovery
  -> runtime detector
  -> validated RuntimeDescriptor
  -> bounded per-process BPF metadata
  -> mixed native/runtime/kernel unwind
  -> userspace runtime symbolizer
  -> native ProfileSampleObservation
  -> pprof and OTLP encoders
```

`RuntimeDescriptor` should contain at least runtime kind, runtime version,
architecture, ELF build identity, executable mapping ranges, pointer width,
required feature bits, structure offsets, symbolization metadata roots, and a
descriptor schema version. Descriptors must be immutable after validation and
keyed by process identity that detects PID reuse. The eBPF side must receive
only numeric, bounded data. File parsing, version discovery, demangling, and
strings remain in Rust userspace.

Every adapter must fail closed. An unknown version, missing required symbol,
impossible offset, unreadable mapping, unsupported pointer compression mode,
or inconsistent process identity produces an unsupported-runtime outcome and
coverage metric. It must never guess a nearby layout.

### Runtime feasibility matrix

| Runtime | Non-intrusive metadata path | Feasibility and boundary |
| --- | --- | --- |
| Native C/C++/Rust/Zig | ELF mappings plus `.eh_frame`, symbols, build IDs, and optional debug files | **High.** This is the existing native-unwind direction. Stripped symbols affect names, not necessarily unwind metadata. |
| Go | ELF mappings plus `.gopclntab`, with native frames around Go frames | **High, versioned.** The OpenTelemetry profiler documents `.gopclntab` as its Go unwind source because ordinary Go binaries commonly lack complete `.eh_frame` coverage. Do not classify Go as a generic DWARF success. |
| HotSpot JVM | Exported VMStructs and related HotSpot introspection tables, code cache metadata, interpreter frames, and nmethod scope data | **High but substantial.** HotSpot provides unusually useful self-description. The OpenTelemetry [HotSpot implementation](https://github.com/open-telemetry/opentelemetry-ebpf-profiler/tree/main/interpreter/hotspot) uses these tables across many JDK releases, while explicitly excluding AOT code outside the code cache. Claim only tested HotSpot builds, not every JVM. |
| CPython | Version discovery, exported symbols, type introspection where available, and exact internal frame/thread layouts where it is not | **Medium to high for a declared matrix.** The OpenTelemetry [Python implementation](https://github.com/open-telemetry/opentelemetry-ebpf-profiler/blob/main/interpreter/python/python.go) currently handles distinct layouts from CPython 3.6 through 3.14, including the 3.11 interpreter-frame change and later TLS/layout changes. This proves breadth is possible, not that internal ABI is stable. CPython's documented [`perf` support](https://docs.python.org/3/howto/perf_profiling.html) is a useful operator-enabled enhancement, but it is not enabled by default and cannot replace fail-closed native detection. |
| Node/V8 | Exact Node and V8 identity, V8 heap and frame metadata, code ranges, pointer-compression and sandbox mode, plus optional runtime-produced perf metadata | **Medium.** Non-intrusive walking is demonstrated by the OpenTelemetry [Node/V8 adapter](https://github.com/open-telemetry/opentelemetry-ebpf-profiler/tree/main/interpreter/nodev8), but V8 internals and generated-code layouts are version-sensitive. Node's documented Linux `--perf-basic-prof`, `--perf-prof`, and `--perf-prof-unwinding-info` flags are explicit operator opt-ins, not safe defaults for E-Navigator to add. |
| Ruby MRI | Exact Ruby version, execution-context and control-frame layouts, instruction-sequence metadata, and JIT mode | **Medium.** The OpenTelemetry [Ruby adapter](https://github.com/open-telemetry/opentelemetry-ebpf-profiler/tree/main/interpreter/ruby) proves the approach. MRI structures are internal and JIT variants need separate proof. Support must be release-family and build-shape specific. |
| PHP Zend VM | Exact PHP version, executor globals, `zend_execute_data`, op-array metadata, and OPcache/JIT state | **Medium.** The OpenTelemetry [PHP adapter](https://github.com/open-telemetry/opentelemetry-ebpf-profiler/tree/main/interpreter/php) contains architecture decoders and separate OPcache handling. PHP internals are not a stable cross-version profiler ABI. Treat ZTS/NTS, JIT, architecture, and packaged build variants separately. |
| .NET CoreCLR | Exact CoreCLR identity, runtime/JIT code metadata, managed frame layouts, and runtime self-description where available | **Medium.** A non-intrusive implementation exists in the OpenTelemetry [.NET adapter](https://github.com/open-telemetry/opentelemetry-ebpf-profiler/tree/main/interpreter/dotnet), but E-Navigator still needs its own build/version validation and live matrix. NativeAOT and alternative .NET runtimes are separate targets. EventPipe is the more stable operator-authorized fallback, not a default mutation-free eBPF mechanism. |
| BEAM, Perl, LuaJIT, and other runtimes | Dedicated, statically registered adapters only | **Possible, not inherited.** The existence of additional adapters in the OpenTelemetry profiler shows an extension path. It does not justify an open-ended claim. Each runtime needs the same descriptor, replay, live, and negative gates. |

### Why perf maps alone are insufficient

A perf map maps an address range to a name. It does not tell the profiler how
to recover callers through interpreter or JIT frames. Correct managed-runtime
profiling needs both unwind and symbol information. E-Navigator should retain
its bounded consumer for maps already produced by a workload, but map presence
must be an optional symbol source, never the definition of runtime support.

Starting a runtime with Node perf flags, Python `-X perf`, or .NET perf-map
settings changes its behavior and filesystem output. Attaching a JVM agent or
starting EventPipe/JFR changes target state. E-Navigator must not do those by
default. An opt-in diagnostics provider must name the mutation, permissions,
overhead budget, and cleanup behavior.

### Licensing constraint

E-Navigator is Apache-2.0. The OpenTelemetry profiler repository states that
its userspace is Apache-2.0 but its eBPF source is GPL-2.0. The repository is a
valid architectural and test precedent, but its BPF implementation must not be
copied into E-Navigator without an explicit licensing decision. Implement the
E-Navigator unwinders independently from Linux and upstream runtime source,
and obtain legal review before reusing any code whose license is not clearly
compatible.

## Kernel plus user stacks

### Capture contract

Linux defines `bpf_get_stack()` and the `BPF_F_USER_STACK` selector in the
[BPF UAPI](https://github.com/torvalds/linux/blob/master/include/uapi/linux/bpf.h),
with implementation and program-type checks in
[`kernel/trace/bpf_trace.c`](https://github.com/torvalds/linux/blob/master/kernel/trace/bpf_trace.c).
The current E-Navigator sampler calls the helper only with
`BPF_F_USER_STACK`. The bounded change is to call it separately with flags
zero for the kernel stack while preserving the existing user stack.

Do not concatenate the two address arrays in BPF. Extend the raw event with:

- `user_frame_count` and `user_instruction_pointers`;
- `kernel_frame_count` and `kernel_instruction_pointers`;
- independent truncation and capture-failure flags; and
- a stack-order/version field if the existing ABI cannot make ordering
  unambiguous.

Userspace should normalize one logical sample in a documented order, for
example root to leaf with kernel frames followed by the user/runtime boundary
and then user frames. The native signal must retain frame domain so identical
numeric addresses in kernel and user address spaces cannot collide. A failed
kernel capture must not discard a valid user stack, and a failed user capture
must not be presented as a complete kernel-only application sample.

The same contract applies to periodic CPU, scheduler off-CPU, and futex-wait
capture where the kernel helper is valid for the current hook context. Each
hook needs live proof that the reported kernel portion has the intended
meaning. In particular, tracepoint machinery and scheduler frames may dominate
the kernel side of an event-driven sample, so documentation must say what the
sample represents rather than imply wakeup-cause or lock-owner attribution.

### Symbolization

Resolve kernel addresses against a snapshot tied to the running kernel:

- `/proc/kallsyms` for the core kernel and exported module symbols;
- `/proc/modules` and module address ranges where required;
- kernel release and build identity recorded with symbol cache entries; and
- an explicit synthetic frame plus warning when a name cannot be read.

Never export raw kernel addresses as a fallback. They may expose KASLR-sensitive
information and are useless after a mismatched kernel restart. Invalidate the
cache when kernel identity changes and refresh module data without unbounded
per-sample filesystem work.

The kernel's [perf security documentation](https://www.kernel.org/doc/html/latest/admin-guide/perf-security.html)
states that captured registers and user or kernel addresses can contain
sensitive data. It recommends `CAP_PERFMON` instead of broad `CAP_SYS_ADMIN`
for perf monitoring and notes that reading kernel addresses from
`/proc/kallsyms` may require `CAP_SYSLOG`. The
[`kptr_restrict` documentation](https://www.kernel.org/doc/html/latest/admin-guide/sysctl/kernel.html)
also permits configurations where usable kernel addresses are withheld even
from privileged readers. E-Navigator must detect this and report kernel
symbolization unavailable. It must not weaken host sysctls.

Aya's [`PerfEvent`](https://docs.rs/aya/latest/aya/programs/perf_event/struct.PerfEvent.html)
provides the existing per-CPU attachment boundary. New map or event-buffer
sizes must remain explicit and checked against the existing memory budget.
Capturing a second stack increases helper work and event bandwidth, so the
change needs matched overhead and loss evidence, not only a verifier pass.

## Allocation and heap profiles

### Three different semantics

The product must choose among three distinct facts:

1. **allocation events**, sampled allocated objects or bytes at allocation
   time;
2. **in-use heap**, allocated objects or bytes that remain live at observation
   time; and
3. **retained objects**, reachability or dominator semantics owned by a managed
   garbage collector.

They are not interchangeable. The standard
[`pprof profile.proto`](https://github.com/google/pprof/blob/main/proto/profile.proto)
can carry sample types such as allocated and in-use objects or space, but the
producer remains responsible for truthful semantics. A `malloc` entry probe
cannot emit `inuse_space` unless successful returns and matching frees are
correlated correctly, including `realloc`, allocator reuse, process exit,
sampling weights, and bounded eviction accounting.

OpenTelemetry Profiles is still development status in the current
[`opentelemetry-proto` repository](https://github.com/open-telemetry/opentelemetry-proto).
E-Navigator's existing pinned backend contract therefore still requires a
wire-version decision and real Pyroscope ingest/query proof for every new
sample type.

### Native allocator provider

A bounded eBPF provider may attach uprobes and return probes to explicitly
supported dynamic allocator symbols, initially glibc `malloc`, `calloc`,
`realloc`, and `free`, with separate musl or jemalloc adapters only after ABI
proof. It can produce a profile named `native_allocation` with sampled allocated
bytes and objects. It must not be called `heap` and must not claim managed
runtime coverage.

Required controls include a minimum or probabilistic byte-sampling interval,
per-CPU rate limits, a fixed-capacity pending-call map, PID and TID identity,
recursion handling, successful-return validation, cgroup filtering before
state insertion, process-exit cleanup, and counters for every miss, replacement,
probe failure, rate limit, and unsupported allocator. Dynamic linking,
symbol-versioning, static linking, inlining, allocator aliases, and custom
allocators are explicit coverage dimensions.

### Runtime-native providers

Managed allocation events occur above libc and often never cross an externally
probeable allocator boundary. JVM TLAB allocation is the clearest example.
Runtime-native mechanisms are therefore the correct long-term source:

- HotSpot JFR or an explicitly authorized attach profiler can emit sampled
  allocation stacks. Oracle documents JFR as the JDK's event and profiling
  framework and exposes allocation views and events. Alloy's Java component
  uses async-profiler for this purpose.
- .NET exposes external diagnostics through the
  [`Microsoft.Diagnostics.NETCore.Client` contract](https://learn.microsoft.com/en-us/dotnet/core/diagnostics/diagnostics-client-library),
  including EventPipe and the `Microsoft-DotNETCore-SampleProfiler`. GC event
  providers can carry allocation information. Access to the diagnostics socket
  and starting a session are operator-visible target interactions.
- Node/V8, CPython, Ruby, and PHP need separate runtime-provider research and
  proof before any allocation claim. CPU-stack layout access does not imply an
  allocation event source.

Every runtime-native allocation provider must be disabled by default and
guarded by a setting whose name makes the action clear, for example
`allow_runtime_diagnostics`. Authorization must be scoped to selected
workloads. Starting, stopping, or reconnecting a session needs deterministic
cleanup and a health state. If policy forbids target interaction, the provider
must remain unavailable rather than silently fall back to semantically false
allocator data.

## Security and privilege boundary

The least-privilege target is capability by feature, not one ever-growing pod
profile:

| Need | Likely host permission | Rule |
| --- | --- | --- |
| system-wide perf sampling and eBPF | `CAP_PERFMON` and `CAP_BPF`, plus kernel-specific resource limits | Keep the modern reduced profile and compatibility profile separate. Do not add `SYS_ADMIN` when narrower capabilities work. |
| inspect target mappings and memory | procfs access and, depending on kernel and operation, ptrace-style permission | Read only selected processes. Preserve PID identity checks and mount namespace boundaries. |
| kernel names | usable `/proc/kallsyms`, potentially `CAP_SYSLOG` | Optional capability with visible degradation. Never change `kptr_restrict`. |
| runtime diagnostics socket or attach | runtime-specific same-user, namespace, filesystem, or attach permission | Explicit opt-in, selected targets, audit log, timeout, and cleanup. |

Interpreter strings, file paths, class names, method names, and allocation type
names are potentially customer data. Existing string limits and sensitive-key
filters are necessary but not sufficient. Add per-runtime length limits,
UTF-8 handling, invalid-pointer accounting, cache bounds, and a policy for
source paths before widening public output.

## Implementation sequence

The work should be split into independently reviewable commits and claims:

1. **Kernel raw ABI and capture.** Add separate bounded kernel fields, decode
   validation, independent loss/truncation accounting, and no symbol names yet.
2. **Kernel symbolizer.** Add kernel-identity-bound kallsyms/module snapshots,
   frame-domain normalization, cache invalidation, and inaccessible-symbol
   warnings.
3. **Kernel end-to-end proof.** Exercise periodic, off-CPU, and futex-wait
   profiles on supported amd64 and arm64 Linux kernels, then qualify overhead,
   loss, pprof, OTLP, and Pyroscope query behavior.
4. **Managed-runtime framework.** Introduce the versioned descriptor,
   statically registered adapter trait, process-identity lifecycle, BPF dispatch,
   coverage metrics, and replay harness without claiming a new runtime.
5. **HotSpot adapter.** Prefer the runtime with exported VMStructs. Qualify a
   declared JDK and architecture matrix, including interpreted, C1, C2, JNI,
   native, and unsupported AOT cases.
6. **CPython breadth.** Replace the two-version switch with a validated matrix
   and introspection-first descriptors. Keep every unproven patch or build
   shape unsupported.
7. **Node/V8, Ruby, PHP, and .NET adapters.** One runtime and one support matrix
   per change series. Do not combine their ABI risk or evidence.
8. **Allocation semantic ADR.** Choose allocated versus in-use semantics,
   naming, sampling weights, privacy, target-interaction policy, and wire types.
9. **One allocation provider.** Implement either narrowly named native
   allocation events or an opt-in HotSpot provider. Do not mix both in the
   first claim.

Documentation and the website should change only when the corresponding live
matrix passes. Before that, update the capability boundary to say implemented
but unproven, or keep the item explicitly unsupported.

## Required test seams and evidence

`100% unit-test covered` cannot guarantee correct eBPF or runtime unwinding.
The verifier, target memory, runtime optimizer, kernel, architecture, and
backend are outside a Rust unit test. The defensible gate combines these
layers:

### Pure Rust tests

- parse every descriptor and symbol source from bounded fixtures;
- reject unknown versions, truncated ELF data, integer overflow, impossible
  offsets, overlapping ranges, reused PIDs, stale build IDs, and invalid text;
- property-test and fuzz every raw event decoder and runtime metadata parser;
- golden-test mixed frame ordering, domains, truncation, pprof sample types,
  OTLP mapping, and stable native JSON;
- test cache capacity, deterministic eviction, process exit, module refresh,
  partial symbolization, and every diagnostic counter;
- use traits for process memory, procfs, time, BPF maps, and diagnostics
  transports so failure paths are deterministic.

### Unwinder replay tests

Create a coredump or captured-memory replay harness that runs the same bounded
unwind state machine against frozen registers, mappings, and process memory.
The OpenTelemetry profiler's documented testing strategy uses this seam because
ordinary unit tests cannot execute real BPF unwinding. Keep fixtures for every
claimed runtime version, architecture, interpreter/JIT mode, mixed native
transition, maximum depth, corrupt pointer, and unsupported layout. Expected
frames must include names, source locations where claimed, frame domains, and
termination reasons.

### BPF verifier and kernel tests

- build both eBPF architectures;
- load every new program and tail-call route on the minimum and current
  supported kernels;
- prove map initialization happens before attachment;
- exercise helper failures, full maps, lost buffers, maximum stacks, and
  process churn;
- compare capture with and without kernel frames under the same workload;
- assert raw kernel addresses never reach exported signals; and
- run privileged tests in Linux VMs or CI kernels, not only in a macOS Docker
  client environment.

### Pinned live runtime matrix

Use digest-pinned Docker images for each claimed runtime and record the image,
runtime version, architecture, kernel, E-Navigator commit, configuration, and
expected named frames. At minimum include interpreted and optimized/JIT code,
native transitions, deep recursion, multiple threads, short-lived processes,
PID reuse, stripped packages, missing symbols, and a deliberately unsupported
version. Three repetitions and zero silent unsupported fallbacks are a
reasonable promotion floor, not proof for untested builds.

### Backend and performance gates

- query the pinned real Pyroscope backend for expected kernel, native, and
  managed frames and correct sample types;
- record input, output, rejection, truncation, pending-state, symbolization,
  queue, and transport loss counters;
- measure CPU, RSS, BPF map memory, event bytes, profiler-induced throughput
  change, and tail latency against the current profiler under counterbalanced
  order;
- keep kernel capture and each runtime adapter independently disableable for
  attribution; and
- retain a NO-GO result when any required semantic, loss, privilege, overhead,
  or query gate fails.

Local Docker can validate userspace fixtures, encoders, pinned runtime images,
and backend ingestion on this computer. It cannot by itself prove privileged
Aya behavior on all production kernels or both architectures. Kernel and
homelab evidence remain separate required gates.

## Claims that cannot be guaranteed

No implementation can honestly guarantee all of the following without a
bounded support matrix:

- every current and future build of Node/V8, JVM, CPython, Ruby, PHP, .NET, or
  an unspecified `other runtime`;
- complete stacks through every JIT optimization, corrupted process, missing
  executable mapping, unsupported architecture, or inaccessible namespace;
- kernel names when host security policy withholds kernel addresses;
- heap liveness from allocation entry probes;
- zero profiling overhead or zero lost samples under arbitrary saturation;
- equivalent meaning between runtime allocation events and allocator calls;
  or
- production readiness from unit coverage and local Docker alone.

The correct guarantee is narrower: for each declared runtime, version,
architecture, build shape, kernel, feature mode, and backend revision, the
agent either produces evidence that meets the published gates or reports a
typed unsupported or degraded state without guessing.

## Primary sources

- [Linux BPF UAPI, stack helper and flags](https://github.com/torvalds/linux/blob/master/include/uapi/linux/bpf.h)
- [Linux implementation of tracing BPF helpers](https://github.com/torvalds/linux/blob/master/kernel/trace/bpf_trace.c)
- [Linux perf events security](https://www.kernel.org/doc/html/latest/admin-guide/perf-security.html)
- [Linux `kptr_restrict`](https://www.kernel.org/doc/html/latest/admin-guide/sysctl/kernel.html)
- [Aya `PerfEvent` API](https://docs.rs/aya/latest/aya/programs/perf_event/struct.PerfEvent.html)
- [OpenTelemetry eBPF profiler source](https://github.com/open-telemetry/opentelemetry-ebpf-profiler)
- [OpenTelemetry eBPF profiler internals and testing strategy](https://github.com/open-telemetry/opentelemetry-ebpf-profiler/blob/main/doc/internals.md)
- [OpenTelemetry managed-runtime adapters](https://github.com/open-telemetry/opentelemetry-ebpf-profiler/tree/main/interpreter)
- [CPython Linux perf support](https://docs.python.org/3/howto/perf_profiling.html)
- [Node command-line runtime profiling flags](https://nodejs.org/api/cli.html)
- [OpenJDK VMStructs source](https://github.com/openjdk/jdk/blob/master/src/hotspot/share/runtime/vmStructs.cpp)
- [Ruby VM structure source](https://github.com/ruby/ruby/blob/master/vm_core.h)
- [PHP Zend execution structure source](https://github.com/php/php-src/blob/master/Zend/zend_compile.h)
- [.NET runtime source](https://github.com/dotnet/runtime)
- [.NET diagnostics client contract](https://learn.microsoft.com/en-us/dotnet/core/diagnostics/diagnostics-client-library)
- [Oracle JDK Flight Recorder guide](https://docs.oracle.com/en/java/java-components/jdk-mission-control/9/user-guide/using-jdk-flight-recorder.html)
- [Grafana Alloy `pyroscope.ebpf`](https://grafana.com/docs/alloy/latest/reference/components/pyroscope/pyroscope.ebpf/)
- [Grafana Alloy Java profiling](https://grafana.com/docs/pyroscope/latest/configure-client/grafana-alloy/java/)
- [pprof profile schema](https://github.com/google/pprof/blob/main/proto/profile.proto)
- [OpenTelemetry protocol schemas and stability](https://github.com/open-telemetry/opentelemetry-proto)
