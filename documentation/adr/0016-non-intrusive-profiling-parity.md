# ADR 0016: Non-intrusive profiling parity

- Status: accepted
- Date: 2026-08-11

## Context

E-Navigator needs a truthful response to three profiling gaps: combined kernel
and user stacks, representative managed-runtime stacks, and allocation or heap
profiles. The product remains a standalone Rust/eBPF agent with native signal
contracts. The accepted operating policy is non-intrusive: the agent must not
attach a runtime profiler, inject an agent, change process startup flags, or
weaken host security settings.

A perf map provides generated-code names but no caller recovery through opaque
interpreter or JIT frames. Runtime internals also vary by release,
architecture, build mode, pointer compression, JIT mode, and packaging. A
generic allocator uprobe observes neither most managed allocations nor live or
retained heap semantics. Treating either mechanism as universal support would
create false data.

Kernel capture is a bounded change to the existing sampler. Linux exposes a
separate `bpf_get_stack` call for kernel frames, and the current event already
has a userspace normalization and export boundary where frame domains can be
kept explicit.

## Decision

Implement kernel stacks as an opt-in extension of `source.aya_cpu_profile`:

- capture user and kernel instruction pointers into separate fixed arrays;
- give each domain an independent validated frame budget;
- retain managed-runtime and user frames when the kernel budget is full;
- carry an explicit frame domain through normalization, deterministic stack
  identity, native JSON, pprof, and OTLP Profiles;
- resolve kernel names from a bounded `/proc/kallsyms` snapshot tied to kernel
  identity and refreshed for module churn;
- never export a raw kernel address when symbolization is unavailable;
- emit address-free placeholders plus per-sample and periodic failure and
  truncation accounting; and
- leave the feature disabled by default until each target kernel and workload
  has verifier, semantic, loss, and overhead evidence.

Do not claim broad managed-runtime support from perf maps. Future runtime
support must use statically registered, independently implemented adapters.
Each adapter must validate an immutable descriptor containing runtime kind,
exact version/build identity, architecture, mapping ownership, feature bits,
and required layouts. Unknown or inconsistent input fails closed and reports a
coverage outcome. Each claim needs replay fixtures, negative fixtures, live
amd64 and arm64 images where applicable, and backend flamegraph proof.

Do not implement a generic `allocation` or `heap` eBPF profile. A future
allocation provider must first name its semantics, such as sampled allocated
bytes, and name its runtime and authorization model. Attach-based JVM,
EventPipe, JFR, or similar providers require a separate operator-approved ADR
because they change target state.

## Consequences

The raw CPU-profile event grows by a fixed 520 bytes for the 64-entry kernel
array and its two counters. Enabling kernel stacks adds a second helper call
and increases event transport bandwidth. The default remains unchanged.

The compatibility Kubernetes capability profile can use `SYSLOG` to read
kernel symbol names where the host permits it. The reduced profile deliberately
omits `SYSLOG`; capture may still succeed while names degrade to
`[kernel:unresolved]`. E-Navigator never changes `kptr_restrict`.

Managed-runtime and allocation parity remain explicit gaps, not hidden partial
successes. The detailed feasibility and qualification gates are recorded in
[Profiling parity feasibility](../research/profiling-parity-feasibility.md).

## Validation status

The implementation has deterministic tests for config bounds and opt-in,
event layout and decoding, independent frame budgets, domain-aware stack
identity, bounded kallsyms parsing and cache invalidation, restricted-symbol
fallback, degradation counters and warnings, pprof separation, and OTLP frame
attributes. Linux eBPF build and Docker smoke are release gates. Privileged
periodic capture passed on the local aarch64 OrbStack kernel
`7.0.11-orbstack-00360-gc9bc4d96ac70`, including combined domains and
address-safe kernel frames. Off-CPU/futex kernel semantics, additional target
kernels, loss, and overhead remain required for broader runtime claims.
