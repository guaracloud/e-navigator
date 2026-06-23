# ADR 0032: Live CPU Profiling Source Boundary

## Status

Accepted.

## Context

Phase 8 defined versioned profiling signals, bounded normalization, attribution, generation, and formatter boundaries. Phase 9 needs a real privileged Linux CPU profiling source foundation without turning E-Navigator into a full continuous profiling backend.

CPU profiling sources can create high-cardinality and high-volume data. Stack capture and symbolization can also block or scan unbounded host state if they are mixed into the async runner hot path. Runtime proof must be separated from non-privileged CI proof.

## Decision

Add a statically registered `source.aya_cpu_profile` module in `e-navigator-sources-ebpf-aya`. It is available through the explicit `aya-cpu-profile` source mode and only registers when the static module and `[cpu_profile_source] enabled = true` are configured.

The source uses a Linux perf-event CPU clock probe and emits existing `profile_sample_observation` envelopes with:

- `profiling_kind = cpu`
- `correlation_kind = observed_profile_sample`
- observed timestamp or receive-time fallback
- sample count
- configured sampling period
- observed process identity
- observed thread ID
- bounded frames only when raw frame data is present
- low-cardinality profiling attributes

Do not symbolize stacks, scan procfs for symbols, or run expensive attribution in the source loop. Container and Kubernetes attribution remain processor responsibilities. Missing attribution remains non-fatal and visible through existing `profiling_warning_observation` behavior.

Use bounded defaults for sample frequency, active targets, frames per sample, samples per batch, symbol/module/file bytes, and backpressure. The default ConfigMap keeps the CPU profiling source disabled. The DaemonSet keeps one process per pod and does not add new permissions or mounts for this phase.

## Consequences

Non-privileged CI covers config validation, static registration, raw event decode fixtures, malformed events, stack truncation, process-only attribution, generator enrichment, and synthetic output.

Privileged local Linux CPU profiling may only be claimed after running the explicit CPU profile source mode on a real privileged Linux host and observing `profile_sample_observation` records from `source.aya_cpu_profile`. Kubernetes CPU profiling may only be claimed after running the explicit CPU profile source mode on a privileged Kubernetes node or cluster and observing real `source.aya_cpu_profile` samples from that environment.

Phase 9 does not implement or claim memory allocation profiling, lock profiling, pprof export, OTLP profile export, profile storage, flamegraph UI, trace/profile correlation, bottleneck analysis, profile-backend replacement behavior, or full continuous profiling backend behavior.
