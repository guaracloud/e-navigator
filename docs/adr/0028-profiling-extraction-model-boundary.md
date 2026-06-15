# ADR 0028: Profiling Extraction Model Boundary

## Status

Accepted.

## Context

Future profiling sources may use Aya, perf events, runtime APIs, or fixture data. Aya details must not leak into the core signal, processor, generator, or sink layers.

## Decision

Keep an Aya-free `e-navigator-profiling` crate for profile model normalization. It accepts synthetic, fixture-backed, or Aya-source raw profile samples, applies fixed bounds for frame count, symbol/module/file bytes, attributes, and sample counts, and emits normalized profiling signal payloads.

The boundary computes deterministic stack IDs with an opaque bounded hash. It does not symbolize, read procfs, attach eBPF programs, or perform blocking runtime profiling work. Aya and perf-event work remains isolated in `e-navigator-sources-ebpf-aya`.

## Consequences

Aya/perf-event profiling sources translate observed kernel/runtime data into the same bounded model. Phase 9 may emit live CPU profile samples only from the explicit privileged Aya CPU profile source; it still does not claim full continuous profiling backend behavior.
