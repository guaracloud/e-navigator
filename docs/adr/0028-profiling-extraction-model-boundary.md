# ADR 0028: Profiling Extraction Model Boundary

## Status

Accepted.

## Context

Future profiling sources may use Aya, perf events, runtime APIs, or fixture data. Aya details must not leak into the core signal, processor, generator, or sink layers.

## Decision

Keep an Aya-free `e-navigator-profiling` crate for profile model normalization. It accepts synthetic or fixture-backed raw profile samples, applies fixed bounds for frame count, symbol/module/file bytes, attributes, and sample counts, and emits normalized profiling signal payloads.

The boundary computes deterministic stack IDs with an opaque bounded hash. It does not symbolize, read procfs, attach eBPF programs, or perform blocking runtime profiling work.

## Consequences

Aya/perf-event profiling sources can later translate observed kernel/runtime data into the same bounded model. Phase 8 does not claim live profiling observation.
