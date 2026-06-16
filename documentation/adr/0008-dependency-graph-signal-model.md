# ADR 0008: Dependency Graph Signal Model

Date: 2026-06-14
Status: Accepted

## Context

Phase 3 needs dependency visibility from runtime network observations while preserving the signal pipeline model. Derived dependency data must be versioned, deterministic, low-noise, and compatible with future storage, UI, and OTLP export.

## Decision

E-Navigator adds a statically registered `generator.dependency_graph` generator. It observes network connection open and close signals and emits versioned `dependency_edge` signals.

Each edge includes:

- source workload context when attribution is available,
- source container context when available,
- destination workload context only when it is known,
- external destination address and port when workload identity is not known,
- protocol,
- observation count,
- first seen and last seen timestamps.

The generator suppresses duplicate output for identical observations. Its in-memory edge state is bounded by a configurable maximum in code, with a conservative default.

## Consequences

Phase 3 dependency edges are justified by observed network signals instead of broad inference. The model is intentionally compatible with future DNS, service lookup, storage, and UI layers, but this phase does not claim complete service maps.
