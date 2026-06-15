# ADR 0031: Profiling Export Mapping

## Status

Accepted.

## Context

Future profile export may target pprof or OTLP profiles, but Phase 8 must not claim production pprof or OTLP profile export.

## Decision

Add an internal `e-navigator.profile.internal.v1` formatter boundary for profile sample and profiling session signals. The formatter owns canonical fields such as profile ID, profile kind, correlation kind, confidence, sample counts, stack ID, frame count, window, resource, and bounded attributes.

Custom attributes are bounded by count, key bytes, and value bytes. Sensitive keys containing token, authorization, cookie, password, or secret are filtered. Custom attributes cannot overwrite canonical formatter fields.

## Consequences

JSON stdout remains newline-delimited `SignalEnvelope` JSON. The formatter gives future pprof or OTLP profile exporters a stable mapping point without claiming those exporters exist.
