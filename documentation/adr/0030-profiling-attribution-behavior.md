# ADR 0030: Profiling Attribution Behavior

## Status

Accepted.

## Context

Profile samples may lack process, container, or Kubernetes metadata. Live CPU samples from `source.aya_cpu_profile` can initially carry only host, process, and thread context. Attribution failures must not stop the pipeline or silently invent context.

## Decision

Reuse the existing container attribution processor for profile sample, stack trace, session, and warning payloads. Observed CPU samples preserve their `source.aya_cpu_profile` provenance and `observed_profile_sample` correlation kind while the processor enriches container and Kubernetes context where available. If a profile-derived generator path cannot attribute a sample to container or Kubernetes context, emit an explicit structured `profiling_warning_observation`.

Do not add Kubernetes permissions for Phase 9. The existing pod metadata list permission remains the only Kubernetes metadata access used by attribution.

## Consequences

Profile-derived signals preserve host, source, process, thread, container, and Kubernetes context when available. Missing attribution remains non-fatal and visible.
