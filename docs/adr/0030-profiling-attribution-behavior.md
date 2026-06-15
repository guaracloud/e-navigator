# ADR 0030: Profiling Attribution Behavior

## Status

Accepted.

## Context

Profile samples may lack process, container, or Kubernetes metadata. Attribution failures must not stop the pipeline or silently invent context.

## Decision

Reuse the existing container attribution processor for profile sample, stack trace, session, and warning payloads. If a profile-derived generator path cannot attribute a sample to container or Kubernetes context, emit an explicit structured `profiling_warning_observation`.

Do not add Kubernetes permissions for Phase 8. The existing pod metadata list permission remains the only Kubernetes metadata access used by attribution.

## Consequences

Profile-derived signals preserve host, source, process, container, and Kubernetes context when available. Missing attribution remains non-fatal and visible.
