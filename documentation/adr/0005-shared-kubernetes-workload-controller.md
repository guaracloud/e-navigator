# ADR 0005: Shared Kubernetes Workload Controller

Status: accepted

Date: 2026-07-17

## Context

Capture filtering and Kubernetes attribution previously maintained independent
node pod-list clients. Besides duplicate API work, their refresh timing could
produce contradictory workload decisions during pod churn. Periodic lists also
leave a longer bootstrap window than an event stream.

## Decision

One process-global, node-scoped controller owns pod API access. It performs a
bounded initial list, watches from that list's `resourceVersion`, applies
ADDED, MODIFIED, DELETED, and BOOKMARK events to a bounded raw-pod snapshot,
and relists at the five-minute watch timeout. HTTP or watch-object 410 responses
cause an immediate relist. Other list/watch failures use capped exponential
backoff while the last successful snapshot remains available.

The snapshot includes only filter/attribution primitives: namespace, pod name
and UID, node, pod IP, bounded labels, and container IDs/names. The capture
controller derives cgroup verdicts from it. The production attribution
processor derives its container-ID and pod-IP indexes from the same snapshot;
it performs no Kubernetes API request.

RBAC grants only `list` and `watch` on core `pods`. Fixed native Prometheus
metrics report readiness, freshness, relists, failures, watch starts,
resource-version expiration, reconciliation count, pod count, and current
allowed/denied/unresolved cgroup counts.

## Consequences

- Capture and attribution observe one coherent pod generation.
- Pod churn normally reaches the controller through watch events instead of a
  periodic list delay.
- The cgroup filesystem is still scanned every two seconds, so a new pod can
  briefly follow the configured unknown-cgroup posture after its watch event.
- Owner and Service/NAT indexes are not implied by this ADR and remain separate
  topology work.
