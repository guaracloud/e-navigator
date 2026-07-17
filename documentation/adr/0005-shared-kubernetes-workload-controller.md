# ADR 0005: Shared Kubernetes Workload Controller

Status: accepted

Date: 2026-07-17

## Context

Capture filtering and Kubernetes attribution previously maintained independent
node pod-list clients. Besides duplicate API work, their refresh timing could
produce contradictory workload decisions during pod churn. Periodic lists also
leave a longer bootstrap window than an event stream.

## Decision

One process-global controller owns Kubernetes workload API access. Its Pod list
is node-scoped by default and cluster-wide when
`attribution.kubernetes.allow_cluster_wide_pod_list=true`; the standalone Guara
preset enables the latter so cross-node destinations can be attributed. Local
Pods are retained before remote Pods when `max_pods` truncates a cluster-wide
snapshot, preserving the cgroup-filter join for this DaemonSet member. The
controller performs a bounded initial Pod list, watches from that list's
`resourceVersion`, applies
ADDED, MODIFIED, DELETED, and BOOKMARK events to a bounded raw-pod snapshot,
and relists at the five-minute watch timeout. HTTP or watch-object 410 responses
cause an immediate relist. Other list/watch failures use capped exponential
backoff while the last successful snapshot remains available.

The same reconciliation lists bounded core Services and discovery-v1
EndpointSlices. The snapshot includes namespace, Pod name and UID, node, Pod
IP, bounded labels, container IDs/names, controller-derived stable workload
owner, Service ClusterIPs, and ready EndpointSlice addresses. Pod watch events
retain the latest Service and EndpointSlice generation; those resources refresh
at the next bounded relist rather than through independent watches. The capture
controller consumes only Pod primitives. The production attribution processor
derives container-ID, Pod-IP, workload-owner, Service-IP, and fallback
EndpointSlice-address indexes from the same snapshot; it performs no Kubernetes
API request.

Pod identity always wins over Service identity for an address. A ClusterIP is
identified as a qualified `namespace/name` Service owner but is never claimed
as one particular backend Pod. EndpointSlice addresses receive Service
ownership only when no Pod identity exists. ReplicaSet owners carrying the
Pod's `pod-template-hash` are normalized to their stable Deployment name;
other controller kinds retain their Kubernetes owner name and lowercase kind.

RBAC grants `list` and `watch` on core Pods and Services plus discovery-v1
EndpointSlices. Fixed native Prometheus metrics report readiness, Pod-watch
freshness, full-resource-relist freshness, relists, failures, watch starts,
resource-version expiration, reconciliation
count, Pod/Service/EndpointSlice counts, and current
allowed/denied/unresolved cgroup counts.

## Consequences

- Capture and attribution observe one coherent workload snapshot generation.
- Pod churn normally reaches the controller through watch events instead of a
  periodic list delay.
- The cgroup filesystem is still scanned every two seconds, so a new pod can
  briefly follow the configured unknown-cgroup posture after its watch event.
- The two cache groups are independently bounded by `max_cache_entries`:
  container/Pod-IP context entries and owner/address topology entries. Total
  retained metadata is therefore bounded by twice that value, in addition to
  the Pod/Service/EndpointSlice list and response-size bounds.
- Connection lifecycle and byte-flow topology remains client-owned: only the
  initiating `connect` side emits it, so two DaemonSet agents do not count the
  same TCP flow twice. Server-side request spans are a separate trace signal,
  not a second flow observation.
- Service and EndpointSlice changes can be stale until the next five-minute
  relist. This is explicit and observable through the separate full-resource
  relist freshness metric; a
  future independent watch may reduce that window without creating another
  controller or API client.
