# ADR 0005: Kubernetes Metadata Attribution Strategy

Date: 2026-06-14
Status: Accepted

## Context

Runtime process signals are most useful in Kubernetes when they include workload context. Phase 1 had a placeholder attribution processor. Phase 2 needs real best-effort attribution without making process visibility depend on Kubernetes API success.

## Decision

E-Navigator attributes process signals in two steps:

1. Parse bounded `/proc/<pid>/cgroup` metadata to identify container IDs for Docker, containerd, and CRI-O style cgroup paths.
2. When running in-cluster, build a Kubernetes metadata cache from the Kubernetes API using the pod service account token and CA bundle.

The cache maps container IDs to namespace, pod name, pod UID, container name, node name, and labels. RBAC is limited to pod and node metadata. Attribution failures are non-fatal; the processor leaves missing context as `null` and emits structured warnings through tracing.

## Consequences

Attribution quality depends on host procfs visibility, cgroup format, and Kubernetes API reachability. The DaemonSet uses mounted host procfs/cgroup paths and a mounted config without joining the host PID namespace, but the same CLI runner path is used locally and in Kubernetes.
