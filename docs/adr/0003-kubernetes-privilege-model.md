# ADR 0003: Start With A Conservative Kubernetes Privilege Model

## Status

Accepted

## Context

The phase 1 DaemonSet must load and attach eBPF programs on Kubernetes nodes. Exact privilege requirements vary by kernel, distribution, container runtime, and cluster policy.

## Decision

Start with a privileged DaemonSet for the first working Kubernetes smoke test. Document this as an initial compatibility choice, not the final security posture.

## Consequences

- The first Kubernetes deployment has the highest chance of working across development clusters.
- Privilege reduction becomes an explicit hardening task after the first eBPF attach path is proven.
- The DaemonSet still uses a dedicated namespace, ServiceAccount, and scoped read-only Kubernetes metadata RBAC.
