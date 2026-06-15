# ADR 0025: Request Attribution Behavior

## Status

Accepted.

## Context

Request-derived signals need the same process, container, Kubernetes, host, and peer attribution behavior as existing network and DNS observations.

## Decision

The container attribution processor enriches protocol request observations, extracted trace-context observations, request span observations, and request correlation warnings using existing container IDs and the Kubernetes metadata cache. It does not perform PID-to-cgroup procfs lookup for request/protocol hot-path signals; sources that can observe process/container context should attach it before emitting. Missing attribution remains non-fatal.

The request correlation generator preserves process, container, Kubernetes, host, peer, method, status, trace context, confidence, and source correlation fields from the originating protocol observation. Missing attribution is emitted as a structured request correlation warning.

## Consequences

No new Kubernetes permissions are required. Attribution failures are visible without dropping signals or inventing workload identity.
