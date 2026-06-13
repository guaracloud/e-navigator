# ADR 0002: Use Static Pipeline Registration

## Status

Accepted

## Context

E-Navigator needs to make it easy to add sources, processors, generators, and sinks while keeping the node agent predictable and reviewable.

## Decision

All phase 1 modules are compiled into the binary and registered statically in code.

## Consequences

- Deployment is a single node-agent binary.
- Runtime-loaded external plugins are outside phase 1.
- New capabilities are added by implementing a pipeline trait, registering the module, adding config, and adding tests.
