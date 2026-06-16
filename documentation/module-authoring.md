# Module Authoring Guide

E-Navigator modules are compiled into the node agent and registered statically. Do not introduce runtime-loaded plugins.

## Sources

- Implement `Source<SignalEnvelope>`.
- Emit only versioned `SignalEnvelope` payloads.
- Keep reads bounded by configured or local limits.
- Treat enabled source attach/load failures as fatal unless an ADR and test define optional behavior.
- Put eBPF, perf-event, or OS-specific unsafe code behind source crate boundaries.

## Processors

- Implement `Processor<SignalEnvelope>`.
- Enrich observed context without overwriting observed fields.
- Missing attribution is non-fatal unless a specific source contract says otherwise.
- Avoid network calls in hot paths unless bounded by timeout and configuration.

## Generators

- Implement `Generator<SignalEnvelope>`.
- Keep maps, caches, queues, and seen sets bounded.
- Emit low-cardinality derived signals.
- Do not invent request IDs, routes, trace IDs, application errors, retries, or profile semantics from lower-confidence inputs.
- A generator must not depend on runtime plugin loading. If it depends on another generator's output, document and test the static generator order.

## Sinks

- Implement `Sink<SignalEnvelope>`.
- Preserve schema stability at the sink boundary.
- Formatter boundaries may be OTEL-compatible or profile-compatible, but they are not production exporters until transport, retry, batching, timeout, backpressure, and integration tests exist.

## Adding A Signal Family

1. Add payload types in `crates/e-navigator-signals`.
2. Add `SignalKind`, `SignalPayload`, constructors, and serde round-trip tests.
3. Add processor/generator/sink handling through exhaustive matches.
4. Add synthetic or fixture output only when the data is explicitly observed or marked synthetic.
5. Update ADRs, README, `documentation/claims-matrix.md`, and smoke tests.
