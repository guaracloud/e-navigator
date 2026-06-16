# ADR 0023: Protocol Context Extraction Boundary

## Status

Accepted.

## Context

Future Aya/eBPF sources may capture bounded protocol bytes or metadata. Shared parsing must not leak Aya details outside Aya source crates, and parsers must be bounded so they can be used safely near hot paths.

## Decision

Introduce `e-navigator-protocol` as an Aya-free protocol extraction boundary. The crate contains bounded HTTP fixture parsing and strict W3C traceparent parsing.

The boundary enforces fixed maximum header bytes, request-line bytes, attribute count, and tracestate bytes. W3C `traceparent` validation checks version, reserved version `ff`, lowercase hex encoding, 16-byte trace ID, 8-byte span ID, flags, malformed lengths, and all-zero IDs. `tracestate` is treated as bounded opaque text inside the extraction boundary and is not serialized into emitted SignalEnvelope JSON by default.

## Consequences

Synthetic and fixture-backed protocol extraction can be tested without eBPF privileges. Live HTTP/gRPC payload capture from Aya sources remains deferred and must not be claimed until a source actually supplies bounded protocol bytes in a privileged Linux environment.
