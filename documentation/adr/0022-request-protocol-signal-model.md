# ADR 0022: Request And Protocol Signal Model

## Status

Accepted.

## Context

Phase 7 needs request-level tracing foundations without claiming full distributed tracing or live HTTP/gRPC parsing from the current Aya sources. Existing trace-foundation schemas describe generic trace spans, service interactions, service paths, and trace-correlation warnings. Request observations need a separate versioned signal family so protocol-observed data is not confused with TCP or dependency inference.

## Decision

Add versioned SignalEnvelope-compatible payloads for protocol request observations, extracted trace-context observations, request span observations, and request correlation warnings.

Request payloads carry optional `trace_id`, `span_id`, and `parent_span_id` fields only when observed or explicitly synthetic. Raw `traceparent` and `tracestate` may be used in-memory by protocol fixtures and future bounded sources for extraction, but they are not serialized into emitted SignalEnvelope JSON by default; parsed identifiers and warnings carry the observable result without logging opaque vendor state. Request payloads preserve host, process, container, Kubernetes, peer, protocol, timing, correlation kind, confidence, and bounded attributes.

Span names remain low-cardinality by default: `http request`, `grpc request`, or `protocol request`. Raw paths, domains, and IP addresses are not used as span names.

## Consequences

Request-derived signals can coexist with existing exec, process exit, lifecycle, network, DNS, dependency, resource metric, security finding, and Phase 6 trace signals. The schema does not claim production OTLP trace export, request storage, UI, route discovery, retries, errors, or application-level semantics unless those fields are actually observed.
