# ADR 0003: Pin Direct OTLP Profiles Delivery

Status: accepted

## Context

E-Navigator must send continuous CPU profiles directly to Pyroscope without an
Alloy hop. OpenTelemetry Profiles remains a development-status protocol, and
its protobuf layout has changed incompatibly between revisions. A test that
decodes an encoder with a second copy of the same stale layout does not prove
backend interoperability.

Guara currently pins Grafana Pyroscope server/chart `1.20.3`. That server pins
`go.opentelemetry.io/proto/otlp/collector/profiles/v1development v0.3.0` and
`go.opentelemetry.io/proto/otlp/profiles/v1development v0.3.0`; its HTTP route
is `POST /v1development/profiles` with `application/x-protobuf`.

## Decision

- The generic `sink.otlp_http` profile worker sends the OTLP Profiles
  `v1development` `v0.3.0` wire contract directly to a configured endpoint.
- CPU data uses sample type `samples/count`, period type `cpu/nanoseconds`, and
  the configured sampling period. Pyroscope normalizes this standard shape to
  its `process_cpu:cpu:nanoseconds:cpu:nanoseconds` query type.
- Every profile carries a nonzero stable 16-byte profile ID and a bounded
  resource containing `service.name` plus Kubernetes context. Pyroscope derives
  `service_name` from `service.name`; E-Navigator does not send both names,
  because Pyroscope `1.20.3` rejects the resulting duplicate label.
- Individual delta profile samples are exported. Cumulative
  `ProfilingSessionObservation` signals remain available to native metric and
  JSON surfaces but are not re-exported as profiles, preventing the same sample
  window from being counted repeatedly.
- The profile worker remains independent from trace and metric workers, with
  its own queue, batching, retry, circuit-breaker, and shutdown state.
- Compatibility is proven by an integration smoke against the pinned real
  Pyroscope image and a backend query for representative frames. Unit tests use
  the encoder's single wire definition rather than a second divergent mirror.

## Consequences

Pyroscope is a backend compatibility target at the standard OTLP boundary, not
part of E-Navigator's internal signal model. Upgrading Pyroscope or the OTLP
Profiles modules requires updating this ADR, the wire definition, and the real
backend smoke together. Local smoke proves encoding, ingestion, labels, and
queryability; it does not prove homelab scheduling, eBPF capture, production
retention, or sustained delivery.
