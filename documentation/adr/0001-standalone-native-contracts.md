# ADR 0001: Standalone Native Observability Contracts

- Status: accepted
- Date: 2026-07-17

## Context

E-Navigator is becoming a standalone Kubernetes node observability agent. It
must collect application traces, network topology, continuous CPU profiles,
and collector health without depending on another privileged collector.
Pyroscope remains a profile backend; Tempo and Prometheus-compatible systems
remain possible trace and metric backends.

Interoperability with backends requires standard protocols. It does not
require copying another collector's configuration, metric names, labels, or
runtime model. Vendor-shaped aliases would make the internal contract depend
on an implementation E-Navigator is intended to replace.

## Decision

E-Navigator owns one versioned native contract for observed and derived
signals. The JSON envelope `schema_version` is the compatibility boundary.
Stable fields are additive within a schema version; removal, semantic reuse,
or type changes require a new schema version and a migration note.

The following rules apply to every stable family:

1. Observed facts and inferred relationships are distinct signal kinds.
2. Inference carries a typed correlation kind, confidence, or an explicit
   warning describing missing evidence.
3. Strings, attributes, labels, collections, maps, queues, and caches have
   validated bounds.
4. Secret-like values, raw database values, raw request bodies, credentials,
   and unrestricted URLs are not exported.
5. Loss, truncation, rejection, unsupported runtimes, missing attribution,
   and invalid correlation are observable outcomes, never silent success.
6. Metric names use the `e_navigator_` Prometheus namespace after text-format
   normalization. OTLP metric names use the `e.navigator.` dotted namespace.
7. Metric dimensions describe E-Navigator concepts. Vendor-specific names or
   labels are forbidden.
8. Standard W3C Trace Context, OTLP, Prometheus exposition, pprof protobuf,
   Kubernetes APIs, and OpenTelemetry semantic conventions are allowed at
   well-defined boundaries.

Native stable families cover:

- process lifecycle observations;
- connections, flows, endpoint attribution, and topology edges;
- protocol requests and request/trace spans;
- profile samples, sessions, and symbolization coverage;
- capture, attribution, parsing, correlation, profiling, and export warnings;
- source, controller, queue, exporter, and process health.

Backend encoders translate these native families into standard wire models.
They must not mutate the native model to match a backend product's private
labels. In particular, direct Pyroscope delivery uses the generic OTLP
Profiles sink and does not introduce Pyroscope-specific fields internally.

## Compatibility and testing

Every stable signal kind must have a golden JSON fixture that deserializes and
serializes byte-for-byte at the value level. Additive fields need explicit
defaults and a fixture proving older schema-v1 input remains accepted. Metric
and OTLP mapping tests must assert native names and reject accidental vendor
aliases.

Capability documentation may say `implemented` when deterministic tests pass.
It may say `homelab proven` only with a recorded Linux/Kubernetes run. It may
say `production ready` only after matched performance trials and the required
soak have passed.

## Consequences

Guara consumers will migrate from existing collector-specific queries to
E-Navigator's native contracts. During the migration, translation belongs in
the consumer or telemetry backend, not in E-Navigator. E-Navigator does not
offer vendor modes, configuration emulation, or runtime compatibility shims.
