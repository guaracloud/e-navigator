# ADR 0017: OpenTelemetry zero-code coexistence suppression

- Status: accepted
- Date: 2026-08-22

## Context

E-Navigator can observe protocol requests in workloads that also create
application spans through an OpenTelemetry SDK or zero-code agent. Exporting a
second E-Navigator request span for the same operation creates misleading
duplicates. Presence of generic `OTEL_*` configuration, a loaded API library,
or an incoming `traceparent` does not prove that the process produces spans.
Reading arbitrary process environment data would also create a secret-exposure
risk unless the inspection is strictly bounded and never exported.

The request-correlation generator is the narrow suppression seam. Network,
resource, security, and profile observations do not pass through it, so they
can remain available independently of application-span coexistence policy.

## Decision

Add disabled-by-default `request_correlation.suppress_otel_sdk_spans`. When it
is enabled, inspect at most 64 KiB each from the observed process's procfs
`environ` and `cmdline` files. Recognize only documented zero-code launch
markers for the OpenTelemetry Java agent, Node.js auto-instrumentation register
module, .NET profiler or startup hook, and Python auto-instrumentation path or
launcher. Never log, export, or retain the inspected file contents.

Treat `OTEL_SDK_DISABLED`, a `none` traces exporter, an `always_off` sampler,
and the corresponding supported runtime controls as explicit negative
evidence. Generic configuration is not positive evidence. Unreadable,
oversized, malformed, renamed, custom, or unknown mechanisms fail open and
retain the E-Navigator span.

Cache decisions only when `/proc/<pid>/stat` supplies a process start time.
The cache key also carries the observed command, executable, and cgroup id to
avoid reusing evidence across a changed identity, and retains at most 4,096
processes with deterministic oldest-entry eviction. A positive decision
suppresses the request span and emits a bounded
`otel_sdk_span_suppressed` request-correlation warning once per pid and source.
The input observation and every other generator remain unchanged.

## Consequences

This policy avoids false positive suppression from configuration alone and
does not expose environment values. It adds bounded procfs reads on the first
request for an identity and a mutex-protected bounded cache thereafter. The
feature requires the same host-procfs visibility already used for workload
attribution.

This is not complete SDK coexistence detection. Manual SDK setup, Java Spring
Boot or Quarkus SDK integration, renamed agents, custom Node loaders, Python
launchers that remove every marker, PHP, Go, Ruby, and actual exporter-activity
detection remain unclaimed. Strict parity requires independently proven
runtime export-activity evidence rather than broader string matching.

## Validation status

Configuration defaults and parsing, official marker families, trace-disabled
negative evidence, generic-configuration false positives, request-span-only
suppression, bounded warning deduplication, and retention of the L4 generator
boundary have deterministic local tests. Live workload/exporter coexistence
and production overhead remain required before enabling this option by
default.
