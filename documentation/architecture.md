# Architecture

E-Navigator is a node-local Rust process with a statically registered signal
pipeline. It captures bounded observations, adds evidence-backed workload
context, derives native telemetry, and exports through bounded sinks.

```text
Linux kernel and host filesystems
             |
          Sources
             |
   bounded signal channel
             |
         Processors
             |
         Generators
             |
           Sinks
             |
 JSON, Prometheus, OTLP HTTP, local pprof
```

Runtime plugin loading is intentionally absent. Configuration can enable or
disable registered modules, but it cannot load arbitrary code.

## Workspace Map

| Crate | Responsibility |
| --- | --- |
| `e-navigator-core` | Module traits, runtime configuration, errors, capture policy, and pipeline contracts |
| `e-navigator-signals` | Versioned signal envelopes and bounded signal models |
| `e-navigator-protocol` | Bounded protocol parsing, stream reassembly, and trace-context parsing |
| `e-navigator-profiling` | Profile models, normalization, symbolization, JIT support, and unwind tables |
| `e-navigator-sources-host` | Host resource observations from procfs, sysfs, and cgroups |
| `e-navigator-sources-ebpf-aya` | Aya loaders, dual RingBuf/perf event readers, raw-event decoding, protocol capture, TLS uprobes, and CPU profiling |
| `e-navigator-processors` | Container and Kubernetes attribution plus workload filtering |
| `e-navigator-generators` | Metrics, dependency edges, request spans, profile sessions, trace paths, and security findings |
| `e-navigator-sinks` | JSON, Prometheus, OTLP HTTP, and local pprof formatting and delivery |
| `e-navigator-runner` | Source supervision, bounded dispatch, derivation budgets, and sink lifecycle |
| `e-navigator-cli` | CLI arguments, configuration loading, static registry construction, and synthetic mode |
| `e-navigator-ebpf-programs` | Kernel-side eBPF programs built with the pinned nightly toolchain |

## Startup Lifecycle

1. The CLI parses arguments and loads either the strict TOML configuration or
   the Rust defaults.
2. Configuration validation rejects unknown fields, invalid endpoints,
   inconsistent bounds, and unsupported module names before capture starts.
3. The CLI constructs one static registry from the enabled modules.
4. The runner starts bounded sink workers and enabled sources.
5. Under the chart's `isolate` source policy, one failed source is reported and
   healthy sources continue. The Rust configuration default remains
   `fail_fast` for compatibility.
6. SIGINT or SIGTERM stops sources, closes the accepted-signal path, and gives
   sinks a bounded interval to drain.

## Signal Lifecycle

Every observation enters the runner as a versioned `SignalEnvelope`.

1. The runner accepts a source signal through a bounded channel.
2. Processors may enrich or drop it. Attribution is attached only when the
   evidence supports it.
3. Each accepting generator derives zero or more native signals. Synchronous
   generators use the immediate path to avoid an unnecessary Tokio channel.
   The async trait path remains available for generators that need it.
4. Per-generator output, total derivation breadth, and derivation depth are
   bounded. A generator cannot create an unbounded cascade.
5. Sinks receive the original and accepted derived signals. One sink failure
   is logged and isolated from other sinks.

The pipeline preserves determinism where it matters. Bounded ordered maps are
used for stable cardinality and repeatable output when their small, configured
limits make that tradeoff appropriate.

## Privileged Boundary

Kernel programs emit fixed raw event layouts. Userspace verifies event size,
decodes with explicit unsafe boundaries where required, validates parser
limits, and converts raw data into safe Rust models. The host and Aya crates
are the only workspace areas that permit the unsafe operations needed for FFI
and raw event decoding. Other workspace crates forbid unsafe code.

An eBPF program compiling is not runtime proof. Kernel, capability, ABI,
uprobe, perf-event, and workload differences require guarded Linux or
Kubernetes evidence before a public capability claim changes.

## Kubernetes Workload Control

One bounded controller owns Pod, Service, and EndpointSlice discovery. Capture
filtering and attribution consume the same snapshot, which prevents two API
clients from disagreeing during normal Pod churn. Pod events are watched,
while Service and EndpointSlice state refreshes on the bounded relist cycle.

The capture filter controls whether selected workload cgroups are probed. The
attribution selectors control which metadata is retained for enrichment. They
are separate policies and should not be treated as interchangeable.

## Export Isolation

Metrics, traces, and profiles have independent OTLP queues and workers. Each
worker owns bounded batching, timeout, retry, circuit-breaker, and shutdown
state. Destination I/O never runs on the shared signal path, so a failed
profile destination cannot block metric or trace capture.

Prometheus reads native process counters directly. This keeps queue loss,
retry, rejection, and circuit state observable even when an OTLP destination
is unavailable.

## Stable Boundaries

- Signals are native E-Navigator contracts, not compatibility aliases for
  another collector.
- E-Navigator is a collector and signal plane, not a storage backend or UI.
- Bounded memory, cardinality, parser input, retry, and shutdown behavior are
  part of the architecture.
- Claims are promoted only when the matching evidence tier exists.

See [engineering invariants](engineering-invariants.md) for change rules and
the [ADR index](README.md#architecture-decisions) for accepted decisions.
