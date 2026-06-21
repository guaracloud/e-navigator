# Engineering Invariants

These invariants are part of the userspace quality gate. They are intentionally narrower than product claims.

## Runtime And Modules

- Runtime modules are statically registered. Do not introduce runtime plugin loading.
- The local CLI and Kubernetes DaemonSet must use the same runner path.
- At least one source and one sink are required for a runnable pipeline.
- Source failures are fatal unless a future test proves a specific source is optional and non-fatal.
- Sink write failures are non-fatal: the runner logs the failing sink, drops
  that signal for that sink, and continues sending the same signal to remaining
  sinks. This keeps collector/export outages from crashing live sources.
- Generators must be bounded. A generator may not emit more than the runner's per-input derived-signal limit.
- Queues, caches, aggregation maps, and seen-key sets must have explicit configured or local bounds.
- Module authoring rules live in `documentation/module-authoring.md`.
- Evidence-backed product claims live in `documentation/claims-matrix.md`.

## Parsers And Decoders

- Parsers must reject malformed input without panics.
- Procfs, sysfs, cgroup, HTTP fixture, traceparent, profile fixture, and raw Aya decode helpers must be testable without privileges.
- Decode helpers must reject short buffers, unknown event types, unknown address families, unknown protocols, zero profile samples, and malformed fixtures without inventing context.
- Truncation must be deterministic and UTF-8 safe.
- Property-style parser tests are part of the non-privileged gate for traceparent parsing, HTTP fixture extraction, profile normalization, cgroup/container ID extraction, and envelope round trips.

## Attribution And Sensitivity

- Raw sensitive request/profile attributes must not pass through by default.
- Compatibility metrics must expose only their documented low-cardinality label
  set; raw addresses, ports, payloads, SQL text, request bodies, packet
  captures, and sensitive arguments must stay out of default exports.
- Derived trace, request, profile, and dependency signals must not invent high-confidence context from low-confidence observations.
- Missing attribution is non-fatal for generators, but it must remain visible through structured warning signals where the generator owns that warning behavior.
- Container and Kubernetes attribution should enrich existing context, not overwrite observed context.

## Privileged Boundaries

- Privileged Aya/eBPF behavior is separate from non-privileged proof.
- Non-privileged tests may prove raw decode, parser, formatter, generator, runner, and manifest validity.
- Live Aya/eBPF, perf-event profiling, DNS runtime visibility, and Kubernetes runtime behavior may only be claimed after running on a real Linux host or Kubernetes cluster with the documented privileges.
- Privileged proof commands and non-claims live in `documentation/privileged-runtime-proof.md`.

## Exporter Boundaries

- OTEL metric/trace and profile formatter records are internal export boundaries.
- Registered HTTP sinks must be distinguished from live collector/backend proof.
  Local fake-collector tests prove transport behavior only.
- Do not claim production OTLP, pprof, Pyroscope, exporter retry, exporter batching, or exporter storage behavior until real exporters and integration tests exist.
- Exporters must define batching, timeout, retry, backpressure, bounded queues,
  auth/header handling, and drop accounting before adding protocol-specific
  production transport claims.

## Fuzz Targets

Cargo-fuzz is wired as an excluded `fuzz/` crate so the normal workspace gate
does not build libFuzzer artifacts. Fuzz targets are non-privileged parser and
userspace decode checks only; they must not attach eBPF programs, read real
`/proc` or `/sys`, contact Kubernetes, use Docker, or open network sockets.

Run bounded local smoke fuzzing with:

```bash
cargo fuzz run traceparent_parser -- -max_total_time=60
cargo fuzz run http_request_parser -- -max_total_time=60
cargo fuzz run profile_fixture_parser -- -max_total_time=60
cargo fuzz run host_procfs_parsers -- -max_total_time=60
cargo fuzz run raw_exec_event_decode -- -max_total_time=60
cargo fuzz run raw_network_event_decode -- -max_total_time=60
cargo fuzz run raw_cpu_profile_event_decode -- -max_total_time=60
```

The target functions are:

- `e_navigator_protocol::trace_context::parse_traceparent`
- `e_navigator_protocol::http::parse_http_request`
- `e_navigator_profiling::model::parse_profile_fixture`
- `e_navigator_sources_host::{parse_cpu_stat, parse_loadavg, parse_meminfo, parse_diskstats, parse_process_stat}`
- feature-gated Aya userspace raw decode fuzz entry points for exec, network,
  and CPU profile sample events
