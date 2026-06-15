# E-Navigator Foundation Design

Date: 2026-06-13
Status: Approved for planning review

## Context

E-Navigator is a Rust-based observability, profiling, security, and diagnostics platform intended to provide zero-configuration visibility for Linux and Kubernetes workloads through eBPF and related system data sources.

The long-term vision includes infrastructure metrics, runtime observability, service discovery, dependency mapping, distributed tracing, continuous profiling, and runtime security. Phase 1 must not attempt to build all of that. Its purpose is to establish a production-grade foundation that can support those capabilities as incremental modules.

## Phase 1 Goal

Build the developer and runtime foundation for E-Navigator:

- A layered Rust workspace.
- A statically registered signal pipeline engine.
- A local Linux runner.
- Kubernetes DaemonSet packaging.
- An Aya-based initial eBPF source for process exec events.
- A typed event model and initial JSON stdout output.
- Developer docs, ADRs, and CI baseline.

Phase 1 should prove that E-Navigator can load an eBPF program, capture process exec signals, route them through the internal pipeline, enrich them where possible, and export them through a sink, both locally and as a Kubernetes node agent.

## Foundational Decisions

### Rust and Aya First

E-Navigator will use Rust as the primary implementation language and Aya as the first eBPF stack. Aya fits the project goal of a Rust-native, low-overhead, high-performance observability agent.

The runner should keep eBPF details behind a source/backend boundary so a future `libbpf-rs` backend can be evaluated if a specific kernel compatibility or probe requirement justifies it.

### Static Registration

E-Navigator will not support runtime-loaded external plugins in phase 1. All capabilities ship as part of the E-Navigator binary and are registered statically at compile time.

Static registration gives better control over safety, performance, binary composition, deployment, and review. Adding a capability should still be straightforward:

1. Add a crate or module.
2. Implement a source, processor, generator, or sink trait.
3. Add a registration line.
4. Add configuration.
5. Add focused tests.

### Pipeline Engine

The core runtime model is:

```text
Sources -> Processors -> Generators -> Sinks
```

- `Source`: produces signals from the outside world.
- `Processor`: enriches, filters, normalizes, batches, samples, or transforms existing signals.
- `Generator`: observes signals and emits derived signals.
- `Sink`: exports or persists signals.

This turns E-Navigator into a signal pipeline engine instead of a single-purpose eBPF runner.

## Architecture

The workspace should be organized around clear ownership boundaries:

- `crates/e-navigator-core`: pipeline traits, module registry, shared config types, shared errors, lifecycle contracts.
- `crates/e-navigator-runner`: runtime orchestration, module lifecycle, pipeline wiring, cancellation, shutdown, and backpressure.
- `crates/e-navigator-signals`: versioned signal schemas, including the initial `ExecEvent`.
- `crates/e-navigator-sources-ebpf-aya`: Aya-based userspace source implementations, starting with process exec.
- `crates/e-navigator-ebpf-programs`: no-std eBPF programs compiled for the kernel side.
- `crates/e-navigator-processors`: processors such as filtering, enrichment, batching, and attribution.
- `crates/e-navigator-generators`: derived signal generators. The interface should exist in phase 1 even if no real generator ships yet.
- `crates/e-navigator-sinks`: output implementations, starting with JSON stdout.
- `crates/e-navigator-cli`: local Linux binary entrypoint.
- `deploy/kubernetes`: DaemonSet, RBAC, security context, namespace/sample manifests, and Kubernetes test assets.
- `docs/adr`: architecture decision records.
- `documentation`: product and vision documentation.

The eBPF implementation details must stay behind source/backend boundaries. Consumers of process exec signals should not need to know how the underlying Aya program is loaded, attached, or decoded.

## Runtime Flow

Phase 1 runtime flow:

```text
Local CLI or Kubernetes DaemonSet container
  -> runner
  -> static module registry
  -> AyaExecSource
  -> SignalEnvelope<ExecEvent>
  -> ContainerAttributionProcessor
  -> JsonStdoutSink
```

Kubernetes deployment should run one DaemonSet pod per node. Each pod runs one `e-navigator` process. Multiple probes, processors, generators, and sinks are modules inside that process, not separate Kubernetes pods.

## Signal Model

Every emitted signal should travel inside a versioned envelope. The envelope should include:

- Signal schema version.
- Signal kind.
- Source module name.
- Timestamp.
- Host identity where available.
- Process identity where relevant.
- Optional container identity.
- Optional Kubernetes context.
- Payload.

The initial payload is `ExecEvent`, representing process execution. It should capture a conservative set of fields that can be reliably obtained early:

- Process ID.
- Parent process ID where available.
- User ID where available.
- Command name.
- Executable path or best available equivalent.
- Arguments if available and safe to capture.
- Cgroup or container hint where available.
- Timestamp.

Argument capture must be bounded to avoid unbounded memory use and sensitive data overexposure. Phase 1 may capture a limited argument representation or defer full argument capture behind an explicit configuration flag.

## Initial Modules

### AyaExecSource

`AyaExecSource` is the first source. It loads and attaches the process exec eBPF program through Aya, decodes kernel events, and emits typed `ExecEvent` signals into the pipeline.

If this source is enabled and cannot load or attach, startup should fail with a non-zero exit code.

### ContainerAttributionProcessor

`ContainerAttributionProcessor` enriches exec events with container or Kubernetes context when available.

Phase 1 attribution may be best-effort. It should be implemented behind a processor boundary so attribution logic can mature independently from the eBPF source.

### JsonStdoutSink

`JsonStdoutSink` serializes signals as newline-delimited JSON to stdout. This is the first operational sink and the simplest way to validate local and Kubernetes runs.

The sink interface should be shaped so future OTLP, file, Prometheus, or storage sinks can be added without changing sources.

### Generator Interface

The generator trait and registration path should exist in phase 1. A production generator is not required in this phase unless it remains trivial and does not expand scope.

Examples of future generators include dependency graph generation, suspicious process detection, and service health summaries.

## Configuration

Phase 1 configuration should support:

- Enabling or disabling known modules.
- Selecting the output sink.
- Setting queue and backpressure limits.
- Configuring log level.
- Configuring bounded exec argument capture behavior.
- Enabling Kubernetes attribution when running in a cluster.

The configuration format should be simple and stable enough for local and Kubernetes use. The CLI should provide clear defaults for local development, while Kubernetes manifests should mount or pass the intended runtime configuration explicitly.

## Error Handling

Startup validates:

- Linux/eBPF prerequisites.
- Required privileges and capabilities.
- Configuration.
- Enabled source load/attach feasibility where possible.
- Output sink availability.
- Kubernetes metadata access when Kubernetes attribution is enabled.

Runtime behavior:

- Required enabled source load/attach failures are fatal.
- Event decode errors are counted, logged with bounded detail, and dropped.
- Pipeline queues are bounded.
- Backpressure behavior is explicit and observable through logs and counters.
- Shutdown detaches probes and drains the pipeline within a deadline.

Phase 1 should prefer clear failure over silent partial operation.

## Kubernetes Packaging

Phase 1 includes Kubernetes packaging for real cluster testing.

The deployment model is:

```text
one Kubernetes node -> one E-Navigator DaemonSet pod -> one E-Navigator process -> many internal modules
```

Manifests should include:

- DaemonSet.
- ServiceAccount.
- RBAC needed for Kubernetes metadata attribution.
- Security context and Linux capabilities required for eBPF.
- Namespace/sample deployment assets.
- Basic configuration.

The privilege model must be documented in an ADR. The initial manifest can be conservative enough to work, but the design should explicitly track the intent to reduce privileges as implementation knowledge improves.

## Local Linux Runner

The local runner should use the same runner library and module registry as Kubernetes. It should be useful for fast development and debugging without requiring a cluster.

Local execution should support:

- Running the exec source.
- Emitting JSON signals to stdout.
- Clear startup validation errors.
- Clear shutdown behavior.

## Developer Foundation

Phase 1 should establish:

- Rust workspace setup.
- Formatting and linting standards.
- Test commands.
- Build commands for userspace and eBPF programs.
- CI for non-privileged checks.
- ADR workflow.
- Local development guide.
- Kubernetes test guide.
- Clear contribution/development documentation.

CI should run checks that do not require kernel privileges by default:

- Format check.
- Clippy.
- Unit tests.
- Workspace build.
- Documentation checks where practical.
- Kubernetes manifest validation where practical.

Privileged eBPF smoke tests should be documented for local Linux and can later move to a self-hosted CI runner.

## Testing Strategy

Phase 1 testing should include:

- Unit tests for signal schemas.
- Unit tests for processors.
- Unit tests for config parsing and validation.
- Unit tests for sinks.
- Integration tests for pipeline wiring without eBPF privileges.
- Documented privileged local Linux smoke test for Aya load/attach behavior.
- Documented Kubernetes smoke test for DaemonSet rollout and exec event visibility.

The design should make most userspace behavior testable without root privileges.

## Non-Goals

Phase 1 does not include:

- Full OpenTelemetry export.
- UI or central backend.
- Long-term storage.
- Network dependency mapping.
- DNS observability.
- Distributed tracing.
- Continuous profiling.
- Runtime-loaded external plugins.
- Cost attribution.
- Capacity planning.
- Production-grade security detection rules.

## Open Follow-Ups For Implementation Planning

Implementation planning should decide:

- Exact Cargo workspace layout and crate dependencies.
- Exact Aya program type and attach point for process exec.
- Signal envelope Rust types.
- Async runtime choice.
- Configuration file format.
- Kubernetes manifest validation tool.
- CI provider and exact job matrix.
- Minimal Linux capabilities required for the first working DaemonSet.

These are implementation details, not changes to the approved phase 1 design.
