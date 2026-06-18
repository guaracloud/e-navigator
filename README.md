# E-Navigator

E-Navigator is a Rust and eBPF observability, security, profiling, and diagnostics platform for Linux and Kubernetes workloads.

Phase 9 builds a live CPU profiling source foundation on the bounded runtime, network, DNS, dependency, security, resource, trace-correlation, request-correlation, profiling, and export-boundary foundations:

- A layered Rust workspace.
- A statically registered signal pipeline.
- A local Linux runner.
- Kubernetes DaemonSet packaging.
- An Aya process exec and process exit source.
- An Aya TCP-oriented network connect/failure and fd-close duration source.
- Bounded, configurable argv capture.
- Best-effort container and Kubernetes attribution.
- Bounded network metric generation for connection counts, failures, durations, active connection gauges, traffic destinations, and protocol distribution.
- DNS query/response schemas, synthetic DNS fixtures, and bounded DNS metric/dependency generation from DNS signals.
- Versioned resource observation schemas for node CPU/load/memory/filesystem/disk, process resources, and cgroup/container CPU, memory, process/thread, fd, and socket counts where available.
- A non-privileged bounded host resource source for procfs, sysfs, and cgroup v2 files with configurable roots and sampling limits.
- A bounded resource metric generator for low-cardinality node, process, and cgroup/container metrics.
- A dependency graph generator for observed network edges.
- Versioned trace-foundation schemas for trace span observations, service interaction span observations, service path observations, and trace correlation warnings.
- A bounded trace correlation generator for network-inferred service interactions, direct/upstream dependency-edge service paths, DNS-derived service paths, duplicate suppression, and missing-attribution warnings.
- Versioned request/protocol schemas for protocol request observations, extracted trace-context observations, request span observations, and request correlation warnings.
- An Aya-free bounded protocol extraction boundary for fixture-backed HTTP request headers, strict W3C traceparent validation, and non-serialized raw trace-context headers by default.
- A bounded request correlation generator for protocol-observed and explicitly synthetic request spans, duplicate suppression, missing or malformed trace-context warnings, and missing-attribution warnings.
- A narrow runtime security generator for process and network findings.
- An internal OTEL-compatible metric formatter boundary for future exporters.
- An internal OTEL-compatible trace formatter boundary for future exporters.
- Versioned profiling schemas for profile sample observations, stack trace observations, profiling session/window observations, and profiling warning observations.
- An Aya-free profiling model boundary for synthetic and fixture-backed profile normalization with bounded stack frames, bounded symbol/module/file bytes, bounded attributes, and deterministic stack IDs.
- A statically registered, opt-in `source.aya_cpu_profile` source mode that attaches a Linux perf-event CPU clock sampler and emits bounded observed CPU profile sample envelopes when run with the required privileges.
- A bounded profiling generator that summarizes explicit observed or synthetic profile sample signals into profiling session/window observations without inferring profiles from raw CPU or resource metrics.
- Existing processor-based profile attribution for host, process, container, and Kubernetes context where available, with structured warning signals for missing attribution.
- An internal profile-compatible formatter boundary for future pprof or OTLP profile exporters.
- Synthetic profiling fixtures and Aya CPU profile source decode fixtures for CPU samples, missing stacks/symbols, oversized stack truncation, malformed events, and process-only attribution.
- JSON stdout output.

Phase 9 is a CPU profiling source foundation, not a full continuous profiling backend, Pyroscope replacement, pprof server, OTLP profile exporter, flamegraph UI, profile storage layer, trace/profile correlation engine, or workload bottleneck analyzer. Synthetic and fixture-backed profiling signals exist. Live CPU profile sample ingestion is implemented only through the explicit privileged `aya-cpu-profile` source mode and may only be claimed after running it on a real Linux host where samples are observed. Memory allocation profiling, lock contention profiling, host runtime profiling accuracy, production pprof export, and production OTLP profile export are not implemented. Synthetic and fixture-backed HTTP trace-context extraction exists. Live HTTP/gRPC parsing from real traffic, request IDs, routes, retries, application errors, full OTLP trace export, production trace storage, UI, critical path analysis, and runtime DNS packet capture are not implemented. The Aya network source remains TCP-oriented. Host resource accuracy depends on running on Linux with the configured host procfs/sysfs/cgroup mounts.

## Kubernetes Install

Install the OCI Helm chart on a capable Linux cluster:

```bash
helm upgrade --install e-navigator oci://ghcr.io/guaracloud/charts/e-navigator \
  --version 0.1.0 \
  --namespace e-navigator-system \
  --create-namespace
```

The chart deploys the current privileged DaemonSet model with read-only host
mounts, Kubernetes metadata RBAC, and the default bounded config. For local chart
development or dev-channel images:

```bash
helm upgrade --install e-navigator charts/e-navigator \
  --namespace e-navigator-system \
  --create-namespace \
  --set image.tag=main
```

Before production use, verify release checksums, signatures, SBOMs, image
digests, and the chart digest with `documentation/release-verification.md`.
Detailed chart configuration is in `documentation/helm.md`. Raw manifests remain
available under `deploy/kubernetes/` for review and development fallback.

## Development

Run the strict local quality gate:

```bash
scripts/quality.sh
```

The strict script fails if required supply-chain tools are missing: `cargo-deny`, `cargo-audit`, and `cargo-machete`. For constrained local environments only, set `E_NAVIGATOR_SKIP_SUPPLY_CHAIN=1` to run the Rust checks without the supply-chain checks.

Direct non-privileged checks:

```bash
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets --exclude e-navigator-ebpf-programs -- -D warnings
cargo test --locked --workspace --exclude e-navigator-ebpf-programs
cargo build --locked --workspace --exclude e-navigator-ebpf-programs
cargo run --locked -p e-navigator-cli -- --source synthetic
helm lint charts/e-navigator
helm template e-navigator charts/e-navigator
cargo deny check
cargo audit
cargo machete
docker build -f Containerfile -t e-navigator:local .
docker run --rm e-navigator:local --source synthetic
tests/smoke_docker.sh e-navigator:local
git diff --check
```

`cargo deny` currently keeps duplicate dependency versions at warning level in `deny.toml`. This keeps the gate focused on actionable license, advisory, source, yanked, and unused-dependency failures while transitive ecosystem convergence is tracked without blocking unrelated systems work.

Aya/eBPF development also requires the nightly Rust toolchain with `rust-src`, `bpf-linker`, and `bpftool`.

See:

- `CONTRIBUTING.md`
- `documentation/engineering-invariants.md`
- `documentation/claims-matrix.md`
- `documentation/helm.md`
- `documentation/release-verification.md`
- `documentation/module-authoring.md`

## Verification

Non-privileged checks:

```bash
scripts/quality.sh
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets --exclude e-navigator-ebpf-programs -- -D warnings
cargo test --locked --workspace --exclude e-navigator-ebpf-programs
cargo build --locked --workspace --exclude e-navigator-ebpf-programs
cargo run --locked -p e-navigator-cli -- --source synthetic
helm lint charts/e-navigator
helm template e-navigator charts/e-navigator
cargo deny check
cargo audit
cargo machete
docker build -f Containerfile -t e-navigator:local .
docker run --rm e-navigator:local --source synthetic
tests/smoke_docker.sh e-navigator:local
git diff --check
```

The `aya-exec` source mode registers the statically compiled Aya exec and network sources when both modules are enabled. The `aya-cpu-profile` source mode registers only `source.aya_cpu_profile` when its module and `[cpu_profile_source] enabled = true` are configured. Do not treat privileged Aya, CPU profiling, DNS runtime visibility, or Kubernetes runtime tests as passed unless they run on a real Linux host or Kubernetes cluster with tracefs/eBPF/perf-event support and the documented privileges.
