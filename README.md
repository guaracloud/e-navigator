# E-Navigator

A Rust and eBPF signal plane for Linux and Kubernetes observability, profiling,
runtime security, and diagnostics.

**Status:** pre-release `0.1.0` foundation. The current tree has a statically
registered signal pipeline, JSON stdout output, Kubernetes DaemonSet packaging,
release-signing workflow, strict non-privileged quality gates, and bounded
foundations for runtime, network, DNS fixture, resource, dependency, trace,
  request, profiling, Guara compatibility projection, registered export
  surfaces, and security signals. See
[documentation/claims-matrix.md](documentation/claims-matrix.md) for the exact
claim boundaries.

## What it does

`e-navigator` runs as a node-local agent and turns workload observations into
versioned signal envelopes. The project is designed to answer practical runtime
questions without application SDKs or sidecars:

- What processes, connections, resources, requests, traces, and profiles were
  observed?
- Which host, process, container, or Kubernetes workload can the signal be
  attributed to?
- Which dependency edges, low-cardinality metrics, request spans, profile
  windows, and runtime security findings can be derived safely?
- Which observations are synthetic, fixture-backed, non-privileged proven, or
  privileged runtime proven?

The default sink emits newline-delimited JSON. Opt-in Prometheus HTTP and OTLP
HTTP sink modules are registered, but live scrape, collector ingestion,
Pyroscope, pprof, storage, and UI proof still require recorded runtime evidence.

## Architecture at a glance

```text
Linux / Kubernetes node
  -> sources
     -> processors
        -> generators
           -> sinks
```

- **Sources:** synthetic fixtures, bounded host resource reads, Aya process
  exec/exit, TCP-oriented network events, opt-in DNS parser/source foundations,
  and opt-in CPU profile sampling.
- **Processors:** best-effort host, process, container, and Kubernetes
  attribution with structured warnings when context is missing.
- **Generators:** runtime security findings, network/resource metrics,
  dependency edges, trace service paths, request spans, profiling windows, and
  optional Guara compatibility projections.
- **Sinks:** JSON stdout by default, plus opt-in Prometheus HTTP and OTLP HTTP
  sink modules with bounded local tests. OTLP uses the current internal record
  boundary and is not live Tempo/Pyroscope compatibility proof.

The pipeline is statically registered by design. Runtime plugin loading is not
part of the current architecture; see
[documentation/adr/0002-static-pipeline-registration.md](documentation/adr/0002-static-pipeline-registration.md).

## Quick start

### Run the synthetic pipeline locally

This exercises the pipeline without privileged Linux, eBPF, Docker, or
Kubernetes dependencies:

```bash
cargo run --locked -p e-navigator-cli -- --source synthetic
```

Useful CLI entry points:

```bash
cargo run --locked -p e-navigator-cli -- --help
cargo run --locked -p e-navigator-cli -- --validate-config
cargo run --locked -p e-navigator-cli -- --validate-config --config path/to/e-navigator.toml
```

### Develop the Helm chart locally

Render and validate the chart from this checkout:

```bash
helm lint charts/e-navigator
helm template e-navigator charts/e-navigator
helm template e-navigator charts/e-navigator \
  | kubeconform -strict -summary -
```

For a local development install that uses the rolling `main` image:

```bash
helm upgrade --install e-navigator charts/e-navigator \
  --namespace e-navigator-system \
  --create-namespace \
  --set image.tag=main
```

Helm rendering, schema validation, and successful installs do not prove live
eBPF behavior. Privileged runtime proof requires a capable Linux node or cluster
and observed Aya/eBPF output.

### Install a tagged release

Tagged releases publish the container image, OCI Helm chart, SBOMs, checksums,
signatures, and release manifest. After a release exists, install the chart with:

```bash
helm upgrade --install e-navigator oci://ghcr.io/guaracloud/charts/e-navigator \
  --version 0.1.0 \
  --namespace e-navigator-system \
  --create-namespace
```

Before production use, verify checksums, Cosign signatures, SBOMs, image
digests, the release manifest, and the chart digest with
[documentation/release-verification.md](documentation/release-verification.md).
Then pin the digest-backed image reference in your values file.

## Current capability map

Implemented and non-privileged proven:

- Static runtime and JSON envelopes through Cargo tests, synthetic CLI runs, and
  Docker smoke tests.
- Process exec/exit source through userspace config coverage and raw decode
  tests.
- TCP-oriented network source through raw decode tests and synthetic smoke
  coverage.
- Host resource source through procfs, sysfs, cgroup parser tests, and Docker
  synthetic fixtures.
- Dependency graph generation through generator tests and runner fan-out tests.
- Trace and request foundations through schema, generator, formatter, fixture,
  and smoke tests.
- CPU profiling foundations through raw decode, profile normalization, and
  generator tests.
- Guara compatibility contracts for the Beyla L4 metric label set, Tempo
  service-graph resource labels, Pyroscope CPU profile identity, and Guara
  tenant scoping through golden/unit tests.
- Kubernetes packaging through Helm lint/template and schema validation.
- Supply-chain checks through `cargo deny`, `cargo audit`, and
  `cargo machete`.

Implemented with narrower or deferred runtime claims:

- Runtime DNS support currently means schemas, synthetic DNS fixtures, bounded
  DNS metric/dependency generation, bounded packet parser/raw decode tests, and
  an opt-in registered `source.aya_dns` boundary. Live eBPF DNS packet capture is
  not privileged-proven; homelab run `20260621-202849-dns-live` failed because
  live kernel attachment is not implemented in this build.
- Prometheus HTTP support is an opt-in registered sink with local `/metrics`,
  `/healthz`, and `/readyz` tests. Homelab run `20260621-201246` deployed image
  `sha-5c417c0`, proved live endpoint reachability, ServiceMonitor discovery,
  active Prometheus targets, nonzero scrape samples, and queryable
  E-Navigator metric series such as `network_connection_open_count`.
- OTLP HTTP support is an opt-in registered sink over the current internal
  metric, trace, and profile record boundary with fake-collector retry tests. It
  is not Tempo or Pyroscope compatibility proof.
- CPU profile sampling is an explicit opt-in source. Homelab run
  `20260621-203358-profile-live` proved `source.aya_cpu_profile` samples and
  `generator.profiling` sessions for a controlled CPU workload, including
  Kubernetes/container attribution.
- Kubernetes packaging proof is separate from privileged eBPF runtime proof.
- Persisted service maps, production exporters, storage, UI, and container
  vulnerability policy gates are deferred.

For the authoritative and more detailed version, use
[documentation/claims-matrix.md](documentation/claims-matrix.md).

## What is not claimed yet

E-Navigator is not yet a full observability backend, Pyroscope replacement,
Tempo replacement, pprof server, flamegraph UI, profile store, trace store, or
critical-path analysis engine.

The following are intentionally not claimed as implemented production behavior:

- production collector-accepted OTLP metric, trace, or profile export;
- pprof or Pyroscope export;
- complete Beyla replacement or alloy-profiles replacement;
- profile storage, flamegraph rendering, or bottleneck analysis;
- live HTTP/gRPC parsing from real traffic;
- request route, retry, application error, or request-ID extraction;
- privileged-proven runtime DNS packet capture;
- full TCP state tracking, packet accounting, retransmits, or resets;
- reduced-privilege Kubernetes eBPF operation.

Do not treat synthetic fixtures, Docker smoke tests, Kubernetes schema checks, and
privileged Linux or cluster runtime evidence as interchangeable.

## Building and testing

Run the full non-privileged local gate:

```bash
scripts/quality.sh
```

The strict gate requires `cargo-deny`, `cargo-audit`, `cargo-machete`, Docker,
Helm, `kubeconform`, Node, and the normal Rust toolchain. In constrained local
environments only, narrow skips are available:

```bash
E_NAVIGATOR_SKIP_SUPPLY_CHAIN=1 scripts/quality.sh
E_NAVIGATOR_SKIP_DOCKER=1 E_NAVIGATOR_SKIP_KUBERNETES=1 scripts/quality.sh
```

Useful direct checks:

```bash
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets \
  --exclude e-navigator-ebpf-programs -- -D warnings
cargo test --locked --workspace --exclude e-navigator-ebpf-programs
cargo build --locked --workspace --exclude e-navigator-ebpf-programs
cargo run --locked -p e-navigator-cli -- --source synthetic
cargo deny check
cargo audit
cargo machete
docker build -f Containerfile -t e-navigator:local .
docker run --rm e-navigator:local --source synthetic
tests/smoke_docker.sh e-navigator:local
tests/packaged_config_guard_test.sh
tests/secret_pattern_guard_test.sh
tests/chart_service_guard_test.sh
kubeconform -strict -summary deploy/kubernetes/*.yaml
helm template e-navigator charts/e-navigator | kubeconform -strict -summary -
node website/check-links.mjs
git diff --check
```

Local benchmark and validation methodology lives in
[documentation/benchmark.md](documentation/benchmark.md). The short local
benchmark smoke command is:

```bash
benchmarks/runner/local-bench-smoke.sh
```

Aya/eBPF development also requires the nightly Rust toolchain with `rust-src`,
`bpf-linker`, `clang`, `llvm`, and `bpftool`.

`cargo deny` currently keeps duplicate dependency versions at warning level in
`deny.toml`. This keeps the gate focused on actionable license, advisory,
source, yanked, and unused-dependency failures while transitive ecosystem
convergence is tracked without blocking unrelated systems work.

## Privileged Linux smoke tests

Run these only on a capable Linux host or cluster with the documented eBPF,
tracefs, perf-event, and Kubernetes privileges:

```bash
scripts/smoke_aya_exec_linux.sh
scripts/smoke_aya_cpu_profile_linux.sh <config>
```

The `aya-exec` source mode registers the statically compiled Aya exec and
network sources when both modules are enabled. The `aya-cpu-profile` source
mode registers only `source.aya_cpu_profile` when its module and
`[cpu_profile_source] enabled = true` are configured.

## Documentation

- [CONTRIBUTING.md](CONTRIBUTING.md): contributor workflow and local gates.
- [documentation/claims-matrix.md](documentation/claims-matrix.md): implemented,
  proven, privileged, and deferred claims.
- [documentation/engineering-invariants.md](documentation/engineering-invariants.md):
  boundaries that must stay true as the system grows.
- [documentation/helm.md](documentation/helm.md): chart install and values
  guidance.
- [documentation/benchmark.md](documentation/benchmark.md): local benchmarks,
  result artifact policy, and guarded homelab validation plan.
- [documentation/privileged-runtime-proof.md](documentation/privileged-runtime-proof.md):
  rules for recording privileged Linux or Kubernetes runtime evidence.
- [documentation/release-verification.md](documentation/release-verification.md):
  checksums, signatures, SBOMs, images, charts, and release manifests.
- [documentation/module-authoring.md](documentation/module-authoring.md): how to
  add sources, processors, generators, and sinks without breaking the static
  pipeline.
- [documentation/vision.md](documentation/vision.md): long-range product vision.

Architecture decision records live under [documentation/adr/](documentation/adr/).

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE).
