# E-Navigator

A Rust and eBPF signal plane for Linux and Kubernetes runtime observability.

**Status:** pre-release `0.1.0`. E-Navigator has a statically registered
`Source -> Processor -> Generator -> Sink` pipeline, versioned signal envelopes,
JSON stdout output, Kubernetes DaemonSet packaging, signed release artifacts,
and guarded proof for selected Linux/Kubernetes runtime paths. It is not yet a
full observability backend, profile store, trace store, UI, or production
collector replacement.

For the current truth, start here:

- [Capabilities](documentation/capabilities.md): what exists and what is proven.
- [Boundaries](documentation/boundaries.md): what E-Navigator does not claim.
- [Proof report](documentation/proof-report.md): curated evidence by area.
- [Benchmarks](documentation/benchmark.md): methodology, commands, and caveats.

## What It Does

E-Navigator runs as a node-local agent and turns workload observations into
bounded, versioned signals:

- process execution and exit observations;
- TCP network observations and native network metrics;
- DNS, HTTP/request, MongoDB, MySQL, PostgreSQL, and Redis parsers, trace, and
  profiling foundations;
- host resource observations from procfs, sysfs, and cgroups;
- Kubernetes/container attribution where context is available;
- derived dependency edges, low-cardinality metrics, request spans, profile
  windows, and runtime security findings.

The default sink emits newline-delimited JSON. Prometheus HTTP and OTLP HTTP
sinks are registered and tested, with selected live collector proof recorded in
the proof report.

## Architecture

```text
Linux / Kubernetes node
  -> sources
     -> processors
        -> generators
           -> sinks
```

- **Sources** observe synthetic fixtures, host resources, Aya exec/network
  events, opt-in DNS/HTTP paths, and opt-in CPU profiling.
- **Processors** attach host, process, container, and Kubernetes context when
  available.
- **Generators** produce metrics, dependency edges, request spans, trace service
  paths, profiling sessions, and runtime security findings.
- **Sinks** export JSON stdout by default, with opt-in Prometheus HTTP and OTLP
  HTTP surfaces.

The pipeline is static by design. Runtime plugin loading is not part of the
current architecture.

## Quick Start

Run the synthetic pipeline without privileged Linux, eBPF, Docker, or
Kubernetes dependencies:

```bash
cargo run --locked -p e-navigator-cli -- --source synthetic
```

Validate a config:

```bash
cargo run --locked -p e-navigator-cli -- --validate-config
cargo run --locked -p e-navigator-cli -- --validate-config --config path/to/e-navigator.toml
```

Render the Helm chart locally:

```bash
helm lint charts/e-navigator
helm template e-navigator charts/e-navigator
```

## Kubernetes Install

Install the published OCI chart:

```bash
helm upgrade --install e-navigator oci://ghcr.io/e-navigator/charts/e-navigator \
  --version 0.1.0 \
  --namespace e-navigator-system \
  --create-namespace
```

Before production use, verify the release manifest, checksums, Cosign
signatures, SBOMs, image digest, and chart digest with
[release verification](documentation/release-verification.md). Then deploy
digest-pinned images.

Helm rendering and a successful install do not prove live eBPF behavior. Live
runtime proof requires a capable Linux host or Kubernetes cluster and recorded
observations.

## Current Proof Snapshot

Evidence-backed today:

- static runtime, config parsing, JSON envelopes, and synthetic pipeline;
- host resource parsing and Docker synthetic fixtures;
- process and TCP network source foundations;
- Kubernetes/container attribution for selected captured signals;
- dependency graph, resource metrics, network metrics, MongoDB, MySQL,
  PostgreSQL, and Redis parser foundations, request/trace/profile foundations,
  and runtime security generator behavior through tests;
- selected guarded homelab proof for exec, network, DNS, HTTP, profile,
  resource, Prometheus, OTLP, and seccomp paths;
- release artifact signing, SBOM generation, Helm packaging, and local quality
  gates.

Important current non-claims:

- no storage backend, UI, flamegraph view, profile store, or trace store;
- no pprof export;
- no production backend compatibility claim;
- no reduced-overhead or reduced-privilege claim;
- no symmetric all-node DNS/HTTP capture claim;
- no live MongoDB protocol capture or request/response matching claim;
- no live MySQL protocol capture or request/response matching claim;
- no live PostgreSQL protocol capture or request/response matching claim;
- no live Redis protocol capture or request/response matching claim;
- live native `network.flow.bytes` export still needs a positive rerun after
  the native metric migration.

See [proof report](documentation/proof-report.md) and
[boundaries](documentation/boundaries.md) for the detailed version.

## Building And Testing

Run the full local gate:

```bash
scripts/quality.sh
```

Useful direct checks:

```bash
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets \
  --exclude e-navigator-ebpf-programs -- -D warnings
cargo test --locked --workspace --exclude e-navigator-ebpf-programs
cargo build --locked --workspace --exclude e-navigator-ebpf-programs
cargo run --locked -p e-navigator-cli -- --source synthetic
helm lint charts/e-navigator
helm template e-navigator charts/e-navigator
node website/check-links.mjs
git diff --check
```

The full gate also uses supply-chain tools, Docker smoke tests, Kubernetes schema
validation, and tracked-file secret-pattern checks. Use skip flags only for
constrained local environments:

```bash
E_NAVIGATOR_SKIP_SUPPLY_CHAIN=1 scripts/quality.sh
E_NAVIGATOR_SKIP_DOCKER=1 E_NAVIGATOR_SKIP_KUBERNETES=1 scripts/quality.sh
```

Aya/eBPF development requires a capable Linux environment plus the nightly Rust
toolchain with `rust-src`, `bpf-linker`, `clang`, `llvm`, and `bpftool`.

## Documentation

- [Capabilities](documentation/capabilities.md)
- [Boundaries](documentation/boundaries.md)
- [Proof report](documentation/proof-report.md)
- [Benchmarks](documentation/benchmark.md)
- [Helm install](documentation/helm.md)
- [Release verification](documentation/release-verification.md)
- [Engineering invariants](documentation/engineering-invariants.md)
- [Module authoring](documentation/module-authoring.md)

## License

Apache-2.0.
