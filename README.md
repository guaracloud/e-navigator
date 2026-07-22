# E-Navigator

E-Navigator is a Rust and eBPF signal plane for Linux and Kubernetes runtime
observability. It captures node-local activity, attaches evidence-backed
workload context, derives bounded native telemetry, and exports through JSON,
Prometheus, OTLP HTTP, and local pprof surfaces.

**Status:** active development after public preview `0.1.2`. E-Navigator is a
collector, not a storage backend, query engine, or UI. Capabilities are promoted
only when their matching evidence exists.

[Website](https://guaracloud.github.io/e-navigator/) ·
[Documentation](documentation/README.md) ·
[Golden path](documentation/golden-path.md) ·
[Capabilities](documentation/capabilities.md) ·
[Boundaries](documentation/boundaries.md) ·
[Proof report](documentation/proof-report.md)

## Choose A Path

| Goal | Start here |
| --- | --- |
| Try the pipeline without Linux privileges | [Five-minute local start](#five-minute-local-start) |
| Deploy a narrow, low-overhead production baseline | [Production performance golden path](documentation/golden-path.md) |
| Configure the complete Helm surface | [Helm install](documentation/helm.md) |
| Understand capture, derivation, and export | [Architecture](documentation/architecture.md) |
| Operate and troubleshoot a deployment | [Operations](documentation/operations.md) |
| Verify a release before rollout | [Release verification](documentation/release-verification.md) |
| Contribute Rust or eBPF code | [Contributing](CONTRIBUTING.md) and [Rust engineering](documentation/rust-engineering.md) |

## What It Does

E-Navigator runs as one node-local agent with a statically registered
`Source -> Processor -> Generator -> Sink` pipeline.

- Sources observe process execution and exit, TCP lifecycle and statistics,
  host resources, DNS, HTTP, supported application protocols, TLS plaintext at
  supported userspace library boundaries, plus periodic CPU, scheduler
  off-CPU, and futex-wait lock profile samples.
- Processors attach process, container, Kubernetes, owner, and service context
  only when the evidence supports it.
- Generators derive bounded resource and network metrics, dependency edges,
  request spans, trace service paths, profile sessions, and runtime security
  findings.
- Sinks emit newline-delimited JSON, serve Prometheus and local pprof, or route
  metrics, traces, and profiles through independent bounded OTLP workers.
- An optional Kubernetes-aware capture filter avoids probing excluded workload
  cgroups at the connection boundary.

Detailed implementation and proof status lives in
[capabilities](documentation/capabilities.md). Unsupported libraries,
unproven runtime combinations, and production non-claims live in
[boundaries](documentation/boundaries.md).

## Five-Minute Local Start

Requirements: Rust 1.96.0 through the checked-in toolchain and the cloned
repository.

Run the synthetic pipeline without eBPF, Docker, or Kubernetes:

```bash
cargo run --locked -p e-navigator-cli -- --source synthetic
```

Validate the built-in configuration and the production baseline example:

```bash
cargo run --locked -p e-navigator-cli -- --validate-config
cargo run --locked -p e-navigator-cli -- \
  --validate-config \
  --config documentation/examples/production-performance.toml
```

Render the Helm chart without changing a cluster:

```bash
helm lint charts/e-navigator
helm template e-navigator charts/e-navigator
```

These commands prove userspace behavior, configuration, and packaging. They do
not prove privileged Aya attachment or live signal capture on a target kernel.

## Production Golden Path

The recommended low-overhead path is deliberate:

1. Verify the release manifest, checksums, signatures, SBOMs, image digest, and
   chart digest.
2. Scope capture to explicit namespaces and labels with a fail-closed posture.
3. Start with exec, network lifecycle, and one-minute host resources.
4. Keep synthetic, payload parsing, TLS uprobes, CPU profiling, and JSON stdout
   disabled until they have an explicit consumer and acceptance test.
5. Export metrics through bounded Prometheus and OTLP surfaces.
6. Measure the same workload with no agent, the base profile, and each added
   signal family.
7. Stop or roll back when application latency, node CPU, memory, source loss,
   export loss, or attribution freshness crosses its recorded threshold.

The complete commands, configuration, metrics, and tuning order are in the
[production performance golden path](documentation/golden-path.md). The
checked-in example is validated by the repository quality gate.

## Architecture At A Glance

```text
kernel probes and host filesystems
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
 JSON | Prometheus | OTLP HTTP | local pprof
```

The static pipeline keeps runtime behavior inspectable. Versioned envelopes,
parser limits, cardinality caps, generation breadth and depth budgets, bounded
export queues, retries, and shutdown deadlines prevent unbounded work. Metrics,
traces, and profiles use independent OTLP workers, so one unavailable
destination cannot block another family or the shared capture path.

Read [architecture](documentation/architecture.md) for the crate map, startup
lifecycle, privileged boundary, Kubernetes controller, and export isolation.

## Kubernetes Install

Install the published OCI chart only after release verification:

```bash
helm upgrade --install e-navigator oci://ghcr.io/guaracloud/charts/e-navigator \
  --version 0.1.2 \
  --namespace e-navigator-system \
  --create-namespace
```

For production, set `image.digest` to the verified digest. Helm rendering and a
successful rollout do not by themselves prove live eBPF behavior. Confirm the
expected signal on a capable Linux node and record backend acceptance before
changing a capability claim.

## Quality Gate

Run the complete non-privileged local gate:

```bash
scripts/quality.sh
```

It checks formatting, documentation policy and links, release contracts,
Clippy, rustdoc, workspace tests and builds, fuzz target compilation, the
synthetic pipeline, supply-chain policy, Docker smoke, Helm, Kubernetes schema,
the website, secret-pattern guards, and `git diff --check`.

Use skip flags only when the local environment lacks the required runtime. A
skipped Docker, Kubernetes, supply-chain, or privileged gate is not proof for
that surface.

Aya development needs a capable Linux environment plus the pinned
`nightly-2026-07-01` toolchain with `rust-src`, `bpf-linker`, Clang, LLVM, and
bpftool.

## Documentation

- [Documentation index](documentation/README.md)
- [Production performance golden path](documentation/golden-path.md)
- [Architecture](documentation/architecture.md)
- [Operations](documentation/operations.md)
- [Capabilities](documentation/capabilities.md)
- [Boundaries](documentation/boundaries.md)
- [Proof report](documentation/proof-report.md)
- [Benchmark methodology](documentation/benchmark.md)
- [Helm install](documentation/helm.md)
- [Rust engineering standard](documentation/rust-engineering.md)
- [Engineering invariants](documentation/engineering-invariants.md)
- [Module authoring](documentation/module-authoring.md)
- [Release verification](documentation/release-verification.md)
- [Release process](documentation/release-process.md)
- [Standalone readiness](documentation/standalone-readiness.md)
- [Architecture decisions](documentation/README.md#architecture-decisions)

## Contributing And Security

Read [CONTRIBUTING.md](CONTRIBUTING.md) before changing code or public claims.
Report vulnerabilities through the private process in
[SECURITY.md](SECURITY.md).

## License

Apache-2.0.
