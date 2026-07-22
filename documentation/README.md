# E-Navigator Documentation

This directory is the source of truth for E-Navigator's technical and
operational documentation. Start with the path that matches your goal.

## Run E-Navigator

- [Golden path](golden-path.md), deploy a narrow, measurable, low-overhead
  production configuration.
- [Helm install](helm.md), configure the complete chart and runtime surface.
- [Operations](operations.md), monitor health, loss, export, and shutdown.
- [Release verification](release-verification.md), verify images, charts,
  checksums, signatures, and SBOMs before deployment.

## Understand The System

- [Architecture](architecture.md), follow a signal from capture to export and
  understand the workspace boundaries.
- [Capabilities](capabilities.md), see the implemented and proven surface.
- [Boundaries](boundaries.md), see explicit non-claims and unsupported cases.
- [Signal and module authoring](module-authoring.md), extend the static module
  pipeline safely.
- [Engineering invariants](engineering-invariants.md), preserve the contracts
  that keep runtime behavior and public claims aligned.

## Evaluate And Contribute

- [Proof report](proof-report.md), inspect the current evidence map.
- [Benchmark methodology](benchmark.md), reproduce local and runtime
  measurements without mixing evidence tiers.
- [Rust engineering](rust-engineering.md), apply the repository's code,
  safety, testing, dependency, and optimization standards.
- [Standalone readiness](standalone-readiness.md), inspect the dated readiness
  matrix and remaining proof work.
- [Contributing](../CONTRIBUTING.md), run the required local gate and prepare a
  focused change.

## Release Maintainers

- [Release process](release-process.md), prepare and publish an immutable
  release.
- [Release verification](release-verification.md), independently verify a
  release before rollout.

## Architecture Decisions

- [ADR 0001, standalone native contracts](adr/0001-standalone-native-contracts.md)
- [ADR 0002, unified source supervisor](adr/0002-unified-source-supervisor.md)
- [ADR 0003, direct OTLP profiles](adr/0003-direct-otlp-profiles.md)
- [ADR 0004, independent export pipelines](adr/0004-independent-export-pipelines.md)
- [ADR 0005, shared Kubernetes workload controller](adr/0005-shared-kubernetes-workload-controller.md)
- [ADR 0006, dual ring-buffer and perf-buffer event transport](adr/0006-dual-ring-perf-event-transport.md)
- [ADR 0007, BTF fexit network byte accounting](adr/0007-btf-fexit-network-accounting.md)
- [ADR 0008, Go crypto/tls uprobes](adr/0008-go-crypto-tls-uprobes.md)
- [ADR 0009, bounded event-driven profiling](adr/0009-event-driven-profiling.md)

## Source-Of-Truth Rules

- `README.md` is the short project entry point.
- This index routes readers to the authoritative guide for each topic.
- `capabilities.md`, `boundaries.md`, and `proof-report.md` define public
  claims. A passing unit test does not automatically change a runtime claim.
- `helm.md` defines every deployment setting. `golden-path.md` selects a
  deliberately small production starting point from that surface.
- Accepted architecture changes live in `documentation/adr/`.
- Dated proof artifacts may support a claim, but they do not replace the
  curated proof report.
