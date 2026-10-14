# E-Navigator Documentation

This directory is the source of truth for E-Navigator's technical and
operational documentation. Start with the path that matches your goal.

## Run E-Navigator

- [Golden path](golden-path.md), deploy a narrow, measurable, low-overhead
  production configuration.
- [Helm install](helm.md), configure the complete chart and runtime surface.
- [Operations](operations.md), monitor health, loss, export, and shutdown.
- [Collector qualification and migration](collector-migration.md), qualify exact
  replacement cells, stage consumer cutover and preserve delivery during rollback.
- [Release verification](release-verification.md), verify images, charts,
  checksums, signatures, and SBOMs before deployment.

- [Durable OTLP export](durable-export.md), configure per-family storage, recovery and deletion.
- [Application log processing and OTLP export](log-export.md), configure privacy rules and independent log delivery.

## Understand The System

- [Architecture](architecture.md), follow a signal from capture to export and
  understand the workspace boundaries.
- [Standalone independence audit](standalone-independence.md), review customer
  coupling removal, compatibility evidence, and verification scope.
- [Capabilities](capabilities.md), see the implemented and proven surface.
- [Boundaries](boundaries.md), see explicit non-claims and unsupported cases.
- [Workload qualification ledger](workload-qualification.md), see the
  undeclared workload cells and live evidence that block replacement.
- [Collector replacement acceptance contract](replacement-acceptance.md),
  record exact cells, consumer queries, numerical thresholds and input owners.
- [Historical customer acceptance profile](guara-replacement-acceptance.md),
  preserve the deployment-specific requirements and missing-input record.
- [Historical customer workload ledger](guara-workload-matrix.md),
  preserve that deployment's qualification status independently of product support.
- [Replacement qualification suite for issue 48](issue-48-replacement-qualification.md),
  run deterministic fixtures and evaluate authorized per-cell backend evidence.
- [Replacement campaign gate for issue 46](issue-46-replacement-campaign.md),
  replay preserved capability assertions and check matched trials, consumer migration and rollback.
- [Protocol request qualification](issue-49-protocol-qualification.md),
  assert per-cell stored traces and metrics, protocol controls and live-input blockers.
- [TLS lifecycle qualification for issue 50](issue-50-tls-qualification.md),
  review process/socket fencing, local regressions and remaining live evidence.
- [Backend compatibility and Grafana workflow qualification](issue-53-backend-qualification.md),
  pinned identities, retention checkpoints and preserved consumer evidence.
- [CPU runtime qualification for issue 52](issue-52-cpu-qualification.md),
  review build attestation, bounded identity fences and per-cell CPU assertions.
- [Signal and module authoring](module-authoring.md), extend the static module
  pipeline safely.
- [Engineering invariants](engineering-invariants.md), preserve the contracts
  that keep runtime behavior and public claims aligned.
- [Peer-flow and W3C propagation feasibility](feature-feasibility-peer-aware-flows-and-w3c-propagation.md),
  review the primary-source design analysis and rejected universal claims.
- [Profiling parity feasibility](research/profiling-parity-feasibility.md),
  review the evidence, support matrices, and non-intrusive implementation
  limits for managed runtimes, kernel stacks, and allocation profiles.

## Evaluate And Contribute

- [Proof report](proof-report.md), inspect the current evidence map.
- [Opt-in HTTP/1 propagation proof](proof/http-propagation-20260811/report.md),
  inspect the exact local verifier, attachment, and live-wire evidence and its
  explicit non-claims.
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

- [CRI application log collection](cri-logs.md), configure bounded collection and read-position recovery.

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
- [ADR 0010, bounded browser protocols and HTTP/3 boundary](adr/0010-browser-protocol-boundaries.md)
- [ADR 0011, cgroup v1 capture filter boundary](adr/0011-cgroup-v1-capture-filter-boundary.md)
- [ADR 0012, reduced privilege on proven modern kernels](adr/0012-reduced-privilege-modern-kernels.md)
- [ADR 0013, event-driven cgroup discovery](adr/0013-event-driven-cgroup-discovery.md)
- [ADR 0014, controlled cumulative head-to-head benchmark](adr/0014-controlled-head-to-head-benchmark.md)
- [ADR 0015, peer flow metrics and opt-in HTTP/1 propagation](adr/0015-peer-flow-metrics-and-opt-in-http1-propagation.md)
- [ADR 0016, non-intrusive profiling parity](adr/0016-non-intrusive-profiling-parity.md)
- [ADR 0018, bounded CRI logs and read checkpoints](adr/0018-cri-log-collection.md)
- [ADR 0019, HTTP propagation lifetime and rollback](adr/0019-http-propagation-lifetime-and-rollback.md)
- [ADR 0021, durable OTLP spools](adr/0021-durable-otlp-spools.md)
- [ADR 0020, processed OTLP Logs](adr/0020-processed-otlp-logs.md)
- [Issue 51 propagation qualification](issue-51-propagation-qualification.md)
- [ADR 0017, OpenTelemetry zero-code coexistence](adr/0017-otel-zero-code-coexistence.md)

- [ADR 0022, Loki backend ownership and replacement requirements](adr/0022-loki-backend-ownership.md)

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
