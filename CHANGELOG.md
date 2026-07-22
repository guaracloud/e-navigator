# Changelog

All notable changes to E-Navigator are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Add a dual eBPF event transport with automatic ring-buffer selection on
  capable kernels, a separately built perf-event fallback for older kernels,
  bounded ring sizing, producer-loss accounting, native transport metrics,
  and explicit A/B benchmark hooks.
- Add strict BTF-backed fexit selection for scalar network `read(2)` and
  `write(2)` accounting, with forced diagnostics, a positively unsupported
  tracepoint fallback, a guarded integrity workload, and counterbalanced
  homelab analysis.
- Add bounded, version-gated Go `crypto/tls` plaintext capture for unstripped
  Linux/amd64 Go 1.24 through 1.26 executables, with exact static-symbol and
  return-site preflight, goroutine-safe correlation, transactional attachment,
  native blind-spot counters, and stripped-binary rejection.

### Performance

- Measure fexit at 7.971% more 256-byte TCP round trips per second and 7.710%
  lower mean latency than syscall tracepoints across three counterbalanced
  90-second homelab runs per arm. Keep the claim scoped to this scalar
  read/write workload: fexit remained 7.045% below no-agent throughput and used
  about 13.4 MiB more summed two-pod RSS than tracepoints.

### Compatibility

- Preserve the raw event ABI and retain `perf_buffer` as a strict diagnostic
  mode while making `auto` the packaged default.
- Preserve syscall tracepoints for network read/write accounting on kernels
  that positively lack tracing-program, kernel-BTF, or target-function support;
  indeterminate capability, verifier, load, and attach failures remain fatal.
- Keep unsupported Go versions, prereleases, stripped binaries, malformed or
  ambiguous symbols, and non-amd64 Go ABIs fail-closed. Go 1.26.4 has homelab
  runtime proof; Go 1.24 and 1.25 remain test-only compatibility claims.

## [0.1.2] - 2026-07-20

### Added

- Add a production performance golden path, architecture guide, operations
  guide, Rust engineering standard, documentation index, and validated
  low-overhead production configuration.
- Add a website documentation portal with responsive navigation, accessible
  content structure, and direct routes for deployment, architecture,
  operations, performance evidence, and proof boundaries.
- Add automated documentation contracts for em-dash policy, local links,
  documentation index coverage, README entry points, and the website golden
  path.

### Performance

- Route every built-in synchronous generator through the immediate runner
  contract, avoiding a Tokio channel and async-trait future for each accepted
  signal while preserving the async trait path for direct callers.
- Move validated immediate generator results directly into runner dispatch
  instead of copying them through a second vector.
- Reduce the container build context from 82.25 MB to 2.29 MB by excluding
  documentation, deployment, proof, development, and repository-only assets
  that are not required to build the runtime image.

### Reliability And Engineering

- Deny production `unwrap`, `expect`, direct `panic`, `dbg`, `todo`, and
  `unimplemented` usage across the workspace, with documented test-only
  allowances.
- Deny broken Rustdoc links, bare Rustdoc URLs, and missing crate-level
  documentation, and run Rustdoc with warnings denied in local and CI gates.
- Replace assumed endpoint, pending-metric, profile-map, and protocol-queue
  states with explicit safe handling.
- Enforce the 64-output generator limit on immediate output and cover the
  failure with a runner regression test.

### Repository And Delivery

- Add weekly Cargo, GitHub Actions, and container dependency updates plus a
  pull-request template that keeps architecture, safety, evidence, and
  documentation review explicit.
- Validate documentation, website links, Rustdoc, and the production example
  configuration in CI, and validate documentation before GitHub Pages upload.
- Remove unused Helm feature flags and add chart home, icon, and source
  metadata.

### Validation

- Measure nine changed generator hot paths between 15.0% and 61.1% faster in
  the focused Criterion comparison, with DNS query aggregation statistically
  unchanged and an unchanged request-correlation control recorded separately
  to expose local measurement sensitivity.
- Run formatting, strict Clippy, Rustdoc, complete Linux workspace tests,
  workspace build, fuzz-target compilation, configuration and synthetic
  execution, supply-chain checks, repository guards, Docker smoke, Helm,
  Kubeconform, website link checks, and desktop and mobile browser QA.
- Keep the benchmark claim scoped to userspace hot-path evidence. This release
  does not add a new privileged Aya, Kubernetes runtime, backend, or production
  overhead claim.

### Compatibility

- Preserve native signal schemas, module names and order, configuration
  contracts, bounded state limits, supported sinks, and deployment surfaces.

## [0.1.1] - 2026-07-13

### Performance

- Build network and DNS metric templates only when their bounded aggregation
  maps receive a new key, avoiding repeated allocation and cloning work for
  established series.
- Normalize each DNS query domain once before constructing its aggregation key
  and stored metric template.

### Reliability

- Return Prometheus and OTLP sink construction failures through the CLI error
  path instead of panicking during registry startup.

### Validation

- Add deterministic regression tests proving existing network and DNS series
  do not rebuild their stored templates.
- Run the complete local quality, supply-chain, container, Helm, and Kubernetes
  schema gates, plus focused Criterion measurements and an isolated AMD64
  homelab Aya exec/network runtime replay.

### Compatibility

- Preserve the public configuration contract, signal schemas, module ordering,
  bounded state limits, and supported deployment surfaces.

## [0.1.0] - 2026-07-11

### Added

- Publish the first E-Navigator public preview with signed multi-architecture
  images, signed release assets and SPDX SBOMs, a public OCI Helm chart, and a
  digest-pinned release manifest.

### Validation

- Independently verify all 15 `v0.1.0-rc.3` assets, five checksums, five
  keyless Sigstore bundles, three SPDX SBOMs, both image aliases, AMD64 and
  ARM64 child-manifest runtime paths, and a byte-identical anonymous OCI chart
  pull before promotion.
- Run the complete local quality gate against the stable version surfaces.
- Do not claim a fresh Kubernetes runtime replay for this promotion: the
  release workstation at `192.168.0.111` had no route to the homelab API at
  `192.168.50.132:6443`, and no cluster mutation was attempted.

### Release integrity

- Promote the validated candidate through protected `main` and an annotated,
  protected `v0.1.0` tag rather than moving or overwriting an existing tag.
- Publish `latest` only after the stable workflow re-verifies checksums,
  signatures, SBOMs, manifest metadata, image aliases, both platform runtimes,
  and the public OCI chart.

## [0.1.0-rc.3] - 2026-07-11

### Fixed

- Resolve and run each Linux platform by its child manifest digest during
  post-publication verification, avoiding Docker's local cache collision when
  two architectures share one OCI index digest.

### Validation

- Prove the corrected verifier against the immutable `v0.1.0-rc.2` image:
  both AMD64 and ARM64 child manifests report the expected CLI version and run
  the synthetic pipeline successfully.

### Release integrity

- Preserve `v0.1.0-rc.2` and its signed OCI/release artifacts in draft state,
  then fix forward with this candidate instead of overwriting its contract.

## [0.1.0-rc.2] - 2026-07-10

### Fixed

- Emit and verify Cosign v3 Sigstore bundles for every signed release blob
  instead of relying on the removed split signature/certificate outputs.
- Bound the artifact-publication and post-publication verification jobs with
  explicit timeouts so an unhealthy release terminates with a clear failure.

### Release integrity

- Preserve the immutable `v0.1.0-rc.1` tag and its versioned OCI artifacts
  after downstream blob signing failed, then fix forward with this candidate
  instead of moving or overwriting the published version.

## [0.1.0-rc.1] - 2026-07-10

### Added

- Introduce the static `Source -> Processor -> Generator -> Sink` runtime with
  versioned signal envelopes, strict configuration parsing, JSON output, and
  bounded derived-signal generation.
- Add Aya/eBPF process, network, DNS, cleartext HTTP, multi-protocol request,
  TLS-library plaintext, and CPU profiling sources for Linux.
- Add bounded parsing, reassembly, and request/response matching for HTTP,
  gRPC, Kafka, MongoDB, MySQL, NATS, PostgreSQL, and Redis traffic.
- Add Kubernetes/container attribution and an opt-in namespace/label capture
  filter enforced by cgroup id in the eBPF fast path.
- Add Prometheus, OTLP HTTP protobuf, JSON, and pprof-compatible output
  surfaces with explicit family and cardinality limits.
- Add a Helm OCI chart, raw Kubernetes manifests, a multi-architecture
  container image, SPDX SBOM generation, keyless Cosign signing, and a signed
  release manifest.

### Security

- Keep raw protocol payloads, SQL, keys, values, subjects, and secret-like
  dynamic attributes out of exported signals.
- Bound parser windows, queues, caches, stream state, in-flight requests,
  profile tables, signal attributes, and exporter cardinality.
- Reject unknown configuration fields and unsafe or unbounded runtime limits
  before sources attach.
- Add tracked-file secret-pattern checks, dependency advisory checks, and
  package/license policy gates.

### Performance

- Compact protocol stream tails at most once per pushed chunk and cover the
  64-frame Redis pipeline path with regression tests and Criterion benchmarks.
- Reuse connection attribution and owned signal strings across protocol and
  observability hot paths.
- Remove temporary procfs parser vectors and reduce profile symbolization,
  resource sampling, and formatter allocations.
- Size perf-event rings by sampling frequency and bound reader shutdown without
  changing signal schemas.

### Reliability

- Add parser, raw-event, stream, symbolization, capture-filter, and unwind fuzz
  targets plus golden signal coverage.
- Add packaged-config, Kubernetes manifest, image, secret-pattern, and
  source-boundary regression guards.
- Record isolated local and homelab runtime proof for selected eBPF, protocol,
  TLS, profiling, attribution, Prometheus, and OTLP paths.
- Add an automated release contract that keeps Cargo packages, CLI version,
  chart metadata, image tags, documentation, and the Git tag aligned.

### Known limitations

- This is a pre-1.0 release candidate, not a production observability backend
  or collector replacement.
- Storage, a UI, broad production backend compatibility, production-load soak,
  reduced-privilege operation, and universal protocol/profile coverage remain
  explicit non-claims documented in `documentation/boundaries.md`.

[Unreleased]: https://github.com/guaracloud/e-navigator/compare/v0.1.2...HEAD
[0.1.2]: https://github.com/guaracloud/e-navigator/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/guaracloud/e-navigator/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/guaracloud/e-navigator/compare/v0.1.0-rc.3...v0.1.0
[0.1.0-rc.3]: https://github.com/guaracloud/e-navigator/compare/v0.1.0-rc.2...v0.1.0-rc.3
[0.1.0-rc.2]: https://github.com/guaracloud/e-navigator/compare/v0.1.0-rc.1...v0.1.0-rc.2
[0.1.0-rc.1]: https://github.com/guaracloud/e-navigator/tree/v0.1.0-rc.1
