# Changelog

All notable changes to E-Navigator are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

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

[Unreleased]: https://github.com/guaracloud/e-navigator/compare/v0.1.0-rc.2...HEAD
[0.1.0-rc.2]: https://github.com/guaracloud/e-navigator/compare/v0.1.0-rc.1...v0.1.0-rc.2
[0.1.0-rc.1]: https://github.com/guaracloud/e-navigator/tree/v0.1.0-rc.1
