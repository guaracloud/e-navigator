# Changelog

All notable changes to E-Navigator are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Performance

- Stop allocating a lowercased copy of every trace attribute key in the
  sensitive-key deny check that runs during envelope construction. The
  check now uses the same allocation-free case-insensitive scan as the
  sink and profiling variants, and all three call one shared helper in
  the signals crate. The new `signal/sensitive_trace_key_checks`
  regression benchmark improved 56.1 percent (702 to 311 nanoseconds for
  a representative eight-key attribute mix, p = 0.00), mixed-case
  filtering behavior is locked by new unit tests, and a three-pair
  whole-agent A/B showed no regression against the preceding commit.

- Apply the perf readers' proven 25 ms coalescing window to ring-buffer
  event readers as well. Ring notifications only self-coalesce while the
  consumer lags; at low and moderate rates every event paid a poll wakeup,
  a drain, and a downstream channel wake. Batching readiness cuts that
  scheduling churn with no event loss: producers keep reserving ring space
  during the window and event timestamps stay kernel-assigned. In the local
  controlled Redis A/B (800 operations per second, four paired arms),
  whole-agent CPU fell from a 69.876 millicore mean to 34.445 millicores,
  50.7 percent, with byte-identical protocol signal counters and zero
  transport, queue, or export loss. Export-visible observation latency
  grows by at most the 25 ms window, well inside the one-second default
  flush interval.

- Classify each tracked TCP connection once, in kernel, from its first
  captured payload in the HTTP source. Previously every write on every
  tracked client connection and every read on every accepted server
  connection was copied, shipped, and decoded by the HTTP source even when
  the connection carried Redis, PostgreSQL, gRPC, or other non-HTTP traffic.
  Non-HTTP connections now skip the payload copy, event output, and
  userspace decode for their lifetime, with skips accounted in the new
  `non_http_connection_skip` diagnostic counter. In the local controlled
  Redis A/B (800 operations per second, four paired arms), whole-agent CPU
  fell 25.2% by median with byte-identical protocol signal counts.

### Fixed

- Chunk the protocol iovec emit tail program across bounded tail-call rounds
  so `writev`, `sendmsg`, `readv`, and `recvmsg` capture verifier-loads within
  the one-million-instruction budget on arm64 kernels. The unchunked emit loop
  loaded on the proven amd64 homelab kernel but was rejected on an arm64
  6.6-class-and-newer verifier, which blocked the whole protocol source on
  those hosts.

## [0.2.0] - 2026-07-23

### Validation

- Add a filesystem-backed Criterion regression benchmark for a bounded
  150-pod cgroup tree with an equal number of unrelated host cgroups.
- Preserve direct-child pod cgroup discovery and bounded scan behavior in a
  focused test.
- Record an evidence-gated optimization NO-GO after 66 corrected homelab arms:
  the candidate reduced RSS by 2.976308% but increased E-Navigator CPU by
  4.440222%. Reject and revert all production candidates from the pass.

## [0.2.0-rc.2] - 2026-07-22

### Fixed

- Create Redis proxy backend connections only after collector attachment so
  server-node eBPF capture observes the complete measured workload.
- Enforce cumulative per-family protocol-operation floors in head-to-head
  analysis, keeping frequency-sampled CPU profiles behind their own positive
  sample and export gates.
- Correct the local Aya protocol benchmark fixture to the current 384-byte raw
  event ABI instead of measuring an early decode error.
- Invalidate the incomplete `0.2.0-rc.1` Beyla plus Alloy comparison and its
  derived full-stack CPU, RSS, allocation, throughput, and latency claims.

### Performance

- Replace allocated request-correlation peer strings with a structured
  fingerprint and compute three deterministic generated-identity hashes in one
  pass. Local Criterion medians improved generated identity by 19.399819% and
  bounded 8,192-entry request deduplication by 15.755034%.
- Replace the bounded HTTP/2 in-flight tree with a preallocated sorted index,
  improving the 32-stream correlation cycle by 2.527201% while preserving
  stream-ID ordering and out-of-order response matching.
- Return before building OTLP resource and attribute maps for trace signals
  that have no declared trace identity and cannot be exported, improving the
  focused local benchmark by 99.906209%. Declared invalid identities still use
  the existing validation and accounting path.

### Validation

- Add exact generated trace and span ID assertions plus bounded HTTP/2 and
  OTLP fast-path regression benchmarks.
- Pass `scripts/quality.sh` with no skipped gates, including strict Rust checks,
  workspace tests, supply-chain checks, Docker smoke, Helm and Kubernetes
  schema validation, website checks, and repository guards.
- Preserve the historical proof bundle with an adjacent erratum and publish a
  corrected campaign report. A fresh homelab comparison remains required
  before making any replacement-overhead claim.

## [0.2.0-rc.1] - 2026-07-22

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
- Add opt-in bounded scheduler off-CPU and futex-wait lock profiling with
  strict raw-event weight semantics, duration thresholds, per-CPU rate caps,
  native state/drop/loss counters, session aggregation, and weighted pprof and
  OTLP Profiles delivery.
- Promote exact CPython 3.11 interpreter unwinding with three guarded homelab
  repetitions containing named frames, alongside the existing CPython 3.12
  support. Keep JVM and V8 support limited to operator-produced bounded perf
  maps without target-process mutation.
- Add bounded, metadata-only WebSocket and gRPC-Web protocol capture over the
  existing HTTP/1 stream path, with connection-generation-safe transitions,
  native protocol counters, property tests, fuzz targets, Criterion coverage,
  and a guarded homelab proof workload.
- Add bounded cgroup hierarchy detection for the capture filter, with an
  explicit cgroup v1 and hybrid non-claim, pre-attachment forced deny on
  unsupported layouts, fixed native diagnostics, and guarded homelab proof of
  the real v2 and legacy-fixture paths.
- Add an opt-in reduced-privilege Helm profile, strict security-context schema,
  source-specific capability overlays, a resumable guarded proof harness, and
  ten homelab arms proving core Aya sources under `BPF` and `PERFMON`, Go TLS
  and cross-UID CPU symbolization with `SYS_PTRACE`, and host resources with no
  effective capabilities on Linux 6.6.68.
- Add event-driven cgroup-tree discovery for the capture filter, with bounded
  inotify watches, one-slot notification coalescing, overflow-triggered state
  rebuilds, a polling compatibility mode, immediate per-source map wakeups,
  and native residual-window accounting.
- Add a guarded 33-run homelab head-to-head harness with pinned HTTP, gRPC,
  Redis, PostgreSQL, and CPU-bound Python workloads; no-agent, Beyla plus
  Alloy, and E-Navigator conditions; cumulative signal-family stages; bounded
  analysis; fixed topology and image gates; per-run variance, resource, and
  loss artifacts; resumable execution; and full cleanup/restore validation.
- Harden benchmark isolation by suspending both the parent and child Argo CD
  applications, asserting that the standing agent remains absent before and
  after every arm, and restoring the exact GitOps posture on every exit path.
- Add digest-pinned, bounded allocation diagnostics for both homelab nodes and
  reproducible Criterion coverage for request correlation, gzip compression,
  sensitive-key filtering, and bounded unwind parsing.

### Performance

- Measure fexit at 7.971% more 256-byte TCP round trips per second and 7.710%
  lower mean latency than syscall tracepoints across three counterbalanced
  90-second homelab runs per arm. Keep the claim scoped to this scalar
  read/write workload: fexit remained 7.045% below no-agent throughput and used
  about 13.4 MiB more summed two-pod RSS than tracepoints.
- Measure the all-mode profiling arm at 2.049% lower busy-loop throughput than
  no agent across three 60-second CPython 3.11 homelab pairs. Keep the number
  scoped to this pinned workload and shared cluster, not general or production
  profiling overhead.
- Record the browser-protocol correctness workload at 19.852290 operations/s
  with `source.aya_protocol` versus 19.862091 without a benchmark agent, a
  0.049345% difference across three paced 30-second homelab runs. Keep this as
  transparent correctness context, not a general overhead claim.
- Measure the capture-filter new-Pod exec window at 0.463 ms median and
  0.487 ms p95 with event-driven discovery, versus 1,148.131 ms median and
  1,216.842 ms p95 with 2-second polling across five counterbalanced homelab
  runs per mode. Keep the result scoped to the Linux 6.6.68 test workload.
- Record the corrected complete final-stack homelab comparison at 97.150478
  +/- 4.096372 millicores and 46.288628 +/- 2.594171 MiB RSS for E-Navigator,
  versus 75.859599 +/- 6.058294 millicores and 128.862413 +/- 7.335634 MiB for
  Beyla plus Alloy. E-Navigator measured 28.066163% more agent CPU and
  64.079030% less agent RSS, so the dual CPU-and-memory objective remains a
  NO-GO while the scoped memory advantage passes. All 591,030 measured
  workload operations succeeded with zero workload errors and zero hard
  E-Navigator signal loss.
- Reduce E-Navigator allocator calls from 8,509,242 to 5,644,163 and requested
  bytes from 925,090,490 to 692,293,775 in the matched diagnostic, reductions
  of 33.670202% and 25.164751% respectively.
- Reduce the focused 512 KiB gzip benchmark mean from 444.83 microseconds to
  95.994 microseconds with level 1 compression, improve 8,192-entry request
  fingerprint churn by 7.3448%, and shrink the release binary by 18.714152%
  with thin LTO and one codegen unit.

### Reliability And Engineering

- Bound native unwind parsing and hot-PID tracking to kernel map budgets, keep
  frame-pointer fallback explicit, and account for skipped modules and rows.
- Move protobuf export batches instead of cloning them, restore failed batches
  in original order, and cover non-clone success, encoding, permanent failure,
  retry, and ordering behavior.
- Remove lowercase-string allocations from sensitive and reserved attribute
  checks while preserving mixed-case credential filtering.
- Invalidate the earlier contaminated comparative proof, preserve it as
  historical evidence, and publish the corrected inputs, results, checksums,
  allocation profiles, CPU profiles, tradeoffs, and remaining bottlenecks.

### Compatibility

- Preserve the raw event ABI and retain `perf_buffer` as a strict diagnostic
  mode while making `auto` the packaged default.
- Preserve syscall tracepoints for network read/write accounting on kernels
  that positively lack tracing-program, kernel-BTF, or target-function support;
  indeterminate capability, verifier, load, and attach failures remain fatal.
- Keep unsupported Go versions, prereleases, stripped binaries, malformed or
  ambiguous symbols, and non-amd64 Go ABIs fail-closed. Go 1.26.4 has homelab
  runtime proof; Go 1.24 and 1.25 remain test-only compatibility claims.
- Keep event-driven profiling disabled by default. Unsupported scheduler
  layouts and futex syscall architectures fail closed; non-futex locks,
  wakeup cause and ownership, allocations, automatic JIT map generation, and
  CPython versions outside 3.11/3.12 remain explicit non-claims.
- Keep WebSocket extensions, compression, fragmented-message reconstruction,
  gRPC-Web protobuf decoding, HTTP/3, and generic QUIC semantics outside the
  claimed capture surface. HTTP/3 remains incompatible with the current TCP
  payload architecture and is guarded by a real negative-control workload.

### Removed

- Remove current documentation and validation references to the intentionally
  deleted Guara-specific production values overlay. The generic chart defaults
  and reduced-privilege overlay remain validated release surfaces.

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

[Unreleased]: https://github.com/guaracloud/e-navigator/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/guaracloud/e-navigator/compare/v0.2.0-rc.2...v0.2.0
[0.2.0-rc.2]: https://github.com/guaracloud/e-navigator/compare/v0.2.0-rc.1...v0.2.0-rc.2
[0.2.0-rc.1]: https://github.com/guaracloud/e-navigator/compare/v0.1.2...v0.2.0-rc.1
[0.1.2]: https://github.com/guaracloud/e-navigator/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/guaracloud/e-navigator/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/guaracloud/e-navigator/compare/v0.1.0-rc.3...v0.1.0
[0.1.0-rc.3]: https://github.com/guaracloud/e-navigator/compare/v0.1.0-rc.2...v0.1.0-rc.3
[0.1.0-rc.2]: https://github.com/guaracloud/e-navigator/compare/v0.1.0-rc.1...v0.1.0-rc.2
[0.1.0-rc.1]: https://github.com/guaracloud/e-navigator/tree/v0.1.0-rc.1
