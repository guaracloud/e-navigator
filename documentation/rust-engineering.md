# Rust Engineering Standard

E-Navigator uses Rust 2024 and a pinned minimum supported Rust version of 1.96.
This standard turns current Rust guidance into repository-specific rules. It
favors explicit bounds, reviewable behavior, measurable changes, and narrow
unsafe boundaries over fashionable abstractions.

## Primary References

- [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/checklist.html)
  for naming, traits, documentation, interoperability, and future-proofing.
- [The Cargo Book, workspaces and lints](https://doc.rust-lang.org/cargo/reference/workspaces.html)
  for shared package policy and inherited workspace settings.
- [Clippy documentation](https://doc.rust-lang.org/stable/clippy/)
  for lint groups, configuration, and lint stability.
- [Rustdoc lints](https://doc.rust-lang.org/rustdoc/lints.html) for public
  documentation correctness.
- [The Rust Performance Book](https://nnethercote.github.io/perf-book/)
  for measurement, profiling, allocation, and data-layout methodology.
- [Rust Fuzz Book](https://rust-fuzz.github.io/book/) for coverage-guided fuzz
  testing at untrusted input boundaries.
- [Cargo profiles](https://doc.rust-lang.org/cargo/reference/profiles.html) for
  measured build and optimization tradeoffs.
- [cargo-deny checks](https://embarkstudios.github.io/cargo-deny/checks/) and
  [RustSec cargo-audit](https://github.com/rustsec/rustsec/tree/main/cargo-audit)
  for dependency policy and advisory checks.

Primary sources describe general mechanisms. The rules below are the project
policy when several valid Rust designs exist.

## Public API And Documentation

- Every crate root explains its responsibility and important boundaries with
  crate-level documentation.
- Public types use Rust naming conventions, implement `Debug` unless unsafe or
  secret-bearing output makes that inappropriate, and expose constructors that
  make invalid state difficult to create.
- Public results use typed errors. Error messages add module context at the
  boundary where that context becomes known.
- Public API changes need tests, relevant documentation, and a SemVer review.
- Rustdoc warnings are denied in the quality gate. Broken intra-doc links and
  invalid code examples are regressions.

## Safety

- Unsafe code is forbidden outside the host and Aya source crates.
- Every unsafe operation must have a local, reviewable invariant about pointer
  validity, layout, lifetime, initialization, or FFI behavior.
- Raw kernel event decoders check the input length before reading a fixed event
  layout.
- Kernel and userspace event layouts change together and retain decode tests.
- Unsafe is never introduced only to improve a microbenchmark. A profiler must
  first show the safe implementation is a material bottleneck.

## Errors, Panics, And Poisoning

- Expected runtime failure returns `Result` or an explicit drop outcome.
- Production code does not use `unwrap`, `expect`, `panic`, `todo`, `dbg`, or
  `unimplemented` as control flow.
- Tests may use panic-oriented assertions when they make the contract clearer.
- A poisoned mutex becomes a typed module failure unless the owning state has a
  documented recovery rule.
- Sink failures are isolated, source failures follow the configured policy, and
  bounded loss is observable.

## Async And Concurrency

- Channels, queues, retries, response bodies, shutdown, and fanout are bounded.
- Do not hold a synchronous mutex guard across an `.await` point.
- CPU-heavy compression, symbolization, or parsing leaves the shared async
  signal path when measurement shows it can block cooperative scheduling.
- Pure synchronous generators and sinks use their immediate trait path. The
  async path remains for implementations that genuinely need asynchronous
  work or channel streaming.
- Cancellation and shutdown behavior must be tested, not inferred from a task
  handle being dropped.

## Data Structures And Allocation

- Choose data structures from measured size, ordering, lookup, and eviction
  needs. Do not replace bounded ordered maps with randomized maps solely on
  asymptotic arguments.
- Reuse allocations only when ownership remains clear and a benchmark shows
  meaningful savings.
- Avoid cloning complete signal envelopes in hot paths. Prefer borrowing,
  moving an owned result, or cloning only the bounded fields that cross an
  ownership boundary.
- Cardinality limits and eviction behavior are part of the public operational
  contract and need tests.

## Parsing And External Input

- Parsers accept explicit maximum sizes and reject truncated, oversized, or
  inconsistent input without panicking.
- Packet data, protocol streams, procfs text, ELF data, Kubernetes responses,
  environment variables, config files, and backend responses are untrusted.
- Keep fixture tests for known shapes, property tests for invariants, and fuzz
  targets for high-risk decode boundaries.
- Sanitization happens before export. Secret-like keys and unbounded raw values
  do not enter labels or attributes.

## Performance Change Protocol

1. Identify a user-visible resource or latency cost.
2. Add or select a benchmark that exercises the same dispatch path.
3. Save a pre-change Criterion baseline with fixed warmup, sample count, and
   measurement time.
4. Make one bounded, API-compatible change.
5. Compare confidence intervals and inspect outliers.
6. Run functional, property, fixture, fuzz-build, and full quality gates.
7. Describe the evidence tier accurately. A microbenchmark is not node-overhead
   proof, and one homelab run is not broad production proof.

Compiler profile changes require the same evidence. LTO, codegen-unit, panic,
and strip settings affect build time, debugging, binary size, and runtime in
different ways, so they are never changed by folklore alone.

## Review Checklist

- Does every allocation, clone, lock, and channel in the hot path have a clear
  ownership or concurrency reason?
- Are all loops, collections, payloads, retries, timeouts, and derived outputs
  bounded?
- Can malformed input, a poisoned lock, a closed channel, or backend failure
  panic the process?
- Does the test sit at the same abstraction boundary as the behavior?
- Does an eBPF or backend claim have real runtime evidence?
- Do README, website, capabilities, boundaries, and proof documentation still
  agree?
- Did the full gate run without unexplained skips?
