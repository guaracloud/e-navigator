# Rust Quality Excellence Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Raise e-navigator's Rust engineering quality by making lint policy, error boundaries, pipeline contracts, schema stability, boundedness, security hygiene, and runtime proof harder to bypass.

**Architecture:** Preserve the existing statically registered `Source -> Processor -> Generator -> Sink` runtime. Add policy, tests, scripts, and documentation around existing contracts before changing behavior. Keep runtime plugin loading, production OTLP/pprof/Pyroscope/UI/storage, live HTTP/gRPC parsing, runtime DNS capture, and full continuous profiling out of scope.

**Tech Stack:** Rust 2024 workspace, Tokio, serde, thiserror, proptest, Aya isolated in source crates, Docker, Kubernetes manifest dry-runs, cargo-deny/audit/machete, optional nextest/llvm-cov/cargo-fuzz/criterion/cargo-mutants.

---

## Audit Findings

### Rust Lints

- Workspace `Cargo.toml` does not centralize lint policy, so new crates can bypass the existing crate-level style guardrails.
- Most userspace crates have `#![forbid(unsafe_code)]`; `e-navigator-sources-host` and `e-navigator-sources-ebpf-aya` do not because they use localized `libc` and raw decode operations.
- Existing `unwrap`/`expect`/`panic` hits are test-only or build-script/main entrypoint paths. Runtime library code does not show obvious unguarded `unwrap` in the initial scan.

### Error Design

- `CoreError` is typed, but config validation returns broad `String` errors and runner module wrapping collapses failure class into `ModuleFailed { message: String }`.
- Runtime operation can benefit from explicit failure categories without changing CLI behavior: config, source attach, decode, backpressure, sink, and pipeline failures.

### Pipeline Contracts

- Runner already requires at least one source and sink and has bounded per-generator derived output.
- Ordered downstream generator fan-out exists and has a test, but the dependency graph to trace-correlation contract deserves a named regression test.
- Static registration is documented in ADR 0002 and engineering invariants; this should be reflected in module-authoring docs.

### Signal Schemas

- `SignalEnvelope` has explicit `SignalKind` plus central `SignalPayload`; schema additions are centralized.
- There is extensive round-trip coverage, but no golden JSON fixture files to make accidental formatting/schema drift obvious in review.

### Tests

- Existing unit/integration/property-style tests cover traceparent, HTTP fixtures, profiling normalization, cgroup container extraction, generators, runner fan-out, sinks, and raw Aya decode helpers.
- There is no `cargo-nextest` configuration. It can be optional locally unless installed.
- Coverage thresholds are not documented. Mutation testing guidance is absent.

### Fuzzing

- `cargo-fuzz` targets are documented as future work but not wired.
- Deterministic proptest coverage exists in normal Cargo tests and should remain mandatory.

### Benchmarks

- No Criterion benchmark harness exists for parsers/generators/pipeline throughput.
- Performance budgets are not documented; the first step should be measuring hot paths, not optimizing.

### CI/Release Hygiene

- `scripts/quality.sh` runs fmt, clippy, test, build, synthetic run, diff check, deny, audit, and machete.
- Docker smoke and Kubernetes dry-runs are documented but not included in the local quality script.
- CI lacks Docker build/run smoke and optional lint helpers such as typos/taplo/yamllint.

### eBPF Proof

- Aya userspace decode tests exist, including CPU profile decode fixtures.
- eBPF/kernel unsafe code is isolated, but privileged smoke proof remains documentation-only.
- ABI/layout checks can be made more explicit with userspace raw struct size tests.

### Docs

- README links currently point at `docs/development/...` and `docs/engineering-invariants.md`, while the repo uses `documentation/...`.
- No `CONTRIBUTING.md`, claims matrix, or module authoring guide exists.

---

## Phase 1: Lint Policy And Error Model

**Files:**
- Modify: `Cargo.toml`
- Modify: `crates/e-navigator-core/src/error.rs`
- Modify: `crates/e-navigator-core/src/config.rs`
- Modify: `crates/e-navigator-runner/src/runtime.rs`
- Modify: `crates/e-navigator-sources-host/src/lib.rs`
- Modify: `crates/e-navigator-sources-ebpf-aya/src/lib.rs`

- [ ] Add workspace lints in `Cargo.toml`:

```toml
[workspace.lints.rust]
unsafe_code = "forbid"
missing_debug_implementations = "warn"
rust_2018_idioms = "warn"
unreachable_pub = "warn"

[workspace.lints.clippy]
dbg_macro = "deny"
todo = "deny"
unimplemented = "deny"
panic = "warn"
unwrap_used = "warn"
expect_used = "warn"
```

- [ ] Add local `unsafe_code = "allow"` only to crates that require userspace unsafe for OS/raw decoding, and document why:

```toml
[lints.rust]
unsafe_code = "allow"
```

- [ ] Add `#![forbid(unsafe_code)]` to `e-navigator-sources-host` if `libc::sysconf` can be replaced safely, or keep the local crate exception documented if it cannot be removed without behavior risk.
- [ ] Introduce typed config validation errors in `CoreError`, preserving existing error text through `Display`.
- [ ] Add tests that invalid config errors preserve field names and runner module context.
- [ ] Run:

```bash
cargo test --locked -p e-navigator-core
cargo test --locked -p e-navigator-runner
cargo clippy --locked --workspace --all-targets --exclude e-navigator-ebpf-programs -- -D warnings
```

**Acceptance Criteria:**
- Workspace lint policy applies to new crates by default.
- Any userspace unsafe exception is local and justified.
- Config errors remain actionable and include the failing field.
- Existing clippy gate remains clean.

## Phase 2: Pipeline And Schema Contract Proof

**Files:**
- Modify: `crates/e-navigator-runner/src/runtime.rs`
- Modify: `crates/e-navigator-generators/tests/trace_correlation.rs`
- Create: `crates/e-navigator-signals/tests/golden_signals.rs`
- Create: `crates/e-navigator-signals/tests/golden/*.json`
- Create: `crates/e-navigator-sinks/tests/golden_formatters.rs`
- Create: `crates/e-navigator-sinks/tests/golden/*.json`

- [ ] Write failing tests proving dependency graph output can feed trace correlation in the configured static generator order.
- [ ] Add golden JSON fixtures for representative signal families: exec, network, DNS, dependency, resource, trace, request, and profiling.
- [ ] Add golden formatter fixtures for OTEL metric, OTEL trace, and profile internal formatter records.
- [ ] Keep `SignalKind`/`SignalPayload` central; do not introduce runtime dynamic dispatch.
- [ ] Run:

```bash
cargo test --locked -p e-navigator-runner
cargo test --locked -p e-navigator-generators --test trace_correlation
cargo test --locked -p e-navigator-signals
cargo test --locked -p e-navigator-sinks
```

**Acceptance Criteria:**
- Generator ordering/dependency behavior has an explicit regression test.
- Golden fixtures fail on schema or formatter drift.
- All signal families still have serialization/deserialization coverage.

## Phase 3: Quality Gate Upgrade

**Files:**
- Modify: `scripts/quality.sh`
- Modify: `.github/workflows/ci.yml`
- Create: `.config/nextest.toml`
- Create: `deny.toml` updates only if current checks require them

- [ ] Extend local quality to include Docker smoke and Kubernetes dry-runs unless explicitly skipped by environment variables.
- [ ] Add optional helper checks for nextest, llvm-cov, cargo-fuzz, cargo-mutants, typos, taplo, and yamllint with clear "optional locally" messaging.
- [ ] Keep mandatory supply-chain checks strict when tools are installed or not skipped.
- [ ] Run:

```bash
E_NAVIGATOR_SKIP_DOCKER=1 E_NAVIGATOR_SKIP_KUBERNETES=1 scripts/quality.sh
```

**Acceptance Criteria:**
- Mandatory and optional checks are clear.
- Missing optional tools do not fail constrained local runs.
- Required tools still fail loudly unless the existing skip flag is used.

## Phase 4: Performance, Fuzz, And Mutation Scaffolding

**Files:**
- Modify: `Cargo.toml`
- Create: `benches/parser_and_generator.rs`
- Create: `fuzz/Cargo.toml`
- Create: `fuzz/fuzz_targets/traceparent_parser.rs`
- Create: `fuzz/fuzz_targets/http_request_parser.rs`
- Create: `fuzz/fuzz_targets/profile_fixture_parser.rs`
- Create: `fuzz/fuzz_targets/host_procfs_parsers.rs`
- Create: `fuzz/fuzz_targets/raw_network_event_decode.rs`

- [ ] Add Criterion benchmark scaffolding for traceparent parsing, HTTP fixture parsing, profile fixture parsing, host procfs parser functions, generator hot paths, and synthetic pipeline throughput where practical.
- [ ] Add cargo-fuzz target scaffolding only if it does not destabilize normal workspace locked builds.
- [ ] Document cargo-mutants target sets rather than making mutation testing mandatory locally.
- [ ] Run:

```bash
cargo test --locked --workspace --exclude e-navigator-ebpf-programs
cargo bench --no-run --locked --workspace --exclude e-navigator-ebpf-programs
```

**Acceptance Criteria:**
- Benchmarks compile without running long measurements.
- Fuzz targets are bounded and map to existing parser/decode helpers.
- Mutation guidance is practical and non-mandatory.

## Phase 5: eBPF And Runtime Proof Documentation

**Files:**
- Modify: `crates/e-navigator-sources-ebpf-aya/src/exec.rs`
- Modify: `crates/e-navigator-sources-ebpf-aya/src/network.rs`
- Modify: `crates/e-navigator-sources-ebpf-aya/src/cpu_profile.rs`
- Create: `scripts/smoke_aya_exec_linux.sh`
- Create: `scripts/smoke_aya_cpu_profile_linux.sh`
- Create: `documentation/privileged-runtime-proof.md`

- [ ] Add explicit raw struct layout/size tests for exec, network, and CPU profile userspace decode helpers.
- [ ] Add privileged Linux smoke scripts that validate command shape and state their privilege requirements.
- [ ] Document exactly what local Linux and Kubernetes privileged runs prove, and what remains unproven.
- [ ] Run:

```bash
cargo test --locked -p e-navigator-sources-ebpf-aya
bash -n scripts/smoke_aya_exec_linux.sh
bash -n scripts/smoke_aya_cpu_profile_linux.sh
```

**Acceptance Criteria:**
- ABI/layout assumptions are tested at the userspace decode boundary.
- Privileged tests are not claimed unless run on Linux with required privileges.

## Phase 6: Documentation As Contracts

**Files:**
- Modify: `README.md`
- Modify: `documentation/engineering-invariants.md`
- Create: `CONTRIBUTING.md`
- Create: `documentation/claims-matrix.md`
- Create: `documentation/module-authoring.md`

- [ ] Add exact quality gates and local skip policy to `CONTRIBUTING.md`.
- [ ] Add a claims matrix with columns: implemented, synthetic-only, non-privileged proven, privileged-proven, deferred.
- [ ] Add a module authoring guide for sources, processors, generators, and sinks.
- [ ] Fix stale README links from `docs/...` to `documentation/...`.
- [ ] Run:

```bash
git diff --check
```

**Acceptance Criteria:**
- Docs align with current implementation.
- Claims remain evidence-backed and do not imply deferred production features.

## Final Required Verification

Run all non-privileged gates:

```bash
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets --exclude e-navigator-ebpf-programs -- -D warnings
cargo test --locked --workspace --exclude e-navigator-ebpf-programs
cargo build --locked --workspace --exclude e-navigator-ebpf-programs
cargo run --locked -p e-navigator-cli -- --source synthetic
docker build -f Containerfile -t e-navigator:local .
docker run --rm e-navigator:local --source synthetic
tests/smoke_docker.sh e-navigator:local
kubectl apply --dry-run=client -f deploy/kubernetes/namespace.yaml
kubectl apply --dry-run=client -f deploy/kubernetes/rbac.yaml
kubectl apply --dry-run=client -f deploy/kubernetes/configmap.yaml
kubectl apply --dry-run=client -f deploy/kubernetes/daemonset.yaml
git diff --check
```

Optional local tools, when installed:

```bash
cargo nextest run --locked --workspace --exclude e-navigator-ebpf-programs
cargo llvm-cov --locked --workspace --exclude e-navigator-ebpf-programs --summary-only
cargo bench --no-run --locked --workspace --exclude e-navigator-ebpf-programs
cargo mutants --package e-navigator-protocol --package e-navigator-profiling --package e-navigator-generators --timeout 60
cargo fuzz run traceparent_parser -- -max_total_time=60
typos
taplo fmt --check Cargo.toml crates/*/Cargo.toml
yamllint .github/workflows/ci.yml deploy/kubernetes
```
