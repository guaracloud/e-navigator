# Kubernetes Runtime Intelligence Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build Phase 2 Kubernetes Runtime Intelligence on top of the Phase 1 process exec foundation.

**Architecture:** Keep the existing static `Sources -> Processors -> Generators -> Sinks` runner path. Extend versioned signal schemas, harden the Aya process source behind the Aya crate boundary, enrich process signals with best-effort container and Kubernetes metadata, and add a statically registered runtime security generator.

**Tech Stack:** Rust 2024, Tokio, Serde, Aya, bounded eBPF perf events, procfs cgroup parsing, Kubernetes in-cluster API metadata cache, Docker, Kubernetes DaemonSet manifests.

---

## References

- `documentation/vision.md`
- `docs/superpowers/specs/2026-06-13-e-navigator-foundation-design.md`
- Current Phase 1 implementation under `crates/`, `deploy/kubernetes/`, and `docs/`

## Task 1: Harden Aya Process Source

**Files:**
- Modify: `crates/e-navigator-core/src/config.rs`
- Modify: `crates/e-navigator-sources-ebpf-aya/src/exec.rs`
- Modify: `crates/e-navigator-ebpf-programs/src/main.rs`
- Test: `crates/e-navigator-core/src/config.rs`
- Test: `crates/e-navigator-sources-ebpf-aya/src/exec.rs`

- [ ] Write failing config and source tests for bounded argv capture defaults, validation, disabled capture behavior, and truncation.
- [ ] Run the focused tests and verify they fail because argv capture config and parsing do not exist.
- [ ] Add `ArgvCaptureConfig` with explicit `enabled`, `max_args`, and `max_bytes` limits.
- [ ] Extend the Aya raw exec event with bounded argv fields using per-CPU scratch memory, fixed verifier-safe loops, and a map-controlled argv capture toggle.
- [ ] Convert raw bounded argv into `ExecEvent.arguments` only when configured.
- [ ] Run focused tests, then commit `feat: harden aya argv capture`.

## Task 2: Add Process Lifecycle Visibility

**Files:**
- Modify: `crates/e-navigator-signals/src/envelope.rs`
- Modify: `crates/e-navigator-signals/src/exec.rs`
- Modify: `crates/e-navigator-signals/src/lib.rs`
- Modify: `crates/e-navigator-sources-ebpf-aya/src/exec.rs`
- Modify: `crates/e-navigator-ebpf-programs/src/main.rs`
- Modify: `crates/e-navigator-runner/src/runtime.rs`
- Test: signal serialization and runner routing tests

- [ ] Write failing tests for `process_exit` and `process_lifecycle_duration` serialization.
- [ ] Write a failing runner test proving non-exec signal routing reaches sinks.
- [ ] Add versioned `ProcessExitEvent` and `ProcessLifecycleDurationEvent` payloads without changing the existing exec signal constructor.
- [ ] Extend the Aya source with a required `sched_process_exit` attachment and an exit perf reader.
- [ ] Run focused tests, then commit `feat: add process lifecycle signals`.

## Task 3: Implement Container And Kubernetes Attribution

**Files:**
- Modify: `crates/e-navigator-core/src/config.rs`
- Modify: `crates/e-navigator-signals/src/exec.rs`
- Modify: `crates/e-navigator-processors/src/container_attribution.rs`
- Modify: `crates/e-navigator-processors/Cargo.toml`
- Test: attribution parsing and enrichment tests

- [ ] Write failing parser tests for Docker, containerd, and CRI-O cgroup patterns.
- [ ] Write failing processor tests for procfs-backed exec enrichment and Kubernetes cache label enrichment.
- [ ] Add attribution config for procfs root, Kubernetes enablement, and service account paths.
- [ ] Parse `/proc/<pid>/cgroup` using bounded file reads and non-fatal structured warnings.
- [ ] Add an in-cluster Kubernetes metadata cache that lists pods with service-account credentials when enabled.
- [ ] Enrich process signals with container ID/runtime plus namespace, pod, pod UID, container, node, and labels when available.
- [ ] Run focused tests, then commit `feat: add runtime attribution`.

## Task 4: Add First Runtime Security Generator

**Files:**
- Create: `crates/e-navigator-generators/Cargo.toml`
- Create: `crates/e-navigator-generators/src/lib.rs`
- Create: `crates/e-navigator-generators/src/runtime_security.rs`
- Modify: `Cargo.toml`
- Modify: `crates/e-navigator-signals/src/envelope.rs`
- Modify: `crates/e-navigator-signals/src/lib.rs`
- Modify: `crates/e-navigator-cli/src/main.rs`
- Test: generator deterministic and low-noise tests

- [ ] Write failing tests for exact shell-in-container detection, exact network-tool detection, deterministic output, and benign commands producing no finding.
- [ ] Add `RuntimeSecurityFinding` versioned payload with rule ID, severity, matched process, and attribution context.
- [ ] Implement a statically registered generator for exact basename matches only.
- [ ] Register the generator through config-controlled static registry wiring.
- [ ] Run focused tests, then commit `feat: add runtime security generator`.

## Task 5: Improve Synthetic And Docker Verification

**Files:**
- Modify: `crates/e-navigator-cli/src/main.rs`
- Modify: `Containerfile`
- Create: `tests/smoke_docker.sh`
- Test: CLI synthetic output tests where practical

- [ ] Write failing CLI tests or fixture tests proving synthetic attributed exec and exit events exist.
- [ ] Extend the synthetic source to emit attributed exec and process exit fixtures.
- [ ] Keep JSON stdout newline-delimited.
- [ ] Add Docker smoke coverage for default synthetic runtime and config-mounted synthetic runtime.
- [ ] Run focused tests and Docker build/run where available, then commit `test: add phase 2 smoke fixtures`.

## Task 6: Improve Kubernetes Packaging

**Files:**
- Modify: `deploy/kubernetes/configmap.yaml`
- Modify: `deploy/kubernetes/rbac.yaml`
- Modify: `deploy/kubernetes/daemonset.yaml`
- Modify: `.github/workflows/ci.yml`

- [ ] Update the ConfigMap for Phase 2 argv, attribution, and generator config.
- [ ] Keep one DaemonSet pod per node and one `e-navigator` process per pod.
- [ ] Scope RBAC to pod/node metadata needed for attribution.
- [ ] Keep non-privileged CI manifest validation only.
- [ ] Commit `chore: update kubernetes phase 2 packaging`.

## Task 7: Documentation And ADRs

**Files:**
- Create: `docs/adr/0004-argv-capture-limits.md`
- Create: `docs/adr/0005-kubernetes-attribution-strategy.md`
- Create: `docs/adr/0006-runtime-security-generator-scope.md`
- Modify: `README.md`
- Modify: `docs/development/local-linux.md`
- Modify: `docs/development/kubernetes.md`

- [ ] Document argv capture limits and sensitive-data handling.
- [ ] Document Kubernetes attribution strategy and failure behavior.
- [ ] Document the first generator scope and service-account token path access as future work until file-open visibility exists.
- [ ] Add Phase 2 verification commands and privileged-test caveats.
- [ ] Commit `docs: describe phase 2 runtime intelligence`.

## Final Verification

Run:

```bash
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets --exclude e-navigator-ebpf-programs -- -D warnings
cargo test --locked --workspace --exclude e-navigator-ebpf-programs
cargo build --locked --workspace --exclude e-navigator-ebpf-programs
cargo run --locked -p e-navigator-cli -- --source synthetic
docker build -f Containerfile -t e-navigator:local .
docker run --rm e-navigator:local --source synthetic
git diff --check
git status --short
```

Privileged real eBPF and Kubernetes smoke tests are documented separately and are not claimed unless run on a real Linux/Kubernetes environment with the required privileges.
