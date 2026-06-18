# Repository Guidelines

## Project Structure & Module Organization

E-Navigator is a Rust 2024 workspace under `crates/`. Core contracts live in `e-navigator-core`, versioned signal schemas in `e-navigator-signals`, protocol and profiling models in `e-navigator-protocol` and `e-navigator-profiling`, and runtime wiring in `e-navigator-runner`. Sources are split between `e-navigator-sources-host` and `e-navigator-sources-ebpf-aya`; processors, generators, sinks, and the CLI each have their own crates. Integration tests live in `crates/*/tests/`. Deployment assets are in `Containerfile`, `charts/e-navigator/`, `deploy/kubernetes/`, and `tests/smoke_docker.sh`. Architecture records and boundaries are in `documentation/`.

## Build, Test, and Development Commands

- `scripts/quality.sh`: full non-privileged local gate; includes Rust checks, supply-chain tools, Docker smoke, Kubernetes dry-runs, and `git diff --check`.
- `cargo fmt --all -- --check`: verify formatting.
- `cargo clippy --locked --workspace --all-targets --exclude e-navigator-ebpf-programs -- -D warnings`: run strict linting for host-side crates.
- `cargo test --locked --workspace --exclude e-navigator-ebpf-programs`: run workspace tests except eBPF programs.
- `cargo run --locked -p e-navigator-cli -- --source synthetic`: exercise the CLI without privileged Linux dependencies.
- `helm lint charts/e-navigator` and `helm template e-navigator charts/e-navigator`: validate Helm packaging.
- `scripts/smoke_aya_exec_linux.sh` and `scripts/smoke_aya_cpu_profile_linux.sh <config>`: privileged Linux-only eBPF smoke tests.

Use `E_NAVIGATOR_SKIP_SUPPLY_CHAIN=1`, `E_NAVIGATOR_SKIP_DOCKER=1`, or `E_NAVIGATOR_SKIP_KUBERNETES=1` only for constrained local environments.

## Coding Style & Naming Conventions

Use Rust 2024 with `rustfmt.toml` settings: Unix newlines, field init shorthand, and try shorthand. Workspace lints forbid unsafe code and deny `dbg!`, `todo!`, and `unimplemented!`. Use kebab-case crate names and snake_case modules, functions, and tests. Preserve the statically registered `Source -> Processor -> Generator -> Sink` pipeline; do not add runtime plugin loading without an ADR.

## Testing Guidelines

Add tests near the behavior they cover: unit tests in `src`, integration tests in `crates/*/tests/`, and golden signal coverage under `crates/e-navigator-signals/tests/`. Prefer fixture-backed, non-privileged tests for schemas, parsers, generators, and sinks. Do not claim privileged Aya, perf-event, DNS runtime capture, or Kubernetes runtime proof unless it ran on a capable Linux host or cluster.

## Commit & Pull Request Guidelines

Git history uses Conventional Commit-style summaries such as `feat: moved documentation` and `chore: harden rust quality gates`. Keep commits imperative and scoped to one concern. PRs should describe the change, list verification commands run, link any relevant issue or ADR, and call out skipped gates with the exact environment reason. Include screenshots only for UI-facing docs or rendered artifacts.

## Security & Configuration Tips

Run `cargo deny check`, `cargo audit`, and `cargo machete` through `scripts/quality.sh` before review. Keep bounded limits, schema versions, attribution warnings, and explicit non-goals intact unless the implementation and tests change with them.
