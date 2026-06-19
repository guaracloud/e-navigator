# Contributing

E-Navigator keeps runtime behavior reviewable through a statically registered Rust pipeline. Contributions must preserve the existing `Source -> Processor -> Generator -> Sink` architecture unless an ADR justifies a change.

## Required Local Gate

Run the full non-privileged gate before submitting changes:

```bash
scripts/quality.sh
```

The strict gate requires `cargo-deny`, `cargo-audit`, `cargo-machete`, Docker,
Helm, `kubeconform`, Node, and the normal Rust toolchain. On macOS with
Homebrew, install missing local-gate CLIs with:

```bash
brew install docker kubeconform
```

The `docker` formula installs the Docker CLI only. Docker smoke checks still
require a reachable Docker daemon, such as Docker Desktop or another compatible
local daemon. CLI installation alone is not Docker smoke evidence.

In constrained local environments only, use:

```bash
E_NAVIGATOR_SKIP_SUPPLY_CHAIN=1 scripts/quality.sh
```

```bash
E_NAVIGATOR_SKIP_DOCKER=1 E_NAVIGATOR_SKIP_KUBERNETES=1 scripts/quality.sh
```

## Mandatory Direct Commands

```bash
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets --exclude e-navigator-ebpf-programs -- -D warnings
cargo test --locked --workspace --exclude e-navigator-ebpf-programs
cargo build --locked --workspace --exclude e-navigator-ebpf-programs
cargo run --locked -p e-navigator-cli -- --source synthetic
helm lint charts/e-navigator
helm template e-navigator charts/e-navigator
docker build -f Containerfile -t e-navigator:local .
docker run --rm e-navigator:local --source synthetic
tests/smoke_docker.sh e-navigator:local
git diff --check
```

## Optional Local Tools

These are useful for release hardening but are not mandatory for every local edit:

```bash
cargo nextest run --locked --workspace --exclude e-navigator-ebpf-programs
cargo llvm-cov --locked --workspace --exclude e-navigator-ebpf-programs --summary-only
cargo bench --no-run --locked --workspace --exclude e-navigator-ebpf-programs
cargo mutants --package e-navigator-protocol --package e-navigator-profiling --package e-navigator-generators --timeout 60
cargo fuzz run traceparent_parser -- -max_total_time=60
cargo fuzz run http_request_parser -- -max_total_time=60
cargo fuzz run profile_fixture_parser -- -max_total_time=60
cargo fuzz run host_procfs_parsers -- -max_total_time=60
cargo fuzz run raw_exec_event_decode -- -max_total_time=60
cargo fuzz run raw_network_event_decode -- -max_total_time=60
cargo fuzz run raw_cpu_profile_event_decode -- -max_total_time=60
typos
taplo fmt --check Cargo.toml crates/*/Cargo.toml
yamllint .github/workflows charts/e-navigator deploy/kubernetes
```

## Boundaries

- Do not add runtime plugin loading.
- Do not weaken bounds, schemas, or explicit non-goal language.
- Do not claim production OTLP, pprof, Pyroscope, UI, storage, live HTTP/gRPC parsing, runtime DNS capture, or full continuous profiling without implementation and integration tests.
- Separate non-privileged parser/decode/generator/smoke proof from privileged Linux, eBPF, and Kubernetes proof.
