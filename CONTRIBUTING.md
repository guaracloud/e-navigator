# Contributing

E-Navigator keeps runtime behavior reviewable through a statically registered Rust pipeline. Contributions must preserve the existing `Source -> Processor -> Generator -> Sink` architecture unless an ADR justifies a change.

## Required Local Gate

Run the full non-privileged gate before submitting changes:

```bash
scripts/quality.sh
```

The strict gate requires `cargo-deny`, `cargo-audit`, and `cargo-machete`. In constrained local environments only, use:

```bash
E_NAVIGATOR_SKIP_SUPPLY_CHAIN=1 scripts/quality.sh
```

Docker and Kubernetes dry-runs are part of the default local gate. They may be skipped only when the local machine cannot run them:

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
docker build -f Containerfile -t e-navigator:local .
docker run --rm e-navigator:local --source synthetic
tests/smoke_docker.sh e-navigator:local
kubectl apply --dry-run=client -f deploy/kubernetes/namespace.yaml
kubectl apply --dry-run=client -f deploy/kubernetes/rbac.yaml
kubectl apply --dry-run=client -f deploy/kubernetes/configmap.yaml
kubectl apply --dry-run=client -f deploy/kubernetes/daemonset.yaml
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
typos
taplo fmt --check Cargo.toml crates/*/Cargo.toml
yamllint .github/workflows/ci.yml deploy/kubernetes
```

## Boundaries

- Do not add runtime plugin loading.
- Do not weaken bounds, schemas, or explicit non-goal language.
- Do not claim production OTLP, pprof, Pyroscope, UI, storage, live HTTP/gRPC parsing, runtime DNS capture, or full continuous profiling without implementation and integration tests.
- Separate non-privileged parser/decode/generator/smoke proof from privileged Linux, eBPF, and Kubernetes proof.
