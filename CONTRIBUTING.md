# Contributing

E-Navigator keeps runtime behavior reviewable through a statically registered Rust pipeline. Contributions must preserve the existing `Source -> Processor -> Generator -> Sink` architecture unless an ADR justifies a change.

## Required Local Gate

Run the full non-privileged gate before submitting changes:

```bash
scripts/quality.sh
```

Release-bound changes must also preserve the version and repository identity
contract enforced by `python3 scripts/release.py check`. Follow
`documentation/release-process.md`; never move or reuse a published tag.

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
python3 scripts/check_docs.py
cargo clippy --locked --workspace --all-targets --exclude e-navigator-ebpf-programs -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --locked --workspace --no-deps --exclude e-navigator-ebpf-programs
cargo test --locked --workspace --exclude e-navigator-ebpf-programs
cargo build --locked --workspace --exclude e-navigator-ebpf-programs
cargo run --locked -p e-navigator-cli -- --source synthetic
helm lint charts/e-navigator
helm template e-navigator charts/e-navigator
docker build -f Containerfile -t e-navigator:local .
docker run --rm e-navigator:local --source synthetic
tests/smoke_docker.sh e-navigator:local
node website/check-links.mjs
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

## Rust And Documentation Policy

- Production code does not use `unwrap`, `expect`, direct `panic`, `dbg`,
  `todo`, or `unimplemented`. Integration tests may carry a documented
  test-only allowance.
- Every crate has crate-level documentation, and rustdoc warnings fail CI.
- Add focused tests at the behavior boundary and fuzz untrusted parser or raw
  event boundaries.
- Start optimization work with a reproducible baseline. Keep microbenchmark,
  live-node, backend, and production claims separate.
- Use commas, parentheses, or separate sentences instead of em dashes in public
  documentation.
- Add every top-level guide and ADR to `documentation/README.md`, and keep the
  README and website routes current.

See [the Rust engineering standard](documentation/rust-engineering.md) and
[the documentation index](documentation/README.md).
