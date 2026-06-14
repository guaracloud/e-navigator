# E-Navigator

E-Navigator is a Rust and eBPF observability, security, profiling, and diagnostics platform for Linux and Kubernetes workloads.

Phase 2 builds Kubernetes runtime intelligence on the Phase 1 foundation:

- A layered Rust workspace.
- A statically registered signal pipeline.
- A local Linux runner.
- Kubernetes DaemonSet packaging.
- An Aya process exec and process exit source.
- Bounded, configurable argv capture.
- Best-effort container and Kubernetes attribution.
- A narrow runtime security generator for shell-in-container and network-tool execution.
- JSON stdout output.

## Development

Run non-privileged checks:

```bash
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets --exclude e-navigator-ebpf-programs -- -D warnings
cargo test --locked --workspace --exclude e-navigator-ebpf-programs
cargo build --locked --workspace --exclude e-navigator-ebpf-programs
cargo run --locked -p e-navigator-cli -- --source synthetic
docker build -f Containerfile -t e-navigator:local .
docker run --rm e-navigator:local --source synthetic
tests/smoke_docker.sh e-navigator:local
```

Aya/eBPF development also requires the nightly Rust toolchain with `rust-src`, `bpf-linker`, and `bpftool`.

See:

- `docs/development/local-linux.md`
- `docs/development/kubernetes.md`

## Verification

Non-privileged checks:

```bash
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets --exclude e-navigator-ebpf-programs -- -D warnings
cargo test --locked --workspace --exclude e-navigator-ebpf-programs
cargo build --locked --workspace --exclude e-navigator-ebpf-programs
cargo run --locked -p e-navigator-cli -- --source synthetic
docker build -f Containerfile -t e-navigator:local .
docker run --rm e-navigator:local --source synthetic
tests/smoke_docker.sh e-navigator:local
```

Privileged eBPF smoke test on Linux:

```bash
sudo -E cargo run -p e-navigator-cli --release -- --source aya-exec
```

Do not treat privileged Aya or Kubernetes runtime tests as passed unless they run on a real Linux host or Kubernetes cluster with tracefs/eBPF support and the documented privileges.
