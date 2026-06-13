# E-Navigator

E-Navigator is a Rust and eBPF observability, security, profiling, and diagnostics platform for Linux and Kubernetes workloads.

Phase 1 builds the foundation:

- A layered Rust workspace.
- A statically registered signal pipeline.
- A local Linux runner.
- Kubernetes DaemonSet packaging.
- An Aya process exec source.
- JSON stdout output.

## Development

Run non-privileged checks:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo build --workspace
```

Aya/eBPF development also requires the nightly Rust toolchain with `rust-src`, `bpf-linker`, and `bpftool`.

See:

- `docs/development/local-linux.md`
- `docs/development/kubernetes.md`
