# Local Linux Development

## Non-Privileged Checks

```bash
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets --exclude e-navigator-ebpf-programs -- -D warnings
cargo test --locked --workspace --exclude e-navigator-ebpf-programs
cargo build --locked --workspace --exclude e-navigator-ebpf-programs
```

## Aya Prerequisites

Install the Rust nightly toolchain with `rust-src`, `bpf-linker`, and `bpftool`:

```bash
rustup toolchain install nightly --component rust-src
cargo install bpf-linker --version 0.10.3 --locked
```

Install `bpftool` from the Linux distribution package manager.

## Synthetic Runner

```bash
cargo run -p e-navigator-cli -- --source synthetic
```

Expected result: one newline-delimited JSON exec signal is printed to stdout.

## Privileged Aya Exec Smoke Test

```bash
sudo -E cargo run -p e-navigator-cli --release -- --source aya-exec
```

In another shell:

```bash
/bin/true
```

Expected result: the runner prints JSON exec signals from `source.aya_exec`.
The smoke test must run as root or with the Linux capabilities and rlimits required to load and attach eBPF programs.
