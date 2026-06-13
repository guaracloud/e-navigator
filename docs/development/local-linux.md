# Local Linux Development

## Non-Privileged Checks

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --exclude e-navigator-ebpf-programs
cargo build --workspace --exclude e-navigator-ebpf-programs
```

## Aya Prerequisites

Install the Rust nightly toolchain with `rust-src`, `bpf-linker`, and `bpftool`:

```bash
rustup toolchain install nightly --component rust-src
cargo install bpf-linker
```

Install `bpftool` from the Linux distribution package manager.

## Synthetic Runner

```bash
cargo run -p e-navigator-cli -- --source synthetic
```

Expected result: one newline-delimited JSON exec signal is printed to stdout.

## Privileged Aya Exec Smoke Test

```bash
cargo run -p e-navigator-cli --release -- --source aya-exec
```

In another shell:

```bash
/bin/true
```

Expected result: the runner prints JSON exec signals from `source.aya_exec`.
