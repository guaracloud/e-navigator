# Local Linux Development

## Non-Privileged Checks

```bash
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets --exclude e-navigator-ebpf-programs -- -D warnings
cargo test --locked --workspace --exclude e-navigator-ebpf-programs
cargo build --locked --workspace --exclude e-navigator-ebpf-programs
cargo run --locked -p e-navigator-cli -- --source synthetic
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
cargo run --locked -p e-navigator-cli -- --source synthetic
```

Expected result: newline-delimited JSON is printed to stdout, including attributed synthetic exec and process exit fixtures. With the default generator enabled, the synthetic shell execution also emits a runtime security finding.

## Docker Smoke Tests

```bash
docker build -f Containerfile -t e-navigator:local .
docker run --rm e-navigator:local --source synthetic
tests/smoke_docker.sh e-navigator:local
```

These checks are non-privileged and do not prove real eBPF attach behavior.

## Argv Capture

Exec argv capture is bounded and configurable:

- `enabled`: defaults to `true`.
- `max_args`: defaults to `8`.
- `max_bytes`: defaults to `512`.

Arguments can contain sensitive data. Disable argv capture or lower limits when running in environments where command-line arguments may include secrets.

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
Do not claim this test passed unless it ran on a Linux host with tracefs/eBPF support.
