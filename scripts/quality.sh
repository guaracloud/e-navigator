#!/usr/bin/env sh
set -eu

cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets --exclude e-navigator-ebpf-programs -- -D warnings
cargo test --locked --workspace --exclude e-navigator-ebpf-programs
cargo build --locked --workspace --exclude e-navigator-ebpf-programs
cargo run --locked -p e-navigator-cli -- --source synthetic
git diff --check

if command -v cargo-deny >/dev/null 2>&1; then
  cargo deny check
else
  printf '%s\n' 'cargo-deny is not installed; install with: cargo install cargo-deny --locked' >&2
fi

if command -v cargo-audit >/dev/null 2>&1; then
  cargo audit
else
  printf '%s\n' 'cargo-audit is not installed; install with: cargo install cargo-audit --locked' >&2
fi

if command -v cargo-machete >/dev/null 2>&1; then
  cargo machete
else
  printf '%s\n' 'cargo-machete is not installed; install with: cargo install cargo-machete --locked' >&2
fi
