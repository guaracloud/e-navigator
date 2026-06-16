#!/usr/bin/env sh
set -eu

require_tool() {
  tool="$1"
  install="$2"
  if ! command -v "$tool" >/dev/null 2>&1; then
    printf '%s\n' "$tool is required for scripts/quality.sh; install with: $install" >&2
    missing_tools=1
  fi
}

missing_tools=0
if [ "${E_NAVIGATOR_SKIP_SUPPLY_CHAIN:-0}" != "1" ]; then
  require_tool cargo-deny 'cargo install cargo-deny --locked'
  require_tool cargo-audit 'cargo install cargo-audit --locked'
  require_tool cargo-machete 'cargo install cargo-machete --locked'
  if [ "$missing_tools" -ne 0 ]; then
    printf '%s\n' 'Set E_NAVIGATOR_SKIP_SUPPLY_CHAIN=1 only for constrained local environments.' >&2
    exit 1
  fi
else
  printf '%s\n' 'Skipping supply-chain checks because E_NAVIGATOR_SKIP_SUPPLY_CHAIN=1 is set.' >&2
fi

cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets --exclude e-navigator-ebpf-programs -- -D warnings
cargo test --locked --workspace --exclude e-navigator-ebpf-programs
cargo build --locked --workspace --exclude e-navigator-ebpf-programs
cargo run --locked -p e-navigator-cli -- --source synthetic
git diff --check

if [ "${E_NAVIGATOR_SKIP_SUPPLY_CHAIN:-0}" != "1" ]; then
  cargo deny check
  cargo audit
  cargo machete
fi
