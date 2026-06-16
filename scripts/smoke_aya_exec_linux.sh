#!/usr/bin/env bash
set -euo pipefail

if [ "$(uname -s)" != "Linux" ]; then
  printf '%s\n' 'aya-exec smoke requires Linux with eBPF and tracefs support.' >&2
  exit 2
fi

config="${1:-}"
if [ -n "$config" ]; then
  exec sudo -E cargo run --locked -p e-navigator-cli --release -- --source aya-exec --config "$config"
fi

exec sudo -E cargo run --locked -p e-navigator-cli --release -- --source aya-exec
