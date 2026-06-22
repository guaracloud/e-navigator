#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

program="crates/e-navigator-ebpf-programs/src/main.rs"

if ! grep -Fq "NEG_EINPROGRESS" "$program"; then
  printf 'expected %s to name and handle nonblocking connect EINPROGRESS\n' "$program" >&2
  exit 1
fi

if ! grep -Fq "retval != NEG_EINPROGRESS" "$program"; then
  printf 'expected %s connect-exit failure branch to exclude EINPROGRESS\n' "$program" >&2
  exit 1
fi
