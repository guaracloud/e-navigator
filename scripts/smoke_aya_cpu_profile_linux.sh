#!/usr/bin/env bash
set -euo pipefail

if [ "$(uname -s)" != "Linux" ]; then
  printf '%s\n' 'aya-cpu-profile smoke requires Linux with eBPF, perf-event, and tracefs support.' >&2
  exit 2
fi

config="${1:-}"
if [ -z "$config" ]; then
  printf '%s\n' 'usage: scripts/smoke_aya_cpu_profile_linux.sh /path/to/e-navigator-cpu-profile.toml' >&2
  printf '%s\n' 'the config must enable [cpu_profile_source] and source.aya_cpu_profile.' >&2
  exit 2
fi

exec sudo -E cargo run --locked -p e-navigator-cli --release -- --source aya-cpu-profile --config "$config"
