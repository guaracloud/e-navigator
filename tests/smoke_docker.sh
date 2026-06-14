#!/usr/bin/env bash
set -euo pipefail

image="${1:-e-navigator:local}"
tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

default_output="$tmp_dir/default.jsonl"
config_output="$tmp_dir/config.jsonl"
config_file="$tmp_dir/e-navigator.toml"

docker run --rm "$image" --source synthetic >"$default_output"
test "$(wc -l <"$default_output" | tr -d ' ')" -ge 2
grep -q '"kind":"exec"' "$default_output"
grep -q '"kind":"process_exit"' "$default_output"

cat >"$config_file" <<'CONFIG'
log_level = "info"
queue_capacity = 32

[argv_capture]
enabled = false
max_args = 8
max_bytes = 512

[attribution]
procfs_root = "/proc"

[attribution.kubernetes]
enabled = false

[[modules]]
name = "source.synthetic_exec"
enabled = true

[[modules]]
name = "processor.container_attribution"
enabled = true

[[modules]]
name = "generator.runtime_security"
enabled = true

[[modules]]
name = "sink.json_stdout"
enabled = true
CONFIG

docker run --rm \
  -v "$config_file:/etc/e-navigator/e-navigator.toml:ro" \
  "$image" \
  --source synthetic \
  --config /etc/e-navigator/e-navigator.toml >"$config_output"

test "$(wc -l <"$config_output" | tr -d ' ')" -ge 2
grep -q '"kind":"exec"' "$config_output"
grep -q '"kind":"process_exit"' "$config_output"
