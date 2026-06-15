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
grep -q '"kind":"network_connection_open"' "$default_output"
grep -q '"kind":"network_connection_close"' "$default_output"
grep -q '"kind":"dns_query"' "$default_output"
grep -q '"kind":"dns_response"' "$default_output"
grep -q '"kind":"network_counter_metric"' "$default_output"
grep -q '"kind":"network_duration_metric"' "$default_output"
grep -q '"kind":"network_gauge_metric"' "$default_output"
grep -q '"kind":"dns_counter_metric"' "$default_output"
grep -q '"kind":"dns_latency_metric"' "$default_output"
grep -q '"kind":"node_memory_observation"' "$default_output"
grep -q '"kind":"process_resource_observation"' "$default_output"
grep -q '"kind":"cgroup_memory_observation"' "$default_output"
grep -q '"kind":"resource_gauge_metric"' "$default_output"
grep -q '"kind":"resource_counter_metric"' "$default_output"
grep -q '"metric_name":"system.memory.available"' "$default_output"
grep -q '"metric_name":"container.memory.usage"' "$default_output"
grep -q '"kind":"dependency_edge"' "$default_output"
grep -q '"kind":"runtime_security_finding"' "$default_output"
grep -q '"rule_id":"runtime.shell_in_container"' "$default_output"
grep -q '"rule_id":"network.unexpected_external_connection"' "$default_output"
grep -q '"duration_nanos":2000000' "$default_output"

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
name = "generator.dependency_graph"
enabled = true

[[modules]]
name = "generator.network_metrics"
enabled = true

[[modules]]
name = "generator.dns_metrics"
enabled = true

[[modules]]
name = "generator.resource_metrics"
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
grep -q '"kind":"network_connection_open"' "$config_output"
grep -q '"kind":"network_connection_close"' "$config_output"
grep -q '"kind":"dns_query"' "$config_output"
grep -q '"kind":"dns_response"' "$config_output"
grep -q '"kind":"network_counter_metric"' "$config_output"
grep -q '"kind":"network_duration_metric"' "$config_output"
grep -q '"kind":"network_gauge_metric"' "$config_output"
grep -q '"kind":"dns_counter_metric"' "$config_output"
grep -q '"kind":"dns_latency_metric"' "$config_output"
grep -q '"kind":"node_memory_observation"' "$config_output"
grep -q '"kind":"process_resource_observation"' "$config_output"
grep -q '"kind":"cgroup_memory_observation"' "$config_output"
grep -q '"kind":"resource_gauge_metric"' "$config_output"
grep -q '"kind":"resource_counter_metric"' "$config_output"
grep -q '"metric_name":"system.memory.available"' "$config_output"
grep -q '"metric_name":"container.memory.usage"' "$config_output"
grep -q '"kind":"dependency_edge"' "$config_output"
grep -q '"kind":"runtime_security_finding"' "$config_output"
grep -q '"rule_id":"runtime.shell_in_container"' "$config_output"
grep -q '"rule_id":"network.unexpected_external_connection"' "$config_output"
grep -q '"duration_nanos":2000000' "$config_output"
