#!/usr/bin/env bash
set -euo pipefail

image="${1:-e-navigator:local}"
tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"

default_output="$tmp_dir/default.jsonl"
config_output="$tmp_dir/config.jsonl"
config_file="$tmp_dir/e-navigator.toml"
configmap_config_file="$tmp_dir/e-navigator-configmap.toml"

assert_min_lines() {
  file="$1"
  min_lines="$2"
  actual="$(wc -l <"$file" | tr -d ' ')"
  if [ "$actual" -lt "$min_lines" ]; then
    printf 'expected at least %s lines in %s, got %s\n' "$min_lines" "$file" "$actual" >&2
    return 1
  fi
}

assert_contains() {
  file="$1"
  pattern="$2"
  if ! grep -q "$pattern" "$file"; then
    printf 'expected %s to contain pattern: %s\n' "$file" "$pattern" >&2
    return 1
  fi
}

docker run --rm "$image" --source synthetic >"$default_output"
assert_min_lines "$default_output" 2
assert_contains "$default_output" '"kind":"exec"'
assert_contains "$default_output" '"kind":"process_exit"'
assert_contains "$default_output" '"kind":"network_connection_open"'
assert_contains "$default_output" '"kind":"network_connection_close"'
assert_contains "$default_output" '"kind":"network_connection_failure"'
assert_contains "$default_output" '"kind":"dns_query"'
assert_contains "$default_output" '"kind":"dns_response"'
assert_contains "$default_output" '"kind":"trace_span_observation"'
assert_contains "$default_output" '"kind":"protocol_request_observation"'
assert_contains "$default_output" '"kind":"request_span_observation"'
assert_contains "$default_output" '"kind":"request_correlation_warning"'
assert_contains "$default_output" '"kind":"profile_sample_observation"'
assert_contains "$default_output" '"kind":"profiling_session_observation"'
assert_contains "$default_output" '"kind":"profiling_warning_observation"'
assert_contains "$default_output" '"kind":"service_interaction_span_observation"'
assert_contains "$default_output" '"kind":"trace_service_path_observation"'
assert_contains "$default_output" '"kind":"network_counter_metric"'
assert_contains "$default_output" '"kind":"network_duration_metric"'
assert_contains "$default_output" '"kind":"network_gauge_metric"'
assert_contains "$default_output" '"kind":"dns_counter_metric"'
assert_contains "$default_output" '"kind":"dns_latency_metric"'
assert_contains "$default_output" '"kind":"node_cpu_observation"'
assert_contains "$default_output" '"kind":"node_load_observation"'
assert_contains "$default_output" '"kind":"node_memory_observation"'
assert_contains "$default_output" '"kind":"node_filesystem_observation"'
assert_contains "$default_output" '"kind":"node_disk_io_observation"'
assert_contains "$default_output" '"kind":"process_resource_observation"'
assert_contains "$default_output" '"kind":"cgroup_cpu_observation"'
assert_contains "$default_output" '"kind":"cgroup_memory_observation"'
assert_contains "$default_output" '"kind":"cgroup_pids_observation"'
assert_contains "$default_output" '"kind":"cgroup_file_descriptor_observation"'
assert_contains "$default_output" '"kind":"resource_gauge_metric"'
assert_contains "$default_output" '"kind":"resource_counter_metric"'
assert_contains "$default_output" '"metric_name":"system.cpu.load_average.milli"'
assert_contains "$default_output" '"metric_name":"system.memory.available"'
assert_contains "$default_output" '"metric_name":"system.disk.io"'
assert_contains "$default_output" '"metric_name":"container.memory.usage"'
assert_contains "$default_output" '"metric_name":"container.file_descriptor.count"'
assert_contains "$default_output" '"kind":"dependency_edge"'
assert_contains "$default_output" '"kind":"runtime_security_finding"'
assert_contains "$default_output" '"rule_id":"runtime.shell_in_container"'
assert_contains "$default_output" '"rule_id":"network.unexpected_external_connection"'
assert_contains "$default_output" '"duration_nanos":2000000'
assert_contains "$default_output" '"trace_id":"4bf92f3577b34da6a3ce929d0e0e4736"'
assert_contains "$default_output" '"warning_type":"malformed_profile_fixture"'
assert_contains "$default_output" '"warning_type":"missing_trace_context"'
assert_contains "$default_output" '"warning_type":"malformed_trace_context"'
assert_contains "$default_output" '"error_type":"errno_111"'

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

[trace_correlation]
max_service_paths = 4096
max_seen_interactions = 8192
max_warnings = 1024

[request_correlation]
max_seen_requests = 8192
max_warnings = 1024

[profiling]
max_windows = 4096
max_seen_samples = 8192
max_warnings = 1024
window_nanos = 30000000000

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
name = "generator.trace_correlation"
enabled = true

[[modules]]
name = "generator.request_correlation"
enabled = true

[[modules]]
name = "generator.profiling"
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

awk '
  $0 == "  e-navigator.toml: |" { in_config = 1; next }
  in_config && substr($0, 1, 4) == "    " { print substr($0, 5); next }
  in_config { exit }
' "$repo_root/deploy/kubernetes/configmap.yaml" >"$configmap_config_file"
test -s "$configmap_config_file"
docker run --rm \
  -v "$configmap_config_file:/etc/e-navigator/e-navigator.toml:ro" \
  "$image" \
  --config /etc/e-navigator/e-navigator.toml \
  --validate-config

assert_min_lines "$config_output" 2
assert_contains "$config_output" '"kind":"exec"'
assert_contains "$config_output" '"kind":"process_exit"'
assert_contains "$config_output" '"kind":"network_connection_open"'
assert_contains "$config_output" '"kind":"network_connection_close"'
assert_contains "$config_output" '"kind":"network_connection_failure"'
assert_contains "$config_output" '"kind":"dns_query"'
assert_contains "$config_output" '"kind":"dns_response"'
assert_contains "$config_output" '"kind":"trace_span_observation"'
assert_contains "$config_output" '"kind":"protocol_request_observation"'
assert_contains "$config_output" '"kind":"request_span_observation"'
assert_contains "$config_output" '"kind":"request_correlation_warning"'
assert_contains "$config_output" '"kind":"profile_sample_observation"'
assert_contains "$config_output" '"kind":"profiling_session_observation"'
assert_contains "$config_output" '"kind":"profiling_warning_observation"'
assert_contains "$config_output" '"kind":"service_interaction_span_observation"'
assert_contains "$config_output" '"kind":"trace_service_path_observation"'
assert_contains "$config_output" '"kind":"network_counter_metric"'
assert_contains "$config_output" '"kind":"network_duration_metric"'
assert_contains "$config_output" '"kind":"network_gauge_metric"'
assert_contains "$config_output" '"kind":"dns_counter_metric"'
assert_contains "$config_output" '"kind":"dns_latency_metric"'
assert_contains "$config_output" '"kind":"node_cpu_observation"'
assert_contains "$config_output" '"kind":"node_load_observation"'
assert_contains "$config_output" '"kind":"node_memory_observation"'
assert_contains "$config_output" '"kind":"node_filesystem_observation"'
assert_contains "$config_output" '"kind":"node_disk_io_observation"'
assert_contains "$config_output" '"kind":"process_resource_observation"'
assert_contains "$config_output" '"kind":"cgroup_cpu_observation"'
assert_contains "$config_output" '"kind":"cgroup_memory_observation"'
assert_contains "$config_output" '"kind":"cgroup_pids_observation"'
assert_contains "$config_output" '"kind":"cgroup_file_descriptor_observation"'
assert_contains "$config_output" '"kind":"resource_gauge_metric"'
assert_contains "$config_output" '"kind":"resource_counter_metric"'
assert_contains "$config_output" '"metric_name":"system.cpu.load_average.milli"'
assert_contains "$config_output" '"metric_name":"system.memory.available"'
assert_contains "$config_output" '"metric_name":"system.disk.io"'
assert_contains "$config_output" '"metric_name":"container.memory.usage"'
assert_contains "$config_output" '"metric_name":"container.file_descriptor.count"'
assert_contains "$config_output" '"kind":"dependency_edge"'
assert_contains "$config_output" '"kind":"runtime_security_finding"'
assert_contains "$config_output" '"rule_id":"runtime.shell_in_container"'
assert_contains "$config_output" '"rule_id":"network.unexpected_external_connection"'
assert_contains "$config_output" '"duration_nanos":2000000'
assert_contains "$config_output" '"trace_id":"4bf92f3577b34da6a3ce929d0e0e4736"'
assert_contains "$config_output" '"warning_type":"malformed_profile_fixture"'
assert_contains "$config_output" '"warning_type":"missing_trace_context"'
assert_contains "$config_output" '"warning_type":"malformed_trace_context"'
assert_contains "$config_output" '"error_type":"errno_111"'
