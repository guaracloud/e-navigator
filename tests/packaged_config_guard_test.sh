#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

known_modules=(
  "source.aya_exec"
  "source.aya_network"
  "source.aya_dns"
  "source.aya_http"
  "source.aya_cpu_profile"
  "source.host_resource"
  "source.synthetic_exec"
  "processor.container_attribution"
  "generator.resource_metrics"
  "generator.network_metrics"
  "generator.dns_metrics"
  "generator.trace_correlation"
  "generator.request_correlation"
  "generator.profiling"
  "generator.dependency_graph"
  "generator.runtime_security"
  "sink.json_stdout"
  "sink.prometheus_http"
  "sink.otlp_http"
)

config_files=(
  "charts/e-navigator/values.yaml"
  "deploy/kubernetes/configmap.yaml"
)

for file in "${config_files[@]}"; do
  for module in "${known_modules[@]}"; do
    if ! grep -Fq "name = \"$module\"" "$file"; then
      printf '%s is missing packaged module row: %s\n' "$file" "$module" >&2
      exit 1
    fi
  done
done

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

awk '
  $0 == "  toml: |" { in_config = 1; next }
  in_config && substr($0, 1, 4) == "    " { print substr($0, 5); next }
  in_config { exit }
' charts/e-navigator/values.yaml >"$tmp_dir/chart-e-navigator.toml"

awk '
  $0 == "  e-navigator.toml: |" { in_config = 1; next }
  in_config && substr($0, 1, 4) == "    " { print substr($0, 5); next }
  in_config { exit }
' deploy/kubernetes/configmap.yaml >"$tmp_dir/static-e-navigator.toml"

test -s "$tmp_dir/chart-e-navigator.toml"
test -s "$tmp_dir/static-e-navigator.toml"

cargo run --quiet --locked -p e-navigator-cli -- \
  --validate-config \
  --config "$tmp_dir/chart-e-navigator.toml"
cargo run --quiet --locked -p e-navigator-cli -- \
  --validate-config \
  --config "$tmp_dir/static-e-navigator.toml"
