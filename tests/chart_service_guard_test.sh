#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

render_chart() {
  local name="$1"
  shift
  helm template e-navigator charts/e-navigator "$@" >"$tmp_dir/${name}.yaml"
}

has_kind() {
  local file="$1"
  local kind="$2"
  grep -Eq "^kind: ${kind}$" "$file"
}

expect_kind() {
  local file="$1"
  local kind="$2"
  if ! has_kind "$file" "$kind"; then
    printf 'expected rendered chart to include kind: %s in %s\n' "$kind" "$file" >&2
    exit 1
  fi
}

expect_no_kind() {
  local file="$1"
  local kind="$2"
  if has_kind "$file" "$kind"; then
    printf 'expected rendered chart not to include kind: %s in %s\n' "$kind" "$file" >&2
    exit 1
  fi
}

render_chart default
expect_no_kind "$tmp_dir/default.yaml" Service
expect_no_kind "$tmp_dir/default.yaml" ServiceMonitor
if ! grep -Fq 'checksum/config:' "$tmp_dir/default.yaml"; then
  printf 'expected rendered DaemonSet pod template to include checksum/config annotation\n' >&2
  exit 1
fi

render_chart service_only --set service.enabled=true
expect_no_kind "$tmp_dir/service_only.yaml" Service
expect_no_kind "$tmp_dir/service_only.yaml" ServiceMonitor

render_chart health_service \
  --set service.enabled=true \
  --set health.enabled=true \
  --set serviceMonitor.enabled=true
expect_kind "$tmp_dir/health_service.yaml" Service
expect_no_kind "$tmp_dir/health_service.yaml" ServiceMonitor

render_chart prometheus_service \
  --set service.enabled=true \
  --set prometheusHttp.enabled=true
expect_kind "$tmp_dir/prometheus_service.yaml" Service
expect_no_kind "$tmp_dir/prometheus_service.yaml" ServiceMonitor

render_chart prometheus_monitor \
  --set service.enabled=true \
  --set prometheusHttp.enabled=true \
  --set serviceMonitor.enabled=true
expect_kind "$tmp_dir/prometheus_monitor.yaml" Service
expect_kind "$tmp_dir/prometheus_monitor.yaml" ServiceMonitor
