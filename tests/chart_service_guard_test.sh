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
if ! grep -Fq 'seccompProfile:' "$tmp_dir/default.yaml" || ! grep -Fq 'type: RuntimeDefault' "$tmp_dir/default.yaml"; then
  printf 'expected rendered DaemonSet container securityContext to use RuntimeDefault seccomp\n' >&2
  exit 1
fi
for expected in 'updateStrategy:' 'maxUnavailable: 10%' 'requests:' 'cpu: 150m' 'memory: 384Mi' 'terminationGracePeriodSeconds: 30'; do
  if ! grep -Fq "$expected" "$tmp_dir/default.yaml"; then
    printf 'expected rendered DaemonSet to include production default: %s\n' "$expected" >&2
    exit 1
  fi
done

render_chart service_only --set service.enabled=true
expect_no_kind "$tmp_dir/service_only.yaml" Service
expect_no_kind "$tmp_dir/service_only.yaml" ServiceMonitor

if helm template e-navigator charts/e-navigator --set health.enabled=true >"$tmp_dir/invalid_health.yaml" 2>/dev/null; then
  printf 'expected health probes without prometheusHttp.enabled to fail schema validation\n' >&2
  exit 1
fi

render_chart health_service \
  --set service.enabled=true \
  --set prometheusHttp.enabled=true \
  --set health.enabled=true
expect_kind "$tmp_dir/health_service.yaml" Service
expect_no_kind "$tmp_dir/health_service.yaml" ServiceMonitor
for probe in startupProbe livenessProbe readinessProbe; do
  if ! grep -Fq "${probe}:" "$tmp_dir/health_service.yaml"; then
    printf 'expected health-enabled DaemonSet to include %s\n' "$probe" >&2
    exit 1
  fi
done

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
