#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

set +e
output="$(
  E_NAVIGATOR_HOMELAB_CONFIRM=0 \
    benchmarks/runner/homelab-collect.sh 2>&1 >/dev/null
)"
status="$?"
set -e

if [ "$status" -ne 2 ]; then
  printf 'expected guard to exit 2, got %s\n%s\n' "$status" "$output" >&2
  exit 1
fi

case "$output" in
  *"refusing to run homelab validation without E_NAVIGATOR_HOMELAB_CONFIRM=1"* ) ;;
  * )
    printf 'guard output did not contain expected refusal\n%s\n' "$output" >&2
    exit 1
    ;;
esac

if ! grep -q 'E_NAVIGATOR_HOMELAB_IMAGE_PULL_SECRET' benchmarks/runner/homelab-collect.sh; then
  printf 'homelab collector does not expose E_NAVIGATOR_HOMELAB_IMAGE_PULL_SECRET\n' >&2
  exit 1
fi

if ! grep -Fq 'imagePullSecrets[0].name=$image_pull_secret' benchmarks/runner/homelab-collect.sh; then
  printf 'homelab collector does not pass imagePullSecrets to Helm\n' >&2
  exit 1
fi

if ! grep -q 'E_NAVIGATOR_HOMELAB_ENABLE_PROMETHEUS_HTTP' benchmarks/runner/homelab-collect.sh; then
  printf 'homelab collector does not expose E_NAVIGATOR_HOMELAB_ENABLE_PROMETHEUS_HTTP\n' >&2
  exit 1
fi

if ! grep -Fq -- '--set-file' benchmarks/runner/homelab-collect.sh ||
  ! grep -Fq 'config.toml=$prometheus_runtime_config' benchmarks/runner/homelab-collect.sh; then
  printf 'homelab collector does not pass an explicit Prometheus runtime config to Helm\n' >&2
  exit 1
fi

if ! grep -Fq 'current context must be exactly staging' benchmarks/runner/homelab-collect.sh; then
  printf 'homelab collector does not hard-stop unless current context is staging\n' >&2
  exit 1
fi

for expected in \
  'summary.md' \
  'proof-matrix.md' \
  'namespace-apply' \
  'helm-upgrade-install' \
  'workload-apply' \
  'cleanup-workload' \
  'cleanup-helm-uninstall' \
  'rendered-manifest' \
  'services-endpoints' \
  'monitoring-api-resources' \
  'servicemonitors' \
  'podmonitors' \
  'prometheus-http-healthz' \
  'prometheus-http-readyz' \
  'prometheus-http-metrics' \
  'sink\.prometheus_http' \
  '\[prometheus_http\]' \
  '/healthz' \
  '/readyz' \
  '/metrics' \
  'E_NAVIGATOR_HOMELAB_PROMETHEUS_URL' \
  'prometheus-api-targets' \
  'prometheus-api-query-up' \
  'prometheus-api-series' \
  '/api/v1/targets' \
  '/api/v1/query' \
  '/api/v1/series' \
  'top-pods-10-samples' \
  'capability-decode' \
  '/proc/1/status' \
  '/proc/1/mounts'
do
  if ! grep -Fq "$expected" benchmarks/runner/homelab-collect.sh; then
    printf 'homelab collector does not capture required evidence surface: %s\n' "$expected" >&2
    exit 1
  fi
done
