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

if ! grep -q 'E_NAVIGATOR_HOMELAB_IMAGE_PULL_POLICY' benchmarks/runner/homelab-collect.sh; then
  printf 'homelab collector does not expose E_NAVIGATOR_HOMELAB_IMAGE_PULL_POLICY\n' >&2
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

if ! grep -q 'E_NAVIGATOR_HOMELAB_DISABLE_JSON_STDOUT' benchmarks/runner/homelab-collect.sh; then
  printf 'homelab collector does not expose E_NAVIGATOR_HOMELAB_DISABLE_JSON_STDOUT\n' >&2
  exit 1
fi

if ! grep -q 'E_NAVIGATOR_HOMELAB_AGENT_MODE' benchmarks/runner/homelab-collect.sh; then
  printf 'homelab collector does not expose a no-agent baseline mode\n' >&2
  exit 1
fi

if ! grep -Fq -- '--set-file' benchmarks/runner/homelab-collect.sh ||
  ! grep -Fq 'config.toml=$runtime_config' benchmarks/runner/homelab-collect.sh; then
  printf 'homelab collector does not pass an explicit runtime config to Helm\n' >&2
  exit 1
fi

if ! grep -Fq 'in_config && $0 == "" { print ""; next }' benchmarks/runner/homelab-collect.sh; then
  printf 'homelab collector does not preserve blank lines while extracting runtime config\n' >&2
  exit 1
fi

if ! grep -Fq 'target context must be exactly homelab' benchmarks/runner/homelab-collect.sh; then
  printf 'homelab collector does not hard-stop unless the target context is homelab\n' >&2
  exit 1
fi

for transport in auto ring_buffer perf_buffer; do
  if ! grep -Fq "$transport" benchmarks/runner/homelab-collect.sh; then
    printf 'homelab collector does not accept event transport mode: %s\n' "$transport" >&2
    exit 1
  fi
done

if ! grep -q 'E_NAVIGATOR_HOMELAB_NETWORK_IO_HOOK' benchmarks/runner/homelab-collect.sh; then
  echo "collector must expose the guarded network I/O hook override" >&2
  exit 1
fi

for hook in auto fexit tracepoint; do
  if ! grep -Fq "$hook" benchmarks/runner/homelab-collect.sh; then
    echo "collector must validate network I/O hook mode: $hook" >&2
    exit 1
  fi
done

if ! grep -Fq 'operator: Exists' benchmarks/k8s/workload.yaml; then
  printf 'homelab workload template must tolerate homelab control-plane taints for symmetric proof scheduling\n' >&2
  exit 1
fi

if ! grep -Fq 'delete -f "$workload_manifest"' benchmarks/runner/homelab-collect.sh; then
  printf 'homelab collector cleanup must delete the generated timestamped workload manifest\n' >&2
  exit 1
fi

if ! grep -q 'E_NAVIGATOR_HOMELAB_WORKLOAD_WAIT_TIMEOUT' benchmarks/runner/homelab-collect.sh; then
  printf 'homelab collector must expose a bounded workload wait timeout\n' >&2
  exit 1
fi

if ! grep -q 'E_NAVIGATOR_HOMELAB_WORKLOAD_TEMPLATE' benchmarks/runner/homelab-collect.sh; then
  printf 'homelab collector must expose an explicit workload template\n' >&2
  exit 1
fi

if ! grep -q 'E_NAVIGATOR_HOMELAB_CONFIG_TEMPLATE' benchmarks/runner/homelab-collect.sh; then
  echo "collector must expose a validated config-template override" >&2
  exit 1
fi

if ! grep -Fq 'homelab config template does not exist' benchmarks/runner/homelab-collect.sh; then
  echo "collector must reject a missing config-template override" >&2
  exit 1
fi

if ! grep -q 'E_NAVIGATOR_HOMELAB_WORKLOAD_DURATION_SECONDS' benchmarks/runner/homelab-collect.sh; then
  printf 'homelab collector must expose a bounded workload duration\n' >&2
  exit 1
fi

if ! grep -Fq 'wait --for=condition=complete "job/${workload_name}"' benchmarks/runner/homelab-collect.sh; then
  printf 'homelab collector must wait for the generated workload Job to complete\n' >&2
  exit 1
fi

if ! grep -Fq 'app.kubernetes.io/name=${workload_name}' benchmarks/runner/homelab-collect.sh; then
  printf 'homelab collector must select the exact generated workload pods\n' >&2
  exit 1
fi

if ! grep -Fq 'E_NAVIGATOR_HOMELAB_CLEANUP_WORKLOAD' benchmarks/runner/homelab-collect.sh; then
  printf 'homelab collector must expose workload-only cleanup for standing benchmark releases\n' >&2
  exit 1
fi

if ! grep -Fq 'E_NAVIGATOR_HOMELAB_UNINSTALL_RELEASE' benchmarks/runner/homelab-collect.sh; then
  printf 'homelab collector must require an explicit release-uninstall flag separate from workload cleanup\n' >&2
  exit 1
fi

cleanup_workload_line="$(grep -n 'cleanup_workload_requested=' benchmarks/runner/homelab-collect.sh | head -1 | cut -d: -f1)"
uninstall_release_line="$(grep -n 'uninstall_release_requested=' benchmarks/runner/homelab-collect.sh | head -1 | cut -d: -f1)"
cleanup_workload_if_line="$(grep -n 'cleanup_workload_requested' benchmarks/runner/homelab-collect.sh | tail -1 | cut -d: -f1)"
uninstall_release_if_line="$(grep -n 'uninstall_release_requested' benchmarks/runner/homelab-collect.sh | tail -1 | cut -d: -f1)"
if [ -z "$cleanup_workload_line" ] ||
  [ -z "$uninstall_release_line" ] ||
  [ -z "$cleanup_workload_if_line" ] ||
  [ -z "$uninstall_release_if_line" ] ||
  [ "$cleanup_workload_line" -ge "$cleanup_workload_if_line" ] ||
  [ "$uninstall_release_line" -ge "$uninstall_release_if_line" ]; then
  printf 'homelab collector must derive and use separate workload cleanup and release uninstall decisions\n' >&2
  exit 1
fi

cleanup_workload_run_line="$(grep -n 'run_capture cleanup-workload' benchmarks/runner/homelab-collect.sh | tail -1 | cut -d: -f1)"
cleanup_helm_run_line="$(grep -n 'run_capture cleanup-helm-uninstall' benchmarks/runner/homelab-collect.sh | tail -1 | cut -d: -f1)"
if [ -z "$cleanup_workload_run_line" ] ||
  [ -z "$cleanup_helm_run_line" ] ||
  [ "$cleanup_workload_run_line" -ge "$cleanup_helm_run_line" ]; then
  printf 'homelab collector must clean workload before any optional Helm uninstall\n' >&2
  exit 1
fi

rollout_line="$(grep -n 'run_capture rollout' benchmarks/runner/homelab-collect.sh | head -1 | cut -d: -f1)"
workload_apply_line="$(grep -n 'workload-apply' benchmarks/runner/homelab-collect.sh | tail -1 | cut -d: -f1)"
workload_wait_line="$(grep -n 'wait --for=condition=complete "job/${workload_name}"' benchmarks/runner/homelab-collect.sh | tail -1 | cut -d: -f1)"
workload_capture_line="$(grep -n 'capture_workload_artifacts' benchmarks/runner/homelab-collect.sh | tail -1 | cut -d: -f1)"
top_capture_line="$(grep -n 'capture_top_samples &' benchmarks/runner/homelab-collect.sh | tail -1 | cut -d: -f1)"
service_capture_line="$(grep -n 'capture_service_surfaces' benchmarks/runner/homelab-collect.sh | tail -1 | cut -d: -f1)"
prometheus_capture_line="$(grep -n 'capture_prometheus_http_endpoints' benchmarks/runner/homelab-collect.sh | tail -1 | cut -d: -f1)"
if [ -z "$rollout_line" ] ||
  [ -z "$workload_apply_line" ] ||
  [ -z "$workload_wait_line" ] ||
  [ -z "$workload_capture_line" ] ||
  [ -z "$top_capture_line" ] ||
  [ -z "$service_capture_line" ] ||
  [ -z "$prometheus_capture_line" ] ||
  [ "$rollout_line" -ge "$workload_apply_line" ] ||
  [ "$workload_apply_line" -ge "$workload_wait_line" ] ||
  [ "$workload_apply_line" -ge "$top_capture_line" ] ||
  [ "$top_capture_line" -ge "$workload_wait_line" ] ||
  [ "$workload_wait_line" -ge "$workload_capture_line" ] ||
  [ "$workload_capture_line" -ge "$service_capture_line" ] ||
  [ "$rollout_line" -ge "$prometheus_capture_line" ]; then
  printf 'homelab collector must wait for rollout and workload completion before service and Prometheus endpoint captures\n' >&2
  exit 1
fi

for expected in \
  'required_image_repository="ghcr.io/guaracloud/e-navigator"' \
  'required_image_tag="sha-8ab271c"' \
  'run-metadata.txt' \
  'Required image:' \
  'Configured image:' \
  'Image substitution:' \
  'workload-manifest.yaml' \
  'workload-wait' \
  'workload-pods' \
  'workload-pod-json' \
  'workload-logs' \
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
  'E_NAVIGATOR_HOMELAB_EVENT_TRANSPORT' \
  'runtime-config.toml' \
  'prometheus-api-targets' \
  'prometheus-api-query-up' \
  'prometheus-api-series' \
  '/api/v1/targets' \
  '/api/v1/query' \
  '/api/v1/series' \
  'top-pods-10-samples' \
  'top-nodes-10-samples' \
  'capability-decode' \
  '/proc/1/status' \
  '/proc/1/mounts'
do
  if ! grep -Fq "$expected" benchmarks/runner/homelab-collect.sh; then
    printf 'homelab collector does not capture required evidence surface: %s\n' "$expected" >&2
    exit 1
  fi
done
