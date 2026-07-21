#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

context="${E_NAVIGATOR_HOMELAB_CONTEXT:-homelab}"
namespace="${E_NAVIGATOR_HOMELAB_NAMESPACE:-e-navigator-bench}"
results_root="${E_NAVIGATOR_KERNEL_HOOK_RESULTS_DIR:-benchmarks/results/kernel-hook-ab}"
duration_seconds="${E_NAVIGATOR_KERNEL_HOOK_DURATION_SECONDS:-120}"
image_repository="${E_NAVIGATOR_HOMELAB_IMAGE_REPOSITORY:-docker.io/library/e-navigator}"
image_tag="${E_NAVIGATOR_HOMELAB_IMAGE_TAG:-gap2-20260721}"
standing_app="e-navigator"
standing_namespace="e-navigator-system"
standing_daemonset="e-navigator-agent"
release="e-navigator-bench"
standing_suspended=0

if [ "${E_NAVIGATOR_HOMELAB_CONFIRM:-0}" != "1" ]; then
  printf 'refusing kernel-hook A/B without E_NAVIGATOR_HOMELAB_CONFIRM=1\n' >&2
  exit 2
fi
if [ "$context" != "homelab" ] || [ "$namespace" != "e-navigator-bench" ]; then
  printf 'kernel-hook A/B target must be exactly homelab/e-navigator-bench\n' >&2
  exit 2
fi
case "$duration_seconds" in
  ""|*[!0-9]*)
    printf 'E_NAVIGATOR_KERNEL_HOOK_DURATION_SECONDS must be an integer\n' >&2
    exit 2
    ;;
esac
if [ "$duration_seconds" -lt 30 ] || [ "$duration_seconds" -gt 600 ]; then
  printf 'kernel-hook A/B duration must be between 30 and 600 seconds\n' >&2
  exit 2
fi

mkdir -p "$results_root"

restore_standing_agent() {
  local status="$?"
  local restore_status=0
  set +e
  helm --kube-context "$context" uninstall "$release" --namespace "$namespace" \
    >"$results_root/final-benchmark-uninstall.txt" 2>&1
  kubectl --context "$context" -n "$namespace" delete job \
    -l app.kubernetes.io/part-of=e-navigator-validation --ignore-not-found=true \
    >"$results_root/final-workload-cleanup.txt" 2>&1
  if [ "$standing_suspended" = "1" ]; then
    restore_patch="$(jq -c '{spec:{syncPolicy:{automated:.spec.syncPolicy.automated}}}' \
      "$results_root/pre-argocd-application.json")"
    kubectl --context "$context" -n argocd patch application "$standing_app" \
      --type=merge -p "$restore_patch" >"$results_root/restore-argocd-automation.txt" 2>&1
    [ "$?" -eq 0 ] || restore_status=1
    for _attempt in $(seq 1 60); do
      if kubectl --context "$context" -n "$standing_namespace" get daemonset \
        "$standing_daemonset" >/dev/null 2>&1; then
        break
      fi
      sleep 2
    done
    kubectl --context "$context" -n "$standing_namespace" rollout status \
      "daemonset/$standing_daemonset" --timeout=180s \
      >"$results_root/restore-standing-daemonset.txt" 2>&1
    [ "$?" -eq 0 ] || restore_status=1
    for _attempt in $(seq 1 60); do
      kubectl --context "$context" -n argocd get application "$standing_app" -o json \
        >"$results_root/post-argocd-application.json" 2>&1 || true
      if [ "$(jq -r '.status.sync.status // ""' "$results_root/post-argocd-application.json" 2>/dev/null)" = "Synced" ] &&
        [ "$(jq -r '.status.health.status // ""' "$results_root/post-argocd-application.json" 2>/dev/null)" = "Healthy" ]; then
        break
      fi
      sleep 2
    done
    jq -e '.metadata.name == "e-navigator"' "$results_root/post-argocd-application.json" \
      >/dev/null 2>&1 || restore_status=1
    kubectl --context "$context" -n "$standing_namespace" get daemonset "$standing_daemonset" -o json \
      >"$results_root/post-standing-daemonset.json" 2>&1
    [ "$?" -eq 0 ] || restore_status=1
    if [ "$restore_status" -eq 0 ]; then
      if [ "$(jq -r '.spec.syncPolicy.automated.prune' "$results_root/post-argocd-application.json")" != "true" ] ||
        [ "$(jq -r '.spec.syncPolicy.automated.selfHeal' "$results_root/post-argocd-application.json")" != "true" ] ||
        [ "$(jq -r '.status.sync.status' "$results_root/post-argocd-application.json")" != "Synced" ] ||
        [ "$(jq -r '.status.health.status' "$results_root/post-argocd-application.json")" != "Healthy" ]; then
        restore_status=1
      fi
    fi
  fi
  if [ "$status" -ne 0 ]; then
    return "$status"
  fi
  return "$restore_status"
}
trap restore_standing_agent EXIT

kubectl --context "$context" get namespace kube-system >/dev/null
kubectl --context "$context" -n argocd get application "$standing_app" -o json \
  >"$results_root/pre-argocd-application.json"
kubectl --context "$context" -n "$standing_namespace" get daemonset "$standing_daemonset" -o json \
  >"$results_root/pre-standing-daemonset.json"
kubectl --context "$context" -n "$standing_namespace" get pods -o wide \
  >"$results_root/pre-standing-pods.txt"

if [ "$(jq -r '.spec.syncPolicy.automated.prune' "$results_root/pre-argocd-application.json")" != "true" ] ||
  [ "$(jq -r '.spec.syncPolicy.automated.selfHeal' "$results_root/pre-argocd-application.json")" != "true" ]; then
  printf 'standing Argo CD automation is not the expected prune+selfHeal posture\n' >&2
  exit 2
fi

kubectl --context "$context" -n argocd patch application "$standing_app" --type=json \
  -p='[{"op":"remove","path":"/spec/syncPolicy/automated"}]' \
  >"$results_root/suspend-argocd-automation.txt"
standing_suspended=1
kubectl --context "$context" -n "$standing_namespace" delete daemonset "$standing_daemonset" \
  --wait=true >"$results_root/suspend-standing-daemonset.txt"

run_arm() {
  local mode="$1"
  local repetition="$2"
  local run_dir="$results_root/${mode}-r${repetition}"
  local agent_mode="enabled"
  local hook="$mode"
  if [ "$mode" = "none" ]; then
    agent_mode="none"
    hook=""
  fi

  E_NAVIGATOR_HOMELAB_CONFIRM=1 \
  E_NAVIGATOR_HOMELAB_APPLY=1 \
  E_NAVIGATOR_HOMELAB_CONTEXT="$context" \
  E_NAVIGATOR_HOMELAB_NAMESPACE="$namespace" \
  E_NAVIGATOR_HOMELAB_RESULTS_DIR="$run_dir" \
  E_NAVIGATOR_HOMELAB_RELEASE="$release" \
  E_NAVIGATOR_HOMELAB_IMAGE_REPOSITORY="$image_repository" \
  E_NAVIGATOR_HOMELAB_IMAGE_TAG="$image_tag" \
  E_NAVIGATOR_HOMELAB_IMAGE_PULL_POLICY=Never \
  E_NAVIGATOR_HOMELAB_CONFIG_TEMPLATE=benchmarks/config/network-only.toml \
  E_NAVIGATOR_HOMELAB_EVENT_TRANSPORT=ring_buffer \
  E_NAVIGATOR_HOMELAB_NETWORK_IO_HOOK="$hook" \
  E_NAVIGATOR_HOMELAB_ENABLE_PROMETHEUS_HTTP=1 \
  E_NAVIGATOR_HOMELAB_AGENT_MODE="$agent_mode" \
  E_NAVIGATOR_HOMELAB_WORKLOAD_TEMPLATE=benchmarks/k8s/kernel-hook-workload.yaml \
  E_NAVIGATOR_HOMELAB_WORKLOAD_DURATION_SECONDS="$duration_seconds" \
  E_NAVIGATOR_HOMELAB_TOP_SAMPLES="$((duration_seconds / 5 + 2))" \
  E_NAVIGATOR_HOMELAB_TOP_INTERVAL_SECONDS=5 \
  E_NAVIGATOR_HOMELAB_LOG_TAIL=4000 \
  E_NAVIGATOR_HOMELAB_CLEANUP_WORKLOAD=1 \
  E_NAVIGATOR_HOMELAB_UNINSTALL_RELEASE=1 \
    benchmarks/runner/homelab-collect.sh

  if helm --kube-context "$context" status "$release" --namespace "$namespace" >/dev/null 2>&1; then
    printf 'benchmark release remained installed after %s-r%s\n' "$mode" "$repetition" >&2
    return 1
  fi
}

for mode in none tracepoint fexit; do run_arm "$mode" 1; done
for mode in fexit none tracepoint; do run_arm "$mode" 2; done
for mode in tracepoint fexit none; do run_arm "$mode" 3; done

python3 benchmarks/runner/analyze-kernel-hooks.py "$results_root" \
  >"$results_root/analysis.json"

restore_standing_agent
trap - EXIT
