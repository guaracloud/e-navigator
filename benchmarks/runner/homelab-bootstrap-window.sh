#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

context="${E_NAVIGATOR_HOMELAB_CONTEXT:-homelab}"
namespace="${E_NAVIGATOR_HOMELAB_NAMESPACE:-e-navigator-bench}"
results_root="${E_NAVIGATOR_BOOTSTRAP_WINDOW_RESULTS_DIR:-benchmarks/results/bootstrap-window-proof}"
image_repository="${E_NAVIGATOR_HOMELAB_IMAGE_REPOSITORY:-docker.io/library/e-navigator}"
image_tag="${E_NAVIGATOR_HOMELAB_IMAGE_TAG:-gap8-bootstrap-amd64}"
repetitions="${E_NAVIGATOR_BOOTSTRAP_WINDOW_REPETITIONS:-5}"
duration_seconds="${E_NAVIGATOR_BOOTSTRAP_WINDOW_DURATION_SECONDS:-6}"
resume="${E_NAVIGATOR_BOOTSTRAP_WINDOW_RESUME:-0}"
release="e-navigator-bench"
standing_app="e-navigator"
standing_namespace="e-navigator-system"
standing_daemonset="e-navigator-agent"
standing_suspended=0

if [ "${E_NAVIGATOR_HOMELAB_CONFIRM:-0}" != "1" ]; then
  printf 'refusing bootstrap-window proof without E_NAVIGATOR_HOMELAB_CONFIRM=1\n' >&2
  exit 2
fi
if [ "$context" != "homelab" ] || [ "$namespace" != "e-navigator-bench" ]; then
  printf 'bootstrap-window proof target must be exactly homelab/e-navigator-bench\n' >&2
  exit 2
fi
for numeric in "$repetitions" "$duration_seconds"; do
  case "$numeric" in
    ""|*[!0-9]*)
      printf 'bootstrap-window repetitions and duration must be integers\n' >&2
      exit 2
      ;;
  esac
done
if [ "$repetitions" -lt 5 ] || [ "$repetitions" -gt 20 ]; then
  printf 'bootstrap-window repetitions must be between 5 and 20\n' >&2
  exit 2
fi
if [ "$duration_seconds" -lt 3 ] || [ "$duration_seconds" -gt 30 ]; then
  printf 'bootstrap-window duration must be between 3 and 30 seconds\n' >&2
  exit 2
fi
if [ "$resume" != "0" ] && [ "$resume" != "1" ]; then
  printf 'E_NAVIGATOR_BOOTSTRAP_WINDOW_RESUME must be 0 or 1\n' >&2
  exit 2
fi
case "$image_repository:$image_tag" in
  *[!A-Za-z0-9._/:@-]*)
    printf 'bootstrap-window proof image contains unsupported characters\n' >&2
    exit 2
    ;;
esac

mkdir -p "$results_root"

restore_standing_agent() {
  local status="$?"
  local restore_status=0
  local restore_patch
  set +e
  helm --kube-context "$context" uninstall "$release" --namespace "$namespace" \
    >"$results_root/final-benchmark-uninstall.txt" 2>&1
  kubectl --context "$context" -n "$namespace" delete \
    job -l app.kubernetes.io/part-of=e-navigator-validation \
    --ignore-not-found=true >"$results_root/final-workload-cleanup.txt" 2>&1
  if [ "$standing_suspended" = "1" ]; then
    restore_patch="$(jq -c '{spec:{syncPolicy:{automated:.spec.syncPolicy.automated}}}' \
      "$results_root/pre-argocd-application.json")"
    if ! kubectl --context "$context" -n argocd patch application "$standing_app" \
      --type=merge -p "$restore_patch" >"$results_root/restore-argocd-automation.txt" 2>&1; then
      restore_status=1
    fi
    for _attempt in $(seq 1 60); do
      if kubectl --context "$context" -n "$standing_namespace" get daemonset \
        "$standing_daemonset" >/dev/null 2>&1; then
        break
      fi
      sleep 2
    done
    if ! kubectl --context "$context" -n "$standing_namespace" rollout status \
      "daemonset/$standing_daemonset" --timeout=180s \
      >"$results_root/restore-standing-daemonset.txt" 2>&1; then
      restore_status=1
    fi
    for _attempt in $(seq 1 60); do
      kubectl --context "$context" -n argocd get application "$standing_app" -o json \
        >"$results_root/post-argocd-application.json" 2>&1 || true
      if [ "$(jq -r '.status.sync.status // ""' "$results_root/post-argocd-application.json" 2>/dev/null)" = "Synced" ] &&
        [ "$(jq -r '.status.health.status // ""' "$results_root/post-argocd-application.json" 2>/dev/null)" = "Healthy" ]; then
        break
      fi
      sleep 2
    done
    if ! kubectl --context "$context" -n "$standing_namespace" get daemonset \
      "$standing_daemonset" -o json >"$results_root/post-standing-daemonset.json" 2>&1; then
      restore_status=1
    fi
    if [ "$restore_status" -eq 0 ] && {
      [ "$(jq -r '.spec.syncPolicy.automated.prune' "$results_root/post-argocd-application.json")" != "true" ] ||
      [ "$(jq -r '.spec.syncPolicy.automated.selfHeal' "$results_root/post-argocd-application.json")" != "true" ] ||
      [ "$(jq -r '.status.sync.status' "$results_root/post-argocd-application.json")" != "Synced" ] ||
      [ "$(jq -r '.status.health.status' "$results_root/post-argocd-application.json")" != "Healthy" ];
    }; then
      restore_status=1
    fi
  fi
  if [ "$status" -ne 0 ]; then
    return "$status"
  fi
  return "$restore_status"
}
trap restore_standing_agent EXIT INT TERM

kubectl --context "$context" get namespace kube-system >/dev/null
kubectl --context "$context" -n argocd get application "$standing_app" -o json \
  >"$results_root/pre-argocd-application.json"
kubectl --context "$context" -n "$standing_namespace" get daemonset "$standing_daemonset" -o json \
  >"$results_root/pre-standing-daemonset.json"
kubectl --context "$context" -n "$standing_namespace" get pods -o wide \
  >"$results_root/pre-standing-pods.txt"
kubectl --context "$context" get nodes -o wide >"$results_root/nodes.txt"

if [ "$(jq -r '.spec.syncPolicy.automated.prune' "$results_root/pre-argocd-application.json")" != "true" ] ||
  [ "$(jq -r '.spec.syncPolicy.automated.selfHeal' "$results_root/pre-argocd-application.json")" != "true" ]; then
  printf 'standing Argo CD automation is not the expected prune+selfHeal posture\n' >&2
  exit 2
fi
if [ -n "$(kubectl --context "$context" -n "$namespace" get all -o name)" ]; then
  printf 'bootstrap-window proof namespace is not empty before the run\n' >&2
  exit 2
fi

kubectl --context "$context" -n argocd patch application "$standing_app" --type=json \
  -p='[{"op":"remove","path":"/spec/syncPolicy/automated"}]' \
  >"$results_root/suspend-argocd-automation.txt"
standing_suspended=1
kubectl --context "$context" -n "$standing_namespace" delete daemonset "$standing_daemonset" \
  --wait=true >"$results_root/suspend-standing-daemonset.txt"

wait_for_benchmark_agent_absence() {
  local remaining
  for _attempt in $(seq 1 120); do
    remaining="$(kubectl --context "$context" -n "$namespace" get pods \
      -l app.kubernetes.io/name=e-navigator -o name 2>/dev/null || true)"
    if [ -z "$remaining" ]; then
      return 0
    fi
    sleep 1
  done
  printf 'benchmark agent pods did not terminate within 120 seconds\n' >&2
  return 1
}

run_arm() {
  local arm="$1"
  local config="$2"
  local mode="$3"
  local agent_mode="enabled"
  local run_dir="$results_root/$arm"
  if [ "$mode" = "none" ]; then
    agent_mode="none"
  fi

  if [ "$resume" = "1" ] && [ -s "$run_dir/validated.json" ]; then
    python3 benchmarks/runner/analyze-bootstrap-window.py run "$mode" "$run_dir" \
      >"$run_dir/validated.rechecked.json"
    mv "$run_dir/validated.rechecked.json" "$run_dir/validated.json"
    printf 'reused validated bootstrap-window arm: %s\n' "$arm"
    return
  fi
  if [ "$resume" = "1" ] && [ -d "$run_dir" ]; then
    find "$run_dir" -mindepth 1 -delete
  elif [ -e "$run_dir" ]; then
    printf 'bootstrap-window run already exists, use resume or a new result root: %s\n' \
      "$run_dir" >&2
    return 1
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
  E_NAVIGATOR_HOMELAB_CONFIG_TEMPLATE="$config" \
  E_NAVIGATOR_HOMELAB_VALUES_FILE="benchmarks/config/reduced-privilege-core-values.yaml" \
  E_NAVIGATOR_HOMELAB_ENABLE_PROMETHEUS_HTTP=1 \
  E_NAVIGATOR_HOMELAB_AGENT_MODE="$agent_mode" \
  E_NAVIGATOR_HOMELAB_WORKLOAD_TEMPLATE="benchmarks/k8s/bootstrap-window-workload.yaml" \
  E_NAVIGATOR_HOMELAB_WORKLOAD_DURATION_SECONDS="$duration_seconds" \
  E_NAVIGATOR_HOMELAB_TOP_SAMPLES=2 \
  E_NAVIGATOR_HOMELAB_TOP_INTERVAL_SECONDS=1 \
  E_NAVIGATOR_HOMELAB_LOG_TAIL=30000 \
  E_NAVIGATOR_HOMELAB_WORKLOAD_LOG_TAIL=1000 \
  E_NAVIGATOR_HOMELAB_CLEANUP_WORKLOAD=1 \
  E_NAVIGATOR_HOMELAB_UNINSTALL_RELEASE=1 \
    benchmarks/runner/homelab-collect.sh

  wait_for_benchmark_agent_absence
  python3 benchmarks/runner/analyze-bootstrap-window.py run "$mode" "$run_dir" \
    >"$run_dir/validated.json"
}

wait_for_benchmark_agent_absence
run_arm none-r1 "" none
for repetition in $(seq 1 "$repetitions"); do
  if [ $((repetition % 2)) -eq 1 ]; then
    run_arm "polling-r${repetition}" benchmarks/config/bootstrap-window-polling.toml polling
    run_arm "event-r${repetition}" benchmarks/config/bootstrap-window-event.toml event
  else
    run_arm "event-r${repetition}" benchmarks/config/bootstrap-window-event.toml event
    run_arm "polling-r${repetition}" benchmarks/config/bootstrap-window-polling.toml polling
  fi
done

python3 benchmarks/runner/analyze-bootstrap-window.py aggregate "$results_root" \
  >"$results_root/analysis.json"
kubectl --context "$context" -n "$namespace" get all -o wide \
  >"$results_root/final-benchmark-namespace.txt"
if helm --kube-context "$context" status "$release" --namespace "$namespace" >/dev/null 2>&1; then
  printf 'benchmark release remained installed after bootstrap-window proof\n' >&2
  exit 1
fi
printf 'PASS: bootstrap-window polling/event A/B completed with no-agent control\n' |
  tee "$results_root/summary.txt"
