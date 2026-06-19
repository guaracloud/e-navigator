#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

namespace="${E_NAVIGATOR_HOMELAB_NAMESPACE:-e-navigator-bench}"
context="${E_NAVIGATOR_HOMELAB_CONTEXT:-}"
timestamp="$(date -u +%Y%m%d-%H%M%S)"
results_dir="${E_NAVIGATOR_HOMELAB_RESULTS_DIR:-benchmarks/results/${timestamp}}"
release="${E_NAVIGATOR_HOMELAB_RELEASE:-e-navigator-bench}"

if [ "${E_NAVIGATOR_HOMELAB_CONFIRM:-0}" != "1" ]; then
  cat >&2 <<MSG
refusing to run homelab validation without E_NAVIGATOR_HOMELAB_CONFIRM=1
target context: ${context:-not queried before confirmation}
target namespace: ${namespace}
MSG
  exit 2
fi

if [ -z "$context" ]; then
  context="$(kubectl config current-context 2>/dev/null || true)"
fi

if [ -z "$context" ]; then
  printf 'kubectl context is empty; set E_NAVIGATOR_HOMELAB_CONTEXT\n' >&2
  exit 2
fi

kubectl_cmd=(kubectl --context "$context")

printf 'homelab validation target context: %s\n' "$context"
printf 'homelab validation target namespace: %s\n' "$namespace"
printf 'homelab validation results: %s\n' "$results_dir"
mkdir -p "$results_dir"

run_capture() {
  local name="$1"
  shift
  printf '\n==> %s\n' "$name" | tee -a "$results_dir/commands.txt"
  printf '%q ' "$@" | tee -a "$results_dir/commands.txt"
  printf '\n' | tee -a "$results_dir/commands.txt"
  "$@" >"$results_dir/${name}.txt" 2>&1 || true
}

if [ "${E_NAVIGATOR_HOMELAB_APPLY:-0}" = "1" ]; then
  image_repository="${E_NAVIGATOR_HOMELAB_IMAGE_REPOSITORY:-}"
  image_tag="${E_NAVIGATOR_HOMELAB_IMAGE_TAG:-}"
  if [ -z "$image_repository" ] || [ -z "$image_tag" ]; then
    printf 'E_NAVIGATOR_HOMELAB_IMAGE_REPOSITORY and E_NAVIGATOR_HOMELAB_IMAGE_TAG are required when E_NAVIGATOR_HOMELAB_APPLY=1\n' >&2
    exit 2
  fi

  "${kubectl_cmd[@]}" create namespace "$namespace" --dry-run=client -o yaml \
    | "${kubectl_cmd[@]}" apply -f -
  helm --kube-context "$context" upgrade --install "$release" charts/e-navigator \
    --namespace "$namespace" \
    --set namespace.create=false \
    --set namespace.name="$namespace" \
    --set image.repository="$image_repository" \
    --set image.tag="$image_tag" \
    --set image.pullPolicy=IfNotPresent \
    --set resources.requests.cpu=50m \
    --set resources.requests.memory=128Mi \
    --set resources.limits.memory=512Mi
  "${kubectl_cmd[@]}" -n "$namespace" apply -f benchmarks/k8s/workload.yaml
fi

run_capture namespace "${kubectl_cmd[@]}" get namespace "$namespace" -o yaml
run_capture pods "${kubectl_cmd[@]}" -n "$namespace" get pods -o wide
run_capture daemonset "${kubectl_cmd[@]}" -n "$namespace" get daemonset -o wide
run_capture rollout "${kubectl_cmd[@]}" -n "$namespace" rollout status "daemonset/${release}" --timeout="${E_NAVIGATOR_HOMELAB_ROLLOUT_TIMEOUT:-120s}"
run_capture pod-json "${kubectl_cmd[@]}" -n "$namespace" get pods -o json
run_capture logs "${kubectl_cmd[@]}" -n "$namespace" logs -l app.kubernetes.io/name=e-navigator --all-containers --tail="${E_NAVIGATOR_HOMELAB_LOG_TAIL:-2000}" --prefix
run_capture events "${kubectl_cmd[@]}" -n "$namespace" get events --sort-by=.lastTimestamp
run_capture top-pods "${kubectl_cmd[@]}" -n "$namespace" top pods --containers

if [ "${E_NAVIGATOR_HOMELAB_CLEANUP:-0}" = "1" ]; then
  printf 'running namespace-scoped cleanup in %s\n' "$namespace"
  "${kubectl_cmd[@]}" -n "$namespace" delete -f benchmarks/k8s/workload.yaml --ignore-not-found=true
  helm --kube-context "$context" uninstall "$release" --namespace "$namespace" || true
fi

printf 'homelab collection complete: %s\n' "$results_dir"
