#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

context="${E_NAVIGATOR_HOMELAB_CONTEXT:-homelab}"
namespace="${E_NAVIGATOR_HOMELAB_NAMESPACE:-e-navigator-bench}"
results_root="${E_NAVIGATOR_GO_TLS_RESULTS_DIR:-benchmarks/results/go-tls-proof}"
duration_seconds="${E_NAVIGATOR_GO_TLS_DURATION_SECONDS:-60}"
repetitions="${E_NAVIGATOR_GO_TLS_REPETITIONS:-3}"
image_repository="${E_NAVIGATOR_HOMELAB_IMAGE_REPOSITORY:-docker.io/library/e-navigator}"
image_tag="${E_NAVIGATOR_HOMELAB_IMAGE_TAG:-gap3-20260721}"
standing_app="e-navigator"
standing_namespace="e-navigator-system"
standing_daemonset="e-navigator-agent"
release="e-navigator-bench"
standing_suspended=0

if [ "${E_NAVIGATOR_HOMELAB_CONFIRM:-0}" != "1" ]; then
  printf 'refusing Go TLS proof without E_NAVIGATOR_HOMELAB_CONFIRM=1\n' >&2
  exit 2
fi
if [ "$context" != "homelab" ] || [ "$namespace" != "e-navigator-bench" ]; then
  printf 'Go TLS proof target must be exactly homelab/e-navigator-bench\n' >&2
  exit 2
fi
case "$duration_seconds" in
  ""|*[!0-9]*)
    printf 'E_NAVIGATOR_GO_TLS_DURATION_SECONDS must be an integer\n' >&2
    exit 2
    ;;
esac
if [ "$duration_seconds" -lt 30 ] || [ "$duration_seconds" -gt 300 ]; then
  printf 'Go TLS proof duration must be between 30 and 300 seconds\n' >&2
  exit 2
fi
case "$repetitions" in
  1|2|3|4|5) ;;
  *)
    printf 'E_NAVIGATOR_GO_TLS_REPETITIONS must be between 1 and 5\n' >&2
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
    job,deployment,service -l app.kubernetes.io/part-of=e-navigator-validation \
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
    if ! kubectl --context "$context" -n "$standing_namespace" get daemonset "$standing_daemonset" -o json \
      >"$results_root/post-standing-daemonset.json" 2>&1; then
      restore_status=1
    fi
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
kubectl --context "$context" get nodes -o wide >"$results_root/nodes.txt"

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

validate_arm() {
  local mode="$1"
  local run_dir="$2"
  python3 - "$mode" "$run_dir" <<'PY'
import json
import re
import sys
from pathlib import Path

mode = sys.argv[1]
run_dir = Path(sys.argv[2])

workload = None
for line in (run_dir / "workload-logs.txt").read_text(errors="replace").splitlines():
    marker = line.find("{")
    if marker < 0:
        continue
    try:
        candidate = json.loads(line[marker:])
    except json.JSONDecodeError:
        continue
    if candidate.get("schema") == "e-navigator.go-tls-client.v1":
        workload = candidate
        break
if workload is None:
    raise SystemExit(f"missing Go TLS workload result in {run_dir}")
if workload.get("failed") != 0 or workload.get("succeeded") != workload.get("requests"):
    raise SystemExit(f"Go TLS workload failed in {run_dir}: {workload}")
if mode == "none":
    pod_inventory = json.loads((run_dir / "pod-json.txt").read_text())
    agent_pods = [
        item.get("metadata", {}).get("name", "")
        for item in pod_inventory.get("items", [])
        if item.get("metadata", {}).get("labels", {}).get("app.kubernetes.io/name")
        == "e-navigator"
    ]
    if agent_pods:
        raise SystemExit(f"no-agent arm contained agent pods in {run_dir}: {agent_pods}")
    raise SystemExit(0)

logs = (run_dir / "logs.txt").read_text(errors="replace")
clean_logs = re.sub(r"\x1b\[[0-9;]*m", "", logs)
ready = any(
    "Go crypto/tls executable is capture-ready" in line
    and 'executable="go-https-proof"' in line
    and 'go_version="go1.26.4"' in line
    for line in clean_logs.splitlines()
)
if not ready:
    raise SystemExit(f"missing capture-ready Go 1.26.4 proof executable in {run_dir}/logs.txt")
stripped = any(
    'executable="go-https-proof-stripped"' in line
    and "stripped binaries fail closed" in line
    for line in clean_logs.splitlines()
)
if not stripped:
    raise SystemExit(f"missing stripped proof executable rejection in {run_dir}/logs.txt")

status_200 = 0
for raw_line in logs.splitlines():
    marker = raw_line.find("{")
    if marker < 0:
        continue
    try:
        signal = json.loads(raw_line[marker:])
    except json.JSONDecodeError:
        continue
    if signal.get("source") != "source.aya_tls" or signal.get("kind") != "protocol_request_observation":
        continue
    payload = signal.get("payload", {})
    attributes = payload.get("attributes", [])
    kubernetes = payload.get("kubernetes") or {}
    if (
        payload.get("process", {}).get("command") == "go-https-proof"
        and kubernetes.get("namespace") == "e-navigator-bench"
        and any(item.get("key") == "url.path" and item.get("value") == "/proof" for item in attributes)
        and any(item.get("key") == "http.response.status_code" and item.get("value") == "200" for item in attributes)
    ):
        status_200 += 1
if status_200 == 0:
    raise SystemExit(f"no captured Go TLS HTTP 200 observation in {run_dir}")

metrics = {}
metric_pattern = re.compile(r"^(e_navigator_ebpf_source_[a-z0-9_]+)(?:\{[^}]*\})? ([0-9]+)$")
for line in (run_dir / "prometheus-http-metrics.txt").read_text(errors="replace").splitlines():
    match = metric_pattern.match(line)
    if match:
        metrics[match.group(1)] = int(match.group(2))
for required in (
    "e_navigator_ebpf_source_go_tls_entries_total",
    "e_navigator_ebpf_source_go_tls_exits_total",
    "e_navigator_ebpf_source_go_tls_fd_resolutions_total",
    "e_navigator_ebpf_source_go_tls_output_attempts_total",
):
    if metrics.get(required, 0) == 0:
        raise SystemExit(f"missing positive {required} in {run_dir}")
if metrics.get("e_navigator_ebpf_source_go_tls_state_update_failures_total", -1) != 0:
    raise SystemExit(f"Go TLS state update failure in {run_dir}")
for loss_name in (
    "e_navigator_ebpf_source_lost_transport_events_total",
    "e_navigator_ebpf_source_ring_buffer_reservation_failures_total",
):
    if metrics.get(loss_name, -1) != 0:
        raise SystemExit(f"non-zero or absent {loss_name} in {run_dir}")
PY
}

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
  kubectl --context "$context" -n "$namespace" get pods \
    -l app.kubernetes.io/name=e-navigator -o wide >&2 || true
  return 1
}

run_arm() {
  local mode="$1"
  local repetition="$2"
  local run_dir="$results_root/${mode}-r${repetition}"
  local agent_mode="enabled"
  if [ "$mode" = "none" ]; then
    agent_mode="none"
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
  E_NAVIGATOR_HOMELAB_CONFIG_TEMPLATE=benchmarks/config/go-tls-only.toml \
  E_NAVIGATOR_HOMELAB_EVENT_TRANSPORT=ring_buffer \
  E_NAVIGATOR_HOMELAB_ENABLE_PROMETHEUS_HTTP=1 \
  E_NAVIGATOR_HOMELAB_AGENT_MODE="$agent_mode" \
  E_NAVIGATOR_HOMELAB_WORKLOAD_TEMPLATE=benchmarks/k8s/go-tls-workload.yaml \
  E_NAVIGATOR_HOMELAB_WORKLOAD_DURATION_SECONDS="$duration_seconds" \
  E_NAVIGATOR_HOMELAB_TOP_SAMPLES=8 \
  E_NAVIGATOR_HOMELAB_TOP_INTERVAL_SECONDS=5 \
  E_NAVIGATOR_HOMELAB_LOG_TAIL=30000 \
  E_NAVIGATOR_HOMELAB_WORKLOAD_LOG_TAIL=4000 \
  E_NAVIGATOR_HOMELAB_CLEANUP_WORKLOAD=1 \
  E_NAVIGATOR_HOMELAB_UNINSTALL_RELEASE=1 \
    benchmarks/runner/homelab-collect.sh

  if [ "$agent_mode" = "enabled" ]; then
    wait_for_benchmark_agent_absence
  fi
  validate_arm "$mode" "$run_dir"
  if helm --kube-context "$context" status "$release" --namespace "$namespace" >/dev/null 2>&1; then
    printf 'benchmark release remained installed after %s-r%s\n' "$mode" "$repetition" >&2
    return 1
  fi
}

wait_for_benchmark_agent_absence
for repetition in $(seq 1 "$repetitions"); do
  if [ $((repetition % 2)) -eq 1 ]; then
    run_arm none "$repetition"
    run_arm tls "$repetition"
  else
    run_arm tls "$repetition"
    run_arm none "$repetition"
  fi
done

python3 benchmarks/runner/analyze-go-tls.py "$results_root" >"$results_root/analysis.json"

restore_standing_agent
trap - EXIT
