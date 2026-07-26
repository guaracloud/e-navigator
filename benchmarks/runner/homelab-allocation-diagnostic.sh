#!/usr/bin/env bash
set -euo pipefail

# Run one bounded allocation window inside the existing full-profile homelab
# diagnostic. The result is directional across Rust and Go because the probes
# observe different runtime layers; it is not a CPU or RSS qualification.

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

collector="${1:?usage: homelab-allocation-diagnostic.sh <e-navigator|beyla>}"
context="${E_NAVIGATOR_HOMELAB_CONTEXT:-homelab}"
namespace="${E_NAVIGATOR_HOMELAB_NAMESPACE:-e-navigator-bench}"
results_root="${E_NAVIGATOR_HEAD_TO_HEAD_RESULTS_DIR:-benchmarks/results/allocation-diagnostic-$collector}"
warmup_seconds="${E_NAVIGATOR_HEAD_TO_HEAD_WARMUP_SECONDS:-20}"
duration_seconds="${E_NAVIGATOR_HEAD_TO_HEAD_DURATION_SECONDS:-90}"
window_seconds="${E_NAVIGATOR_ALLOCATION_WINDOW_SECONDS:-45}"
window_margin_seconds="${E_NAVIGATOR_ALLOCATION_WINDOW_MARGIN_SECONDS:-10}"
probe_manifest="benchmarks/k8s/allocation-probe.yaml"
probe_pod="allocation-probe-homelab02"
runner_pid=""
alloy_forward_pid=""
probes_applied=0

if [ "$collector" != "e-navigator" ] && [ "$collector" != "beyla" ]; then
  printf 'allocation diagnostic collector must be e-navigator or beyla\n' >&2
  exit 2
fi
if [ "${E_NAVIGATOR_HOMELAB_CONFIRM:-0}" != "1" ]; then
  printf 'refusing allocation diagnostic without E_NAVIGATOR_HOMELAB_CONFIRM=1\n' >&2
  exit 2
fi
if [ "$context" != "homelab" ] || [ "$namespace" != "e-navigator-bench" ]; then
  printf 'allocation diagnostic target must be exactly homelab/e-navigator-bench\n' >&2
  exit 2
fi
for numeric in "$warmup_seconds" "$duration_seconds" "$window_seconds" "$window_margin_seconds"; do
  case "$numeric" in
    ""|*[!0-9]*)
      printf 'allocation diagnostic durations must be integers\n' >&2
      exit 2
      ;;
  esac
done
if [ "$warmup_seconds" -lt 20 ] ||
  [ "$duration_seconds" -lt 90 ] ||
  [ "$window_seconds" -lt 10 ] ||
  [ "$((window_margin_seconds + window_seconds))" -gt "$duration_seconds" ]; then
  printf 'allocation window must fit inside at least 20s warmup plus 90s measurement\n' >&2
  exit 2
fi
if [ -e "$results_root" ]; then
  printf 'allocation diagnostic result root already exists: %s\n' "$results_root" >&2
  exit 2
fi

window_dir="$results_root/allocation-window"
mkdir -p "$window_dir"

cleanup() {
  local status="${1-$?}"
  local cleanup_status=0
  trap - EXIT INT TERM
  set +e
  if [ -n "$alloy_forward_pid" ]; then
    kill "$alloy_forward_pid" 2>/dev/null
    wait "$alloy_forward_pid" 2>/dev/null
  fi
  if [ -n "$runner_pid" ] && kill -0 "$runner_pid" 2>/dev/null; then
    kill -TERM "$runner_pid" 2>/dev/null
    wait "$runner_pid" 2>/dev/null
  fi
  if [ "$probes_applied" = "1" ]; then
    kubectl --context "$context" delete -f "$probe_manifest" \
      --ignore-not-found=true --wait=true >"$window_dir/probe-cleanup.txt" 2>&1 ||
      cleanup_status=1
  fi
  if [ "$status" -ne 0 ]; then
    exit "$status"
  fi
  exit "$cleanup_status"
}

trap 'cleanup $?' EXIT
trap 'cleanup 130' INT
trap 'cleanup 143' TERM

kubectl --context "$context" get namespace kube-system >/dev/null
if [ "$(kubectl --context "$context" get node homelab-02 \
  -o jsonpath='{.status.nodeInfo.architecture}')" != "amd64" ]; then
  printf 'allocation diagnostic currently requires the homelab amd64 Go register ABI\n' >&2
  exit 2
fi
if [ -n "$(kubectl --context "$context" -n "$namespace" get pods \
  -l app.kubernetes.io/name=e-navigator-allocation-probe -o name 2>/dev/null)" ]; then
  printf 'allocation probes already exist in benchmark namespace\n' >&2
  exit 2
fi

kubectl --context "$context" apply -f "$probe_manifest" >"$window_dir/probe-apply.txt"
probes_applied=1
kubectl --context "$context" -n "$namespace" wait --for=condition=Ready \
  -l app.kubernetes.io/name=e-navigator-allocation-probe pod --timeout=180s \
  >"$window_dir/probe-wait.txt"
kubectl --context "$context" -n "$namespace" exec "$probe_pod" -- timeout 300 sh -lc \
  'export DEBIAN_FRONTEND=noninteractive; apt-get -o Acquire::Retries=3 -o Acquire::http::Timeout=20 -o Acquire::https::Timeout=20 update >/tmp/apt-update.log; apt-get -o Acquire::Retries=3 -o Acquire::http::Timeout=20 -o Acquire::https::Timeout=20 install -y --no-install-recommends bpftrace >/tmp/apt-install.log' \
  >"$window_dir/bpftrace-install.txt" 2>&1
kubectl --context "$context" -n "$namespace" exec "$probe_pod" -- bpftrace --version \
  >"$window_dir/bpftrace-version.txt"

E_NAVIGATOR_HEAD_TO_HEAD_RUN_MODE=profile-diagnostic \
E_NAVIGATOR_HEAD_TO_HEAD_DIAGNOSTIC_COLLECTOR="$collector" \
E_NAVIGATOR_HEAD_TO_HEAD_REPETITIONS=1 \
E_NAVIGATOR_HEAD_TO_HEAD_WARMUP_SECONDS="$warmup_seconds" \
E_NAVIGATOR_HEAD_TO_HEAD_DURATION_SECONDS="$duration_seconds" \
benchmarks/runner/homelab-head-to-head.sh >"$window_dir/harness.log" 2>&1 &
runner_pid="$!"

collector_label="$collector"
if [ "$collector" = "e-navigator" ]; then
  collector_label="e-navigator"
fi
collector_json="$window_dir/collector-pods.json"
for _attempt in $(seq 1 240); do
  kubectl --context "$context" -n "$namespace" get pods \
    -l "e-navigator.dev/collector=$collector_label" -o json \
    >"${collector_json}.tmp" 2>/dev/null || true
  if jq -e '.items[] | select(.spec.nodeName == "homelab-02" and .status.phase == "Running")' \
    "${collector_json}.tmp" >/dev/null 2>&1; then
    mv "${collector_json}.tmp" "$collector_json"
    break
  fi
  if ! kill -0 "$runner_pid" 2>/dev/null; then
    wait "$runner_pid"
  fi
  sleep 1
done
if [ ! -s "$collector_json" ]; then
  printf 'collector did not become ready on homelab-02\n' >&2
  exit 1
fi

container_id="$(jq -r '
  .items[] |
  select(.spec.nodeName == "homelab-02" and .status.phase == "Running") |
  .status.containerStatuses[0].containerID
' "$collector_json" | sed -n '1s|^containerd://||p')"
if [ -z "$container_id" ]; then
  printf 'collector container ID was not available\n' >&2
  exit 1
fi
host_pid="$(kubectl --context "$context" -n "$namespace" exec "$probe_pod" -- \
  cat "/host/run/k3s/containerd/io.containerd.runtime.v2.task/k8s.io/$container_id/init.pid")"
case "$host_pid" in
  ""|*[!0-9]*)
    printf 'collector host PID was not numeric\n' >&2
    exit 1
    ;;
esac
printf '%s\n' "$host_pid" >"$window_dir/$collector.pid"
kubectl --context "$context" -n "$namespace" exec "$probe_pod" -- \
  readlink "/host/proc/$host_pid/exe" >"$window_dir/$collector.exe"

job_name="h2h-${collector//e-navigator/enav}-profile-r1"
for _attempt in $(seq 1 240); do
  if [ "$(kubectl --context "$context" -n "$namespace" get pod \
    -l "job-name=$job_name" -o jsonpath='{.items[0].status.phase}' 2>/dev/null || true)" = "Running" ]; then
    kubectl --context "$context" -n "$namespace" get pod \
      -l "job-name=$job_name" -o json >"$window_dir/workload-pod-at-start.json"
    break
  fi
  if ! kill -0 "$runner_pid" 2>/dev/null; then
    wait "$runner_pid"
  fi
  sleep 1
done
if [ ! -s "$window_dir/workload-pod-at-start.json" ]; then
  printf 'diagnostic workload did not start\n' >&2
  exit 1
fi

sleep "$((warmup_seconds + window_margin_seconds))"

if [ "$collector" = "e-navigator" ]; then
  # shellcheck disable=SC2016 # $6 belongs to awk.
  libc_path="$(kubectl --context "$context" -n "$namespace" exec "$probe_pod" -- \
    awk '/libc\.so\.6/ { print $6; exit }' "/host/proc/$host_pid/maps")"
  if [ -z "$libc_path" ]; then
    printf 'collector libc mapping was not available\n' >&2
    exit 1
  fi
  probe_target="/host/proc/$host_pid/root$libc_path"
  trace_program="
uprobe:$probe_target:malloc /pid == $host_pid/ { @allocation_calls = count(); @requested_bytes = sum(arg0); }
uprobe:$probe_target:calloc /pid == $host_pid/ { @allocation_calls = count(); @requested_bytes = sum(arg0 * arg1); }
uprobe:$probe_target:realloc /pid == $host_pid/ { @allocation_calls = count(); @requested_bytes = sum(arg1); }
uprobe:$probe_target:posix_memalign /pid == $host_pid/ { @allocation_calls = count(); @requested_bytes = sum(arg2); }
uprobe:$probe_target:aligned_alloc /pid == $host_pid/ { @allocation_calls = count(); @requested_bytes = sum(arg1); }
interval:s:$window_seconds { exit(); }
"
else
  probe_target="/host/proc/$host_pid/exe"
  trace_program="
uprobe:$probe_target:runtime.mallocgc /pid == $host_pid/ { @allocation_calls = count(); @requested_bytes = sum(reg(\"ax\")); }
interval:s:$window_seconds { exit(); }
"
  alloy_pod="$(kubectl --context "$context" -n "$namespace" get pod \
    -l e-navigator.dev/collector=alloy \
    --field-selector=status.phase=Running -o jsonpath='{.items[0].metadata.name}')"
  if [ -z "$alloy_pod" ]; then
    printf 'Alloy pod was not available for runtime counters\n' >&2
    exit 1
  fi
  kubectl --context "$context" -n "$namespace" port-forward "pod/$alloy_pod" \
    29123:12345 >"$window_dir/alloy-port-forward.txt" 2>&1 &
  alloy_forward_pid="$!"
  for _attempt in $(seq 1 60); do
    if curl --silent --show-error --fail --max-time 2 \
      http://127.0.0.1:29123/-/ready >/dev/null 2>&1; then
      break
    fi
    sleep 1
  done
  curl --silent --show-error --fail --max-time 10 \
    http://127.0.0.1:29123/metrics >"$window_dir/alloy-before.prom"
fi

date -u +%Y-%m-%dT%H:%M:%SZ >"$window_dir/window-start.txt"
kubectl --context "$context" -n "$namespace" exec "$probe_pod" -- \
  bpftrace -e "$trace_program" >"$window_dir/$collector.bpftrace" 2>&1
date -u +%Y-%m-%dT%H:%M:%SZ >"$window_dir/window-end.txt"

if ! grep -Fq '@allocation_calls:' "$window_dir/$collector.bpftrace" ||
  ! grep -Fq '@requested_bytes:' "$window_dir/$collector.bpftrace"; then
  printf 'allocation probe did not emit both counters\n' >&2
  exit 1
fi
if [ "$collector" = "beyla" ]; then
  curl --silent --show-error --fail --max-time 10 \
    http://127.0.0.1:29123/metrics >"$window_dir/alloy-after.prom"
  kill "$alloy_forward_pid" 2>/dev/null
  wait "$alloy_forward_pid" 2>/dev/null || true
  alloy_forward_pid=""
fi

wait "$runner_pid"
runner_pid=""
kubectl --context "$context" delete -f "$probe_manifest" \
  --ignore-not-found=true --wait=true >"$window_dir/probe-cleanup.txt"
probes_applied=0

printf 'DIAGNOSTIC ONLY: %ss allocation window inside %ss measured %s profile arm\n' \
  "$window_seconds" "$duration_seconds" "$collector" | tee "$window_dir/summary.txt"

trap - EXIT INT TERM
