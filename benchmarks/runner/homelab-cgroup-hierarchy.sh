#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

context="${E_NAVIGATOR_HOMELAB_CONTEXT:-homelab}"
namespace="${E_NAVIGATOR_HOMELAB_NAMESPACE:-e-navigator-bench}"
image="${E_NAVIGATOR_HOMELAB_IMAGE:-}"
results_dir="${E_NAVIGATOR_HOMELAB_RESULTS_DIR:-benchmarks/results/cgroup-hierarchy-$(date -u +%Y%m%d-%H%M%S)}"
template="benchmarks/k8s/cgroup-hierarchy-proof.yaml"
config="benchmarks/config/cgroup-hierarchy-proof.toml"
rendered=""

if [ "${E_NAVIGATOR_HOMELAB_CONFIRM:-0}" != "1" ]; then
  printf 'refusing to run cgroup hierarchy proof without E_NAVIGATOR_HOMELAB_CONFIRM=1\n' >&2
  exit 2
fi
if [ "$context" != "homelab" ]; then
  printf 'target context must be exactly homelab; got: %s\n' "$context" >&2
  exit 2
fi
if [ "$namespace" != "e-navigator-bench" ]; then
  printf 'target namespace must be exactly e-navigator-bench; got: %s\n' "$namespace" >&2
  exit 2
fi
if [ -z "$image" ]; then
  printf 'E_NAVIGATOR_HOMELAB_IMAGE must name the preloaded proof image\n' >&2
  exit 2
fi
case "$image" in
  *[!A-Za-z0-9._/:@-]*)
    printf 'E_NAVIGATOR_HOMELAB_IMAGE contains unsupported characters\n' >&2
    exit 2
    ;;
esac
if ! kubectl --context "$context" get namespace kube-system >/dev/null 2>&1; then
  printf 'unable to reach guarded homelab context\n' >&2
  exit 2
fi

mkdir -p "$results_dir"
rendered="$(mktemp)"
cleanup() {
  status="$?"
  if [ -n "$rendered" ] && [ -f "$rendered" ]; then
    kubectl --context "$context" delete -f "$rendered" --ignore-not-found=true \
      >"$results_dir/cleanup.txt" 2>&1 || true
    kubectl --context "$context" wait --for=delete pod -n "$namespace" \
      -l 'app.kubernetes.io/name in (e-navigator-cgroup-v2,e-navigator-cgroup-v1-fixture,e-navigator-cgroup-proof-execs)' \
      --timeout=120s >>"$results_dir/cleanup.txt" 2>&1 || true
    rm -f "$rendered"
  fi
  kubectl --context "$context" get all -n "$namespace" \
    >"$results_dir/post-cleanup.txt" 2>&1 || true
  exit "$status"
}
trap cleanup EXIT INT TERM

kubectl --context "$context" get pods -n "$namespace" -o wide \
  >"$results_dir/baseline-pods.txt" 2>&1 || true
kubectl --context "$context" top nodes >"$results_dir/baseline-node-top.txt" 2>&1 || true
kubectl --context "$context" get nodes -o wide >"$results_dir/nodes.txt"
kubectl --context "$context" create namespace "$namespace" --dry-run=client -o yaml |
  kubectl --context "$context" apply -f - >"$results_dir/namespace-apply.txt"

awk '{ print "    " $0 }' "$config" >"$results_dir/config-indented.txt"
sed "s|__IMAGE__|$image|g" "$template" |
  awk -v config_file="$results_dir/config-indented.txt" '
    /__CONFIG_TOML__/ {
      while ((getline line < config_file) > 0) print line
      close(config_file)
      next
    }
    { print }
  ' >"$rendered"
cp "$rendered" "$results_dir/rendered-manifest.yaml"

kubectl --context "$context" apply -f "$rendered" >"$results_dir/apply.txt"
for deployment in e-navigator-cgroup-v2 e-navigator-cgroup-v1-fixture; do
  kubectl --context "$context" rollout status "deployment/$deployment" -n "$namespace" \
    --timeout=180s >>"$results_dir/rollout.txt"
done
kubectl --context "$context" wait --for=condition=complete \
  job/e-navigator-cgroup-proof-execs -n "$namespace" --timeout=180s \
  >"$results_dir/workload-wait.txt"

# The filter applier reports cumulative kernel drops every 30 seconds.
sleep 35

collect_arm() {
  arm="$1"
  selector="$2"
  port="$3"
  pod="$(kubectl --context "$context" get pods -n "$namespace" -l "$selector" \
    -o jsonpath='{.items[0].metadata.name}')"
  printf '%s\n' "$pod" >"$results_dir/$arm-pod.txt"
  kubectl --context "$context" logs -n "$namespace" "$pod" \
    >"$results_dir/$arm-logs.raw.txt"
  sed $'s/\033\\[[0-9;]*[mK]//g' "$results_dir/$arm-logs.raw.txt" \
    >"$results_dir/$arm-logs.txt"
  kubectl --context "$context" port-forward -n "$namespace" "pod/$pod" \
    "$port:9090" >"$results_dir/$arm-port-forward.txt" 2>&1 &
  forward_pid="$!"
  metrics_status=1
  for _attempt in 1 2 3 4 5; do
    if curl --fail --silent --show-error "http://127.0.0.1:$port/metrics" \
      >"$results_dir/$arm-metrics.txt"; then
      metrics_status=0
      break
    fi
    sleep 1
  done
  kill "$forward_pid" >/dev/null 2>&1 || true
  wait "$forward_pid" >/dev/null 2>&1 || true
  if [ "$metrics_status" -ne 0 ]; then
    printf 'failed to collect %s metrics\n' "$arm" >&2
    return 1
  fi
}

collect_arm v2 'app.kubernetes.io/name=e-navigator-cgroup-v2' 19091
collect_arm v1-fixture 'app.kubernetes.io/name=e-navigator-cgroup-v1-fixture' 19092

grep -Fq 'e_navigator_capture_filter_cgroup_hierarchy_info{mode="unified_v2"} 1' \
  "$results_dir/v2-metrics.txt"
grep -Fq 'e_navigator_capture_filter_cgroup_v2_compatible 1' "$results_dir/v2-metrics.txt"
grep -Fq 'e_navigator_capture_filter_fail_closed_total 0' "$results_dir/v2-metrics.txt"
grep -Fq 'e_navigator_ebpf_source_initialized{source="source.aya_exec"} 1' \
  "$results_dir/v2-metrics.txt"

grep -Fq 'e_navigator_capture_filter_cgroup_hierarchy_info{mode="legacy_v1"} 1' \
  "$results_dir/v1-fixture-metrics.txt"
grep -Fq 'e_navigator_capture_filter_cgroup_v2_compatible 0' \
  "$results_dir/v1-fixture-metrics.txt"
grep -Fq 'e_navigator_capture_filter_fail_closed_total 1' \
  "$results_dir/v1-fixture-metrics.txt"
grep -Fq 'e_navigator_ebpf_source_initialized{source="source.aya_exec"} 1' \
  "$results_dir/v1-fixture-metrics.txt"
grep -Fq 'e_navigator_ebpf_source_decoded_samples_total{source="source.aya_exec"} 0' \
  "$results_dir/v1-fixture-metrics.txt"
grep -Fq 'e_navigator_ebpf_source_sent_signals_total{source="source.aya_exec"} 0' \
  "$results_dir/v1-fixture-metrics.txt"
grep -Fq 'cgroup_hierarchy_mode="legacy_v1"' "$results_dir/v1-fixture-logs.txt"
grep -Fq 'control_word=2' "$results_dir/v1-fixture-logs.txt"
grep -Eq 'dropped_total=[1-9][0-9]*' "$results_dir/v1-fixture-logs.txt"

kubectl --context "$context" get pods -n "$namespace" -o wide >"$results_dir/pods.txt"
kubectl --context "$context" get events -n "$namespace" --sort-by=.lastTimestamp \
  >"$results_dir/events.txt"
printf 'PASS: unified v2 accepted; legacy fixture detected and forced to deny\n' |
  tee "$results_dir/summary.txt"
