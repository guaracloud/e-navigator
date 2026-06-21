#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

namespace="${E_NAVIGATOR_HOMELAB_NAMESPACE:-e-navigator-bench}"
context="${E_NAVIGATOR_HOMELAB_CONTEXT:-}"
timestamp="$(date -u +%Y%m%d-%H%M%S)"
results_dir="${E_NAVIGATOR_HOMELAB_RESULTS_DIR:-benchmarks/results/${timestamp}}"
release="${E_NAVIGATOR_HOMELAB_RELEASE:-e-navigator-bench}"
required_context="staging"
required_namespace="e-navigator-bench"

if [ "${E_NAVIGATOR_HOMELAB_CONFIRM:-0}" != "1" ]; then
  cat >&2 <<MSG
refusing to run homelab validation without E_NAVIGATOR_HOMELAB_CONFIRM=1
target context: ${context:-not queried before confirmation}
target namespace: ${namespace}
MSG
  exit 2
fi

current_context="$(kubectl config current-context 2>/dev/null || true)"

if [ -z "$current_context" ]; then
  printf 'kubectl context is empty; set E_NAVIGATOR_HOMELAB_CONTEXT\n' >&2
  exit 2
fi

if [ "$current_context" != "$required_context" ]; then
  printf 'current context must be exactly staging; got: %s\n' "$current_context" >&2
  exit 2
fi

if [ -z "$context" ]; then
  context="$current_context"
fi

if [ "$context" != "$current_context" ]; then
  printf 'requested context must match current context %s; got: %s\n' "$current_context" "$context" >&2
  exit 2
fi

if [ "$namespace" != "$required_namespace" ]; then
  printf 'homelab validation namespace must be exactly e-navigator-bench; got: %s\n' "$namespace" >&2
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

top_samples="${E_NAVIGATOR_HOMELAB_TOP_SAMPLES:-10}"
top_interval_seconds="${E_NAVIGATOR_HOMELAB_TOP_INTERVAL_SECONDS:-5}"

capture_top_samples() {
  local output="$results_dir/top-pods-10-samples.txt"
  : >"$output"
  printf '\n==> top-pods-10-samples\n' | tee -a "$results_dir/commands.txt"
  printf 'kubectl --context %q -n %q top pods --containers # repeated %q times every %q seconds\n' \
    "$context" "$namespace" "$top_samples" "$top_interval_seconds" | tee -a "$results_dir/commands.txt"

  for sample in $(seq 1 "$top_samples"); do
    printf 'sample=%s timestamp=%s\n' "$sample" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >>"$output"
    "${kubectl_cmd[@]}" -n "$namespace" top pods --containers >>"$output" 2>&1 || true
    if [ "$sample" != "$top_samples" ]; then
      sleep "$top_interval_seconds"
    fi
  done
}

capture_capabilities() {
  local pod_list="$results_dir/runtime-pod-names.txt"
  "${kubectl_cmd[@]}" -n "$namespace" get pods -l app.kubernetes.io/name=e-navigator \
    -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' >"$pod_list" 2>/dev/null || true

  while IFS= read -r pod; do
    [ -n "$pod" ] || continue
    run_capture "proc-status-${pod}" "${kubectl_cmd[@]}" -n "$namespace" exec "$pod" -- sh -c 'cat /proc/1/status'
    run_capture "proc-mounts-${pod}" "${kubectl_cmd[@]}" -n "$namespace" exec "$pod" -- sh -c 'cat /proc/1/mounts'
    run_capture "proc-id-${pod}" "${kubectl_cmd[@]}" -n "$namespace" exec "$pod" -- sh -c 'id && grep -E "^(CapEff|NoNewPrivs|Seccomp|Uid|Gid):" /proc/1/status'
  done <"$pod_list"

  python3 - "$results_dir" >"$results_dir/capability-decode.txt" <<'PY'
import sys
from pathlib import Path

caps = {
    0: "CAP_CHOWN", 1: "CAP_DAC_OVERRIDE", 2: "CAP_DAC_READ_SEARCH",
    3: "CAP_FOWNER", 4: "CAP_FSETID", 5: "CAP_KILL", 6: "CAP_SETGID",
    7: "CAP_SETUID", 8: "CAP_SETPCAP", 9: "CAP_LINUX_IMMUTABLE",
    10: "CAP_NET_BIND_SERVICE", 11: "CAP_NET_BROADCAST", 12: "CAP_NET_ADMIN",
    13: "CAP_NET_RAW", 14: "CAP_IPC_LOCK", 15: "CAP_IPC_OWNER",
    16: "CAP_SYS_MODULE", 17: "CAP_SYS_RAWIO", 18: "CAP_SYS_CHROOT",
    19: "CAP_SYS_PTRACE", 20: "CAP_SYS_PACCT", 21: "CAP_SYS_ADMIN",
    22: "CAP_SYS_BOOT", 23: "CAP_SYS_NICE", 24: "CAP_SYS_RESOURCE",
    25: "CAP_SYS_TIME", 26: "CAP_SYS_TTY_CONFIG", 27: "CAP_MKNOD",
    28: "CAP_LEASE", 29: "CAP_AUDIT_WRITE", 30: "CAP_AUDIT_CONTROL",
    31: "CAP_SETFCAP", 32: "CAP_MAC_OVERRIDE", 33: "CAP_MAC_ADMIN",
    34: "CAP_SYSLOG", 35: "CAP_WAKE_ALARM", 36: "CAP_BLOCK_SUSPEND",
    37: "CAP_AUDIT_READ", 38: "CAP_PERFMON", 39: "CAP_BPF",
    40: "CAP_CHECKPOINT_RESTORE",
}

base = Path(sys.argv[1])
for path in sorted(base.glob("proc-status-e-navigator-*.txt")):
    pod = path.name.removeprefix("proc-status-").removesuffix(".txt")
    text = path.read_text(errors="replace")
    cap_eff = next((line.split()[1] for line in text.splitlines() if line.startswith("CapEff:")), None)
    no_new = next((line.split()[1] for line in text.splitlines() if line.startswith("NoNewPrivs:")), None)
    seccomp = next((line.split()[1] for line in text.splitlines() if line.startswith("Seccomp:")), None)
    uid = next((line for line in text.splitlines() if line.startswith("Uid:")), None)
    gid = next((line for line in text.splitlines() if line.startswith("Gid:")), None)
    print(f"{pod}: CapEff={cap_eff} NoNewPrivs={no_new} Seccomp={seccomp}")
    if uid:
        print(f"  {uid}")
    if gid:
        print(f"  {gid}")
    if cap_eff:
        value = int(cap_eff, 16)
        enabled = [name for bit, name in caps.items() if value & (1 << bit)]
        print("  " + ", ".join(enabled))
PY
}

capture_service_surfaces() {
  run_capture services-endpoints "${kubectl_cmd[@]}" -n "$namespace" get service,endpoints -o wide
  run_capture monitoring-api-resources kubectl --context "$context" api-resources \
    --api-group=monitoring.coreos.com --verbs=list -o name

  if grep -q '^servicemonitors\.monitoring\.coreos\.com$' "$results_dir/monitoring-api-resources.txt"; then
    run_capture servicemonitors "${kubectl_cmd[@]}" -n "$namespace" get servicemonitors.monitoring.coreos.com -o wide
  else
    printf 'servicemonitors.monitoring.coreos.com API not present\n' >"$results_dir/servicemonitors.txt"
  fi

  if grep -q '^podmonitors\.monitoring\.coreos\.com$' "$results_dir/monitoring-api-resources.txt"; then
    run_capture podmonitors "${kubectl_cmd[@]}" -n "$namespace" get podmonitors.monitoring.coreos.com -o wide
  else
    printf 'podmonitors.monitoring.coreos.com API not present\n' >"$results_dir/podmonitors.txt"
  fi
}

capture_prometheus_http_endpoints() {
  local service_name="$release"
  local local_port="${E_NAVIGATOR_HOMELAB_PROMETHEUS_LOCAL_PORT:-19090}"
  local port_forward_log="$results_dir/prometheus-http-port-forward.txt"

  if ! "${kubectl_cmd[@]}" -n "$namespace" get service "$service_name" >/dev/null 2>&1; then
    printf 'service %s not present; Prometheus HTTP endpoint checks skipped\n' "$service_name" \
      >"$results_dir/prometheus-http-skipped.txt"
    return
  fi

  printf '\n==> prometheus-http-port-forward\n' | tee -a "$results_dir/commands.txt"
  printf 'kubectl --context %q -n %q port-forward service/%q %q:9090\n' \
    "$context" "$namespace" "$service_name" "$local_port" | tee -a "$results_dir/commands.txt"
  "${kubectl_cmd[@]}" -n "$namespace" port-forward "service/${service_name}" "${local_port}:9090" \
    >"$port_forward_log" 2>&1 &
  local port_forward_pid="$!"

  sleep 2

  capture_prometheus_http_path() {
    local name="$1"
    local path="$2"
    local url="http://127.0.0.1:${local_port}${path}"

    printf '\n==> %s\n' "$name" | tee -a "$results_dir/commands.txt"
    printf 'curl -sS -i --max-time 5 %q\n' "$url" | tee -a "$results_dir/commands.txt"
    curl -sS -i --max-time 5 "$url" >"$results_dir/${name}.txt" 2>&1 || true
  }

  capture_prometheus_http_path prometheus-http-healthz /healthz
  capture_prometheus_http_path prometheus-http-readyz /readyz
  capture_prometheus_http_path prometheus-http-metrics /metrics

  kill "$port_forward_pid" >/dev/null 2>&1 || true
  wait "$port_forward_pid" >/dev/null 2>&1 || true
}

sanitize_url_for_log() {
  printf '%s' "$1" | sed -E 's#(https?://)[^/@]+@#\1[REDACTED]@#'
}

capture_prometheus_api_request() {
  local name="$1"
  local base_url="$2"
  local api_path="$3"
  shift 3
  local url="${base_url%/}${api_path}"
  local sanitized_url
  sanitized_url="$(sanitize_url_for_log "$url")"

  printf '\n==> %s\n' "$name" | tee -a "$results_dir/commands.txt"
  printf 'curl -sS --get --max-time 10 %q' "$sanitized_url" | tee -a "$results_dir/commands.txt"
  for arg in "$@"; do
    printf ' --data-urlencode %q' "$arg" | tee -a "$results_dir/commands.txt"
  done
  printf '\n' | tee -a "$results_dir/commands.txt"

  local curl_args=(curl -sS --get --max-time 10 "$url")
  for arg in "$@"; do
    curl_args+=(--data-urlencode "$arg")
  done

  "${curl_args[@]}" >"$results_dir/${name}.txt" 2>&1 || true
}

capture_prometheus_api_queries() {
  local prometheus_url="${E_NAVIGATOR_HOMELAB_PROMETHEUS_URL:-}"
  local prometheus_service="${E_NAVIGATOR_HOMELAB_PROMETHEUS_SERVICE:-}"
  local prometheus_namespace="${E_NAVIGATOR_HOMELAB_PROMETHEUS_NAMESPACE:-observability-system}"
  local prometheus_port="${E_NAVIGATOR_HOMELAB_PROMETHEUS_PORT:-9090}"
  local prometheus_local_port="${E_NAVIGATOR_HOMELAB_PROMETHEUS_API_LOCAL_PORT:-19091}"
  local port_forward_pid=""

  if [ -n "$prometheus_url" ]; then
    printf 'using configured Prometheus API URL\n' >"$results_dir/prometheus-api-source.txt"
  elif [ -n "$prometheus_service" ]; then
    printf '\n==> prometheus-api-port-forward\n' | tee -a "$results_dir/commands.txt"
    printf 'kubectl --context %q -n %q port-forward service/%q %q:%q\n' \
      "$context" "$prometheus_namespace" "$prometheus_service" "$prometheus_local_port" "$prometheus_port" \
      | tee -a "$results_dir/commands.txt"
    kubectl --context "$context" -n "$prometheus_namespace" port-forward \
      "service/${prometheus_service}" "${prometheus_local_port}:${prometheus_port}" \
      >"$results_dir/prometheus-api-port-forward.txt" 2>&1 &
    port_forward_pid="$!"
    prometheus_url="http://127.0.0.1:${prometheus_local_port}"
    sleep 2
  else
    cat >"$results_dir/prometheus-api-skipped.txt" <<EOF
Prometheus API checks skipped.
Set E_NAVIGATOR_HOMELAB_PROMETHEUS_URL or E_NAVIGATOR_HOMELAB_PROMETHEUS_SERVICE to capture active targets and query results.
EOF
    return
  fi

  capture_prometheus_api_request prometheus-api-targets "$prometheus_url" \
    /api/v1/targets \
    state=active
  capture_prometheus_api_request prometheus-api-query-up "$prometheus_url" \
    /api/v1/query \
    "query=up{namespace=\"${namespace}\"}"
  capture_prometheus_api_request prometheus-api-query-e-navigator "$prometheus_url" \
    /api/v1/query \
    "query={namespace=\"${namespace}\"}"
  capture_prometheus_api_request prometheus-api-series "$prometheus_url" \
    /api/v1/series \
    "match[]={namespace=\"${namespace}\"}"

  if [ -n "$port_forward_pid" ]; then
    kill "$port_forward_pid" >/dev/null 2>&1 || true
    wait "$port_forward_pid" >/dev/null 2>&1 || true
  fi
}

write_summary_files() {
  cat >"$results_dir/summary.md" <<EOF
# Homelab Validation Summary: ${timestamp}

- Context: \`${context}\`
- Namespace: \`${namespace}\`
- Release: \`${release}\`
- Cleanup requested: \`${E_NAVIGATOR_HOMELAB_CLEANUP:-0}\`

This generated summary is an artifact index. It does not upgrade any claim by
itself; inspect the referenced evidence before updating documentation.

## Captured Evidence

- Commands: \`commands.txt\`
- Rendered manifest: \`rendered-manifest.txt\`
- Live Helm values: \`helm-values.txt\`
- Live Helm manifest: \`helm-manifest.txt\`
- Namespace: \`namespace.txt\`
- Pods: \`pods.txt\`, \`pod-json.txt\`
- DaemonSet: \`daemonset.txt\`, \`daemonset-yaml.txt\`
- ConfigMap: \`configmap-yaml.txt\`
- Services and endpoints: \`services-endpoints.txt\`
- Prometheus monitor resources: \`monitoring-api-resources.txt\`, \`servicemonitors.txt\`, \`podmonitors.txt\`
- Prometheus HTTP endpoint checks: \`prometheus-http-port-forward.txt\`, \`prometheus-http-healthz.txt\`, \`prometheus-http-readyz.txt\`, \`prometheus-http-metrics.txt\`, or \`prometheus-http-skipped.txt\`
- Prometheus API checks: \`prometheus-api-targets.txt\`, \`prometheus-api-query-up.txt\`, \`prometheus-api-query-e-navigator.txt\`, \`prometheus-api-series.txt\`, \`prometheus-api-port-forward.txt\`, or \`prometheus-api-skipped.txt\`
- Logs: \`logs.txt\`
- Events: \`events.txt\`
- Resource samples: \`top-pods-10-samples.txt\`
- Capability decode: \`capability-decode.txt\`
EOF

  cat >"$results_dir/proof-matrix.md" <<EOF
# Proof Matrix: ${timestamp}

| Item | Status | Evidence | Non-claim |
| --- | --- | --- | --- |
| Context | captured | \`current-context.txt\` | no other context validated |
| Namespace | captured | \`namespace.txt\` | no other namespace validated |
| Rendered manifest | captured | \`rendered-manifest.txt\`, \`helm-manifest.txt\`, \`helm-values.txt\` | render does not prove runtime behavior |
| DaemonSet rollout | captured | \`rollout.txt\`, \`daemonset-yaml.txt\` | no production soak |
| JSON logs | captured | \`logs.txt\` | logs must be inspected before claiming source/generator proof |
| Services/endpoints | captured | \`services-endpoints.txt\`, \`servicemonitors.txt\`, \`podmonitors.txt\` | no Prometheus proof unless HTTP 200 and scrape evidence are present |
| Prometheus HTTP endpoints | captured when Service exists | \`prometheus-http-healthz.txt\`, \`prometheus-http-readyz.txt\`, \`prometheus-http-metrics.txt\`, \`prometheus-http-port-forward.txt\`, or \`prometheus-http-skipped.txt\` | endpoint captures alone do not prove Prometheus active target or queryability |
| Prometheus API queries | captured when configured | \`prometheus-api-targets.txt\`, \`prometheus-api-query-up.txt\`, \`prometheus-api-query-e-navigator.txt\`, \`prometheus-api-series.txt\`, \`prometheus-api-port-forward.txt\`, or \`prometheus-api-skipped.txt\` | empty query results are negative or inconclusive, not success |
| Resource overhead | captured | \`top-pods-10-samples.txt\` | no reduced-overhead claim without a comparable baseline |
| Capabilities | captured | \`capability-decode.txt\` | no reduced-privilege claim if CAP_SYS_ADMIN remains or seccomp is disabled |
EOF
}

render_args=(--namespace "$namespace" --set namespace.create=false --set namespace.name="$namespace")

if [ "${E_NAVIGATOR_HOMELAB_APPLY:-0}" = "1" ]; then
  image_repository="${E_NAVIGATOR_HOMELAB_IMAGE_REPOSITORY:-}"
  image_tag="${E_NAVIGATOR_HOMELAB_IMAGE_TAG:-}"
  if [ -z "$image_repository" ] || [ -z "$image_tag" ]; then
    printf 'E_NAVIGATOR_HOMELAB_IMAGE_REPOSITORY and E_NAVIGATOR_HOMELAB_IMAGE_TAG are required when E_NAVIGATOR_HOMELAB_APPLY=1\n' >&2
    exit 2
  fi
  image_pull_secret="${E_NAVIGATOR_HOMELAB_IMAGE_PULL_SECRET:-}"
  helm_args=(
    --set namespace.create=false
    --set namespace.name="$namespace"
    --set image.repository="$image_repository"
    --set image.tag="$image_tag"
    --set image.pullPolicy=IfNotPresent
    --set resources.requests.cpu=50m
    --set resources.requests.memory=128Mi
    --set resources.limits.memory=512Mi
  )
  if [ -n "$image_pull_secret" ]; then
    helm_args+=(--set "imagePullSecrets[0].name=$image_pull_secret")
  fi
  render_args+=("${helm_args[@]}")

  "${kubectl_cmd[@]}" create namespace "$namespace" --dry-run=client -o yaml \
    | "${kubectl_cmd[@]}" apply -f -
  helm --kube-context "$context" upgrade --install "$release" charts/e-navigator \
    --namespace "$namespace" "${helm_args[@]}"
  "${kubectl_cmd[@]}" -n "$namespace" apply -f benchmarks/k8s/workload.yaml
fi

run_capture current-context kubectl config current-context
run_capture rendered-manifest helm --kube-context "$context" template "$release" charts/e-navigator "${render_args[@]}"
run_capture helm-values helm --kube-context "$context" get values "$release" --namespace "$namespace" --all
run_capture helm-manifest helm --kube-context "$context" get manifest "$release" --namespace "$namespace"
run_capture namespace "${kubectl_cmd[@]}" get namespace "$namespace" -o yaml
run_capture pods "${kubectl_cmd[@]}" -n "$namespace" get pods -o wide
run_capture daemonset "${kubectl_cmd[@]}" -n "$namespace" get daemonset -o wide
run_capture daemonset-yaml "${kubectl_cmd[@]}" -n "$namespace" get daemonset "$release" -o yaml
run_capture configmap-yaml "${kubectl_cmd[@]}" -n "$namespace" get configmap "${release}-config" -o yaml
capture_service_surfaces
capture_prometheus_http_endpoints
capture_prometheus_api_queries
run_capture rollout "${kubectl_cmd[@]}" -n "$namespace" rollout status "daemonset/${release}" --timeout="${E_NAVIGATOR_HOMELAB_ROLLOUT_TIMEOUT:-120s}"
run_capture pod-json "${kubectl_cmd[@]}" -n "$namespace" get pods -o json
run_capture logs "${kubectl_cmd[@]}" -n "$namespace" logs -l app.kubernetes.io/name=e-navigator --all-containers --tail="${E_NAVIGATOR_HOMELAB_LOG_TAIL:-2000}" --prefix
run_capture events "${kubectl_cmd[@]}" -n "$namespace" get events --sort-by=.lastTimestamp
capture_top_samples
capture_capabilities
write_summary_files

if [ "${E_NAVIGATOR_HOMELAB_CLEANUP:-0}" = "1" ]; then
  printf 'running namespace-scoped cleanup in %s\n' "$namespace"
  "${kubectl_cmd[@]}" -n "$namespace" delete -f benchmarks/k8s/workload.yaml --ignore-not-found=true
  helm --kube-context "$context" uninstall "$release" --namespace "$namespace" || true
fi

printf 'homelab collection complete: %s\n' "$results_dir"
