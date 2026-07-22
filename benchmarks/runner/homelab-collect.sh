#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

namespace="${E_NAVIGATOR_HOMELAB_NAMESPACE:-e-navigator-bench}"
context="${E_NAVIGATOR_HOMELAB_CONTEXT:-homelab}"
timestamp="$(date -u +%Y%m%d-%H%M%S)"
results_dir="${E_NAVIGATOR_HOMELAB_RESULTS_DIR:-benchmarks/results/${timestamp}}"
release="${E_NAVIGATOR_HOMELAB_RELEASE:-e-navigator-bench}"
required_context="homelab"
required_namespace="e-navigator-bench"
required_image_repository="ghcr.io/guaracloud/e-navigator"
required_image_tag="sha-8ab271c"
image_repository="${E_NAVIGATOR_HOMELAB_IMAGE_REPOSITORY:-$required_image_repository}"
image_tag="${E_NAVIGATOR_HOMELAB_IMAGE_TAG:-$required_image_tag}"
image_pull_policy="${E_NAVIGATOR_HOMELAB_IMAGE_PULL_POLICY:-IfNotPresent}"
image_pull_secret="${E_NAVIGATOR_HOMELAB_IMAGE_PULL_SECRET:-}"
cleanup_all_requested="${E_NAVIGATOR_HOMELAB_CLEANUP:-0}"
cleanup_workload_requested="${E_NAVIGATOR_HOMELAB_CLEANUP_WORKLOAD:-$cleanup_all_requested}"
uninstall_release_requested="${E_NAVIGATOR_HOMELAB_UNINSTALL_RELEASE:-$cleanup_all_requested}"
workload_wait_timeout="${E_NAVIGATOR_HOMELAB_WORKLOAD_WAIT_TIMEOUT:-300s}"
event_transport="${E_NAVIGATOR_HOMELAB_EVENT_TRANSPORT:-}"
network_io_hook="${E_NAVIGATOR_HOMELAB_NETWORK_IO_HOOK:-}"
disable_json_stdout="${E_NAVIGATOR_HOMELAB_DISABLE_JSON_STDOUT:-0}"
agent_mode="${E_NAVIGATOR_HOMELAB_AGENT_MODE:-enabled}"
workload_template="${E_NAVIGATOR_HOMELAB_WORKLOAD_TEMPLATE:-benchmarks/k8s/workload.yaml}"
config_template="${E_NAVIGATOR_HOMELAB_CONFIG_TEMPLATE:-}"
values_file="${E_NAVIGATOR_HOMELAB_VALUES_FILE:-}"
workload_duration_seconds="${E_NAVIGATOR_HOMELAB_WORKLOAD_DURATION_SECONDS:-120}"

if [ "${E_NAVIGATOR_HOMELAB_CONFIRM:-0}" != "1" ]; then
  cat >&2 <<MSG
refusing to run homelab validation without E_NAVIGATOR_HOMELAB_CONFIRM=1
target context: ${context:-not queried before confirmation}
target namespace: ${namespace}
MSG
  exit 2
fi

if [ "$context" != "$required_context" ]; then
  printf 'target context must be exactly homelab; got: %s\n' "$context" >&2
  exit 2
fi

case "$event_transport" in
  ""|auto|ring_buffer|perf_buffer) ;;
  *)
    printf 'E_NAVIGATOR_HOMELAB_EVENT_TRANSPORT must be auto, ring_buffer, or perf_buffer; got: %s\n' \
      "$event_transport" >&2
    exit 2
    ;;
esac

case "$network_io_hook" in
  ""|auto|fexit|tracepoint) ;;
  *)
    printf 'E_NAVIGATOR_HOMELAB_NETWORK_IO_HOOK must be auto, fexit, or tracepoint; got: %s\n' \
      "$network_io_hook" >&2
    exit 2
    ;;
esac

case "$image_pull_policy" in
  Always|IfNotPresent|Never) ;;
  *)
    printf 'E_NAVIGATOR_HOMELAB_IMAGE_PULL_POLICY must be Always, IfNotPresent, or Never; got: %s\n' \
      "$image_pull_policy" >&2
    exit 2
    ;;
esac

case "$disable_json_stdout" in
  0|1) ;;
  *)
    printf 'E_NAVIGATOR_HOMELAB_DISABLE_JSON_STDOUT must be 0 or 1\n' >&2
    exit 2
    ;;
esac

case "$agent_mode" in
  enabled|none) ;;
  *)
    printf 'E_NAVIGATOR_HOMELAB_AGENT_MODE must be enabled or none\n' >&2
    exit 2
    ;;
esac

if ! kubectl --context "$context" get namespace kube-system >/dev/null 2>&1; then
  printf 'unable to reach the guarded homelab context: %s\n' "$context" >&2
  exit 2
fi

if [ "$namespace" != "$required_namespace" ]; then
  printf 'homelab validation namespace must be exactly e-navigator-bench; got: %s\n' "$namespace" >&2
  exit 2
fi

if [ ! -f "$workload_template" ]; then
  printf 'homelab workload template does not exist: %s\n' "$workload_template" >&2
  exit 2
fi

if [ -n "$config_template" ] && [ ! -f "$config_template" ]; then
  printf 'homelab config template does not exist: %s\n' "$config_template" >&2
  exit 2
fi
if [ -n "$values_file" ] && [ ! -f "$values_file" ]; then
  printf 'homelab values file does not exist: %s\n' "$values_file" >&2
  exit 2
fi

case "$workload_duration_seconds" in
  ""|*[!0-9]*)
    printf 'E_NAVIGATOR_HOMELAB_WORKLOAD_DURATION_SECONDS must be an integer\n' >&2
    exit 2
    ;;
esac
if [ "$workload_duration_seconds" -lt 1 ] || [ "$workload_duration_seconds" -gt 3600 ]; then
  printf 'E_NAVIGATOR_HOMELAB_WORKLOAD_DURATION_SECONDS must be between 1 and 3600\n' >&2
  exit 2
fi
workload_active_deadline_seconds="$((workload_duration_seconds + 120))"

kubectl_cmd=(kubectl --context "$context")

printf 'homelab validation target context: %s\n' "$context"
printf 'homelab validation target namespace: %s\n' "$namespace"
printf 'homelab validation results: %s\n' "$results_dir"
mkdir -p "$results_dir"

log_command() {
  local name="$1"
  shift
  printf '\n==> %s\n' "$name" | tee -a "$results_dir/commands.txt"
  printf '%q ' "$@" | tee -a "$results_dir/commands.txt"
  printf '\n' | tee -a "$results_dir/commands.txt"
}

run_capture() {
  local name="$1"
  shift
  log_command "$name" "$@"
  "$@" >"$results_dir/${name}.txt" 2>&1 || true
}

run_required_capture() {
  local name="$1"
  shift
  log_command "$name" "$@"
  "$@" >"$results_dir/${name}.txt" 2>&1
}

write_runtime_config() {
  local output="$1"

  if [ -n "$config_template" ]; then
    cp "$config_template" "$output"
  else
    awk '
      $0 == "  toml: |" { in_config = 1; next }
      in_config && $0 == "" { print ""; next }
      in_config && substr($0, 1, 4) == "    " { print substr($0, 5); next }
      in_config { exit }
    ' charts/e-navigator/values.yaml >"$output"
  fi

  if [ "${E_NAVIGATOR_HOMELAB_ENABLE_PROMETHEUS_HTTP:-0}" = "1" ]; then
    perl -0pi -e '
      s/(\[prometheus_http\]\nenabled = )false/${1}true/;
      s/(\[\[modules\]\]\nname = "sink\.prometheus_http"\nenabled = )false/${1}true/;
    ' "$output"
  fi

  case "$event_transport" in
    auto) perl -0pi -e 's/event_transport = "[^"]+"/event_transport = "auto"/' "$output" ;;
    ring_buffer) perl -0pi -e 's/event_transport = "[^"]+"/event_transport = "ring_buffer"/' "$output" ;;
    perf_buffer) perl -0pi -e 's/event_transport = "[^"]+"/event_transport = "perf_buffer"/' "$output" ;;
  esac

  case "$network_io_hook" in
    auto) perl -0pi -e 's/network_io_hook = "[^"]+"/network_io_hook = "auto"/' "$output" ;;
    fexit) perl -0pi -e 's/network_io_hook = "[^"]+"/network_io_hook = "fexit"/' "$output" ;;
    tracepoint) perl -0pi -e 's/network_io_hook = "[^"]+"/network_io_hook = "tracepoint"/' "$output" ;;
  esac


  if [ "$disable_json_stdout" = "1" ]; then
    perl -0pi -e '
      s/(\[\[modules\]\]\nname = "sink\.json_stdout"\nenabled = )true/${1}false/;
    ' "$output"
  fi
}

write_run_metadata() {
  local image_substitution="no"
  if [ "$image_repository" != "$required_image_repository" ] || [ "$image_tag" != "$required_image_tag" ]; then
    image_substitution="yes"
  fi

  local pull_secret_configured="no"
  if [ -n "$image_pull_secret" ]; then
    pull_secret_configured="yes"
  fi

  cat >"$results_dir/run-metadata.txt" <<EOF
Context: ${context}
Namespace: ${namespace}
Release: ${release}
Apply mode: ${E_NAVIGATOR_HOMELAB_APPLY:-0}
Required image: ${required_image_repository}:${required_image_tag}
Configured image: ${image_repository}:${image_tag}
Image pull policy: ${image_pull_policy}
Image substitution: ${image_substitution}
Pull secret configured: ${pull_secret_configured}
Prometheus HTTP opt-in: ${E_NAVIGATOR_HOMELAB_ENABLE_PROMETHEUS_HTTP:-0}
Event transport override: ${event_transport:-none}
Network I/O hook override: ${network_io_hook:-none}
JSON stdout disabled: ${disable_json_stdout}
Agent mode: ${agent_mode}
ServiceMonitor opt-in: ${E_NAVIGATOR_HOMELAB_ENABLE_SERVICE_MONITOR:-0}
Prometheus API configured: $([ -n "${E_NAVIGATOR_HOMELAB_PROMETHEUS_URL:-}${E_NAVIGATOR_HOMELAB_PROMETHEUS_SERVICE:-}" ] && printf 'yes' || printf 'no')
Cleanup requested: ${E_NAVIGATOR_HOMELAB_CLEANUP:-0}
Cleanup workload requested: ${cleanup_workload_requested}
Uninstall release requested: ${uninstall_release_requested}
Workload wait timeout: ${workload_wait_timeout}
Workload template: ${workload_template}
Config template: ${config_template:-chart default}
Values file: ${values_file:-chart default}
Workload duration seconds: ${workload_duration_seconds}
EOF
}

workload_name="e-navigator-bench-workload-${timestamp}"
workload_manifest="$results_dir/workload-manifest.yaml"
workload_selector="app.kubernetes.io/name=${workload_name}"

write_workload_manifest() {
  sed \
    -e "s/e-navigator-bench-workload/${workload_name}/g" \
    -e "s/activeDeadlineSeconds: 240/activeDeadlineSeconds: ${workload_active_deadline_seconds}/" \
    -e "s/value: \"120\" # Replaced by the guarded collector./value: \"${workload_duration_seconds}\" # Replaced by the guarded collector./" \
    "$workload_template" >"$workload_manifest"
}

capture_workload_artifacts() {
  run_capture workload-pods "${kubectl_cmd[@]}" -n "$namespace" get pods -l "$workload_selector" -o wide
  run_capture workload-pod-json "${kubectl_cmd[@]}" -n "$namespace" get pods -l "$workload_selector" -o json
  run_capture workload-describe "${kubectl_cmd[@]}" -n "$namespace" describe pods -l "$workload_selector"
  run_capture workload-logs "${kubectl_cmd[@]}" -n "$namespace" logs -l "$workload_selector" --all-containers --tail="${E_NAVIGATOR_HOMELAB_WORKLOAD_LOG_TAIL:-2000}" --prefix
}

top_samples="${E_NAVIGATOR_HOMELAB_TOP_SAMPLES:-10}"
top_interval_seconds="${E_NAVIGATOR_HOMELAB_TOP_INTERVAL_SECONDS:-5}"

capture_top_samples() {
  local output="$results_dir/top-pods-10-samples.txt"
  local node_output="$results_dir/top-nodes-10-samples.txt"
  : >"$output"
  : >"$node_output"
  printf '\n==> top-pods-10-samples\n' | tee -a "$results_dir/commands.txt"
  printf 'kubectl --context %q -n %q top pods --containers # repeated %q times every %q seconds\n' \
    "$context" "$namespace" "$top_samples" "$top_interval_seconds" | tee -a "$results_dir/commands.txt"

  for sample in $(seq 1 "$top_samples"); do
    printf 'sample=%s timestamp=%s\n' "$sample" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >>"$output"
    "${kubectl_cmd[@]}" -n "$namespace" top pods --containers >>"$output" 2>&1 || true
    printf 'sample=%s timestamp=%s\n' "$sample" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >>"$node_output"
    "${kubectl_cmd[@]}" top nodes >>"$node_output" 2>&1 || true
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
  capture_prometheus_http_path prometheus-http-pprof-profile /debug/pprof/profile

  kill "$port_forward_pid" >/dev/null 2>&1 || true
  wait "$port_forward_pid" >/dev/null 2>&1 || true
}

capture_prometheus_pod_endpoints() {
  local local_port="${E_NAVIGATOR_HOMELAB_PROMETHEUS_POD_LOCAL_PORT:-19092}"
  local pod_list="$results_dir/prometheus-http-pod-names.txt"
  "${kubectl_cmd[@]}" -n "$namespace" get pods -l app.kubernetes.io/name=e-navigator \
    -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' >"$pod_list" 2>/dev/null || true

  while IFS= read -r pod; do
    [ -n "$pod" ] || continue
    local port_forward_log="$results_dir/prometheus-http-port-forward-${pod}.txt"
    printf '\n==> prometheus-http-port-forward-%s\n' "$pod" | tee -a "$results_dir/commands.txt"
    printf 'kubectl --context %q -n %q port-forward pod/%q %q:9090\n' \
      "$context" "$namespace" "$pod" "$local_port" | tee -a "$results_dir/commands.txt"
    "${kubectl_cmd[@]}" -n "$namespace" port-forward "pod/${pod}" "${local_port}:9090" \
      >"$port_forward_log" 2>&1 &
    local port_forward_pid="$!"
    sleep 2

    printf '\n==> prometheus-http-metrics-%s\n' "$pod" | tee -a "$results_dir/commands.txt"
    curl -sS -i --max-time 5 "http://127.0.0.1:${local_port}/metrics" \
      >"$results_dir/prometheus-http-metrics-${pod}.txt" 2>&1 || true
    printf '\n==> prometheus-http-pprof-profile-%s\n' "$pod" | tee -a "$results_dir/commands.txt"
    curl -sS --max-time 5 -D "$results_dir/prometheus-http-pprof-profile-${pod}-headers.txt" \
      -o "$results_dir/prometheus-http-pprof-profile-${pod}.pb" \
      "http://127.0.0.1:${local_port}/debug/pprof/profile" || true

    kill "$port_forward_pid" >/dev/null 2>&1 || true
    wait "$port_forward_pid" >/dev/null 2>&1 || true
  done <"$pod_list"
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
- Required image: \`${required_image_repository}:${required_image_tag}\`
- Configured image: \`${image_repository}:${image_tag}\`
- Cleanup requested: \`${E_NAVIGATOR_HOMELAB_CLEANUP:-0}\`
- Cleanup workload requested: \`${cleanup_workload_requested}\`
- Uninstall release requested: \`${uninstall_release_requested}\`
- Workload wait timeout: \`${workload_wait_timeout}\`

This generated summary is an artifact index. It does not upgrade any claim by
itself; inspect the referenced evidence before updating documentation.

## Captured Evidence

- Commands: \`commands.txt\`
- Run metadata: \`run-metadata.txt\`
- Apply/install outputs, when apply mode is enabled: \`namespace-apply.txt\`, \`helm-upgrade-install.txt\`, \`workload-apply.txt\`
- Workload manifest and runtime artifacts: \`workload-manifest.yaml\`, \`workload-wait.txt\`, \`workload-pods.txt\`, \`workload-pod-json.txt\`, \`workload-describe.txt\`, \`workload-logs.txt\`
- Rendered manifest: \`rendered-manifest.txt\`
- Live Helm values: \`helm-values.txt\`
- Live Helm manifest: \`helm-manifest.txt\`
- Namespace: \`namespace.txt\`
- Pods: \`pods.txt\`, \`pod-json.txt\`
- DaemonSet: \`daemonset.txt\`, \`daemonset-yaml.txt\`
- ConfigMap: \`configmap-yaml.txt\`
- Services and endpoints: \`services-endpoints.txt\`
- Prometheus monitor resources: \`monitoring-api-resources.txt\`, \`servicemonitors.txt\`, \`podmonitors.txt\`
- Prometheus runtime config, when enabled: \`prometheus-http-runtime-config.toml\`
- Prometheus HTTP endpoint checks: \`prometheus-http-port-forward.txt\`, \`prometheus-http-healthz.txt\`, \`prometheus-http-readyz.txt\`, \`prometheus-http-metrics.txt\`, or \`prometheus-http-skipped.txt\`
- Per-agent Prometheus/profile checks: \`prometheus-http-pod-names.txt\`, \`prometheus-http-metrics-<pod>.txt\`, \`prometheus-http-pprof-profile-<pod>-headers.txt\`, and \`prometheus-http-pprof-profile-<pod>.pb\`
- Prometheus API checks: \`prometheus-api-targets.txt\`, \`prometheus-api-query-up.txt\`, \`prometheus-api-query-e-navigator.txt\`, \`prometheus-api-series.txt\`, \`prometheus-api-port-forward.txt\`, or \`prometheus-api-skipped.txt\`
- Logs: \`logs.txt\`
- Events: \`events.txt\`
- Resource samples: \`top-pods-10-samples.txt\`, \`top-nodes-10-samples.txt\`
- Capability decode: \`capability-decode.txt\`
- Cleanup outputs, when cleanup is enabled: \`cleanup-workload.txt\`, \`cleanup-helm-uninstall.txt\`
EOF

  cat >"$results_dir/proof-matrix.md" <<EOF
# Proof Matrix: ${timestamp}

| Item | Status | Evidence | Non-claim |
| --- | --- | --- | --- |
| Context | captured | \`current-context.txt\` | no other context validated |
| Namespace | captured | \`namespace.txt\` | no other namespace validated |
| Run metadata | captured | \`run-metadata.txt\` | metadata records configured intent only; image, sink, and cleanup claims require the related runtime artifacts |
| Apply/install commands | captured when apply mode is enabled | \`namespace-apply.txt\`, \`helm-upgrade-install.txt\`, \`workload-apply.txt\` | successful apply does not prove runtime behavior without rollout, logs, and endpoint evidence |
| Controlled workload | captured when apply mode is enabled | \`workload-manifest.yaml\`, \`workload-apply.txt\`, \`workload-wait.txt\`, \`workload-pods.txt\`, \`workload-pod-json.txt\`, \`workload-describe.txt\`, \`workload-logs.txt\`, \`events.txt\`, \`logs.txt\` | workload completion and workload logs do not prove E-Navigator attribution unless collector logs contain matching workload context |
| Rendered manifest | captured | \`rendered-manifest.txt\`, \`helm-manifest.txt\`, \`helm-values.txt\` | render does not prove runtime behavior |
| DaemonSet rollout | captured | \`rollout.txt\`, \`daemonset-yaml.txt\` | no production soak |
| JSON logs | captured | \`logs.txt\` | logs must be inspected before claiming source/generator proof |
| Services/endpoints | captured | \`services-endpoints.txt\`, \`servicemonitors.txt\`, \`podmonitors.txt\` | no Prometheus proof unless HTTP 200 and scrape evidence are present |
| Prometheus runtime config | captured when enabled | \`prometheus-http-runtime-config.toml\` | config enablement does not prove scrape or queryability |
| Prometheus HTTP endpoints | captured when Service exists | \`prometheus-http-healthz.txt\`, \`prometheus-http-readyz.txt\`, \`prometheus-http-metrics.txt\`, \`prometheus-http-port-forward.txt\`, or \`prometheus-http-skipped.txt\` | endpoint captures alone do not prove Prometheus active target or queryability |
| Prometheus API queries | captured when configured | \`prometheus-api-targets.txt\`, \`prometheus-api-query-up.txt\`, \`prometheus-api-query-e-navigator.txt\`, \`prometheus-api-series.txt\`, \`prometheus-api-port-forward.txt\`, or \`prometheus-api-skipped.txt\` | empty query results are negative or inconclusive, not success |
| Resource overhead | captured | \`top-pods-10-samples.txt\`, \`top-nodes-10-samples.txt\` | no reduced-overhead claim without a comparable baseline |
| Capabilities | captured | \`capability-decode.txt\` | no reduced-privilege claim if CAP_SYS_ADMIN remains or seccomp is disabled |
| Cleanup | captured when enabled | \`cleanup-workload.txt\`, \`cleanup-helm-uninstall.txt\` | no cleanup occurred unless cleanup artifacts or commands prove it |
EOF
}

render_args=(--namespace "$namespace" --set namespace.create=false --set namespace.name="$namespace")
if [ -n "$values_file" ]; then
  render_args+=(--values "$values_file")
fi
write_run_metadata
write_workload_manifest

if [ "${E_NAVIGATOR_HOMELAB_APPLY:-0}" = "1" ] && [ "$agent_mode" = "enabled" ]; then
  helm_args=(
    --set namespace.create=false
    --set namespace.name="$namespace"
    --set image.repository="$image_repository"
    --set image.tag="$image_tag"
    --set image.pullPolicy="$image_pull_policy"
    --set resources.requests.cpu=50m
    --set resources.requests.memory=128Mi
    --set resources.limits.memory=512Mi
  )
  if [ -n "$values_file" ]; then
    helm_args+=(--values "$values_file")
  fi
  if [ -n "$image_pull_secret" ]; then
    helm_args+=(--set "imagePullSecrets[0].name=$image_pull_secret")
  fi

  if [ "${E_NAVIGATOR_HOMELAB_ENABLE_PROMETHEUS_HTTP:-0}" = "1" ] || \
    [ -n "$config_template" ] || [ -n "$event_transport" ] || \
    [ -n "$network_io_hook" ] || \
    [ "$disable_json_stdout" = "1" ]; then
    runtime_config="$results_dir/runtime-config.toml"
    write_runtime_config "$runtime_config"
    cp "$runtime_config" "$results_dir/prometheus-http-runtime-config.toml"
    helm_args+=(--set-file "config.toml=$runtime_config")
  fi

  if [ "${E_NAVIGATOR_HOMELAB_ENABLE_PROMETHEUS_HTTP:-0}" = "1" ]; then
    helm_args+=(
      --set prometheusHttp.enabled=true
      --set health.enabled=true
      --set service.enabled=true
    )

    if [ "${E_NAVIGATOR_HOMELAB_ENABLE_SERVICE_MONITOR:-0}" = "1" ]; then
      helm_args+=(--set serviceMonitor.enabled=true)
    fi
  fi
  render_args+=("${helm_args[@]}")

  run_required_capture namespace-apply bash -c \
    'kubectl --context "$1" create namespace "$2" --dry-run=client -o yaml | kubectl --context "$1" apply -f -' \
    _ "$context" "$namespace"
  run_required_capture helm-upgrade-install helm --kube-context "$context" upgrade --install "$release" charts/e-navigator \
    --namespace "$namespace" "${helm_args[@]}"
fi

if [ "${E_NAVIGATOR_HOMELAB_APPLY:-0}" = "1" ] && [ "$agent_mode" = "none" ]; then
  run_required_capture namespace-apply bash -c \
    'kubectl --context "$1" create namespace "$2" --dry-run=client -o yaml | kubectl --context "$1" apply -f -' \
    _ "$context" "$namespace"
fi

run_capture current-context bash -c 'printf "%s\n" "$1"' _ "$context"
run_capture rendered-manifest helm --kube-context "$context" template "$release" charts/e-navigator "${render_args[@]}"
run_capture helm-values helm --kube-context "$context" get values "$release" --namespace "$namespace" --all
run_capture helm-manifest helm --kube-context "$context" get manifest "$release" --namespace "$namespace"
run_capture namespace "${kubectl_cmd[@]}" get namespace "$namespace" -o yaml
if [ "$agent_mode" = "enabled" ]; then
  run_capture rollout "${kubectl_cmd[@]}" -n "$namespace" rollout status "daemonset/${release}" --timeout="${E_NAVIGATOR_HOMELAB_ROLLOUT_TIMEOUT:-120s}"
else
  printf 'agent rollout skipped for no-agent baseline\n' >"$results_dir/rollout.txt"
fi
if [ "${E_NAVIGATOR_HOMELAB_APPLY:-0}" = "1" ]; then
  run_required_capture workload-apply "${kubectl_cmd[@]}" -n "$namespace" apply -f "$workload_manifest"
  capture_top_samples &
  top_capture_pid="$!"
  run_capture workload-wait "${kubectl_cmd[@]}" -n "$namespace" wait --for=condition=complete "job/${workload_name}" --timeout="$workload_wait_timeout"
  capture_workload_artifacts
  wait "$top_capture_pid"
fi
run_capture pods "${kubectl_cmd[@]}" -n "$namespace" get pods -o wide
run_capture daemonset "${kubectl_cmd[@]}" -n "$namespace" get daemonset -o wide
run_capture daemonset-yaml "${kubectl_cmd[@]}" -n "$namespace" get daemonset "$release" -o yaml
run_capture configmap-yaml "${kubectl_cmd[@]}" -n "$namespace" get configmap "${release}-config" -o yaml
capture_service_surfaces
capture_prometheus_http_endpoints
capture_prometheus_pod_endpoints
capture_prometheus_api_queries
run_capture pod-json "${kubectl_cmd[@]}" -n "$namespace" get pods -o json
run_capture logs "${kubectl_cmd[@]}" -n "$namespace" logs -l app.kubernetes.io/name=e-navigator --all-containers --tail="${E_NAVIGATOR_HOMELAB_LOG_TAIL:-2000}" --prefix
run_capture events "${kubectl_cmd[@]}" -n "$namespace" get events --sort-by=.lastTimestamp
if [ "${E_NAVIGATOR_HOMELAB_APPLY:-0}" != "1" ]; then
  capture_top_samples
fi
capture_capabilities
write_summary_files

if [ "$cleanup_workload_requested" = "1" ]; then
  printf 'running workload cleanup in %s\n' "$namespace"
  run_capture cleanup-workload "${kubectl_cmd[@]}" -n "$namespace" delete -f "$workload_manifest" --ignore-not-found=true
fi

if [ "$uninstall_release_requested" = "1" ] && [ "$agent_mode" = "enabled" ]; then
  printf 'uninstalling Helm release %s in %s\n' "$release" "$namespace"
  run_capture cleanup-helm-uninstall helm --kube-context "$context" uninstall "$release" --namespace "$namespace"
fi

printf 'homelab collection complete: %s\n' "$results_dir"
