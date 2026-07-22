#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

context="${E_NAVIGATOR_HOMELAB_CONTEXT:-homelab}"
namespace="${E_NAVIGATOR_HOMELAB_NAMESPACE:-e-navigator-bench}"
results_root="${E_NAVIGATOR_HEAD_TO_HEAD_RESULTS_DIR:-benchmarks/results/head-to-head-proof}"
repetitions="${E_NAVIGATOR_HEAD_TO_HEAD_REPETITIONS:-3}"
warmup_seconds="${E_NAVIGATOR_HEAD_TO_HEAD_WARMUP_SECONDS:-15}"
duration_seconds="${E_NAVIGATOR_HEAD_TO_HEAD_DURATION_SECONDS:-45}"
attach_settle_seconds="${E_NAVIGATOR_HEAD_TO_HEAD_ATTACH_SETTLE_SECONDS:-20}"
resume="${E_NAVIGATOR_HEAD_TO_HEAD_RESUME:-0}"
e_navigator_image_repository="${E_NAVIGATOR_HOMELAB_IMAGE_REPOSITORY:-docker.io/library/e-navigator}"
e_navigator_image_tag="${E_NAVIGATOR_HOMELAB_IMAGE_TAG:-gap9-head-to-head-amd64}"
workload_image="${E_NAVIGATOR_HEAD_TO_HEAD_WORKLOAD_IMAGE:-docker.io/library/e-navigator-head-to-head:gap9-amd64}"
beyla_chart_version="1.16.10"
beyla_chart_sha256="f404a525451c1b36ab0a8a98560e20fc4af70f59016518d414ce5fed367855e2"
beyla_release="head-to-head-beyla"
e_navigator_release="head-to-head-enav"
standing_app="e-navigator"
standing_namespace="e-navigator-system"
standing_daemonset="e-navigator-agent"
prometheus_local_port="${E_NAVIGATOR_HEAD_TO_HEAD_PROMETHEUS_PORT:-29090}"
sink_local_port="${E_NAVIGATOR_HEAD_TO_HEAD_SINK_PORT:-24318}"
prometheus_pid=""
sink_pid=""
standing_suspended=0
workload_applied=0

if [ "${E_NAVIGATOR_HOMELAB_CONFIRM:-0}" != "1" ]; then
  printf 'refusing head-to-head proof without E_NAVIGATOR_HOMELAB_CONFIRM=1\n' >&2
  exit 2
fi
if [ "$context" != "homelab" ] || [ "$namespace" != "e-navigator-bench" ]; then
  printf 'head-to-head proof target must be exactly homelab/e-navigator-bench\n' >&2
  exit 2
fi
for numeric in "$repetitions" "$warmup_seconds" "$duration_seconds" "$attach_settle_seconds"; do
  case "$numeric" in
    ""|*[!0-9]*)
      printf 'head-to-head repetitions and durations must be integers\n' >&2
      exit 2
      ;;
  esac
done
if [ "$repetitions" -ne 3 ]; then
  printf 'head-to-head proof requires exactly three repetitions\n' >&2
  exit 2
fi
if [ "$warmup_seconds" -lt 5 ] || [ "$warmup_seconds" -gt 120 ]; then
  printf 'head-to-head warmup must be between 5 and 120 seconds\n' >&2
  exit 2
fi
if [ "$duration_seconds" -lt 20 ] || [ "$duration_seconds" -gt 300 ]; then
  printf 'head-to-head duration must be between 20 and 300 seconds\n' >&2
  exit 2
fi
if [ "$attach_settle_seconds" -lt 5 ] || [ "$attach_settle_seconds" -gt 120 ]; then
  printf 'head-to-head attach settling must be between 5 and 120 seconds\n' >&2
  exit 2
fi
if [ "$resume" != "0" ] && [ "$resume" != "1" ]; then
  printf 'E_NAVIGATOR_HEAD_TO_HEAD_RESUME must be 0 or 1\n' >&2
  exit 2
fi
case "$e_navigator_image_repository:$e_navigator_image_tag:$workload_image" in
  *[!A-Za-z0-9._/:@-]*)
    printf 'head-to-head image reference contains unsupported characters\n' >&2
    exit 2
    ;;
esac

mkdir -p "$results_root"

stop_port_forwards() {
  if [ -n "$prometheus_pid" ]; then
    kill "$prometheus_pid" 2>/dev/null
    wait "$prometheus_pid" 2>/dev/null
    prometheus_pid=""
  fi
  if [ -n "$sink_pid" ]; then
    kill "$sink_pid" 2>/dev/null
    wait "$sink_pid" 2>/dev/null
    sink_pid=""
  fi
}

cleanup_collectors() {
  helm --kube-context "$context" uninstall "$e_navigator_release" --namespace "$namespace" \
    >/dev/null 2>&1 || true
  helm --kube-context "$context" uninstall "$beyla_release" --namespace "$namespace" \
    >/dev/null 2>&1 || true
  kubectl --context "$context" delete -f benchmarks/k8s/head-to-head-alloy.yaml \
    --ignore-not-found=true >/dev/null 2>&1 || true
  kubectl --context "$context" -n "$namespace" delete pods \
    -l e-navigator.dev/collector --ignore-not-found=true --wait=true >/dev/null 2>&1 || true
}

restore_environment() {
  local status="$?"
  local restore_status=0
  local restore_patch
  set +e
  stop_port_forwards
  cleanup_collectors
  kubectl --context "$context" -n "$namespace" delete jobs \
    -l app.kubernetes.io/part-of=e-navigator-head-to-head \
    --ignore-not-found=true --wait=true \
    >"$results_root/final-job-cleanup.txt" 2>&1 || restore_status=1
  if [ "$workload_applied" = "1" ]; then
    kubectl --context "$context" delete -f "$results_root/rendered-workload.yaml" \
      --ignore-not-found=true --wait=true \
      >"$results_root/final-workload-cleanup.txt" 2>&1 || restore_status=1
  fi
  if [ "$standing_suspended" = "1" ]; then
    restore_patch="$(jq -c '{spec:{syncPolicy:{automated:.spec.syncPolicy.automated}}}' \
      "$results_root/pre-argocd-application.json")"
    kubectl --context "$context" -n argocd patch application "$standing_app" \
      --type=merge -p "$restore_patch" \
      >"$results_root/restore-argocd-automation.txt" 2>&1 || restore_status=1
    for _attempt in $(seq 1 60); do
      if kubectl --context "$context" -n "$standing_namespace" get daemonset \
        "$standing_daemonset" >/dev/null 2>&1; then
        break
      fi
      sleep 2
    done
    kubectl --context "$context" -n "$standing_namespace" rollout status \
      "daemonset/$standing_daemonset" --timeout=180s \
      >"$results_root/restore-standing-daemonset.txt" 2>&1 || restore_status=1
    for _attempt in $(seq 1 60); do
      kubectl --context "$context" -n argocd get application "$standing_app" -o json \
        >"$results_root/post-argocd-application.json" 2>&1 || true
      if [ "$(jq -r '.status.sync.status // ""' "$results_root/post-argocd-application.json" 2>/dev/null)" = "Synced" ] &&
        [ "$(jq -r '.status.health.status // ""' "$results_root/post-argocd-application.json" 2>/dev/null)" = "Healthy" ]; then
        break
      fi
      sleep 2
    done
    kubectl --context "$context" -n "$standing_namespace" get daemonset \
      "$standing_daemonset" -o json >"$results_root/post-standing-daemonset.json" 2>&1 || restore_status=1
    if [ "$restore_status" -eq 0 ] && {
      [ "$(jq -r '.spec.syncPolicy.automated.prune' "$results_root/post-argocd-application.json")" != "true" ] ||
      [ "$(jq -r '.spec.syncPolicy.automated.selfHeal' "$results_root/post-argocd-application.json")" != "true" ] ||
      [ "$(jq -r '.status.sync.status' "$results_root/post-argocd-application.json")" != "Synced" ] ||
      [ "$(jq -r '.status.health.status' "$results_root/post-argocd-application.json")" != "Healthy" ];
    }; then
      restore_status=1
    fi
  fi
  for _attempt in $(seq 1 120); do
    if [ -z "$(kubectl --context "$context" -n "$namespace" get pods \
      -l e-navigator.dev/disposable=true -o name 2>/dev/null)" ]; then
      break
    fi
    sleep 1
  done
  kubectl --context "$context" -n "$namespace" get all,configmap,serviceaccount,role,rolebinding \
    -l e-navigator.dev/disposable=true -o name \
    >"$results_root/post-cleanup-namespaced-resources.txt" 2>&1 || restore_status=1
  kubectl --context "$context" get clusterrole,clusterrolebinding \
    -l app.kubernetes.io/part-of=e-navigator-head-to-head -o name \
    >"$results_root/post-cleanup-cluster-resources.txt" 2>&1 || restore_status=1
  if [ -s "$results_root/post-cleanup-namespaced-resources.txt" ] ||
    [ -s "$results_root/post-cleanup-cluster-resources.txt" ]; then
    restore_status=1
  fi
  if [ "$status" -ne 0 ]; then
    return "$status"
  fi
  return "$restore_status"
}
trap restore_environment EXIT INT TERM

wait_for_http() {
  local url="$1"
  for _attempt in $(seq 1 60); do
    if curl --silent --show-error --fail --max-time 2 "$url" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  printf 'HTTP endpoint did not become ready: %s\n' "$url" >&2
  return 1
}

start_port_forwards() {
  kubectl --context "$context" -n observability-system port-forward \
    service/kube-prometheus-stack-prometheus \
    "$prometheus_local_port:9090" \
    >"$results_root/prometheus-port-forward.txt" 2>&1 &
  prometheus_pid="$!"
  wait_for_http "http://127.0.0.1:$prometheus_local_port/-/ready"

  kubectl --context "$context" -n "$namespace" port-forward \
    service/head-to-head-otlp-sink "$sink_local_port:4318" \
    >"$results_root/sink-port-forward.txt" 2>&1 &
  sink_pid="$!"
  wait_for_http "http://127.0.0.1:$sink_local_port/health"
}

capture_pod_endpoint() {
  local selector="$1"
  local remote_port="$2"
  local path="$3"
  local output="$4"
  local local_port=29092
  local pod
  local endpoint_pid
  pod="$(kubectl --context "$context" -n "$namespace" get pods -l "$selector" \
    --field-selector=status.phase=Running -o jsonpath='{.items[0].metadata.name}')"
  if [ -z "$pod" ]; then
    printf 'no running pod matched endpoint selector: %s\n' "$selector" >&2
    return 1
  fi
  kubectl --context "$context" -n "$namespace" port-forward "pod/$pod" \
    "$local_port:$remote_port" >"${output}.port-forward.txt" 2>&1 &
  endpoint_pid="$!"
  if ! wait_for_http "http://127.0.0.1:$local_port$path"; then
    kill "$endpoint_pid" 2>/dev/null || true
    wait "$endpoint_pid" 2>/dev/null || true
    return 1
  fi
  curl --silent --show-error --fail --max-time 10 \
    "http://127.0.0.1:$local_port$path" >"$output"
  kill "$endpoint_pid" 2>/dev/null || true
  wait "$endpoint_pid" 2>/dev/null || true
}

prometheus_query_range() {
  local query="$1"
  local start="$2"
  local end="$3"
  local output="$4"
  curl --silent --show-error --fail --get \
    "http://127.0.0.1:$prometheus_local_port/api/v1/query_range" \
    --data-urlencode "query=$query" \
    --data-urlencode "start=$start" \
    --data-urlencode "end=$end" \
    --data-urlencode 'step=15' >"$output"
}

wait_for_collector_absence() {
  for _attempt in $(seq 1 120); do
    if [ -z "$(kubectl --context "$context" -n "$namespace" get pods \
      -l e-navigator.dev/collector -o name 2>/dev/null || true)" ]; then
      return 0
    fi
    sleep 1
  done
  printf 'head-to-head collector pods did not terminate\n' >&2
  return 1
}

deploy_collector() {
  local collector="$1"
  local stage="$2"
  local run_dir="$3"
  local daemonset
  cleanup_collectors
  wait_for_collector_absence
  if [ "$collector" = "none" ]; then
    return
  fi
  if [ "$collector" = "beyla" ]; then
    python3 benchmarks/runner/analyze-head-to-head.py render-beyla "$stage" \
      >"$run_dir/beyla-values.json"
    helm --kube-context "$context" upgrade --install "$beyla_release" \
      "$results_root/inputs/beyla-${beyla_chart_version}.tgz" \
      --namespace "$namespace" --values "$run_dir/beyla-values.json" \
      >"$run_dir/collector-install.txt"
    daemonset="$(kubectl --context "$context" -n "$namespace" get daemonset \
      -l app.kubernetes.io/instance="$beyla_release" -o jsonpath='{.items[0].metadata.name}')"
    kubectl --context "$context" -n "$namespace" rollout status \
      "daemonset/$daemonset" --timeout=180s >"$run_dir/beyla-rollout.txt"
    if [ "$stage" = "profile" ]; then
      kubectl --context "$context" apply -f benchmarks/k8s/head-to-head-alloy.yaml \
        >"$run_dir/alloy-apply.txt"
      kubectl --context "$context" -n "$namespace" rollout status \
        daemonset/head-to-head-alloy --timeout=180s >"$run_dir/alloy-rollout.txt"
    fi
  else
    helm --kube-context "$context" upgrade --install "$e_navigator_release" \
      charts/e-navigator --namespace "$namespace" \
      --values benchmarks/config/head-to-head-e-navigator-values.yaml \
      --set-file "config.toml=benchmarks/config/head-to-head-${stage}.toml" \
      --set-string "image.repository=$e_navigator_image_repository" \
      --set-string "image.tag=$e_navigator_image_tag" \
      --set-string 'image.digest=' \
      --set-string 'image.pullPolicy=Never' \
      >"$run_dir/collector-install.txt"
    kubectl --context "$context" -n "$namespace" rollout status \
      daemonset/head-to-head-enav --timeout=180s >"$run_dir/e-navigator-rollout.txt"
  fi
  sleep "$attach_settle_seconds"
}

capture_collector_metrics() {
  local collector="$1"
  local stage="$2"
  local when="$3"
  local run_dir="$4"
  if [ "$collector" = "beyla" ]; then
    capture_pod_endpoint 'e-navigator.dev/collector=beyla' 9090 /metrics \
      "$run_dir/collector-app-${when}.prom"
    capture_pod_endpoint 'e-navigator.dev/collector=beyla' 9090 /internal/metrics \
      "$run_dir/collector-internal-${when}.prom"
    if [ "$stage" = "profile" ]; then
      capture_pod_endpoint 'e-navigator.dev/collector=alloy' 12345 /metrics \
        "$run_dir/alloy-${when}.prom"
    fi
  elif [ "$collector" = "e-navigator" ]; then
    capture_pod_endpoint 'e-navigator.dev/collector=e-navigator' 9090 /metrics \
      "$run_dir/collector-app-${when}.prom"
  fi
}

capture_collector_logs() {
  local collector="$1"
  local run_dir="$2"
  if [ "$collector" = "none" ]; then
    printf 'no collector\n' >"$run_dir/collector.log"
    return
  fi
  kubectl --context "$context" -n "$namespace" logs \
    -l e-navigator.dev/collector --all-containers=true --prefix=true --tail=-1 \
    >"$run_dir/collector.log" 2>&1
}

capture_resource_queries() {
  local collector="$1"
  local stage="$2"
  local run_dir="$3"
  local start
  local end
  local pod_regex
  start="$(jq -r '(.measured.started_unix_nanos / 1000000000 | floor) + 15' \
    "$run_dir/workload-result.json")"
  end="$(jq -r '(.measured.finished_unix_nanos / 1000000000 | floor)' \
    "$run_dir/workload-result.json")"
  prometheus_query_range \
    'sum by (node) (rate(container_cpu_usage_seconds_total{container!="",pod!=""}[60s]))' \
    "$start" "$end" "$run_dir/prom-node-cpu.json"
  prometheus_query_range \
    'sum by (node) (container_memory_working_set_bytes{container!="",pod!=""})' \
    "$start" "$end" "$run_dir/prom-node-memory.json"
  if [ "$collector" = "none" ]; then
    pod_regex='a^'
  elif [ "$collector" = "beyla" ] && [ "$stage" = "profile" ]; then
    pod_regex='head-to-head-(beyla|alloy).*'
  elif [ "$collector" = "beyla" ]; then
    pod_regex='head-to-head-beyla.*'
  else
    pod_regex='head-to-head-enav.*'
  fi
  prometheus_query_range \
    "sum(rate(container_cpu_usage_seconds_total{namespace=\"$namespace\",pod=~\"$pod_regex\",container!=\"\"}[60s]))" \
    "$start" "$end" "$run_dir/prom-agent-cpu.json"
  prometheus_query_range \
    "sum(container_memory_rss{namespace=\"$namespace\",pod=~\"$pod_regex\",container!=\"\"})" \
    "$start" "$end" "$run_dir/prom-agent-rss.json"
}

run_arm() {
  local collector="$1"
  local stage="$2"
  local repetition="$3"
  local condition
  local run_name
  local run_dir
  local job_name
  if [ "$collector" = "none" ]; then
    condition="none"
    run_name="none-r${repetition}"
  else
    condition="${collector}-${stage}"
    run_name="${condition}-r${repetition}"
  fi
  run_dir="$results_root/$run_name"
  if [ "$resume" = "1" ] && [ -s "$run_dir/validated.json" ]; then
    capture_resource_queries "$collector" "$stage" "$run_dir"
    python3 benchmarks/runner/analyze-head-to-head.py validate-run "$run_dir" \
      >"$run_dir/validated.rechecked.json"
    mv "$run_dir/validated.rechecked.json" "$run_dir/validated.json"
    if ! grep -Fq " $run_name" "$results_root/validated-run-order.log" 2>/dev/null; then
      printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$run_name" \
        >>"$results_root/validated-run-order.log"
    fi
    printf 'reused validated head-to-head arm: %s\n' "$run_name"
    return
  fi
  if [ -d "$run_dir" ]; then
    if [ "$resume" != "1" ]; then
      printf 'head-to-head run already exists, use resume or a new result root: %s\n' \
        "$run_dir" >&2
      return 1
    fi
    find "$run_dir" -mindepth 1 -delete
  fi
  mkdir -p "$run_dir"

  printf 'starting head-to-head arm %s\n' "$run_name"
  printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$run_name" \
    >>"$results_root/run-order.log"
  deploy_collector "$collector" "$stage" "$run_dir"
  kubectl --context "$context" -n "$namespace" get pods -o json \
    >"$run_dir/pods-before.json"
  capture_collector_metrics "$collector" "$stage" before "$run_dir"
  curl --silent --show-error --fail --request POST \
    "http://127.0.0.1:$sink_local_port/reset" >"$run_dir/otlp-sink-reset.json"

  job_name="h2h-${condition//e-navigator/enav}-r${repetition}"
  kubectl --context "$context" -n "$namespace" create job "$job_name" \
    --from=cronjob/head-to-head-load-template --dry-run=client -o json \
    >"$run_dir/job-base.json"
  jq --arg condition "$condition" --arg repetition "$repetition" \
    --arg warmup "$warmup_seconds" --arg duration "$duration_seconds" '
      .metadata.labels["app.kubernetes.io/part-of"] = "e-navigator-head-to-head" |
      .metadata.labels["e-navigator.dev/disposable"] = "true" |
      .spec.template.metadata.labels["e-navigator.dev/condition"] = $condition |
      .spec.template.spec.containers[0].env |= (
        map(select(.name != "HEAD2HEAD_CONDITION" and
          .name != "HEAD2HEAD_REPETITION" and
          .name != "HEAD2HEAD_WARMUP_SECONDS" and
          .name != "HEAD2HEAD_DURATION_SECONDS")) + [
          {"name":"HEAD2HEAD_CONDITION","value":$condition},
          {"name":"HEAD2HEAD_REPETITION","value":$repetition},
          {"name":"HEAD2HEAD_WARMUP_SECONDS","value":$warmup},
          {"name":"HEAD2HEAD_DURATION_SECONDS","value":$duration}
        ]
      )
    ' "$run_dir/job-base.json" >"$run_dir/job.json"
  kubectl --context "$context" apply -f "$run_dir/job.json" >"$run_dir/job-apply.txt"
  kubectl --context "$context" -n "$namespace" wait --for=condition=complete \
    "job/$job_name" --timeout="$((warmup_seconds + duration_seconds + 180))s" \
    >"$run_dir/job-wait.txt"
  kubectl --context "$context" -n "$namespace" logs "job/$job_name" \
    >"$run_dir/workload.log"
  sed -n 's/^.*HEAD2HEAD_RESULT //p' "$run_dir/workload.log" \
    >"$run_dir/workload-result.json"
  if [ "$(wc -l <"$run_dir/workload-result.json" | tr -d ' ')" -ne 1 ]; then
    printf 'head-to-head arm did not emit exactly one result: %s\n' "$run_name" >&2
    return 1
  fi

  sleep 5
  capture_collector_metrics "$collector" "$stage" after "$run_dir"
  curl --silent --show-error --fail \
    "http://127.0.0.1:$sink_local_port/stats" >"$run_dir/otlp-sink-after.json"
  capture_resource_queries "$collector" "$stage" "$run_dir"
  kubectl --context "$context" top nodes >"$run_dir/top-nodes.txt"
  kubectl --context "$context" -n "$namespace" top pods --containers \
    >"$run_dir/top-pods.txt" 2>&1 || true
  kubectl --context "$context" -n "$namespace" get pods -o json \
    >"$run_dir/pods-after.json"
  kubectl --context "$context" -n "$namespace" get events --sort-by=.lastTimestamp \
    >"$run_dir/events.txt"
  capture_collector_logs "$collector" "$run_dir"
  python3 benchmarks/runner/analyze-head-to-head.py validate-run "$run_dir" \
    >"$run_dir/validated.json"
  printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$run_name" \
    >>"$results_root/validated-run-order.log"

  kubectl --context "$context" -n "$namespace" delete job "$job_name" --wait=true \
    >"$run_dir/job-cleanup.txt"
  cleanup_collectors
  wait_for_collector_absence
  sleep 5
}

kubectl --context "$context" get namespace kube-system >/dev/null
kubectl --context "$context" -n argocd get application "$standing_app" -o json \
  >"$results_root/pre-argocd-application.json"
kubectl --context "$context" -n "$standing_namespace" get daemonset "$standing_daemonset" -o json \
  >"$results_root/pre-standing-daemonset.json"
kubectl --context "$context" -n "$standing_namespace" get pods -o wide \
  >"$results_root/pre-standing-pods.txt"
kubectl --context "$context" get nodes -o json >"$results_root/nodes.json"
kubectl --context "$context" version -o json >"$results_root/kubernetes-version.json"
git rev-parse HEAD >"$results_root/git-revision.txt"
git status --short >"$results_root/git-status.txt"
kubectl version --client -o json >"$results_root/kubectl-client-version.json"
helm version --short >"$results_root/helm-version.txt"
python3 --version >"$results_root/python-version.txt" 2>&1
shasum -a 256 benchmarks/config/head-to-head-*.toml \
  benchmarks/config/head-to-head-e-navigator-values.yaml \
  benchmarks/k8s/head-to-head-alloy.yaml \
  benchmarks/k8s/head-to-head-workload.yaml \
  benchmarks/runner/analyze-head-to-head.py \
  benchmarks/runner/homelab-head-to-head.sh \
  benchmarks/workloads/head-to-head/Dockerfile \
  benchmarks/workloads/head-to-head/head_to_head.py \
  benchmarks/workloads/head-to-head/requirements.txt >"$results_root/input-sha256.txt"

if [ "$(jq -r '.spec.syncPolicy.automated.prune' "$results_root/pre-argocd-application.json")" != "true" ] ||
  [ "$(jq -r '.spec.syncPolicy.automated.selfHeal' "$results_root/pre-argocd-application.json")" != "true" ]; then
  printf 'standing Argo CD automation is not the expected prune+selfHeal posture\n' >&2
  exit 2
fi
if [ -n "$(kubectl --context "$context" -n "$namespace" get all \
  -l app.kubernetes.io/part-of=e-navigator-head-to-head -o name)" ]; then
  printf 'head-to-head resources already exist in benchmark namespace\n' >&2
  exit 2
fi

kubectl --context "$context" -n argocd patch application "$standing_app" --type=json \
  -p='[{"op":"remove","path":"/spec/syncPolicy/automated"}]' \
  >"$results_root/suspend-argocd-automation.txt"
standing_suspended=1
kubectl --context "$context" -n "$standing_namespace" delete daemonset "$standing_daemonset" \
  --wait=true >"$results_root/suspend-standing-daemonset.txt"

mkdir -p "$results_root/inputs"
if [ ! -s "$results_root/inputs/beyla-${beyla_chart_version}.tgz" ]; then
  helm pull grafana/beyla --version "$beyla_chart_version" \
    --destination "$results_root/inputs"
fi
shasum -a 256 "$results_root/inputs/beyla-${beyla_chart_version}.tgz" \
  >"$results_root/inputs/beyla-chart.sha256"
if [ "$(awk '{print $1}' "$results_root/inputs/beyla-chart.sha256")" != "$beyla_chart_sha256" ]; then
  printf 'Beyla chart checksum did not match the pinned input\n' >&2
  exit 2
fi

default_workload_image='docker.io/library/e-navigator-head-to-head:gap9-amd64'
sed "s|$default_workload_image|$workload_image|g" \
  benchmarks/k8s/head-to-head-workload.yaml >"$results_root/rendered-workload.yaml"
kubeconform -strict -summary "$results_root/rendered-workload.yaml" \
  >"$results_root/workload-kubeconform.txt"
workload_applied=1
kubectl --context "$context" apply -f "$results_root/rendered-workload.yaml" \
  >"$results_root/workload-apply.txt"
kubectl --context "$context" -n "$namespace" wait --for=condition=available \
  deployment -l app.kubernetes.io/part-of=e-navigator-head-to-head \
  --timeout=300s >"$results_root/workload-wait.txt"
kubectl --context "$context" -n "$namespace" get pods -o wide \
  >"$results_root/workload-pods.txt"
kubectl --context "$context" -n "$namespace" get pods -o json \
  >"$results_root/workload-pods.json"

start_port_forwards
curl --silent --show-error --fail \
  "http://127.0.0.1:$sink_local_port/stats" >"$results_root/initial-otlp-sink.json"

run_arm none none 1
run_arm beyla http 1
run_arm e-navigator http 1
run_arm e-navigator grpc 1
run_arm beyla grpc 1
run_arm beyla redis 1
run_arm e-navigator redis 1
run_arm e-navigator postgres 1
run_arm beyla postgres 1
run_arm beyla profile 1
run_arm e-navigator profile 1

run_arm e-navigator profile 2
run_arm beyla profile 2
run_arm beyla postgres 2
run_arm e-navigator postgres 2
run_arm e-navigator redis 2
run_arm beyla redis 2
run_arm beyla grpc 2
run_arm e-navigator grpc 2
run_arm e-navigator http 2
run_arm beyla http 2
run_arm none none 2

run_arm beyla postgres 3
run_arm e-navigator postgres 3
run_arm beyla http 3
run_arm e-navigator http 3
run_arm none none 3
run_arm e-navigator profile 3
run_arm beyla profile 3
run_arm e-navigator redis 3
run_arm beyla redis 3
run_arm e-navigator grpc 3
run_arm beyla grpc 3

python3 benchmarks/runner/analyze-head-to-head.py aggregate "$results_root" \
  >"$results_root/analysis.json"
jq -r '
  "PASS: 33 matched runs; final E-Navigator vs Beyla+Alloy CPU " +
  (.final_stack_comparison.e_navigator_agent_cpu_change_vs_beyla_alloy_percent | tostring) +
  "% and RSS " +
  (.final_stack_comparison.e_navigator_agent_rss_change_vs_beyla_alloy_percent | tostring) + "%"
' "$results_root/analysis.json" | tee "$results_root/summary.txt"

trap - EXIT INT TERM
restore_environment
