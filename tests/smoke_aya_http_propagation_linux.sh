#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
image="${E_NAVIGATOR_IMAGE:-e-navigator:local}"
python_image="${E_NAVIGATOR_PYTHON_IMAGE:-python:3.13-slim-bookworm}"
agent_name="e-navigator-http-propagation-$RANDOM-$$"
work_dir="$(mktemp -d)"
agent_log="$work_dir/agent.log"

cleanup() {
  docker rm -f "$agent_name" >/dev/null 2>&1 || true
  rm -rf "$work_dir"
}
trap cleanup EXIT

docker run --detach \
  --name "$agent_name" \
  --privileged \
  --pid host \
  --cgroupns host \
  --volume /proc:/host/proc:ro \
  --volume "$repo_root/tests/fixtures/aya_http_propagation_smoke.toml:/etc/e-navigator.toml:ro" \
  --entrypoint /bin/sh \
  "$image" \
  -c 'mountpoint -q /sys/kernel/tracing || mount -t tracefs tracefs /sys/kernel/tracing; exec e-navigator --source unified --config /etc/e-navigator.toml' \
  >/dev/null

for _ in $(seq 1 160); do
  docker logs "$agent_name" >"$agent_log" 2>&1 || true
  if grep -Fq 'aya http source ready' "$agent_log"; then
    break
  fi
  sleep 0.25
done
if ! grep -Fq 'aya http source ready' "$agent_log"; then
  cat "$agent_log" >&2
  printf 'Aya HTTP propagation did not attach\n' >&2
  exit 1
fi

if workload_output="$(
  docker run --rm \
    --volume "$repo_root/tests/fixtures/http_propagation_workload.py:/http_propagation_workload.py:ro" \
    "$python_image" \
    python /http_propagation_workload.py 2>&1
)"; then
  printf '%s\n' "$workload_output" \
    | grep -F 'http-propagation-workload-ok write=sendmsg body=4 tracestate=preserved'
else
  for _ in $(seq 1 48); do
    docker logs "$agent_name" >"$agent_log" 2>&1 || true
    if grep -Fq 'HTTP context propagation counters' "$agent_log"; then
      break
    fi
    sleep 0.25
  done
  printf '%s\n' "$workload_output" >&2
  cat "$agent_log" >&2
  printf 'HTTP propagation workload failed\n' >&2
  exit 1
fi

docker stop --time 5 "$agent_name" >/dev/null

printf 'Aya HTTP propagation smoke passed: sendmsg, body, traceparent, and tracestate\n'
