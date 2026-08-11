#!/usr/bin/env bash
set -euo pipefail

image="${1:-e-navigator:local}"
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
config_file="$repo_root/tests/fixtures/kernel-profile-smoke.toml"
run_id="${E_NAVIGATOR_KERNEL_PROFILE_RUN_ID:-$$}"
workload_name="e-navigator-kernel-workload-${run_id}"
profiler_name="e-navigator-kernel-profiler-${run_id}"
tmp_dir="$(mktemp -d)"
log_file="$tmp_dir/profiler.log"

cleanup() {
  docker rm --force "$profiler_name" >/dev/null 2>&1 || true
  docker rm --force "$workload_name" >/dev/null 2>&1 || true
  rm -rf "$tmp_dir"
}
trap cleanup EXIT

for command in docker jq; do
  if ! command -v "$command" >/dev/null 2>&1; then
    printf 'required command is unavailable: %s\n' "$command" >&2
    exit 1
  fi
done

if [ "$(docker info --format '{{.OSType}}')" != "linux" ]; then
  echo "kernel profile smoke requires a Linux Docker backend" >&2
  exit 1
fi

docker run --detach --rm \
  --name "$workload_name" \
  --entrypoint /bin/sh \
  "$image" \
  -c 'while :; do :; done' >/dev/null

docker run --detach --rm \
  --name "$profiler_name" \
  --privileged \
  --pid host \
  --mount "type=bind,source=$config_file,target=/etc/e-navigator/kernel-profile-smoke.toml,readonly" \
  "$image" \
  --source aya-cpu-profile \
  --config /etc/e-navigator/kernel-profile-smoke.toml >/dev/null

passed=false
for _ in $(seq 1 30); do
  docker logs "$profiler_name" >"$log_file" 2>&1 || true
  if grep -E '^\{' "$log_file" | jq --exit-status --slurp '
      any(.[].payload?;
        .stack_frames? != null and
        any(.stack_frames[]?; .domain == "user") and
        any(.stack_frames[]?; .domain == "kernel") and
        all(.stack_frames[]?;
          .domain != "kernel" or
          ((.symbol // "") | startswith("ip:") | not)) and
        any(.attributes[]?;
          .key == "profiling.stack.kernel_frames" and
          ((.value | tonumber) > 0)))
    ' >/dev/null 2>&1
  then
    passed=true
    break
  fi
  if [ "$(docker inspect "$profiler_name" --format '{{.State.Running}}' 2>/dev/null || true)" != "true" ]; then
    break
  fi
  sleep 1
done

if [ "$passed" != true ]; then
  cat "$log_file" >&2
  echo "did not observe a combined user and kernel profile sample" >&2
  exit 1
fi

echo "kernel profile smoke passed with combined user and address-safe kernel frames"
