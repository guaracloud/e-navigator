#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
image="${E_NAVIGATOR_IMAGE:-e-navigator:local}"
python_image="${E_NAVIGATOR_PYTHON_IMAGE:-python:3.13-slim-bookworm}"
mmsg_batch_size="${E_NAVIGATOR_MMSG_BATCH_SIZE:-32}"
case "$mmsg_batch_size" in
  32)
    expected_sent=1423
    expected_received=1584
    ;;
  1024)
    expected_sent=33663
    expected_received=39776
    ;;
  *)
    printf 'E_NAVIGATOR_MMSG_BATCH_SIZE must be 32 or 1024\n' >&2
    exit 1
    ;;
esac
agent_name="e-navigator-network-io-$RANDOM-$$"
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
  --volume /proc:/host/proc:ro \
  --volume /sys/fs/cgroup:/host/cgroup:ro \
  --volume "$repo_root/tests/fixtures/aya_network_io_smoke.toml:/etc/e-navigator.toml:ro" \
  --entrypoint /bin/sh \
  "$image" \
  -c 'mountpoint -q /sys/kernel/tracing || mount -t tracefs tracefs /sys/kernel/tracing; exec e-navigator --source unified --config /etc/e-navigator.toml' \
  >/dev/null

for _ in $(seq 1 60); do
  docker logs "$agent_name" >"$agent_log" 2>&1 || true
  if grep -Fq 'aya network source attached' "$agent_log"; then
    break
  fi
  sleep 0.25
done
if ! grep -Fq 'aya network source attached' "$agent_log"; then
  cat "$agent_log" >&2
  printf 'Aya network source did not attach\n' >&2
  exit 1
fi

docker run --rm \
  --env "E_NAVIGATOR_MMSG_BATCH_SIZE=$mmsg_batch_size" \
  --volume "$repo_root/tests/fixtures/network_io_workload.py:/network_io_workload.py:ro" \
  "$python_image" \
  python /network_io_workload.py \
  | grep -F "network-io-workload-ok sent=$expected_sent received=$expected_received"

sleep 1
docker stop --time 5 "$agent_name" >/dev/null
docker logs "$agent_name" >"$agent_log" 2>&1

if ! grep -F '"kind":"network_connection_snapshot"' "$agent_log" \
  | grep -F "\"bytes_sent\":$expected_sent" \
  | grep -Fq "\"bytes_received\":$expected_received"; then
  cat "$agent_log" >&2
  printf 'active snapshot did not include all vectored, message-batch, and zero-copy bytes\n' >&2
  exit 1
fi

if ! grep -F '"kind":"network_connection_close"' "$agent_log" \
  | grep -F "\"bytes_sent\":$expected_sent" \
  | grep -Fq "\"bytes_received\":$expected_received"; then
  cat "$agent_log" >&2
  printf 'close event did not include all vectored, message-batch, and zero-copy bytes\n' >&2
  exit 1
fi

printf 'Aya network I/O smoke passed: vectored/message-batch/zero-copy and active snapshot totals\n'
