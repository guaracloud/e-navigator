#!/bin/bash
# Runs N repetitions of the local whole-agent A/B arm for one binary label.
#
# Usage: run_reps.sh <label> <binary-name-in-volume> [reps] [rates] [duration]
#
# The agent binary is read from the Docker volume named by TARGET_VOLUME
# (default e-nav-target), the same volume the containerized release build
# writes to. Results land under benchmarks/results/local-agent-ab/<label>-rN
# (ignored raw evidence). Alternate candidate and baseline labels pairwise
# and keep the host otherwise idle; a shared VM makes unpaired or
# contended arms unusable for comparison.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
harness_dir="$repo_root/benchmarks/runner/local-agent-ab"

LABEL="${1:?usage: run_reps.sh <label> <binary-name> [reps] [rates] [duration]}"
BIN_NAME="${2:?missing binary name inside the target volume}"
REPS="${3:-3}"
RATES="${4:-redis=800}"
DURATION="${5:-60}"
TARGET_VOLUME="${TARGET_VOLUME:-e-nav-target}"
IMAGE="${LOCAL_AB_IMAGE:-e-nav-local-ab}"

for rep in $(seq 1 "$REPS"); do
  out="$repo_root/benchmarks/results/local-agent-ab/$LABEL-r$rep"
  mkdir -p "$out"
  docker run --rm --privileged --pid=host \
    -v /sys/kernel/tracing:/sys/kernel/tracing \
    -v /sys/kernel/debug:/sys/kernel/debug \
    -v "$harness_dir:/local-ab:ro" \
    -v "$out:/out" \
    -v "$TARGET_VOLUME:/agent:ro" \
    -e AGENT_BIN="/agent/$BIN_NAME" \
    -e LOCAL_AB_RATES="$RATES" \
    -e LOCAL_AB_WARMUP_SECONDS="${LOCAL_AB_WARMUP_SECONDS:-10}" \
    -e LOCAL_AB_DURATION_SECONDS="$DURATION" \
    -e ATTACH_SETTLE_SECONDS="${ATTACH_SETTLE_SECONDS:-10}" \
    ${PERF_RECORD:+-e PERF_RECORD=$PERF_RECORD} \
    ${PERF_SECONDS:+-e PERF_SECONDS=$PERF_SECONDS} \
    "$IMAGE" /local-ab/run_arm.sh >"$out/arm.log" 2>&1 || {
      echo "ARM FAILED: $LABEL-r$rep" >&2
      tail -5 "$out/arm.log" >&2
      exit 1
    }
  echo "== $LABEL-r$rep"
  cat "$out/result.json"
  echo
  grep -o 'decoded_samples_total{source="source.aya_protocol"} [0-9]*' \
    "$out/metrics.prom" || true
done
