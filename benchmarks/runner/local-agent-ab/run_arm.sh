#!/bin/bash
# One local whole-agent A/B arm. Runs inside the local-agent-ab container
# (privileged, host pid namespace, tracing mounts). Expects:
#   /local-ab   this directory, mounted read-only
#   $AGENT_BIN  agent binary path inside the container
#   /out        writable results directory
# Env: LOCAL_AB_RATES (family=rps pairs), LOCAL_AB_CONCURRENCY,
#      LOCAL_AB_WARMUP_SECONDS, LOCAL_AB_DURATION_SECONDS,
#      ATTACH_SETTLE_SECONDS, PERF_RECORD=1, PERF_SECONDS.
set -euo pipefail

AGENT_BIN=${AGENT_BIN:-/agent/e-navigator}
OUT=${OUT:-/out}
mkdir -p "$OUT"

redis-server --port 6379 --save '' --appendonly no --logfile "$OUT/redis.log" --daemonize yes
python3 /local-ab/local_ab.py otlp-sink >"$OUT/otlp-sink.log" 2>&1 &
SINK_PID=$!

for _ in $(seq 1 100); do
  curl -sf http://127.0.0.1:4318/health >/dev/null 2>&1 && break
  sleep 0.1
done

"$AGENT_BIN" --config /local-ab/agent.toml >"$OUT/agent.log" 2>&1 &
AGENT_PID=$!

agent_ready=0
for _ in $(seq 1 120); do
  if curl -sf http://127.0.0.1:9099/metrics >/dev/null 2>&1; then
    agent_ready=1
    break
  fi
  if ! kill -0 "$AGENT_PID" 2>/dev/null; then break; fi
  sleep 0.5
done
if [ "$agent_ready" != "1" ]; then
  echo "AGENT_FAILED_TO_START" >&2
  tail -50 "$OUT/agent.log" >&2
  exit 1
fi

python3 /local-ab/local_ab.py redis-proxy >"$OUT/redis-proxy.log" 2>&1 &
PROXY_PID=$!
python3 /local-ab/local_ab.py http >"$OUT/http.log" 2>&1 &
HTTP_PID=$!
for _ in $(seq 1 100); do
  grep -q LOCAL_AB_READY "$OUT/redis-proxy.log" 2>/dev/null && break
  sleep 0.2
done

sleep "${ATTACH_SETTLE_SECONDS:-10}"

: >"$OUT/load.log"
python3 /local-ab/local_ab.py load >"$OUT/load.log" 2>&1 &
LOAD_PID=$!

while ! grep -q LOCAL_AB_MEASURE_START "$OUT/load.log" 2>/dev/null; do
  if ! kill -0 "$LOAD_PID" 2>/dev/null; then
    echo "LOAD_FAILED" >&2
    cat "$OUT/load.log" >&2
    exit 1
  fi
  sleep 0.1
done

CLK=$(getconf CLK_TCK)
STAT0=$(awk '{print $14+$15}' "/proc/$AGENT_PID/stat")
WALL0=$(date +%s.%N)

if [ "${PERF_RECORD:-0}" = "1" ]; then
  perf record -F 997 -g --call-graph fp -p "$AGENT_PID" \
    -o "$OUT/perf.data" -- sleep "${PERF_SECONDS:-45}" >"$OUT/perf.log" 2>&1 &
  PERF_PID=$!
fi

while ! grep -q LOCAL_AB_MEASURE_END "$OUT/load.log" 2>/dev/null; do
  if ! kill -0 "$LOAD_PID" 2>/dev/null; then
    echo "LOAD_DIED_MID_MEASURE" >&2
    cat "$OUT/load.log" >&2
    exit 1
  fi
  sleep 0.2
done

STAT1=$(awk '{print $14+$15}' "/proc/$AGENT_PID/stat")
WALL1=$(date +%s.%N)
RSS_KB=$(awk '/VmRSS/{print $2}' "/proc/$AGENT_PID/status")
HWM_KB=$(awk '/VmHWM/{print $2}' "/proc/$AGENT_PID/status")

wait "$LOAD_PID" || true
if [ "${PERF_RECORD:-0}" = "1" ]; then
  wait "$PERF_PID" || true
fi

curl -s http://127.0.0.1:9099/metrics >"$OUT/metrics.prom" || true
curl -s http://127.0.0.1:4318/stats >"$OUT/otlp-stats.json" || true

python3 - "$STAT0" "$STAT1" "$WALL0" "$WALL1" "$CLK" "$RSS_KB" "$HWM_KB" <<'PYEOF' >"$OUT/result.json"
import json, sys
stat0, stat1 = int(sys.argv[1]), int(sys.argv[2])
wall0, wall1 = float(sys.argv[3]), float(sys.argv[4])
clk = int(sys.argv[5])
rss_kb, hwm_kb = int(sys.argv[6]), int(sys.argv[7])
cpu_seconds = (stat1 - stat0) / clk
wall_seconds = wall1 - wall0
print(json.dumps({
    "schema": "e-navigator.local-ab-arm.v1",
    "agent_cpu_seconds": cpu_seconds,
    "wall_seconds": wall_seconds,
    "agent_cpu_cores": cpu_seconds / wall_seconds if wall_seconds else None,
    "agent_rss_kb": rss_kb,
    "agent_rss_hwm_kb": hwm_kb,
}, sort_keys=True))
PYEOF

cat "$OUT/result.json"
grep LOCAL_AB_RESULT "$OUT/load.log" || true

kill "$AGENT_PID" 2>/dev/null || true
for _ in $(seq 1 40); do
  kill -0 "$AGENT_PID" 2>/dev/null || break
  sleep 0.5
done
kill "$PROXY_PID" "$HTTP_PID" "$SINK_PID" 2>/dev/null || true
redis-cli -p 6379 shutdown nosave 2>/dev/null || true
exit 0
