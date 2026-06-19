#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

timestamp="$(date -u +%Y%m%d-%H%M%S)"
results_dir="benchmarks/results/${timestamp}"
mkdir -p "$results_dir"

sample_size="${E_NAVIGATOR_BENCH_SAMPLE_SIZE:-10}"
measurement_time="${E_NAVIGATOR_BENCH_MEASUREMENT_TIME:-1}"
warm_up_time="${E_NAVIGATOR_BENCH_WARM_UP_TIME:-1}"

printf 'local benchmark smoke results: %s\n' "$results_dir"
printf 'sample_size=%s measurement_time=%ss warm_up_time=%ss\n' \
  "$sample_size" "$measurement_time" "$warm_up_time"

cargo bench --locked -p e-navigator-local-benches --bench hot_paths -- \
  --sample-size "$sample_size" \
  --measurement-time "$measurement_time" \
  --warm-up-time "$warm_up_time" \
  2>&1 | tee "$results_dir/criterion-smoke.txt"
