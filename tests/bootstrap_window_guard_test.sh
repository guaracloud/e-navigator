#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

set +e
output="$(E_NAVIGATOR_HOMELAB_CONFIRM=0 benchmarks/runner/homelab-bootstrap-window.sh 2>&1)"
status="$?"
set -e
if [ "$status" -ne 2 ]; then
  printf 'expected bootstrap-window guard to exit 2, got %s\n%s\n' "$status" "$output" >&2
  exit 1
fi
case "$output" in
  *"refusing bootstrap-window proof"*) ;;
  *) printf 'missing bootstrap-window confirmation refusal\n%s\n' "$output" >&2; exit 1 ;;
esac

bash -n benchmarks/runner/homelab-collect.sh
bash -n benchmarks/runner/homelab-bootstrap-window.sh
python3 -m py_compile benchmarks/runner/analyze-bootstrap-window.py

for required in \
  'target must be exactly homelab/e-navigator-bench' \
  'E_NAVIGATOR_BOOTSTRAP_WINDOW_REPETITIONS' \
  'E_NAVIGATOR_BOOTSTRAP_WINDOW_RESUME' \
  'run_arm none-r1' \
  'bootstrap-window-polling.toml polling' \
  'bootstrap-window-event.toml event' \
  'analyze-bootstrap-window.py aggregate' \
  'find "$run_dir" -mindepth 1 -delete' \
  'restore-standing-daemonset.txt'; do
  if ! grep -Fq "$required" benchmarks/runner/homelab-bootstrap-window.sh; then
    printf 'missing bootstrap-window harness guard: %s\n' "$required" >&2
    exit 1
  fi
done

grep -Fq 'discovery_mode = "polling"' benchmarks/config/bootstrap-window-polling.toml
grep -Fq 'discovery_mode = "event_driven"' benchmarks/config/bootstrap-window-event.toml
grep -Fq 'unknown_cgroup = "deny"' benchmarks/config/bootstrap-window-event.toml
grep -Fq 'namespace_include = ["e-navigator-bench"]' benchmarks/config/bootstrap-window-event.toml
grep -Fq 'e-navigator.bootstrap-window-start.v1' benchmarks/k8s/bootstrap-window-workload.yaml
grep -Fq 'e-navigator.bootstrap-window-workload.v1' benchmarks/k8s/bootstrap-window-workload.yaml
grep -Fq 'e_navigator_capture_filter_inotify_queue_overflows_total' \
  benchmarks/runner/analyze-bootstrap-window.py
grep -Fq 'event p95 did not improve polling' benchmarks/runner/analyze-bootstrap-window.py

for config in benchmarks/config/bootstrap-window-*.toml; do
  cargo run --locked -q -p e-navigator-cli -- --validate-config --config "$config"
done
kubeconform -strict -summary benchmarks/k8s/bootstrap-window-workload.yaml >/dev/null

for proof_file in analysis.json manifest.json report.md representative-metrics.prom runs.json SHA256SUMS; do
  test -s "documentation/proof/bootstrap-window-20260722/$proof_file"
done
(cd documentation/proof/bootstrap-window-20260722 && shasum -a 256 -c SHA256SUMS >/dev/null)
grep -Fq 'ADR 0013' documentation/README.md
grep -Fq 'Capture-Filter Bootstrap Window (Homelab, 2026-07-22)' documentation/benchmark.md
grep -Fq 'Capture-filter bootstrap-window proof (2026-07-22' documentation/proof-report.md
grep -Fq '0.463 ms event-driven median' documentation/capabilities.md
grep -Fq '0.487 ms p95 event-driven' documentation/boundaries.md
grep -Fq '0.463 ms event-driven median' website/index.html
test -s benchmarks/results/sample-bootstrap-window-20260722.md
