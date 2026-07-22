#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

set +e
output="$(E_NAVIGATOR_HOMELAB_CONFIRM=0 benchmarks/runner/homelab-head-to-head.sh 2>&1)"
status="$?"
set -e
if [ "$status" -ne 2 ]; then
  printf 'expected head-to-head guard to exit 2, got %s\n%s\n' "$status" "$output" >&2
  exit 1
fi
case "$output" in
  *"refusing head-to-head proof"*) ;;
  *) printf 'missing head-to-head confirmation refusal\n%s\n' "$output" >&2; exit 1 ;;
esac

bash -n benchmarks/runner/homelab-head-to-head.sh
python3 -c '
from pathlib import Path
for name in (
    "benchmarks/runner/analyze-head-to-head.py",
    "benchmarks/workloads/head-to-head/head_to_head.py",
):
    path = Path(name)
    compile(path.read_text(), str(path), "exec")
'

if [ "$(grep -Ec '^[[:space:]]+run_arm (none|beyla|e-navigator) ' \
  benchmarks/runner/homelab-head-to-head.sh)" -ne 33 ]; then
  printf 'head-to-head harness must contain exactly 33 benchmark arms\n' >&2
  exit 1
fi
if [ "$(grep -c 'assert_standing_suspended >' \
  benchmarks/runner/homelab-head-to-head.sh)" -ne 3 ]; then
  printf 'head-to-head harness must assert initial, pre-arm, and post-arm isolation\n' >&2
  exit 1
fi

for required in \
  'target must be exactly homelab/e-navigator-bench' \
  'requires exactly three repetitions' \
  'profile diagnostic requires exactly one repetition' \
  'f404a525451c1b36ab0a8a98560e20fc4af70f59016518d414ce5fed367855e2' \
  'validated-run-order.log' \
  'prom-node-cpu.json' \
  'prom-node-memory.json' \
  'prom-agent-cpu.json' \
  'prom-agent-rss.json' \
  'suspend-root-argocd-automation.txt' \
  'restore-standing-daemonset.txt' \
  'restore-root-argocd-automation.txt' \
  'post-argocd-application.json' \
  'post-root-argocd-application.json' \
  'assert_standing_suspended' \
  'E_NAVIGATOR_HEAD_TO_HEAD_RESUME'; do
  if ! grep -Fq "$required" benchmarks/runner/homelab-head-to-head.sh; then
    printf 'missing head-to-head harness guard or evidence: %s\n' "$required" >&2
    exit 1
  fi
done

grep -Fq 'e-navigator.head-to-head-workload.v1' \
  benchmarks/workloads/head-to-head/head_to_head.py

for required in \
  'head-to-head-http' \
  'head-to-head-grpc' \
  'head-to-head-redis-proxy' \
  'head-to-head-postgres-proxy' \
  'head-to-head-python-cpu' \
  'head-to-head-load-template' \
  'kubernetes.io/hostname: homelab-01' \
  'kubernetes.io/hostname: homelab-02'; do
  if ! grep -Fq "$required" benchmarks/k8s/head-to-head-workload.yaml; then
    printf 'missing head-to-head workload contract: %s\n' "$required" >&2
    exit 1
  fi
done

grep -Fq 'sha256:133b8d66190f21e20365d9972e1621513ea5e44518fb71e1c3e0180c64815566' \
  benchmarks/runner/analyze-head-to-head.py
grep -Fq 'sha256:491b0578c04983fd54fe99b587b6fab4404dc46d0dc16677bd6b00cc1140b308' \
  benchmarks/k8s/head-to-head-alloy.yaml
grep -Fq 'sample_rate      = 10' benchmarks/k8s/head-to-head-alloy.yaml
grep -Fq 'python_enabled   = true' benchmarks/k8s/head-to-head-alloy.yaml
grep -Fq 'unknown_cgroup = "deny"' benchmarks/config/head-to-head-profile.toml
grep -Fq 'discovery_mode = "event_driven"' benchmarks/config/head-to-head-profile.toml
grep -Fq 'sample_frequency_hz = 10' benchmarks/config/head-to-head-profile.toml
grep -Fq 'e_navigator_export_dropped_queue_full_total' \
  benchmarks/runner/analyze-head-to-head.py
grep -Fq 'pyroscope_ebpf_profiling_sessions_failing_total' \
  benchmarks/runner/analyze-head-to-head.py
grep -Fq 'beyla_instrumentation_errors_total' benchmarks/runner/analyze-head-to-head.py
grep -Fq 'MAX_PROMETHEUS_SERIES = 100_000' benchmarks/runner/analyze-head-to-head.py
grep -Fq 'MAX_OTLP_BODY_BYTES = 16 * 1024 * 1024' \
  benchmarks/workloads/head-to-head/head_to_head.py
grep -Fq 'MAX_LATENCY_SAMPLES = 300_000' \
  benchmarks/workloads/head-to-head/head_to_head.py
grep -Fq 'client = await wait_for_redis()' \
  benchmarks/workloads/head-to-head/head_to_head.py
grep -Fq 'minimum_expected_protocol_signals' \
  benchmarks/runner/analyze-head-to-head.py
grep -Fq 'E-Navigator protocol signal completeness failed' \
  benchmarks/runner/analyze-head-to-head.py
grep -Fq 'comparative CPU, RSS, allocation, throughput, and latency claims' \
  documentation/proof/optimization-20260722/ERRATUM.md
grep -Fq 'Status: local campaign complete, homelab baseline and A/B blocked' \
  documentation/proof/optimization-20260722-campaign2/report.md

for config in benchmarks/config/head-to-head-*.toml; do
  cargo run --locked -q -p e-navigator-cli -- --validate-config --config "$config"
done

historical_proof_dir="documentation/proof/head-to-head-20260722"
for artifact in \
  SHA256SUMS \
  analysis.json \
  cleanup.json \
  executed-input-sha256.txt \
  manifest.json \
  report.md \
  representative-alloy-after.prom \
  representative-alloy-before.prom \
  representative-beyla-application-after.prom \
  representative-beyla-application-before.prom \
  representative-beyla-internal-after.prom \
  representative-beyla-internal-before.prom \
  representative-e-navigator-after.prom \
  representative-e-navigator-before.prom \
  representative-workload-result.json \
  runs.json \
  validated-run-order.log; do
  if [ ! -s "$historical_proof_dir/$artifact" ]; then
    printf 'missing historical head-to-head proof artifact: %s\n' "$artifact" >&2
    exit 1
  fi
done

(
  cd "$historical_proof_dir"
  shasum -a 256 -c SHA256SUMS >/dev/null
)

jq -e '
  .schema == "e-navigator.head-to-head-proof-analysis.v1" and
  .decision == "PASS" and
  (.run_order | length) == 33 and
  (.conditions | length) == 11 and
  .final_stack_comparison.e_navigator_agent_cpu_change_vs_beyla_alloy_percent == 43.601071 and
  .final_stack_comparison.e_navigator_agent_rss_change_vs_beyla_alloy_percent == 31.903883
' "$historical_proof_dir/analysis.json" >/dev/null
jq -e '
  .schema == "e-navigator.head-to-head-proof-runs.v1" and
  (.runs | length) == 33 and
  ([.runs[].workload.measured.families[].errors] | add) == 0
' "$historical_proof_dir/runs.json" >/dev/null
jq -e '
  .schema == "e-navigator.head-to-head-proof-manifest.v1" and
  .validation.scripts_quality_sh == "pass" and
  (.validation.skipped_gates | length) == 0 and
  .cleanup.production_context_touched == false and
  .cleanup.candidate_image_references_removed_from_both_nodes == true
' "$historical_proof_dir/manifest.json" >/dev/null
grep -Fq 'Result: INVALIDATED for comparative claims.' \
  "$historical_proof_dir/report.md"
grep -Fq 'left the automated `root-app` parent able to restore that' \
  "$historical_proof_dir/report.md"

for config in benchmarks/config/head-to-head-*.toml; do
  expected="$(jq -r --arg config "$config" \
    '.execution.finalized_config_sha256[$config] // empty' \
    "$historical_proof_dir/manifest.json")"
  actual="$(shasum -a 256 "$config" | awk '{print $1}')"
  if [ -z "$expected" ] || [ "$actual" != "$expected" ]; then
    printf 'finalized config checksum mismatch: %s\n' "$config" >&2
    exit 1
  fi
done
jq -e '
  .namespaced_disposable_resource_count == 0 and
  .cluster_scoped_disposable_resource_count == 0 and
  .standing_argocd_application.sync == "Synced" and
  .standing_argocd_application.health == "Healthy" and
  .standing_daemonset.ready == 2 and
  .production_context_touched == false
' "$historical_proof_dir/cleanup.json" >/dev/null

if [ "$(wc -l <"$historical_proof_dir/validated-run-order.log" | tr -d ' ')" -ne 33 ]; then
  printf 'historical head-to-head proof must contain 33 validated entries\n' >&2
  exit 1
fi

optimization_proof_dir="documentation/proof/optimization-20260722"
for artifact in SHA256SUMS report.md summary.json; do
  if [ ! -s "$optimization_proof_dir/$artifact" ]; then
    printf 'missing optimization proof artifact: %s\n' "$artifact" >&2
    exit 1
  fi
done
(
  cd "$optimization_proof_dir"
  shasum -a 256 -c SHA256SUMS >/dev/null
)
jq -e '
  .schema == "e-navigator.optimization-campaign-summary.v1" and
  .verdict.evidence_integrity == "pass" and
  .verdict.dual_cpu_and_memory_goal == "no-go" and
  .head_to_head.runs == 33 and
  .head_to_head.measured_successes == 591030 and
  .head_to_head.workload_errors == 0 and
  .head_to_head.final_stack.e_navigator_cpu_change_percent == 28.066163 and
  .head_to_head.final_stack.e_navigator_rss_change_percent == -64.07903 and
  .head_to_head.e_navigator_signals.hard_loss_total == 0 and
  .allocations.baseline_to_final.calls_change_percent == -33.670202 and
  .allocations.baseline_to_final.requested_bytes_change_percent == -25.164751 and
  .validation.scripts_quality_sh == "pass" and
  (.validation.skipped_gates | length) == 0 and
  .cleanup.candidate_image_references_removed_from_both_nodes == true and
  .cleanup.production_context_touched == false
' "$optimization_proof_dir/summary.json" >/dev/null

grep -Fq 'ADR 0014, controlled cumulative head-to-head benchmark' documentation/README.md
grep -Fq 'earlier 33-run capture is invalidated' documentation/capabilities.md
grep -Fq 'lower CPU or memory versus another observability stack' \
  documentation/boundaries.md
grep -Fq 'Invalidated full-stack optimization campaign' documentation/proof-report.md
grep -Fq '<span class="metric-value">5</span>' website/index.html
grep -Fq '<span class="metric-label">cumulative workload stages</span>' website/index.html
grep -Fq '<span class="metric-value">3x</span>' website/index.html
grep -Fq '<span class="metric-value">0</span>' website/index.html

if command -v kubeconform >/dev/null 2>&1; then
  kubeconform -strict -summary benchmarks/k8s/head-to-head-workload.yaml >/dev/null
  kubeconform -strict -summary benchmarks/k8s/head-to-head-alloy.yaml >/dev/null
  kubeconform -strict -summary benchmarks/k8s/allocation-probe.yaml >/dev/null
fi
