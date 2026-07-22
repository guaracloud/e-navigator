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

if [ "$(grep -c '^run_arm ' benchmarks/runner/homelab-head-to-head.sh)" -ne 33 ]; then
  printf 'head-to-head harness must contain exactly 33 benchmark arms\n' >&2
  exit 1
fi

for required in \
  'target must be exactly homelab/e-navigator-bench' \
  'requires exactly three repetitions' \
  'f404a525451c1b36ab0a8a98560e20fc4af70f59016518d414ce5fed367855e2' \
  'validated-run-order.log' \
  'prom-node-cpu.json' \
  'prom-node-memory.json' \
  'prom-agent-cpu.json' \
  'prom-agent-rss.json' \
  'restore-standing-daemonset.txt' \
  'post-argocd-application.json' \
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

for config in benchmarks/config/head-to-head-*.toml; do
  cargo run --locked -q -p e-navigator-cli -- --validate-config --config "$config"
done

proof_dir="documentation/proof/head-to-head-20260722"
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
  if [ ! -s "$proof_dir/$artifact" ]; then
    printf 'missing head-to-head proof artifact: %s\n' "$artifact" >&2
    exit 1
  fi
done

(
  cd "$proof_dir"
  shasum -a 256 -c SHA256SUMS >/dev/null
)

jq -e '
  .schema == "e-navigator.head-to-head-proof-analysis.v1" and
  .decision == "PASS" and
  (.run_order | length) == 33 and
  (.conditions | length) == 11 and
  .final_stack_comparison.e_navigator_agent_cpu_change_vs_beyla_alloy_percent == 43.601071 and
  .final_stack_comparison.e_navigator_agent_rss_change_vs_beyla_alloy_percent == 31.903883
' "$proof_dir/analysis.json" >/dev/null
jq -e '
  .schema == "e-navigator.head-to-head-proof-runs.v1" and
  (.runs | length) == 33 and
  ([.runs[].workload.measured.families[].errors] | add) == 0
' "$proof_dir/runs.json" >/dev/null
jq -e '
  .results.integrity_verdict == "pass" and
  .results.lower_agent_overhead_claim == "rejected" and
  .validation.scripts_quality_sh == "pass" and
  (.validation.skipped_gates | length) == 0 and
  .cleanup.production_context_touched == false and
  .cleanup.candidate_image_references_removed_from_both_nodes == true
' "$proof_dir/manifest.json" >/dev/null

for config in benchmarks/config/head-to-head-*.toml; do
  expected="$(jq -r --arg config "$config" \
    '.execution.finalized_config_sha256[$config] // empty' \
    "$proof_dir/manifest.json")"
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
' "$proof_dir/cleanup.json" >/dev/null

if [ "$(wc -l <"$proof_dir/validated-run-order.log" | tr -d ' ')" -ne 33 ]; then
  printf 'head-to-head proof must contain 33 validated run-order entries\n' >&2
  exit 1
fi
grep -Fq 'ADR 0014, controlled cumulative head-to-head benchmark' documentation/README.md
grep -Fq '43.601071% more agent CPU' documentation/capabilities.md
grep -Fq 'lower overhead or lower memory versus another observability stack' \
  documentation/boundaries.md
grep -Fq 'Full-stack head-to-head proof' documentation/proof-report.md
grep -Fq '<span class="metric-value">33</span>' website/index.html
grep -Fq '<span class="metric-label">matched homelab runs</span>' website/index.html

if command -v kubeconform >/dev/null 2>&1; then
  kubeconform -strict -summary benchmarks/k8s/head-to-head-workload.yaml >/dev/null
  kubeconform -strict -summary benchmarks/k8s/head-to-head-alloy.yaml >/dev/null
fi
