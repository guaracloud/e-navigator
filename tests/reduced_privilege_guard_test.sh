#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

set +e
output="$(E_NAVIGATOR_HOMELAB_CONFIRM=0 benchmarks/runner/homelab-reduced-privilege.sh 2>&1)"
status="$?"
set -e
if [ "$status" -ne 2 ]; then
  printf 'expected reduced-privilege confirmation guard to exit 2, got %s\n%s\n' \
    "$status" "$output" >&2
  exit 1
fi
case "$output" in
  *"refusing reduced-privilege proof"*) ;;
  *) printf 'missing reduced-privilege confirmation refusal\n%s\n' "$output" >&2; exit 1 ;;
esac

bash -n benchmarks/runner/homelab-collect.sh
bash -n benchmarks/runner/homelab-reduced-privilege.sh
python3 -m py_compile benchmarks/runner/analyze-reduced-privilege.py

for required in \
  'target must be exactly homelab/e-navigator-bench' \
  'kubectl --context "$context"' \
  'E_NAVIGATOR_HOMELAB_VALUES_FILE="$values"' \
  'E_NAVIGATOR_REDUCED_PRIVILEGE_RESUME' \
  'reused validated reduced-privilege arm' \
  'find "$run_dir" -mindepth 1 -delete' \
  'run_arm none' \
  'run_arm tls-none' \
  'run_arm exec' \
  'run_arm network' \
  'run_arm dns' \
  'run_arm http' \
  'run_arm protocol' \
  'run_arm cpu-profile' \
  'run_arm host-resource' \
  'run_arm tls'; do
  if ! grep -Fq "$required" benchmarks/runner/homelab-reduced-privilege.sh; then
    printf 'missing reduced-privilege harness guard: %s\n' "$required" >&2
    exit 1
  fi
done

grep -Fq 'homelab values file does not exist' benchmarks/runner/homelab-collect.sh
grep -Fq 'helm_args+=(--values "$values_file")' benchmarks/runner/homelab-collect.sh
grep -Fq 'render_args+=(--values "$values_file")' benchmarks/runner/homelab-collect.sh

for values in \
  charts/e-navigator/values-reduced-privilege.yaml \
  benchmarks/config/reduced-privilege-core-values.yaml \
  benchmarks/config/reduced-privilege-none-values.yaml; do
  if grep -Eq '^[[:space:]]+- (SYS_ADMIN|NET_ADMIN|NET_RAW|SYS_RESOURCE|SYSLOG|CHECKPOINT_RESTORE|DAC_READ_SEARCH)[[:space:]]*$' "$values"; then
    printf 'legacy umbrella capability remains in reduced profile: %s\n' "$values" >&2
    exit 1
  fi
  grep -Fq 'type: RuntimeDefault' "$values"
  grep -Fq 'privileged: false' "$values"
  grep -Fq 'allowPrivilegeEscalation: false' "$values"
done

grep -Fq -- '- BPF' charts/e-navigator/values-reduced-privilege.yaml
grep -Fq -- '- PERFMON' charts/e-navigator/values-reduced-privilege.yaml
grep -Fq -- '- SYS_PTRACE' charts/e-navigator/values-reduced-privilege.yaml

for config in benchmarks/config/reduced-privilege-*.toml; do
  cargo run --locked -q -p e-navigator-cli -- --validate-config --config "$config"
done

helm lint charts/e-navigator --values charts/e-navigator/values-reduced-privilege.yaml >/dev/null
rendered="$(helm template e-navigator charts/e-navigator \
  --values charts/e-navigator/values-reduced-privilege.yaml)"
for capability in BPF PERFMON SYS_PTRACE; do
  if ! grep -Eq -- "- ${capability}$" <<<"$rendered"; then
    printf 'rendered reduced profile lacks %s\n' "$capability" >&2
    exit 1
  fi
done
if grep -Eq -- '- (SYS_ADMIN|NET_ADMIN|NET_RAW|SYS_RESOURCE|SYSLOG|CHECKPOINT_RESTORE|DAC_READ_SEARCH)$' \
  <<<"$rendered"; then
  printf 'rendered reduced profile retains a legacy umbrella capability\n' >&2
  exit 1
fi

kubeconform -strict -summary benchmarks/k8s/reduced-privilege-workload.yaml >/dev/null

for proof_file in analysis.json manifest.json report.md representative-observations.json SHA256SUMS; do
  test -s "documentation/proof/reduced-privilege-20260722/$proof_file"
done
(cd documentation/proof/reduced-privilege-20260722 && shasum -a 256 -c SHA256SUMS >/dev/null)
grep -Fq 'ADR 0012' documentation/README.md
grep -Fq 'values-reduced-privilege.yaml' documentation/helm.md
grep -Fq 'Reduced privilege operation' documentation/capabilities.md
grep -Fq 'The opt-in reduced profile removes `SYS_ADMIN`' documentation/boundaries.md
grep -Fq 'Reduced-privilege proof (2026-07-22' documentation/proof-report.md
grep -Fq 'Reduced Privilege Matrix (Homelab, 2026-07-22)' documentation/benchmark.md
grep -Fq 'Privilege posture' website/index.html
