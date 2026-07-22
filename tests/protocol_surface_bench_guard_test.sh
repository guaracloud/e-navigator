#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

set +e
output="$(E_NAVIGATOR_HOMELAB_CONFIRM=0 benchmarks/runner/homelab-protocol-surface.sh 2>&1)"
status="$?"
set -e
if [ "$status" -ne 2 ] || [[ "$output" != *"refusing protocol-surface proof"* ]]; then
  printf 'protocol-surface campaign guard did not fail closed: status=%s output=%s\n' \
    "$status" "$output" >&2
  exit 1
fi

# Literal source-code fragments are intentionally single-quoted.
# shellcheck disable=SC2016
for required in \
  'context="${E_NAVIGATOR_HOMELAB_CONTEXT:-homelab}"' \
  'namespace="${E_NAVIGATOR_HOMELAB_NAMESPACE:-e-navigator-bench}"' \
  'protocol-surface proof target must be exactly homelab/e-navigator-bench' \
  'kubectl --context "$context"' \
  'restore_standing_agent' \
  'pre-argocd-application.json' \
  'post-argocd-application.json' \
  'wait_for_benchmark_agent_absence' \
  'run_arm none "$repetition"' \
  'run_arm protocol "$repetition"' \
  'analyze-protocol-surface.py'
do
  if ! grep -Fq "$required" benchmarks/runner/homelab-protocol-surface.sh; then
    printf 'protocol-surface campaign is missing guard/evidence surface: %s\n' "$required" >&2
    exit 1
  fi
done
