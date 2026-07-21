#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

set +e
output="$(E_NAVIGATOR_HOMELAB_CONFIRM=0 benchmarks/runner/homelab-kernel-hook-ab.sh 2>&1)"
status="$?"
set -e
if [ "$status" -ne 2 ] || [[ "$output" != *"refusing kernel-hook A/B"* ]]; then
  printf 'kernel-hook campaign guard did not fail closed: status=%s output=%s\n' "$status" "$output" >&2
  exit 1
fi

for required in \
  'context="${E_NAVIGATOR_HOMELAB_CONTEXT:-homelab}"' \
  'namespace="${E_NAVIGATOR_HOMELAB_NAMESPACE:-e-navigator-bench}"' \
  'kubectl --context "$context"' \
  'restore_standing_agent' \
  'pre-argocd-application.json' \
  'post-argocd-application.json' \
  'E_NAVIGATOR_HOMELAB_AGENT_MODE="$agent_mode"' \
  'none tracepoint fexit' \
  'fexit none tracepoint' \
  'tracepoint fexit none'
do
  if ! grep -Fq "$required" benchmarks/runner/homelab-kernel-hook-ab.sh; then
    printf 'kernel-hook campaign is missing guard/evidence surface: %s\n' "$required" >&2
    exit 1
  fi
done
