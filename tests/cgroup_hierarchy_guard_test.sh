#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

set +e
output="$(E_NAVIGATOR_HOMELAB_CONFIRM=0 benchmarks/runner/homelab-cgroup-hierarchy.sh 2>&1)"
status="$?"
set -e
if [ "$status" -ne 2 ]; then
  printf 'expected confirmation guard to exit 2, got %s\n%s\n' "$status" "$output" >&2
  exit 1
fi
case "$output" in
  *"refusing to run cgroup hierarchy proof"*) ;;
  *) printf 'missing confirmation refusal\n%s\n' "$output" >&2; exit 1 ;;
esac

for required in \
  'target context must be exactly homelab' \
  'target namespace must be exactly e-navigator-bench' \
  'kubectl --context "$context"' \
  'delete -f "$rendered" --ignore-not-found=true' \
  'e_navigator_capture_filter_fail_closed_total 1' \
  'dropped_total=[1-9][0-9]*'; do
  if ! grep -Fq "$required" benchmarks/runner/homelab-cgroup-hierarchy.sh; then
    printf 'missing cgroup hierarchy guard: %s\n' "$required" >&2
    exit 1
  fi
done

grep -Fq 'imagePullPolicy: Never' benchmarks/k8s/cgroup-hierarchy-proof.yaml
grep -Fq 'cgroup-root' benchmarks/k8s/cgroup-hierarchy-proof.yaml
grep -Fq 'tasks: ""' benchmarks/k8s/cgroup-hierarchy-proof.yaml
