#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

set +e
output="$(
  E_NAVIGATOR_HOMELAB_CONFIRM=0 \
    benchmarks/runner/homelab-collect.sh 2>&1 >/dev/null
)"
status="$?"
set -e

if [ "$status" -ne 2 ]; then
  printf 'expected guard to exit 2, got %s\n%s\n' "$status" "$output" >&2
  exit 1
fi

case "$output" in
  *"refusing to run homelab validation without E_NAVIGATOR_HOMELAB_CONFIRM=1"* ) ;;
  * )
    printf 'guard output did not contain expected refusal\n%s\n' "$output" >&2
    exit 1
    ;;
esac
