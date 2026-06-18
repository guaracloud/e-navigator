#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

run() {
  printf '\n==> %s\n' "$*"
  "$@"
}

require_tool() {
  tool="$1"
  if ! command -v "$tool" >/dev/null 2>&1; then
    printf 'missing required tool: %s\n' "$tool" >&2
    exit 1
  fi
}

run cargo fmt --all -- --check
run cargo clippy --locked --workspace --all-targets --exclude e-navigator-ebpf-programs -- -D warnings
run cargo test --locked --workspace --exclude e-navigator-ebpf-programs
run cargo build --locked --workspace --exclude e-navigator-ebpf-programs
run cargo run --locked -p e-navigator-cli -- --source synthetic

if [ "${E_NAVIGATOR_SKIP_SUPPLY_CHAIN:-0}" != "1" ]; then
  require_tool cargo-deny
  require_tool cargo-audit
  require_tool cargo-machete
  run cargo deny check
  run cargo audit
  run cargo machete
else
  printf '\n==> skipped supply-chain checks\n'
fi

if [ "${E_NAVIGATOR_SKIP_DOCKER:-0}" != "1" ]; then
  require_tool docker
  run docker build -f Containerfile -t e-navigator:local .
  run docker run --rm e-navigator:local --source synthetic
  run tests/smoke_docker.sh e-navigator:local
else
  printf '\n==> skipped Docker checks\n'
fi

if [ "${E_NAVIGATOR_SKIP_KUBERNETES:-0}" != "1" ]; then
  require_tool helm
  require_tool kubeconform
  run helm lint charts/e-navigator
  run helm template e-navigator charts/e-navigator
  run kubeconform -strict -summary deploy/kubernetes/*.yaml
  run sh -c 'helm template e-navigator charts/e-navigator | kubeconform -strict -summary -'
else
  printf '\n==> skipped Kubernetes and Helm checks\n'
fi

run node website/check-links.mjs
run git diff --check
