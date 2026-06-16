#!/usr/bin/env sh
set -eu

require_tool() {
  tool="$1"
  install="$2"
  if ! command -v "$tool" >/dev/null 2>&1; then
    printf '%s\n' "$tool is required for scripts/quality.sh; install with: $install" >&2
    missing_tools=1
  fi
}

optional_tool() {
  tool="$1"
  command="$2"
  if command -v "$tool" >/dev/null 2>&1; then
    printf '%s\n' "optional: $command"
  else
    printf '%s\n' "optional: $tool not installed; skipping $command"
  fi
}

missing_tools=0
if [ "${E_NAVIGATOR_SKIP_SUPPLY_CHAIN:-0}" != "1" ]; then
  require_tool cargo-deny 'cargo install cargo-deny --locked'
  require_tool cargo-audit 'cargo install cargo-audit --locked'
  require_tool cargo-machete 'cargo install cargo-machete --locked'
  if [ "$missing_tools" -ne 0 ]; then
    printf '%s\n' 'Set E_NAVIGATOR_SKIP_SUPPLY_CHAIN=1 only for constrained local environments.' >&2
    exit 1
  fi
else
  printf '%s\n' 'Skipping supply-chain checks because E_NAVIGATOR_SKIP_SUPPLY_CHAIN=1 is set.' >&2
fi

if [ "${E_NAVIGATOR_SKIP_DOCKER:-0}" != "1" ]; then
  require_tool docker 'install Docker Engine or Docker Desktop'
fi

if [ "${E_NAVIGATOR_SKIP_KUBERNETES:-0}" != "1" ]; then
  require_tool kubectl 'install kubectl'
fi

if [ "$missing_tools" -ne 0 ]; then
  exit 1
fi

cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets --exclude e-navigator-ebpf-programs -- -D warnings
cargo test --locked --workspace --exclude e-navigator-ebpf-programs
cargo build --locked --workspace --exclude e-navigator-ebpf-programs
cargo run --locked -p e-navigator-cli -- --source synthetic
git diff --check

if [ "${E_NAVIGATOR_SKIP_SUPPLY_CHAIN:-0}" != "1" ]; then
  cargo deny check
  cargo audit
  cargo machete
fi

if [ "${E_NAVIGATOR_SKIP_DOCKER:-0}" != "1" ]; then
  docker build -f Containerfile -t e-navigator:local .
  docker run --rm e-navigator:local --source synthetic >/dev/null
  tests/smoke_docker.sh e-navigator:local
else
  printf '%s\n' 'Skipping Docker checks because E_NAVIGATOR_SKIP_DOCKER=1 is set.' >&2
fi

if [ "${E_NAVIGATOR_SKIP_KUBERNETES:-0}" != "1" ]; then
  kubectl apply --dry-run=client -f deploy/kubernetes/namespace.yaml
  kubectl apply --dry-run=client -f deploy/kubernetes/rbac.yaml
  kubectl apply --dry-run=client -f deploy/kubernetes/configmap.yaml
  kubectl apply --dry-run=client -f deploy/kubernetes/daemonset.yaml
else
  printf '%s\n' 'Skipping Kubernetes dry-runs because E_NAVIGATOR_SKIP_KUBERNETES=1 is set.' >&2
fi

optional_tool cargo-nextest 'cargo nextest run --locked --workspace --exclude e-navigator-ebpf-programs'
optional_tool cargo-llvm-cov 'cargo llvm-cov --locked --workspace --exclude e-navigator-ebpf-programs --summary-only'
optional_tool cargo-fuzz 'cargo fuzz run traceparent_parser -- -max_total_time=60'
optional_tool cargo-mutants 'cargo mutants --package e-navigator-protocol --package e-navigator-profiling --package e-navigator-generators --timeout 60'
optional_tool typos 'typos'
optional_tool taplo 'taplo fmt --check Cargo.toml crates/*/Cargo.toml'
optional_tool yamllint 'yamllint .github/workflows/ci.yml deploy/kubernetes'
