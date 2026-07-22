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
run python3 scripts/check_docs.py
run python3 scripts/release.py check
run cargo clippy --locked --workspace --all-targets --exclude e-navigator-ebpf-programs -- -D warnings
run env "RUSTDOCFLAGS=-D warnings" cargo doc --locked --workspace --no-deps --exclude e-navigator-ebpf-programs
run cargo test --locked --workspace --exclude e-navigator-ebpf-programs
run cargo build --locked --workspace --exclude e-navigator-ebpf-programs
run bash scripts/fuzz_check.sh
run cargo run --locked -p e-navigator-cli -- --validate-config --config documentation/examples/production-performance.toml
run cargo run --locked -p e-navigator-cli -- --source synthetic
run tests/homelab_bench_guard_test.sh
run tests/packaged_config_guard_test.sh
run tests/secret_pattern_guard_test.sh
run tests/network_einprogress_guard_test.sh
run tests/network_socket_io_guard_test.sh
run tests/dns_connected_udp_guard_test.sh
run tests/http_request_capture_guard_test.sh
run tests/event_transport_guard_test.sh
run env PYTHONDONTWRITEBYTECODE=1 python3 tests/event_transport_analysis_test.py
run tests/kernel_hook_bench_guard_test.sh
run env PYTHONDONTWRITEBYTECODE=1 python3 tests/kernel_hook_analysis_test.py
run tests/go_tls_bench_guard_test.sh
run env PYTHONDONTWRITEBYTECODE=1 python3 tests/go_tls_analysis_test.py
run tests/profiling_breadth_bench_guard_test.sh
run env PYTHONDONTWRITEBYTECODE=1 python3 tests/profiling_breadth_analysis_test.py
run tests/reduced_privilege_guard_test.sh
run env PYTHONDONTWRITEBYTECODE=1 python3 tests/reduced_privilege_analysis_test.py
run tests/bootstrap_window_guard_test.sh
run env PYTHONDONTWRITEBYTECODE=1 python3 tests/bootstrap_window_analysis_test.py

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
  run helm lint charts/e-navigator --values charts/e-navigator/values-guara-production.yaml
  run helm lint charts/e-navigator --values charts/e-navigator/values-reduced-privilege.yaml
  run tests/chart_service_guard_test.sh
  run helm template e-navigator charts/e-navigator
  run kubeconform -strict -summary deploy/kubernetes/*.yaml
  run sh -c 'helm template e-navigator charts/e-navigator | kubeconform -strict -summary -'
else
  printf '\n==> skipped Kubernetes and Helm checks\n'
fi

run node website/check-links.mjs
run git diff --check
