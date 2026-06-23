# Local Sample: Prometheus Compatibility Formatter Smoke

Run: `20260623-130410`

Raw evidence lives under `benchmarks/results/20260623-130410/`.

Scope: local non-privileged Criterion smoke plus targeted Rust verification.
No Kubernetes resources were created, updated, or deleted for this run.

Commands:

- `cargo fmt --all -- --check`
- `cargo test --locked -p e-navigator-sinks prometheus -- --nocapture`
- `cargo clippy --locked -p e-navigator-sinks --all-targets -- -D warnings`
- `benchmarks/runner/local-bench-smoke.sh`
- `cargo test --locked --workspace --exclude e-navigator-ebpf-programs`

Configuration:

- `sample_size=10`
- `measurement_time=1s`
- `warm_up_time=1s`

Observed evidence:

- Prometheus compatibility sink tests passed, including the stable
  `network_flow_bytes` text rendering test and the sensitive-label
  filtering tests.
- The workspace test suite passed after the formatter change.
- Criterion reported `formatter/prometheus_compat` improved from the previous
  local baseline: median change `-64.030%`, measured interval
  `2.0792 us` to `2.5384 us`.
- The same smoke still reported unrelated regressions for
  `protocol/http_fixture_parse`, `generator/network_metrics`, and
  `formatter/profile_record`.

Outcome: `partial`.

Proven:

- The Prometheus compatibility formatting hot path improved in this local
  Criterion smoke without changing the existing rendered metric contract.

Not proven:

- A whole-harness performance improvement.
- Live eBPF attach behavior, kernel event volume, Kubernetes scheduling,
  production exporter throughput, or live Prometheus scrape behavior.
