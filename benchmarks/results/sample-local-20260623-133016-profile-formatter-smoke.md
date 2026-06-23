# Local Sample: Profile Formatter Smoke

Run: `20260623-133016`

Raw evidence lives under `benchmarks/results/20260623-133016/`.

Scope: local non-privileged Criterion smoke plus targeted Rust verification.
No Kubernetes resources were created, updated, or deleted for this run.

Commands:

- `cargo fmt --all -- --check`
- `cargo test --locked -p e-navigator-sinks --test profile_format -- --nocapture`
- `cargo clippy --locked -p e-navigator-sinks --all-targets -- -D warnings`
- `benchmarks/runner/local-bench-smoke.sh`
- `cargo test --locked --workspace --exclude e-navigator-ebpf-programs`
- `E_NAVIGATOR_SKIP_DOCKER=1 scripts/quality.sh`

Configuration:

- `sample_size=10`
- `measurement_time=1s`
- `warm_up_time=1s`

Observed evidence:

- Profile formatter integration tests passed, including exact profile ID
  stability and mixed-case sensitive attribute filtering.
- The workspace test suite passed after the formatter change.
- The Docker-skipped quality gate passed. Docker was skipped because the local
  Docker Desktop daemon remained wedged after a disk-full/read-only VM state.
- Criterion reported `formatter/profile_record` improved from the previous
  local baseline: median change `-61.889%`, measured interval `1.7037 us` to
  `1.7230 us`.
- The same smoke also reported `formatter/prometheus_compat` improved with
  median change `-13.625%`.
- The same smoke still reported unrelated or noisy regressions for
  `host_parser/cpu_stat`, `host_parser/loadavg`,
  `generator/dependency_graph`, `generator/request_correlation`, and
  `generator/profiling`.

Outcome: `partial`.

Proven:

- The profile formatter hot path improved in this local Criterion smoke without
  changing profile ID coverage or sensitive attribute filtering.

Not proven:

- A whole-harness performance improvement.
- Docker packaging on this workstation for this run.
- Live eBPF attach behavior, kernel event volume, Kubernetes scheduling,
  production exporter throughput, OTLP transport, Pyroscope export, or live
  Prometheus scrape behavior.
