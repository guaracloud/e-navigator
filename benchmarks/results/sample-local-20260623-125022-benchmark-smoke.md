# Local Sample: Criterion Hot-Path Smoke

Run: `20260623-125022`

Raw evidence lives under `benchmarks/results/20260623-125022/`.

Scope: local non-privileged Criterion smoke only. No Kubernetes resources were
created, updated, or deleted for this run.

Command:

- `benchmarks/runner/local-bench-smoke.sh`

Configuration:

- `sample_size=10`
- `measurement_time=1s`
- `warm_up_time=1s`

Observed evidence:

- The benchmark crate compiled successfully in the optimized bench profile.
- The smoke run exited `0`.
- Stable or no-change paths included exec/network raw decode, meminfo,
  diskstats, process stat parsing, profiling normalization, network metrics,
  DNS metrics within threshold, resource metrics, dependency graph,
  trace/request correlation, profiling, runtime security, profile record
  formatting, and bounded exporter queue enqueue.
- Criterion reported statistically significant improvements for
  `protocol/traceparent_parse` and `generator/network_metrics`.
- Criterion reported statistically significant regressions for
  `aya_decode/cpu_profile_fuzz_harness`, `host_parser/cpu_stat`,
  `host_parser/loadavg`, `protocol/http_fixture_parse`,
  `json/signal_to_vec`, and `formatter/prometheus_compat`.

Outcome: `partial`.

Proven:

- The deterministic local benchmark harness still compiles and runs across the
  parser, decode, generator, formatter, and queue fixture paths.

Not proven:

- Live eBPF attach behavior, kernel event volume, Kubernetes scheduling,
  production exporter throughput, or live resource overhead.
- A performance improvement over previous local baselines. Several measured
  fixture paths need follow-up before making a positive performance claim.
