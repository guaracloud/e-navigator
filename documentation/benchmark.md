# Benchmark And Proof Methodology

E-Navigator keeps performance evidence, local pipeline proof, packaging proof,
and privileged runtime proof separate. These layers answer different questions
and must not be merged into one readiness claim.

## Evidence Tiers

| Tier | Command or artifact | Proves | Does not prove |
| --- | --- | --- | --- |
| Local Criterion benchmarks | `benchmarks/runner/local-bench-smoke.sh` or `cargo bench --locked -p e-navigator-local-benches --bench hot_paths` | deterministic userspace hot paths compile and run under fixed fixtures | live eBPF attach, kernel event volume, Kubernetes scheduling, production exporter throughput |
| Synthetic pipeline | `cargo run --locked -p e-navigator-cli -- --source synthetic` | the shared runner path processes synthetic signals, including sanitized protocol request fixtures and flow-attribution warnings, through processors, generators, and JSON stdout | privileged Aya, live traffic capture, real procfs/sysfs/cgroup accuracy |
| Docker smoke | `docker build -f Containerfile -t e-navigator:local .` and `tests/smoke_docker.sh e-navigator:local` | the image runs the synthetic pipeline and validates packaged config fixtures | live kernel or cluster behavior |
| Kubernetes rendering | `helm lint charts/e-navigator` and `helm template e-navigator charts/e-navigator` | Helm and manifest schemas are valid for the declared DaemonSet shape | pods schedule, eBPF programs attach, host paths contain expected data |
| Guarded runtime proof | `E_NAVIGATOR_HOMELAB_CONFIRM=1 benchmarks/runner/homelab-collect.sh` after explicit approval | whatever the recorded run observed on a real cluster | anything absent from collected logs, pod state, metrics, workload output, or collector output |

## Local Benchmarks

The benchmark package lives in `benchmarks/runner/local-benches`.

Short smoke:

```bash
benchmarks/runner/local-bench-smoke.sh
```

Longer local pass:

```bash
cargo bench --locked -p e-navigator-local-benches --bench hot_paths
```

Current local benchmark targets:

- raw Aya userspace decode harnesses for exec, network, and CPU profile event
  bytes;
- procfs, loadavg, meminfo, diskstats, and process stat parser paths;
- traceparent, HTTP request/response fixture parsing, gRPC decoded HTTP/2
  metadata/trailer parsing, Kafka request-header and ApiVersions response
  parsing, MongoDB wire-message and response parsing, MySQL command packet
  parsing, NATS text command and response parsing, PostgreSQL wire-message
  parsing, and Redis RESP command parsing;
- profiling fixture normalization;
- Kubernetes pod-list JSON parsing and bounded metadata cache construction;
- generator hot paths for network, DNS, resource, dependency graph, trace,
  request, profiling, runtime security, and native export;
- JSON signal serialization, OpenTelemetry metric/trace/profile formatting,
  pprof profile sample protobuf rendering, Prometheus profile session/warning
  formatting, prefilled Prometheus latest-metric updates, and bounded HTTP
  exporter queue enqueue behavior.

Benchmark setup must stay outside measured loops where the code path supports
that. Benchmarks use fixed in-memory fixtures only. They must not read live
`/proc`, `/sys`, Kubernetes, network sockets, Docker, or host files inside a
Criterion measurement.

## Current Local Benchmark Status

Recent smoke runs prove the deterministic benchmark harness compiles and runs,
but they do not support a whole-harness performance-win claim. Focused formatter
work produced directional local improvements for metric/profile formatting, but
short-sample Criterion output is not production throughput proof.

Treat local Criterion output as:

- **valid** for hot-path hygiene and regression detection;
- **directional** for optimization work;
- **not valid** as live eBPF, Kubernetes, collector, or production overhead
  proof.

Focused Prometheus profile formatter smoke from this development host:

```bash
cargo bench --locked -p e-navigator-local-benches --bench hot_paths -- \
  --sample-size 10 formatter/prometheus_profile
```

- `formatter/prometheus_profile_session_write`: 6.1102-6.2853 us.
- `formatter/prometheus_profile_warning_write`: 2.9423-2.9558 us.

These timings measure fixed-fixture sink write formatting/storage only. They do
not prove scrape latency, production profile overhead, collector behavior, or
live kernel event cost. In this short local run, Criterion reported no
statistically significant session-write change and a small warning-write
regression against the prior local baseline, so the result is evidence of
benchmark coverage rather than an optimization claim.

Focused protocol error trace formatter smoke from this development host:

```bash
cargo bench --locked -p e-navigator-local-benches --bench hot_paths -- \
  --sample-size 10 formatter/otel_protocol_error_trace_record
```

- `formatter/otel_protocol_error_trace_record`: 1.5412-1.5687 us.

This timing measures fixed-fixture internal OpenTelemetry trace-record
formatting only. It does not prove OTLP collector latency, backend acceptance,
or live protocol capture overhead.

Focused pprof profile sample formatter smoke from this development host:

```bash
cargo bench --locked -p e-navigator-local-benches --bench hot_paths -- \
  --sample-size 10 formatter/pprof_profile_sample
```

- `formatter/pprof_profile_sample`: 3.7686-3.7823 us.

This timing measures fixed-fixture pprof protobuf rendering only. It does not
prove a runtime pprof endpoint, backend upload, storage behavior, or live
profiling overhead.

Focused network flow-byte aggregation smoke from this development host:

```bash
cargo bench --locked -p e-navigator-local-benches --bench hot_paths -- \
  --sample-size 10 generator/network_flow_byte_aggregation
```

- `generator/network_flow_byte_aggregation`: 2.1893-2.6888 us.

This timing measures fixed-fixture generator handling for byte-counted close
events across rotating remote destinations. It does not prove live eBPF event
volume, Prometheus scrape latency, or production network overhead.

Focused Kubernetes metadata cache-build smoke from this development host:

```bash
cargo bench --locked -p e-navigator-local-benches --bench hot_paths \
  processor/kubernetes_pod_list_cache_build -- --sample-size 10
```

- `processor/kubernetes_pod_list_cache_build`: 604.25-606.14 us.

This timing measures fixed-fixture parsing and bounded cache construction for
512 pods with container-ID and pod-IP indexes. It does not prove Kubernetes API
latency, watch/list behavior, live attribution coverage, or production cluster
overhead.

## Guarded Runtime Proof

The guarded collector writes evidence under `benchmarks/results/<timestamp>/`.
Timestamped raw directories are ignored by Git by default. Do not commit raw
logs, screenshots, Criterion reports, or large transient output. Public proof
belongs in [proof-report.md](proof-report.md).

Collection-only mode:

```bash
E_NAVIGATOR_HOMELAB_CONFIRM=1 \
E_NAVIGATOR_HOMELAB_CONTEXT=<context> \
benchmarks/runner/homelab-collect.sh
```

Apply-and-collect mode:

```bash
E_NAVIGATOR_HOMELAB_CONFIRM=1 \
E_NAVIGATOR_HOMELAB_APPLY=1 \
E_NAVIGATOR_HOMELAB_CONTEXT=<context> \
benchmarks/runner/homelab-collect.sh
```

Cleanup is explicit:

- `E_NAVIGATOR_HOMELAB_CLEANUP_WORKLOAD=1` deletes only the generated workload.
- `E_NAVIGATOR_HOMELAB_UNINSTALL_RELEASE=1` uninstalls the Helm release.
- `E_NAVIGATOR_HOMELAB_CLEANUP=1` remains a backward-compatible full cleanup
  switch.

## Published Proof Requirements

A runtime proof claim may be added to [proof-report.md](proof-report.md) only
when the run records:

- context, namespace, image tag, image digest, commit SHA, and Helm revision;
- rendered values/manifests and rollout state;
- pod placement, restart counts, security context, and capability posture when
  relevant;
- workload manifest, workload logs, and cleanup/restore result;
- E-Navigator logs or metrics containing the claimed signal;
- collector, Prometheus, or OTLP evidence when exporter behavior is claimed;
- explicit non-claims for every nearby capability not proven by the run.

## Proof Boundaries

Current local benchmarks prove repeatable userspace performance for fixed
fixtures and compile-time benchmark health only. They do not prove:

- privileged Aya/eBPF attachment;
- live DNS packet capture beyond recorded runtime runs;
- complete HTTP/gRPC parsing from real traffic;
- Kubernetes DaemonSet readiness;
- real host procfs/sysfs/cgroup accuracy;
- production OTLP, Prometheus, pprof, trace, profile, or storage behavior;
- reduced overhead, reduced privilege, or all-node capture symmetry.
