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

- raw Aya userspace decode harnesses for exec, network, CPU profile, and
  protocol data event bytes;
- protocol request-stream reassembly (Redis pipelined chunk decode and Kafka
  split-frame reassembly through `RequestStreamDecoder`);
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
  exporter queue enqueue behavior;
- bounded signal-envelope construction and JSON stdout line serialization,
  including the argv-redacting and non-argv borrowed paths.

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

Focused protocol stream reassembly smoke from this development host:

```bash
cargo bench --locked -p e-navigator-local-benches --bench hot_paths -- \
  'protocol_stream|protocol_data'
```

- `protocol_stream/redis_pipeline_push_chunk`: 44.486-45.005 ns (two pipelined
  RESP commands reassembled and framed per iteration).
- `protocol_stream/kafka_split_frame_push_chunk`: 24.365-24.720 ns (one Kafka
  request frame split across two captured chunks per iteration).
- `aya_decode/protocol_data_fuzz_harness`: 1.6794-1.7021 us (full raw event
  decode path including per-call registry construction and procfs-miss
  container lookup; the steady-state source reuses one registry, so this is an
  upper bound for per-event decode cost, not a live capture claim).
- `protocol_stream/request_response_match`: 1.7394-1.7527 us for one full
  matched pair on a persistent registry: request raw-event decode, reassembly,
  parse, in-flight queue push, response raw-event decode, response parse, and
  matched observation emission including a procfs-miss container lookup.
  Re-measured after the multi-segment capture change (2026-07-05) at
  1.7190-1.7476 us; Criterion reported the change within its noise threshold,
  so single-segment matching cost is unregressed.
- `protocol_stream/segmented_syscall_splice`: 1.9247-1.9417 us (2026-07-05) for
  a three-segment 600-byte Redis SET spliced through the segment cursor,
  reassembled, parsed, and matched against its response on a persistent
  registry, including a procfs-miss container lookup. The extra two segments
  add roughly 0.2 us over the single-segment matched pair.

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

Focused allocation and protocol-request hot paths measured on 2026-07-09 on an
Apple M5 Pro (`Mac17,9`, macOS 26.5.2) with `rustc 1.96.0`:

```bash
cargo bench --locked -p e-navigator-local-benches --bench hot_paths -- \
  'protocol_stream/request_response_match|json/stdout|signal/network_open' \
  --sample-size 100 --measurement-time 5 --warm-up-time 3
```

The baseline was detached commit `3a88b7d` with only the benchmark cases added;
the optimized run used the same command and fixtures:

| Benchmark | Baseline | Optimized | Result |
| --- | --- | --- | --- |
| `protocol_stream/request_response_match` | 2.3825-2.4994 us | 1.3574-1.3792 us | ~44% lower central estimate |
| `json/stdout_network_line` | 0.99238-1.2683 us | 0.56346-0.56921 us | ~49% lower central estimate |
| `json/stdout_exec_line` | 1.1088-1.2305 us | 1.1442-1.1739 us | intervals overlap; no change claimed |
| `signal/network_open_envelope_sanitize` | 446.72-501.23 ns | 144.34-154.02 ns | ~68% lower central estimate |

These timings cover fixed-fixture userspace construction, sanitization,
serialization, protocol reassembly, response matching, and observation
emission. They do not measure stdout I/O, live procfs latency, kernel capture,
collector latency, or production throughput.

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

## Local Overhead Baseline (OrbStack, 2026-07-06)

A controlled A/B overhead measurement recorded on the local OrbStack Linux VM
(kernel `7.0.11-orbstack`, aarch64, 15 CPUs visible, Apple-Silicon host).
Workloads and the release-built agent ran in the same VM under privileged
Docker containers with the host pid namespace. This is a **local baseline,
not production proof**: the VM shares hardware with the host OS, containers
share the VM, and run counts are small (3 per arm). Numbers are medians of
3 runs; raw outputs are recorded below.

### Saturated Redis request capture (`source.aya_protocol`)

Workload: `redis-benchmark -n 200000 -c 50 -d 64 -t set,get` against a local
`redis-server 8.4.0` (no persistence). Three arms, run back-to-back in one
container session:

| Arm | SET rps | GET rps | SET p50/p95/p99 ms | GET p50/p95/p99 ms |
| --- | --- | --- | --- | --- |
| Baseline (no agent) | 386,100 | 386,100 | 0.079 / 0.127 / 0.143 | 0.079 / 0.127 / 0.151 |
| Agent on, watching a different port | 314,961 (-18%) | 316,456 (-18%) | 0.095-0.103 / 0.159 / 0.191 | 0.095 / 0.159 / 0.183 |
| Agent capturing the benchmarked port | 220,995 (-43%) | 217,155 (-44%) | 0.111 / 0.255 / 0.343 | 0.119 / 0.263 / 0.359 |

Agent userspace cost during full capture: ~0.52 CPU cores and 28 MB RSS
(313 ticks over 6 s at 100 Hz). Watching a non-matching port cost ~0 agent
userspace CPU and 22 MB RSS; its 18% throughput hit is in-kernel tracepoint
overhead on every read/write syscall at ~770k syscalls/second.

What this proves: the worst realistic case - request capture of a workload
saturating a loopback socket at ~386k requests/second with an observation
emitted per request. What it does not prove: overhead at production request
rates (orders of magnitude lower per node), wire-network workloads, or
non-loopback latency profiles; at lower rates both the per-event userspace
cost and the per-syscall in-kernel cost scale down proportionally.

### CPU profiling with DWARF + CPython unwinding (`source.aya_cpu_profile`)

Workload: CPython 3.12 nested-function busy loop reporting iterations per
fixed 15 s window; agent sampling at 99 Hz with DWARF unwind tables and the
CPython walker active (first refresh completed before measurement).

| Arm | Iterations / 15 s (3 runs) | Mean |
| --- | --- | --- |
| Baseline (no agent) | 37,651 / 37,434 / 37,825 | 37,637 |
| Agent profiling at 99 Hz | 37,694 / 37,651 / 37,580 | 37,642 |

Workload delta is within run-to-run noise (<0.5%). Agent cost: ~3.1% of one
CPU core (139 ticks over 45 s) and 60 MB RSS with unwind tables and shared
symbol caches for the busy host loaded (before the shared symbol cache this
was 412 MB; the fix is recorded in the capability history).

What this proves: sampling profiling with in-kernel DWARF and interpreter
unwinding is workload-neutral at 99 Hz on this host and the agent's own
footprint is bounded. What it does not prove: behavior at higher sampling
frequencies, wider process fleets than this VM ran (~250 registered
processes), or production node shapes.

Raw run logs for both A/Bs are retained in the session records for this date.

### Capture filter: excluded-workload per-syscall cost (`[capture_filter]`, 2026-07-07)

Workload: identical `redis-benchmark -n 50000 -c 20` against a Redis server, run
once in a captured namespace and once in a namespace excluded by an allowlist
capture-filter policy, on OrbStack Kubernetes v1.34 (arm64). The agent's
`source.aya_protocol`/`source.aya_network` were active in both arms; only the
capture filter differed.

| Arm | SET rps | GET rps | p50 latency |
| --- | --- | --- | --- |
| Captured (included namespace) | 134,048 | 148,809 | 0.079 ms |
| Filtered out (excluded namespace) | 190,114 | 210,970 | 0.063 ms |
| Delta | +42% | +42% | −20% |

What this proves: an excluded workload measurably reclaims per-syscall cost
because its connections are filtered at `connect()` and never tracked, so the
read/write capture path early-exits — the filter is an overhead lever, not only
a scope control. What it does not prove: a production overhead number. OrbStack
is a shared VM and this is a single-run local smoke A/B; the direction and
rough magnitude are consistent with the ~−43% cost of capturing this workload
recorded in the overhead baseline above, but the exact percentage is not a
production figure.
