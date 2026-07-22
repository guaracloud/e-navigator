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

- raw Aya userspace decode harnesses for exec, network, periodic/off-CPU/futex
  profile, and protocol data event bytes;
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
  request, profiling, runtime security, and native export, including unique
  network-open and DNS-query aggregation fixtures that cannot collapse into
  the duplicate-rejection fast path after warm-up;
- concurrent Aya source-telemetry summary-gate checks across four reader
  threads;
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

### Immediate generator dispatch, 2026-07-20

The built-in generators perform bounded synchronous derivation. The runner
formerly sent those results through a fresh Tokio channel and an async-trait
future for each accepted signal. They now use the existing immediate generator
contract, while retaining equivalent async behavior for direct trait callers.
The runner also moves the returned vector after validating its 64-output limit
instead of copying each item into a second vector.

The benchmark helper was first changed to mirror the runner: use
`observe_immediate` when present, otherwise create and drain the bounded async
channel. A pre-change baseline was then saved and compared with 100 samples,
five seconds of measurement, and two seconds of warmup:

```bash
cargo bench --locked -p e-navigator-local-benches --bench hot_paths -- \
  'generator/' \
  --save-baseline elite-grade-pre \
  --sample-size 100 \
  --measurement-time 5 \
  --warm-up-time 2

cargo bench --locked -p e-navigator-local-benches --bench hot_paths -- \
  'generator/' \
  --baseline elite-grade-pre \
  --sample-size 100 \
  --measurement-time 5 \
  --warm-up-time 2
```

| Benchmark | Before | After | Criterion result |
| --- | --- | --- | --- |
| Network metric duplicate path | 319.11-322.48 ns | 123.82-127.48 ns | 59.2% faster |
| Network open aggregation | 3.4315-3.4481 us | 2.7803-2.8581 us | 15.0% faster |
| Network flow-byte aggregation | 2.9771-3.0145 us | 2.1402-2.1926 us | 28.1% faster |
| DNS metric duplicate path | 316.67-318.30 ns | 123.25-127.87 ns | 61.1% faster |
| DNS query aggregation | 1.7620-1.8329 us | 1.5198-1.8547 us | no significant change |
| Resource metrics | 468.03-481.03 ns | 319.62-373.88 ns | 32.1% faster |
| Dependency graph | 441.75-444.68 ns | 301.57-314.79 ns | 34.1% faster |
| Trace correlation | 394.75-398.52 ns | 222.33-234.63 ns | 39.2% faster |
| Profiling | 355.81-364.08 ns | 186.40-199.84 ns | 44.8% faster |
| Runtime security | 689.33-699.45 ns | 428.28-450.53 ns | 34.9% faster |

The unchanged request-correlation immediate path acted as a control. A focused
200-sample repeat moved from 214.98-215.57 ns to 235.21-243.42 ns, a 12.4%
regression despite no implementation change in that generator. That movement
shows the sensitivity of sub-microsecond whole-binary measurements to local
conditions and code layout. The changed paths improved by substantially more
than the control movement, but these results remain scoped hot-path evidence,
not a claim about total node overhead.

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
measure runtime endpoint serving overhead, backend upload, storage behavior, or
live profiling overhead; endpoint proof is recorded separately in the proof
report.

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

Focused source-telemetry and network-key A/B measured on 2026-07-09 on an
Apple M5 Pro (`Mac17,9`, macOS 26.5.2) with `rustc 1.96.0`. Baseline and
optimized runs used identical fixtures, 100 samples, a 5-second warm-up, and a
10-second measurement for network aggregation; the telemetry fixture used a
3-second warm-up and 5-second measurement:

```bash
cargo bench --locked -p e-navigator-local-benches --bench hot_paths -- \
  'generator/network_(open_aggregation|flow_byte_aggregation)$' \
  --sample-size 100 --measurement-time 10 --warm-up-time 5

cargo bench --locked -p e-navigator-local-benches --bench hot_paths -- \
  'source_telemetry/summary_gate' \
  --sample-size 100 --measurement-time 5 --warm-up-time 3
```

| Benchmark | Baseline | Optimized | Criterion result |
| --- | --- | --- | --- |
| `source_telemetry/summary_gate_4_threads_2000_calls` | 578.38-585.02 us | 104.32-114.56 us | 80.1-81.3% lower, `p < 0.05` |
| `generator/network_open_aggregation` | 5.3471-5.5013 us | 5.0204-5.1797 us | 11.1-14.3% lower, `p < 0.05` |
| `generator/network_flow_byte_aggregation` | 10.547-12.393 us | 3.4713-3.5991 us | 69.6-75.7% lower, `p < 0.05` |

The telemetry case measures 8,000 concurrent summary-gate checks per
iteration; it does not include kernel capture. The network cases create a new
observation timestamp per iteration and therefore exercise aggregation and
bounded dedupe eviction rather than repeatedly returning from the duplicate
fast path. A proposed DNS normalization refactor was reverted because an
alternating focused A/B did not validate an improvement; no DNS performance
claim is made.

Focused procfs-parser and protocol-stream A/B measured on 2026-07-09 on the
same Apple M5 Pro development host with `rustc 1.96.0`. Both arms used 100
samples, a 3-second warm-up, a 5-second measurement, and Criterion's saved
baseline comparison:

```bash
cargo bench --locked -p e-navigator-local-benches --bench hot_paths -- \
  'host_parser/(cpu_stat|loadavg|diskstats|process_stat)|protocol_stream/redis_pipeline(_64)?_push_chunk' \
  --sample-size 100 --measurement-time 5 --warm-up-time 3 \
  --save-baseline pre-elite

cargo bench --locked -p e-navigator-local-benches --bench hot_paths -- \
  'host_parser/(cpu_stat|loadavg|diskstats|process_stat)|protocol_stream/redis_pipeline(_64)?_push_chunk' \
  --sample-size 100 --measurement-time 5 --warm-up-time 3 \
  --baseline pre-elite
```

| Benchmark | Baseline | Optimized | Criterion result |
| --- | --- | --- | --- |
| `host_parser/cpu_stat` | 193.15-195.62 ns | 108.19-108.91 ns | 44.2-45.1% lower, `p < 0.05` |
| `host_parser/loadavg` | 122.78-130.05 ns | 65.405-66.429 ns | 46.6-49.4% lower, `p < 0.05` |
| `host_parser/diskstats` | 257.49-264.91 ns | 117.76-118.45 ns | 53.7-54.7% lower, `p < 0.05` |
| `host_parser/process_stat` | 424.30-427.18 ns | 229.04-231.64 ns | 47.0-48.1% lower, `p < 0.05` |
| `protocol_stream/redis_pipeline_push_chunk` | 57.310-58.757 ns | 53.587-54.009 ns | 5.2-8.2% lower, `p < 0.05` |
| `protocol_stream/redis_pipeline_64_push_chunk` | 2.0299-2.0843 us | 1.3055-1.3127 us | 36.8-38.4% lower, `p < 0.05` |

The parser cases measure fixed procfs fixtures after removing temporary token
vectors; they do not include filesystem I/O. The stream cases measure bounded
RESP frame extraction after changing unread-tail compaction from once per
frame to at most once per pushed chunk; they do not measure kernel capture or
network I/O.

Focused normalization, sanitization, and meminfo-parser A/B measured on
2026-07-10 on the same Apple M5 Pro development host with `rustc 1.96.0`.
Both arms used identical fixtures, 100 samples, a 2-second warm-up, a 5-second
measurement, and Criterion saved-baseline comparisons:

```bash
cargo bench --locked -p e-navigator-local-benches --bench hot_paths -- \
  '(host_parser/meminfo$|host_parser/meminfo_realistic|profiling/fixture_normalize|profiling/owned_sample_normalize_64_frames|signal/network_open_envelope_sanitize)' \
  --save-baseline elite2_pre --sample-size 100 --warm-up-time 2 \
  --measurement-time 5

cargo bench --locked -p e-navigator-local-benches --bench hot_paths -- \
  '(host_parser/meminfo$|host_parser/meminfo_realistic|profiling/fixture_normalize|profiling/owned_sample_normalize_64_frames|signal/network_open_envelope_sanitize)' \
  --baseline elite2_pre --sample-size 100 --warm-up-time 2 \
  --measurement-time 5

cargo bench --locked -p e-navigator-local-benches --bench hot_paths -- \
  'generator/profiling$' --save-baseline elite2_gen_pre \
  --sample-size 100 --warm-up-time 2 --measurement-time 5

cargo bench --locked -p e-navigator-local-benches --bench hot_paths -- \
  'generator/profiling$' --baseline elite2_gen_pre \
  --sample-size 100 --warm-up-time 2 --measurement-time 5

cargo bench --locked -p e-navigator-local-benches --bench hot_paths -- \
  'signal/network_open_envelope_sanitize' \
  --save-baseline elite2_signal_alt_pre --sample-size 100 \
  --warm-up-time 2 --measurement-time 5

cargo bench --locked -p e-navigator-local-benches --bench hot_paths -- \
  'signal/network_open_envelope_sanitize' \
  --baseline elite2_signal_alt_pre --sample-size 100 \
  --warm-up-time 2 --measurement-time 5
```

| Benchmark | Baseline | Optimized | Criterion result |
| --- | --- | --- | --- |
| `host_parser/meminfo` | 273.96-278.28 ns | 191.95-200.53 ns | 28.8-30.7% lower, `p < 0.05` |
| `host_parser/meminfo_realistic` | 509.84-520.56 ns | 406.20-415.65 ns | 22.6-25.3% lower, `p < 0.05` |
| `profiling/fixture_normalize` | 2.3990-2.4329 us | 2.2020-2.2279 us | 8.3-9.7% lower, `p < 0.05` |
| `profiling/owned_sample_normalize_64_frames` | 12.571-12.872 us | 7.9298-8.0184 us | 36.4-37.6% lower, `p < 0.05` |
| `generator/profiling` | 322.49-336.49 ns | 230.84-243.00 ns | 26.2-30.3% lower, `p < 0.05` |
| `signal/network_open_envelope_sanitize` (immediate alternating A/B) | 175.26-184.16 ns | 165.67-200.72 ns | mean comparison 11.5-28.5% lower, `p < 0.05`; slope intervals overlap |

The owned profile benchmark excludes fixture cloning from the measured routine
and exercises 64 frames plus 16 attributes. The signal fixture includes one
already-bounded Kubernetes label. These results support only the fixed-fixture
userspace paths: they do not measure procfs file I/O, kernel event transport,
live profile symbolization, or production request volume. The label sanitizer
also had a later full-filter run in which Criterion detected no change, so its
tree-rebuild allocation removal is retained but no stable latency percentage
is claimed for that path.

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

### Capture filter: cgroup hierarchy fail-closed proof (2026-07-22)

The guarded homelab harness ran the same image and Aya exec source against the
real unified v2 mount and a legacy `tasks` marker fixture on `homelab-01`. Both
arms configured unknown cgroups to allow, and a Job made 300 external exec
attempts after readiness.

| Arm | Detected mode | Compatible | Fail-closed | Decoded/sent | Kernel drops |
| --- | --- | ---: | ---: | ---: | ---: |
| Real host root | `unified_v2` | 1 | 0 | 3,135 / 3,135 | 0 |
| Legacy marker fixture | `legacy_v1` | 0 | 1 | 0 / 0 | 3,012 |

This proves that the unsupported-mode posture is applied before Aya program
attachment and remains visible in native metrics and kernel accounting. The
legacy arm is a fixture on a v2 node, not a benchmark or a claim of cgroup v1
support. Method, image identity, exact metrics, logs, limitations, and cleanup
are in the [cgroup hierarchy proof](proof/cgroup-hierarchy-20260722/report.md).

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
read/write capture path early-exits. The filter is an overhead lever, not only
a scope control. What it does not prove: a production overhead number. OrbStack
is a shared VM and this is a single-run local smoke A/B; the direction and
rough magnitude are consistent with the ~−43% cost of capturing this workload
recorded in the overhead baseline above, but the exact percentage is not a
production figure.

## BPF Event Transport A/B (Homelab, 2026-07-21)

The RingBuf migration used the guarded homelab collector with a dedicated
connection-heavy HTTP workload, exec churn, two Linux 6.6 nodes, and only the
exec/network Aya source slice enabled. Three 180-second repetitions per arm
were counterbalanced as `none/perf/ring`, `ring/none/perf`, and
`perf/ring/none`. The no-agent arm means no E-Navigator benchmark release; the
homelab's unrelated background observability stack remained constant.

| Arm | Requests/s mean +/- sd | Mean latency ms +/- sd | Agent CPU m +/- sd | Agent RSS MiB +/- sd |
| --- | ---: | ---: | ---: | ---: |
| no benchmark agent | 41.955000 +/- 0.000000 | 95.316655 +/- 1.789863 | n/a | n/a |
| perf | 42.073667 +/- 0.205537 | 94.424151 +/- 2.806871 | 83.991533 +/- 3.585834 | 65.544861 +/- 0.039762 |
| ring | 41.837000 +/- 0.410496 | 95.799402 +/- 3.191258 | 93.570370 +/- 1.468405 | 62.630423 +/- 0.677374 |

RingBuf versus perf was -0.562506% requests/s, +1.456461% mean latency,
+11.404527% agent CPU across two pods, and -4.446478% agent RSS. Both paths
reported zero transport loss for the enabled sources. The coarse p95/p99
histogram, short windows, shared-node background activity, and small failure
counts prevent a comparative performance claim.

A focused 30-sample Criterion run measured the contiguous 368-byte handoff at
669.42-670.44 ps for the perf inline copy and 297.04-316.02 ps for the borrowed
RingBuf record. That is an isolated userspace handoff result, not live agent
overhead. Full method, raw run values, variance, image identity, and cleanup
scope are recorded in the
[`event-transport proof report`](proof/event-transport-20260721/report.md).

## Network Kernel-Hook A/B (Homelab, 2026-07-21)

The scalar network read/write hook evaluation used a pinned Python workload on
`homelab-01` with one loopback TCP connection and exact 256-byte
`os.write`/`os.read` round trips. RingBuf and the network-only module profile
were held constant. Three 90-second repetitions per arm were counterbalanced as
`none/tracepoint/fexit`, `fexit/none/tracepoint`, and
`tracepoint/fexit/none`.

| Arm | Operations/s mean +/- sd | Mean latency us +/- sd | Agent CPU m +/- sd | Agent RSS MiB +/- sd |
| --- | ---: | ---: | ---: | ---: |
| no benchmark agent | 39,452.230 +/- 230.731 | 23.467 +/- 0.133 | n/a | n/a |
| tracepoint | 33,965.449 +/- 1,344.217 | 27.378 +/- 1.053 | 13.965 +/- 1.827 | 20.611 +/- 1.058 |
| fexit | 36,672.691 +/- 148.847 | 25.267 +/- 0.080 | 13.984 +/- 2.770 | 34.000 +/- 1.000 |

The predeclared adoption gate required exact byte parity, zero loss, at least
5% more throughput than tracepoints, and no more than 2% worse mean latency.
Fexit passed: +7.970576% operations/s and -7.710353% mean latency. It remained
-7.045329% below the no-agent arm and used about 13.4 MiB more summed two-pod
RSS than tracepoints. Every enabled arm emitted exactly one matching close
signal with `operations * 256` bytes in both directions and reported zero
transport loss.

This is a narrow scalar read/write result, not a mixed-workload, vectored-I/O,
`send*`/`recv*`, lower-memory, production, or whole-stack overhead claim. Full
method, normalized run values, image identity, and cleanup scope are recorded
in the [`kernel-hook proof report`](proof/kernel-hook-20260721/report.md).

## Profiling Breadth A/B (Homelab, 2026-07-22)

The profiling campaign used a pinned CPython 3.11.15 workload on `homelab-01`
with a nested CPU-bound call chain, two sleepers, three mutex contenders, and
one lock holder. Three 60-second repetitions compared no benchmark agent with
an agent enabling only periodic 11 Hz CPU, scheduler off-CPU, and futex-wait
lock profiling. Run order was counterbalanced as `none/profiling`,
`profiling/none`, and `none/profiling`.

| Arm | Busy batches/s mean +/- sd | Agent CPU m mean +/- sd | Agent memory MiB mean +/- sd |
| --- | ---: | ---: | ---: |
| no benchmark agent | 4,753.099 +/- 56.078 | n/a | n/a |
| profiling | 4,655.687 +/- 33.739 | 78.162 +/- 13.175 | 205.861 +/- 5.263 |

The profiling arm measured 2.049% lower busy-loop throughput. All profiling
runs contained named CPython 3.11 frames, on-CPU, off-CPU, and futex-wait
samples, positive event duration weights, and a non-empty pprof payload. Every
run reported zero pending misses, state replacements, transport loss, perf
loss, and RingBuf reservation failures. The stack-capture failure rate ranged
from 0.0042 to 0.0049%, below the declared 0.1% gate.

This is one pinned application on a shared cluster, not a mixed-workload,
higher-rate, backend, JVM/V8, dedicated-node, or production overhead claim.
Exact normalized values, configuration, workload, image identity, and cleanup
scope are recorded in the
[`profiling-breadth proof report`](proof/profiling-breadth-20260722/report.md).

A focused local Criterion run measured raw decode medians of 1.607 microseconds
for on-CPU, 1.573 microseconds for off-CPU, and 1.935 microseconds for
futex-wait samples. The raw event fuzz target executed 1,344,282 inputs in 21
seconds without a failure. Those local numbers are decoder hygiene, not kernel
or whole-agent overhead.

## Browser Protocol Surface A/B (Homelab, 2026-07-22)

The browser-protocol campaign used a pinned Python workload with an
extension-free raw WebSocket exchange, binary-request/text-response gRPC-Web,
and a real aioquic HTTP/3 exchange as a negative control. Three 30-second
repetitions compared no benchmark agent with an agent enabling only
`source.aya_protocol` on both Linux 6.6.68 nodes. Run order was counterbalanced
as `none/protocol`, `protocol/none`, and `none/protocol`.

| Arm | Operations/s mean +/- sd | Iteration p95 ms mean +/- sd | Agent CPU m mean +/- sd | Agent memory MiB mean +/- sd |
| --- | ---: | ---: | ---: | ---: |
| no benchmark agent | 19.862091 +/- 0.002021 | 0.858090 +/- 0.018113 | n/a | n/a |
| protocol source | 19.852290 +/- 0.006286 | 0.938343 +/- 0.022766 | 39.386905 +/- 13.970088 | 23.345238 +/- 0.135212 |

The protocol arm measured 0.049345% fewer operations per second. Every protocol
run recorded exact semantic/native parity at 298 WebSocket upgrades, 596
WebSocket frames, and 298 gRPC-Web requests, with zero transition rejections,
zero transport loss, and zero false HTTP/3 or QUIC semantic observations.

The 100 ms pacing interval dominated application throughput, each arm lasted
only 30 seconds, and the two shared nodes retained unrelated background work.
The p95 iteration latency mean was 9.35% higher with the source, but this
campaign was designed for correctness and a negative protocol boundary. It
does not support a general or production overhead claim. Exact normalized
values, semantic/native counter gates, image identity, and cleanup scope are in
the [`browser-protocol proof report`](proof/protocol-surface-20260722/report.md).

A focused local Criterion run measured WebSocket upgrade detection at 339.92
to 346.98 ns, 1 KiB frame boundary and metadata handling at 3.1090 to 4.1909
ns, gRPC-Web request parsing at 1.1899 to 1.2784 microseconds, and response
parsing at 841.88 to 852.95 ns. Both dedicated fuzz targets ran for 20 seconds
without a failure. These are parser hygiene results, not live overhead proof.

## Reduced Privilege Matrix (Homelab, 2026-07-22)

The reduced-privilege campaign used no-agent controls and one source at a time
on both Linux 6.6.68 homelab nodes. The general workload ran as UID 65532 and
repeated exec, DNS, HTTP, Redis, and CPU work for 30 seconds. A separate Go
1.26.4 workload ran 4,000 HTTPS requests in both the no-agent and TLS arms.

| Source | Effective capabilities | Workload-correlated signals |
| --- | --- | ---: |
| Exec | `BPF`, `PERFMON` | 776 |
| Network | `BPF`, `PERFMON` | 500 |
| DNS | `BPF`, `PERFMON` | 6,058 |
| Cleartext HTTP | `BPF`, `PERFMON` | 1,502 |
| Redis protocol | `BPF`, `PERFMON` | 1,544 |
| CPU profile | `BPF`, `PERFMON`, `SYS_PTRACE` | 1 strict Python match |
| Host resource | none | 7,788 |
| Go TLS | `BPF`, `PERFMON`, `SYS_PTRACE` | 7,988 |

Every positive arm had two ready pods with zero restarts, exact effective
capabilities, `NoNewPrivs: 1`, `Seccomp: 2`, and zero transport, ring-buffer
reservation, or send loss. The analyzer matched deterministic workload fields,
not signal kind alone. The CPU count is deliberately the one sample satisfying
all non-root Python and resolved-symbol predicates; native metrics recorded
14,567 decoded and sent CPU samples.

This matrix proves correctness under the scoped capability sets. The arms were
not counterbalanced performance trials, and the short no-agent results support
no overhead comparison. Full methodology, image identity, native totals, and
cleanup state are in the
[`reduced-privilege proof report`](proof/reduced-privilege-20260722/report.md).

## Capture-Filter Bootstrap Window (Homelab, 2026-07-22)

The guarded campaign compared the preserved 2-second polling mode with
bounded event-driven inotify discovery. A non-root Python workload was pinned
to `homelab-01`, recorded its start timestamp, then immediately executed a
unique probe path every 10 milliseconds for six seconds. The allowlist used
`unknown_cgroup = "deny"`. One no-agent control and five repetitions per agent
mode were run; agent order alternated polling/event and event/polling.

| Mode | First-signal window median, ms | P95, ms | Mean, ms | Standard deviation, ms |
| --- | ---: | ---: | ---: | ---: |
| 2-second polling | 1148.131 | 1216.842 | 1109.394 | 105.194 |
| Event driven | 0.463 | 0.487 | 0.464 | 0.016 |

Event-driven discovery reduced the median observed window by 1147.667 ms, or
99.959648%, and improved p95. The five event-driven values ranged from 0.443
to 0.487 ms; polling ranged from 987.286 to 1216.842 ms. Event-driven runs
captured 521 or 522 workload signals, while polling runs captured 416 to 436
because initial probes followed the deny posture.

Native accounting across the five event-driven runs recorded 120 discovery
notifications, 116 event reconciliations, and 30 inotify events. Every agent
run reported zero inotify failures, queue overflows, watch-limit drops,
map-application failures, transport loss, perf loss, RingBuf reservation
failures, and userspace send failures. The no-agent control completed 523
probes without a workload failure.

This is a new-Pod exec result on one shared Linux 6.6.68 k3s cluster. It does
not prove instant policy changes, every runtime/cgroup driver, sustained churn,
production behavior, or a whole-agent overhead reduction. Full per-run values,
image identity, method, and cleanup state are in the
[`bootstrap-window proof report`](proof/bootstrap-window-20260722/report.md).

A focused local Criterion run measured one-slot coalescing of 64 notifications
at 53.112 to 53.664 ns. That is local hot-path hygiene, not live overhead.

## Invalidated Full-Stack Optimization Campaign (Homelab, 2026-07-22)

Status: invalid for comparative claims. The Redis proxy opened its backend
connection before collector attachment, so all E-Navigator Redis arms missed
the complete Redis family. Their 10,800 source signals covered only the 6,000
HTTP and 4,800 gRPC operations, below the 20,400 cumulative protocol floor.
The aggregate signal gate accepted those arms and was insufficient. The
tables in this section remain historical diagnostics only. See the
[`erratum`](proof/optimization-20260722/ERRATUM.md) and the
[`corrected rerun report`](proof/optimization-20260722-campaign2/report.md).

The flagship guarded campaign kept five services active under every condition:
HTTP at 100 requests/s, gRPC at 80 calls/s, Redis at 160 operations/s,
PostgreSQL at 50 operations/s, and CPU-bound Python at 8 operations/s. Servers
and observed collectors ran on `homelab-02`; the fixed-rate load generator and
opaque OTLP trace sink ran on `homelab-01`. Both nodes were amd64 NixOS 24.05
on Linux 6.6.68 and k3s v1.30.4.

Three no-agent repetitions and three repetitions for each cumulative signal
stage of each stack produced 33 accepted runs. Stages added HTTP, gRPC, Redis,
PostgreSQL, then 10 Hz periodic CPU profiles. Every run used a 15-second
warmup and a 45-second measurement. Beyla 3.28.0 and Alloy 1.18.0 were pinned
by image digest; the Beyla 1.16.10 chart archive was pinned by checksum. Local
E-Navigator and workload images were loaded directly into both homelab nodes
and never pushed. The corrected harness suspended both the parent `root-app`
and child `e-navigator` Argo CD applications, deleted the standing DaemonSet,
and asserted its absence initially and before and after all 33 arms. The
earlier capture is retained as invalidated diagnostic history because it did
not enforce that parent-application boundary.

Final-stack application values below are means across three repetitions with
sample standard deviation after `+/-`. Throughput followed the fixed offered
rate and all operations succeeded, so it is a pacing and correctness check,
not a capacity result.

| Family | Condition | Throughput/s | p50 us | p95 us | p99 us |
| --- | --- | ---: | ---: | ---: | ---: |
| HTTP | no agent | 100.010226 +/- 0.000591 | 1767.000 +/- 13.115 | 6088.000 +/- 353.467 | 6916.000 +/- 35.000 |
| HTTP | Beyla plus Alloy | 100.010123 +/- 0.001114 | 1817.000 +/- 6.000 | 6347.667 +/- 178.262 | 6993.667 +/- 34.948 |
| HTTP | E-Navigator | 100.009620 +/- 0.000785 | 1838.000 +/- 12.166 | 6253.667 +/- 287.243 | 6999.000 +/- 10.440 |
| gRPC | no agent | 80.008181 +/- 0.000473 | 2797.333 +/- 24.947 | 3770.000 +/- 154.522 | 5249.000 +/- 164.794 |
| gRPC | Beyla plus Alloy | 80.008098 +/- 0.000891 | 2937.000 +/- 11.533 | 4078.333 +/- 36.295 | 5333.667 +/- 167.936 |
| gRPC | E-Navigator | 80.007696 +/- 0.000628 | 2977.333 +/- 20.033 | 4470.000 +/- 161.391 | 5798.000 +/- 153.873 |
| Redis | no agent | 160.016361 +/- 0.000946 | 954.667 +/- 7.095 | 1586.000 +/- 64.954 | 2447.333 +/- 228.354 |
| Redis | Beyla plus Alloy | 160.016196 +/- 0.001782 | 1076.000 +/- 13.000 | 1883.667 +/- 15.503 | 2888.667 +/- 15.011 |
| Redis | E-Navigator | 160.015392 +/- 0.001256 | 1041.333 +/- 5.033 | 2006.667 +/- 55.967 | 3071.667 +/- 117.458 |
| PostgreSQL | no agent | 50.005113 +/- 0.000296 | 1092.667 +/- 40.857 | 1972.000 +/- 155.242 | 3481.333 +/- 254.129 |
| PostgreSQL | Beyla plus Alloy | 50.005061 +/- 0.000557 | 1196.000 +/- 36.014 | 2351.667 +/- 21.962 | 3961.667 +/- 177.858 |
| PostgreSQL | E-Navigator | 50.004810 +/- 0.000393 | 1395.333 +/- 48.881 | 2665.000 +/- 117.320 | 3985.667 +/- 36.364 |
| Python CPU | no agent | 8.000818 +/- 0.000047 | 30110.000 +/- 157.617 | 43970.333 +/- 932.543 | 49783.333 +/- 2517.339 |
| Python CPU | Beyla plus Alloy | 8.000810 +/- 0.000089 | 30410.000 +/- 78.886 | 44094.667 +/- 4039.664 | 51954.333 +/- 1701.497 |
| Python CPU | E-Navigator | 8.000770 +/- 0.000063 | 31155.000 +/- 93.920 | 41493.000 +/- 3302.583 | 52031.000 +/- 1959.936 |

The cumulative collector resources were:

| Stage | Beyla or Beyla plus Alloy CPU m | E-Navigator CPU m | Beyla or Beyla plus Alloy RSS MiB | E-Navigator RSS MiB |
| --- | ---: | ---: | ---: | ---: |
| HTTP | 27.898294 +/- 1.867604 | 32.438155 +/- 2.089083 | 25.511719 +/- 0.637046 | 11.029948 +/- 0.030033 |
| plus gRPC | 34.747475 +/- 1.151602 | 63.770120 +/- 4.082139 | 27.834201 +/- 2.137823 | 18.043837 +/- 0.178021 |
| plus Redis | 41.558824 +/- 0.831611 | 69.372705 +/- 3.991127 | 25.292101 +/- 0.222520 | 18.467882 +/- 0.293435 |
| plus PostgreSQL | 45.508600 +/- 1.363484 | 91.127337 +/- 4.422200 | 24.538628 +/- 1.201238 | 21.107639 +/- 0.175063 |
| plus profiles | 75.859599 +/- 6.058294 | 97.150478 +/- 4.096372 | 128.862413 +/- 7.335634 | 46.288628 +/- 2.594171 |

The final-stage differences cannot support a CPU or RSS claim because the
E-Navigator workload omitted Redis capture while the reference arm observed
the offered Redis operations.

The final E-Navigator runs decoded 110,830 source samples and sent 69,482
source signals with zero hard-loss increments. Their asynchronous boundary
scrapes recorded 68,621 traces enqueued and 68,624 sent, plus 860 profiles
enqueued and 861 sent. Final Beyla application metrics accounted for all HTTP,
Redis, and PostgreSQL operations while leaving 26 of 14,400 gRPC calls
unaccounted. Alloy collected and forwarded 38 profiles with zero drops and
zero failing sessions.

Matched 45-second allocation diagnostics reduced E-Navigator libc allocator
calls from 8,509,242 to 5,644,163, or 33.670202%, and requested bytes from
925,090,490 to 692,293,775, or 25.164751%. The final values still exceeded the
combined Beyla and Alloy counters by 143.440915% in calls and 139.416141% in
bytes. This comparison is descriptive because E-Navigator was measured at
libc entry points while the Go processes were measured through
`runtime.mallocgc` and Go runtime counters.

Node-level container CPU and working-set memory were also recorded for every
stage and repetition. They include unrelated shared-cluster work and are not
total host utilization. In particular, `homelab-01` no-agent CPU exceeded the
final agent-arm values, so node totals support variance disclosure, not causal
agent subtraction.

This historical capture does not prove comparative CPU, RSS, allocations,
throughput, latency, saturation capacity, production behavior, sustained-load
stability, backend storage equivalence, total host utilization, or universal
loss behavior. Exact invalidation evidence is in the
[`optimization campaign erratum`](proof/optimization-20260722/ERRATUM.md).
