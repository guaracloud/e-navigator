# Evidence-Driven Optimization Campaign 7

Date: 2026-08-24

Status: **RETAINED HOT-PATH WIN, OVERALL NO-GO**. The sensitive attribute-key
matcher is measurably faster and remains behavior-equivalent under property
testing. The fresh 33-arm homelab comparison, however, measured E-Navigator at
25.783671% more CPU than combined Beyla plus Alloy. It used 10.337372% less
RSS, but that memory win does not meet the requested CPU-and-memory footprint
goal.

Nothing was pushed. The campaign used only `kubectl --context homelab` for
temporary benchmark resources. The standing deployment was not changed
persistently: the harness temporarily isolated it, then restored its recorded
Argo automation, image, and 2/2 Ready DaemonSet state.

## Retained Change

`is_sensitive_attribute_key` no longer calls `to_ascii_lowercase` for every
byte it scans. Its direct `a/A`, `c/C`, `j/J`, `p/P`, `s/S`, and `t/T` dispatch
has the same case-insensitive ASCII substring behavior and remains allocation
free. A property test generates arbitrary ASCII keys and compares the result
with the reference matcher.

The representative request-span mix improved from 279.866 ns to 250.896 ns:
an estimated mean change of -10.351363%, with a 95% confidence interval of
-12.257% to -8.400%. The candidate HashSet trace cache and a shared cache
abstraction both regressed focused duplicate paths, so both experiments were
fully reverted.

The permanent `generator/trace_correlation_unique_at_capacity` benchmark now
covers the 8,192-entry bounded trace cache under unique churn. Its current
95% interval is 1.5103-1.6266 microseconds, with a 1.5658 microsecond median.

## Local Before And After

The privileged local whole-agent harness ran three pre-change and three
post-change Redis arms at 800 operations/second, with 8 seconds warmup,
5 seconds attachment settle, and 45 seconds measured time. Every arm completed
36,000 of 36,000 operations with zero errors.

| Metric | Pre-change mean | Post-change mean | Change |
| --- | ---: | ---: | ---: |
| Agent CPU | 49.398326 mCPU | 48.772956 mCPU | -1.265974% |
| RSS | 45,121.333 KiB | 43,968 KiB | -2.556071% |
| RSS high-water mark | 50,540 KiB | 50,522.667 KiB | -0.034296% |
| Redis p50 | 277.667 us | 301.333 us | +8.523% |
| Redis p95 | 1,101.667 us | 1,150.667 us | +4.448% |
| Redis p99 | 3,366.667 us | 3,773.667 us | +12.089% |

This shared-VM harness is directional evidence. It corroborates the focused
CPU and RSS improvement but does not qualify the latency variation as an
end-to-end latency regression or win.

## Fresh Homelab Comparison

The final image was built locally for `linux/amd64`, loaded directly into both
homelab node-local containerd stores, and never pushed. The post-change agent
binary SHA-256 was
`bf01e5871797cfa8b515f5229279b2f47ade6d29112a39b5a42d42c5b8c50f26`.
The pre-change binary was
`f61579fc5f2d2eaa7d7beadaf6c5833771921ec28358dcfc52acf9a99607bc2a`.

The campaign ran exactly 33 validated arms: three counterbalanced repetitions
of no collector, E-Navigator, and Beyla plus Alloy across cumulative HTTP,
gRPC, Redis, PostgreSQL, and an 8 requests/second Python CPU profile stage.
Every arm used 15 seconds warmup and 45 seconds measured time. All 591,030
measured and 197,010 warmup operations succeeded, with zero workload errors.

| Stack | CPU mean | CPU stdev | CPU CV | RSS mean | RSS stdev | RSS CV |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| E-Navigator | 96.149058 mCPU | 4.292309 mCPU | 4.464% | 122,683,392 bytes | 532,233 bytes | 0.434% |
| Beyla plus Alloy | 76.440016 mCPU | 3.632599 mCPU | 4.752% | 136,827,790 bytes | 15,781,857 bytes | 11.534% |

E-Navigator therefore used 25.783671% more agent CPU and 10.337372% less RSS.
The memory tradeoff is real for this workload, but it is not sufficient to
declare a win against the stated CPU target.

### Throughput And Latency Versus Beyla Plus Alloy

Negative latency is faster. All figures are three-arm means under the fixed
offered rate; the short shared-cluster sample does not establish production
latency superiority.

| Family | Throughput | p50 | p95 | p99 |
| --- | ---: | ---: | ---: | ---: |
| HTTP | +0.000495% | -2.033037% | -0.388078% | -0.834163% |
| gRPC | +0.000495% | -2.422883% | +1.191626% | +0.005796% |
| Redis | +0.000495% | -8.178654% | -5.729252% | -6.454474% |
| PostgreSQL | +0.000495% | -5.540467% | -3.290993% | -11.118627% |
| Python CPU | +0.000495% | +0.433534% | -4.090330% | -4.219361% |

The stable offered throughput and zero workload errors rule out a throughput
reduction as the explanation for the CPU/RSS result.

## Signal Completeness

Across the three E-Navigator profile arms, the source decoded 169,836 samples
and sent 99,251 signals. It decoded and sent 775 profile signals. The exporter
recorded 98,474 traces enqueued and sent; it recorded 775 profiles enqueued
and 776 sent, which is an asynchronous scrape-boundary effect. Hard loss was
zero across all signal families, and all per-arm protocol completeness gates
passed.

## Allocation Diagnostics

Each diagnostic observed a 45-second window inside a separate 90-second
profile arm. The E-Navigator libc probes reported 6,882,002 allocation calls
and 1,008,661,895 requested bytes. The Beyla Go runtime probe reported
2,298,103 calls and 289,853,667 requested bytes. Alloy's Go metrics increased
by 24,271 allocations and 5,861,952 allocated bytes, yielding a directional
Beyla-plus-Alloy total of 2,322,374 calls and 295,715,619 bytes.

These totals are **not comparable**: E-Navigator uses libc uprobes, Beyla uses
the Go runtime, and Alloy contributes process metrics rather than the same
uprobes. The two traces also emitted tracefs `uprobe_events` teardown warnings
after their counters were printed. They are retained as diagnostic allocation
baselines, not a cross-runtime allocation performance claim.

## Size And Quality

The amd64 release binary decreased from 18,453,448 to 18,453,400 bytes
(-48 bytes). The local image increased from 38,028,049 to 38,028,204 bytes
(+155 bytes). No compile-target-directory size claim is made.

`scripts/quality.sh` passed with no skip variables. It covered formatting,
documentation and release checks, strict Clippy, rustdoc warnings, workspace
tests and builds, fuzz and repository guards, supply-chain checks, Docker and
smoke validation, Helm and Kubernetes schema validation, website checks, and
diff hygiene.

## Cleanup And Next Work

The harness restored `root-app` and `e-navigator` to automated prune plus
self-heal, Synced and Healthy. The standing `e-navigator-agent` returned to
2/2 Ready and Available on its original digest. No disposable namespaced or
cluster-scoped benchmark resources remain, and the privileged image loader and
node-local tar files were removed. The local benchmark image remains only in
the node containerd stores; it was not deployed as the standing agent.

Further work must start from a fresh symbolized CPU profile. Historical named
candidates such as request-fingerprint hashing, attribute materialization,
ordered-map insertion, exporter batching, and Tokio scheduling require a new
measured hypothesis; none is accepted on the basis of this report alone.

Raw local, homelab, profile, allocation, Prometheus, and workload artifacts
remain ignored under `benchmarks/results/optimization7-*`. The compact machine
readable record is [`summary.json`](summary.json).
