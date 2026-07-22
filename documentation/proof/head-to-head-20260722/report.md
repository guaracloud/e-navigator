# Full-Stack Head-To-Head Homelab Proof

Date: 2026-07-22

Result: PASS for evidence integrity. NO-GO for a lower-agent-overhead claim.

## Scope

This guarded campaign compared three conditions on the two-node `homelab`
cluster: no benchmark agent, Grafana Beyla plus Grafana Alloy profiling, and
E-Navigator. The same HTTP, gRPC, Redis, PostgreSQL, and CPU-bound Python
services remained active for every arm. The same fixed-rate load generator,
nodes, Linux 6.6.68 kernel, workload image, warmup, and measurement duration
were used throughout.

The complete 33-run matrix passed its workload, topology, image, resource,
signal, loss, and run-order gates. The final E-Navigator stack measured
43.601071% more agent CPU and 31.903883% more agent RSS than Beyla plus Alloy.
This evidence therefore rejects a lower-overhead or lower-memory claim for
E-Navigator on this workload.

## Environment And Inputs

- Kubernetes context: exactly `homelab`, never a production context.
- Cluster: k3s `v1.30.4+k3s1`, two amd64 NixOS 24.05 nodes, Linux 6.6.68,
  containerd `1.7.20-k3s1`.
- Placement: observed services and collectors on `homelab-02`; load generator
  and opaque OTLP sink on `homelab-01`.
- Candidate source revision: `a30ed28a654d5566040c1e860898224996159064`.
- E-Navigator candidate: local-only
  `docker.io/library/e-navigator:gap9-head-to-head-amd64`, local index
  `sha256:8201c7def131e42f3e43ed83a5fbb740e3b5795d03253f7df536cc9f85a9bac3`,
  observed runtime image ID
  `sha256:f3e543e47b4fee2c906ad61fe1d88c1301644e63e249c3a6a48e6cdbe048db78`.
- Workload: local-only
  `docker.io/library/e-navigator-head-to-head:gap9-amd64`, local index
  `sha256:7fbd65f7d34680eaabaf730f568c8967a3c8ef018dca1e8d1b93b047c49f672f`,
  observed runtime image ID
  `sha256:d630d323d2387b27627e1b1ded6b93e85296bb28538478182f08cf46a5a18c18`.
- Workload runtime: Python 3.13.11, `grpcio` 1.82.1, `redis` 8.0.1, and
  `psycopg` 3.3.4, with package hashes enforced during the image build.
- Backends: digest-pinned Redis and PostgreSQL images recorded in
  [manifest.json](manifest.json).
- Comparison: Beyla 3.28.0 at a pinned image digest through Helm chart 1.16.10
  with a pinned chart checksum, and Alloy 1.18.0 at a pinned image digest.
- Candidate and workload images were bundled into a 97,184,768-byte OCI
  archive with SHA-256
  `3577702bc611fabf210cc5986423c91274cfbf2c5f00e1c85251b99a832abf7e`,
  loaded directly into both homelab containerd stores, and never pushed.

## Method

The workload ran at fixed offered rates of 100 HTTP requests/s, 80 gRPC
calls/s, 160 Redis operations/s, 50 PostgreSQL operations/s, and 8 Python CPU
operations/s. Each arm used a 15-second warmup and a 45-second measured
interval. All five workload families ran in all 33 arms.

Each observed stack used five cumulative stages: HTTP, plus gRPC, plus Redis,
plus PostgreSQL, then plus periodic CPU profiles at 10 Hz. Three repetitions
per stage and three no-agent repetitions produced 33 validated runs. Collector
order was counterbalanced across repetitions. The final Beyla condition sums
Beyla and Alloy resources. The final E-Navigator condition is its single
DaemonSet process.

Prometheus queries used the same late 30-second portion of each measured
interval and a 60-second CPU rate window. Agent memory is container RSS. The
node-level series are sums of container CPU usage and container working-set
memory grouped by node. They intentionally do not claim total host busy CPU or
host used memory. Full method and rationale are in
[ADR 0014](../../adr/0014-controlled-head-to-head-benchmark.md).

The first attempt stopped after eight validated arms and one incomplete Beyla
PostgreSQL arm because the original 30-second CPU rate window returned only one
sample. The exit trap restored the standing installation. The query window was
changed to 60 seconds, all eight retained arms were re-queried from historical
Prometheus data with that same formula, the incomplete arm was rerun, and the
campaign resumed. The committed `validated-run-order.log` contains each of the
33 accepted arms exactly once. No measurement from the incomplete attempt is
present in the normalized results.

After collection, bounded-input and cleanup-wait hardening was added without
changing recorded values. A trailing blank line was also removed from each of
the five TOML source configs without changing its parsed value. The executed
byte-for-byte input hashes remain in `executed-input-sha256.txt`; the finalized
config hashes are separate fields in `manifest.json`, and every finalized
config was revalidated through the CLI.

## Application Results

Values are the mean across three repetitions, with sample standard deviation
after `+/-`. Latencies are microseconds. Throughput is operations per second.
Because the driver uses fixed offered rates and every operation succeeded,
throughput is a correctness and pacing check, not a saturation-capacity test.

| Family | Condition | Throughput | p50 | p95 | p99 |
| --- | --- | ---: | ---: | ---: | ---: |
| HTTP | No agent | 100.009479 +/- 0.000391 | 1793.667 +/- 3.055 | 6301.000 +/- 239.056 | 6971.667 +/- 19.732 |
| HTTP | Beyla plus Alloy | 100.009727 +/- 0.000170 | 1850.000 +/- 8.544 | 6257.667 +/- 375.042 | 7037.000 +/- 37.723 |
| HTTP | E-Navigator | 100.009765 +/- 0.000795 | 1851.667 +/- 12.897 | 6463.000 +/- 24.000 | 7020.667 +/- 20.599 |
| gRPC | No agent | 80.007583 +/- 0.000312 | 2863.333 +/- 24.542 | 4110.667 +/- 59.214 | 5763.333 +/- 106.547 |
| gRPC | Beyla plus Alloy | 80.007781 +/- 0.000136 | 3042.000 +/- 64.211 | 4312.000 +/- 121.787 | 5866.333 +/- 203.866 |
| gRPC | E-Navigator | 80.007812 +/- 0.000636 | 3056.333 +/- 48.563 | 4590.333 +/- 27.025 | 6234.333 +/- 259.278 |
| Redis | No agent | 160.015166 +/- 0.000625 | 1008.667 +/- 10.970 | 1784.667 +/- 18.824 | 2971.000 +/- 217.401 |
| Redis | Beyla plus Alloy | 160.015562 +/- 0.000272 | 1137.333 +/- 17.786 | 2048.000 +/- 28.355 | 3399.667 +/- 222.480 |
| Redis | E-Navigator | 160.015624 +/- 0.001273 | 1087.333 +/- 13.051 | 2071.000 +/- 51.507 | 3260.000 +/- 299.040 |
| PostgreSQL | No agent | 50.004739 +/- 0.000195 | 1150.000 +/- 5.196 | 2281.667 +/- 31.086 | 4067.667 +/- 91.850 |
| PostgreSQL | Beyla plus Alloy | 50.004863 +/- 0.000085 | 1258.333 +/- 6.658 | 2469.333 +/- 67.241 | 4477.667 +/- 620.033 |
| PostgreSQL | E-Navigator | 50.004883 +/- 0.000398 | 1439.333 +/- 16.503 | 2802.667 +/- 43.317 | 4365.667 +/- 401.438 |
| Python CPU | No agent | 8.000758 +/- 0.000031 | 30423.333 +/- 459.375 | 48258.667 +/- 221.816 | 53257.333 +/- 600.622 |
| Python CPU | Beyla plus Alloy | 8.000778 +/- 0.000014 | 30875.000 +/- 240.308 | 45560.667 +/- 6748.336 | 53568.333 +/- 1382.483 |
| Python CPU | E-Navigator | 8.000781 +/- 0.000064 | 31269.333 +/- 110.586 | 41879.333 +/- 4934.424 | 50957.000 +/- 3167.350 |

Across all arms, the workload completed 197,010 warmup and 591,030 measured
operations with zero reported errors. Final-stack p99 changes versus no agent
ranged from +0.584% to +14.428% for Beyla plus Alloy, and from -4.319% to
+9.727% for E-Navigator. With only three shared-cluster repetitions, these are
descriptive results, not significance-tested general latency claims.

## Agent Resource Increments

Agent CPU is millicores and agent memory is MiB of RSS, both mean +/- sample
standard deviation across three runs. Each row adds one cumulative signal
family while all five application workloads stay constant.

| Cumulative stage | Beyla or Beyla plus Alloy CPU m | E-Navigator CPU m | Beyla or Beyla plus Alloy RSS MiB | E-Navigator RSS MiB |
| --- | ---: | ---: | ---: | ---: |
| HTTP | 33.891 +/- 1.735 | 36.768 +/- 1.828 | 24.640 +/- 1.306 | 12.821 +/- 0.436 |
| plus gRPC | 37.023 +/- 3.356 | 74.540 +/- 3.201 | 28.260 +/- 1.204 | 20.427 +/- 0.539 |
| plus Redis | 45.019 +/- 0.981 | 71.933 +/- 1.536 | 23.979 +/- 0.459 | 20.751 +/- 0.345 |
| plus PostgreSQL | 48.768 +/- 1.577 | 103.476 +/- 4.173 | 24.861 +/- 0.696 | 25.125 +/- 0.539 |
| plus 10 Hz CPU profiles | 81.721 +/- 5.618 | 117.353 +/- 6.010 | 137.131 +/- 4.680 | 180.881 +/- 5.079 |

At the final cumulative stage, E-Navigator measured +35.631 millicores and
+43.750 MiB versus Beyla plus Alloy, or +43.601071% CPU and +31.903883% RSS.
E-Navigator used less RSS in the first three stages, but that does not offset
the final profile-stage result and does not support a broad memory claim.

## Node-Scoped Container Resources

Values are mean +/- sample standard deviation across the three repetitions.
CPU is cores used by containers grouped on the node. Memory is GiB of summed
container working set. These shared-node totals include unrelated background
work and are retained to show variance, not to estimate a causal agent delta.

| Condition | `homelab-01` CPU | `homelab-01` GiB | `homelab-02` CPU | `homelab-02` GiB |
| --- | ---: | ---: | ---: | ---: |
| No agent | 0.795258 +/- 0.042424 | 13.380998 +/- 0.123106 | 0.680568 +/- 0.066784 | 1.085594 +/- 0.006813 |
| Beyla HTTP | 0.633539 +/- 0.046128 | 13.246515 +/- 0.046312 | 0.680437 +/- 0.016054 | 1.280414 +/- 0.001565 |
| E-Navigator HTTP | 0.631131 +/- 0.027560 | 13.339396 +/- 0.106423 | 0.671660 +/- 0.010610 | 1.112858 +/- 0.005804 |
| Beyla plus gRPC | 0.632550 +/- 0.038103 | 13.294048 +/- 0.038144 | 0.680054 +/- 0.009297 | 1.299793 +/- 0.023027 |
| E-Navigator plus gRPC | 0.708511 +/- 0.080662 | 13.278790 +/- 0.069834 | 0.725234 +/- 0.021232 | 1.118428 +/- 0.006062 |
| Beyla plus Redis | 0.611466 +/- 0.037456 | 13.300997 +/- 0.077242 | 0.737447 +/- 0.050303 | 1.298034 +/- 0.012109 |
| E-Navigator plus Redis | 0.638651 +/- 0.038157 | 13.279946 +/- 0.014977 | 0.744657 +/- 0.002829 | 1.117836 +/- 0.009378 |
| Beyla plus PostgreSQL | 0.615244 +/- 0.019916 | 13.323813 +/- 0.061716 | 0.698520 +/- 0.018731 | 1.295447 +/- 0.002941 |
| E-Navigator plus PostgreSQL | 0.638695 +/- 0.066854 | 13.328824 +/- 0.056073 | 0.786911 +/- 0.004153 | 1.131760 +/- 0.022890 |
| Beyla plus Alloy profiles | 0.649775 +/- 0.041528 | 13.251579 +/- 0.055056 | 0.751015 +/- 0.008030 | 1.502117 +/- 0.012374 |
| E-Navigator profiles | 0.653229 +/- 0.035164 | 13.261637 +/- 0.047570 | 0.768541 +/- 0.007373 | 1.291978 +/- 0.004888 |

The no-agent `homelab-01` CPU mean exceeded every final-stack mean, which
demonstrates why these shared-node totals cannot support a simple causal
overhead subtraction. Direct collector cgroup metrics are the narrower agent
resource evidence.

## Signal And Loss Accounting

E-Navigator cumulative totals below sum the three repetitions at each stage.
Hard loss includes invalid raw samples, userspace send failures, transport and
perf loss, RingBuf reservation failures, profile capture/state loss, source
failures, export queue drops, failed batches, rejected items, permanent
responses, and invalid responses or trace records.

| E-Navigator stage | Source samples decoded | Source signals sent | Traces enqueued / sent | Profiles enqueued / sent | Hard loss |
| --- | ---: | ---: | ---: | ---: | ---: |
| HTTP | 18,000 | 18,000 | 18,000 / 18,000 | 0 / 0 | 0 |
| plus gRPC | 91,096 | 32,400 | 32,400 / 32,400 | 0 / 0 | 0 |
| plus Redis | 91,115 | 32,404 | 32,402 / 32,402 | 0 / 0 | 0 |
| plus PostgreSQL | 109,979 | 68,622 | 68,620 / 68,623 | 0 / 0 | 0 |
| plus profiles | 110,544 | 69,189 | 68,622 / 68,622 | 567 / 567 | 0 |

The three-operation PostgreSQL-stage sent-versus-enqueued boundary difference
is preserved. The two scrapes are not atomic with the asynchronous exporter,
so in-flight flushes can cross the before or after boundary. No drop, failure,
rejection, or hard-loss counter increased.

Beyla application metrics were compared with the exact warmup plus measured
operation totals for every enabled protocol. Counts sum three repetitions.

| Beyla stage | HTTP | gRPC | Redis | PostgreSQL | Hard instrumentation/export errors |
| --- | ---: | ---: | ---: | ---: | ---: |
| HTTP | 18,000 / 18,000 | n/a | n/a | n/a | 0 |
| plus gRPC | 18,000 / 18,000 | 14,380 / 14,400 | n/a | n/a | 0 |
| plus Redis | 18,000 / 18,000 | 14,382 / 14,400 | 28,800 / 28,800 | n/a | 0 |
| plus PostgreSQL | 18,000 / 18,000 | 14,382 / 14,400 | 28,802 / 28,800 | 9,000 / 9,000 | 0 |
| plus profiles | 18,000 / 18,000 | 14,383 / 14,400 | 28,800 / 28,800 | 9,000 / 9,000 | 0 |

The final Beyla arm left 17 of 14,400 gRPC calls unaccounted, or 0.118056%.
The PostgreSQL stage overcounted Redis by two operations. These discrepancies
are reported rather than converted into a lossless claim.

Across the final three Alloy arms, 55 pprof profiles were collected and 55
were forwarded. Dropped profiles and failing sessions were zero. Alloy also
reported one `bpf_errors_empty_stack_total` increment and one
`bpf_native_errors_wrong_text_section_total` increment. They did not trigger
the predeclared hard gate, but they remain profiler coverage diagnostics and
are not hidden.

## Evidence Artifacts

- [runs.json](runs.json) is the normalized raw record for all 33 accepted
  runs, including workload output, resource samples, topology identities,
  signal accounting, and opaque OTLP sink totals.
- [analysis.json](analysis.json) contains all condition aggregates, standard
  deviations, coefficients of variation, signal summaries, node summaries,
  and final-stack comparisons.
- [representative-workload-result.json](representative-workload-result.json)
  is the raw final E-Navigator repetition-one workload result.
- The `representative-*.prom` files retain before and after raw Prometheus
  scrapes for E-Navigator, Beyla, and Alloy in final repetition one.
- [manifest.json](manifest.json), [validated-run-order.log](validated-run-order.log),
  and [executed-input-sha256.txt](executed-input-sha256.txt) preserve exact
  environment, order, executed and finalized input, image, interruption, and
  cleanup provenance.
- [cleanup.json](cleanup.json) records the post-image-removal resource audit
  and standing GitOps state.
- [SHA256SUMS](SHA256SUMS) covers every committed proof artifact except itself.

The full 17 MiB local capture remains under the ignored
`benchmarks/results/head-to-head-proof/` directory. It includes every Pod
inventory, event list, log, Prometheus query response, raw collector scrape,
Helm output, workload result, and cleanup command output.

## Validation

- Eight deterministic analyzer tests cover workload validation, protocol
  coverage, signal-family accounting, topology, randomized Prometheus input,
  bounded input rejection, proof projection, and complete symmetric matrices.
- The shell guard proves the homelab confirmation failure, exact 33-arm
  contract, fixed context and namespace, pinned comparison inputs, bounded
  workload and analyzer limits, source config validation, shell syntax, and
  Kubernetes schema validation.
- The complete `scripts/quality.sh` gate passed without skipped checks after all
  curated artifacts and documentation were finalized.

## Cleanup And Claim Boundary

The disposable workload, collectors, jobs, namespace-scoped objects, Alloy
ClusterRole and ClusterRoleBinding, and both local candidate image tags were
removed. The standing Argo CD application returned `Synced` and `Healthy` with
automated prune and self-heal restored. Its digest-pinned E-Navigator
DaemonSet returned 2/2 Ready at
`sha256:62402d21b9cb02d59d63365c7e3716ffa0980bfea42d070b43fed618703a7df9`.
The benchmark namespace and cluster-scoped disposable resource audits were
empty. No production context, namespace, collector, dashboard, or workload was
touched.

This proof covers one shared two-node Linux 6.6.68 cluster, five fixed-rate
services, three short repetitions, the pinned comparison versions, periodic
10 Hz CPU profiling, opaque acceptance of trace exports, and the recorded
node-scoped container resource definition. It does not prove production
behavior, sustained-load stability, backend ingestion equivalence, full
semantic parity between the stacks, total host utilization, capacity limits,
statistical superiority, or universal CPU, memory, latency, and loss results.
