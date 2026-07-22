# ADR 0014: Controlled Cumulative Head-To-Head Benchmark

Status: accepted

Date: 2026-07-22

## Context

E-Navigator combines application protocol observation and periodic CPU
profiling in one process. The closest comparison in this campaign is Grafana
Beyla for application observation plus Grafana Alloy `pyroscope.ebpf` for
profiling. Earlier project measurements covered individual sources, local hot
paths, or narrow kernel changes. They did not provide a controlled comparison
of the complete stacks against a no-agent baseline.

A useful comparison must keep the workload, node placement, kernel, load
generator, measurement window, and exporter destination identical. It must
also expose the marginal cost of adding each signal family instead of hiding
that cost inside one final aggregate. A successful benchmark means the
evidence is internally valid. It does not mean E-Navigator wins.

## Decision

Use a guarded, homelab-only, cumulative campaign with these properties:

- Keep five workloads active in every arm: HTTP/1.1, generic gRPC, Redis,
  PostgreSQL, and a CPU-bound Python service.
- Pin the servers, Redis and PostgreSQL backends, and the observed collector to
  `homelab-02`. Pin the fixed-rate load generator and opaque OTLP acceptance
  sink to `homelab-01`.
- Run three no-agent repetitions and three repetitions for each cumulative
  stage of each observed stack: HTTP, HTTP plus gRPC, plus Redis, plus
  PostgreSQL, then plus 10 Hz periodic CPU profiling. This produces 33 matched
  runs.
- Counterbalance collector order across repetitions. Keep every workload
  request rate and concurrency fixed, with a 15-second warmup followed by a
  45-second measured interval.
- Target the service-side processes. Redis and PostgreSQL use small bounded
  proxy services so both agents observe the actual database protocols while
  application latency includes the end-to-end backend operation.
- Compare E-Navigator's cumulative source configuration with Beyla's
  cumulative discovery selectors. Add Alloy only in the final profiling arm,
  and sum Beyla and Alloy CPU and RSS for the split-stack resource result.
- Use periodic on-CPU profiling at 10 Hz in both final arms. E-Navigator's
  off-CPU and futex-wait modes remain disabled because this comparison has no
  equivalent Alloy signal enabled.
- Query Prometheus over the same late measurement window for each arm. Record
  agent CPU cores and RSS, plus node-scoped sums of container CPU usage and
  container working-set memory. These node series are Kubernetes container
  workload totals, not total host CPU busy time or host used memory.
- Preserve application p50, p95, p99, throughput, standard deviation, and
  coefficient of variation across repetitions. Preserve native signal
  accounting and the opaque sink's request and byte totals.
- Fail analysis if the 33-run matrix, run order, workload contract, topology,
  image identities, node kernels, successful operations, resource samples, or
  required signal evidence drift. Fail on E-Navigator hard loss, Beyla
  instrumentation or export errors, or Alloy dropped profiles and failing
  sessions.
- Report undercounts, overcounts, and low-level profiler diagnostics even when
  the hard gates pass. A PASS verdict is evidence-integrity success only.

The workload image pins Python and Python dependencies by digest and hash.
Redis and PostgreSQL images are digest-pinned. The comparison pins Beyla
3.28.0, Beyla Helm chart 1.16.10 by archive checksum, and Alloy 1.18.0 by image
digest. The selected discovery and profiling configuration follows the
[Beyla service-discovery documentation](https://grafana.com/docs/beyla/latest/configure/service-discovery/)
and the
[Alloy `pyroscope.ebpf` documentation](https://grafana.com/docs/alloy/latest/reference/components/pyroscope/pyroscope.ebpf/).

The harness refuses to run unless the Kubernetes context is exactly
`homelab`, the namespace is exactly `e-navigator-bench`, and
`E_NAVIGATOR_HOMELAB_CONFIRM=1` is present. It suspends the standing
E-Navigator Argo CD automation and DaemonSet before the comparison, then
restores their recorded state. Candidate images are loaded directly into the
two homelab containerd stores and are never pushed.

## Evidence Artifact Policy

The ignored `benchmarks/results/head-to-head-proof/` directory retains the
complete local capture, including Prometheus scrapes, Pod inventories, logs,
events, query responses, Helm output, and workload output. The committed proof
contains:

- a normalized raw record for every run;
- aggregate analysis with variance and final-stack comparisons;
- exact environment, image, input, cleanup, and interruption provenance;
- representative raw metrics and a workload result;
- checksums covering every curated artifact.

The analyzer bounds file size, Prometheus series count, and matrix sample count
before retaining input. The workload bounds request bodies, decompressed OTLP
bodies, offered rates, concurrency, and retained latency samples. These are
benchmark controls, not new product configuration. No Helm value,
`values.schema.json` field, or production TOML contract changes under this
decision.

## Consequences

The campaign can make a scoped statement about this exact shared two-node
homelab and workload. It cannot establish production overhead, broad workload
superiority, total host utilization, backend storage cost, long-duration
stability, or a universal comparison with every Beyla and Alloy configuration.

The first complete result measured higher E-Navigator agent CPU and RSS than
Beyla plus Alloy. That result is retained as a negative performance finding.
It blocks a reduced-overhead or reduced-memory claim and gives future work a
reproducible baseline.
