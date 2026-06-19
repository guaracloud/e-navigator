# Benchmark And Validation Evidence

E-Navigator keeps local performance evidence, synthetic pipeline proof, Docker
smoke proof, and privileged runtime proof separate. These checks are useful
together, but they are not interchangeable.

## Evidence Tiers

| Tier | Command or artifact | Proves | Does not prove |
| --- | --- | --- | --- |
| Local Criterion benchmarks | `benchmarks/runner/local-bench-smoke.sh` or `cargo bench --locked -p e-navigator-local-benches --bench hot_paths` | Deterministic userspace hot paths compile and run under fixed fixtures | live eBPF attach, kernel event volume, Kubernetes scheduling, production exporter throughput |
| Synthetic pipeline | `cargo run --locked -p e-navigator-cli -- --source synthetic` | The shared runner path can process synthetic source signals through processors, generators, and JSON stdout | privileged Aya, real procfs/sysfs/cgroup accuracy, live traffic capture |
| Docker smoke | `docker build -f Containerfile -t e-navigator:local .` and `tests/smoke_docker.sh e-navigator:local` | The container image runs the synthetic pipeline and validates packaged config fixtures | live kernel or cluster behavior |
| Kubernetes rendering | `helm lint charts/e-navigator` and `helm template e-navigator charts/e-navigator \| kubeconform -strict -summary -` | Helm and manifest schemas are valid for the declared DaemonSet shape | pods schedule, eBPF programs attach, host paths contain expected data |
| Guarded homelab proof | `E_NAVIGATOR_HOMELAB_CONFIRM=1 benchmarks/runner/homelab-collect.sh` after explicit approval | Whatever the recorded result directory observed on a real cluster | anything not present in the collected logs, pod state, or metrics |

## Local Criterion Benchmarks

The local benchmark package lives at
`benchmarks/runner/local-benches`. It is a workspace package so normal Rust
compile and lint gates can catch benchmark drift.

Run the short smoke profile:

```bash
benchmarks/runner/local-bench-smoke.sh
```

Run a longer local pass:

```bash
cargo bench --locked -p e-navigator-local-benches --bench hot_paths
```

The current benchmark targets are deterministic and non-privileged:

- raw Aya userspace decode fuzz harnesses for exec, network, and CPU profile
  event bytes;
- procfs, loadavg, meminfo, diskstats, and process stat parser paths;
- traceparent and HTTP fixture parsing;
- profiling fixture normalization;
- generator hot paths for network, DNS, resource, dependency graph, trace,
  request, profiling, runtime security, and Guara compatibility;
- JSON signal serialization, profile and Prometheus compatibility formatting,
  and bounded HTTP exporter queue enqueue behavior.

Benchmark setup stays outside the measured loops where the code path supports
that. The benchmarks use fixed in-memory fixtures only. They must not read live
`/proc`, `/sys`, Kubernetes, network sockets, Docker, or host files inside a
Criterion measurement.

## Result Artifact Policy

Local benchmark scripts write to:

```text
benchmarks/results/<timestamp>/
```

`benchmarks/results/` ignores timestamped result directories by default. Do not
commit raw Criterion reports, `target/`, HTML reports, screenshots, or transient
logs. Commit only small curated `sample-*.md` summaries when a human-reviewable
summary is intentionally part of the evidence trail.

Criterion's normal detailed reports still live under `target/criterion/`, which
is intentionally untracked.

## Synthetic And Docker Proof

Synthetic proof is the cheapest end-to-end local signal check:

```bash
cargo run --locked -p e-navigator-cli -- --source synthetic
```

Docker proof adds image packaging and config-file coverage:

```bash
docker build -f Containerfile -t e-navigator:local .
tests/smoke_docker.sh e-navigator:local
```

These checks validate userspace wiring and packaged fixtures. They do not prove
Aya/eBPF attach, DNS packet capture, perf-event profiling, Kubernetes runtime
behavior, OTLP transport, Pyroscope export, or replacement readiness.

## Guarded Homelab Proof Plan

Live homelab validation is prepared but not automatic. Do not run it without
explicit user approval for the live phase.

The intended namespace is:

```text
e-navigator-bench
```

The guarded collection script refuses to run unless
`E_NAVIGATOR_HOMELAB_CONFIRM=1` is set, prints the target context and namespace,
and writes collected evidence into `benchmarks/results/<timestamp>/`.

Collection-only mode:

```bash
E_NAVIGATOR_HOMELAB_CONFIRM=1 \
E_NAVIGATOR_HOMELAB_CONTEXT=<context> \
benchmarks/runner/homelab-collect.sh
```

Apply-and-collect mode requires an explicit image:

```bash
E_NAVIGATOR_HOMELAB_CONFIRM=1 \
E_NAVIGATOR_HOMELAB_APPLY=1 \
E_NAVIGATOR_HOMELAB_CONTEXT=<context> \
E_NAVIGATOR_HOMELAB_IMAGE_REPOSITORY=<repository> \
E_NAVIGATOR_HOMELAB_IMAGE_TAG=<tag> \
benchmarks/runner/homelab-collect.sh
```

The initial live proof should record:

- DaemonSet schedules and remains Ready in `e-navigator-bench`;
- Aya exec and network source logs include observed events from the controlled
  workload;
- host resource source reads mounted host paths;
- controlled workload produces expected exec, TCP, DNS, HTTP, and profiling
  signal opportunities;
- no E-Navigator pod restarts during a short soak;
- CPU and RSS are recorded from `kubectl top` when metrics are available;
- logs, pod JSON, events, and command output are stored in
  `benchmarks/results/<timestamp>/`.

Cleanup is namespace scoped. Set `E_NAVIGATOR_HOMELAB_CLEANUP=1` to delete the
benchmark workload and uninstall the benchmark Helm release from the target
namespace.

## Homelab Observability Context

The current homelab reference stack uses Beyla, Alloy, Tempo, and Prometheus:

- Beyla instruments `proj-*` tenant namespaces and sends traces to Alloy;
- Alloy receives OTLP on `4317` and `4318`, forwards traces to Tempo, and remote
  writes metrics to Prometheus;
- Tempo has service graph and span metrics generation enabled with
  `k8s.namespace.name` as a service graph dimension;
- Prometheus receives Alloy remote-write metrics and scrapes ServiceMonitors.

Future E-Navigator live proof can compare resource overhead against those
observability agents and can inspect whether controlled workload traffic appears
in the expected Beyla/Tempo service graph topology. That comparison is not
replacement proof until live E-Navigator signals, resource overhead, and
collector/export parity are recorded.

## Proof Boundaries

Current local benchmarks prove only repeatable userspace performance for fixed
fixtures and compile-time benchmark health. They do not prove:

- privileged Aya/eBPF attachment;
- runtime DNS packet capture;
- Kubernetes DaemonSet readiness;
- real host procfs/sysfs/cgroup accuracy;
- OTLP, Prometheus, Pyroscope, pprof, or production collector export;
- replacement readiness for Beyla, Alloy, Tempo, Prometheus, or Pyroscope.

Privileged runtime proof rules live in
`documentation/privileged-runtime-proof.md`.
