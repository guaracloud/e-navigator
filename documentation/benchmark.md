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

Apply-and-collect mode defaults to the required benchmark image
`ghcr.io/guaracloud/e-navigator:sha-8ab271c`:

```bash
E_NAVIGATOR_HOMELAB_CONFIRM=1 \
E_NAVIGATOR_HOMELAB_APPLY=1 \
E_NAVIGATOR_HOMELAB_CONTEXT=<context> \
benchmarks/runner/homelab-collect.sh
```

Override `E_NAVIGATOR_HOMELAB_IMAGE_REPOSITORY` or
`E_NAVIGATOR_HOMELAB_IMAGE_TAG` only when the required image is unavailable.
The collector records the required image, configured image, and whether an image
substitution occurred in `run-metadata.txt`.

Homelab run `20260621-221944-required-image-live` proved the required image is
currently pullable in `staging/e-navigator-bench` with pull secret
`ghcr-e-navigator-pull` and starts far enough to print CLI help. That is an
image availability check only. It does not prove DaemonSet runtime behavior or
feature parity with newer images used by later Prometheus, OTLP, DNS, Guara, or
resource-baseline proof slices.

Prometheus HTTP validation is opt-in because the chart must enable both the
runtime sink and the Kubernetes HTTP surface. For a Prometheus endpoint run with
a current image that supports `sink.prometheus_http`, add:

```bash
E_NAVIGATOR_HOMELAB_ENABLE_PROMETHEUS_HTTP=1 \
E_NAVIGATOR_HOMELAB_ENABLE_SERVICE_MONITOR=1 \
benchmarks/runner/homelab-collect.sh
```

The collector writes `prometheus-http-runtime-config.toml` with
`[prometheus_http] enabled = true` and `sink.prometheus_http` enabled, passes it
to Helm with `--set-file config.toml=...`, renders the chart Service, and renders
the ServiceMonitor when `E_NAVIGATOR_HOMELAB_ENABLE_SERVICE_MONITOR=1` is set.
Only recorded `/healthz`, `/readyz`, `/metrics`, Prometheus active-target, and
query artifacts can upgrade Prometheus claims. Config and render evidence alone
remain non-privileged or inconclusive.

The initial live proof should record:

- DaemonSet schedules and remains Ready in `e-navigator-bench`;
- Aya exec and network source logs include observed events from the controlled
  workload;
- host resource source reads mounted host paths;
- controlled workload produces expected exec, TCP, DNS, HTTP, and profiling
  signal opportunities;
- Prometheus HTTP validation enables both `sink.prometheus_http` in the runtime
  config and chart Service/ServiceMonitor values before treating port `9090` as
  meaningful;
- OTLP validation enables `sink.otlp_http` with an explicit endpoint and records
  collector evidence separately from fake-collector unit tests;
- `20260621-205344-otlp-live` is the first homelab OTLP HTTP sink boundary run:
  image `sha-5c417c0` delivered internal JSON metric, trace, and profile records
  to a namespace-local fake collector, then restored the release to
  Prometheus-enabled `aya-exec`;
- `20260621-224414-alloy-otlp-boundary-live` pointed `sink.otlp_http` at real
  homelab Alloy OTLP HTTP `/v1/traces`: deployed image `sha-5c417c0` crashed on
  Alloy HTTP 400, while current local code loaded directly into both homelab
  node runtimes logged and dropped the HTTP 400 sink failures with both pods
  Ready, zero restarts, JSON stdout active, and Prometheus HTTP still reachable;
- `20260622-001716-published-image-live` pushed commit `d3167e3`, waited for
  GitHub image publication, deployed
  `ghcr.io/guaracloud/e-navigator:sha-d3167e3` to `staging/e-navigator-bench`,
  repeated the real Alloy HTTP 400 boundary with the published image, restored
  the baseline config, and recorded Prometheus scrape proof, JSON stdout counts,
  resource samples, and capability posture;
- `20260622-004011-current-head-live` rolled current pushed `main` image
  `sha-c89f345` to `staging/e-navigator-bench`, ran a controlled BusyBox
  workload, proved the DaemonSet stayed `2/2` Ready with zero restarts, captured
  JSON stdout source/generator families, and proved Prometheus-level controlled
  workload network attribution for the workload pod; JSON stdout did not show
  that workload pod name and must not be used for that attribution claim;
- `20260622-013602-dns-msg-live` pushed commit `10b81e6`, waited for GitHub CI
  and GHCR image publication, rolled
  `ghcr.io/guaracloud/e-navigator:sha-10b81e6` to
  `staging/e-navigator-bench`, ran DNS workloads pinned to both homelab nodes,
  observed live `source.aya_dns` plus `generator.dns_metrics` output from
  CoreDNS and Pi-hole, and recorded that the controlled BusyBox
  client-to-CoreDNS workload did not appear in DNS attribution;
- `20260621-233103-generator-resource-security-live` was a collection-only
  current-release run that observed live `generator.dependency_graph` output,
  `source.aya_network`, `source.aya_exec` process exits, network metrics,
  trace-correlation records, Prometheus resource/network metric queries, 10
  resource samples, and capability posture; it did not observe fresh
  `runtime_security_finding` or `source.host_resource` JSON stdout lines;
- `20260621-234159-runtime-security-live` was a current-release runtime-security
  proof run with workloads pinned to both homelab nodes: it observed 209 live
  `runtime_security_finding` records from `generator.runtime_security`,
  including `runtime.network_tool_exec`, `runtime.shell_in_container`, and
  `network.kubernetes_api_from_workload`, while both E-Navigator pods stayed
  Ready and Prometheus returned `up` plus workload-labelled network metrics;
- `20260621-222508-required-image-daemonset-live` is the first required-image
  DaemonSet runtime run: image `sha-8ab271c` rolled out on both homelab nodes,
  emitted live Aya network-derived JSON stdout records, and was then restored to
  the pre-run `sha-5c417c0` Prometheus-enabled release;
- `20260622-001716-published-image-live` left the Helm release on pushed image
  `sha-d3167e3` with the baseline config restored and both homelab pods Ready;
- `20260622-004011-current-head-live` left the Helm release on current pushed
  image `sha-c89f345` with both homelab pods Ready;
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
- runtime DNS packet capture beyond the exact recorded live DNS runs;
- controlled client workload DNS attribution;
- Kubernetes DaemonSet readiness;
- real host procfs/sysfs/cgroup accuracy;
- OTLP, Prometheus, Pyroscope, pprof, or production collector export;
- DNS parser/raw decode tests as a substitute for runtime DNS packet capture;
- replacement readiness for Beyla, Alloy, Tempo, Prometheus, or Pyroscope.

Privileged runtime proof rules live in
`documentation/privileged-runtime-proof.md`.
