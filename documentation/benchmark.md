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

Guara L4 flow proof on `20260622-111022-guara-flow-live` and
`20260622-111448-guara-flow-python-client-live` used the same guarded homelab
boundary with pushed image `sha-762561f`. These runs prove live byte counters on
some `network_connection_close` records and live ambient `network_flow_summary`
generation, but they do not prove controlled workload `network_flow_summary` or
`beyla_network_flow_bytes_total`. The BusyBox workload completed on both nodes
without Kubernetes attribution on its byte-bearing close records, and the
Python socket workload produced server-IP `EINPROGRESS` failure records rather
than byte-bearing closes.

Follow-up run `20260622-122803-guara-einprogress-live` deployed pushed image
`sha-622e1aa` with the Linux `-EINPROGRESS` source-path fix included in
`scripts/quality.sh`. Two Python nonblocking clients completed 240 total socket
requests. Captured stdout proved the observed homelab-02 target
`10.42.134.6:8080` emitted 120 opens and 120 closes with 0 failures and 0 errno
115 failures, and direct `/metrics` exposed matching aggregate network counters
for the homelab-02 container runtime path. The run did not prove byte-bearing
controlled closes, controlled `network_flow_summary`,
`beyla_network_flow_bytes_total`, Kubernetes attribution for the Python client
records, or stdout capture for the successful homelab-01 client target.
Prometheus API queries were not run for this slice because no Prometheus server
service exists in `e-navigator-bench` and the live boundary kept actions inside
that namespace.

Follow-up run `20260622-220427-socket-bytes-live` deployed pushed image
`sha-86b3fce` with socket send/recv byte accounting for `sendto`, `sendmsg`,
`recvfrom`, and `recvmsg` tracepoints. Two Python nonblocking clients again
completed 240 total socket requests. Captured stdout proved the observed
homelab-02 target `10.42.134.22:8080` emitted 120 byte-bearing controlled
`network_connection_close` records, each with `bytes_sent=243` and
`bytes_received=1372`. Direct `/healthz` returned `ok`, `/readyz` returned
`ready`, and `/metrics` exposed aggregate controlled network counters at 120.
The run still did not prove Kubernetes attribution for the Python client
records, controlled `network_flow_summary`, `beyla_network_flow_bytes_total`, or
symmetric controlled-client stdout capture across both nodes.

Follow-up run `20260622-192821-new-container-attribution-live` deployed pushed
image `sha-dd67a3b` with immediate Kubernetes metadata refresh on newly missed
containers after a successful prior cache refresh. The corrected Python
workload ran only in `staging/e-navigator-bench` on `homelab-02` and completed
1,594 HTTP requests with zero application errors. Captured stdout proved 34
byte-bearing controlled `network_connection_close` records with Kubernetes
pod/container attribution for client pod
`e-nav-attrib-192821-r2-client-2zq4g`, and 34 controlled
`network_flow_summary` records for the same pod. Direct `/metrics` on the
homelab-02 E-Navigator pod exposed Kubernetes-attributed aggregate counters for
that client at 1,574 opens, destination observations, and duration samples. The
run still did not prove `beyla_network_flow_bytes_total` because Guara
compatibility scope excludes the `e-navigator-bench` temporary workload
namespace, and no Prometheus server service exists inside that namespace for a
bounded API query.

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
  collector evidence separately from fake-collector unit tests. Local
  fake-collector tests can prove protobuf metric, trace, and profile request
  encoding, but only live collector logs or accepted requests can upgrade
  collector-ingestion claims;
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
- `20260622-213109-dns-connected-udp-live-r2` pushed commit `94e808c`, waited
  for GitHub CI and GHCR image publication, rolled
  `ghcr.io/guaracloud/e-navigator:sha-94e808c` to
  `staging/e-navigator-bench`, enabled `source.aya_dns` and
  `generator.dns_metrics`, ran connected-UDP Python DNS clients pinned to both
  homelab nodes, and proved the observed warmed `homelab-02` client pod emitted
  attributed `dns_query`, `dns_response`, `dns_counter_metric`, and
  `dns_latency_metric` records for `10.43.0.10:53`; the `homelab-01`
  controlled client completed but did not produce matching controlled-client DNS
  records in the final structured pass, and dropped DNS perf events mean the run
  is not lossless capture proof;
- `20260622-122803-guara-einprogress-live` pushed commit `622e1aa`, waited for
  GHCR image publication, rolled
  `ghcr.io/guaracloud/e-navigator:sha-622e1aa` to
  `staging/e-navigator-bench`, ran nonblocking Python clients pinned to both
  homelab nodes, proved the observed homelab-02 target no longer emitted
  `EINPROGRESS` failure-only records, and recorded that byte-bearing controlled
  closes, controlled flow summaries, Beyla projection, homelab-01 stdout
  capture, and Kubernetes attribution remain unproven;
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
- `20260622-160350-otlp-trace-protobuf-live` ran a namespace-local
  OpenTelemetry Collector plus one-shot pushed image `sha-c00a7d5` synthetic
  Job in `staging/e-navigator-bench`, proved collector acceptance of two OTLP
  protobuf trace spans, and cleaned up the temporary Job and collector
  resources;
- `20260622-135450-otlp-metric-protobuf-live` ran a namespace-local
  OpenTelemetry Collector plus one-shot pushed image `sha-e7016b5` synthetic
  Job in `staging/e-navigator-bench`, proved collector acceptance of 45 OTLP
  protobuf metrics across network, DNS, system, process, and container
  families, and cleaned up the temporary Job and collector resources;
- `20260622-142733-otlp-profile-protobuf-blocked` records local OTLP profile
  protobuf proof for commit `a66e1ca` and published image
  `ghcr.io/guaracloud/e-navigator:sha-a66e1ca`, but no homelab collector
  proof: the required preflight stopped before deployment because
  `kubectl config current-context` returned `kind-tentacle-alpha` instead of
  `staging`;
- `20260622-165710-otlp-profile-protobuf-live` records a follow-up
  `staging/e-navigator-bench` run with pushed image `sha-35ecc6c`, a
  namespace-local OpenTelemetry Collector `0.130.0`, profile support enabled,
  and endpoint `/v1development/profiles`; the one-shot Job completed and the
  collector remained healthy, but the collector returned HTTP 400 for
  E-Navigator's real profile protobuf, so live profile collector acceptance is
  not proven; all temporary Job and collector resources were cleaned up;
- `20260622-204027-otlp-profile-protobuf-live` records the corrected
  `staging/e-navigator-bench` run with pushed image `sha-796b980`, a
  namespace-local OpenTelemetry Collector `0.130.0`, profile support enabled,
  and endpoint `/v1development/profiles`; the one-shot Job completed, the
  Collector debug exporter decoded `ResourceProfiles` with synthetic stack
  frame names and populated location indices, no sink failure or HTTP 400/404
  markers were found, and all temporary Job and collector resources were
  cleaned up;
- `20260622-144636-http-request-path-local` records local request/protocol
  proof that the HTTP fixture parser extracts bounded origin-form `url.path`
  attributes without query or fragment values and that request-span dedupe
  distinguishes spanless requests with different path attributes; this is not
  live HTTP traffic capture or route-template proof;
- `20260622-150549-http-request-id-local` records local request/protocol proof
  that the HTTP fixture parser extracts bounded `http.request.id` attributes
  from `X-Request-ID` or `Request-ID` headers without copying secret headers or
  oversized request IDs; this is not live HTTP traffic capture or production
  request-correlation proof;
- `20260622-154547-http-host-authority-local` records local request/protocol
  proof that the HTTP fixture parser extracts bounded `server.address` and
  `server.port` attributes from valid Host authorities without copying secret
  headers, malformed userinfo authorities, oversized hosts, invalid ports, or
  out-of-range ports; this is not live HTTP traffic capture or production
  service-topology proof;
- `20260622-162915-http-absolute-target-local` records local request/protocol
  proof that the HTTP fixture parser extracts bounded `url.path`,
  `server.address`, and `server.port` attributes from valid absolute-form
  `http://` and `https://` request targets without copying query strings,
  fragments, secret headers, unsupported schemes, userinfo authorities,
  oversized hosts, invalid ports, or out-of-range ports; this is not live HTTP
  traffic capture or production service-topology proof;
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
