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
  request, profiling, runtime security, and native export;
- JSON signal serialization, profile and Prometheus compatibility formatting,
  and bounded HTTP exporter queue enqueue behavior.

Benchmark setup stays outside the measured loops where the code path supports
that. The benchmarks use fixed in-memory fixtures only. They must not read live
`/proc`, `/sys`, Kubernetes, network sockets, Docker, or host files inside a
Criterion measurement.

Recent local smoke evidence:

- `20260623-125022` compiled and ran the deterministic hot-path suite, but
  reported regressions in CPU profile decode, host CPU/load parsing, HTTP
  fixture parsing, JSON serialization, and Prometheus compatibility formatting.
  This run did not support a positive performance claim.
- `20260623-130410` followed up on Prometheus compatibility formatting after
  sink-local formatter changes. Targeted sink tests, sink clippy, and workspace
  tests passed. Criterion reported `formatter/prometheus_compat` improved with
  median change `-64.030%` and measured interval `2.0792 us` to `2.5384 us`.
  The same smoke still reported unrelated regressions in
  `protocol/http_fixture_parse`, `generator/network_metrics`, and
  `formatter/profile_record`, so the outcome remains partial rather than a
  whole-harness performance improvement.
- `20260623-133016` followed up on profile formatting after replacing nested
  profile ID formatting with streamed hashing and allocation-free mixed-case
  sensitive-key checks. Targeted profile formatter tests, sink clippy,
  workspace tests, and the Docker-skipped quality gate passed. Criterion
  reported `formatter/profile_record` improved with median change `-61.889%`
  and measured interval `1.7037 us` to `1.7230 us`. The same smoke still
  reported unrelated or noisy regressions in host parser and generator targets,
  so the outcome remains partial rather than a whole-harness performance
  improvement.

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
behavior, OTLP transport, external profile backend export, or replacement readiness.

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
`ghcr.io/e-navigator/e-navigator:sha-8ab271c`:

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

Cleanup controls are intentionally split. For standing benchmark releases, use
`E_NAVIGATOR_HOMELAB_CLEANUP_WORKLOAD=1` to delete only the generated
timestamped workload manifest after evidence capture. Use
`E_NAVIGATOR_HOMELAB_UNINSTALL_RELEASE=1` only when the run should uninstall
the Helm release. The older `E_NAVIGATOR_HOMELAB_CLEANUP=1` remains a
backward-compatible full cleanup switch and enables both workload cleanup and
release uninstall when the split flags are not set.

Homelab run `20260621-221944-required-image-live` proved the required image is
currently pullable in `staging/e-navigator-bench` with pull secret
`ghcr-e-navigator-pull` and starts far enough to print CLI help. That is an
image availability check only. It does not prove DaemonSet runtime behavior or
feature parity with newer images used by later Prometheus, OTLP, DNS, E-Navigator, or
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

Native L4 flow proof on `20260622-111022-flow-live` and
`20260622-111448-flow-python-client-live` used the same guarded homelab
boundary with pushed image `sha-762561f`. These runs prove live byte counters on
some `network_connection_close` records and live ambient `network_flow_summary`
generation, but they do not prove controlled workload `network_flow_summary` or
`network_flow_bytes`. The BusyBox workload completed on both nodes
without Kubernetes attribution on its byte-bearing close records, and the
Python socket workload produced server-IP `EINPROGRESS` failure records rather
than byte-bearing closes.

Follow-up run `20260622-122803-flow-einprogress-live` deployed pushed image
`sha-622e1aa` with the Linux `-EINPROGRESS` source-path fix included in
`scripts/quality.sh`. Two Python nonblocking clients completed 240 total socket
requests. Captured stdout proved the observed homelab-02 target
`10.42.134.6:8080` emitted 120 opens and 120 closes with 0 failures and 0 errno
115 failures, and direct `/metrics` exposed matching aggregate network counters
for the homelab-02 container runtime path. The run did not prove byte-bearing
controlled closes, controlled `network_flow_summary`,
`network_flow_bytes`, Kubernetes attribution for the Python client
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
records, controlled `network_flow_summary`, `network_flow_bytes`, or
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
run still did not prove `network_flow_bytes` because E-Navigator
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
  `ghcr.io/e-navigator/e-navigator:sha-d3167e3` to `staging/e-navigator-bench`,
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
  `ghcr.io/e-navigator/e-navigator:sha-10b81e6` to
  `staging/e-navigator-bench`, ran DNS workloads pinned to both homelab nodes,
  observed live `source.aya_dns` plus `generator.dns_metrics` output from
  CoreDNS and Pi-hole, and recorded that the controlled BusyBox
  client-to-CoreDNS workload did not appear in DNS attribution;
- `20260622-213109-dns-connected-udp-live-r2` pushed commit `94e808c`, waited
  for GitHub CI and GHCR image publication, rolled
  `ghcr.io/e-navigator/e-navigator:sha-94e808c` to
  `staging/e-navigator-bench`, enabled `source.aya_dns` and
  `generator.dns_metrics`, ran connected-UDP Python DNS clients pinned to both
  homelab nodes, and proved the observed warmed `homelab-02` client pod emitted
  attributed `dns_query`, `dns_response`, `dns_counter_metric`, and
  `dns_latency_metric` records for `10.43.0.10:53`; the `homelab-01`
  controlled client completed but did not produce matching controlled-client DNS
  records in the final structured pass, and dropped DNS perf events mean the run
  is not lossless capture proof;
- `20260623-045808-dns-bpf-drop-diagnostics-not-proven` rolled three pushed
  DNS diagnostic images only to `staging/e-navigator-bench`; the first two
  failed BPF loading in `source.aya_dns` at `tracepoint_recvfrom_exit`, the
  third failed BPF loading in `source.aya_network` at `tracepoint_read_exit`,
  the diagnostic changes were reverted in `e3bc6f2`, and the release was
  restored to the previous baseline digest; this is negative verifier proof, not
  DNS capture progress;
- `20260623-051700-dns-seccomp-live` rolled pushed image `sha-beec11d` to
  `staging/e-navigator-bench` with `source.aya_dns`, `generator.dns_metrics`,
  and chart `RuntimeDefault` seccomp enabled; both E-Navigator pods reported
  `Seccomp: 2`, a controlled connected-UDP Python `os.write`/`os.read` DNS
  workload on `homelab-02` completed 120 measured responses with zero errors,
  and E-Navigator captured 148 Kubernetes-attributed `dns_query`, 148
  `dns_response`, 296 `dns_counter_metric`, and 148 `dns_latency_metric`
  records for the workload after attribution warmup; the release was rolled
  back to revision `103` and no run-labeled resources remained;
- `20260623-084626-profile-seccomp-workload-live` rolled pushed image
  `sha-7d772fc` to `staging/e-navigator-bench` with
  `source.aya_cpu_profile`, `generator.profiling`, and chart
  `RuntimeDefault` seccomp enabled; both E-Navigator pods reported
  `Seccomp: 2` and `NoNewPrivs: 1`, a lighter shell-loop workload completed
  without matching profile records, and a four-worker hot Python workload on
  `homelab-02` produced 726 Kubernetes-attributed `profile_sample_observation`
  records plus 726 Kubernetes-attributed `profiling_session_observation`
  records with zero precise failure markers; the release was rolled back to
  revision `105` and no run-labeled resources remained;
- `20260623-091319-host-resource-seccomp-live` rolled pushed image
  `sha-ab19ab5` to `staging/e-navigator-bench` with `source.host_resource`,
  `generator.resource_metrics`, `sink.prometheus_http`, and chart
  `RuntimeDefault` seccomp enabled; both E-Navigator pods reported
  `Seccomp: 2` and `NoNewPrivs: 1`, JSON stdout contained node, process, and
  cgroup host resource observations plus derived resource gauges and counters
  from both homelab nodes, direct `/metrics` returned 163 lines including
  resource series, and the release was rolled back to revision `107`;
- `20260623-125209-baseline-collection-live` ran the guarded collector in
  collection-only mode against `staging/e-navigator-bench`; it did not apply,
  upgrade, roll back, or clean up resources. The live DaemonSet was `2/2`
  Ready on digest
  `sha256:90b571bf89ac36c1432a503ad9b9add7abd7604579533c1912201568db1d5bfc`,
  direct `/healthz`, `/readyz`, and `/metrics` returned `200 OK`, JSON stdout
  included network source and generator output, and ten `kubectl top` samples
  recorded `41m`-`48m`/`31Mi` on `homelab-01` plus `9m`-`11m`/`21Mi`-`22Mi`
  on `homelab-02`. Prometheus API checks were skipped, older proof pods and
  fake collector services were observed but not modified, and both pods still
  reported UID `0`, `Seccomp: 0`, and `CAP_SYS_ADMIN`;
- `20260623-131846-prometheus-formatter-live` deployed the published
  formatter-change image `sha-5469a11` to the existing
  `staging/e-navigator-bench` Helm release as revision `128`, preserving the
  existing Prometheus-enabled network/native config. The DaemonSet
  stayed `2/2` Ready on digest
  `sha256:2de950aece9580dcb5c896d5df386899d12f76ccfd34b97535a34d8a3edc8738`,
  direct `/healthz`, `/readyz`, and `/metrics` returned `200 OK`, direct
  `/metrics` exposed 40 network metric lines across 8 network metric families,
  and JSON stdout contained network source and generator output. Prometheus API
  checks were skipped, no `network_flow_bytes` lines were observed,
  and both pods still reported UID `0`, `Seccomp: 0`, and `CAP_SYS_ADMIN`;
- `20260623-135438-profile-formatter-image-live` deployed the published
  profile-formatter image `sha-6c04aaa` to the existing
  `staging/e-navigator-bench` Helm release as revision `129`, preserving the
  existing Prometheus-enabled network/native config. The DaemonSet
  stayed `2/2` Ready on linux/amd64 digest
  `sha256:3abcd8d1c9b9b890801eeab94252f8cc507cd0dba665ddcc449cf409275b90d0`,
  direct `/healthz`, `/readyz`, and `/metrics` returned `200 OK`, direct
  `/metrics` exposed 233 network metric lines across 9 network metric
  families, and JSON stdout contained network source and generator output. This
  proves the pushed image's default runtime smoke only. It does not prove live
  profile formatter behavior because profile source/generator/export paths were
  not enabled and the captured logs contained zero profile records;
- `20260623-145037-collector-workload-cleanup-live` used the guarded collector
  with `E_NAVIGATOR_HOMELAB_CLEANUP_WORKLOAD=1` and
  `E_NAVIGATOR_HOMELAB_UNINSTALL_RELEASE=0` against
  `staging/e-navigator-bench`. The run upgraded the standing Helm release to
  published image `sha-6080e38` as revision `132`, captured rendered/live Helm
  values, Service and ServiceMonitor state, direct `/healthz`, `/readyz`, and
  `/metrics` `200 OK` responses, ten `kubectl top` samples, capability decode,
  and JSON stdout counts. It applied temporary Job
  `e-navigator-bench-workload-20260623-145037`, then deleted only the generated
  workload manifest; final exact-name inventory showed no remaining Job or pod,
  while Helm revision `132` remained deployed. This proves collector
  workload-only cleanup repeatability for standing benchmark releases, not
  controlled workload signal attribution or Prometheus server queryability;
- `20260623-151140-collector-workload-wait-live` added a bounded workload wait
  and exact workload pod artifact capture to the guarded collector. The first
  live attempt with a `180s` wait timed out after the workload had emitted all
  60 expected lines, so the collector default was raised to `300s`. The
  successful rerun upgraded the standing Helm release to published image
  `sha-6c15296` as revision `134`, recorded
  `job.batch/e-navigator-bench-workload-20260623-151140 condition met`,
  captured pod `e-navigator-bench-workload-20260623-151140-4vl4l` on
  `homelab-02` as `Succeeded` with exit code `0`, captured all 60 workload log
  lines, and deleted only the generated workload manifest while leaving Helm
  deployed. E-Navigator JSON stdout contained 261 records with the generated
  workload name, including workload-attributed opens, closes, network metrics,
  dependency graph, trace-service-path, service interaction, runtime-security,
  exec, and 18 egress TCP `network_flow_summary` records with source-side
  Kubernetes attribution and total `bytes=5358`. This proves the collector
  wait/artifact slice and observed homelab-02 controlled workload attribution
  for those families, not symmetric node coverage, destination workload
  attribution on flow summaries, `network_flow_bytes`, Prometheus
  server queryability, or reduced privilege;
- `20260622-122803-flow-einprogress-live` pushed commit `622e1aa`, waited for
  GHCR image publication, rolled
  `ghcr.io/e-navigator/e-navigator:sha-622e1aa` to
  `staging/e-navigator-bench`, ran nonblocking Python clients pinned to both
  homelab nodes, proved the observed homelab-02 target no longer emitted
  `EINPROGRESS` failure-only records, and recorded that byte-bearing controlled
  closes, controlled flow summaries, external flow agent projection, homelab-01 stdout
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
- `20260623-092819-required-image-host-resource-live` is the focused
  required-image host-resource run: image `sha-8ab271c` digest
  `sha256:249ad67fa8578ade9ecc1279bcf52a52ae6038a342b7c68844ebfd7a38d4e34e`
  rolled out on both homelab nodes under chart `RuntimeDefault` seccomp,
  emitted `source.host_resource` node/process/cgroup observations and
  `generator.resource_metrics` gauges/counters from both nodes, recorded
  `Seccomp: 2` plus `NoNewPrivs: 1` in both pods, and was rolled back to the
  pre-run revision `109`;
- `20260623-094439-required-image-profile-live` is the focused required-image
  CPU profile run: image `sha-8ab271c` digest
  `sha256:249ad67fa8578ade9ecc1279bcf52a52ae6038a342b7c68844ebfd7a38d4e34e`
  rolled out on both homelab nodes under chart `RuntimeDefault` seccomp,
  emitted 9,038 `profile_sample_observation` records and 8,991
  `profiling_session_observation` records across both nodes, recorded
  `Seccomp: 2` plus `NoNewPrivs: 1` in both pods, and was rolled back to the
  pre-run revision `111`; the controlled hot Python workload completed but did
  not appear in captured profile records;
- `20260623-101215-required-image-dns-version-boundary` is a local parser
  boundary check for the required image: current-head accepted a config enabling
  `source.aya_dns`, but
  `ghcr.io/e-navigator/e-navigator:sha-8ab271c` rejected the same config with
  `unknown module 'source.aya_dns'`; this means live DNS source output cannot be
  proven on the required image without changing the required benchmark image;
- `20260623-101950-required-image-exporter-version-boundary` is a local parser
  boundary check for the required image export surfaces: current-head accepted
  configs enabling `sink.prometheus_http` and `sink.otlp_http`, but
  `ghcr.io/e-navigator/e-navigator:sha-8ab271c` rejected them with
  `unknown module 'sink.prometheus_http'` and
  `unknown module 'sink.otlp_http'`; this means Prometheus and OTLP export
  cannot be proven on the required image without changing the required
  benchmark image;
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
  `ghcr.io/e-navigator/e-navigator:sha-a66e1ca`, but no homelab collector
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
- `20260623-065356-live-profile-otlp-aya` records a DaemonSet-based
  `staging/e-navigator-bench` run with pushed image `sha-6037089`,
  `source.aya_cpu_profile`, `generator.profiling`, and profile-only
  `sink.otlp_http` enabled against a namespace-local OpenTelemetry Collector
  `0.130.0`; a controlled CPU workload on `homelab-02` completed, E-Navigator
  JSON stdout captured 33 workload-attributed profile samples plus 33
  workload-attributed profiling sessions, the Collector debug exporter decoded
  1,874 live `ResourceProfiles`, no precise sink or Collector failure markers
  were found, all temporary Collector/workload resources were cleaned up, and
  the Helm release was rolled back to the previous baseline digest;
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
- `20260622-231600-http-live` records a bounded live HTTP-source proof on
  `staging/e-navigator-bench`: commit `cfd7ea8` passed `scripts/quality.sh`,
  GitHub CI run `27989986288`, and image publication run `27989986293`, then
  pushed image `ghcr.io/e-navigator/e-navigator:sha-cfd7ea8` digest
  `sha256:c2c850cffcc1209bebfce2e9915728718b4ab2e04a6873f9b25c59dc884e968c`
  was rolled out as Helm revision 52 with `source.aya_http` and
  `generator.request_correlation` enabled. Both homelab DaemonSet pods stayed
  Ready, and JSON stdout showed `protocol_request_observation` records from
  `source.aya_http` plus `request_span_observation` records from
  `generator.request_correlation` for real cluster traffic, including
  Kubernetes-attributed CoreDNS `GET /health` on `homelab-02`. The controlled
  Python client completed 50 HTTP requests and the controlled BusyBox `nc`
  client completed 80 HTTP requests, but neither controlled client produced
  matching protocol or request-span records in the collected E-Navigator logs.
  The release was rolled back to revision 53, restored to digest
  `sha256:90b571bf89ac36c1432a503ad9b9add7abd7604579533c1912201568db1d5bfc`,
  and the temporary HTTP proof Job, pod, and Service resources were deleted;
- `20260622-234023-http-writev-live` records the controlled-client follow-up
  on `staging/e-navigator-bench`: commit `fb9a6d1` added `sys_enter_writev`
  HTTP request capture, passed `scripts/quality.sh`, GitHub CI run
  `27991365112`, and image publication run `27991365123`, then pushed image
  `ghcr.io/e-navigator/e-navigator:sha-fb9a6d1` index digest
  `sha256:dec316f7c02504ce99e0500e423adc35398482756f634e915fe14f421d2924e0`
  and linux/amd64 digest
  `sha256:2c984944dee476bfdb27ecaa473277152a4f7b304a0ed99d24b867a90dbba751`
  rolled out as Helm revision 54 with `source.aya_http` and
  `generator.request_correlation` enabled. A Python client and server pinned to
  `homelab-02` completed 120 cleartext HTTP requests, with each complete
  request written through `os.writev`. JSON stdout contained 120
  `protocol_request_observation` records from `source.aya_http` and 120
  `request_span_observation` records from `generator.request_correlation` for
  `/proof/http-writev-20260622-234023`; 101 of each included Kubernetes
  namespace, pod, and container attribution for client pod
  `e-nav-http-writev-20260622-234023-client-msdw5`. This proves the bounded
  outbound client-side cleartext writev path on the observed homelab-02 client,
  including traceparent and request ID extraction. It does not prove symmetric
  node coverage, TLS, gRPC, inbound parsing, status-code extraction, route
  templates, retries, application errors, or multi-iovec HTTP header assembly.
  The release was rolled back to revision 55/rollback-to-53, restored to digest
  `sha256:90b571bf89ac36c1432a503ad9b9add7abd7604579533c1912201568db1d5bfc`,
  and all temporary HTTP writev workload resources were deleted;
- `20260623-030630-http-iovec-live-r9` records the split-iovec controlled
  follow-up on `staging/e-navigator-bench`: commit `7ac7ef2` removed the
  verifier-panic-prone dynamic request slice from split-iovec BPF request
  copying, passed `scripts/quality.sh`, GitHub CI run `27999145227`, and image
  publication run `27999145243`, then pushed image
  `ghcr.io/e-navigator/e-navigator:sha-7ac7ef2` index digest
  `sha256:c8fe0da75d741e2ce2993e7006d5384fe6f76904e4d00b10e8fbdc30bc7c5c48`
  and linux/amd64 digest
  `sha256:7967acb8ca974c6e0fbdd578c33d1229bfb04b8112ebbc7c546eccaea3b99818`
  rolled out as Helm revision 72 with `source.aya_http` and
  `generator.request_correlation` enabled. The DaemonSet stayed `2/2` Ready
  with zero restarts, and the startup-log scan found none of the previous BPF
  verifier failure markers. A first Python job completed 80 requests whose
  request line was split across two `writev` iovecs and produced 80
  `protocol_request_observation` plus 80 `request_span_observation` records for
  `/proof/http-iovec-r9-20260623-030630`, with 80 unique request IDs but no
  Kubernetes fields. A paced follow-up job completed 20 warmups and 80 measured
  split-iovec proof requests for `/proof/http-iovec-r9b-20260623-030630`; all
  80 measured protocol records and all 80 measured request-span records
  included Kubernetes namespace `e-navigator-bench`, pod
  `http-iovec-r9b-dptfg`, and container `workload`. This proves bounded
  two-slot split `writev` request assembly, request-span generation, request ID
  extraction, and Host extraction on the observed homelab-02 client. It does
  not prove symmetric node coverage, more than two iovec slots, chunks larger
  than the configured bounded slot size, TLS, gRPC, inbound parsing,
  status-code extraction, route templates, retries, application errors, or
  production replacement readiness. The temporary Jobs were deleted, and the
  release was rolled back to revision 73/rollback-to-71 with baseline digest
  `sha256:90b571bf89ac36c1432a503ad9b9add7abd7604579533c1912201568db1d5bfc`;
- `20260623-030344-http-three-iovec-live` records the three-slot split-iovec
  follow-up on `staging/e-navigator-bench`: commit `396e70d` added local
  decoder and structural guard coverage for three bounded HTTP `writev` iovec
  slots, passed `scripts/quality.sh`, GitHub CI run `28005540728`, and image
  publication run `28005540720`, then pushed image
  `ghcr.io/e-navigator/e-navigator:sha-396e70d` index digest
  `sha256:5f2060de32c6206b07868e43cccaa59ebf2489fae34edf2d6646b565354ce84a`
  and linux/amd64 digest
  `sha256:64ee132ff66b21c8f9d449ff701372858bde37258e1502f900e9d1afe806959a`.
  Helm revision 92 rolled out the corrected live config, but `source.aya_http`
  failed BPF verifier loading with `BPF program is too large. Processed
  1000001 insn` and `processed 1000001 insns (limit 1000000)`. No controlled
  three-iovec workload was run. The release was rolled back to revision
  93/rollback-to-91 with baseline digest
  `sha256:90b571bf89ac36c1432a503ad9b9add7abd7604579533c1912201568db1d5bfc`.
- `20260623-033542-http-three-iovec-bounded-live` records the bounded
  three-slot follow-up on `staging/e-navigator-bench`: commit `30c2026`
  changed the split `writev` event shape to three explicit 96-byte iovec slots,
  passed `scripts/quality.sh`, GitHub CI run `28006891441`, and image
  publication run `28006891438`, then pushed image
  `ghcr.io/e-navigator/e-navigator:sha-30c2026` index digest
  `sha256:6dfffd7dd40a76a1c18573c8a4f85677518228a2c45ac8a4ee042f30ad11d000`
  and linux/amd64 digest
  `sha256:2d17c1e7aeccc59c3ac73ef7b32684b9215b8b0db4f138376b0f0f32ef24778c`.
  Helm revision 94 kept both homelab pods Ready with `source.aya_http` and
  `generator.request_correlation` enabled. A Python workload pinned to
  `homelab-02` completed 20 warmups and 80 measured requests through
  `os.writev` with request-line, Host, and request-ID data split across three
  iovecs of 24, 27, and 71 bytes. JSON stdout contained 80 measured
  `protocol_request_observation` records plus 80 measured
  `request_span_observation` records for `/proof/iovec3-033542`, 80 unique
  `i3-proof-*` request IDs, and Kubernetes namespace `e-navigator-bench`, pod
  `http-iovec3-033542-gsbxx`, and container `workload` on every measured proof
  record. A two-iovec control also produced 20 protocol and 20 request-span
  records on the same pushed image. trace backendrary proof/control Jobs were deleted.
  Cleanup briefly saw `staging` API readiness/refusal flapping, then rollback
  completed to revision 95/rollback-to-93 with baseline digest
  `sha256:90b571bf89ac36c1432a503ad9b9add7abd7604579533c1912201568db1d5bfc`
  and the DaemonSet verified `2/2` Ready;
- `20260623-072108-http-symmetric-iovec-live` records a symmetric-node boundary
  pass on `staging/e-navigator-bench` using pushed image `sha-416e88c` index
  digest
  `sha256:2b6094593c71313f9e2a50cc24fb4247e975243d4c86bd9c0d60a94a27eabd0a`.
  Helm revision 114 enabled `source.aya_http`, `source.aya_network`,
  `generator.request_correlation`, `generator.network_metrics`,
  `sink.json_stdout`, and `sink.prometheus_http` under `RuntimeDefault`
  seccomp. Two Python Jobs completed 20 warmups and 80 measured three-iovec
  proof requests each, one pinned to `homelab-01` and one pinned to
  `homelab-02`. The `homelab-02` workload produced 80
  `protocol_request_observation` records plus 80 `request_span_observation`
  records with Kubernetes namespace, pod, and container attribution on every
  measured proof record, and direct `/metrics` exposed controlled workload
  network counters at value `100`. The `homelab-01` workload completed
  successfully but produced zero exact-path protocol/request-span records and
  zero matching network-source or network-metric records for its pod. The run
  was therefore partial, not symmetric HTTP proof. trace backendrary Jobs were deleted,
  rollback completed to revision 115/rollback-to-113, and the DaemonSet verified
  `2/2` Ready on baseline digest
  `sha256:90b571bf89ac36c1432a503ad9b9add7abd7604579533c1912201568db1d5bfc`;
- `20260623-073736-http-homelab01-diagnostics-live` records a follow-up
  homelab-01 diagnostic on `staging/e-navigator-bench` using pushed image
  `sha-d83e5bf` index digest
  `sha256:5dffedd5d3d23942cff39c4943c4ff6a7be76cef1673b29dedfe6abb535927b5`.
  Helm revision 116 enabled the same HTTP, network, request-correlation,
  network-metric, JSON stdout, and Prometheus HTTP modules under
  `RuntimeDefault` seccomp. Three homelab-01 workloads completed successfully:
  self-connect three-iovec `writev` (`60` measured requests), self-connect
  `sendall` (`60` measured requests), and split client/server three-iovec
  `writev` (`60` measured requests). Direct homelab-01 `/metrics` exposed
  Kubernetes-attributed controlled workload network counters for all three
  pods, with open/protocol-open/destination/duration counts of `60`, `67`, and
  `95` respectively. Captured JSON stdout still contained zero exact-path
  protocol/request-span records for the diagnostic proof paths, and the
  homelab-02 control workload also did not produce exact-path protocol output in
  this run. Events recorded transient apiserver/Calico sandbox teardown warnings
  during the workload window. trace backendrary resources were deleted, rollback
  completed to revision 117/rollback-to-115, and the DaemonSet verified `2/2`
  Ready on baseline digest
  `sha256:90b571bf89ac36c1432a503ad9b9add7abd7604579533c1912201568db1d5bfc`;
- `20260623-075814-http-sequential-iovec-live` records a sequential follow-up
  on `staging/e-navigator-bench` using pushed image `sha-90111f5` index digest
  `sha256:deafa27690d9c987ae1ffe5d72bfdfc909547549fb51407919727bab958d2072`
  and linux/amd64 digest
  `sha256:7cbf02d0480ee542ed0201e6533801285c05ac7124c9298b5366087c59fa88ab`.
  CI run `28020995828` and image publish run `28020995805` succeeded before
  rollout. Helm revision 118 enabled the same HTTP, network,
  request-correlation, network-metric, JSON stdout, and Prometheus HTTP modules
  under `RuntimeDefault` seccomp. After a 60-second source warmup, the
  homelab-02 control job completed 30 warmups and 80 measured three-iovec
  proof requests with zero errors, and JSON stdout contained 80 exact-path
  `protocol_request_observation` records plus 80 exact-path
  `request_span_observation` records for `/proof/iovec3-seq-075814-h02`, all
  with Kubernetes namespace, pod, and container attribution and 80 unique proof
  request IDs. The matching homelab-01 job also completed 30 warmups and 80
  measured proof requests with zero errors, but JSON stdout contained zero
  exact-path protocol/request-span records and zero rows attributed to pod
  `http-seq-075814-h01-vv6r2`. Direct `/metrics` exposed
  Kubernetes-attributed network counters at value `109` for both workload pods.
  This confirms the current boundary: homelab-01 network-metric attribution is
  present for the sequential workload shape, while homelab-01 HTTP protocol
  capture remains unproven. trace backendrary Jobs were deleted, rollback completed to
  revision 119/rollback-to-117, and the DaemonSet verified `2/2` Ready on
  baseline digest
  `sha256:90b571bf89ac36c1432a503ad9b9add7abd7604579533c1912201568db1d5bfc`;
- `20260623-111825-http-sequential-rerun-live` repeated the sequential
  three-iovec shape on `staging/e-navigator-bench` using the same pushed image
  `sha-90111f5`. Helm revision 120 enabled the HTTP, network,
  request-correlation, network-metric, JSON stdout, and Prometheus HTTP
  modules under `RuntimeDefault` seccomp. The homelab-02 control job completed
  30 warmups and 80 measured proof requests with zero errors, and JSON stdout
  contained 80 exact-path `protocol_request_observation` records plus 80
  exact-path `request_span_observation` records for
  `/proof/iovec3-seq-111825-h02`. The matching homelab-01 job also completed
  30 warmups and 80 measured proof requests with zero errors, but JSON stdout
  contained zero exact-path protocol/request-span records and zero rows
  attributed to pod `http-seq-111825-h01-tgtbm`. Direct `/metrics` exposed
  Kubernetes-attributed network counters at value `109` for the homelab-02 pod
  and `110` for the homelab-01 pod. trace backendrary Jobs were deleted, rollback
  completed to revision 121/rollback-to-119, and the DaemonSet verified `2/2`
  Ready on baseline digest
  `sha256:90b571bf89ac36c1432a503ad9b9add7abd7604579533c1912201568db1d5bfc`;
- `20260623-085800-http-stage-diagnostics-live` records the next diagnostic
  follow-up on `staging/e-navigator-bench` using pushed image `sha-8ed766a`
  index digest
  `sha256:87010498798c297c6ddd7f1f3672c312824b76281ff944f3d6f5697ba218f8bb`
  and linux/amd64 digest
  `sha256:c616e55ff011e5145648cf6e54231a7b43368600753ed75e8da5a36e24d3ee81`.
  CI run `28023920841` and image publish run `28023920824` succeeded before
  rollout. Helm revision 122 enabled the HTTP, network, request-correlation,
  network-metric, JSON stdout, Prometheus HTTP, and HTTP source diagnostic
  paths. Matching controlled workloads on `homelab-01` and `homelab-02`
  completed 30 warmups and 80 measured three-iovec proof requests each with
  zero errors. Captured JSON stdout contained zero exact-path
  `protocol_request_observation` records, zero exact-path
  `request_span_observation` records, and zero rows attributed to either
  workload pod, so this run did not reproduce the positive homelab-02 HTTP
  control. Direct `/metrics` did expose Kubernetes-attributed workload network
  counters at value `109` for both pods. The new diagnostic logger emitted six
  `source diagnostic http stage counters` lines; the latest captured line
  included `writev_enter=27`, `copy_success=1168`, `output_attempt=1168`, and
  `active_connection_miss=10116`. This proves the diagnostic counter path and
  narrows the next HTTP investigation to connection-state correlation. It does
  not prove exact-path controlled HTTP capture in this run. trace backendrary Jobs were
  deleted after transient apiserver/etcd leadership errors, rollback completed
  to revision 123/rollback-to-121, and the DaemonSet verified `2/2` Ready on
  baseline digest
  `sha256:90b571bf89ac36c1432a503ad9b9add7abd7604579533c1912201568db1d5bfc`;
- `20260623-122906-http-fallback-peer-live` records the bounded fallback HTTP
  follow-up on `staging/e-navigator-bench` using pushed image `sha-ef74874`
  index digest
  `sha256:e7a8bde9969b8f643433a55b3bb0ca658fc9013e97e09f428331b134cd418591`
  and linux/amd64 digest
  `sha256:674f2c50139bde031c09d840ec4d7ee497780dd2504b7b9469ce72b98de1aed6`.
  Local `scripts/quality.sh`, CI run `28025951181`, and image publish run
  `28025951829` succeeded before rollout. The first rollout failed as revision
  `124` because the run values omitted `ghcr-e-navigator-pull` and GHCR
  returned `403 Forbidden`; rollback restored the release as revision `125`,
  then corrected revision `126` rolled out successfully. Both controlled
  workloads completed 80 proof requests with zero workload errors. Captured
  JSON stdout contained zero exact-path `protocol_request_observation` records,
  zero exact-path `request_span_observation` records, and zero decoded records
  with the fallback Host domains. Direct `/metrics` did expose
  Kubernetes-attributed proof-pod network counters at value `109` on
  `homelab-01` and `79` on `homelab-02`. The new fallback diagnostic buckets
  emitted live; one captured line included `fallback_candidate=109405`,
  `fallback_non_http_start=108488`, and `fallback_output_attempt=916`.
  trace backendrary Jobs were deleted, rollback completed to revision
  `127`/rollback-to-125, and the DaemonSet verified `2/2` Ready on baseline
  digest
  `sha256:90b571bf89ac36c1432a503ad9b9add7abd7604579533c1912201568db1d5bfc`;
- `20260623-111601-http-sendmsg-live` records the `sys_enter_sendmsg` HTTP
  follow-up on `staging/e-navigator-bench` using pushed image `sha-e8f8575`
  index digest
  `sha256:5957f2656ba975cebdf6f655cff53eeab108a1a70605c6a9c2b026cb6b37ba20`
  and linux/amd64 digest
  `sha256:ec34257b72019c6802d338c8f310f2e2d5e5788dec7289a245d79c7f2e2c9ce1`.
  Local guards first proved the sendmsg tracepoint was wired through bounded
  `msghdr`/iovec HTTP request copying instead of remaining a no-op. CI run
  `28032489334` and image publish run `28032489764` succeeded before rollout.
  Helm revision `130` rolled out successfully with HTTP source diagnostics
  enabled. The `homelab-01` controlled `socket.sendmsg` job completed
  `ok=80/80`; the `homelab-02` job did not schedule because `homelab-02` had
  the untolerated control-plane taint. Captured JSON stdout contained zero
  exact-path `protocol_request_observation` records, zero exact-path
  `request_span_observation` records, and zero rows attributed to pod
  `http-sendmsg-111601-h01-jnjvb`. Source telemetry still reported live HTTP
  decode activity with zero lost perf events or send failures in sampled
  windows, and the diagnostic counters emitted nonzero `sendmsg_enter` plus
  bounded output activity, including captured lines with
  `sendmsg_enter=26`/`fallback_output_attempt=102`,
  `sendmsg_enter=137`/`fallback_output_attempt=42`, and
  `sendmsg_enter=548`/`fallback_output_attempt=84`. This proves the live
  sendmsg tracepoint is no longer inert, but it does not prove exact-path
  controlled sendmsg HTTP capture, request-span generation, pod attribution,
  or symmetric node coverage. trace backendrary Jobs were deleted, rollback completed
  to revision `131`/rollback-to-129, and the DaemonSet verified `2/2` Ready on
  baseline digest
  `sha256:3abcd8d1c9b9b890801eeab94252f8cc507cd0dba665ddcc449cf409275b90d0`;
- `20260623-154408-http-invalid-reason-live` records the structured invalid
  HTTP decode diagnostic follow-up on `staging/e-navigator-bench` using pushed
  image `sha-9c6463a` index digest
  `sha256:dad05511f63ebf80548e46c28d92e0de335f8c1e800bb649a2ba569c881b4362`
  and linux/amd64 digest
  `sha256:727e098764ba13cbb2d4dfcc402d8eb689f1b818985218451bb22a1919c93bfb`.
  Local focused tests, crate clippy, guards, and non-Docker quality stages
  passed; the local Docker build blocked on the Docker daemon and was
  terminated, while CI run `28037630005` and image publish run `28037630364`
  succeeded before rollout. Helm revision `135` rolled out successfully with
  HTTP diagnostics enabled. Both h01/h02 controlled three-iovec workloads
  completed 30 warmups and 80 measured proof requests with zero workload
  errors. Captured JSON stdout contained 80 exact-path
  `protocol_request_observation` records plus 80 exact-path
  `request_span_observation` records for `/proof/iovec3-stage-085800-h02`, all
  attributed to pod `http-stage-085800-h02-mqrtt` on `homelab-02`. The matching
  h01 proof path `/proof/iovec3-stage-085800-h01` still produced zero
  exact-path protocol/request-span rows. Structured invalid diagnostics emitted
  `invalid_reason="headers_too_long"` samples, with 301 captured diagnostic
  lines in the bounded log sample, and HTTP telemetry still showed zero send
  failures and zero lost perf events in sampled windows. trace backendrary Jobs were
  deleted, rollback completed to revision `136`/rollback-to-134, final context
  remained `staging`, and the DaemonSet verified `2/2` Ready on
  `sha-6c15296`;
- `20260623-160619-http-invalid-metadata-live` records the bounded invalid HTTP
  sample metadata follow-up on `staging/e-navigator-bench` using pushed image
  `sha-5cb242d` index digest
  `sha256:37d9b68cb78d18c76e99e348e536f76280a22edb207ac89f14009cab5c859dc6`
  and linux/amd64 digest
  `sha256:5a734b3e13a07727868b3433e2e6f77e1cff015b8f1a35ef9290c02bf519bbcd`.
  Local focused test, guard, crate tests, workspace clippy, workspace tests,
  synthetic CLI, Helm lint/template, and `git diff --check` passed; CI run
  `28038902204` and image publish run `28038901119` succeeded before rollout.
  Helm revision `137` rolled the metadata build, then revision `138` added a
  bounded `python` diagnostic filter. A stable rerun after collector warmup
  completed 30 warmups and 80 measured proof requests on both h01 and h02 with
  zero workload errors. Full collector log capture required `kubectl logs
  --tail=-1` because selector-based log collection otherwise returned only the
  default tail. The corrected capture contained 20,594 lines, 110 exact-path
  `protocol_request_observation` records plus 110 exact-path
  `request_span_observation` records for `/proof/invalid-meta-160619b-h02`, and
  zero exact-path rows for `/proof/invalid-meta-160619b-h01`. It also contained
  zero `invalid_http_request_sample` metadata lines, so this run proves h02
  preservation on the metadata build but does not prove h01 rejected-sample
  attribution. trace backendrary workloads were deleted, rollback completed to revision
  `139`/rollback-to-136, final context remained `staging`, and no
  `http-invalid-metadata-160619*` resources remained;
- `20260623-143751-homelab-workload-toleration-smoke` records a harness-only
  scheduling and cleanup proof. The shared workload template now includes an
  `operator: Exists` toleration so generated proof workloads can schedule on
  tainted homelab nodes such as `homelab-02`, and
  `benchmarks/runner/homelab-collect.sh` cleanup now deletes the generated
  timestamped workload manifest instead of the static template name. The guard
  failed before the toleration change, then passed after the fix. `kubeconform`
  validated `benchmarks/k8s/workload.yaml`, Docker-skipped `scripts/quality.sh`
  passed, and a bounded live smoke created pod
  `e-nav-toleration-smoke-20260623-143751` only in
  `staging/e-navigator-bench` with `nodeSelector` pinned to `homelab-02` plus
  the `Exists` toleration. The pod completed on `homelab-02`, logged
  `toleration-smoke-ok`, and label-scoped cleanup left no resources. This
  proves only harness scheduling and cleanup behavior, not E-Navigator runtime
  signal capture;
- no E-Navigator pod restarts during a short soak;
- CPU and RSS are recorded from `kubectl top` when metrics are available;
- logs, pod JSON, events, and command output are stored in
  `benchmarks/results/<timestamp>/`.

Cleanup is namespace scoped. Set `E_NAVIGATOR_HOMELAB_CLEANUP=1` to delete the
benchmark workload and uninstall the benchmark Helm release from the target
namespace.

## Homelab Observability Context

The current homelab reference stack uses external flow agent, Alloy, trace backend, and Prometheus:

- external flow agent instruments `namespace-*` tenant namespaces and sends traces to Alloy;
- Alloy receives OTLP on `4317` and `4318`, forwards traces to trace backend, and remote
  writes metrics to Prometheus;
- trace backend has service graph and span metrics generation enabled with
  `k8s.namespace.name` as a service graph dimension;
- Prometheus receives Alloy remote-write metrics and scrapes ServiceMonitors.

Future E-Navigator live proof can compare resource overhead against those
observability agents and can inspect whether controlled workload traffic appears
in the expected external flow agent/trace backend service graph topology. That comparison is not
replacement proof until live E-Navigator signals, resource overhead, and
collector/export parity are recorded.

## Proof Boundaries

Current local benchmarks prove only repeatable userspace performance for fixed
fixtures and compile-time benchmark health. They do not prove:

- privileged Aya/eBPF attachment;
- runtime DNS packet capture beyond the exact recorded live DNS runs;
- controlled client workload DNS attribution;
- controlled application-client HTTP request capture beyond the exact
  homelab-02 writev client paths observed in
  `20260622-234023-http-writev-live` and
  `20260623-030630-http-iovec-live-r9`, plus the exact bounded three-slot
  follow-up in `20260623-033542-http-three-iovec-bounded-live`;
- Kubernetes DaemonSet readiness;
- real host procfs/sysfs/cgroup accuracy;
- OTLP, Prometheus, external profile backend, pprof, or production collector export;
- DNS parser/raw decode tests as a substitute for runtime DNS packet capture;
- replacement readiness for external flow agent, Alloy, trace backend, Prometheus, or external profile backend.

Privileged runtime proof rules live in
`documentation/privileged-runtime-proof.md`.
