# E-Navigator

A Rust and eBPF signal plane for Linux and Kubernetes observability, profiling,
runtime security, and diagnostics.

**Status:** pre-release `0.1.0` foundation. The current tree has a statically
registered signal pipeline, JSON stdout output, Kubernetes DaemonSet packaging,
release-signing workflow, strict non-privileged quality gates, and bounded
foundations for runtime, network, DNS fixture, resource, dependency, trace,
  request, profiling, Guara compatibility projection, registered export
  surfaces, and security signals. See
[documentation/claims-matrix.md](documentation/claims-matrix.md) for the exact
claim boundaries.

## What it does

`e-navigator` runs as a node-local agent and turns workload observations into
versioned signal envelopes. The project is designed to answer practical runtime
questions without application SDKs or sidecars:

- What processes, connections, resources, requests, traces, and profiles were
  observed?
- Which host, process, container, or Kubernetes workload can the signal be
  attributed to?
- Which dependency edges, low-cardinality metrics, request spans, profile
  windows, and runtime security findings can be derived safely?
- Which observations are synthetic, fixture-backed, non-privileged proven, or
  privileged runtime proven?

The default sink emits newline-delimited JSON. Opt-in Prometheus HTTP and OTLP
HTTP sink modules are registered, but live scrape, collector ingestion,
Pyroscope, pprof, storage, and UI proof still require recorded runtime evidence.

## Architecture at a glance

```text
Linux / Kubernetes node
  -> sources
     -> processors
        -> generators
           -> sinks
```

- **Sources:** synthetic fixtures, bounded host resource reads, Aya process
  exec/exit, TCP-oriented network events, opt-in DNS parser/source foundations,
  and opt-in CPU profile sampling.
- **Processors:** best-effort host, process, container, and Kubernetes
  attribution with structured warnings when context is missing.
- **Generators:** runtime security findings, network/resource metrics,
  dependency edges, trace service paths, request spans, profiling windows, and
  optional Guara compatibility projections.
- **Sinks:** JSON stdout by default, plus opt-in Prometheus HTTP and OTLP HTTP
  sink modules with bounded local tests. OTLP metric records are encoded as
  protobuf `ExportMetricsServiceRequest` payloads, and OTLP trace records with
  valid trace/span IDs are encoded as protobuf `ExportTraceServiceRequest`
  payloads. OTLP profile records are encoded as development-status
  `ExportProfilesServiceRequest` payloads in local tests, and homelab run
  `20260622-204027-otlp-profile-protobuf-live` proved namespace-local
  OpenTelemetry Collector `0.130.0` acceptance of synthetic profile protobuf
  from pushed image `sha-796b980`. Homelab run
  `20260623-065356-live-profile-otlp-aya` then proved live Aya CPU profile
  observations and generated profiling sessions flowing through
  `sink.otlp_http` as development-status OTLP profile protobuf accepted by a
  namespace-local Collector from pushed image `sha-6037089`. No Tempo,
  Pyroscope, pprof, or profile storage compatibility proof is claimed.

The pipeline is statically registered by design. Runtime plugin loading is not
part of the current architecture; see
[documentation/adr/0002-static-pipeline-registration.md](documentation/adr/0002-static-pipeline-registration.md).

## Quick start

### Run the synthetic pipeline locally

This exercises the pipeline without privileged Linux, eBPF, Docker, or
Kubernetes dependencies:

```bash
cargo run --locked -p e-navigator-cli -- --source synthetic
```

Useful CLI entry points:

```bash
cargo run --locked -p e-navigator-cli -- --help
cargo run --locked -p e-navigator-cli -- --validate-config
cargo run --locked -p e-navigator-cli -- --validate-config --config path/to/e-navigator.toml
```

### Develop the Helm chart locally

Render and validate the chart from this checkout:

```bash
helm lint charts/e-navigator
helm template e-navigator charts/e-navigator
helm template e-navigator charts/e-navigator \
  | kubeconform -strict -summary -
```

For a local development install that uses the rolling `main` image:

```bash
helm upgrade --install e-navigator charts/e-navigator \
  --namespace e-navigator-system \
  --create-namespace \
  --set image.tag=main
```

Helm rendering, schema validation, and successful installs do not prove live
eBPF behavior. Privileged runtime proof requires a capable Linux node or cluster
and observed Aya/eBPF output.

### Install a tagged release

Tagged releases publish the container image, OCI Helm chart, SBOMs, checksums,
signatures, and release manifest. After a release exists, install the chart with:

```bash
helm upgrade --install e-navigator oci://ghcr.io/guaracloud/charts/e-navigator \
  --version 0.1.0 \
  --namespace e-navigator-system \
  --create-namespace
```

Before production use, verify checksums, Cosign signatures, SBOMs, image
digests, the release manifest, and the chart digest with
[documentation/release-verification.md](documentation/release-verification.md).
Then pin the digest-backed image reference in your values file.

## Current capability map

Implemented and non-privileged proven:

- Static runtime and JSON envelopes through Cargo tests, synthetic CLI runs, and
  Docker smoke tests.
- Process exec/exit source through userspace config coverage and raw decode
  tests.
- TCP-oriented network source through raw decode tests and synthetic smoke
  coverage.
- Host resource source through procfs, sysfs, cgroup parser tests, and Docker
  synthetic fixtures.
- Dependency graph generation through generator tests and runner fan-out tests.
- Runner reliability for export outages through tests proving sink failures are
  logged and non-fatal while source failures still propagate.
- Trace and request foundations through schema, generator, formatter, fixture,
  and smoke tests, including local HTTP fixture extraction of bounded
  `url.path` attributes without query or fragment values and bounded
  `http.request.id` attributes from request ID headers, plus bounded
  `server.address` and `server.port` attributes from HTTP Host authorities and
  absolute-form HTTP request targets.
- CPU profiling foundations through raw decode, profile normalization, and
  generator tests.
- Guara compatibility contracts for the Beyla L4 metric label set, Tempo
  service-graph resource labels, Pyroscope CPU profile identity, and Guara
  tenant scoping through golden/unit tests.
- Kubernetes packaging through Helm lint/template and schema validation.
- Supply-chain checks through `cargo deny`, `cargo audit`, and
  `cargo machete`.

Implemented with narrower or deferred runtime claims:

- Runtime DNS support currently means schemas, synthetic DNS fixtures, bounded
  DNS metric/dependency generation, bounded packet parser/raw decode tests, and
  opt-in live Aya DNS capture for observed UDP DNS packet paths. Homelab run
  `20260622-013602-dns-msg-live` observed live `source.aya_dns` and
  `generator.dns_metrics` output from CoreDNS and Pi-hole with Kubernetes or
  container attribution. Homelab run
  `20260622-213109-dns-connected-udp-live-r2` proved an observed `homelab-02`
  connected-UDP Python client, while
  `20260623-005331-dns-homelab01-negative-live` still did not prove
  `homelab-01` controlled-client DNS capture. Full workload DNS coverage is
  still not proven. Homelab run
  `20260623-051700-dns-seccomp-live` proved the observed `homelab-02`
  connected-UDP Python `os.write`/`os.read` DNS path under chart
  `RuntimeDefault` seccomp, with both E-Navigator pods reporting `Seccomp: 2`
  and 148 attributed controlled `dns_query` plus 148 attributed controlled
  `dns_response` records after attribution warmup. Follow-up run
  `20260623-045808-dns-bpf-drop-diagnostics-not-proven` showed that the
  attempted BPF drop-diagnostic path was verifier-hostile on the homelab kernel
  and was reverted in `e3bc6f2`.
- HTTP `writev` capture has live proof for observed `homelab-02` clients with
  request data split across two bounded iovec slots and, in follow-up
  `20260623-033542-http-three-iovec-bounded-live`, across three explicit
  96-byte iovec slots. The three-slot run deployed pushed image `sha-30c2026`,
  kept `source.aya_http` verifier-loadable on the homelab kernel, and observed
  80 measured `protocol_request_observation` plus 80 measured
  `request_span_observation` records with 80 unique request IDs and Kubernetes
  attribution for the controlled workload. Homelab run
  `20260623-045606-http-seccomp-live` repeated the bounded three-slot proof
  under chart `RuntimeDefault` seccomp from pushed image `sha-643ea37`; both
  E-Navigator pods reported `Seccomp: 2`, and the controlled workload again
  produced 80 attributed protocol request records plus 80 attributed request
  spans. Homelab run `20260623-072108-http-symmetric-iovec-live` then tested
  the same three-iovec workload shape on both homelab nodes from pushed image
  `sha-416e88c`: the `homelab-02` workload again produced 80 attributed
  protocol request records plus 80 attributed request spans, but the
  `homelab-01` workload completed 80 proof requests with zero matching network,
  protocol, or request-span records. Symmetric HTTP coverage remains unproven.
  Follow-up diagnostic run
  `20260623-073736-http-homelab01-diagnostics-live` narrowed the
  `homelab-01` boundary: direct `/metrics` exposed Kubernetes-attributed
  controlled workload network counters for homelab-01 self-connect `writev`,
  self-connect `sendall`, and split client/server `writev` workloads, but
  captured JSON stdout still contained zero exact-path protocol/request-span
  records, and the homelab-02 control did not reproduce a fresh positive HTTP
  capture in that run. Sequential follow-up
  `20260623-075814-http-sequential-iovec-live` removed that control weakness:
  `homelab-02` again produced 80 attributed protocol records plus 80 attributed
  request spans, while the matching `homelab-01` workload produced direct
  Kubernetes-attributed network counters at `109` but zero exact-path
  protocol/request-span records. Symmetric HTTP remains unproven and is now
  bounded to homelab-01 HTTP/protocol capture rather than network metric
  attribution for this shape. Rerun
  `20260623-111825-http-sequential-rerun-live` reproduced the same boundary:
  `homelab-02` again produced 80 exact-path protocol records and 80 request
  spans, while `homelab-01` produced direct network counters at `110` and zero
  exact-path protocol/request-span records. Diagnostic follow-up
  `20260623-085800-http-stage-diagnostics-live` deployed pushed image
  `sha-8ed766a` with HTTP source stage counters enabled. Both controlled
  workloads completed 30 warmups plus 80 proof requests and both produced
  Kubernetes-attributed direct `/metrics` network counters at `109`, but
  captured JSON stdout had zero exact-path protocol/request-span rows for both
  proof paths. The new diagnostic counters emitted live and showed write/copy
  activity plus a large `active_connection_miss` bucket, narrowing the next
  investigation to connection-state correlation rather than workload network
  attribution. Follow-up `20260623-122906-http-fallback-peer-live` deployed
  pushed image `sha-ef74874` with bounded fallback emission when socket peer
  metadata is missing. After correcting an omitted GHCR pull secret, Helm
  revision 126 rolled out successfully, both proof jobs completed `ok=80/80`,
  and direct `/metrics` exposed attributed proof-pod network counters
  (`109` on `homelab-01`, `79` on `homelab-02`). The new fallback diagnostic
  buckets emitted live, including a captured line with
  `fallback_output_attempt=916`, but JSON stdout still had zero exact-path
  protocol/request-span rows and no fallback Host-derived peer rows. Exact-path
  fallback HTTP capture remains unproven. Follow-up
  `20260623-111601-http-sendmsg-live` deployed pushed image `sha-e8f8575`
  after local guards proved `sys_enter_sendmsg` was wired through bounded
  `msghdr`/iovec HTTP request copying rather than the previous no-op boundary.
  The `homelab-01` `socket.sendmsg` proof job completed `ok=80/80`, while the
  `homelab-02` job did not schedule because the node still carried the
  untolerated control-plane taint. Live diagnostics emitted nonzero
  `sendmsg_enter` and `fallback_output_attempt` counters, but JSON stdout still
  had zero exact-path protocol/request-span rows and zero rows attributed to
  the proof pod. Exact-path sendmsg HTTP capture remains unproven. Follow-up
  `20260623-154408-http-invalid-reason-live` deployed pushed image
  `sha-9c6463a` with structured invalid HTTP decode reasons. Both h01/h02
  three-iovec workloads completed 30 warmups plus 80 proof requests with zero
  workload errors. The `homelab-02` proof path again produced 80 exact-path
  protocol records and 80 request spans with Kubernetes attribution, while
  `homelab-01` still produced zero exact-path protocol/request-span records.
  Diagnostics sampled `headers_too_long` as the invalid HTTP reason, so the
  remaining symmetric blocker is still h01 HTTP/protocol capture rather than
  workload execution or h02 regression.
- Prometheus HTTP support is an opt-in registered sink with local `/metrics`,
  `/healthz`, and `/readyz` tests. Homelab run `20260621-201246` deployed image
  `sha-5c417c0`, proved live endpoint reachability, ServiceMonitor discovery,
  active Prometheus targets, nonzero scrape samples, and queryable
  E-Navigator metric series such as `network_connection_open_count`. Follow-up
  `20260623-131846` deployed published image `sha-5469a11` and kept the direct
  Prometheus HTTP endpoint plus network metric output healthy, but did not run
  Prometheus API checks or prove `beyla_network_flow_bytes_total`.
- OTLP HTTP support is an opt-in registered sink. Local fake-collector tests
  prove trace records with valid trace/span IDs are posted as OTLP protobuf
  `ExportTraceServiceRequest` payloads with `application/x-protobuf`, metric
  records as `ExportMetricsServiceRequest`, and profile records as
  development-status `ExportProfilesServiceRequest`. Homelab run
  `20260622-160350-otlp-trace-protobuf-live` proved that pushed image
  `sha-c00a7d5` delivered synthetic trace/request spans as OTLP protobuf to a
  namespace-local OpenTelemetry Collector. Homelab run
  `20260622-135450-otlp-metric-protobuf-live` proved namespace-local
  OpenTelemetry Collector acceptance of pushed image `sha-e7016b5` OTLP
  protobuf metrics. Commit `796b980` aligned development-status profile
  protobuf encoding with the OpenTelemetry Collector `0.130.0` profile schema;
  homelab run `20260622-204027-otlp-profile-protobuf-live` used pushed image
  `sha-796b980` against a namespace-local Collector with profile support
  enabled and the `/v1development/profiles` route, the one-shot Job completed,
  no sink failure markers were logged, and the Collector debug exporter decoded
  `ResourceProfiles` with synthetic stack frame names and populated location
  indices. Homelab run `20260623-065356-live-profile-otlp-aya` deployed pushed
  image `sha-6037089` as a DaemonSet with `source.aya_cpu_profile`,
  `generator.profiling`, and profile-only `sink.otlp_http` enabled, ran a
  controlled CPU workload on `homelab-02`, observed 33 workload-attributed
  profile samples plus 33 workload-attributed profiling sessions in JSON stdout,
  and the namespace-local Collector decoded 1,874 `ResourceProfiles` from live
  OTLP profile protobuf with no sink failure, HTTP 400/404, or wire-type
  markers. Homelab run
  `20260621-205344-otlp-live` proved live delivery to a namespace-local fake
  collector for internal JSON records. Homelab run
  `20260621-214450-sink-failure-live` proved that HTTP 500 responses from a
  namespace-local collector are logged and dropped for `sink.otlp_http` without
  terminating the runner or stopping Prometheus/JSON stdout. Homelab run
  `20260622-001716-published-image-live` repeated the real Alloy HTTP 400
  failure boundary with pushed GHCR image `sha-d3167e3` and kept both pods Ready
  with JSON stdout and Prometheus HTTP active. These runs are not Tempo,
  Pyroscope, Alloy, or broad production collector compatibility proof.
- Guara Beyla L4 compatibility remains generator and formatter proven, with a
  recorded live boundary. Homelab run `20260621-220029-guara-compat-live`
  enabled `generator.guara_compat` while Prometheus scraping was healthy and
  other network metrics were queryable, but `beyla_network_flow_bytes_total`
  produced 0 direct endpoint lines and 0 Prometheus results because the live Aya
  path did not emit `network_flow_summary` records. Later homelab runs proved
  ambient and controlled `network_flow_summary` records, including
  `20260623-151140-collector-workload-wait-live`, which observed 18 egress TCP
  flow summaries with source-side Kubernetes attribution for the generated
  workload on `homelab-02`. Positive `beyla_network_flow_bytes_total` export,
  destination workload attribution, Guara `proj-*` scope, Prometheus server
  queryability, and symmetric-node controlled capture remain unproven.
- CPU profile sampling is an explicit opt-in source. Homelab run
  `20260621-203358-profile-live` proved `source.aya_cpu_profile` samples and
  `generator.profiling` sessions for a controlled CPU workload, including
  Kubernetes/container attribution. Homelab run
  `20260623-065356-live-profile-otlp-aya` proved that live Aya profile records
  can also flow through the OTLP HTTP profile sink to a namespace-local
  OpenTelemetry Collector. Homelab run
  `20260623-084626-profile-seccomp-workload-live` then proved controlled hot
  Python CPU workload attribution under chart `RuntimeDefault` seccomp on
  `homelab-02`, while a lighter shell-loop workload in the same run remained
  non-proving.
- Kubernetes packaging proof is separate from privileged eBPF runtime proof.
- Resource and privilege evidence is currently a set of point-in-time runtime
  samples, not a reduced-privilege or reduced-overhead proof.
  Homelab run `20260621-221235-baseline-resource-live` captured 10
  `kubectl top` samples per E-Navigator pod, Prometheus cAdvisor CPU and memory
  series, rendered security context, and decoded capabilities. Homelab run
  `20260622-001716-published-image-live` repeated resource and capability
  capture on pushed image `sha-d3167e3`. Homelab runs
  `20260623-041434-runtime-default-seccomp-live`,
  `20260623-043123-profile-seccomp-live`, and
  `20260623-045606-http-seccomp-live`,
  `20260623-051700-dns-seccomp-live`, and
  `20260623-084626-profile-seccomp-workload-live` proved selected network, CPU
  profile, HTTP, and DNS source modes under kernel-applied `Seccomp: 2`.
  Homelab run `20260623-091319-host-resource-seccomp-live` then proved
  `source.host_resource` and `generator.resource_metrics` under the same
  seccomp boundary on both homelab nodes. These runs still
  do not prove reduced overhead or reduced privilege because no equivalent
  baseline comparison was captured and the pods still ran as UID 0 with
  `CAP_SYS_ADMIN`.
- The collection-only baseline run
  `20260623-125209-baseline-collection-live` recorded the current homelab
  DaemonSet as `2/2` Ready with direct Prometheus HTTP `200 OK` responses,
  network JSON/stdout output, and ten resource samples, but it also confirmed
  the live baseline still runs as UID 0 with `Seccomp: 0` and `CAP_SYS_ADMIN`.
- The published-image follow-up `20260623-131846-prometheus-formatter-live`
  upgraded the homelab benchmark release to image `sha-5469a11`, kept the
  DaemonSet `2/2` Ready with direct Prometheus HTTP `200 OK`, and left the
  release on revision `128`; it does not prove Prometheus server scrape or
  Guara-compatible byte-flow export.
- The published-image follow-up `20260623-135438-profile-formatter-image-live`
  upgraded the homelab benchmark release to image `sha-6c04aaa`, kept the
  DaemonSet `2/2` Ready with direct Prometheus HTTP `200 OK`, and left the
  release on revision `129`; it proves only the pushed image's default runtime
  smoke. The profile formatter improvement remains local Criterion evidence
  because the live baseline did not enable profile source/generator/export
  paths and captured zero profile records.
- Persisted service maps, production exporters, storage, UI, and container
  vulnerability policy gates are deferred.

For the authoritative and more detailed version, use
[documentation/claims-matrix.md](documentation/claims-matrix.md).

## What is not claimed yet

E-Navigator is not yet a full observability backend, Pyroscope replacement,
Tempo replacement, pprof server, flamegraph UI, profile store, trace store, or
critical-path analysis engine.

The following are intentionally not claimed as implemented production behavior:

- production collector or backend OTLP deployment compatibility;
- pprof or Pyroscope export;
- complete Beyla replacement or alloy-profiles replacement;
- live Beyla-compatible `beyla_network_flow_bytes_total` export from traffic;
- profile storage, flamegraph rendering, or bottleneck analysis;
- complete live HTTP/gRPC parsing from real traffic; `source.aya_http` has
  bounded opt-in live proof for observed cleartext cluster traffic and
  controlled `homelab-02` clients using `writev` with up to three explicit
  96-byte iovec slots, including one run under kernel-applied `Seccomp: 2`, but
  the symmetric run `20260623-072108-http-symmetric-iovec-live` produced zero
  controlled `homelab-01` network or HTTP records, and the sendmsg follow-up
  `20260623-111601-http-sendmsg-live` produced zero exact-path controlled
  protocol/request-span records. It does not prove symmetric node coverage,
  TLS, gRPC framing, inbound server-side parsing,
  status-code extraction, route templates, retries, application errors, more
  than three iovec slots, chunks larger than 96 bytes per slot, or broader
  multi-iovec HTTP header assembly;
- privileged-proven runtime DNS packet capture beyond the exact recorded live
  DNS runs; controlled-client DNS remains proven only for the recorded
  `homelab-02` path, not symmetrically across both homelab nodes;
- full TCP state tracking, packet accounting, retransmits, or resets;
- reduced-privilege Kubernetes eBPF operation.
- reduced overhead versus existing homelab observability agents.

Do not treat synthetic fixtures, Docker smoke tests, Kubernetes schema checks, and
privileged Linux or cluster runtime evidence as interchangeable.

## Building and testing

Run the full non-privileged local gate:

```bash
scripts/quality.sh
```

The strict gate requires `cargo-deny`, `cargo-audit`, `cargo-machete`, Docker,
Helm, `kubeconform`, Node, and the normal Rust toolchain. In constrained local
environments only, narrow skips are available:

```bash
E_NAVIGATOR_SKIP_SUPPLY_CHAIN=1 scripts/quality.sh
E_NAVIGATOR_SKIP_DOCKER=1 E_NAVIGATOR_SKIP_KUBERNETES=1 scripts/quality.sh
```

Useful direct checks:

```bash
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets \
  --exclude e-navigator-ebpf-programs -- -D warnings
cargo test --locked --workspace --exclude e-navigator-ebpf-programs
cargo build --locked --workspace --exclude e-navigator-ebpf-programs
cargo run --locked -p e-navigator-cli -- --source synthetic
cargo deny check
cargo audit
cargo machete
docker build -f Containerfile -t e-navigator:local .
docker run --rm e-navigator:local --source synthetic
tests/smoke_docker.sh e-navigator:local
tests/packaged_config_guard_test.sh
tests/secret_pattern_guard_test.sh
tests/chart_service_guard_test.sh
kubeconform -strict -summary deploy/kubernetes/*.yaml
helm template e-navigator charts/e-navigator | kubeconform -strict -summary -
node website/check-links.mjs
git diff --check
```

Local benchmark and validation methodology lives in
[documentation/benchmark.md](documentation/benchmark.md). The short local
benchmark smoke command is:

```bash
benchmarks/runner/local-bench-smoke.sh
```

Aya/eBPF development also requires the nightly Rust toolchain with `rust-src`,
`bpf-linker`, `clang`, `llvm`, and `bpftool`.

`cargo deny` currently keeps duplicate dependency versions at warning level in
`deny.toml`. This keeps the gate focused on actionable license, advisory,
source, yanked, and unused-dependency failures while transitive ecosystem
convergence is tracked without blocking unrelated systems work.

## Privileged Linux smoke tests

Run these only on a capable Linux host or cluster with the documented eBPF,
tracefs, perf-event, and Kubernetes privileges:

```bash
scripts/smoke_aya_exec_linux.sh
scripts/smoke_aya_cpu_profile_linux.sh <config>
```

The `aya-exec` source mode registers the statically compiled Aya exec and
network sources when both modules are enabled. The `aya-cpu-profile` source
mode registers only `source.aya_cpu_profile` when its module and
`[cpu_profile_source] enabled = true` are configured.

## Documentation

- [CONTRIBUTING.md](CONTRIBUTING.md): contributor workflow and local gates.
- [documentation/claims-matrix.md](documentation/claims-matrix.md): implemented,
  proven, privileged, and deferred claims.
- [documentation/engineering-invariants.md](documentation/engineering-invariants.md):
  boundaries that must stay true as the system grows.
- [documentation/helm.md](documentation/helm.md): chart install and values
  guidance.
- [documentation/benchmark.md](documentation/benchmark.md): local benchmarks,
  result artifact policy, and guarded homelab validation plan.
- [documentation/privileged-runtime-proof.md](documentation/privileged-runtime-proof.md):
  rules for recording privileged Linux or Kubernetes runtime evidence.
- [documentation/release-verification.md](documentation/release-verification.md):
  checksums, signatures, SBOMs, images, charts, and release manifests.
- [documentation/module-authoring.md](documentation/module-authoring.md): how to
  add sources, processors, generators, and sinks without breaking the static
  pipeline.
- [documentation/vision.md](documentation/vision.md): long-range product vision.

Architecture decision records live under [documentation/adr/](documentation/adr/).

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE).
