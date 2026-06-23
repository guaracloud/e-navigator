# Homelab Sample: OTLP Metric Protobuf Collector Ingestion

Run: `20260622-135450-otlp-metric-protobuf-live`

Raw evidence lives under
`benchmarks/results/20260622-135450-otlp-metric-protobuf-live/`.

Scope: `staging` context, `e-navigator-bench` namespace only.

Image:

- Git SHA: `e7016b5808dbb269981e62aef288469810255bc0`
- Tag: `ghcr.io/e-navigator/e-navigator:sha-e7016b5`
- Image index digest: `sha256:d5697141e1b56ad8ba2e72ca541ccc096c24156e3a5e5c4b0bf1af13fb451c83`
- Linux/amd64 digest: `sha256:09d329565302616fcef011ff22e9b9e7c896e0294cd3197bc0382f0bedec8d1c`
- CI run: `27969101982`
- Image publish run: `27969103256`

Local proof before deployment:

- `cargo test -p e-navigator-sinks otlp_http_sink_exports_metric_records_as_otlp_protobuf -- --nocapture`
- `cargo test --locked -p e-navigator-sinks -- --nocapture`
- `cargo fmt --all -- --check`
- `cargo clippy --locked --workspace --all-targets --exclude e-navigator-ebpf-programs -- -D warnings`
- `git diff --check`
- `cargo test --locked --workspace --exclude e-navigator-ebpf-programs`
- `cargo run --locked -p e-navigator-cli -- --source synthetic`
- `scripts/quality.sh`
- `cargo run --locked -p e-navigator-cli -- --validate-config --config benchmarks/results/20260622-135450-otlp-metric-protobuf-live/e-navigator-otlp-metrics-config.toml`
- Server-side dry runs for `collector.yaml` and `job.yaml`

Live workload:

- A namespace-local OpenTelemetry Collector `0.130.0` received OTLP/HTTP
  metrics on port `4318` and exported them through its debug exporter.
- A one-shot E-Navigator Job ran the pushed image `sha-e7016b5` with
  `--source synthetic`.
- The Job config enabled `sink.otlp_http` with `metrics_enabled = true`,
  `traces_enabled = false`, `profiles_enabled = false`, and endpoint
  `http://e-nav-otlp-metrics-20260622-135450:4318/v1/metrics`.
- The Job completed `1/1` in 9 seconds with zero pod restarts.
- The collector decoded 45 OTLP metrics across network, DNS, system, process,
  and container families.
- Decoded metric names included `network.connection.open.count`,
  `network.connection.duration`, `dns.query.count`,
  `dns.response.code.count`, `dns.lookup.duration`, `system.cpu.time`,
  `process.memory.usage`, and `container.cpu.time`.
- The collector decoded OTLP Sum, Gauge, and Summary data types, including
  monotonic Delta Sums and Summary quantile values for duration metrics.
- Decoded attributes included `net.transport = tcp` and Kubernetes resource
  attributes such as `k8s.namespace.name = e-navigator-system`,
  `k8s.node.name = synthetic-node`, and
  `k8s.pod.name = e-navigator-synthetic`.
- The captured Job and collector logs contained no sink transport failure,
  HTTP 4xx/5xx, collector rejection, panic, or decode error text in the
  refined negative search.
- trace backendrary Job, ConfigMap, Deployment, and Service resources were deleted;
  final label-scoped inventory reported no resources found.

Outcome: `proven` for namespace-local OpenTelemetry Collector acceptance of
E-Navigator OTLP protobuf metric export from synthetic network, DNS, system,
process, and container metric records.

Not proven:

- OTLP protobuf profiles.
- trace backend, Prometheus remote-write, or external profile backend storage/query behavior.
- Live application HTTP/gRPC parsing.
- Live Aya/eBPF generation of these metric records.
- Production collector compatibility outside this namespace-local
  OpenTelemetry Collector.
- Reduced overhead or reduced privilege.
