# Homelab Sample: OTLP Trace Protobuf Collector Ingestion

Run: `20260622-160350-otlp-trace-protobuf-live`

Raw evidence lives under
`benchmarks/results/20260622-160350-otlp-trace-protobuf-live/`.

Scope: `staging` context, `e-navigator-bench` namespace only.

Image:

- Git SHA: `c00a7d5ad71c42760f3271a8b460bc500509f6fb`
- Tag: `ghcr.io/e-navigator/e-navigator:sha-c00a7d5`
- Image index digest: `sha256:4fd7c9b15969d93bdd54a4db776f2ceac4836789da110366b6fff38895c7f9ff`
- Linux/amd64 digest: `sha256:3024bad4d5b7c76d15f4b57e7d415db3fcf9d5b2410921ba2fa811e15f8fa6ae`
- CI run: `27966037985`
- Image publish run: `27966038004`

Local proof before deployment:

- `cargo fmt --all -- --check`
- `git diff --check`
- `cargo test --locked -p e-navigator-sinks -- --nocapture`
- `cargo clippy --locked --workspace --all-targets --exclude e-navigator-ebpf-programs -- -D warnings`
- `cargo test --locked --workspace --exclude e-navigator-ebpf-programs`
- `cargo run --locked -p e-navigator-cli -- --source synthetic`
- `scripts/quality.sh`
- `cargo run --locked -p e-navigator-cli -- --validate-config --config benchmarks/results/20260622-160350-otlp-trace-protobuf-live/e-navigator-otlp-config.toml`
- Server-side dry runs for `collector.yaml` and `job.yaml`

Live workload:

- A namespace-local OpenTelemetry Collector `0.130.0` received OTLP/HTTP traces on port `4318` and exported them through its debug exporter.
- A one-shot E-Navigator Job ran the pushed image `sha-c00a7d5` with `--source synthetic`.
- The Job config enabled `sink.otlp_http` with `metrics_enabled = false`, `traces_enabled = true`, `profiles_enabled = false`, and endpoint `http://e-nav-otlp-protobuf-20260622-160350:4318/v1/traces`.
- The Job completed `1/1` in 11 seconds with zero pod restarts.
- The collector logged two trace exports, each with `resource spans: 1` and `spans: 1`.
- The collector decoded span `synthetic checkout` as OTLP kind `Internal`, trace ID `4bf92f3577b34da6a3ce929d0e0e4736`, span ID `00f067aa0ba902b7`, and resource `service.name = synthetic-api`.
- The collector decoded span `http request` as OTLP kind `Server`, trace ID `4bf92f3577b34da6a3ce929d0e0e4736`, span ID `00f067aa0ba902b7`, resource `service.name = synthetic-api`, and attribute `http.request.method = GET`.
- The captured Job and collector logs contained no `sink write failed`, HTTP 4xx/5xx, collector rejection, panic, or error text.
- trace backendrary Job, ConfigMap, Deployment, and Service resources were deleted; final label-scoped inventory reported no resources found.

Outcome: `proven` for namespace-local OpenTelemetry Collector acceptance of E-Navigator OTLP protobuf trace export from synthetic trace/request records with valid trace IDs.

Not proven:

- OTLP protobuf metrics or profiles.
- trace backend storage/query behavior.
- external profile backend or pprof export.
- Live application HTTP/gRPC parsing.
- Live Aya/eBPF generation of propagated trace IDs.
- Production collector compatibility outside this namespace-local OpenTelemetry Collector.
- Reduced overhead or reduced privilege.

