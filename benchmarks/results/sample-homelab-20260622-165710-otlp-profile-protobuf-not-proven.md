# Homelab Sample: OTLP Profile Protobuf Collector Ingestion Not Proven

Run family:

- `20260622-165054-otlp-profile-protobuf-live`
- `20260622-165437-otlp-profile-protobuf-live`
- `20260622-165710-otlp-profile-protobuf-live`

Raw evidence lives under the matching `benchmarks/results/<run>/` directories.

Scope: `staging` context, `e-navigator-bench` namespace only.

Image:

- Git SHA: `35ecc6c`
- Tag: `ghcr.io/guaracloud/e-navigator:sha-35ecc6c`
- Image index digest: `sha256:c55bd7bd336d8fa7251db0bcd99a3fcf4d51bf5b49d7356d06a86d584f8eb6f8`
- Linux/amd64 digest: `sha256:be54100409aa2fc6f3c520e7ee1cecf397dce6a126a44531a27092c230b00ec9`
- CI run: `27979164318`
- Image publish run: `27979164334`

Local proof before deployment:

- `cargo run --locked -p e-navigator-cli -- --validate-config --config benchmarks/results/20260622-165710-otlp-profile-protobuf-live/e-navigator-otlp-profiles-config.toml`
- Server-side dry runs for `collector.yaml` and `job.yaml`

Live workload:

- A namespace-local OpenTelemetry Collector `0.130.0` was deployed with a
  profiles pipeline and debug exporter.
- A one-shot E-Navigator Job ran the pushed image `sha-35ecc6c` with
  `--source synthetic`.
- The Job config enabled `sink.otlp_http` with `metrics_enabled = false`,
  `traces_enabled = false`, `profiles_enabled = true`, and endpoint
  `http://e-nav-otlp-profiles-20260622-165710:4318/v1development/profiles`.
- The corrected Job completed `1/1` in 5 seconds with zero pod restarts.
- The corrected Collector remained Ready with zero pod restarts.
- Temporary Job, ConfigMap, Deployment, and Service resources were deleted; the
  final label-scoped inventory reported no resources.

Observed negative evidence:

- The first attempt used `/v1/profiles` without the collector feature gate. The
  collector rejected the config with `service.profilesSupport` required.
- The second attempt enabled `service.profilesSupport`, and the collector
  started, but `/v1/profiles` returned HTTP `404`.
- A namespace-scoped port-forward path probe against the running collector
  showed `/v1development/profiles` returned HTTP `200` for an empty protobuf
  POST, while `/v1/profiles` returned HTTP `404`.
- The final attempt used `service.profilesSupport` and
  `/v1development/profiles`, but E-Navigator logged `sink write failed` for
  profile exports with `collector returned HTTP 400`.
- The collector debug exporter did not log decoded `ResourceProfiles` or a
  `process_cpu:cpu:nanoseconds:cpu:nanoseconds` profile payload.

Outcome: `not proven` for namespace-local OpenTelemetry Collector acceptance of
E-Navigator OTLP profile protobuf.

Local result that still holds: E-Navigator can encode profile records as
development-status OTLP protobuf `ExportProfilesServiceRequest` payloads that
decode with the local `opentelemetry-proto` Rust type.

Not proven:

- Live OpenTelemetry Collector acceptance of E-Navigator profile protobuf.
- Pyroscope, pprof, or profile storage export.
- Tempo, Alloy, or broad production collector compatibility.
- Live Aya/eBPF profile export through the OTLP HTTP sink.
- Reduced overhead or reduced privilege.
