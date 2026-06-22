# Homelab Sample: OTLP Profile Protobuf Collector Ingestion Proven

Run:

- `20260622-204027-otlp-profile-protobuf-live`

Raw evidence lives under
`benchmarks/results/20260622-204027-otlp-profile-protobuf-live/`.

Scope: `staging` context, `e-navigator-bench` namespace only.

Image:

- Git SHA: `796b980`
- Tag: `ghcr.io/guaracloud/e-navigator:sha-796b980`
- Image index digest: `sha256:61d9761205ba29da86de0acea4cff102d6a6d8278eca41408e05b25a1772a908`
- Linux/amd64 digest: `sha256:53e96917821745a6bb62c663d157a8aa2ab6df578b3bc8ae9700a431bfedf3ef`
- CI run: `27982082852`
- Image publish run: `27982082880`

Local proof before deployment:

- `cargo test --locked -p e-navigator-sinks otlp_http_sink_exports_profile_records_as_otlp_protobuf -- --nocapture`
- `cargo fmt --all -- --check`
- `cargo clippy --locked --workspace --all-targets --exclude e-navigator-ebpf-programs -- -D warnings`
- `cargo test --locked --workspace --exclude e-navigator-ebpf-programs`
- `cargo run --locked -p e-navigator-cli -- --source synthetic`
- `helm lint charts/e-navigator`
- `helm template e-navigator charts/e-navigator`
- `docker build -f Containerfile -t e-navigator:otlp-profile-collector .`
- `tests/smoke_docker.sh e-navigator:otlp-profile-collector`
- `scripts/quality.sh`

Live workload:

- A namespace-local OpenTelemetry Collector `0.130.0` was deployed with a
  profiles pipeline, debug exporter, and `service.profilesSupport` feature
  gate.
- A one-shot E-Navigator Job ran the pushed image `sha-796b980` with
  `--source synthetic`.
- The Job config enabled `sink.otlp_http` with `metrics_enabled = false`,
  `traces_enabled = false`, `profiles_enabled = true`, and endpoint
  `http://e-nav-otlp-profiles-20260622-204027:4318/v1development/profiles`.
- The Job completed with condition `Complete`.
- The Collector rolled out successfully and remained Ready during capture.
- The pulled Job image resolved to
  `ghcr.io/guaracloud/e-navigator@sha256:61d9761205ba29da86de0acea4cff102d6a6d8278eca41408e05b25a1772a908`.
- `failure-marker-search.txt` was empty for `sink write failed`,
  `collector returned`, HTTP `400`, HTTP `404`, `wrong wireType`, `Bad Request`,
  and `DecodeError`.
- Collector debug logs decoded `ResourceProfiles`, `Profile #0`, synthetic
  stack frame names including `synthetic_api::checkout_handler` and
  `synthetic_api::deep_frame_0` through `synthetic_api::deep_frame_3`,
  `Location indices: [1 2]`, `Location length: 2`,
  `Location indices: [1 2 3 4]`, and `Location length: 4`.
- The metrics-server sample for the Collector pod reported `6m` CPU and `15Mi`
  memory during the short run.

Cleanup:

- Deleted the temporary Job, Collector Deployment, Collector Service, and both
  ConfigMaps created for this run.
- The final label-scoped inventory for `e-nav-run=20260622-204027` reported no
  resources in `e-navigator-bench`.
- Helm release `e-navigator-bench` was not changed; revision `42` remained
  deployed before and after the proof.

Outcome: `proven` for namespace-local OpenTelemetry Collector `0.130.0`
acceptance of E-Navigator synthetic OTLP profile protobuf on the
development-status `/v1development/profiles` route.

Not proven:

- Pyroscope, pprof, or profile storage export.
- Tempo, Alloy, or broad production collector compatibility.
- Live Aya/eBPF profile export through the OTLP HTTP sink.
- Symbolization or demangling quality in live profile export.
- Reduced overhead or reduced privilege.
