# Homelab Sample: OTLP Profile Protobuf Collector Proof Blocked

Run: `20260622-142733-otlp-profile-protobuf-blocked`

Scope: intended `staging` context, `e-navigator-bench` namespace only.

Image:

- Git SHA: `a66e1ca88ac77546678028af4a405a454a036f25`
- Tag: `ghcr.io/e-navigator/e-navigator:sha-a66e1ca`
- Image index digest: `sha256:cca45ed8c6a1eaf54d1be8ee044cdde7019f18166c45d513fd421a502ba6f79e`
- Linux/amd64 digest: `sha256:f3726ba5b1161515afa8cd6e0211c48ff5f1f420d1128d7222a17a30e2d35cdc`
- CI run: `27971061684`
- Image publish run: `27971061481`

Local proof before attempted deployment:

- `cargo test -p e-navigator-sinks otlp_http_sink_exports_profile_records_as_otlp_protobuf -- --nocapture`
- `cargo test --locked -p e-navigator-sinks -- --nocapture`
- `cargo fmt --all -- --check`
- `git diff --check`
- `cargo clippy --locked --workspace --all-targets --exclude e-navigator-ebpf-programs -- -D warnings`
- `cargo test --locked --workspace --exclude e-navigator-ebpf-programs`
- `cargo run --locked -p e-navigator-cli -- --source synthetic`
- `scripts/quality.sh`

Published image proof:

- Push commit: `a66e1ca`
- GitHub CI run `27971061684`: success
- GitHub image publish run `27971061481`: success
- Published tags: `ghcr.io/e-navigator/e-navigator:main`, `ghcr.io/e-navigator/e-navigator:sha-a66e1ca`

Preflight:

- `pwd`: `/Users/victorbona/Daedalus/e-navigator`
- `kubectl config current-context`: `kind-tentacle-alpha`
- Required context: `staging`
- Namespace check on the current context returned `namespaces "e-navigator-bench" not found`

Outcome: `blocked` for homelab collector proof. The required live boundary stopped before any E-Navigator profile Job, collector Deployment, Service, ConfigMap, or Helm mutation was applied.

Local result: `proven` for encoding E-Navigator profile records as OTLP protobuf `ExportProfilesServiceRequest` payloads with `application/x-protobuf` and no internal JSON `signal_family` wrapper.

Not proven:

- Namespace-local OpenTelemetry Collector acceptance of OTLP profile protobuf.
- external profile backend, pprof, or profile storage export.
- trace backend, Alloy, or broad production collector compatibility.
- Live Aya/eBPF profile export through the OTLP HTTP sink.
- Reduced overhead or reduced privilege.
