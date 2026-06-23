# Homelab Sample: Live Aya CPU Profile OTLP Export Proven

Run:

- `20260623-065356-live-profile-otlp-aya`

Raw evidence lives under
`benchmarks/results/20260623-065356-live-profile-otlp-aya/`.

Scope: `staging` context, `e-navigator-bench` namespace only.

Image:

- Git SHA: `6037089`
- Tag: `ghcr.io/guaracloud/e-navigator:sha-6037089`
- Image index digest:
  `sha256:75633eaeb8898f04d31a13898f1ceb5e37409dd39d1d06e1428626e4f24c1409`
- Linux/amd64 digest:
  `sha256:68fca5607652bc4dbcdb5891d1973322c9a48c198a529ace5e14414ed153a08e`
- CI run: `28007776427`
- Image publish run: `28007776456`

Local proof before deployment:

- `cargo test --locked -p e-navigator-sinks otlp_http_sink_exports_profile_records_as_otlp_protobuf -- --nocapture`
- `cargo test --locked -p e-navigator-cli profiling_enabled_fixture_enables_only_the_opt_in_cpu_profile_source -- --nocapture`
- `cargo run --locked -p e-navigator-cli -- --config benchmarks/results/20260623-065356-live-profile-otlp-aya/profile-otlp-runtime-config.toml --validate-config`
- `helm lint charts/e-navigator`
- `helm template e-navigator-bench charts/e-navigator --namespace e-navigator-bench -f benchmarks/results/20260623-065356-live-profile-otlp-aya/profile-otlp-values.yaml --set-file config.toml=benchmarks/results/20260623-065356-live-profile-otlp-aya/profile-otlp-runtime-config.toml`
- `kubectl apply --dry-run=client -f benchmarks/results/20260623-065356-live-profile-otlp-aya/collector.yaml`
- `kubectl apply --dry-run=client -f benchmarks/results/20260623-065356-live-profile-otlp-aya/cpu-workload.yaml`

Live configuration:

- Helm revision `96` deployed
  `ghcr.io/guaracloud/e-navigator@sha256:75633eaeb8898f04d31a13898f1ceb5e37409dd39d1d06e1428626e4f24c1409`.
- Runtime args were `--source aya-cpu-profile --config /etc/e-navigator/e-navigator.toml`.
- `source.aya_cpu_profile`, `generator.profiling`, `sink.json_stdout`,
  `sink.prometheus_http`, and `sink.otlp_http` were enabled.
- `sink.otlp_http` enabled only profile export and posted to namespace-local
  Collector endpoint
  `http://e-nav-live-profile-otlp-20260623-065356:4318/v1development/profiles`.
- The OpenTelemetry Collector image was `otel/opentelemetry-collector:0.130.0`
  with `service.profilesSupport` enabled and a profiles pipeline using the
  debug exporter.
- Controlled workload Job `live-profile-otlp-cpu-20260623-065356` ran on
  `homelab-02` and completed with pod
  `live-profile-otlp-cpu-20260623-065356-spk75`.

Observed evidence:

- The controlled workload completed successfully with zero restarts and logged
  `outer=289`.
- E-Navigator DaemonSet pods stayed `2/2` Ready with zero restarts during the
  proof.
- E-Navigator JSON stdout captured 6,840 `profile_sample_observation` records
  and 6,839 `profiling_session_observation` records.
- The controlled workload pod appeared in 33 live
  `profile_sample_observation` records and 33 live
  `profiling_session_observation` records with Kubernetes namespace, pod name,
  pod UID, container name, node name, labels, and containerd ID.
- The Collector debug exporter decoded 1,874 `ResourceProfiles`, 1,874
  `Profile #0` entries, and 1,874 `Location indices` entries from live
  E-Navigator OTLP profile protobuf requests.
- Precise failure marker search found zero `sink write failed`,
  `collector returned`, HTTP `400`, HTTP `404`, `wrong wireType`,
  `Bad Request`, `DecodeError`, or `ModuleFailed` entries in the captured
  E-Navigator and Collector logs.

Cleanup:

- Deleted the temporary workload Job, Collector Deployment, Collector Service,
  and Collector ConfigMap.
- Rolled Helm release `e-navigator-bench` back to revision `97`, description
  `Rollback to 95`.
- Final DaemonSet image was restored to
  `ghcr.io/guaracloud/e-navigator@sha256:90b571bf89ac36c1432a503ad9b9add7abd7604579533c1912201568db1d5bfc`.
- Final DaemonSet state was `2/2 ready`.
- Final label-scoped inventory for `e-nav-run=20260623-065356` reported no
  resources in `e-navigator-bench`.

Outcome: `proven` for live Aya/eBPF CPU profile observations and generated
profiling sessions flowing through `sink.otlp_http` as development-status OTLP
profile protobuf accepted by a namespace-local OpenTelemetry Collector `0.130.0`
on the `/v1development/profiles` route.

Not proven:

- Pyroscope write transport, pprof, profile storage, or flamegraph export.
- Symbolization or demangling quality beyond raw IP-style live stack frame
  labels.
- Broad production Collector, Tempo, Alloy, or Pyroscope compatibility.
- Collector debug output preserving the controlled workload's exact pod name;
  the workload pod identity was proven in E-Navigator JSON stdout before export,
  while the captured Collector debug excerpts showed namespace/pod attributes
  for other sampled Kubernetes workloads.
- Reduced overhead or reduced privilege.
