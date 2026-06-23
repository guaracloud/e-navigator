# Homelab Sample: Controlled CPU Profile Attribution Under RuntimeDefault Seccomp

Run:

- `20260623-084626-profile-seccomp-workload-live`

Raw evidence lives under
`benchmarks/results/raw/20260623-084626-profile-seccomp-workload-live/`.

Scope: `staging` context, `e-navigator-bench` namespace only.

Image:

- Git SHA: `7d772fca9a22bfb5c1a6ad93da0110a338c63407`
- Tag: `ghcr.io/guaracloud/e-navigator:sha-7d772fc`
- Image index digest:
  `sha256:029c384ba7d050feec2fee908fa7357a58dfb2bf20ff0b893b34142b93faa9b1`
- Linux/amd64 digest:
  `sha256:820e9fa79e444bd1d54a41c6c2b11ec5713051ae826c2c9a045ef9716e42fe0c`
- CI run: `28013499073`
- Image publish run: `28013499062`

Local proof before deployment:

- `cargo run --locked -p e-navigator-cli -- --source synthetic --config benchmarks/results/raw/20260623-084626-profile-seccomp-workload-live/profile-seccomp-runtime-config.toml --validate-config`
- `helm lint charts/e-navigator -f benchmarks/results/raw/20260623-084626-profile-seccomp-workload-live/profile-seccomp-values.yaml --set-file config.toml=benchmarks/results/raw/20260623-084626-profile-seccomp-workload-live/profile-seccomp-runtime-config.toml`
- `helm template e-navigator-bench charts/e-navigator -n e-navigator-bench -f benchmarks/results/raw/20260623-084626-profile-seccomp-workload-live/profile-seccomp-values.yaml --set-file config.toml=benchmarks/results/raw/20260623-084626-profile-seccomp-workload-live/profile-seccomp-runtime-config.toml`
- `kubectl --context staging -n e-navigator-bench apply --dry-run=server -f benchmarks/results/raw/20260623-084626-profile-seccomp-workload-live/cpu-workload.yaml`
- `kubectl --context staging -n e-navigator-bench apply --dry-run=server -f benchmarks/results/raw/20260623-084626-profile-seccomp-workload-live/cpu-hot-workload.yaml`

Live configuration:

- Helm release `e-navigator-bench` upgraded from revision `105` to revision
  `106` with chart `RuntimeDefault` seccomp enabled.
- Runtime args were `--source aya-cpu-profile --config /etc/e-navigator/e-navigator.toml`.
- `source.aya_cpu_profile`, `processor.container_attribution`,
  `generator.profiling`, `sink.json_stdout`, and `sink.prometheus_http` were
  enabled.
- `sink.otlp_http`, network, exec, DNS, HTTP, resource, trace, request,
  runtime-security, and Guara compatibility modules were disabled for this run.

Observed evidence:

- DaemonSet `e-navigator-bench` rolled out successfully and stayed `2/2` Ready.
- Runtime pods were:
  - `e-navigator-bench-m9zfw` on `homelab-02`
  - `e-navigator-bench-vgs2d` on `homelab-01`
- `/proc/1/status` inside both pods reported `NoNewPrivs: 1` and
  `Seccomp: 2`.
- Both pods ran
  `ghcr.io/guaracloud/e-navigator@sha256:029c384ba7d050feec2fee908fa7357a58dfb2bf20ff0b893b34142b93faa9b1`.
- Single shell-loop Job `live-profile-seccomp-cpu-20260623-084626` completed
  on `homelab-02` as pod
  `live-profile-seccomp-cpu-20260623-084626-5ln6q` and logged `outer=315`, but
  produced zero controlled profile samples and zero controlled profiling
  sessions in the captured window.
- Hot Python Job `live-profile-seccomp-hot-20260623-084626` completed on
  `homelab-02` as pod
  `live-profile-seccomp-hot-20260623-084626-qrrt8` after four CPU-bound worker
  processes completed.
- The hot-workload E-Navigator window captured 8,672
  `profile_sample_observation` records and 8,643
  `profiling_session_observation` records.
- The controlled hot Python pod appeared in 726 live
  `profile_sample_observation` records and 726 live
  `profiling_session_observation` records with Kubernetes namespace
  `e-navigator-bench`, pod name, container name, node name, labels, and
  containerd identity.
- Precise failure-marker search over the hot E-Navigator window found zero
  `error`, `panic`, `failed`, `denied`, `Operation not permitted`, or
  `permission denied` lines.

Cleanup:

- Deleted both temporary workload Jobs.
- Rolled Helm release `e-navigator-bench` back to revision `105`; Helm recorded
  revision `107` as `Rollback to 105`.
- Final DaemonSet state was `2/2` Ready on the baseline image
  `ghcr.io/guaracloud/e-navigator@sha256:90b571bf89ac36c1432a503ad9b9add7abd7604579533c1912201568db1d5bfc`.
- Final label-scoped inventory for `e-nav-run in (20260623-084626,
  20260623-084626-hot)` reported no resources in `e-navigator-bench`.

Outcome: `proven` for controlled hot Python CPU profile attribution under
kernel-applied RuntimeDefault seccomp on the observed `homelab-02` workload.

Not proven:

- Lossless CPU profile capture or deterministic capture for all CPU workload
  shapes; the single shell-loop workload in this run completed without matching
  profile records.
- Symmetric node coverage for controlled CPU profile attribution.
- Pyroscope write transport, pprof, profile storage, or flamegraph export.
- Symbolization or demangling quality beyond raw IP-style frames.
- Non-root operation, capability reduction, or removal of `CAP_SYS_ADMIN`.
