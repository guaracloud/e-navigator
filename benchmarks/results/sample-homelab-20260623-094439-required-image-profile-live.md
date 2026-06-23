# Homelab Sample: Required Image CPU Profile Output Under RuntimeDefault Seccomp

Run:

- `20260623-094439-required-image-profile-live`

Raw evidence lives under
`benchmarks/results/raw/20260623-094439-required-image-profile-live/`.

Scope: `staging` context, `e-navigator-bench` namespace only.

Image:

- Required benchmark tag: `ghcr.io/e-navigator/e-navigator:sha-8ab271c`
- Image digest:
  `sha256:249ad67fa8578ade9ecc1279bcf52a52ae6038a342b7c68844ebfd7a38d4e34e`

Local proof before deployment:

- `cargo run --locked -p e-navigator-cli -- --source synthetic --config benchmarks/results/raw/20260623-094439-required-image-profile-live/e-navigator.toml --validate-config`
- `docker run --rm --platform linux/amd64 -v "$PWD/benchmarks/results/raw/20260623-094439-required-image-profile-live/e-navigator.toml:/tmp/e-navigator.toml:ro" ghcr.io/e-navigator/e-navigator:sha-8ab271c --source aya-cpu-profile --config /tmp/e-navigator.toml --validate-config`
- `helm lint charts/e-navigator -f benchmarks/results/raw/20260623-094439-required-image-profile-live/values.yaml --set-file config.toml=benchmarks/results/raw/20260623-094439-required-image-profile-live/e-navigator.toml`
- `helm template e-navigator-bench charts/e-navigator -n e-navigator-bench -f benchmarks/results/raw/20260623-094439-required-image-profile-live/values.yaml --set-file config.toml=benchmarks/results/raw/20260623-094439-required-image-profile-live/e-navigator.toml`
- `kubectl --context staging -n e-navigator-bench apply --dry-run=server -f benchmarks/results/raw/20260623-094439-required-image-profile-live/rendered.yaml`
- `kubectl --context staging -n e-navigator-bench apply --dry-run=server -f benchmarks/results/raw/20260623-094439-required-image-profile-live/cpu-hot-workload.yaml`

Live configuration:

- Helm release `e-navigator-bench` upgraded from revision `111` to revision
  `112` with chart `RuntimeDefault` seccomp enabled.
- Runtime args were `--source aya-cpu-profile --config /etc/e-navigator/e-navigator.toml`.
- `source.aya_cpu_profile`, `processor.container_attribution`,
  `generator.profiling`, and `sink.json_stdout` were enabled.
- Network, exec, host-resource, metrics, trace, request, runtime-security,
  native export, Prometheus, and OTLP modules were disabled for this
  older-compatible profile run.

Observed evidence:

- DaemonSet `e-navigator-bench` rolled out successfully and stayed `2/2` Ready.
- Runtime pods were:
  - `e-navigator-bench-2cvbp` on `homelab-01`
  - `e-navigator-bench-cb5jl` on `homelab-02`
- `/proc/1/status` inside both pods reported `NoNewPrivs: 1`,
  `Seccomp: 2`, and `CapEff: 000001c401283004`.
- Both pods ran
  `ghcr.io/e-navigator/e-navigator@sha256:249ad67fa8578ade9ecc1279bcf52a52ae6038a342b7c68844ebfd7a38d4e34e`.
- The captured E-Navigator window contained 9,038
  `profile_sample_observation` records and 8,991
  `profiling_session_observation` records.
- Both homelab nodes emitted profile source and profiling generator output:
  - `homelab-01`: 7,744 profile samples and 7,697 profiling sessions
  - `homelab-02`: 1,294 profile samples and 1,294 profiling sessions
- Precise failure-marker search over the per-pod log window found zero
  `error`, `panic`, `failed`, `denied`, `Operation not permitted`, or
  `permission denied` lines.

Controlled workload:

- Hot Python Job `live-required-profile-hot-20260623-094439` completed on
  `homelab-02` as pod
  `live-required-profile-hot-20260623-094439-b4nqf` after four CPU-bound worker
  processes completed.
- The controlled workload pod appeared in zero captured
  `profile_sample_observation` records and zero
  `profiling_session_observation` records.

Cleanup:

- Deleted the temporary workload Job.
- Rolled Helm release `e-navigator-bench` back to revision `111`; Helm recorded
  revision `113` as `Rollback to 111`.
- Final DaemonSet state was `2/2` Ready on the baseline image
  `ghcr.io/e-navigator/e-navigator@sha256:90b571bf89ac36c1432a503ad9b9add7abd7604579533c1912201568db1d5bfc`.
- Final label-scoped inventory for `e-nav-run=20260623-094439-hot` reported no
  resources in `e-navigator-bench`.

Outcome: `proven` for required-image live CPU profile source output and
profiling generator output under kernel-applied RuntimeDefault seccomp on both
observed homelab nodes.

Not proven:

- Controlled workload CPU profile attribution on the required image.
- Lossless CPU profile capture or deterministic capture for all CPU workload
  shapes.
- Function symbolization or demangling beyond raw IP-style frames.
- external profile backend write transport, pprof, profile storage, flamegraph export,
  Prometheus export, or OTLP export on `sha-8ab271c`.
- DNS output, non-root operation, capability reduction, or removal of
  `CAP_SYS_ADMIN` on `sha-8ab271c`.
