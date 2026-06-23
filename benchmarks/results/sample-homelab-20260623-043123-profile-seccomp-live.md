# Homelab Sample: CPU Profile Source Under RuntimeDefault Seccomp

Run:

- `20260623-043123-profile-seccomp-live`

Raw evidence lives under
`benchmarks/results/20260623-043123-profile-seccomp-live/`.

Scope: `staging` context, `e-navigator-bench` namespace only.

Image:

- Git SHA: `6c739f8`
- Tag: `ghcr.io/guaracloud/e-navigator:sha-6c739f8`
- Image index digest:
  `sha256:124c622387a5355a9b5f05a6e133859a1f2f5f25d41beac53942d5d7cc3d1ccb`
- Linux/amd64 digest:
  `sha256:9c307f7d6094d67654e2a750efa810f1342fb5d3e915dff50da7f6d95353b760`
- CI run: `28009565530`
- Image publish run: `28009565572`

Local proof before deployment:

- `cargo run --quiet --locked -p e-navigator-cli -- --config benchmarks/results/20260623-043123-profile-seccomp-live/profile-seccomp-runtime-config.toml --validate-config`
- `helm lint charts/e-navigator`
- `helm template e-navigator-bench charts/e-navigator --namespace e-navigator-bench -f benchmarks/results/20260623-043123-profile-seccomp-live/profile-seccomp-values.yaml --set-file config.toml=benchmarks/results/20260623-043123-profile-seccomp-live/profile-seccomp-runtime-config.toml`
- `helm template e-navigator-bench charts/e-navigator --namespace e-navigator-bench -f benchmarks/results/20260623-043123-profile-seccomp-live/profile-seccomp-values.yaml --set-file config.toml=benchmarks/results/20260623-043123-profile-seccomp-live/profile-seccomp-runtime-config.toml | kubeconform -strict -summary -`
- `kubectl apply --dry-run=client --context staging -f benchmarks/results/20260623-043123-profile-seccomp-live/cpu-workload.yaml`
- `kubectl apply --dry-run=client --context staging -f benchmarks/results/20260623-043123-profile-seccomp-live/cpu-hot-workload.yaml`

Live configuration:

- Helm release `e-navigator-bench` upgraded from revision `99` to revision
  `100` with the local chart defaulting the container to
  `seccompProfile.type: RuntimeDefault`.
- Runtime args were `--source aya-cpu-profile --config /etc/e-navigator/e-navigator.toml`.
- `source.aya_cpu_profile`, `processor.container_attribution`,
  `generator.profiling`, `sink.json_stdout`, and `sink.prometheus_http` were
  enabled.
- `sink.otlp_http`, network, exec, DNS, HTTP, resource, trace, request,
  runtime-security, and Guara compatibility modules were disabled for this run.

Observed evidence:

- DaemonSet `e-navigator-bench` rolled out successfully and stayed `2/2` Ready.
- Runtime pods were:
  - `e-navigator-bench-rlc86` on `homelab-01`
  - `e-navigator-bench-rw4c5` on `homelab-02`
- `/proc/1/status` inside both pods reported:
  - `Uid: 0 0 0 0`
  - `Gid: 0 0 0 0`
  - `CapEff: 000001c401283004`
  - `NoNewPrivs: 1`
  - `Seccomp: 2`
- E-Navigator logs captured 8 `profile_sample_observation` records from
  `source.aya_cpu_profile` and 6 `profiling_session_observation` records from
  `generator.profiling` under that seccomp mode.
- The deployment returned `/healthz=ok` and `/readyz=ready`.
- Precise failure-marker searches over the captured E-Navigator logs found zero
  `module failed`, `Error:`, `verifier`, `seccomp`, `permission denied`,
  `operation not permitted`, `sink write failed`, or panic markers.

Negative evidence:

- Controlled workload Job `live-profile-seccomp-cpu-20260623-043123` completed
  on `homelab-02` with zero restarts and logged `outer=305`.
- Hot workload Job `live-profile-seccomp-hot-20260623-043123` completed on
  `homelab-02` with zero restarts after running eight BusyBox `yes` processes.
- The captured profile records contained zero references to either controlled
  workload pod name, `profile-seccomp-hot`, or `command="yes"`.
- The captured profile records were for kernel idle tasks and `k3s-server`,
  mostly without Kubernetes/container attribution.
- `/metrics` returned HTTP 200 but zero lines in this profile-only config, so
  this run does not prove profile-related Prometheus metrics.

Cleanup:

- Deleted both temporary workload Jobs.
- Rolled Helm release `e-navigator-bench` back to revision `99`; Helm recorded
  revision `101` as `Rollback to 99`.
- Final DaemonSet state was `2/2` Ready on the baseline image
  `ghcr.io/guaracloud/e-navigator@sha256:90b571bf89ac36c1432a503ad9b9add7abd7604579533c1912201568db1d5bfc`.
- Final label-scoped inventory for `e-nav-run in (20260623-043123,
  20260623-043123-hot)` reported no resources in `e-navigator-bench`.

Outcome: `partial`.

Proven:

- The current published chart/image can run `source.aya_cpu_profile` and
  `generator.profiling` under kernel-applied `Seccomp: 2` on both homelab
  nodes without BPF verifier, module, seccomp, or permission failure markers.

Not proven:

- Controlled workload CPU profile attribution under RuntimeDefault seccomp.
- Profile samples for the BusyBox controlled workloads.
- Pyroscope write transport, pprof, profile storage, or flamegraph export.
- Symbolization or demangling quality beyond raw IP-style frames.
- Non-root operation, capability reduction, or removal of `CAP_SYS_ADMIN`.
- RuntimeDefault compatibility for DNS or HTTP source modes.
