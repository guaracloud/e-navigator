# Claims Matrix

| Area | Implemented | Synthetic-only | Non-privileged proven | Privileged-proven | Deferred |
| --- | --- | --- | --- | --- | --- |
| Static pipeline runtime | yes | no | cargo tests and synthetic CLI | no | runtime plugin loading |
| JSON stdout envelopes | yes | no | cargo tests, Docker smoke | no | storage/UI |
| Process exec source | yes | no | userspace config and decode tests | requires `scripts/smoke_aya_exec_linux.sh` on Linux | reduced privilege Kubernetes proof |
| TCP network source | yes | no | raw decode tests | requires aya-exec smoke on Linux | full TCP state, packet accounting |
| Runtime DNS capture | no | yes, DNS envelopes and fixtures | schema/generator/smoke tests | no | eBPF DNS packet capture |
| Host resource source | yes | no | procfs/sysfs/cgroup parser tests and Docker synthetic fixtures | not claimed | host accuracy on mounted Linux filesystems |
| Dependency graph | yes | no | generator tests and runner fan-out tests | no | persisted service map |
| Trace foundation | yes | partly | schema, generator, formatter, Docker smoke | no | full OTLP trace export, trace storage, UI, critical path analysis |
| Request/protocol foundation | yes | fixture-backed | traceparent and HTTP fixture tests | no | live HTTP/gRPC parsing, routes, retries, app errors |
| CPU profiling source | yes, explicit opt-in source | no | raw decode, profile normalization, generator tests | homelab `aya-cpu-profile` canary observed `source.aya_cpu_profile` sample envelopes and bounded raw IP stack frames for the controlled CPU workload | function symbolization, pprof, Pyroscope, OTLP profiles, flamegraph UI, storage |
| Supply-chain checks | yes | no | `cargo deny`, `cargo audit`, `cargo machete`, release SBOM/signature workflow | no | container vulnerability policy gates |
| Kubernetes packaging | yes | no | `helm lint`, `helm template`, `kubectl apply --dry-run=client` | not claimed | privileged cluster runtime proof |

`Privileged-proven` must remain `no` unless the exact privileged smoke command or guarded homelab canary is run on a real Linux host or Kubernetes cluster and the observed output is recorded.
