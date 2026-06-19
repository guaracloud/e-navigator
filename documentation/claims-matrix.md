# Claims Matrix

| Area | Implemented | Synthetic-only | Non-privileged proven | Privileged-proven | Deferred |
| --- | --- | --- | --- | --- | --- |
| Static pipeline runtime | yes | no | cargo tests and synthetic CLI | no | runtime plugin loading |
| JSON stdout envelopes | yes | no | cargo tests, Docker smoke | no | storage/UI |
| Process exec source | yes | no | userspace config and decode tests | guarded homelab run `20260619-205746` observed `source.aya_exec` records from live Kubernetes nodes | reduced privilege hardening, workload-attributed benchmark capture |
| TCP network source | yes | no | raw decode tests | guarded homelab run `20260619-205746` observed `source.aya_network` records from live Kubernetes nodes | full TCP state, packet accounting, workload-attributed benchmark capture |
| Runtime DNS capture | no | yes, DNS envelopes and fixtures | schema/generator/smoke tests | no | eBPF DNS packet capture |
| Host resource source | yes | no | procfs/sysfs/cgroup parser tests and Docker synthetic fixtures | guarded homelab run `20260619-205746` observed `source.host_resource` node, process, and cgroup records from mounted host paths | warning detail expansion, longer host accuracy baseline |
| Dependency graph | yes | no | generator tests and runner fan-out tests | no | persisted service map |
| Trace foundation | yes | partly | schema, generator, formatter, Docker smoke | no | full OTLP trace export, trace storage, UI, critical path analysis |
| Request/protocol foundation | yes | fixture-backed | traceparent and HTTP fixture tests | no | live HTTP/gRPC parsing, routes, retries, app errors |
| CPU profiling source | yes, explicit opt-in source | no | raw decode, profile normalization, generator tests | homelab `aya-cpu-profile` canary observed `source.aya_cpu_profile` sample envelopes and bounded raw IP stack frames for the controlled CPU workload | function symbolization, pprof, Pyroscope, OTLP profiles, flamegraph UI, storage |
| Guara Beyla L4 compatibility projection | partial | no | golden schema tests plus generator and sink formatter tests | no | live byte-accurate Aya flow cache, active timeout flushing, cross-node runtime dedupe, Prometheus endpoint runtime |
| Guara Tempo service graph compatibility | partial | partly | trace formatter tests for `service.name`, `k8s.namespace.name`, `k8s.pod.name`, and `k8s.deployment.name` | no | OTLP trace transport, Tempo ingestion proof, live HTTP/gRPC/database spans, context propagation |
| Guara Pyroscope CPU identity | partial | no | profile formatter tests for `process_cpu:cpu:nanoseconds:cpu:nanoseconds` and Guara labels | no | Pyroscope write transport, OTLP profile transport, symbolization/demangling runtime proof |
| Exporter infrastructure | partial | no | sink-layer fake-collector tests for batching, timeout config, retry, bounded queue, headers, and drop counters | no | full OTLP protobuf metrics/traces/profiles, production collector compatibility proof |
| Benchmark evidence harness | yes | no | local Criterion compile and smoke runs for deterministic parser, decode, generator, formatter, and queue fixtures | guarded homelab run `20260619-205746` recorded raw DaemonSet, pod, log, event, workload, and metrics artifacts | committed raw results, live overhead baselines, homelab runtime comparison |
| Supply-chain checks | yes | no | `cargo deny`, `cargo audit`, `cargo machete`, release SBOM/signature workflow | no | container vulnerability policy gates |
| Kubernetes packaging | yes | no | `helm lint`, `helm template`, `kubeconform -strict -summary` | guarded homelab run `20260619-205746` rolled out the DaemonSet Ready on both homelab nodes with `ghcr-pull-secret` | reduced-privilege eBPF hardening, production rollout proof |

`Privileged-proven` must remain `no` unless the exact privileged smoke command or guarded homelab canary is run on a real Linux host or Kubernetes cluster and the observed output is recorded.
