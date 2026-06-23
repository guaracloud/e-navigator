# Extended Homelab Validation Sample: 20260619-210812

This is a curated summary of the raw artifacts in
`benchmarks/results/20260619-210812-extended/`.

## Scope

- Context: `staging`
- Namespace: `e-navigator-bench`
- Release: `e-navigator-bench`
- Image: `ghcr.io/e-navigator/e-navigator:sha-8ab271c`
- Pull secret: `ghcr-pull-secret` in `e-navigator-bench`
- Observed nodes: `homelab-01` and `homelab-02`

No raw credential material is included in this summary.

## Live Runtime State

The DaemonSet remained Ready on both homelab nodes:

- `e-navigator-bench-wbncb` on `homelab-01`
- `e-navigator-bench-cmxkb` on `homelab-02`

Both pods were Running with zero restarts in the final snapshot. The temporary
probe pod used for service and Prometheus checks was deleted before the final
snapshot.

## Resource Overhead

`kubectl top pods --containers` was sampled over a short window. The robust
sample file recorded 12 samples for `e-navigator-bench-cmxkb` and 10 samples
for `e-navigator-bench-wbncb`:

| Pod | CPU avg | CPU min | CPU max | Memory avg | Memory min | Memory max |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `e-navigator-bench-cmxkb` | `13.33m` | `11m` | `18m` | `39.00Mi` | `39Mi` | `39Mi` |
| `e-navigator-bench-wbncb` | `39.20m` | `32m` | `49m` | `53.60Mi` | `53Mi` | `54Mi` |

The chart requested `50m` CPU and `128Mi` memory per E-Navigator pod, with no
CPU limit and a `512Mi` memory limit.

Prometheus kubelet/cAdvisor queries also returned container resource metrics:

- E-Navigator 10-minute CPU average:
  - `e-navigator-bench-wbncb`: `0.0364` cores
  - `e-navigator-bench-cmxkb`: `0.0129` cores
- E-Navigator 10-minute memory average:
  - `e-navigator-bench-wbncb`: about `52.1Mi`
  - `e-navigator-bench-cmxkb`: about `39.6Mi`
- E-Navigator 10-minute memory max:
  - `e-navigator-bench-wbncb`: about `54.8Mi`
  - `e-navigator-bench-cmxkb`: about `40.6Mi`

For context only, Prometheus returned external flow agent 10-minute CPU averages of about
`0.0088` and `0.0049` cores, and memory averages of about `258.3Mi` and
`22.2Mi` for the two external flow agent pods. This is not a replacement or reduced-overhead
claim because the workloads, configuration, and signal responsibilities are not
equivalent.

## Capabilities And Pod Security

The rendered E-Navigator container security context was:

- `privileged: false`
- `allowPrivilegeEscalation: false`
- `readOnlyRootFilesystem: true`
- `runAsUser: 0`
- `runAsNonRoot: false`
- drop all capabilities, then add:
  `BPF`, `SYS_PTRACE`, `NET_RAW`, `PERFMON`, `DAC_READ_SEARCH`,
  `CHECKPOINT_RESTORE`, `SYS_ADMIN`, `NET_ADMIN`, `SYS_RESOURCE`, and `SYSLOG`

`/proc/1/status` inside both E-Navigator pods showed:

- effective capabilities:
  `CAP_DAC_READ_SEARCH`, `CAP_NET_ADMIN`, `CAP_NET_RAW`, `CAP_SYS_PTRACE`,
  `CAP_SYS_ADMIN`, `CAP_SYS_RESOURCE`, `CAP_SYSLOG`, `CAP_PERFMON`, `CAP_BPF`,
  and `CAP_CHECKPOINT_RESTORE`
- `NoNewPrivs=1`
- `Seccomp=0`

This proves the pod is not Kubernetes-privileged and uses `no_new_privs`, but it
does not prove reduced-privilege eBPF hardening. `CAP_SYS_ADMIN` is still
present and seccomp was not active.

## Runtime Signals

The captured E-Navigator log tail included:

- `1,426` `source.aya_exec` records
- `1,515` `source.aya_network` records
- `532` `source.host_resource` records
- `15` runtime security findings
- `1,600` trace-like derived records

The same log scan found:

- `0` `source.aya_cpu_profile` records
- `0` DNS signal records
- `0` records attributed to `e-navigator-bench-workload`

This extends the live proof for Aya exec, Aya network, and host resource
observation, but still does not prove DNS packet capture, CPU profiling for this
run, or controlled-workload attribution.

## OTEL And Collection Surfaces

The homelab observability stack has Alloy, Prometheus, trace backend, Loki, external flow agent, and
node-exporter running in `observability-system`. Alloy exposes OTLP receivers on
`4317` and `4318`, forwards traces to trace backend, and converts OTLP metrics to
Prometheus remote write.

E-Navigator did not export to that OTLP path in this run:

- the current repo still registers only `sink.json_stdout` as a concrete sink;
- focused tests confirmed OTEL metric, trace, and profile formatter boundaries,
  plus HTTP exporter queue behavior, but not a registered OTLP sink;
- the E-Navigator Service on port `9090` existed but refused HTTP connections;
- there was no `ServiceMonitor` or `PodMonitor` in `e-navigator-bench`;
- Prometheus active targets had `0` matches for E-Navigator;
- `up{namespace="e-navigator-bench"}` returned an empty vector.

Kubelet/cAdvisor metrics for E-Navigator containers were available in
Prometheus. That is resource collection by the existing Prometheus stack, not
E-Navigator's own metrics export.

Rendering the chart with `serviceMonitor.enabled=true` produced a
`ServiceMonitor`, but `kubeconform` could not validate it because the
Prometheus Operator CRD schema was unavailable to the local validator.

## Focused Local Checks

The following focused checks passed and their output was captured:

- `cargo test --locked -p e-navigator-sinks`
- `cargo test --locked -p e-navigator-core known_sinks_claim_only_json_stdout_as_concrete_registered_sink`
- `cargo test --locked -p e-navigator-cli registry::tests::registry_registers_only_json_stdout_as_concrete_sink`
- `cargo test --locked -p e-navigator-signals golden_signal_families_round_trip_without_schema_drift`

The sink tests prove formatter and exporter-foundation behavior only. They do
not prove production OTLP transport, Prometheus scrape export, trace backend ingestion,
external profile backend export, or replacement readiness.

## Proof Boundary

This run proves:

- live E-Navigator DaemonSet readiness on both homelab nodes;
- short-window E-Navigator CPU and memory samples from `kubectl top`;
- Prometheus kubelet/cAdvisor resource metrics for E-Navigator containers;
- rendered and effective Linux capabilities for the E-Navigator process;
- live Aya exec, Aya network, and host resource signal emission;
- the existence of the homelab Alloy OTLP receiver and trace backend endpoint;
- local OTEL-compatible formatter and HTTP exporter-foundation tests.

This run does not prove:

- E-Navigator OTLP export to Alloy or trace backend;
- E-Navigator Prometheus scrape export;
- DNS packet capture;
- CPU profiling in this run;
- controlled-workload attribution;
- external profile backend, pprof, trace backend, or production collector compatibility;
- external flow agent, Alloy, trace backend, Prometheus, or external profile backend replacement readiness;
- reduced-overhead or reduced-privilege readiness.
