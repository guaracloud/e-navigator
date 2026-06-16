# Privileged Runtime Proof

Non-privileged CI proves parser, decode, formatter, generator, runner, Docker synthetic, and Kubernetes manifest shape. It does not prove live eBPF attachment, perf-event sampling, runtime DNS capture, or Kubernetes runtime behavior.

## Local Linux Aya Exec Smoke

```bash
scripts/smoke_aya_exec_linux.sh
```

With a custom config:

```bash
scripts/smoke_aya_exec_linux.sh /path/to/e-navigator.toml
```

This proves only that the local Linux host can run the explicit `aya-exec` mode with its configured Aya exec and network sources. It must observe real `exec`, `network_connection_open`, `network_connection_close`, or `network_connection_failure` envelopes before those runtime paths are claimed for that host.

## Local Linux CPU Profiling Smoke

```bash
scripts/smoke_aya_cpu_profile_linux.sh /path/to/e-navigator-cpu-profile.toml
```

The config must enable `[cpu_profile_source]` and the `source.aya_cpu_profile` module. This proves only that the explicit CPU profile source mode can attach and observe `profile_sample_observation` records on that Linux host.

## Kubernetes Runtime Proof

Client dry-runs:

```bash
kubectl apply --dry-run=client -f deploy/kubernetes/namespace.yaml
kubectl apply --dry-run=client -f deploy/kubernetes/rbac.yaml
kubectl apply --dry-run=client -f deploy/kubernetes/configmap.yaml
kubectl apply --dry-run=client -f deploy/kubernetes/daemonset.yaml
```

These dry-runs prove manifest shape only. Kubernetes runtime proof requires deploying the DaemonSet to a real Linux node with the documented privileges, then observing real source envelopes from that environment.

## Still Unproven Without Separate Work

- production OTLP metric, trace, or profile export
- pprof or Pyroscope integration
- storage or UI behavior
- live HTTP/gRPC traffic parsing
- runtime DNS packet capture
- allocation or lock profiling
- full continuous profiling backend behavior
