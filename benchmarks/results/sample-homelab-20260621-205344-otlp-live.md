# Homelab OTLP HTTP Sink Boundary Sample

Run: `20260621-205344-otlp-live`

This run validated `sink.otlp_http` on the homelab Kubernetes cluster with a
namespace-local fake HTTP collector. It proves live delivery of E-Navigator's
internal JSON metric, trace, and profile records from the DaemonSet to an HTTP
endpoint. It does not prove upstream OTLP protobuf compatibility, trace backend,
external profile backend, Alloy, or production collector ingestion.

## Environment

- Kubernetes context: `staging`
- Namespace: `e-navigator-bench`
- Helm release: `e-navigator-bench`
- E-Navigator image: `ghcr.io/e-navigator/e-navigator:sha-5c417c0`
- Fake collector: `e-navigator-otlp-fake-20260621-205344`
- Endpoint: `http://e-navigator-otlp-fake-20260621-205344.e-navigator-bench.svc.cluster.local:4318/v1/e-navigator`
- Exec workload: `e-navigator-bench-workload-20260621-205344-otlp`
- Profile workload: `e-navigator-bench-profile-20260621-205344-otlp`

## Result

The fake collector received `10,335` POST events from the live DaemonSet:

- `56` `metric` records
- `18` `trace` records
- `10,261` `profile` records

Observed record names included:

- `network.connection.open.count`
- `network.protocol.connection.open.count`
- `network.traffic.destination.count`
- `network.connection.duration`
- `network.connection.active`
- `container.cpu.time`
- `container.memory.usage`
- `tcp client`
- `trace.service.path`
- `trace.correlation.warning`
- `e-navigator.profile.internal.v1`

Profile-mode E-Navigator logs included `source.aya_cpu_profile` samples and
`generator.profiling` sessions. The collector summary includes profile records
using the internal `e-navigator.profile.internal.v1` schema.

## Restore And Caveats

The release was restored after capture to `--source aya-exec` with
`sink.prometheus_http` enabled and `sink.otlp_http` disabled. Post-restore
cluster capture reported the DaemonSet `2/2` ready on image `sha-5c417c0`.

No manual cleanup was run. The timestamped fake collector and workload resources
were left in `e-navigator-bench`.

The exec workload completed, but the bounded `kubectl wait` artifact timed out
just before completion; the later pod and job captures show the job as
`Complete`. During the profile phase, E-Navigator pods restarted and events
recorded BackOff warnings, while collector and log artifacts still proved
profile record delivery. This run should not be used as a short-soak stability
claim for `aya-cpu-profile` plus `sink.otlp_http`.

## Raw Artifacts

Raw artifacts are in ignored directory
`benchmarks/results/20260621-205344-otlp-live/`, including:

- `collector-summary.json`
- `summary.md`
- `commands.txt`
- `otlp-exec-runtime-config.toml`
- `otlp-profile-runtime-config.toml`
- `collector-logs-after-exec.txt`
- `collector-logs-after-profile.txt`
- `cluster-after-restore.txt`
- `ds-after-restore.txt`
