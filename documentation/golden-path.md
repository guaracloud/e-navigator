# Production Performance Golden Path

This is the recommended production starting point for low overhead and clear
operational proof. It intentionally begins with a narrow signal surface and
adds expensive capture families only after the base deployment is measured.

There is no universal configuration that is fastest for every kernel,
workload, traffic mix, and backend. Treat this path as a controlled baseline,
then tune from measurements on the target nodes.

## 1. Verify And Pin A Release

Verify the release manifest, checksums, signatures, SBOMs, image digest, and
chart digest before deployment. Follow [release verification](release-verification.md),
then keep the image digest immutable through the rollout.

Required node conditions:

- Linux with BTF and the kernel facilities required by the enabled probes;
- the chart's documented capabilities, mounts, and service account;
- a reachable OTLP HTTP receiver if OTLP export is enabled;
- enough CPU and memory headroom to compare the baseline against the node
  without E-Navigator.

## 2. Scope Capture Before Enabling Expensive Sources

The largest avoidable cost is observing workloads that do not need coverage.
Edit the capture filter in
[`examples/production-performance.toml`](examples/production-performance.toml)
before installation:

```toml
[capture_filter]
enabled = true
default_posture = "deny"
unknown_cgroup = "deny"
namespace_include = ["payments", "checkout"]
label_in = { "observability.e-navigator.dev/enabled" = ["true"] }
process_exclude = ["*-exporter", "otelcol*", "alloy*", "e-navigator*"]
```

An allowlist posture minimizes unintended collection and work, but it can
briefly miss a newly started workload until Kubernetes identity and cgroup
state reconcile. Read the policy tradeoff in [Helm install](helm.md).

## 3. Start With The Base Profile

The example configuration enables:

- process execution and network lifecycle capture;
- host resource sampling once per minute;
- container and Kubernetes attribution;
- resource, network, dependency, and runtime security generators;
- Prometheus health and native metrics;
- OTLP metric export;
- no synthetic, DNS, HTTP, protocol, TLS, or CPU profile source;
- no JSON stdout, trace export, or profile export.

This profile avoids parsing payloads and sampling stacks until those signals
have an explicit consumer. It also avoids high-volume JSON serialization and
container-log I/O in production.

Validate the exact config before rendering the chart:

```bash
cargo run --locked -p e-navigator-cli -- \
  --validate-config \
  --config documentation/examples/production-performance.toml

helm lint charts/e-navigator

helm template e-navigator charts/e-navigator \
  --namespace e-navigator-system \
  --set image.digest=sha256:<verified-image-digest> \
  --set-file config.toml=documentation/examples/production-performance.toml \
  --set prometheusHttp.enabled=true \
  --set health.enabled=true \
  --set service.enabled=true
```

Inspect the rendered ConfigMap, DaemonSet, RBAC, capabilities, resource bounds,
and digest. Then install the same inputs:

```bash
helm upgrade --install e-navigator charts/e-navigator \
  --namespace e-navigator-system \
  --create-namespace \
  --set image.digest=sha256:<verified-image-digest> \
  --set-file config.toml=documentation/examples/production-performance.toml \
  --set prometheusHttp.enabled=true \
  --set health.enabled=true \
  --set service.enabled=true
```

Replace the example OTLP endpoint and capture selectors before either command.

## 4. Establish A Matched Baseline

Measure the same representative workload in three conditions:

1. no agent;
2. the base E-Navigator profile;
3. each additional capture family, enabled one at a time.

Keep workload version, node, kernel, duration, warmup, request rate, and backend
state fixed. Record CPU, resident memory, application throughput and latency,
source loss, queue loss, export latency, and backend acceptance. Repeat enough
times to expose run-to-run variance.

Criterion benchmarks protect local code hot paths, but they do not prove node
overhead. Use the evidence tiers and guarded commands in
[benchmark methodology](benchmark.md).

## 5. Tune From Native Signals

Watch these classes before increasing coverage or limits:

| Signal | Interpretation | First response |
| --- | --- | --- |
| Source perf loss or send failure | Kernel or source-to-runner pressure | Narrow capture, reduce source rate, then review queue and CPU headroom |
| Export queue drops | Destination or worker cannot keep up | Check destination latency, batch settings, and queue capacity |
| Export retries or open circuits | Backend or network is unhealthy | Repair the destination before increasing buffers |
| Rejected OTLP records | Receiver accepted the request but rejected data | Inspect receiver response and schema compatibility |
| Capture controller unresolved cgroups | Workload identity is not ready | Check node name, RBAC, Pod watch freshness, and cgroup paths |
| Readiness false | A required configured surface is not ready | Inspect source and exporter health before rollout continues |

Increasing a queue only postpones loss and consumes more memory when the
destination is persistently slower than the producer. Fix steady-state
throughput first, then size queues for measured bursts and shutdown drain.

## 6. Add Coverage In Cost Order

Enable only the source and downstream families required by an acceptance test:

1. DNS capture and DNS metrics.
2. HTTP capture and request, trace, and dependency output.
3. Protocol capture on explicit ports.
4. TLS uprobes only for supported, dynamically linked libraries and explicit
   application ports.
5. CPU profiling, beginning at 10 Hz with bounded targets, frames, and batch
   size.

When a source is disabled, disable generators and OTLP families that have no
remaining input. Each additional family needs a matched overhead run, backend
acceptance proof, and a rollback threshold.

## 7. Preserve Bounded Defaults

- Keep the shared input queue and per-family export queues bounded.
- Keep parser, reassembly, connection, metric-key, attribution-cache, profile,
  and response-body limits explicit.
- Prefer a longer resource sampling interval over larger scans when freshness
  requirements allow it.
- Use gzip only when network savings exceed compression CPU for the measured
  batch and payload size.
- Keep JSON stdout disabled for sustained production traffic unless the logs
  are the intended bounded destination.
- Do not raise memory or cardinality limits before identifying the specific
  dropped or evicted signal they must address.

## 8. Roll Out And Roll Back Deliberately

Use the DaemonSet's bounded rolling update, observe at least one full backend
flush and workload cycle, then continue. Roll back if application latency,
node CPU, memory, source loss, export loss, or attribution freshness crosses
the threshold recorded before rollout.

The chart rendering and readiness endpoint prove configuration and process
health. They do not by themselves prove privileged capture on the target
kernel. Promote a source only after its expected live signal is observed.
