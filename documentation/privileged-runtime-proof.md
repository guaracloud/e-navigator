# Privileged Runtime Proof

Privileged runtime proof means E-Navigator was run on a capable Linux host or
Kubernetes cluster with the required eBPF, tracefs, perf-event, host path, and
service-account access, and the observed output was recorded.

Non-privileged checks may prove parser, decoder, formatter, generator, runner,
Docker, and manifest behavior. They may not be described as live Aya/eBPF,
Kubernetes runtime, DNS packet capture, perf-event profiling, production export,
or replacement proof.

## What Counts

The following can count as privileged proof only when the command actually ran
and its output was recorded:

- `scripts/smoke_aya_exec_linux.sh` on a capable Linux host;
- `scripts/smoke_aya_cpu_profile_linux.sh <config>` on a capable Linux host;
- a guarded homelab run through `benchmarks/runner/homelab-collect.sh` with
  `E_NAVIGATOR_HOMELAB_CONFIRM=1`, after explicit approval for the live phase;
- equivalent manual Kubernetes proof that records the exact context, namespace,
  image digest or tag, commands, pod state, logs, and metrics.

## What To Record

For Linux host smoke tests, record:

- host kernel and architecture;
- command line and config file;
- source mode used;
- observed signal excerpts;
- failures, warnings, and skipped checks.

For Kubernetes or homelab runs, record:

- kubectl context and namespace;
- image repository, tag, and digest when available;
- Helm values or manifest overrides;
- DaemonSet readiness and pod placement;
- pod restarts before and after the soak;
- logs or JSONL containing observed source events;
- for Prometheus proof, Service endpoints, `/metrics` HTTP 200 output,
  ServiceMonitor or PodMonitor state when enabled, Prometheus active targets,
  and emitted E-Navigator metric series;
- for OTLP proof, the registered sink config, collector receiver state, and
  downstream collector/backend evidence; fake-collector unit tests are not
  collector compatibility proof;
- CPU and memory samples when metrics are available;
- cleanup commands, if any.

Store local run artifacts under:

```text
benchmarks/results/<timestamp>/
```

Raw result directories are local by default. Commit only small curated summaries
when they are intentionally human-reviewable.

## Current Non-Claims

Unless the exact proof is present in a recorded result set, do not claim:

- privileged Aya exec or network runtime behavior;
- DNS packet capture beyond the exact recorded live DNS runs;
- HTTP request capture beyond the exact recorded live HTTP runs, including
  symmetric node coverage, TLS, gRPC framing, inbound server-side parsing,
  status-code extraction, route templates, retries, application errors, or
  multi-iovec HTTP header assembly;
- Prometheus scrape/export compatibility;
- Tempo, Alloy, Pyroscope, pprof, or collector-ingested OTLP compatibility;
- perf-event CPU profiling parity;
- Kubernetes runtime readiness;
- reduced-privilege eBPF operation beyond the exact recorded RuntimeDefault
  seccomp proofs, including the exact recorded network, HTTP, CPU profile, and
  DNS source-mode runs; non-root and reduced-capability operation remain
  separate claims;
- production OTLP, pprof, Pyroscope, Prometheus, or Tempo export;
- Beyla, Alloy, Tempo, Prometheus, or Pyroscope replacement readiness.

Synthetic fixtures, Docker smoke tests, Helm rendering, and kubeconform checks
remain non-privileged evidence.
