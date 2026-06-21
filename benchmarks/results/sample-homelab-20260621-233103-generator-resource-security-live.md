# Homelab Generator, Resource, And Security Sample: 20260621-233103

This is a curated summary of the raw artifacts in
`benchmarks/results/20260621-233103-generator-resource-security-live/`.

## Scope

- Context: `staging`
- Namespace: `e-navigator-bench`
- Release: `e-navigator-bench`
- Mode: collection-only with one controlled workload Job
- Image observed:
  `ghcr.io/guaracloud/e-navigator:sha-5c417c0`
- Image digest observed on both E-Navigator pods:
  `ghcr.io/guaracloud/e-navigator@sha256:553f2008f53f6da5ec05b0a45102ab8eb1f8bf4c640b2d61ce4d958ed6470cc3`
- Pull secret present in live Helm values: `ghcr-e-navigator-pull`
- Nodes observed: `homelab-01` and `homelab-02`

The requested required image `sha-8ab271c` was not used for this collection-only
slice because the live release was already restored to the current homelab
baseline `sha-5c417c0`. No Helm upgrade or image change was applied.

## Result

The run proves current live dependency graph output, network/trace derived
output, Prometheus resource/network export, and current privilege posture.

What was recorded:

- Controlled workload `e-nav-generator-proof-203121` completed successfully.
- DaemonSet `e-navigator-bench` stayed `2/2` Ready with zero restarts.
- Extended E-Navigator logs contained:
  - `source.aya_network`: 5 records
  - `source.aya_exec`: 3 records, all `process_exit`
  - `generator.network_metrics`: 4 records
  - `generator.trace_correlation`: 8 records
  - `generator.dependency_graph`: 1 record
- The dependency edge included Kubernetes/container attribution for an
  `infisical-system` workload and destination `10.43.0.10:53`.
- `/healthz` returned `ok`, `/readyz` returned `ready`, and `/metrics` returned
  393 metric lines.
- Prometheus active targets included both E-Navigator pods with `health=up`.
- Prometheus query `up{namespace="e-navigator-bench"}` returned both pods with
  value `1`.
- Prometheus query `scrape_samples_scraped{namespace="e-navigator-bench"}`
  returned values `393` and `136`.
- Prometheus returned 41 `network_connection_open_count` results and 45
  `network_connection_failure_count` results.
- Prometheus returned resource metric series:
  - 6 `system_cpu_load_average_milli` results
  - 2 `system_memory_available` results
- Ten `kubectl top pods --containers` samples were captured:
  - `e-navigator-bench-98qlt`: 37m to 51m CPU, 54Mi memory
  - `e-navigator-bench-m7pzt`: 12m to 15m CPU, 37Mi memory
- Capability evidence for both E-Navigator pods recorded UID/GID `0`,
  `NoNewPrivs: 1`, `Seccomp: 0`, and
  `CapEff/CapBnd=000001c401283004`.

Decoded effective capabilities on both pods:

- `CAP_DAC_READ_SEARCH`
- `CAP_NET_ADMIN`
- `CAP_NET_RAW`
- `CAP_SYS_PTRACE`
- `CAP_SYS_ADMIN`
- `CAP_SYS_RESOURCE`
- `CAP_SYSLOG`
- `CAP_PERFMON`
- `CAP_BPF`
- `CAP_CHECKPOINT_RESTORE`

## Resources Left

No cleanup was performed because cleanup requires explicit approval. This run
left completed workload Job `e-nav-generator-proof-203121` in
`e-navigator-bench` with `ttlSecondsAfterFinished: 86400`.

Older evidence resources from previous runs, including fake OTLP collectors and
the privileged image importer, were already present and remained in the
namespace.

## Proof Boundary

This run proves live dependency graph generation from network observations,
live network-derived trace correlation, Prometheus scrape/query availability for
network and resource metrics, and current resource/capability samples for the
restored homelab release.

This run does not prove:

- fresh `runtime_security_finding` output; none was observed in the captured
  log window;
- fresh `source.host_resource` JSON stdout output, although Prometheus exposed
  current resource metric series;
- controlled workload attribution for the workload Job itself;
- runtime DNS packet capture;
- successful OTLP protobuf export;
- Tempo trace ingestion;
- Pyroscope profile ingestion;
- Beyla-compatible byte flow export;
- reduced overhead or reduced privilege.
