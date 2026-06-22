# Homelab Runtime Security Sample: 20260621-234159

This is a curated summary of the raw artifacts in
`benchmarks/results/20260621-234159-runtime-security-live/`.

## Scope

- Context: `staging`
- Namespace: `e-navigator-bench`
- Release: `e-navigator-bench`
- Mode: collection-only plus two controlled workload Jobs pinned to the two
  homelab nodes
- Image observed:
  `ghcr.io/guaracloud/e-navigator:sha-5c417c0`
- Image digest observed on both E-Navigator pods:
  `ghcr.io/guaracloud/e-navigator@sha256:553f2008f53f6da5ec05b0a45102ab8eb1f8bf4c640b2d61ce4d958ed6470cc3`
- Pull secret present in live Helm values: `ghcr-e-navigator-pull`
- Nodes observed: `homelab-01` and `homelab-02`

The required image `sha-8ab271c` was validated separately for pullability and
DaemonSet runtime with its older compatible config. It was not used for this
runtime-security proof because the live homelab release was already restored to
the current Prometheus-enabled baseline image `sha-5c417c0`. No Helm upgrade or
image change was applied for this slice.

## Result

The run proves live `generator.runtime_security` output from real Aya exec and
network observations on both homelab nodes.

What was recorded:

- Initial workload `e-nav-runtime-security-204219` completed but did not
  produce fresh runtime-security findings in the captured window.
- Pinned workload Jobs
  `e-nav-runtime-security-204845-homelab-01` and
  `e-nav-runtime-security-204845-homelab-02` ran on `homelab-01` and
  `homelab-02` respectively.
- DaemonSet `e-navigator-bench` stayed `2/2` Ready with zero restarts.
- Both DaemonSet pod logs were captured from the pinned workload interval:
  - `e-navigator-bench-98qlt`: 9,319 lines
  - `e-navigator-bench-m7pzt`: 6,118 lines
  - combined: 15,437 lines
- Combined source counts included:
  - `generator.network_metrics`: 5,087 records
  - `generator.trace_correlation`: 3,948 records
  - `source.aya_network`: 2,711 records
  - `source.aya_exec`: 1,844 records
  - `generator.dependency_graph`: 1,219 records
  - `source.host_resource`: 266 records
  - `generator.runtime_security`: 209 records
  - `generator.resource_metrics`: 138 records
- Combined kind counts included:
  - `network_connection_open`: 644 records
  - `exec`: 632 records
  - `runtime_security_finding`: 209 records
  - host resource observations and derived resource metrics.
- Runtime-security finding rule counts:
  - `runtime.network_tool_exec`: 135
  - `network.kubernetes_api_from_workload`: 59
  - `runtime.shell_in_container`: 15
- Controlled workload attribution was observed on both nodes:
  - 50 `runtime.network_tool_exec` findings for
    `e-nav-runtime-security-204845-homelab-02-jdstj`
  - 15 `runtime.network_tool_exec` findings for
    `e-nav-runtime-security-204845-homelab-01-ztmqb`
  - 3 `runtime.shell_in_container` findings for
    `e-nav-runtime-security-204845-homelab-02-jdstj`
  - 2 `runtime.shell_in_container` findings for
    `e-nav-runtime-security-204845-homelab-01-ztmqb`
- Some runtime-security findings, including the Kubernetes API connection
  findings, did not carry container or Kubernetes attribution in the captured
  records.
- `/healthz` returned `ok`, `/readyz` returned `ready`, and `/metrics` returned
  410 metric lines during the pinned workload.
- Prometheus query `up{namespace="e-navigator-bench"}` returned both
  E-Navigator pods with value `1`.
- Prometheus query `network_connection_open_count{namespace="e-navigator-bench"}`
  returned 45 results, including workload-labelled series for both pinned
  workload pods.
- Prometheus queries for `process_thread_count` and `container_process_count`
  returned live resource series for both E-Navigator pods.
- Capability evidence for both E-Navigator pods recorded
  `CapEff/CapBnd=000001c401283004` and `CapAmb=0000000000000000`.

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
left completed workload Job `e-nav-runtime-security-204219` in
`e-navigator-bench` with `ttlSecondsAfterFinished: 86400`.

At final status capture, pinned workload Jobs
`e-nav-runtime-security-204845-homelab-01` and
`e-nav-runtime-security-204845-homelab-02` were still running with
`restartCount=0`. They are finite Jobs with `ttlSecondsAfterFinished: 86400`,
but the TTL starts only after completion.

Older evidence resources from previous runs, including fake OTLP collectors and
the privileged image importer, were already present and remained in the
namespace.

## Proof Boundary

This run proves live runtime-security generation for exact network-tool exec,
shell-in-container, and Kubernetes API connection rules on the homelab cluster.
It also proves JSON stdout, Prometheus scrape/query visibility, host-resource
stdout, and resource metric output remained active during that run.

This run does not prove:

- complete attribution for every runtime-security finding;
- runtime DNS packet capture;
- successful OTLP protobuf export;
- Tempo trace ingestion;
- Pyroscope profile ingestion;
- Beyla-compatible byte flow export;
- reduced overhead or reduced privilege;
- replacement readiness for Beyla, Alloy, Tempo, Prometheus, or Pyroscope.
