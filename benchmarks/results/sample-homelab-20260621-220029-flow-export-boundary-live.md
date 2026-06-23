# Homelab E-Navigator Compatibility Boundary Sample: 20260621-220029

This is a curated summary of the raw artifacts in
`benchmarks/results/20260621-220029-flow-export-boundary-live/`.

## Scope

- Context: `staging`
- Namespace: `e-navigator-bench`
- Release: `e-navigator-bench`
- Image tested: `ghcr.io/e-navigator/e-navigator:sha-5c417c0`
- Live test config: `features.nativeFlowMetrics=true` and
  `generator.network_metrics` enabled
- Pull secret present in release values: `ghcr-e-navigator-pull`
- Nodes observed: `homelab-01` and `homelab-02`

The requested older image `sha-8ab271c` was not used in this run because the
homelab release path was already operating on the available and previously
validated image `sha-5c417c0`.

## Result

This run records a negative live boundary for the E-Navigator external flow agent L4 compatibility
projection.

What was recorded:

- Helm revision 23 rolled the DaemonSet with `generator.network_metrics` enabled.
- Both live-test pods were Ready on the two homelab nodes:
  - `e-navigator-bench-pp4jd` on `homelab-01`
  - `e-navigator-bench-j5764` on `homelab-02`
- A controlled BusyBox workload completed in `e-navigator-bench`:
  `job/e-nav-flow-workload-220029`.
- The live service returned `ok` from `/healthz` and `ready` from `/readyz`.
- Direct `/metrics` returned 356 lines, including 33
  `network_connection_open_count` lines and 39
  `network_connection_failure_count` lines.
- Direct `/metrics` returned 0 `network_flow_bytes` lines.
- Prometheus reported both E-Navigator targets `up`.
- Prometheus scrape samples were `356` and `98` for the two E-Navigator pods.
- Prometheus returned 37 `network_connection_open_count` results and 43
  `network_connection_failure_count` results.
- Prometheus returned 0 `network_flow_bytes` results.
- Captured logs contained 0 `network_flow_summary`,
  `NetworkFlowSummary`, or `network_flow_bytes` lines.
- Code search confirmed `generator.network_metrics` consumes
  `SignalPayload::NetworkFlowSummary` and projects
  `network_flow_bytes`; this run found no live Aya producer for
  `NetworkFlowSummary`.
- Corrected capability capture on the restored pods recorded
  `NoNewPrivs: 1`, `Seccomp: 0`, and raw capability masks
  `CapEff/CapBnd=000001c401283004`.

## Restore

The first restore command reused Helm values that already included
`features.nativeFlowMetrics=true`, so it did not disable the generator. A
corrected restore explicitly supplied the captured pre-test config and
`features.nativeFlowMetrics=false`.

Final restored state:

- Helm revision 25 deployed.
- DaemonSet `e-navigator-bench` was `2/2` Ready.
- Restored pods:
  - `e-navigator-bench-hd5lq` on `homelab-01`
  - `e-navigator-bench-m4cg4` on `homelab-02`
- Both restored pods ran `ghcr.io/e-navigator/e-navigator:sha-5c417c0`.
- Restored ConfigMap had `generator.network_metrics` disabled.
- Restored Helm values had `features.nativeFlowMetrics=false`.

## Resources Left

No live evidence resources were cleaned up because the run boundary required
asking before cleanup. This run left:

- `job/e-nav-flow-workload-220029`
- `pod/e-nav-flow-workload-220029-ncqz8`

Older evidence resources from previous runs were also still present in the
namespace and are listed in the raw artifact `live-proof-left-resources.txt`.

## Proof Boundary

This run proves that, in the `staging` homelab context, enabling
`generator.network_metrics` did not produce `network_flow_bytes` while
the live Prometheus HTTP endpoint and Prometheus scrape path were healthy and
reporting other E-Navigator network metrics.

This run does not prove:

- live byte-accurate Aya flow summaries;
- `network_flow_bytes` production from live traffic;
- external flow agent replacement readiness;
- trace backend, external profile backend, Alloy, or production collector compatibility;
- reduced overhead or sustained overhead baselines;
- reduced-privilege eBPF operation;
- runtime DNS packet capture.
