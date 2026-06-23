# Homelab Sink-Failure Validation Sample: 20260621-214450

This is a curated summary of the raw artifacts in
`benchmarks/results/20260621-214450-sink-failure-live/`.

## Scope

- Context: `staging`
- Namespace: `e-navigator-bench`
- Release: `e-navigator-bench`
- Baseline image before and after the run:
  `ghcr.io/e-navigator/e-navigator:sha-5c417c0`
- Image tested during the run:
  `ghcr.io/e-navigator/e-navigator:sha-56c4b4e`
- Pull secret present in the release values: `ghcr-e-navigator-pull`
- Nodes observed: `homelab-01` and `homelab-02`, both `linux/amd64`

The requested older image `sha-8ab271c` was not used for this specific check
because the behavior under test is the newer runner reliability fix at local
commit `56c4b4e`. GHCR push for `sha-56c4b4e` failed because the available token
did not have package push scope, so the built `linux/amd64` image was loaded
directly into k3s/containerd on both homelab nodes under the same tag.

## Result

The run proves that a failing OTLP HTTP sink does not terminate the runner in
the tested image.

What was recorded:

- The local Docker build produced image ID
  `sha256:99a1de3ccc088dc9a268a29e809fcb7929e878e2d54e0e383fedbad36d397a16`
  for `linux/amd64`.
- The image was imported into both homelab node containerd stores as
  `ghcr.io/e-navigator/e-navigator:sha-56c4b4e`.
- A namespace-local fake OTLP collector was deployed and configured to return
  HTTP 500 for every POST.
- Helm revision 20 rolled the DaemonSet to `sha-56c4b4e` with
  `sink.otlp_http` enabled, `sink.prometheus_http` enabled, and the OTLP
  endpoint set to the failing in-cluster collector.
- The DaemonSet rolled out Ready on both nodes:
  - `e-navigator-bench-5mnts` on `homelab-02`
  - `e-navigator-bench-j2bdw` on `homelab-01`
- Both live-test pods reported `ready=true`, `restarts=0`, and image
  `ghcr.io/e-navigator/e-navigator:sha-56c4b4e`.
- The failing collector logged `35,787` received POST events at
  `/v1/e-navigator`.
- E-Navigator logs included `sink write failed; dropping signal for this sink`
  warnings for `sink.otlp_http` with `collector returned HTTP 500`.
- The same log windows still included JSON stdout signals after sink failures,
  including `source.aya_network`, `generator.network_metrics`, and
  `generator.trace_correlation` records.
- Prometheus stayed reachable through the live Service:
  - `/healthz` returned `ok`
  - `/readyz` returned `ready`
  - `/metrics` returned system, container, and network metric series.
- Ten `kubectl top pod` samples during the failing-export window reported both
  E-Navigator pods running, with CPU around `262m` to `323m` and memory around
  `45Mi` to `54Mi`.
- Capability evidence for both tested pods recorded `NoNewPrivs: 1`,
  `Seccomp: 0`, and raw capability masks
  `CapEff/CapBnd=000001c401283004`.
- The release was restored afterward to `sha-5c417c0`, `2/2` Ready, with both
  restored pods reporting zero restarts.

## Resources Left

No live evidence resources were cleaned up because the run boundary required
asking before cleanup. The following proof resources were left in
`e-navigator-bench`:

- `daemonset/e-navigator-image-importer`
- `deployment/e-navigator-otlp-fail-20260621-214450-sink-failure-live`
- `service/e-navigator-otlp-fail-20260621-214450-sink-failure-live`
- `configmap/e-navigator-otlp-fail-20260621-214450-sink-failure-live`
- `job/e-navigator-bench-workload-20260621-214450-sink-failure-live`

The image importer is privileged and should be removed after the evidence is no
longer needed.

## Proof Boundary

This run proves that, in the `staging` homelab context, the tested runner image
continues running and keeps other sinks active when `sink.otlp_http` receives
HTTP 500 responses from an in-cluster endpoint.

This run does not prove:

- GHCR publication for `sha-56c4b4e`;
- production collector compatibility;
- upstream OTLP protobuf metrics, traces, or profiles;
- trace backend, external profile backend, Alloy, or Prometheus replacement readiness;
- reduced overhead or sustained overhead baselines;
- reduced-privilege eBPF operation;
- runtime DNS packet capture.
