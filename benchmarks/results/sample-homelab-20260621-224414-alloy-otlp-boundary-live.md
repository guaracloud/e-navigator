# Homelab Alloy OTLP Boundary Sample: 20260621-224414

This is a curated summary of the raw artifacts in
`benchmarks/results/20260621-224414-alloy-otlp-boundary-live/`.

## Scope

- Context: `staging`
- Namespace: `e-navigator-bench`
- Release: `e-navigator-bench`
- Baseline image before and after the run:
  `ghcr.io/e-navigator/e-navigator:sha-5c417c0`
- Real receiver endpoint:
  `http://alloy.observability-system.svc.cluster.local:4318/v1/traces`
- Pull secret present in the release values: `ghcr-e-navigator-pull`
- Local substitution image tested for the current-code fix:
  `ghcr.io/e-navigator/e-navigator:sha-fafb91a-alloy-boundary`
- Nodes observed: `homelab-01` and `homelab-02`, both `linux/amd64`

The requested required image `sha-8ab271c` was validated separately in the same
session for pullability and DaemonSet runtime with its older compatible config.
It was not used for this Alloy boundary check because the behavior under test is
newer `sink.otlp_http` runner reliability. The already deployed GHCR image
`sha-5c417c0` was tested first, then current local code was loaded directly into
each homelab node's k3s/containerd store because this run was kept local and did
not push to GitHub/GHCR.

## Result

The run proves a real production-collector boundary, not successful OTLP
ingestion.

What was recorded:

- Real homelab Alloy exists in `observability-system` and exposes OTLP HTTP on
  port `4318`.
- `sha-5c417c0` was rolled to `e-navigator-bench` with `sink.otlp_http`
  enabled and endpoint `/v1/traces` on Alloy.
- Both `sha-5c417c0` pods emitted live records, then entered CrashLoopBackOff
  after `sink.otlp_http` received `collector returned HTTP 400`.
- The release was rolled back to the prior good revision and restored to
  `2/2` Ready.
- Current local code was built as
  `ghcr.io/e-navigator/e-navigator:sha-fafb91a-alloy-boundary`, saved as a
  `linux/amd64` image, and imported into both homelab node runtimes.
- Helm revision 30 rolled the DaemonSet to the local tag with
  `imagePullPolicy: Never`.
- Both live-test pods reported runtime image ID
  `sha256:99a1de3ccc088dc9a268a29e809fcb7929e878e2d54e0e383fedbad36d397a16`.
- Workload `e-nav-alloy-otlp-workload-202101` completed successfully on
  `homelab-01`.
- Both E-Navigator pods stayed `Running`, `ready=true`, and `restartCount=0`
  while logging:
  `sink write failed; dropping signal for this sink` for `sink.otlp_http` with
  `collector returned HTTP 400`.
- The same log window still included JSON stdout records from
  `source.aya_network`, `generator.network_metrics`, and
  `generator.trace_correlation`.
- The Prometheus HTTP service remained reachable:
  - `/healthz` returned `ok`
  - `/readyz` returned `ready`
  - `/metrics` returned non-empty resource and network metric series.
- The release was restored afterward to `sha-5c417c0`, `2/2` Ready, with
  `[otlp_http] enabled = false`, `endpoint = ""`, and module
  `sink.otlp_http` disabled.

## Resources Left

No live evidence resources were cleaned up because the run boundary required
asking before cleanup. This run left the completed workload Job
`e-nav-alloy-otlp-workload-202101` in `e-navigator-bench` with
`ttlSecondsAfterFinished: 86400`. Previously created namespace-local fake OTLP
proof resources and the image importer were also still present.

The image importer is privileged and should be removed after the evidence is no
longer needed.

## Proof Boundary

This run proves that current local code keeps the runner alive and keeps
JSON/Prometheus output active when real homelab Alloy rejects
`sink.otlp_http` requests with HTTP 400.

This run also proves that `sha-5c417c0` does not survive the same real Alloy
HTTP 400 rejection path.

This run does not prove:

- successful OTLP protobuf export;
- trace backend trace ingestion;
- external profile backend profile ingestion;
- Alloy production compatibility;
- replacement readiness for Alloy, trace backend, external profile backend, Prometheus, or external flow agent;
- DNS packet capture;
- reduced overhead or reduced privileges.
