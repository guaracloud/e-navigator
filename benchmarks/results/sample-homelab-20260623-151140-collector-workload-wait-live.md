# Homelab Sample: Collector Workload Wait and Attribution Evidence

Run: `20260623-151140-collector-workload-wait-live`

Raw evidence lives under
`benchmarks/results/raw/20260623-151140-collector-workload-wait-live/`.

Scope: guarded homelab validation on Kubernetes context `staging`, namespace
`e-navigator-bench`.

Purpose:

- Make the guarded collector wait for the generated benchmark workload before
  collecting the main runtime evidence.
- Capture exact workload pod inventory, JSON, describe output, and workload
  logs as first-class artifacts.
- Preserve workload-only cleanup without uninstalling the standing Helm release.
- Re-check whether the controlled generated workload appears in E-Navigator
  JSON stdout after the collector waits for completion.

Code changes:

- `benchmarks/runner/homelab-collect.sh` now records
  `E_NAVIGATOR_HOMELAB_WORKLOAD_WAIT_TIMEOUT`, defaulting to `300s`.
- The collector waits for `job/${workload_name}` with
  `condition=complete` after applying the generated workload manifest.
- The collector captures `workload-pods.txt`, `workload-pod-json.txt`,
  `workload-describe.txt`, and `workload-logs.txt` using the exact generated
  `app.kubernetes.io/name=${workload_name}` selector.
- Generated `summary.md` and `proof-matrix.md` list the new workload wait and
  artifact files.
- `tests/homelab_bench_guard_test.sh` guards the wait timeout, exact workload
  selector, ordering, and new evidence surfaces.

Proof criteria:

- The guard fails before the collector exposes the workload wait timeout.
- Local quality gates pass after the collector change.
- A guarded live run records the `300s` workload wait timeout.
- The generated Job reaches `condition met`.
- The collector captures workload pod identity and workload logs before cleanup.
- The generated workload is deleted without uninstalling the Helm release.
- E-Navigator JSON stdout is inspected separately from workload stdout before
  upgrading any signal-family claim.

Local verification:

- `tests/homelab_bench_guard_test.sh` failed before implementation with:
  `homelab collector must expose a bounded workload wait timeout`.
- `tests/homelab_bench_guard_test.sh` passed after implementation.
- `bash -n benchmarks/runner/homelab-collect.sh tests/homelab_bench_guard_test.sh`
  passed.
- `node website/check-links.mjs` passed.
- `git diff --check` passed.
- `E_NAVIGATOR_SKIP_DOCKER=1 scripts/quality.sh` passed, including fmt,
  clippy, workspace tests, supply-chain checks, Helm lint/render,
  kubeconform, link checks, and `git diff --check`; Docker was skipped.

Live action:

- Preflight recorded:
  - `pwd=/Users/victorbona/Daedalus/e-navigator`
  - `kubectl config current-context=staging`
  - `namespace/e-navigator-bench`
- The first live attempt with `E_NAVIGATOR_HOMELAB_WORKLOAD_WAIT_TIMEOUT=180s`
  timed out while the workload pod was still `Running` after emitting all 60
  expected log lines. The collector captured artifacts and cleaned the workload,
  but that attempt was treated as partial timing evidence, not success.
- The successful rerun used the collector default `300s` wait timeout.
- Collector flags included:
  - `E_NAVIGATOR_HOMELAB_APPLY=1`
  - `E_NAVIGATOR_HOMELAB_IMAGE_TAG=sha-6c15296`
  - `E_NAVIGATOR_HOMELAB_IMAGE_PULL_SECRET=ghcr-e-navigator-pull`
  - `E_NAVIGATOR_HOMELAB_ENABLE_PROMETHEUS_HTTP=1`
  - `E_NAVIGATOR_HOMELAB_ENABLE_SERVICE_MONITOR=1`
  - `E_NAVIGATOR_HOMELAB_CLEANUP_WORKLOAD=1`
  - `E_NAVIGATOR_HOMELAB_UNINSTALL_RELEASE=0`
- Helm release `e-navigator-bench` upgraded to revision `134`.
- Live pods ran published image tag `sha-6c15296` with image ID:
  `ghcr.io/guaracloud/e-navigator@sha256:2e512f069c0beb18bc16d600ef8386f4d98b1f42728c201a61db7a2dce108b57`.
- DaemonSet `e-navigator-bench` stayed `2/2` Ready on `homelab-01` and
  `homelab-02`.
- `workload-wait.txt` recorded:
  `job.batch/e-navigator-bench-workload-20260623-151140 condition met`.
- Workload pod evidence recorded:
  - pod `e-navigator-bench-workload-20260623-151140-4vl4l`
  - node `homelab-02`
  - phase `Succeeded`
  - pod IP `10.42.134.32`
  - pod UID `3ef44d2b-5756-4a6f-89e1-ec2276c063e6`
  - container ID
    `containerd://ae079fe8e4a07aff645b01b2ae1edf7cfec426b09bf0206b2dd5f3bcb60c0cd6`
  - exit code `0`
  - start `2026-06-23T15:11:53Z`
  - finish `2026-06-23T15:14:54Z`
- `workload-logs.txt` captured all 60 expected
  `e-navigator-bench exec N` lines.
- Direct Prometheus HTTP probes through the namespace-local Service returned:
  - `/healthz`: `HTTP/1.1 200 OK`, body `ok`
  - `/readyz`: `HTTP/1.1 200 OK`, body `ready`
  - `/metrics`: `HTTP/1.1 200 OK`
- Captured JSON stdout counts included:
  - 797 `network_counter_metric`
  - 536 `trace_service_path_observation`
  - 535 `dependency_edge`
  - 405 `network_gauge_metric`
  - 282 `service_interaction_span_observation`
  - 275 `network_duration_metric`
  - 275 `network_connection_close`
  - 264 `network_connection_open`
  - 231 `process_exit`
  - 180 `network_flow_summary`
  - 101 `trace_correlation_warning`
  - 97 `exec`
- E-Navigator JSON stdout contained 261 records with the generated workload
  name. Workload-attributed counts included:
  - 54 `network_counter_metric`
  - 36 `dependency_edge`
  - 36 `trace_service_path_observation`
  - 33 `network_gauge_metric`
  - 18 `network_duration_metric`
  - 18 `network_connection_open`
  - 18 `network_connection_close`
  - 18 `network_flow_summary`
  - 18 `service_interaction_span_observation`
  - 6 `runtime_security_finding`
  - 6 `exec`
- The 18 workload `network_flow_summary` records were egress TCP summaries with
  source-side Kubernetes attribution for the controlled workload and total
  `bytes=5358`. Destination workload attribution was absent.
- Both E-Navigator pods reported UID/GID `0`, `NoNewPrivs: 1`, `Seccomp: 2`,
  and effective capabilities including `CAP_SYS_ADMIN`.

Cleanup:

- The collector ran:
  `kubectl --context staging -n e-navigator-bench delete -f benchmarks/results/raw/20260623-151140-collector-workload-wait-live/workload-manifest.yaml --ignore-not-found=true`
- `cleanup-workload.txt` recorded:
  `job.batch "e-navigator-bench-workload-20260623-151140" deleted`
- Final exact-name inventory for
  `e-navigator-bench-workload-20260623-151140` returned no Job or pod.
- Helm release `e-navigator-bench` remained deployed as revision `134`.

Outcome: `proven` for the collector workload wait and workload artifact slice.

Proven:

- The guarded collector now waits for the generated workload Job to complete
  under a bounded timeout.
- The collector captures exact generated workload pod identity, workload logs,
  and workload cleanup output.
- The standing Helm release remained deployed and Ready after workload-only
  cleanup.
- Current published image `sha-6c15296` emitted controlled workload-attributed
  source and derived records for the observed `homelab-02` workload, including
  network opens, closes, counters, dependency graph, trace-service-path, service
  interaction, runtime-security, exec, and egress flow-summary records.

Partial:

- Controlled workload flow-summary proof is source-attributed egress TCP only;
  destination workload attribution was not present.
- The run is a current-image smoke for direct Prometheus HTTP endpoints and
  capability posture.

Not proven:

- Symmetric controlled workload attribution across both homelab nodes.
- `beyla_network_flow_bytes_total` live export.
- Prometheus server active-target or query proof. The collector did not have a
  Prometheus API URL or service configured inside `e-navigator-bench`.
- New HTTP, DNS, profile, OTLP, or Guara compatibility behavior.
- Reduced privilege or reduced overhead.
