# Homelab Sample: Collector Workload Cleanup

Run: `20260623-145037-collector-workload-cleanup-live`

Raw evidence lives under
`benchmarks/results/raw/20260623-145037-collector-workload-cleanup-live/`.

Scope: guarded homelab validation on Kubernetes context `staging`, namespace
`e-navigator-bench`.

Purpose:

- Split benchmark collector cleanup so temporary proof workloads can be removed
  without uninstalling the standing Helm release.
- Prove the new workload-only cleanup branch with a live apply-and-collect run.
- Keep the result bounded to harness repeatability and current-image baseline
  smoke evidence.

Code changes:

- `benchmarks/runner/homelab-collect.sh` now derives:
  - `E_NAVIGATOR_HOMELAB_CLEANUP_WORKLOAD`
  - `E_NAVIGATOR_HOMELAB_UNINSTALL_RELEASE`
  - legacy `E_NAVIGATOR_HOMELAB_CLEANUP` as a backward-compatible full cleanup
    switch when the split flags are unset.
- `run-metadata.txt` and generated `summary.md` record workload cleanup and
  release-uninstall decisions separately.
- `tests/homelab_bench_guard_test.sh` guards the split cleanup controls and
  verifies workload cleanup runs before any optional Helm uninstall.

Proof criteria:

- The guard fails before workload-only cleanup is exposed.
- Local quality gates pass after the collector change.
- A guarded live run records `Cleanup workload requested: 1` and
  `Uninstall release requested: 0`.
- The generated workload Job is deleted after capture.
- The standing Helm release remains deployed after cleanup.
- Final exact-name inventory shows no Job or pod for the generated workload.

Local verification:

- `tests/homelab_bench_guard_test.sh` failed before the implementation with:
  `homelab collector must expose workload-only cleanup for standing benchmark releases`.
- `tests/homelab_bench_guard_test.sh` passed after the implementation.
- `git diff --check` passed.
- `node website/check-links.mjs` passed.
- `E_NAVIGATOR_SKIP_DOCKER=1 scripts/quality.sh` passed, including fmt,
  clippy, workspace tests, supply-chain checks, Helm lint/render,
  kubeconform, link checks, and `git diff --check`; Docker was skipped.

Live action:

- Preflight recorded:
  - `pwd=/Users/victorbona/Daedalus/e-navigator`
  - `kubectl config current-context=staging`
  - `namespace/e-navigator-bench`
- Collector flags included:
  - `E_NAVIGATOR_HOMELAB_APPLY=1`
  - `E_NAVIGATOR_HOMELAB_IMAGE_TAG=sha-6080e38`
  - `E_NAVIGATOR_HOMELAB_IMAGE_PULL_SECRET=ghcr-e-navigator-pull`
  - `E_NAVIGATOR_HOMELAB_ENABLE_PROMETHEUS_HTTP=1`
  - `E_NAVIGATOR_HOMELAB_ENABLE_SERVICE_MONITOR=1`
  - `E_NAVIGATOR_HOMELAB_CLEANUP_WORKLOAD=1`
  - `E_NAVIGATOR_HOMELAB_UNINSTALL_RELEASE=0`
- Helm release `e-navigator-bench` upgraded to revision `132`.
- Live pods ran published image tag `sha-6080e38` with image ID:
  `ghcr.io/e-navigator/e-navigator@sha256:ee37daf3cc621799b989a8363007a47291df52fd3115931d244dcf0e3dec775a`.
- DaemonSet `e-navigator-bench` stayed `2/2` Ready on `homelab-01` and
  `homelab-02`.
- Service `e-navigator-bench` had endpoints on both homelab nodes, and
  ServiceMonitor `e-navigator-bench` existed in namespace `e-navigator-bench`.
- Direct Prometheus HTTP probes through the namespace-local Service returned:
  - `/healthz`: `HTTP/1.1 200 OK`, body `ok`
  - `/readyz`: `HTTP/1.1 200 OK`, body `ready`
  - `/metrics`: `HTTP/1.1 200 OK`
- Captured JSON stdout counts included:
  - 561 `resource_gauge_metric`
  - 475 `network_counter_metric`
  - 290 `dependency_edge`
  - 290 `trace_service_path_observation`
  - 242 `process_exit`
  - 158 `network_connection_open`
  - 134 `network_connection_close`
  - 84 `exec`
  - 77 `network_flow_summary`
  - 15 `runtime_security_finding`
- Ten `kubectl top` samples captured E-Navigator pod CPU/memory and the
  temporary workload while it was running.
- Both E-Navigator pods reported UID/GID `0`, `NoNewPrivs: 1`, `Seccomp: 2`,
  and effective capabilities including `CAP_SYS_ADMIN`.

Cleanup:

- The collector ran:
  `kubectl --context staging -n e-navigator-bench delete -f benchmarks/results/raw/20260623-145037-collector-workload-cleanup-live/workload-manifest.yaml --ignore-not-found=true`
- `cleanup-workload.txt` recorded:
  `job.batch "e-navigator-bench-workload-20260623-145037" deleted`
- Final exact-name inventory for
  `e-navigator-bench-workload-20260623-145037` returned no Job or pod after
  background pod deletion settled.
- Helm release `e-navigator-bench` remained deployed as revision `132`.

Outcome: `proven` for the collector workload-only cleanup slice.

Proven:

- The collector can delete a generated timestamped workload manifest without
  uninstalling the standing benchmark Helm release.
- The standing release remained deployed and Ready after workload cleanup.
- The live run recorded cleanup intent, cleanup command output, and post-cleanup
  exact-name absence.

Partial:

- The same run is a current-image baseline smoke for `sha-6080e38`: DaemonSet
  rollout, direct Prometheus HTTP endpoints, JSON stdout families, resource
  samples, and capability posture were recorded.

Not proven:

- Controlled workload signal attribution. Captured JSON stdout contained zero
  rows with the generated workload name.
- Prometheus server active-target or query proof. The collector did not have a
  Prometheus API URL or service configured.
- `network_flow_bytes` live export.
- New HTTP, DNS, profile, OTLP, or native export behavior.
- Reduced privilege or reduced overhead.
