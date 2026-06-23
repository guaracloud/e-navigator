# Homelab Sample: Workload Toleration Smoke

Run: `20260623-143751-homelab-workload-toleration-smoke`

Raw evidence lives under
`benchmarks/results/raw/20260623-143751-homelab-workload-toleration-smoke/`.

Scope: `staging` context, `e-navigator-bench` namespace only.

Purpose:

- Fix the shared homelab proof workload template so it can schedule on
  tainted homelab nodes such as `homelab-02`.
- Fix `benchmarks/runner/homelab-collect.sh` cleanup so it deletes the
  generated timestamped workload manifest rather than the static template name.
- Prove the toleration shape with a bounded live scheduling smoke, without
  upgrading any E-Navigator signal-family claim.

Code changes:

- `benchmarks/k8s/workload.yaml` adds:
  - `tolerations:`
  - `operator: Exists`
- `benchmarks/runner/homelab-collect.sh` now deletes
  `"$workload_manifest"` during cleanup.
- `tests/homelab_bench_guard_test.sh` now guards both behaviors.

Proof criteria:

- The guard fails before the template carries an `Exists` toleration.
- The guard fails unless cleanup targets the generated timestamped workload
  manifest.
- The workload manifest remains Kubernetes-schema valid.
- A temporary live pod with the same toleration shape can schedule on
  `homelab-02` in `staging/e-navigator-bench`.
- Cleanup leaves no resources with the smoke run label.

Local verification:

- `tests/homelab_bench_guard_test.sh` failed before the fix with:
  `homelab workload template must tolerate homelab control-plane taints for symmetric proof scheduling`.
- `tests/homelab_bench_guard_test.sh` passed after the fix.
- `kubeconform -strict -summary benchmarks/k8s/workload.yaml` passed with
  `Valid: 1`.
- `git diff --check` passed.
- `E_NAVIGATOR_SKIP_DOCKER=1 scripts/quality.sh` passed, including fmt,
  clippy, workspace tests, supply-chain checks, Helm lint/render,
  kubeconform, link checks, and `git diff --check`; Docker was skipped.
- `kubectl apply --dry-run=client -f benchmarks/k8s/workload.yaml` was not
  useful as an offline check because `kubectl apply` tried to read the live
  object from the staging API and hit a transient connection refusal. The
  schema check above is the local manifest validation evidence.

Live smoke:

- Preflight recorded:
  - `pwd=/Users/victorbona/Daedalus/e-navigator`
  - `kubectl config current-context=staging`
  - `namespace/e-navigator-bench`
  - existing E-Navigator DaemonSet `2/2` Ready on baseline digest
    `sha256:3abcd8d1c9b9b890801eeab94252f8cc507cd0dba665ddcc449cf409275b90d0`
- trace backendrary pod:
  `e-nav-toleration-smoke-20260623-143751`
- Label:
  `e-navigator.e-navigator.io/proof-run=20260623-143751-homelab-workload-toleration-smoke`
- Pod override:
  - `nodeSelector.kubernetes.io/hostname=homelab-02`
  - `tolerations[0].operator=Exists`
- Recorded pod state:
  - `STATUS=Completed`
  - `NODE=homelab-02`
  - `RESTARTS=0`
  - `IP=10.42.134.25`
- Recorded pod log:
  `toleration-smoke-ok`
- Cleanup:
  - deleted pod `e-nav-toleration-smoke-20260623-143751`
  - final label-scoped inventory was empty.

Outcome: `proven` for the harness slice.

Proven:

- The shared homelab proof workload template now carries a control-plane-taint
  tolerant scheduling shape.
- The collector cleanup path targets the generated timestamped workload
  manifest.
- A pod with the same toleration shape can schedule and complete on
  `homelab-02` inside `staging/e-navigator-bench`.
- Smoke cleanup left no run-labeled resources.

Not proven:

- Any E-Navigator source, processor, generator, or sink behavior.
- Symmetric HTTP, DNS, network, profile, or resource capture.
- Prometheus server scrape, OTLP collector ingestion, or native export
  export.
- Reduced privilege, reduced overhead, or production replacement readiness.
