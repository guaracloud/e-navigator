# Homelab Sample: HTTP Sendmsg Boundary

Run: `20260623-111601-http-sendmsg-live`

Raw evidence lives under
`benchmarks/results/raw/20260623-111601-http-sendmsg-live/`.

Scope: `staging` context, `e-navigator-bench` namespace only.

Image:

- Git SHA: `e8f8575`
- Tag: `ghcr.io/guaracloud/e-navigator:sha-e8f8575`
- Image index digest:
  `sha256:5957f2656ba975cebdf6f655cff53eeab108a1a70605c6a9c2b026cb6b37ba20`
- Linux/amd64 digest:
  `sha256:ec34257b72019c6802d338c8f310f2e2d5e5788dec7289a245d79c7f2e2c9ce1`

Deployment:

- Local guard `tests/http_request_capture_guard_test.sh` failed before the fix
  because `sys_enter_sendmsg` was still a no-op verifier boundary.
- Commit `e8f8575` wired `sys_enter_sendmsg` through bounded
  `msghdr`/iovec HTTP request copying and added structural guards.
- Targeted HTTP/Aya tests, formatting, clippy, and Docker-skipped
  `scripts/quality.sh` passed before rollout.
- CI run `28032489334` passed, including Docker smoke.
- Image publish run `28032489764` succeeded.
- Baseline before test: Helm revision `129` on image digest
  `sha256:3abcd8d1c9b9b890801eeab94252f8cc507cd0dba665ddcc449cf409275b90d0`.
- Test rollout: Helm revision `130`.
- Runtime config enabled `source.aya_http`, `source.aya_network`,
  `processor.container_attribution`, `generator.request_correlation`,
  `generator.network_metrics`, `sink.json_stdout`, and
  `sink.prometheus_http`.
- HTTP source diagnostics were enabled with
  `E_NAVIGATOR_SOURCE_DIAGNOSTICS=true`.

Controlled workloads:

- Job `http-sendmsg-111601-h01` pinned to `homelab-01`.
  - Pod: `http-sendmsg-111601-h01-jnjvb`
  - Path: `/proof/http-sendmsg-20260623-111601-h01`
  - Host header: `sendmsg-h01.example.test:18083`
  - Workload log: `ok=80/80`
- Job `http-sendmsg-111601-h02` pinned to `homelab-02`.
  - Pod: `http-sendmsg-111601-h02-d8ln5`
  - Path: `/proof/http-sendmsg-20260623-111601-h02`
  - Host header: `sendmsg-h02.example.test:18083`
  - Outcome: pending, then deleted during cleanup.
  - Scheduler reason: `homelab-02` had the untolerated
    `node-role.kubernetes.io/control-plane` taint, while the other node did
    not match the node selector.

Observed signals:

- Captured JSON stdout contained zero exact-path
  `protocol_request_observation` records for the `homelab-01` proof path.
- Captured JSON stdout contained zero exact-path
  `request_span_observation` records for the `homelab-01` proof path.
- Captured JSON stdout contained zero signal rows attributed to pod
  `http-sendmsg-111601-h01-jnjvb`.
- JSON stdout did contain ambient live `protocol_request_observation` and
  `request_span_observation` records from other cluster traffic, so the HTTP
  source and request-correlation generator remained active during the window.
- HTTP source telemetry reported nonzero decoded samples, zero send failures,
  and zero lost perf events in sampled windows.
- The HTTP diagnostic logger emitted live stage counters that included
  nonzero `sendmsg_enter`, `copy_success`, `output_attempt`, and
  `fallback_output_attempt`. Captured lines included:
  - `sendmsg_enter=26`, `copy_success=225`, `output_attempt=225`, and
    `fallback_output_attempt=102`.
  - `sendmsg_enter=137`, `copy_success=161`, `output_attempt=161`, and
    `fallback_output_attempt=42`.
  - `sendmsg_enter=548`, `copy_success=263`, `output_attempt=263`, and
    `fallback_output_attempt=84`.

Cleanup:

- Deleted both proof Jobs with the run label
  `e-navigator.guara.cloud/proof-run=20260623-111601-http-sendmsg-live`.
- Rolled Helm release `e-navigator-bench` back to revision `129`; Helm
  recorded final revision `131` as `Rollback to 129`.
- Final label-scoped inventory reported no resources in `e-navigator-bench`.
- Final DaemonSet state was `2/2` Ready on baseline image digest
  `sha256:3abcd8d1c9b9b890801eeab94252f8cc507cd0dba665ddcc449cf409275b90d0`.
- Final `kubectl config current-context` remained `staging`.

Outcome: `partial`.

Proven:

- `sys_enter_sendmsg` is no longer an inert HTTP source tracepoint in the
  shipped image.
- The live homelab DaemonSet loaded the image with the new sendmsg path and
  emitted nonzero `sendmsg_enter` diagnostics.
- The bounded fallback/output path attempted live output during the proof
  window.
- The `homelab-01` controlled `socket.sendmsg` workload completed 80 measured
  requests with zero workload errors.
- Cleanup and rollback restored the previous homelab release state.

Not proven:

- Exact-path controlled-client HTTP protocol capture for `socket.sendmsg`.
- Request-span generation for the controlled `socket.sendmsg` workload.
- Kubernetes or pod attribution for the controlled `homelab-01` sendmsg
  workload in captured signal output.
- Any `homelab-02` workload behavior; the proof pod did not schedule.
- Symmetric controlled-client HTTP protocol coverage across both homelab nodes.
- TLS, gRPC, inbound server-side parsing, status-code extraction, route
  templates, retries, application errors, more than three iovec slots, chunks
  larger than 96 bytes per slot, or broader multi-iovec HTTP header assembly.
- Non-root operation, capability reduction, or removal of `CAP_SYS_ADMIN`.
- Production replacement readiness.
