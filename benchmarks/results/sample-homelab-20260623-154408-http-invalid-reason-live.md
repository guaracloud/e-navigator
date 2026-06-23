# Homelab Sample: HTTP Invalid-Reason Diagnostics

Run: `20260623-154408-http-invalid-reason-live`

Raw evidence lives under
`benchmarks/results/raw/20260623-154408-http-invalid-reason-live/`.

Scope: manual homelab validation on Kubernetes context `staging`, namespace
`e-navigator-bench`.

Purpose:

- Verify the pushed invalid HTTP decode reason diagnostics in live Aya HTTP
  capture.
- Re-run the bounded three-iovec HTTP proof shape on both homelab nodes.
- Preserve the known `homelab-02` positive path while re-checking the
  `homelab-01` symmetric-node blocker.
- Record negative evidence without upgrading broad HTTP claims by inference.

Code changes:

- Commit `9c6463a` added structured invalid HTTP request sample reasons for
  source diagnostics.
- Local docs commit `c2720ee` recorded the proof boundary in the README,
  claims matrix, and benchmark evidence.

Proof criteria:

- CI and GHCR image publication succeed for the pushed commit.
- Live preflight records
  `pwd=/Users/victorbona/Daedalus/e-navigator` and
  `kubectl config current-context=staging`.
- Helm rolls `ghcr.io/guaracloud/e-navigator:sha-9c6463a` only in
  `e-navigator-bench`.
- Both pinned HTTP proof Jobs complete 30 warmups and 80 measured three-iovec
  requests with zero workload errors.
- The `homelab-02` path produces exact-path `protocol_request_observation` and
  `request_span_observation` rows with Kubernetes attribution.
- The `homelab-01` path is counted separately; zero exact-path rows remain
  negative evidence, not success.
- Invalid HTTP samples emit bounded structured reasons.
- Temporary Jobs are deleted and the release is rolled back to the previous
  standing image.

Local verification:

- `cargo test --locked -p e-navigator-sources-ebpf-aya` passed.
- `cargo clippy --locked -p e-navigator-sources-ebpf-aya --all-targets -- -D warnings`
  passed.
- `tests/http_request_capture_guard_test.sh` passed.
- `cargo fmt --all -- --check` passed.
- `git diff --check` passed.
- `scripts/quality.sh` passed Rust, synthetic, guard, and supply-chain stages,
  then local Docker build was blocked by the unavailable Docker daemon. Remote
  CI and image publication succeeded for the pushed image.

Publication:

- Code commit: `9c6463a`
- Image tag: `ghcr.io/guaracloud/e-navigator:sha-9c6463a`
- Image index digest:
  `sha256:dad05511f63ebf80548e46c28d92e0de335f8c1e800bb649a2ba569c881b4362`
- Linux/amd64 digest:
  `sha256:727e098764ba13cbb2d4dfcc402d8eb689f1b818985218451bb22a1919c93bfb`
- GitHub CI run: `28037630005`
- GitHub image publication run: `28037630364`

Live action:

- Preflight recorded:
  - `pwd=/Users/victorbona/Daedalus/e-navigator`
  - `kubectl config current-context=staging`
  - final context after live actions: `staging`
- Helm release `e-navigator-bench` upgraded from revision `134` to revision
  `135`.
- `daemonset-after.yaml` rendered image
  `ghcr.io/guaracloud/e-navigator:sha-9c6463a`.
- The rollout completed successfully with both DaemonSet pods Ready.
- The two generated proof pods completed:
  - `http-stage-085800-h01-hhkvv` on `homelab-01`
  - `http-stage-085800-h02-mqrtt` on `homelab-02`
- Workload logs recorded for both nodes:
  - `warmup_requests=30 warmup_ok=30`
  - `three_iovec_requests=80 ok=80 errors=0`
  - `proof_iovec_lengths=(34, 30, 88)`

Observed E-Navigator evidence:

- The `homelab-02` proof path `/proof/iovec3-stage-085800-h02` produced:
  - 80 exact-path `protocol_request_observation` records
  - 80 exact-path `request_span_observation` records
  - Kubernetes attribution to pod `http-stage-085800-h02-mqrtt`
- The matching `homelab-01` proof path `/proof/iovec3-stage-085800-h01`
  produced:
  - 0 exact-path `protocol_request_observation` records
  - 0 exact-path `request_span_observation` records
  - 0 captured rows attributed to pod `http-stage-085800-h01-hhkvv`
- Source diagnostics emitted 301 bounded invalid HTTP sample lines with:
  - `raw_event="invalid_http_request_sample"`
  - `invalid_reason="headers_too_long"`
- Source telemetry summaries for `source.aya_http` and `source.aya_network`
  reported `send_failures=0` and `lost_perf_events=0` in sampled windows.
- HTTP stage counters emitted live in 8 sampled lines, including write,
  writev, sendto, sendmsg, copy, output, fallback, and
  `active_connection_miss` buckets.

Cleanup:

- The temporary Jobs were deleted:
  - `job.batch "http-stage-085800-h02" deleted`
  - `job.batch "http-stage-085800-h01" deleted`
- Final HTTP workload inventory returned:
  `No resources found in e-navigator-bench namespace.`
- Helm rollback to revision `134` succeeded, creating deployed revision `136`
  with description `Rollback to 134`.
- Post-rollback DaemonSet state was `2/2` Ready on standing image
  `ghcr.io/guaracloud/e-navigator:sha-6c15296`.

Outcome: `partial` for the HTTP invalid-reason diagnostic slice.

Proven:

- The invalid HTTP diagnostic path is no longer an undifferentiated invalid
  counter in this live run; bounded samples recorded `headers_too_long`.
- The previously positive `homelab-02` bounded three-iovec HTTP proof path was
  preserved on the pushed image.
- Temporary workloads were cleaned up and the standing release was restored.

Not proven:

- Symmetric HTTP capture across both homelab nodes.
- Exact-path HTTP capture for the controlled `homelab-01` workload.
- Root cause of the `homelab-01` HTTP/protocol miss.
- TLS, gRPC, inbound server-side parsing, status-code extraction, route
  templates, retries, app errors, more than three iovec slots, or chunks larger
  than 96 bytes per slot.
- Reduced privilege or reduced overhead.
