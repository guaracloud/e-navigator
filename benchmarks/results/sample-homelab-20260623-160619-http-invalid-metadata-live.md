# Homelab Sample: HTTP Invalid-Sample Metadata

Run: `20260623-160619-http-invalid-metadata-live`

Raw evidence lives under
`benchmarks/results/raw/20260623-160619-http-invalid-metadata-live/`.

Scope: manual homelab validation on Kubernetes context `staging`, namespace
`e-navigator-bench`.

Purpose:

- Validate the pushed bounded invalid HTTP sample metadata implementation.
- Preserve the known h02 three-iovec HTTP proof path while re-checking h01.
- Record whether rejected HTTP samples expose bounded metadata such as process,
  file descriptor, socket family, ports, request length, and iovec lengths.
- Keep the result bounded; no other cluster or namespace was targeted.

Code changes:

- Commit `5cb242d` added `RawHttpInvalidSampleMetadata`, preserved invalid
  sample metadata through decode failures, and logged bounded metadata for
  `invalid_http_request_sample` diagnostics without request payload bytes.
- Commit `0ff4aae` recorded the previous invalid-reason diagnostic proof.

Proof criteria:

- CI and GHCR image publication succeed for the pushed commit.
- Live preflight records
  `pwd=/Users/victorbona/Daedalus/e-navigator` and
  `kubectl config current-context=staging`.
- Helm rolls `ghcr.io/e-navigator/e-navigator:sha-5cb242d` only in
  `e-navigator-bench`.
- Both h01/h02 proof Jobs complete 30 warmups and 80 measured three-iovec
  requests with zero workload errors.
- The h02 proof path produces exact-path `protocol_request_observation` and
  `request_span_observation` rows.
- The h01 proof path is counted separately.
- Invalid-sample diagnostics, if emitted for the proof workloads, include
  bounded metadata fields and no request payload bytes.
- trace backendrary workloads are deleted and the release is rolled back to the
  previous standing revision.

Local verification:

- Failing-first focused test initially failed before `sample_metadata()` existed.
- `cargo test --locked -p e-navigator-sources-ebpf-aya raw_http_decode_result_preserves_invalid_sample_metadata`
  passed after implementation.
- `tests/http_request_capture_guard_test.sh` passed.
- `cargo fmt --all -- --check` passed after formatting.
- `cargo test --locked -p e-navigator-sources-ebpf-aya` passed.
- `cargo clippy --locked -p e-navigator-sources-ebpf-aya --all-targets -- -D warnings`
  passed.
- `cargo clippy --locked --workspace --all-targets --exclude e-navigator-ebpf-programs -- -D warnings`
  passed.
- `cargo test --locked --workspace --exclude e-navigator-ebpf-programs` passed.
- `cargo run --locked -p e-navigator-cli -- --source synthetic` passed.
- `helm lint charts/e-navigator` passed with the existing icon recommendation.
- `helm template e-navigator charts/e-navigator` rendered successfully.
- `git diff --check` passed.

Publication:

- Code commit: `5cb242d`
- Image tag: `ghcr.io/e-navigator/e-navigator:sha-5cb242d`
- Image index digest:
  `sha256:37d9b68cb78d18c76e99e348e536f76280a22edb207ac89f14009cab5c859dc6`
- Linux/amd64 digest:
  `sha256:5a734b3e13a07727868b3433e2e6f77e1cff015b8f1a35ef9290c02bf519bbcd`
- GitHub CI run: `28038902204`
- GitHub image publication run: `28038901119`

Live action:

- Preflight recorded:
  - `pwd=/Users/victorbona/Daedalus/e-navigator`
  - `kubectl config current-context=staging`
  - namespace check: `namespace/e-navigator-bench`
- Helm revision `137` rolled image `sha-5cb242d` with HTTP diagnostics enabled.
- Helm revision `138` added:
  - `E_NAVIGATOR_SOURCE_DIAGNOSTICS_FILTER=python`
  - `E_NAVIGATOR_SOURCE_DIAGNOSTICS_LIMIT=256`
  - `E_NAVIGATOR_SOURCE_DIAGNOSTICS_FILTERED_LIMIT=32`
- The initial filtered capture used selector-based `kubectl logs` without
  `--tail=-1`, which returned only the default tail and was not treated as
  evidence.
- The stable rerun used the same manifest after collector warmup and collected
  full logs with `--tail=-1`.

Observed workload evidence:

- Stable rerun h01 pod `http-invalid-metadata-160619b-h01-9n4dc` on
  `homelab-01` completed:
  - `warmup_requests=30 warmup_ok=30`
  - `three_iovec_requests=80 ok=80 errors=0`
  - `proof_iovec_lengths=(46, 27, 71)`
  - path `/proof/invalid-meta-160619b-h01`
- Stable rerun h02 pod `http-invalid-metadata-160619b-h02-v7sv9` on
  `homelab-02` completed:
  - `warmup_requests=30 warmup_ok=30`
  - `three_iovec_requests=80 ok=80 errors=0`
  - `proof_iovec_lengths=(46, 26, 71)`
  - path `/proof/invalid-meta-160619b-h02`

Observed E-Navigator evidence:

- Corrected collector log file:
  `e-navigator-logs-filtered-stable-rerun-all.txt`
- Corrected capture line count: `20,594`
- The h02 proof path `/proof/invalid-meta-160619b-h02` produced:
  - `110` exact-path `protocol_request_observation` records
  - `110` exact-path `request_span_observation` records
  - `1,155` h02 path mentions in the full collector log
- The h01 proof path `/proof/invalid-meta-160619b-h01` produced:
  - `0` exact-path `protocol_request_observation` records
  - `0` exact-path `request_span_observation` records
  - `0` h01 path mentions in the full collector log
- Invalid diagnostic metadata evidence:
  - `0` `invalid_http_request_sample` lines
  - `0` `headers_too_long` diagnostic lines
  - `0` lines containing the new metadata fields
- Source telemetry did show live HTTP decoding/invalid counters and zero send
  failures in sampled windows, but the diagnostic filter recorded those samples
  as filtered rather than matched.

Cleanup:

- trace backendrary proof resources were deleted from `e-navigator-bench`.
- Final resource query for `http-invalid-metadata-160619*` returned no matches.
- Helm rollback to revision `136` succeeded, creating deployed revision `139`
  with description `Rollback to 136`.
- Final context after live actions remained `staging`.

Outcome: `partial` for the HTTP invalid-sample metadata slice.

Proven:

- The invalid-sample metadata build did not regress the h02 three-iovec HTTP
  path in the stable rerun.
- Full log collection for selector-based `kubectl logs` must use `--tail=-1`
  for evidence-grade counts.
- trace backendrary workloads were cleaned up and the standing release was restored.

Not proven:

- h01 exact-path HTTP capture.
- h01 rejected-sample metadata attribution.
- That the h01 proof requests reach userspace as invalid HTTP samples.
- TLS, gRPC, inbound server-side parsing, status-code extraction, route
  templates, retries, app errors, more than three iovec slots, or chunks larger
  than 96 bytes per slot.
- Reduced privilege or reduced overhead.
