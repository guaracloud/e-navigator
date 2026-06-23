# Homelab HTTP Three-Iovec Negative Proof 20260623-030344

## Scope

- Context: `staging`
- Namespace: `e-navigator-bench`
- Commit: `396e70d38a814eb699c8507a60ac97667529f9d9`
- Image tag: `ghcr.io/guaracloud/e-navigator:sha-396e70d`
- Image index digest:
  `sha256:5f2060de32c6206b07868e43cccaa59ebf2489fae34edf2d6646b565354ce84a`
- Linux amd64 digest:
  `sha256:64ee132ff66b21c8f9d449ff701372858bde37258e1502f900e9d1afe806959a`
- Baseline restored digest:
  `sha256:90b571bf89ac36c1432a503ad9b9add7abd7604579533c1912201568db1d5bfc`
- Raw evidence directory:
  `benchmarks/results/raw/20260623-030344-http-three-iovec-live/`

## Build And Publication

- Local TDD first failed the guard and decoder coverage for a third bounded
  HTTP `writev` iovec slot.
- Commit `396e70d` changed the BPF request copy path from two fixed iovec
  slots to three fixed iovec slots, added `copy_http_request_iovec_slot2`, and
  added decoder coverage for request-line/header/request-ID assembly across
  three raw slots.
- Full local gate passed: `scripts/quality.sh`.
- GitHub CI run `28005540728`: success.
- GitHub image publication run `28005540720`: success.

## Live Run

- Preflight confirmed `pwd` was `/Users/victorbona/Daedalus/e-navigator` and
  `kubectl config current-context` was `staging`.
- All live Kubernetes actions were limited to namespace `e-navigator-bench`.
- Baseline before test: Helm revision 89, digest
  `sha256:90b571bf89ac36c1432a503ad9b9add7abd7604579533c1912201568db1d5bfc`,
  DaemonSet `2/2` Ready.
- First upgrade attempt, Helm revision 90, failed before runtime proof because
  a temporary generated TOML config duplicated the `source.aya_http` key.
  The release was rolled back to revision 91 and restored to the baseline
  digest with both pods Ready.
- Corrected upgrade attempt, Helm revision 92, deployed the new image digest
  and rolled the DaemonSet, but startup logs showed `source.aya_http` failed to
  load its BPF program.

## Observed Failure

The homelab-02 startup log recorded:

- `module failed: source.aya_http: the BPF_PROG_LOAD syscall returned Argument list too long (os error 7)`
- `BPF program is too large. Processed 1000001 insn`
- `processed 1000001 insns (limit 1000000)`

Because the HTTP source failed verifier loading, no three-iovec workload was
run and no `protocol_request_observation` or `request_span_observation` proof
was attempted for this image.

## Cleanup And Restore

- Rolled Helm back to revision 93, described by Helm as rollback to revision
  91.
- Verified final DaemonSet image:
  `ghcr.io/guaracloud/e-navigator@sha256:90b571bf89ac36c1432a503ad9b9add7abd7604579533c1912201568db1d5bfc`.
- Verified final DaemonSet `2/2` Ready on `homelab-01` and `homelab-02` with
  zero restarts on the restored pods.
- No proof workload Jobs were created for the corrected attempt.

## Proof Status

Proven:

- Local decoder and structural guard coverage for three fixed raw HTTP iovec
  slots.
- The pushed image `sha-396e70d` was built and published successfully.

Not proven:

- Live three-slot HTTP `writev` request capture on the homelab kernel.
- Request-span generation, request ID extraction, Host extraction, or
  Kubernetes attribution for a three-iovec controlled workload.
- Any broader HTTP claims beyond the earlier two-slot split-iovec live proof.
