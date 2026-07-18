# TLS attachment hardening proof, 2026-07-17

## Decision and proof level

This is a focused local Linux/arm64 smoke, not homelab or production proof. It
supports the narrowed `source.aya_tls` runtime claim and does not change the
overall standalone replacement decision from **NO-GO**. Homelab coverage,
matched performance trials, and the mandatory continuous 24-hour soak remain
separate gates.

## Artifact and environment

- Source branch: `codex/standalone-observability-agent`
- Source parent before this uncommitted slice: `558ff62`
- Worktree patch SHA-256 at evidence capture:
  `2041fcd13dc4a038abd9cc89a85352cabcd756386c8e36f18a79f25ddfc71c49`
- Host: Darwin 25.5.0 arm64
- Container runtime: Docker client/server 29.4.0, Linux/arm64 server
- Builder: Buildx 0.33.0
- Image tag: `e-navigator:standalone-tls-final-arm64-20260717`
- Image manifest-list ID:
  `sha256:c9490e633a8044a8d2ccd25eccbf20ddde20d5f6dae8dff5652b3ed9e6ccc0cf`
- The same source also completed a Linux/amd64 release/eBPF build for the
  homelab path as `e-navigator:standalone-tls-final-amd64-20260717`, manifest
  list `sha256:1d70b524981ee7015952f33311b364905e2b5c12aa44020a27b0213f3a9d6379`.
- Embedded eBPF programs and the release CLI were compiled inside the Linux
  image build.
- The privileged OrbStack smoke mounted tracefs inside the agent container
  before startup because that local VM did not expose a mounted tracefs at the
  expected path. This is local-environment handling, not a Kubernetes proof.

The build command was:

```sh
docker buildx build --platform linux/arm64 -f Containerfile \
  -t e-navigator:standalone-tls-final-arm64-20260717 --load .
docker buildx build --platform linux/amd64 -f Containerfile \
  -t e-navigator:standalone-tls-final-amd64-20260717 --load .
```

## Supported-runtime results

The final image discovered four capture-ready library identities and attached
51 probes with no attachment failure. That count is consistent with three
OpenSSL 3 identities at 15 probes each plus one GnuTLS ABI 30 identity at six
probes. The source then captured body-consuming HTTP requests over both library
families.

| Client/library | Assertion | Result |
| --- | --- | --- |
| Python 3.12 / OpenSSL 3 | HTTPS GET `/`, complete response body | HTTP 200, 877-byte body, one matched request |
| `gnutls-cli` / GnuTLS ABI 30 | HTTPS GET `/`, complete response | HTTP 200, one matched request |

Both emitted observations had:

```json
{"kind":"protocol_request_observation","source":"source.aya_tls","payload":{"protocol":"http","role":"client","attributes":[{"key":"http.response.status_code","value":"200"}]}}
```

The bounded diagnostic stream logged PID, fd, direction, role, port, and length
metadata with the command redacted. It did not log plaintext payload bytes.
After both requests, the native metrics were:

```text
e_navigator_ebpf_source_decoded_samples_total{source="source.aya_tls"} 12
e_navigator_ebpf_source_invalid_samples_total{source="source.aya_tls"} 0
e_navigator_ebpf_source_sent_signals_total{source="source.aya_tls"} 2
e_navigator_ebpf_source_lost_perf_events_total{source="source.aya_tls"} 0
e_navigator_ebpf_source_optional_targets_discovered_total{source="source.aya_tls"} 4
e_navigator_ebpf_source_optional_targets_ready_total{source="source.aya_tls"} 4
e_navigator_ebpf_source_optional_targets_unsupported_total{source="source.aya_tls"} 0
e_navigator_ebpf_source_optional_probe_attachments_total{source="source.aya_tls"} 51
e_navigator_ebpf_source_optional_attachment_failures_total{source="source.aya_tls"} 0
e_navigator_ebpf_source_optional_capacity_rejections_total{source="source.aya_tls"} 0
```

## Fail-closed result

A disposable Python container copied its architecture-matching libc image to
`/tmp/libssl.so.4`, mapped it, and remained alive across a 15-second rescan.
The agent rejected it before attachment and emitted the bounded warning:

```text
library="libssl.so.4"
reason="unsupported or unversioned OpenSSL-compatible ABI; skipped fail-closed"
```

The readiness totals changed to five discovered, four ready, and one
unsupported while probe attachments stayed at 51 and attachment failures and
capacity rejections stayed at zero. This demonstrates version gating; it is not
a substitute for malformed-ELF and export-preflight unit coverage.

## Focused validation

```text
cargo fmt --all
cargo test --locked -p e-navigator-sources-ebpf-aya -p e-navigator-cli
  CLI unit: 32 passed
  CLI integration: 6 passed
  Aya source unit: 163 passed
cargo clippy --locked -p e-navigator-sources-ebpf-aya \
  -p e-navigator-cli --all-targets -- -D warnings
  passed
```

The source tests cover version classification, TLS provenance, fd lifecycle,
protocol reassembly, and cumulative telemetry. Full workspace and supply-chain
gates are recorded separately after this focused slice is committed.

## Exact claim and remaining gaps

The claimed capture surface is dynamically linked OpenSSL 1.1.1/3 with the
complete required classic and `_ex` read/write plus fd-association export set,
and GnuTLS ABI 30 using its standard integer socket transport. Candidates are
bounded, architecture-checked, version-gated, export-preflighted, and attached
transactionally.

BoringSSL, Go `crypto/tls`, rustls, custom OpenSSL BIOs, custom GnuTLS
transports, statically bundled Node TLS, and JVM JSSE are not claimed. Unknown
or incomplete libraries fail closed. This source intercepts plaintext at the
library boundary; it does not decrypt packets on the wire.

## Local cleanup

The exact disposable agent, Python HTTPS server, GnuTLS HTTP server,
unknown-ABI fixture container, and `enav-tls-20260717` Docker network were
removed after evidence capture. The two final arm64/amd64 E-Navigator image
tags were retained for the next verification stage; the two earlier
intermediate TLS image tags were removed. No unrelated Docker resource was
modified.
