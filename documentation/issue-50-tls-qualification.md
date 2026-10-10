# TLS capture lifecycle qualification for issue 50

Scope: [issue #50](https://github.com/guaracloud/e-navigator/issues/50).
This change hardens the existing dynamic OpenSSL 1.1.1/3, GnuTLS ABI 30 and
unstripped Linux/amd64 Go 1.24–1.26 capture paths. It introduces no adapter,
architecture claim, exported schema, dependency, or HTTPS context mutation.

## Lifecycle contract

The TLS source requires sched process-exec and process-exit tracepoints before
attaching adapters. A bounded 4,096-entry process-generation LRU map initializes
identity before observed connect/accept operations. Exec and leader exit
invalidate process identity and Go ABI layouts. Handles and pending Go calls
include the process generation; dynamic TLS pending calls validate it before
reading return-count pointers or payloads. Go discovery republishes validated
layouts each scan because kernel lifecycle hooks can invalidate them between
scans, even when the numeric PID remains configured in userspace.

OpenSSL/GnuTLS fd assignment must reference a connection observed by this
collector. It stores the connection start token independently for each direction.
An unobserved connection, including fd assignment before observed connect,
fails closed rather than binding the handle to a later reused descriptor.
Go resolves and snapshots its socket token at the nested netFD entry.
All adapters compare the token again at return. A reused fd cannot redirect
pending plaintext to a new connection. Connections older than the current
process generation are rejected, including sockets inherited across exec.

Generation-map eviction makes old handles and pending calls unreachable and
rejects existing connections until reconnect. Leader exit conservatively
invalidates surviving threads too. These are bounded coverage losses, never
historical reconstruction. Association rejection uses the existing TLS
connection-miss diagnostic and Go fd-unresolved counters. Dynamic TLS diagnostics
retain their existing opt-in configuration. Attachment remains transactional
through the existing per-library/per-executable rollback paths. Old-generation
entries in existing bounded maps remain unreachable until eviction or cleanup;
there is no unbounded map traversal.

## Local regression evidence

The host-runnable tests compile the same identity predicates used in eBPF and
cover matching identities, exec/PID reuse/map eviction, socket reuse, missing
tokens and connections predating a process generation. A shared-parser fixture
compares cleartext and TLS-derived HTTP observations, including an HTTP 401,
and verifies that authorization values, cookies and request/response secrets
are absent from serialized signals. Existing supported/rejected library and
Go-version fixtures remain in the workspace suite.

These tests do not prove kernel attachment, rollback under injected kernel
failures, concurrent lifecycle execution, or runtime/build/architecture support.
Optimized eBPF compilation is likewise not verifier or live capture proof.

## Verification record

On 2026-10-10, `scripts/quality.sh` passed with no skip flags on the local
macOS/arm64 workstation and its Docker Linux/arm64 build environment. This
included workspace tests, strict Clippy, Rustdoc, fuzz-target builds, supply-chain
checks, Docker build/smokes and Helm/Kubernetes schema validation. The initial
sandboxed run could not bind sockets in two CLI tests; the complete gate passed
with normal local access. No cluster resources were changed.

All four optimized eBPF builds passed with the pinned nightly toolchain:

```sh
for arch in x86_64 aarch64; do
  for transport in ring-buffer perf-buffer; do
    RUSTFLAGS="--cfg bpf_target_arch=\"$arch\" -C linker=bpf-linker" \
      cargo +nightly-2026-07-01 build --locked -Z build-std=core \
      --target bpfel-unknown-none -p e-navigator-ebpf-programs --release \
      --no-default-features --features "$transport"
  done
done
```

The Docker build emitted an LLVM shared-library lookup warning from bpf-linker
but successfully produced both transport artifacts and the CLI. Independent
code review found no actionable correctness or security defect. No privileged
kernel verifier, TLS workload, backend, or lifecycle fault-injection run was
performed for this change.

## Remaining acceptance evidence

Issue #50 remains open. The [acceptance contract](guara-replacement-acceptance.md)
contains no declared exact workload cells. IN-02 and IN-07 must identify required
builds, TLS linkage, architecture/ABI and capture roles before selecting a new
adapter child issue. The qualification suite dependency
[#48](https://github.com/guaracloud/e-navigator/issues/48) remains open. IN-03 must
name an authorized target; IN-04 through IN-06 provide backend assertions and
approved expected results. No current Guara cell is promoted by this change.

For each declared cell, record positive and unsupported-build fixtures plus
live commands, binary/image digests, architecture/kernel identity, attach and
association outcomes, capture/loss counters and backend privacy assertions.
Exercise process restart, same-PID exec to supported and unsupported builds,
fd reuse while TLS IO is pending, failed multi-probe attachment rollback,
late attachment, concurrency and bounded-state saturation. Compare encrypted
and cleartext operation/status/latency semantics. Every claimed architecture
needs recorded execution on an authorized capable target before issue closure.
