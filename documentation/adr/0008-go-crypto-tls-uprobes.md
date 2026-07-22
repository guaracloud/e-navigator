# ADR 0008: Go crypto/tls Uprobe Capture

Status: accepted

Date: 2026-07-21

## Context

The TLS source captured plaintext at dynamically linked OpenSSL and GnuTLS
library boundaries. Go normally links `crypto/tls` into each executable, uses
the toolchain-private ABIInternal calling convention, and may move a goroutine
between operating-system threads while a call is in flight. A shared-library
symbol scan, conventional thread-keyed uretprobe, or guessed object layout
would therefore be unsafe.

Go documents ABIInternal as unstable. Supporting every Go version or
architecture without an audited layout would weaken the source's existing
version, architecture, symbol, and transactional-attachment preflight.
Stripped binaries also remove the exact function bounds needed to place return
probes safely.

## Decision

Support unstripped 64-bit ELF Go executables on Linux/amd64 for Go 1.24 through
1.26. Unknown versions, prereleases, malformed build information, stripped
binaries, missing or ambiguous symbols, unsupported architectures, invalid
function decoding, excessive return sites, and attachment failures fail
closed with native coverage accounting.

Userspace performs a bounded 15-second procfs rescan. It inspects at most 4,096
processes, 1,024 executable identities per scan, 4,096 tracked identities and
configured processes, a 256 MiB executable, and 1 MiB each for build
information and a function body. A 64-entry return-site limit bounds each
method. Capacity rejection and attachment failures increment the established
optional-target counters; warning output has a separate 64-message budget.

Preflight requires inline `.go.buildinfo`, an exact supported version, and the
exact static text symbols:

- `crypto/tls.(*Conn).Read`
- `crypto/tls.(*Conn).Write`
- `net.(*netFD).Read`
- `net.(*netFD).Write`

The implementation fully decodes each TLS method with `iced-x86` and attaches
ordinary uprobes at every decoded `RET`. It does not use a conventional
uretprobe because return correlation is keyed by `(tgid, direction,
goroutine)` using the Go goroutine register, not by operating-system thread.
The audited amd64 ABIInternal registers are RAX for the receiver or integer
result, RBX for the slice pointer, RCX for the slice length, and R14 for the
goroutine pointer.

The nested `net.(*netFD).Read` and `Write` entry probes resolve the concrete
socket descriptor. Go 1.24 through 1.26 place `internal/poll.FD.Sysfd` 16 bytes
after the `netFD` receiver. Userspace publishes that version-gated offset in a
4,096-entry LRU process-layout map. The eBPF side correlates at most 8,192
pending operations in an LRU map, records replacement, missing-state, layout,
fd-resolution, update-failure, entry, exit, and output-attempt counters, and
removes pending state on every observed return.

Probe attachment is transactional per executable. A partial attach is rolled
back. Map absence disables Go ABI memory reads. Successfully resolved
plaintext enters the existing bounded TLS raw-event transport, connection
lookup, multi-segment stream reassembler, parsers, and request/response
matcher. No new exported signal kind or raw payload export is introduced.

Linux/arm64 is deliberately rejected. Implementing its register ABI without a
capable runtime proof environment would create an unverified claim. Go 1.24
and 1.25 pass layout and parser tests but are not runtime-proven by this
campaign.

## Consequences

Go `crypto/tls` capture adds executable-wide uprobe attachment work and can
attach many return sites. Native counters make this cost and every blind spot
visible. The scan may encounter unrelated short-lived Go processes; global
optional-target totals are node-wide and should not be interpreted as
workload-specific proof.

The feature requires unstripped symbol tables. This is an intentional safety
boundary, not a request to ship debug information or expose application
payloads. BoringSSL, rustls, custom TLS implementations, Go versions outside
1.24 through 1.26, and statically bundled Node/JVM TLS remain unsupported.

## Evidence

Unit and property tests cover supported and rejected build versions plus
arbitrary build-info and instruction inputs. Dedicated fuzz targets executed
384,179 build-info inputs and 283,763 amd64 instruction streams without a
failure. A Criterion fixture that fully decodes 4 KiB of instructions measured
13.643 to 13.785 microseconds on the development workstation; this is local
hot-path hygiene, not runtime overhead proof.

The guarded homelab campaign ran three counterbalanced no-agent/TLS pairs. A
real unstripped Go 1.26.4 HTTPS server completed 4,000 of 4,000 requests in
every arm. Every TLS arm recorded a capture-ready Go 1.26.4 executable,
workload-scoped `/proof` HTTP 200 observations, a rejected stripped companion,
positive native Go TLS counters, zero state-update failures, and zero transport
loss. The evidence is in
`documentation/proof/go-crypto-tls-20260721/`.

The request bursts lasted only 0.105 to 0.265 seconds on a shared cluster.
Their throughput and resource samples do not support an overhead claim.

## References

- [Go internal ABI specification](https://go.dev/src/cmd/compile/abi-internal)
- [OpenTelemetry Go eBPF instrumentation](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation)
