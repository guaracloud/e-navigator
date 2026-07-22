# Go crypto/tls capture proof, 2026-07-21

## Decision

E-Navigator supports plaintext interception at the Go `crypto/tls` library
boundary for unstripped 64-bit ELF Go 1.24 through 1.26 executables on
Linux/amd64. The guarded homelab run proves the exact Go 1.26.4 server slice.
Go 1.24 and 1.25 remain implementation-and-test claims without runtime proof.

Unsupported versions, prereleases, malformed build information, stripped
binaries, non-amd64 binaries, missing or ambiguous symbols, invalid function
decoding, excessive return sites, and failed attachments are rejected with
native accounting. This is library-boundary interception, not on-the-wire TLS
decryption.

## Implementation proved

Userspace boundedly scans procfs and accepts an executable only after exact Go
version, architecture, static-symbol, function-bound, and instruction-decoder
preflight. It transactionally attaches entry probes to
`crypto/tls.(*Conn).Read` and `Write`, entry probes to the nested
`net.(*netFD).Read` and `Write`, and ordinary uprobes at every decoded TLS
method return instruction.

The eBPF path uses the audited amd64 ABIInternal registers and correlates
entries and returns by process, direction, and Go goroutine. That key remains
valid when a goroutine moves between operating-system threads. The nested
`netFD` probes resolve the concrete socket descriptor through a version-gated
`internal/poll.FD.Sysfd` offset. A missing process layout disables the read.

The process-layout map is a 4,096-entry LRU and pending operations use an
8,192-entry LRU. Native counters account for entries, exits, layout misses,
pending misses, replacements, map-update failures, fd resolution and failure,
and output attempts. Successfully resolved plaintext reuses the TLS source's
existing bounded raw event, RingBuf loss accounting, connection tuple lookup,
multi-segment stream reassembler, HTTP parser, and request/response matcher.

## Environment and method

- Context: `homelab`, exclusively.
- Cluster: k3s `v1.30.4+k3s1`, two amd64 NixOS 24.05 nodes, Linux 6.6.68,
  containerd `1.7.20-k3s1`.
- Agent image: `docker.io/library/e-navigator:gap3-20260721`, local manifest
  `sha256:240ceab0ebe67e0492ff0c21d87ab84500f54535b8a8e807c3807c842f1e721b`.
- Workload image: `docker.io/library/e-navigator-go-tls:gap3-20260721`, local
  manifest
  `sha256:296a5a72fcccccb4b33eba9397cd353b2e34afbae87d16ea7851f48917131fb3`.
  It pinned Go 1.26.4 and contained both normal and `-s -w` binaries.
- Both images were loaded directly into each homelab containerd store and were
  never pushed.
- Arms: no benchmark agent and an agent with only `source.aya_tls`, RingBuf,
  JSON output, Kubernetes attribution, and Prometheus HTTP enabled.
- Order: `none/tls`, `tls/none`, then `none/tls`.
- Workload: two topology-spread normal HTTPS server replicas plus one stripped
  rejection control. After a 20-second attachment window, a pinned client used
  concurrency 16 for 4,000 HTTPS GET requests to `/proof`.
- Collection: eight five-second pod-resource samples, workload output, pod
  inventory and placement, rendered Helm values and manifest, agent logs,
  native Prometheus metrics, process capability/mount state, events, and
  cleanup/restore state.
- Every no-agent arm had a post-teardown inventory gate requiring zero
  benchmark E-Navigator pods before the workload was accepted.

## Runtime results

All six clients completed 4,000 of 4,000 requests without an application
failure. Every TLS arm logged the exact unstripped Go 1.26.4 executable as
capture-ready and the stripped companion as unsupported because its required
static symbol was absent.

| TLS repetition | Workload-scoped `/proof` HTTP 200 observations | Go TLS entries | Go TLS exits | FD resolutions | FD resolution failures | Output attempts | State update failures | Transport loss |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 7,971 | 9,779 | 9,770 | 5,718 | 7,783 | 3,798 | 0 | 0 |
| 2 | 1,277 | 7,015 | 7,006 | 3,954 | 5,844 | 2,635 | 0 | 0 |
| 3 | 1,566 | 8,695 | 8,686 | 4,812 | 7,425 | 3,201 | 0 | 0 |

The captured observation was scoped to source `source.aya_tls`, process
`go-https-proof`, namespace `e-navigator-bench`, path `/proof`, and HTTP status
200. A curated example is in
[representative-signal.json](representative-signal.json).

All TLS runs reported zero Go state-update failures, zero aggregate transport
loss, zero RingBuf reservation failures, and zero optional attachment failures
at the final scrape. Pending misses were 14, 15, and 10; state replacements
were 1, 0, and 1. FD-resolution failures are accounted node-wide and include
TLS calls that could not be matched to an already tracked connection. They are
not silently discarded and are not interpreted as workload request failures.

The exact normalized results and run-level counters are in
[runs.json](runs.json).

## Local validation

- Six focused unit/property tests passed for supported/rejected versions,
  build-info bounds, and sorted in-range return sites.
- The build-info fuzz target executed 384,179 inputs in six seconds without a
  failure.
- The amd64 return-site fuzz target executed 283,763 instruction streams in
  six seconds without a failure.
- The 4 KiB full-instruction decoder Criterion fixture measured 13.643 to
  13.785 microseconds on the arm64 development workstation.
- The complete repository quality gate passed, including strict Clippy,
  Rustdoc warnings, workspace tests/build, fuzz compilation, supply-chain
  checks, Docker smoke, Helm/Kubernetes validation, documentation checks, and
  repository guards.

The local benchmark and fuzz executions establish hygiene for bounded
decoding. They are not homelab runtime or overhead proof.

## Performance boundary

The fixed request bursts lasted only 0.105 to 0.265 seconds on a shared
cluster. The no-agent runs averaged 34,732 requests/s and the TLS runs averaged
15,475 requests/s, but the sample is too short, attachment work overlaps the
resource window, and the campaign was designed as a correctness proof. No
throughput, latency, CPU, memory, or comparative overhead claim is made from
these numbers.

## Remaining boundaries

- Go 1.24 and 1.25 pass the audited-layout tests but were not runtime-proven.
- Linux/arm64 and every non-amd64 Go ABI are rejected.
- Stripped binaries are deliberately unsupported and fail closed.
- Go versions outside 1.24 through 1.26, prereleases, dynamically rewritten
  functions, and executables beyond the documented bounds are unsupported.
- The run proves HTTP/1 request/status recovery for one Go 1.26.4 HTTPS
  service. It does not prove gRPC, WebSocket, every parser, all-node symmetry,
  production traffic, or production overhead.
- Optional-target and Go native counters are node-wide. Unrelated Go process
  churn can change them independently of the proof workload.
- BoringSSL, rustls, custom TLS stacks, and statically bundled Node/JVM TLS
  remain outside this capture surface.

## Cleanup and restore

The disposable workloads and Helm release were removed. Both campaign image
tags were removed from both homelab containerd stores and the local Docker
store, the loader DaemonSet was deleted, and `e-navigator-bench` was deleted.
The standing Argo CD application reported `Synced` and `Healthy` with automated
prune and self-heal restored. Its original digest-pinned DaemonSet was 2/2
Ready at
`sha256:62402d21b9cb02d59d63365c7e3716ffa0980bfea42d070b43fed618703a7df9`.
The campaign touched no production context.
