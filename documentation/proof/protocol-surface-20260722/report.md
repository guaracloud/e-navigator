# Browser Protocol Surface Proof, 2026-07-22

## Decision

E-Navigator supports bounded, metadata-only capture for extension-free RFC 6455
WebSocket frames and binary or base64-text gRPC-Web envelopes carried on the
configured HTTP/1 protocol ports. It does not claim WebSocket extensions,
compression, fragmented-message reconstruction, gRPC-Web protobuf decoding,
HTTP/3, or generic QUIC semantics.

The HTTP/3 non-claim is architectural. The current protocol source observes
bounded TCP socket payloads. HTTP/3 uses QUIC over UDP, and QUIC protects the
HTTP HEADERS and DATA semantics that a passive payload parser would need. The
campaign therefore used a real HTTP/3 exchange as a negative control instead
of promoting a parser that could not receive truthful input.

## Implementation proved

The WebSocket path validates the HTTP/1 request and response upgrade pair,
including the RFC 6455 accept derivation, before switching stream state. It
accepts only extension-free framing, validates masking by direction, reserved
bits, opcodes, minimal lengths, and control-frame limits, then exports opcode,
direction, FIN, masking, payload length, and capture completeness. It never
exports application bytes.

The raw kernel event carries the connection start timestamp. Userspace combines
that generation with pid and fd, so rapid operating-system fd reuse cannot leak
WebSocket state into a new socket. The defect was found during the first proof
attempt and is covered by a dedicated regression.

The gRPC-Web path recognizes the standard binary and text content types,
boundedly removes HTTP chunking, validates a maximum of 64 five-byte-framed
messages or trailers, handles base64 padding and concatenated text segments,
and reports RPC service, method, mode, message counts, HTTP status, and gRPC
trailer status. It does not decode or export protobuf messages.

Native cumulative Prometheus metrics expose successful WebSocket upgrades,
frames, transition rejections, and gRPC-Web requests. Periodic structured
summaries retain delta semantics. Malformed transitions and parser limits fail
closed with accounting.

## Environment and method

- Context: `homelab`, exclusively.
- Cluster: k3s `v1.30.4+k3s1`, two amd64 NixOS 24.05 nodes, Linux 6.6.68,
  containerd `1.7.20-k3s1`.
- Agent image: `docker.io/library/e-navigator:gap5-dev-amd64`, local manifest
  `sha256:99d8f1b59f1694746a173d40d6e0103426577894c7bd61c4a8e84747c899490a`.
- Workload image: `docker.io/library/e-navigator-protocol-surface:gap5-20260722`,
  local manifest
  `sha256:931586dd6c6d27b6d9766c4310b8b63ddd153c5388f5ca3155cb15c6245fa316`.
- Both images were loaded directly into both homelab containerd stores and were
  never pushed.
- Arms: no benchmark agent and an agent with only `source.aya_protocol`,
  RingBuf, JSON output, Kubernetes attribution, and Prometheus HTTP enabled.
- Order: `none/protocol`, `protocol/none`, then `none/protocol`.
- Each 30-second workload used a 100 ms pacing interval and completed 298
  WebSocket exchanges, 298 gRPC-Web exchanges, and three real aioquic HTTP/3
  exchanges without a failure.
- Collection included workload output, pod inventory and placement, eight
  five-second resource samples, rendered Helm values and manifests, agent
  output, per-pod native Prometheus metrics, process capability and mount
  state, events, and cleanup/restore state.
- Every no-agent arm required zero benchmark E-Navigator pods.

## Runtime results

All three protocol repetitions produced the same validated evidence:

| Evidence per protocol repetition | Count |
| --- | ---: |
| WebSocket workload successes | 298 |
| WebSocket handshake observations | 298 |
| WebSocket frame observations | 596 |
| Native WebSocket upgrades | 298 |
| Native WebSocket frames | 596 |
| Native WebSocket transition rejections | 0 |
| gRPC-Web workload successes | 298 |
| gRPC-Web status-zero observations | 298 |
| Native gRPC-Web requests | 298 |
| aioquic HTTP/3 successes | 3 |
| HTTP/3 or QUIC semantic observations | 0 |
| Transport loss, perf loss, and RingBuf reservation failures | 0 |

The analyzer also required every semantic observation carrying Kubernetes
context to remain in `e-navigator-bench`. Neither workload secret marker was
present in agent output. Native protocol counters matched the semantic counts
exactly in every run. Curated signal examples are in
[`representative-signals.json`](representative-signals.json), and the complete
normalized run analysis is in [`analysis.json`](analysis.json).

## Measured performance boundary

| Arm | Operations/s mean +/- sd | Iteration p95 ms mean +/- sd | Agent CPU m mean +/- sd | Agent memory MiB mean +/- sd |
| --- | ---: | ---: | ---: | ---: |
| no benchmark agent | 19.862091 +/- 0.002021 | 0.858090 +/- 0.018113 | n/a | n/a |
| protocol source | 19.852290 +/- 0.006286 | 0.938343 +/- 0.022766 | 39.386905 +/- 13.970088 | 23.345238 +/- 0.135212 |

The protocol arm measured 0.049345% fewer operations per second. The workload
was deliberately paced at 100 ms per pair of application operations, the
30-second windows were short, and the shared nodes had background activity.
The p95 iteration latency was 9.35% higher, but application throughput was
dominated by the pacing interval. These numbers are recorded for transparency
and support no general or production overhead claim.

## Local validation

- The complete focused package suite passed, including 208 Aya source tests,
  418 protocol extraction tests, 64 protocol library tests, and all signal,
  generator, sink, and CLI tests.
- Both new cargo-fuzz targets executed for 20 seconds under nightly with no
  crash. The gRPC-Web run completed about 8.0 million inputs.
- Criterion measured WebSocket upgrade detection at 339.92 to 346.98 ns,
  1 KiB frame boundary validation at 3.1090 to 3.1801 ns, 1 KiB frame metadata
  extraction at 4.0981 to 4.1909 ns, gRPC-Web binary request parsing at 1.1899
  to 1.2784 microseconds, and response parsing at 841.88 to 852.95 ns on the
  arm64 development workstation.

Those local runs prove parser hygiene and bound regression surfaces. They are
not homelab runtime or whole-agent overhead evidence.

## Cleanup and restore

The disposable workload jobs and benchmark Helm release were removed. The two
exact campaign image tags were removed from both homelab containerd stores and
the loader DaemonSet was deleted. The benchmark namespace contained no
resources. The standing Argo CD application reported automated prune and
self-heal enabled, `Synced`, and `Healthy`; its DaemonSet was 2/2 Ready. No
production context, namespace, dashboard, or collector was touched.

## Standards and protocol references

- RFC 6455, The WebSocket Protocol: <https://www.rfc-editor.org/rfc/rfc6455>
- gRPC-Web protocol specification:
  <https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-WEB.md>
- RFC 9114, HTTP/3: <https://www.rfc-editor.org/rfc/rfc9114>
- RFC 9001, Using TLS to Secure QUIC:
  <https://www.rfc-editor.org/rfc/rfc9001>
