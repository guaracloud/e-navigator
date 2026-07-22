# ADR 0010: Bounded Browser Protocols and the HTTP/3 Boundary

Status: accepted

Date: 2026-07-22

## Context

The protocol source already reassembled bounded HTTP/1 streams and matched
requests to responses. Browser-facing traffic adds two protocols that remain
realistic on that capture path: WebSocket upgrades and gRPC-Web envelopes.
Both are carried over HTTP/1 before or around their message framing, so the
existing socket payload source can observe their metadata without exporting
application payloads.

HTTP/3 is materially different. It carries HTTP semantics over QUIC and UDP.
QUIC protects almost all transport and application metadata, including HTTP/3
HEADERS and DATA frames. The current protocol source observes configured TCP
socket payloads, and the TLS source intercepts only audited OpenSSL, GnuTLS,
and Go `crypto/tls` stream boundaries. None of those boundaries yields generic
QUIC stream data, connection-ID state, or QPACK state.

WebSocket extensions can redefine RSV bits and payload interpretation. A
parser that accepted an extension negotiation without implementing that
extension would silently misclassify frames. File descriptors are also reused
aggressively. A WebSocket transition keyed only by `(pid, fd)` can therefore
leak into a later connection to the same endpoint.

## Decision

Add WebSocket and gRPC-Web to the existing HTTP/1 port surface. Do not add a
separate port list or unvalidated runtime knob.

The WebSocket path:

- validates an RFC 6455 version 13 request key and the corresponding response
  accept value before changing protocol state;
- accepts only extension-free upgrades and rejects any extension negotiation;
- switches both stream directions only after a matching HTTP 101 response;
- validates direction-specific masking, RSV bits, opcodes, minimal length
  encodings, control-frame bounds, and the configured frame-size bound;
- exports only opcode, FIN, masking, declared payload length, direction, and
  capture-completeness metadata, never frame payload bytes;
- accounts rejected transitions, truncated frames, decoder resynchronization,
  and dropped buffered bytes through bounded stream and registry counters.

The raw protocol ABI carries the kernel connection start timestamp as a
generation token. Userspace includes it in connection identity checks, so a
closed and reused `(pid, fd)` evicts the old stream before parsing the new
connection. This token is shared by cleartext and supported TLS plaintext
events and avoids heuristic protocol resets.

The gRPC-Web path:

- recognizes the standard binary and base64 text content types on HTTP/1;
- applies existing HTTP header and entity bounds, including bounded
  `Content-Length` and chunked decoding;
- permits at most 64 envelopes per message and rejects invalid flags,
  truncated envelopes, a non-final trailer, invalid base64, and bodies beyond
  the configured bound;
- requires an in-body `grpc-status` trailer on responses and maps that status
  into the existing gRPC request observation;
- exports service, method, wire mode, frame counts, and status metadata, never
  protobuf or trailer payload bytes.

Keep HTTP/3 and generic QUIC semantic capture as an explicit non-claim. A
future implementation requires an audited plaintext boundary in each
supported QUIC runtime, or a different kernel or application contract that
provides decrypted stream and QPACK state. UDP datagram capture alone is not a
safe HTTP/3 parser input.

## Consequences

WebSocket observations cover extension-free RFC 6455 framing only. Compressed
or otherwise extended frames fail closed. Fragmented data frames are reported
as independent frame metadata; E-Navigator does not reconstruct or export the
application message.

gRPC-Web is metadata extraction, not protobuf decoding. It does not claim
browser CORS behavior, streaming semantics beyond bounded envelope counts, or
native HTTP/2 gRPC equivalence.

The generation token changes the internal raw-event ABI. The userspace and
both embedded eBPF transport objects are built together, so mixed object and
userspace versions are unsupported and fail raw-size validation.

## Evidence

Unit and property tests cover valid and malformed WebSocket handshakes,
directional masking, coalesced HTTP 101 plus frame transitions, gRPC-Web binary
and text messages, chunked bodies, concatenated padded base64 segments, trailer
ordering, payload non-export, and file-descriptor reuse across protocol
transitions. Dedicated parser fuzz targets and Criterion hot-path benchmarks
cover both new parsers.

The guarded homelab campaign runs a pinned workload with raw WebSocket,
binary-request/text-response gRPC-Web, and a real aioquic HTTP/3 exchange. It
alternates three no-agent and three protocol-source arms, validates workload
success and semantic output, rejects payload-secret leakage, requires zero
transport loss, and records restoration of the standing Argo CD deployment.
The committed evidence is in
`documentation/proof/protocol-surface-20260722/`.

The successful HTTP/3 exchange coupled with zero HTTP/3 or QUIC semantic
observations is negative runtime evidence for the non-claim. It is not proof
that every QUIC runtime is invisible to every possible future probe.

## References

- RFC 6455, The WebSocket Protocol:
  <https://www.rfc-editor.org/rfc/rfc6455.html>
- gRPC-Web protocol specification:
  <https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-WEB.md>
- RFC 9114, HTTP/3:
  <https://www.rfc-editor.org/rfc/rfc9114.html>
- RFC 9001, Using TLS to Secure QUIC:
  <https://www.rfc-editor.org/rfc/rfc9001.html>
