# ADR 0015: Peer flow metrics and opt-in HTTP/1 propagation

- Status: accepted
- Date: 2026-08-11

## Context

E-Navigator already owns client-side TCP connection byte totals and enriches
native flow summaries with Kubernetes namespace, controller, and Service
identity. It also passively observes W3C trace context. The former is enough to
derive a stable peer-aware L4 metric; the latter cannot connect uninstrumented
services because observation does not modify the request.

Active context propagation changes application traffic. TLS, HTTP/2, HTTP/3,
segmented headers, request bodies, application-owned trace context, and kernel
feature differences make a universal injector unsafe and untruthful. The
standalone contract requires native behavior with explicit limits rather than
vendor compatibility modes.

## Decision

### Peer-aware flow metric

Add `generator.peer_flow_metrics` after container attribution. It consumes only
enriched `NetworkFlowSummaryEvent` signals and emits the cumulative monotonic
sum `network.peer.flow.bytes` with:

- `source.k8s.namespace.name`, `source.k8s.workload.name`, and
  `source.k8s.workload.kind`;
- the corresponding `destination.*` attributes;
- native `network.flow.direction`, plus standard `network.transport` and
  `network.type`; and
- `otel.metric.overflow`.

Locally sent bytes are source-to-destination `egress`; locally received bytes
reverse the endpoints and are `ingress`. A series is emitted only when both
endpoints have a namespace, stable owner name, and owner type. Missing or
ambiguous attribution remains absent rather than being guessed.

The generator retains at most `network_metrics.max_metric_keys` exact series.
Further observations aggregate into the fixed `__other__` identity by protocol,
address family, and direction, preserving byte totals. The compiled protocol,
address-family, and direction enums bound this overflow set independently of
workload cardinality (eight series in the current TCP/UDP, IPv4/IPv6, and
ingress/egress model). Pod names, IP addresses, ports, container ids, and labels
never enter the metric identity.

### W3C context propagation

Add a narrow `http_source.context_propagation` capability. It is disabled by
default and enabling it requires:

- `source.aya_http` and inbound HTTP capture;
- a directly mounted cgroup v2 root;
- a non-empty bounded plaintext destination-port allowlist;
- a target kernel that can load and attach `BPF_SOCK_OPS`, `BPF_SK_MSG`,
  `BPF_MAP_TYPE_SOCKHASH`, and the required socket-message helpers; and
- privileged qualification on the exact kernel, image, capability set, and
  workload before production use.

A cgroup `SOCK_OPS` program adds capture-allowed, actively established client
TCP sockets to a bounded `SOCKHASH`. An `SK_MSG` program mutates eligible socket
messages before TCP packetization with `bpf_msg_push_data`, so the kernel still
owns sequence numbers, acknowledgements, checksums, segmentation, retransmits,
and application send-return semantics. E-Navigator does not implement a packet
sequence translator.

Injection is allowed only for one complete, contiguous, header-only HTTP/1.0 or
HTTP/1.1 message of at most 1,024 bytes observed through a supported scalar
write path. It bypasses:

- an existing `traceparent`, regardless of header-name case;
- incomplete or segmented headers, multiple requests, and trailing bytes;
- positive `Content-Length` or any `Transfer-Encoding`;
- CONNECT, HTTP/2 prefaces, upgrades, TLS, and non-HTTP traffic;
- iovec/sendmsg paths, sockets established before attachment, sockets outside
  the cgroup capture policy, and ports outside the allowlist; and
- an empty context pool, full pending map, or any pre-mutation helper failure.

All decisions occur before `bpf_msg_push_data`. After a successful push, direct
message pointers are reloaded and the complete inserted range is proven before
all 70 bytes are overwritten. If that post-push proof unexpectedly fails, the
message is dropped: passing could transmit kernel-created uninitialized bytes.
This exceptional counter must remain zero in qualification and production.

Userspace fills and continuously replenishes a bounded BPF queue with
cryptographically secure random trace and span ids. The kernel never derives
wire ids from local correlation hashes. Existing application-owned context is
preserved. A successfully injected client observation is marked as
E-Navigator-owned so request correlation exports the matching client span.
Inbound single-message HTTP/1 requests create a new server span beneath the
wire parent and retain a short, bounded same-thread context for synchronous
downstream calls. Async task/thread hops are not claimed.

## Consequences

- Peer metrics are available through native JSON, Prometheus, and OTLP metric
  contracts without changing the existing `network.flow.bytes` series.
- Passive HTTP capture remains unchanged when propagation is disabled.
- This closes multi-service traces only for the qualified plaintext,
  synchronous HTTP/1 subset. HTTPS, HTTP/2/gRPC, HTTP/3/QUIC, segmented writes,
  and asynchronous continuation require separate pre-encryption or
  protocol-aware designs.
- Propagation counters report socket tracking, planning, injection, bypass,
  context exhaustion, contention, push failure, post-push failure, and thread
  context failure. Any nonzero mutation-failure counter blocks capability
  promotion.
- Unit and integration tests prove deterministic planning, formatting,
  identity ownership, correlation, bounded aggregation, overflow, and sink
  formatting. They do not prove verifier acceptance or live mutation on a
  target Linux kernel.

## Rejected alternatives

- TC packet rewriting: it requires bidirectional TCP sequence/acknowledgement,
  SACK, retransmission, checksum, and offload translation.
- Ciphertext mutation: TLS authentication makes it invalid.
- Header injection into HTTP/2 or HTTP/3 without stream and compression state:
  it would corrupt the protocol.
- Overwriting application context: it breaks upstream sampling and trace
  ownership.
- Collector-specific aliases or compatibility modes: they violate the native
  standalone contract.
