# Peer-Aware Flows And W3C Propagation Feasibility

Status: research

Date: 2026-08-11

## Decision

The peer-aware L4 byte metric is implementable within E-Navigator's existing
native pipeline. The kernel already reports bounded connection byte totals and
the userspace attribution processor already resolves both flow endpoints. The
missing contract is a directional signal that retains sent and received byte
counts until Kubernetes enrichment has completed, followed by bounded metric
aggregation and native OTLP and Prometheus projection.

A universal zero-code `traceparent` injector is not one feature with one safe
eBPF implementation. Cleartext HTTP/1, HTTP/2 and gRPC, and HTTPS require
different mutation and context-association mechanisms. Shipping generic packet
or process-memory mutation under a universal claim would be unsafe and would
not produce reliable parent-child relationships. The feature must therefore be
split into explicitly qualified transports and runtimes, fail open, and remain
disabled by default until privileged Linux evidence exists for each supported
cell.

Here, fail open is a policy guarantee for unsupported traffic and for helper
rejection before mutation: pass the original message. It is not an absolute
availability guarantee under kernel memory pressure. Inserting a socket into a
SOCKHASH changes its send path to allocate and process `sk_msg` state, and those
kernel allocations can fail independently of the BPF program's verdict.

## Implementation disposition (2026-08-11)

The peer metric is implemented as the post-attribution
`generator.peer_flow_metrics` module and native `network.peer.flow.bytes`
signal. Active TCP connections emit versioned cumulative snapshots on a
configurable interval; the network generator derives interval deltas and the
peer generator reclaims idle exact series through an ordered expiry index. The
narrow socket-message design is implemented behind the
disabled-by-default `[http_source.context_propagation]` gate. It adopts the
strictest safe subset from this analysis: one complete bounded plaintext HTTP/1
header block, valid `Content-Length` body prefixes, up to three 96-byte iovecs,
application-context preservation, valid inbound `tracestate` forwarding,
userspace CSPRNG ids, bounded maps, capture-policy admission, exact pre-push
message comparison, and post-push drop if the inserted region cannot be
linearized and proven before overwrite.

The repository-pinned nightly and `bpf-linker` produce the release eBPF object.
A privileged local aarch64 OrbStack run on kernel
`7.0.11-orbstack-00360-gc9bc4d96ac70` proved verifier acceptance, cgroup
`SOCK_OPS`/`SK_MSG` attachment, and live three-iovec `sendmsg` injection with a
four-byte body, child `traceparent`, and preserved multi-member `tracestate`.
This promotes only that exact cell. Backend trace shape, other kernels and
architectures, async runtimes, saturation, exhaustion, and soak remain in the
qualification matrix below. ADR 0015 fixes the public support contract.

| Feature | Engineering decision | Main reason |
| --- | --- | --- |
| Peer-aware L4 byte metric | Implemented as a native bounded metric with active snapshots and idle exact-series reclamation | Kernel-owned cumulative connection counters, generated directional flow summaries, and Kubernetes endpoint attribution provide the required data without waiting for close |
| Cleartext HTTP/1 propagation | Prefer an opt-in `SK_MSG` socket-message implementation for mapped local TCP sockets; retain TC only as a separately qualified fallback | Mutation before `tcp_sendmsg_locked` leaves packetization, sequence numbers, retransmission, and checksums to TCP, but it covers only eligible sockets and still requires bounded HTTP stream parsing |
| HTTPS propagation | Support only through explicit pre-encryption, runtime or library integrations | TLS application data is authenticated and encrypted, so ciphertext mutation cannot create a valid HTTP header |
| HTTP/2 and gRPC propagation | Separate HPACK-aware, per-stream implementation | A connection carries concurrent streams and compressed header blocks |
| HTTP/3 and QUIC propagation | Out of scope | HTTP/3 runs over QUIC with TLS 1.3 confidentiality and integrity |

## Current E-Navigator Baseline

The existing native path already has most of the peer metric substrate:

1. The network source emits final connection observations plus periodic,
   cumulative active-connection snapshots with sent and received byte totals.
2. `generator.network_metrics` converts snapshots to non-overlapping interval
   deltas, reconciles the final close remainder, and emits directional
   `NetworkFlowSummaryEvent` signals plus the current `network.flow.bytes`
   counter.
3. Generated signals are processed again by the runner. This allows
   `processor.container_attribution` to enrich both flow endpoints after the
   flow summary has been generated.
4. Kubernetes attribution already resolves container identities, Pod IPs,
   Service ClusterIPs, and EndpointSlice addresses into endpoint namespace,
   owner name, and owner type.
5. OTLP traces already establish the native source and destination workload
   attribute vocabulary.

The native `network.flow.bytes` counter intentionally retains its stable local
workload, protocol, and address-family identity. The separately named
`network.peer.flow.bytes` contract carries peer identity and direction without
silently changing the older series. Its exact-series budget is recyclable
after the configured idle timeout, while a fixed `__other__` family preserves
traffic observed during saturation.

The request-correlation path provides useful observation and local correlation,
but it is not an injection implementation. It intentionally avoids generating
a duplicate client span when a valid outbound W3C context is already present.
Its generated identities are deterministic hashes, which are not suitable for
wire propagation. The W3C recommendation requires globally unique, opaque
identifiers and advises against embedding identifying information in them.

## Peer-Aware L4 Byte Metric

### Metric semantics

The metric must count L4 payload bytes observed by the connection source, not
link, IP, or TCP header bytes. Retransmitted payload must not be counted again if
the underlying kernel counters already report application byte progress rather
than wire retransmissions. The exact source counter and retransmission behavior
must be named in the public contract and proved against the relevant kernel
field before release.

Use one monotonic Sum with unit `By`. The existing public native name is
`network.flow.bytes`. Changing its aggregation identity in place would alter the
meaning and number of its series, so the implementation must either:

- version the existing contract explicitly, with a migration note, or
- add a separately named native peer-flow metric while retaining the old metric
  for a documented deprecation window.

Do not add a vendor compatibility alias. Prometheus projection should follow the
native name deterministically and use counter semantics. Prometheus recommends
base units and a `_total` suffix for accumulating counters. OpenTelemetry Sum
points must declare monotonicity and aggregation temporality explicitly.

Every contribution has unambiguous orientation:

| Observation | Source endpoint | Destination endpoint | Direction | Bytes |
| --- | --- | --- | --- | --- |
| Locally sent | Local workload | Remote peer | `egress` | `bytes_sent` |
| Locally received | Remote peer | Local workload | `ingress` | `bytes_received` |

Zero-valued contributions are omitted. A bidirectional connection therefore
produces two directional contributions. This preserves the byte producer and
consumer meaning of source and destination and prevents a total from being
mislabelled as egress.

The current summary loses the split, so the signal contract must preserve both
directional contributions until after endpoint attribution. A downstream metric
generator should consume the enriched flow signal. It must not aggregate the
unattributed close observation and try to reconstruct peers later.

### Attribute contract

The fixed peer series dimensions should be:

- source Kubernetes namespace;
- source workload owner name;
- source workload owner type;
- destination Kubernetes namespace;
- destination workload owner name;
- destination workload owner type;
- flow direction;
- transport protocol; and
- network address family.

OTel Kubernetes resource conventions model the emitting resource, not two
participants in a flow. The peer-prefixed fields are therefore E-Navigator
native point attributes. Reuse the source and destination workload vocabulary
already established by native flow traces. Do not present those fields as
standard OTel resource attributes.

Do not reuse the standard `network.io.direction` attribute for this purpose.
OpenTelemetry defines it as interface receive or transmit direction, while this
contract defines logical direction relative to the observed workload. Use the
native `network.flow.direction` point attribute with `ingress` or `egress`. See the
[OpenTelemetry network attribute registry](https://opentelemetry.io/docs/specs/semconv/registry/attributes/network/).

Do not add IP address, port, Pod name, Pod UID, container ID, process ID, or
request information to this metric. Prometheus creates a new series for every
unique label combination and explicitly warns against unbounded or
high-cardinality labels. Pod and process identities are also too transient for a
workload-owner metric.

The owner resolver must follow controller references to the canonical workload.
A Pod owned by a ReplicaSet that is owned by a Deployment should be attributed
to the Deployment, not merely to the intermediate ReplicaSet. Kubernetes owner
references include kind, name, and UID, and names are namespace-scoped. Service
attribution and Pod workload attribution are different evidence classes and
must retain their owner type. EndpointSlice duplication, stale cache entries,
and Network Address Translation can make attribution ambiguous. When the cache
cannot prove one owner, leave the peer unknown and increment a bounded warning
counter rather than inventing an identity.

Kubernetes documents the ownership chain and the controller relationship in
[Owners and Dependents](https://kubernetes.io/docs/concepts/overview/working-with-objects/owners-dependents/),
the [OwnerReference API](https://kubernetes.io/docs/reference/kubernetes-api/common-parameters/common-definitions/#OwnerReference),
and the [ReplicaSet controller documentation](https://kubernetes.io/docs/concepts/workloads/controllers/replicaset/).

### Cardinality and accounting

Apply the hard series limit in userspace after both endpoint identities are
known. Kernel maps should retain only bounded connection state, not
Kubernetes-derived strings.

Reserve one aggregation slot for overflow and follow the OTel cardinality-limit
model:

- every byte measurement belongs to exactly one aggregator;
- no byte measurement is dropped or counted twice;
- excess attribute sets aggregate into a point with
  `otel.metric.overflow=true`; and
- overflow activity and source event loss are exposed as native self-metrics.

This is stricter than silently suppressing new keys. The OTel SDK specification
defines cardinality as a hard limit and specifies an overflow attribute so that
measurements are not discarded. See [OpenTelemetry metric cardinality limits](https://opentelemetry.io/docs/specs/otel/metrics/sdk/#cardinality-limits)
and the [OpenTelemetry Metrics Data Model](https://opentelemetry.io/docs/specs/otel/metrics/data-model/).

The limit must be configurable, validated as nonzero, and covered by exact-total
tests. A deterministic bounded map policy is preferable to an implicit standard
library eviction policy. If LRU maps are used for kernel flow state, eviction
must not silently discard accumulated bytes. Linux documents hash and LRU map
behavior in [BPF map type HASH](https://docs.kernel.org/bpf/map_hash.html).

### Duplicate capture

The metric needs one authoritative accounting observation per connection. An
intra-node flow can be visible at multiple network interfaces and at both ends
of a DaemonSet deployment. The implementation must retain the existing precise
flow fingerprint or define an equally explicit local/remote ownership rule. A
short time-window heuristic is insufficient because it can merge legitimate
parallel connections.

The contract must state whether a node-local flow is emitted once globally or
once by each observed endpoint. If once globally is required, the ownership
rule must be deterministic across agents and survive restarts. This cannot be
hidden inside Prometheus query conventions.

### Required tests and evidence

Unit and integration coverage must include:

- sent-only, received-only, and bidirectional directional splitting;
- exact source/destination reversal for ingress;
- TCP and UDP, IPv4 and IPv6;
- Pod, Service, and EndpointSlice attribution;
- Pod to ReplicaSet to Deployment owner traversal;
- namespace, owner name, and owner type separation;
- unknown, stale, and ambiguous peers without invented attribution;
- duplicate suppression and two legitimate parallel connections;
- cardinality saturation with exact total preservation in overflow;
- sanitization, truncation, deterministic ordering, and reset behavior;
- OTLP monotonic Sum, unit, temporality, and exact point attributes;
- Prometheus name, labels, escaping, counter type, and exact exposition text;
- generated-signal reprocessing through the real runner; and
- source loss, overflow, and attribution warning self-metrics.

Live proof must include traffic between two Kubernetes workloads and a Service,
both directions, and comparison with application-known byte totals. It must
show native OTLP collection and Prometheus scraping from the same build. Unit
tests cannot prove Kubernetes cache timing, duplicate observation, or runtime
byte accounting.

## Zero-Code W3C Trace Context Propagation

### Correctness model

W3C Trace Context version `00` uses:

```text
00-{32 lowercase hexadecimal trace-id}-{16 lowercase hexadecimal parent-id}-{2 lowercase hexadecimal flags}
```

Trace and parent IDs cannot be all zero. Receivers match header names without
case sensitivity, senders use the lowercase `traceparent` name, and invalid
input is ignored. A participant that creates an outbound client operation keeps
the inbound trace ID and writes the new client span ID as the outbound parent
ID. Valid `tracestate` is propagated with its order and value preserved unless
the participant makes a permitted update. `tracestate` without a valid
`traceparent` is discarded. See the [W3C Trace Context Recommendation](https://www.w3.org/TR/trace-context/).

An application-provided valid outbound header is authoritative. E-Navigator
must observe it and suppress duplicate injection and duplicate client-span
generation. It must never append a second `traceparent` header or overwrite a
valid application decision.

For a missing or invalid outbound context, injection requires all of the
following:

1. discover the correct inbound execution context for this logical request;
2. create one client operation with an unpredictable trace or span ID as
   appropriate;
3. retain that operation through transport send and response completion;
4. inject the exact W3C carrier before the request is committed to the wire; and
5. export a client span whose ID is exactly the outbound parent ID.

Formatting a header without the matching operation lifecycle creates a header
but not a correct trace. The OpenTelemetry propagator model places context in a
carrier, while the tracing API defines the span lifecycle. See the
[OpenTelemetry Propagators API](https://opentelemetry.io/docs/specs/otel/context/api-propagators/)
and [OpenTelemetry Trace API](https://opentelemetry.io/docs/specs/otel/trace/api/).

Generate wire IDs with the operating system cryptographic random source. Do not
reuse deterministic local-correlation hashes for `traceparent`. Do not inject
W3C Baggage in the first scope because it has separate privacy, trust, and size
requirements.

### Execution-context association

A process and thread identifier is not a universal causal context key. A single
thread can interleave many async requests, and an HTTP/2 connection can carry
many concurrent streams. A process-wide current trace risks attaching one
tenant's context to another tenant's outbound request.

Correct association therefore needs bounded, versioned runtime integrations,
for example Go goroutines, Node async resources, Java tasks, or Python asyncio
tasks. Each integration must publish its architecture, runtime versions, ABI or
symbol assumptions, attach probes, detach behavior, and known concurrency
limits. If E-Navigator cannot prove the current logical context, it must not
inject. It may still export the observed local span with a propagation-miss
reason.

The official OpenTelemetry eBPF Instrumentation documentation reaches the same
boundary. Its distributed tracing support uses different mechanisms for
network, Go, Node.js, Java, Python, Ruby, and NGINX, and documents async and
multiplexing limitations. See [OBI distributed traces](https://opentelemetry.io/docs/zero-code/obi/distributed-traces/)
and [OBI context propagation](https://opentelemetry.io/docs/zero-code/obi/context-propagation/).
That implementation is useful feasibility evidence, not a compatibility
contract for E-Navigator.

### Preferred cleartext HTTP/1 socket-message insertion

Linux provides a materially safer cleartext TCP mutation point than TC. A
`BPF_PROG_TYPE_SOCK_OPS` program attached to the workload cgroup can insert
newly established TCP sockets into a bounded `BPF_MAP_TYPE_SOCKHASH`. A
`BPF_PROG_TYPE_SK_MSG` verdict program attached to that map then runs on the
socket's outbound message path. `bpf_msg_cork_bytes` can accumulate a bounded
prefix across writes, `bpf_msg_pull_data` can make a bounded range directly
readable, and `bpf_msg_push_data` can insert bytes into the socket message.

This path avoids E-Navigator translating TCP sequence numbers, acknowledgement
numbers, SACK blocks, retransmissions, or checksums. In the kernel's current
TCP implementation, the modified `sk_msg` is passed by `tcp_bpf_push` to
`tcp_sendmsg_locked`, so the TCP stack packetizes and accounts for the added
bytes as part of the original outgoing stream. See the
[Linux SOCKMAP and SOCKHASH documentation](https://docs.kernel.org/bpf/map_sockmap.html)
and the current [`tcp_bpf.c` send path](https://github.com/torvalds/linux/blob/master/net/ipv4/tcp_bpf.c).

This is a transport-mutation improvement, not a complete propagation solution.
It does not discover the correct logical trace context, create the matching
client span, parse all HTTP/1 message boundaries, or cover sockets that never
enter the map.

#### Call and socket coverage

The verdict runs only for sockets that are successfully inserted into the
SOCKHASH and inherit the map's `BPF_SK_MSG_VERDICT` program. The natural
population points are `BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB` and
`BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB`. E-Navigator should map only the active
client side for request injection. Mapping passive server sockets would also
run the program on HTTP responses and requires a separate, explicit use case.
The kernel UAPI defines these callbacks after the active or passive three-way
handshake completes. See [`struct bpf_sock_ops` and its operation definitions](https://github.com/torvalds/linux/blob/master/include/uapi/linux/bpf.h).

The practical coverage is:

| Path | Coverage and limit |
| --- | --- |
| `write` and `writev` on a normal TCP socket | Covered when they reach the socket write iterator and the TCP `sendmsg` protocol operation; current `net/socket.c` routes `sock_write_iter` through `__sock_sendmsg` |
| `send`, `sendto`, `sendmsg`, and `sendmmsg` | Covered when they use the mapped socket's TCP `sendmsg` operation |
| `sendfile` and splice-backed sends | The kernel SOCKMAP contract includes `sendfile`, but direct data starts as an empty range for shared splice pages and `bpf_msg_pull_data` may have to copy it |
| `io_uring` and zero-copy variants | Do not claim until each operation is live-tested on the supported kernel; paths or flags that bypass or materially alter the normal protocol `sendmsg` path are outside the default claim |
| Connections established before the cgroup program and map are ready | Not covered; they do not replay the established callback and can remain unmodified for the life of a pool connection |
| TCP Fast Open request data in the SYN | Not covered because map insertion happens after the established callback |
| Sockets outside the attached cgroup subtree | Not covered |
| User-space TCP stacks, DPDK, AF_XDP, raw sockets, UDP, QUIC, and unsupported protocol operations | Not covered |

The ordinary `write` route is visible in the current
[`net/socket.c` implementation](https://github.com/torvalds/linux/blob/master/net/socket.c).
The kernel SOCKMAP documentation states that `bpf_msg_apply_bytes` and
`bpf_msg_cork_bytes` operate across `sendmsg` and `sendfile` calls, and that
splice-backed data can require `bpf_msg_pull_data` to copy a directly readable
range.

The hook sees data at the TCP socket boundary. For ordinary userspace TLS this
is already ciphertext. It does not see HTTP plaintext. Current upstream kTLS
also explicitly makes TLS and SOCKMAP mutually exclusive: configuring TLS
rejects a socket that already has a psock, and psock initialization rejects an
existing TLS socket. See the current
[`tls_main.c` exclusion](https://github.com/torvalds/linux/blob/master/net/tls/tls_main.c).
Therefore this design supports cleartext TCP only and provides no HTTPS
coverage.

`SK_MSG` is an egress message verdict. It does not provide symmetric ingress
stream mutation. The `BPF_F_INGRESS` flag accepted by socket-map redirection
helpers selects a redirect destination; it does not turn this verdict into an
ingress HTTP-header editing hook.

For accepted messages, adding carrier bytes does not change the application's
successful byte count. The current `tcp_bpf_sendmsg` implementation increments
its return counter only for bytes consumed from the original user iterator,
while `tcp_bpf_push` loops until the enlarged message segments are passed to the
TCP send path. Backpressure, partial lower-level writes, interruption, and error
returns still require integration tests on every supported kernel.

#### Fragmented HTTP headers

`SK_MSG` removes packet segmentation from the problem, but it does not remove
application write fragmentation. A request line or header block can span
multiple `write` or `sendmsg` calls, and one call can contain a body plus the
start of the next pipelined request.

The safest first implementation should not cork across calls. It should inject
only when one current `sk_msg` contains one complete, bounded HTTP/1 request
header and the insertion offset is proved. A fragmented or oversized header
passes unchanged and increments a bounded `fragmented_header` or
`header_too_large` reason counter. This deliberately trades coverage for
failure isolation and avoids holding application writes while waiting for a
delimiter. The published support matrix must not describe split-header calls as
covered.

`bpf_msg_cork_bytes` can defer the verdict until a requested byte count has
accumulated across calls. It cannot express an unbounded "wait until CRLF CRLF"
condition. The program must iteratively inspect bounded chunks up to a fixed
maximum header size. `bpf_msg_pull_data` may be needed because direct access is
normally limited to the first scatterlist element. Both corking and pulling
change latency, memory use, and zero-copy behavior, so their limits must be
native configuration with self-metrics. Cross-call corking is therefore a
possible later qualification cell, not part of the recommended first scope.

A correct per-socket state machine must cover:

- a request line and header terminator split at every byte boundary;
- duplicate and case-insensitive `traceparent` detection before mutation;
- `Content-Length`, chunked bodies, no-body requests, and exact body skipping;
- keep-alive and multiple requests in one write;
- pipelining and a partial next request;
- `Expect: 100-continue`;
- CONNECT, `Upgrade: websocket`, h2c, the HTTP/2 connection preface, and other
  protocol upgrades, which permanently move the socket into a bypass state;
- bounded method, target, header count, header bytes, and buffered bytes; and
- close, half-close, reset, parser error, and idle-state cleanup.

When the bounded parser cannot prove one complete HTTP/1 header, it must pass
the original bytes unchanged. A future, separately qualified corking mode may
continue a bounded cork. At the configured maximum it must disable injection
for that request or socket and emit a bounded reason code. It must never guess
an insertion offset or resume HTTP/1 parsing after a tunnel or upgrade.

`bpf_msg_apply_bytes` is needed to delimit how many post-mutation bytes a
verdict covers before the program runs again. Its value must account for the
inserted carrier bytes. This is especially important when one system call
contains multiple requests. The exact interaction must be integration-tested,
not inferred from one-request examples.

#### Mutation transaction

`bpf_msg_push_data` inserts bytes in the `sk_msg` scatterlist and can fail under
memory pressure. Its flags argument must be zero. The helper can split or copy
scatterlist entries and invalidates previously verified direct-data pointers.
The program must reload pointers, obtain a directly writable inserted range,
and prove bounds again before writing.

All fallible parsing, context lookup, ID selection, carrier formatting, and
duplicate checks must happen before `bpf_msg_push_data`. If the push fails,
return `SK_PASS` with the original message unchanged. After a successful push,
reload the invalidated data pointers, prove the inserted range again, overwrite
every inserted byte with fixed-size verifier-checked stores, and perform no
further fallible helper call. The current kernel helper allocates a new page and
does not make partial carrier initialization safe. The first implementation
must not depend on `bpf_msg_pop_data` rollback: rollback is itself fallible and
cannot restore a general fail-open guarantee. If the complete post-push store
sequence cannot be proved, do not enable mutation on that kernel.

Even with that transaction shape, SOCKHASH attachment cannot promise strict
failure transparency under all memory pressure. Mapped sends require `sk_msg`
allocation before the verdict. A future use of `bpf_msg_cork_bytes` adds another
allocation; current `tcp_bpf_send_verdict` returns `ENOMEM` and frees the
message when the socket cork cannot be allocated rather than passing the
original bytes. This is a kernel-path availability risk introduced by the
feature, so active propagation must remain opt-in and must have allocation
stress and fault-injection qualification.

The helper implementation and pointer recomputation are visible in current
[`net/core/filter.c`](https://github.com/torvalds/linux/blob/master/net/core/filter.c).
The program must use fixed-size, verifier-proved stores for the complete
formatted carrier and must not log the carrier value.

#### Map bounds and coexistence

SOCKHASH is bounded by `max_entries`; it is not an LRU map. Current kernel code
returns `E2BIG` when a new entry would exceed the limit. E-Navigator should use
a socket cookie as the key, `BPF_NOEXIST` for insertion, and socket-local BPF
storage for bounded HTTP parser state. It must not evict an arbitrary live
socket because eviction can remove propagation halfway through a keep-alive
connection.

When the map is full or insertion fails, the socket has no message verdict and
continues unmodified. Increment bounded `socket_map_full`, `socket_map_conflict`,
and `socket_map_insert_failed` self-metrics. Socket close removes its map link,
but close cleanup, agent shutdown, and stale-state behavior still require live
tests. The capacity and update behavior are implemented in current
[`net/core/sock_map.c`](https://github.com/torvalds/linux/blob/master/net/core/sock_map.c).

A socket may be referenced by multiple socket maps, but it can inherit only one
message parser or verdict program. The kernel returns `EBUSY` for conflicting
program ownership. E-Navigator must detect the conflict and leave the socket
unchanged. It must not replace another agent's or policy engine's socket
program.

#### Kernel, attachment, and privilege floor

The combined API first becomes possible in Linux 4.20:

- SOCKHASH was introduced in Linux 4.18, according to the kernel map
  documentation;
- `BPF_PROG_TYPE_SK_MSG` and `BPF_SK_MSG_VERDICT` predate SOCKHASH; and
- `bpf_msg_push_data` was merged by
  [commit `6fff607e2f14`](https://github.com/torvalds/linux/commit/6fff607e2f14bd7c63c06c464a6f93b8efbabe28)
  for Linux 4.20.

Linux 4.20 is an API-availability floor, not a production support claim. The
helper has received correctness fixes long after introduction. In particular,
[commit `f72eed9b84fb`](https://github.com/torvalds/linux/commit/f72eed9b84fb771019a955908132410a9ba9ea3f)
fixes the tail-fragment offset when insertion occurs in a non-first scatterlist
entry. E-Navigator must require that fix or a verified distribution backport
for any helper pattern that can insert there. It must also run upstream-style
push, pull, pop, cork, and scatterlist regression tests on the exact deployed
kernel. The existing Linux 6.6.68 homelab must not be assumed to contain a 2026
fix merely because its major and minor version exceed 4.20.

Required kernel facilities are `CONFIG_BPF`, `CONFIG_BPF_SYSCALL`,
`CONFIG_CGROUPS`, `CONFIG_CGROUP_BPF`, `CONFIG_BPF_STREAM_PARSER`, TCP/INET, a
mounted and reachable cgroup v2 hierarchy, SOCKHASH,
`BPF_PROG_TYPE_SOCK_OPS`, `BPF_PROG_TYPE_SK_MSG`, and every message helper used
by the selected parser. `CONFIG_BPF_STREAM_PARSER` selects
`CONFIG_NET_SOCK_MSG`; startup must still feature-probe the actual map, program,
attach, and helper operations and disable active mutation if any probe fails.
See the current [Linux networking BPF configuration](https://github.com/torvalds/linux/blob/master/net/Kconfig).

Attach the SK_MSG verdict to the SOCKHASH first, then attach the SOCK_OPS
program to the intended cgroup subtree. This ordering ensures newly inserted
sockets inherit the intended verdict. Shutdown must stop new insertions,
disable mutation through a generation/configuration gate, drain or remove map
entries, and only then detach the verdict.

On modern kernels the loader requires `CAP_BPF` and `CAP_NET_ADMIN`; current
kernel code classifies SOCKHASH creation, SK_MSG, and SOCK_OPS as network-admin
BPF operations. Older kernels use the broader `CAP_SYS_ADMIN` model. See the
current [BPF syscall capability checks](https://github.com/torvalds/linux/blob/master/kernel/bpf/syscall.c)
and [capabilities(7)](https://man7.org/linux/man-pages/man7/capabilities.7.html).
This path does not require a TC qdisc or `hostNetwork`, but it is still outside
E-Navigator's reduced profile because that profile does not grant
`CAP_NET_ADMIN`. It needs a separate opt-in security profile and an ADR.

### TC packet insertion fallback

Cleartext HTTP/1 header injection at TC is possible only as a stateful TCP stream
translator. Requests can span packets, persistent connections can carry many
requests, and pipelining permits several outstanding requests. HTTP message
framing requirements are defined in [RFC 9112](https://www.rfc-editor.org/rfc/rfc9112.html).

Inserting `traceparent: ...\r\n` changes the TCP byte stream. A correct translator
must handle:

- request headers split across segments;
- sequence-number translation for all later client packets;
- reverse ACK-number translation;
- retransmission without reinserting or shifting twice;
- SACK edge translation;
- FIN sequence position and RST cleanup;
- sequence-number wraparound;
- IPv4 and IPv6 length and checksum handling;
- cloned and nonlinear socket buffers;
- GSO, GRO, and checksum-offload metadata;
- IP fragmentation;
- keep-alive and pipelined requests;
- bounded idle timeout and map eviction; and
- coexistence with CNI and other TC programs.

TCP sequence and acknowledgement rules and the mandatory checksum are defined
by [RFC 9293](https://www.rfc-editor.org/rfc/rfc9293.html). SACK block edges are
sequence numbers, as specified by [RFC 2018](https://www.rfc-editor.org/rfc/rfc2018.html).
Linux documents checksum and segmentation behavior in
[Checksum Offloads](https://docs.kernel.org/networking/checksum-offloads.html)
and [Segmentation Offloads](https://docs.kernel.org/networking/segmentation-offloads.html).

The BPF packet helpers do not make this automatically safe.
`bpf_skb_adjust_room` changes room around network headers rather than providing
an arbitrary insert primitive inside every TCP payload shape. Packet mutation
invalidates prior verifier proofs for packet pointers, so the program must
reload and revalidate them. Checksum and GSO metadata must be repaired with the
correct helper flags. See [bpf-helpers(7)](https://man7.org/linux/man-pages/man7/bpf-helpers.7.html)
and the [Linux eBPF verifier](https://docs.kernel.org/bpf/verifier.html).

Mutation must be transactional from the network's perspective. If parsing,
capacity, checksum, or state lookup fails, pass the original packet unchanged.
A packet must never leave with a partial header, shifted payload without state,
or mismatched checksum.

TC attachment requires `CAP_NET_ADMIN` and a network placement that sees the
target traffic. This is outside E-Navigator's reduced capability profile and
its current default `hostNetwork: false` deployment. Active packet propagation
therefore needs an opt-in security profile and an ADR before implementation.

### HTTPS

Packet-level injection cannot add an HTTP header to TLS. TLS 1.3 application
records use authenticated encryption. Any ciphertext modification without the
session key fails authentication, as specified in [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446.html).

Socket-message insertion does not change this result. Ordinary userspace TLS
writes ciphertext to the mapped TCP socket, and current upstream kTLS and
SOCKMAP are mutually exclusive. SK_MSG is therefore not a pre-encryption HTTPS
hook.

A custom TCP option or side-channel context is agent-to-agent metadata, not a
W3C HTTP `traceparent`. It disappears at common L7 proxies, is not understood by
ordinary instrumented services, and cannot satisfy the standalone
interoperability requirement.

Standards-compatible HTTPS injection must occur before encryption at a
runtime or HTTP-library boundary. Existing SSL and Go TLS plaintext probes show
that observation is possible, but observation does not provide spare writable
capacity or safe ownership of the request buffer. A supported integration must
mutate the library's header model before serialization or use a documented,
preallocated carrier slot.

### Process-memory mutation

`bpf_probe_write_user` can attempt to write only the current task's userspace
memory. The kernel describes it as experimental and intended for prototypes,
warns when programs using it are loaded, and notes that it can crash the target
process. It cannot allocate or safely grow an arbitrary header buffer. See the
[Linux BPF design Q&A](https://docs.kernel.org/bpf/bpf_design_QA.html)
and [bpf-helpers(7)](https://man7.org/linux/man-pages/man7/bpf-helpers.7.html).

It is not an acceptable generic production foundation. A narrowly supported
integration could use it only when all of these conditions hold:

- exact runtime, library, version, architecture, and structure layout match;
- the mutation targets existing, owned, preallocated storage;
- probe attachment is transactional and fail closed;
- kernel lockdown and capabilities are preflighted;
- concurrent reuse and lifetime are proved;
- native success, suppression, layout-mismatch, and failure counters exist; and
- live tests prove application stability and correct context under load.

Unsupported versions must remain unmodified. A best-effort write to an inferred
address is a process-corruption bug, not graceful degradation.

### HTTP/2 and gRPC

HTTP/2 multiplexes concurrent streams. Header blocks can span HEADERS and
CONTINUATION frames, and no other frame may interleave before the block is
complete. HPACK also maintains connection-level compression state. See
[RFC 9113](https://www.rfc-editor.org/rfc/rfc9113.html) and
[RFC 7541](https://www.rfc-editor.org/rfc/rfc7541.html).

A safe injector must operate per stream, reconstruct a complete header block,
respect peer frame-size and header-list limits, update frame lengths, and
preserve compression state. A literal field without indexing can avoid changing
the dynamic table, but it does not remove the frame, HPACK, TLS, or concurrency
requirements. SK_MSG can leave TCP packetization to the kernel for cleartext
HTTP/2, but it still needs a per-stream frame and compression state machine.
Generic ASCII insertion is invalid. gRPC and generic HTTP/2 should be separate
qualification cells.

### HTTP/3 and QUIC

HTTP/3 uses QUIC and integrates TLS 1.3 protection. It is outside the current
TCP-centric source architecture and must remain an explicit nonclaim. See
[RFC 9114](https://www.rfc-editor.org/rfc/rfc9114.html).

### Security and privacy

Propagated context crosses trust boundaries. The W3C security and privacy model
requires opaque identifiers, protects against invalid values, and warns that
sampling flags are attacker-controlled input. E-Navigator must:

- generate random IDs without host, process, user, or tenant information;
- validate exact lengths, hexadecimal form, version, forbidden zero values, and
  maximum `tracestate` limits;
- never treat the sampled bit as authorization;
- bound all carrier parsing and state maps;
- redact carrier contents from logs and self-metrics;
- preserve an application-provided valid context; and
- expose only bounded reason codes for injection decisions.

## Recommended Delivery Order

1. Implement the peer-aware metric independently, including directional signal
   preservation, post-attribution aggregation, overflow accounting, sink
   projections, documentation, and Kubernetes runtime proof.
2. Add a propagation ADR that fixes trust boundaries, security profile, causal
   context model, carrier ownership, native configuration, and the per-transport
   compatibility matrix.
3. Implement and fuzz a pure Rust W3C parser, validator, formatter, and policy
   layer. This is shared logic, not proof of transport injection.
4. Implement causal client-operation association separately from carrier
   mutation. Unsupported runtimes must report a bounded miss and skip injection.
5. Implement the first cleartext HTTP/1 carrier using SOCK_OPS, a bounded
   SOCKHASH, and SK_MSG. Qualify exact syscall, cgroup, kernel, helper-fix, and
   HTTP framing coverage. Keep TC as a separate fallback only if broader socket
   coverage justifies its TCP translator and deployment cost.
6. Treat gRPC and generic HTTP/2 as separate HPACK-aware work.
7. Treat HTTPS as separate, versioned pre-TLS runtime/library integrations.
8. Keep active injection disabled by default until the exact kernel, runtime,
   transport, and deployment cell passes live qualification.

This ordering preserves the standalone boundary. E-Navigator should implement
native contracts and standard W3C and OpenTelemetry interoperability, without
vendor configuration aliases, custom compatibility modes, or an agent-only
side channel presented as W3C propagation.

## Propagation Acceptance Evidence

Pure Rust tests:

- W3C official valid and invalid vectors;
- version `00`, forbidden zero IDs, flags, duplicate headers, and case handling;
- `tracestate` member, length, ordering, and invalid-without-parent rules;
- random ID nonzero and uniqueness checks without brittle entropy claims;
- existing valid application context preservation;
- invalid context restart and stray `tracestate` discard;
- exact client span ID to outbound parent-ID equality;
- bounded state, timeout, eviction, and reason-code behavior;
- parser fuzzing and property tests over arbitrary carrier bytes; and
- concurrency tests that prevent context crossing between logical requests.

Privileged SK_MSG cleartext HTTP/1 Linux tests:

- feature probing and verifier loading on every supported kernel build;
- SOCK_OPS attachment to the exact cgroup subtree and exclusion outside it;
- active client mapping, passive server non-mapping, and IPv4 and IPv6;
- connections created before and after attach, pooled connections, TCP Fast
  Open, and deterministic nonclaims for uncovered sockets;
- `write`, `writev`, `send`, `sendmsg`, `sendmmsg`, `sendfile`, splice,
  supported `io_uring` operations, and explicit nonclaims for paths not proved;
- complete bounded headers at every insertion and scatterlist boundary;
- request lines and headers split at every write boundary, proving unchanged,
  nonblocking bypass in the initial no-cork implementation;
- `bpf_msg_pull_data` and `bpf_msg_push_data` under bounded allocation and
  helper failures, with no post-push helper or rollback dependency;
- separate future qualification for `bpf_msg_cork_bytes`, including cork
  allocation failure and cross-call latency, before any corking mode is enabled;
- insertion at the first, middle, non-first scatterlist, and message-end
  positions, including the regression fixed by `f72eed9b84fb`;
- complete overwrite of every inserted byte and no kernel-memory disclosure;
- exact application syscall return values before and after insertion;
- memory-pressure and fault-injection proof, including documented `ENOMEM`
  behavior rather than an absolute fail-open claim;
- duplicate context preservation, exact body preservation, keep-alive,
  pipelining, chunked and fixed bodies, and protocol upgrades;
- SOCKHASH saturation, key collision, `EBUSY` program conflict, socket close,
  agent restart, attach rollback, and ordered detach;
- memory, latency, throughput, and zero-copy impact with and without cork and
  pull helpers;
- packet capture confirming that ordinary TCP produces valid sequence,
  acknowledgement, retransmission, SACK, segmentation, and checksums without an
  E-Navigator translation map; and
- standard W3C server proof of exactly one valid header plus exact Tempo
  parent-child topology.

If the TC fallback is selected, its privileged cleartext HTTP/1 tests are:

- headers wholly in one segment and split at every insertion boundary;
- keep-alive, pipelining, chunked and fixed bodies, and body preservation;
- IPv4, IPv6, SACK on and off, sequence wraparound, FIN, and RST;
- loss, duplication, reordering, and retransmission using `tc netem`;
- GSO, GRO, and checksum offload combinations;
- map saturation, timeout, process exit, attach rollback, and detach;
- interaction with the supported CNI chain;
- packet capture proving exact sequence, ACK, SACK, and checksum translation;
- server proof of exactly one valid header and an unchanged request body; and
- load proof with no additional resets, checksum failures, or application
  crashes.

Runtime or library integration tests:

- every supported version and architecture in the published matrix;
- concurrent requests, nested async work, connection pools, and reuse;
- proxy and load-balancer boundaries;
- application-provided context and mixed instrumented/uninstrumented traffic;
- layout mismatch, missing symbols, kernel lockdown, and privilege failure;
- HTTPS proof captured before encryption and observed by a standard W3C server;
  and
- exact trace topology in Tempo, not merely matching trace IDs.

No capability row should move to positively proved based only on unit tests,
parser tests, or a macOS build. Active eBPF mutation requires a capable Linux
host, and Kubernetes deployment claims require cluster evidence from the exact
artifact under review.

## Primary Sources

- [W3C Trace Context Recommendation](https://www.w3.org/TR/trace-context/)
- [OpenTelemetry Metrics Data Model](https://opentelemetry.io/docs/specs/otel/metrics/data-model/)
- [OpenTelemetry metric cardinality limits](https://opentelemetry.io/docs/specs/otel/metrics/sdk/#cardinality-limits)
- [OpenTelemetry Kubernetes resource conventions](https://opentelemetry.io/docs/specs/semconv/resource/k8s/)
- [OpenTelemetry semantic convention naming](https://opentelemetry.io/docs/specs/semconv/general/naming/)
- [OpenTelemetry Propagators API](https://opentelemetry.io/docs/specs/otel/context/api-propagators/)
- [OpenTelemetry eBPF Instrumentation distributed traces](https://opentelemetry.io/docs/zero-code/obi/distributed-traces/)
- [OpenTelemetry eBPF Instrumentation context propagation](https://opentelemetry.io/docs/zero-code/obi/context-propagation/)
- [Prometheus metric and label naming](https://prometheus.io/docs/practices/naming/)
- [Linux BPF design Q&A](https://docs.kernel.org/bpf/bpf_design_QA.html)
- [Linux eBPF verifier](https://docs.kernel.org/bpf/verifier.html)
- [Linux BPF hash and LRU maps](https://docs.kernel.org/bpf/map_hash.html)
- [Linux SOCKMAP and SOCKHASH](https://docs.kernel.org/bpf/map_sockmap.html)
- [Linux TCP BPF send path](https://github.com/torvalds/linux/blob/master/net/ipv4/tcp_bpf.c)
- [Linux socket syscall send path](https://github.com/torvalds/linux/blob/master/net/socket.c)
- [Linux socket-map implementation](https://github.com/torvalds/linux/blob/master/net/core/sock_map.c)
- [Linux SK_MSG mutation helpers](https://github.com/torvalds/linux/blob/master/net/core/filter.c)
- [Linux kTLS and SOCKMAP exclusion](https://github.com/torvalds/linux/blob/master/net/tls/tls_main.c)
- [Linux BPF privilege checks](https://github.com/torvalds/linux/blob/master/kernel/bpf/syscall.c)
- [Linux networking BPF configuration](https://github.com/torvalds/linux/blob/master/net/Kconfig)
- [Linux sockmap selftest](https://github.com/torvalds/linux/blob/master/tools/testing/selftests/bpf/progs/test_sockmap_kern.h)
- [Linux io_uring networking paths](https://github.com/torvalds/linux/blob/master/io_uring/net.c)
- [Linux `bpf_msg_push_data` introduction](https://github.com/torvalds/linux/commit/6fff607e2f14bd7c63c06c464a6f93b8efbabe28)
- [Linux non-first scatterlist insertion fix](https://github.com/torvalds/linux/commit/f72eed9b84fb771019a955908132410a9ba9ea3f)
- [Linux kTLS and SOCKMAP mutual-exclusion commit](https://linux.googlesource.com/linux/kernel/git/torvalds/linux/+/79511603a65b990bed675eb4bcfd85305d3ff42a)
- [Linux checksum offloads](https://docs.kernel.org/networking/checksum-offloads.html)
- [Linux segmentation offloads](https://docs.kernel.org/networking/segmentation-offloads.html)
- [Linux bpf-helpers(7)](https://man7.org/linux/man-pages/man7/bpf-helpers.7.html)
- [RFC 9293, Transmission Control Protocol](https://www.rfc-editor.org/rfc/rfc9293.html)
- [RFC 2018, TCP Selective Acknowledgment Options](https://www.rfc-editor.org/rfc/rfc2018.html)
- [RFC 9112, HTTP/1.1](https://www.rfc-editor.org/rfc/rfc9112.html)
- [RFC 9113, HTTP/2](https://www.rfc-editor.org/rfc/rfc9113.html)
- [RFC 7541, HPACK](https://www.rfc-editor.org/rfc/rfc7541.html)
- [RFC 8446, TLS 1.3](https://www.rfc-editor.org/rfc/rfc8446.html)
- [RFC 9114, HTTP/3](https://www.rfc-editor.org/rfc/rfc9114.html)
- [Kubernetes Owners and Dependents](https://kubernetes.io/docs/concepts/overview/working-with-objects/owners-dependents/)
- [Kubernetes OwnerReference API](https://kubernetes.io/docs/reference/kubernetes-api/common-parameters/common-definitions/#OwnerReference)
- [Kubernetes ReplicaSet controller](https://kubernetes.io/docs/concepts/workloads/controllers/replicaset/)
