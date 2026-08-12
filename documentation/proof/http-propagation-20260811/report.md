# Opt-in HTTP/1 context propagation qualification - 2026-08-11

## Scope

This local qualification covers E-Navigator's disabled-by-default propagation
path for one complete plaintext HTTP/1 request carried by an allowlisted TCP
socket. The qualified request may include a bounded `Content-Length` body in
the same syscall and may be written through one scalar buffer or at most three
fixed iovecs of at most 96 bytes each.

The path preserves application-owned `traceparent`, refuses orphan
`tracestate`, continues a valid inbound wire parent through a same-thread
synchronous downstream call, creates distinct server and client child span
identities, and forwards a valid combined W3C `tracestate`. Before mutation it
compares the live `SK_MSG` bytes with the exact syscall bytes captured by the
planner. After `bpf_msg_push_data`, it linearizes only the inserted range with
`bpf_msg_pull_data`, reloads every direct-access pointer, proves every bound,
and drops rather than transmit uninitialized inserted bytes if the post-push
proof fails.

## Executed evidence

Environment:

- implementation commit
  `fd266f2d135eed248e3adc3baa9ee6163f4bafc7`;
- release container image
  `sha256:5ef53614ca0c5290202dd7dc869a7bb3929947ce591590621df83db2a02657bf`;
- OrbStack kernel `7.0.11-orbstack-00360-gc9bc4d96ac70`; and
- Linux `aarch64`.

`tests/smoke_aya_http_propagation_linux.sh` started the release image in a
privileged disposable container and enabled propagation only for two local
plaintext ports. The kernel verifier accepted the release eBPF object, and the
loader attached the `SOCK_OPS` program to the cgroup v2 root and the `SK_MSG`
program to the bounded socket hash before reporting source readiness.

The external Python workload sent an inbound request containing a valid remote
`traceparent` and two-member `tracestate`. The proxy accepted that request and,
on the same thread, used a three-iovec `sendmsg` for a downstream `POST` whose
four-byte body was present in the third iovec. The downstream wire capture
proved all of the following:

- exactly one `traceparent` field was present;
- its trace ID and sampled flag matched the inbound parent;
- its span ID was nonzero and differed from the inbound parent span ID;
- exactly one `tracestate` field preserved the original members, values, and
  order; and
- the request body remained exactly `data`.

The same final image also passed `tests/smoke_docker.sh` and the independent
network-I/O smoke, which retained exact active-snapshot and close totals of
383 sent bytes and 352 received bytes.

## Safety and support boundary

This is a deliberately narrow mutation contract, not universal transparent
propagation. It does not claim TLS ciphertext mutation, HTTP/2 or gRPC stream
and HPACK state, HTTP/3 or QUIC state, segmented header reassembly, chunked
bodies, pipelined or trailing messages, more or larger iovecs, sockets
established before attachment, async task continuation, other kernels, load or
map-saturation behavior, multi-hop backend trace-tree correctness, or
production readiness. Every unsupported or ambiguous case bypasses injection;
diagnostic counters distinguish planning, mutation, pool, attachment, and
post-push failures.

## Reproduction

```bash
docker build -f Containerfile -t e-navigator:local .
E_NAVIGATOR_IMAGE=e-navigator:local tests/smoke_docker.sh
E_NAVIGATOR_IMAGE=e-navigator:local tests/smoke_aya_http_propagation_linux.sh
E_NAVIGATOR_IMAGE=e-navigator:local tests/smoke_aya_network_io_linux.sh
```

Compilation and this local runtime proof do not establish verifier,
attachment, protocol, workload, performance, or backend coverage outside the
listed environment and support envelope.
