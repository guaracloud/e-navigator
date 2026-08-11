# Network I/O accounting qualification - 2026-08-11

## Scope

This local qualification covers application-byte accounting for TCP client
connections through scalar `read`/`write`, vectored `readv`/`writev`,
`sendto`/`recvfrom`, `sendmsg`/`recvmsg`, `sendfile`, and both directions of
`splice`. It also records why `io_uring` is not counted by pretending that the
`io_uring_enter` return value is a byte result.

The implementation keeps one bounded pending record per calling thread. A
successful syscall exit contributes its positive byte return to the tracked
connection. A socket-to-socket `splice` can update the input connection's
received bytes and the output connection's sent bytes from the same return.
Negative and zero returns do not change totals.

## Executed evidence

Environment:

- OrbStack kernel `7.0.11-orbstack-00360-gc9bc4d96ac70` on arm64;
- E-Navigator local release image manifest
  `sha256:12698a11c3f048b344bc162aa9110ca9e2d2d682d60d8cbe87b5f5c33373b29e`;
- Python `3.13.15`; and
- Node `20.20.2`, matching the major runtime used by the target Node services.

`tests/smoke_aya_network_io_linux.sh` ran the release eBPF object in a
privileged disposable container with syscall tracepoint accounting. The kernel
loaded and attached every required program. The Python workload used
`writev`, `readv`, `sendfile`, pipe-to-socket `splice`, and socket-to-pipe
`splice` on one client connection. Both a periodic active snapshot and the
final close event reported exactly:

```text
bytes_sent=383
bytes_received=352
```

`tests/qualify_node_network_io_linux.sh` traced a Node 20 `net.Socket`
request/response with corked multi-buffer writes. It observed a vectored socket
write and no `io_uring_setup`, `io_uring_enter`, or `io_uring_register` call.
The target Redis, NATS, and PostgreSQL JavaScript clients reviewed for this
qualification use Node's `net`/`tls` transport rather than a private native
socket implementation. This is representative evidence for those versions,
not a universal customer-runtime claim.

## io_uring boundary

The local kernel exposes three relevant tracepoint fragments:

- `io_uring_file_get`: request pointer and fd;
- `io_uring_submit_req`: request pointer and opcode; and
- `io_uring_complete`: request pointer and completion result.

No single stable event carries the application connection key, resolved fd,
operation direction, and completed byte count. Registered fixed files replace
the application fd with a table index, SQPOLL and worker execution can run
outside the submitting task, and multishot requests can complete more than
once. E-Navigator's current connection state is keyed by application tgid and
fd, so a tracepoint-only join would misattribute some valid io_uring modes.

Correct general support therefore requires a separately designed socket/file
identity seam (for example a qualified socket-cookie relationship), bounded
request lifetime state, fixed-file resolution, multishot completion handling,
and target-kernel tests. Until that exists, io_uring network I/O is an explicit
non-claim. The current Node 20 workload proof shows that this gap does not lose
bytes for the reviewed Guara Redis, NATS, and PostgreSQL transport path.

## Reproduction

```bash
docker build -f Containerfile -t e-navigator:local .
E_NAVIGATOR_IMAGE=e-navigator:local tests/smoke_aya_network_io_linux.sh
tests/qualify_node_network_io_linux.sh
```

Compilation and this local runtime proof do not establish verifier, attachment,
or workload coverage on other kernels, architectures, runtimes, or io_uring
users.
