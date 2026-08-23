# TCP Message-Batch Accounting Proof - updated 2026-08-23

## Claim

E-Navigator accounts application bytes for TCP `sendmmsg(2)` and
`recvmmsg(2)` calls made through a native LP64 syscall ABI on x86-64 or arm64.
It uses a verifier-bounded `bpf_loop` to sum the kernel-written
`mmsghdr.msg_len` fields for every successful entry through Linux's
1,024-entry `UIO_MAXIOV` ceiling. It does not interpret the syscall return
value, which is a message count, as a byte count.

Calls from a compat ABI, impossible out-of-contract counts, and user-memory
read failures are omitted and increment the bounded unsupported counter.
`e_navigator_ebpf_source_network_mmsg_accounted_batches_total` and
`e_navigator_ebpf_source_network_mmsg_unsupported_batches_total` expose the two
outcomes without adding workload-derived labels.

## Local runtime proof

Both release eBPF transport objects were built in Docker. The selected object
was verifier-loaded and attached in a privileged container on arm64 OrbStack
Linux kernel `7.0.11-orbstack-00360-gc9bc4d96ac70`. In addition to the existing
scalar, vectored, `sendfile`, and bidirectional `splice` operations, the
fixture ran once with 32 messages in each batch and again at the 1,024-message
Linux maximum.

The guarded smoke completed with:

```text
network-io-workload-ok sent=1423 received=1584
Aya network I/O smoke passed: vectored/message-batch/zero-copy and active snapshot totals
network-io-workload-ok sent=33663 received=39776
Aya network I/O smoke passed: vectored/message-batch/zero-copy and active snapshot totals
```

Both the periodic active snapshot and final close event matched the exact
cumulative totals. The same fixture independently completed in the pinned
`python:3.13-slim-bookworm` container.

## Remaining boundary

This proof does not cover compat processes, other architectures or kernels,
UDP accounting, packet-byte semantics, pre-attachment history, or general
io_uring submission/completion correlation.
