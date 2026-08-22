# TCP Message-Batch Accounting Proof - 2026-08-22

## Claim

E-Navigator accounts application bytes for TCP `sendmmsg(2)` and
`recvmmsg(2)` calls made through a native LP64 syscall ABI on x86-64 or arm64.
It sums the kernel-written `mmsghdr.msg_len` fields for at most 16 successfully
completed messages. It does not interpret the syscall return value, which is a
message count, as a byte count.

Calls from a compat ABI, batches with more than 16 completed messages, and
user-memory read failures are omitted and increment the bounded unsupported
counter. `e_navigator_ebpf_source_network_mmsg_accounted_batches_total` and
`e_navigator_ebpf_source_network_mmsg_unsupported_batches_total` expose the two
outcomes without adding workload-derived labels.

## Local runtime proof

The release eBPF object was built in Docker, verifier-loaded, and attached in a
privileged container on arm64 OrbStack Linux kernel
`7.0.11-orbstack-00360-gc9bc4d96ac70`. The fixture sent two messages of 107 and
109 bytes with `sendmmsg` and received one 211-byte message with `recvmmsg`, in
addition to the existing scalar, vectored, `sendfile`, and bidirectional
`splice` operations.

The guarded smoke completed with:

```text
network-io-workload-ok sent=599 received=563
Aya network I/O smoke passed: vectored/message-batch/zero-copy and active snapshot totals
```

Both the periodic active snapshot and final close event matched the exact
cumulative totals. The same fixture independently completed in the pinned
`python:3.13-slim-bookworm` container.

## Remaining boundary

This proof does not cover compat processes, batches above the traversal bound,
other architectures or kernels, UDP accounting, packet-byte semantics,
pre-attachment history, or general io_uring submission/completion correlation.
