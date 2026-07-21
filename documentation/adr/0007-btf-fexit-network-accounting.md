# ADR 0007: BTF fexit Network Byte Accounting

Status: accepted

Date: 2026-07-21

## Context

The network source previously accounted `read(2)` and `write(2)` bytes with
four raw syscall tracepoints: enter and exit for each syscall. The enter side
looked up the connection and populated a bounded pending-I/O map keyed by
thread; the exit side removed that entry and updated the connection. This is a
hot node-wide path even though most syscalls do not belong to tracked sockets.

Linux tracing programs can attach at a function exit and access both the
function arguments and return value. Kernel BTF provides the target metadata
needed to attach the same program across compatible kernel builds. This could
replace four tracepoint invocations and the pending-map correlation with two
direct `ksys_read` and `ksys_write` fexit programs. It also adds dependencies
on tracing-program support, readable and valid kernel BTF, target function
metadata, and a verifier-compatible target signature.

The decision had to be based on a live controlled comparison, not the expected
lower probe count. Before the run, adoption required exact byte-accounting
parity with zero reported transport loss, at least 5% more workload throughput
than tracepoints, and no more than a 2% mean-latency regression.

## Decision

Adopt BTF-backed fexit for only the network source's scalar `read(2)` and
`write(2)` byte accounting. Retain the syscall tracepoint implementation as a
strict compatibility path. Other network hooks and the DNS, HTTP, and protocol
source hooks are unchanged.

The `[ebpf] network_io_hook` control has three modes:

- `auto` first probes the kernel tracing program type, then loads kernel BTF
  and requires `FUNC` records for both `ksys_read` and `ksys_write`. It selects
  fexit only after all checks succeed. A positively unsupported tracing type,
  an absent `/sys/kernel/btf/vmlinux`, or an absent target selects tracepoints
  with a warning.
- `fexit` requires the same capability and metadata checks and fails source
  startup if any are unsupported.
- `tracepoint` selects the four syscall tracepoints without probing fexit. It
  remains available for compatibility and controlled A/B measurements.

Permission failures, malformed BTF, probe errors, unexpected loader errors,
and verifier or attachment errors fail source startup. They are not treated as
evidence that fexit is unsupported. Aya program ownership keeps attachment
transactional: if a later load or attach fails, dropping the not-yet-started
eBPF object detaches anything already attached.

Each fexit program reads the file descriptor from argument zero and the signed
return value from the slot after the three `ksys_*` arguments. The verifier and
target BTF validate the available context during program load. The path updates
the existing bounded active-connection map directly and retains saturating byte
arithmetic. It does not introduce a new map, queue, raw event layout, decoder,
or loss path.

An fentry pair was rejected for this operation. It would still require an exit
hook and the pending thread-correlation map, preserving the extra invocation
and state the change is intended to remove. CO-RE field relocations were also
rejected because these programs read scalar function arguments and no kernel
structure fields. Kernel BTF is used for target discovery and typed fexit
attachment; calling the path CO-RE would imply relocations that do not exist.

The finite selection matrix is unit-tested. Existing network raw-event tests
and fuzz targets continue to cover the unchanged event ABI. No userspace
per-event hot path was added, so a synthetic Criterion model would benchmark a
different data structure rather than the BPF maps. The guarded homelab
syscall-rate A/B is the performance benchmark for this kernel path.

## Evidence

Three counterbalanced 90-second runs per arm compared no benchmark agent,
forced tracepoints, and forced fexit on the two-node homelab. The workload used
one persistent loopback TCP connection and explicit `os.write`/`os.read` calls
with fixed 256-byte payloads. Every enabled run emitted exactly one matching
close event with byte counts equal to the workload total and reported zero
transport loss.

Fexit averaged 36,672.691 operations/s versus 33,965.449 for tracepoints, a
7.971% improvement. Mean latency averaged 25.267 microseconds versus 27.378,
a 7.710% reduction. Both predeclared performance gates passed. Against the
no-agent arm, fexit remained 7.045% lower throughput. Two-pod agent CPU was
effectively unchanged, while fexit used 34.000 MiB summed RSS versus 20.611 MiB
for tracepoints. The decision therefore applies only to this measured network
read/write path and does not claim lower total agent memory or universally
lower overhead.

The complete method and result bundle is in
`documentation/proof/kernel-hook-20260721/`.

## Consequences

- Supported BTF kernels use two direct fexit programs for tracked-socket
  `read(2)` and `write(2)` accounting.
- Compatible kernels without the required tracing or BTF surface keep the
  established tracepoint path under `auto`.
- Old-kernel fallback behavior is unit-tested but not runtime-proven because
  both homelab nodes run Linux 6.6.68 with BTF.
- The retained forced modes make future kernel and workload regressions
  measurable without changing code.
- Vectored I/O, `send*`, and `recv*` behavior is unchanged and is outside this
  measured fexit result.

## References

- Linux kernel BTF documentation: <https://docs.kernel.org/bpf/btf.html>
- Linux BPF tracing program-type documentation:
  <https://www.kernel.org/doc/html/v6.9/bpf/libbpf/program_types.html>
- Aya `Btf`: <https://docs.rs/aya/latest/aya/struct.Btf.html>
- Aya fexit macro:
  <https://docs.rs/aya-ebpf-macros/latest/aya_ebpf_macros/attr.fexit.html>
