# ADR 0006: Dual Ring-Buffer and Perf-Buffer Event Transport

Status: accepted

Date: 2026-07-21

## Context

Every Aya source previously transferred kernel events through a per-CPU
perf-event array. BPF ring buffers provide one shared ordered queue, precise
wakeup behavior, and producer-visible reservation failures on Linux 5.8 and
newer. E-Navigator still supports older kernels, so adopting the newer map type
cannot make the existing perf transport unloadable.

A single eBPF object containing both map types does not provide a safe fallback.
The kernel creates every declared map while loading the object; an older kernel
rejects the ring-buffer map before any userspace or eBPF branch can select the
perf path. Runtime branching inside one object was therefore rejected.

## Decision

Build and embed two eBPF objects from the same source package. The
`ring-buffer` feature produces an object in which all nine event maps are BPF
ring buffers. The `perf-buffer` feature produces the legacy per-CPU perf-event
arrays. Exactly one feature must be enabled for an eBPF build.

The `[ebpf]` runtime config exposes three strict modes:

- `auto` probes `BPF_MAP_TYPE_RINGBUF`, selects the ring object when supported,
  and selects the perf object only when the probe positively reports that the
  map type is unsupported.
- `ring_buffer` requires successful ring-buffer support and otherwise fails the
  source startup.
- `perf_buffer` selects the legacy object without probing. It is retained for
  old kernels and controlled A/B measurements.

An unexpected probe error fails source startup. It is not treated as evidence
that the map type is unsupported. This prevents permission, seccomp, or other
runtime failures from silently changing the requested transport.

The configured ring capacity is a bounded power of two from 4 KiB through
16 MiB and must be a multiple of the runtime kernel page size. Each source load
shrinks unrelated event rings to one page. Ring output uses the copy-based
`bpf_ringbuf_output` migration path because existing events are already built
in bounded per-CPU scratch maps. Reserve and submit would require rewriting
every producer before comparative proof establishes that the extra complexity
is useful.

Perf losses continue to use Aya's lost-record notifications. Ring output
failures increment a fixed nine-slot per-CPU kernel map, and userspace polls the
slots owned by each source. Native telemetry exposes the active transport,
aggregate transport losses, legacy perf losses, and ring reservation failures.

The raw event ABI is identical between transports. Existing raw-event fuzz
targets therefore exercise both reader paths after transport framing is
removed, and no new byte parser was introduced. Transport selection has only
three modes and three probe outcomes; unit tests enumerate the meaningful
matrix, so property generation would add repetitions without a larger state
space. Criterion retains the perf inline-copy benchmark and adds the borrowed
ring-record handoff benchmark. Runtime claims still require the homelab A/B
evidence bundle.

## Consequences

- Kernels with ring-buffer support use one shared-across-CPU ordered queue for
  each retained event map instead of one reader and buffer per CPU.
- Old kernels never load an object containing a ring-buffer map.
- Ring reservation failures are observable even though the userspace ring
  reader receives no lost-record notification.
- Shipping two eBPF objects increases the userspace binary size.
- The ring-buffer fast path still copies from eBPF scratch storage. A future
  reserve-and-submit conversion needs verifier proof and measured benefit.
- Forced `perf_buffer` remains a supported diagnostic control, not the default
  on capable kernels.
