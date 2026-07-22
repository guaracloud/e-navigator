# ADR 0011: Cgroup v1 Capture Filter Boundary

Status: accepted

Date: 2026-07-22

## Context

The capture filter joins an inode number discovered while walking the mounted
cgroup tree to the value returned by `bpf_get_current_cgroup_id()` inside each
eBPF handler. That equality is the security boundary for allow and deny
decisions. It cannot be inferred from path similarity alone.

Linux 6.6 implements `bpf_get_current_cgroup_id()` by reading
`task_dfl_cgroup(current)` and returning that cgroup's id. The kernel's cgroup
documentation defines cgroup v2 as one unified hierarchy, identifies
`cgroup.controllers` as a v2 core file, and explains that cgroup v1 can have an
arbitrary number of controller hierarchies. These contracts are recorded in
the upstream [helper implementation](https://github.com/torvalds/linux/blob/v6.6/kernel/bpf/helpers.c#L398-L411)
and [cgroup v2 documentation](https://github.com/torvalds/linux/blob/v6.6/Documentation/admin-guide/cgroup-v2.rst).

On cgroup v1, the same task may have different paths and inode ids in the cpu,
memory, pids, and other controller hierarchies. The BPF helper does not identify
which v1 controller hierarchy a userspace scanner should select. Guessing one
would let a numerically unrelated inode receive another workload's verdict.
Hybrid layouts add the same ambiguity when a configured root contains both
legacy controller mounts and a nested or direct v2 hierarchy.

## Decision

Cgroup v1 and hybrid capture filtering are permanent non-claims for the
current cgroup-id join architecture. E-Navigator supports this filter only when
the configured cgroup root is a directly mounted unified v2 hierarchy.

At controller startup, a bounded probe inspects the configured root and at
most 256 immediate children:

- `cgroup.controllers` at the root with no legacy `tasks` or
  `cgroup.clone_children` marker is `unified_v2` and is accepted;
- legacy markers without a v2 marker are `legacy_v1`;
- mixed markers, or a v2 marker only below the configured root, are `hybrid`;
- an unreadable or unrecognized root is `unavailable`.

Only `unified_v2` is compatible. When the capture filter is enabled in any
other mode, E-Navigator overrides the configured `unknown_cgroup` posture to
the kernel control word for deny, publishes an error before loading sources,
does not scan or publish potentially unrelated inode ids, and increments
`e_navigator_capture_filter_fail_closed_total`. Every Aya eBPF object receives
that control word centrally during object loading and before any program is
attached. This removes the attachment-time fail-open window as well as the
steady-state ambiguity.

The fixed-cardinality native diagnostics are:

- `e_navigator_capture_filter_cgroup_hierarchy_info{mode="..."}`;
- `e_navigator_capture_filter_cgroup_v2_compatible`;
- `e_navigator_capture_filter_fail_closed_total`.

The mode label has exactly five values: `not_checked`, `unified_v2`,
`legacy_v1`, `hybrid`, and `unavailable`.

## Rejected Alternatives

Selecting one conventional v1 controller, such as `memory` or `cpu`, is
rejected because the BPF helper is tied to the default hierarchy rather than
that selected controller. Parsing `/proc/<pid>/cgroup` does not repair the
kernel map key because it still leaves multiple valid v1 memberships and a
race between process movement and map publication.

Using container ids or pod UIDs as the in-kernel key is not available from the
current tracepoint and tracing contexts without another bounded kernel-side
identity mechanism. Adding process-id maps would introduce pid reuse and
namespace races and would not be equivalent to cgroup membership.

Treating a nested v2 mount in a hybrid tree as supported is rejected until a
future design can prove that it is the exact default hierarchy seen by the BPF
helper for every workload and can verify that contract before attachment.

## Evidence And Consequences

Unit fixtures cover unified v2, legacy v1, hybrid, and unavailable layouts and
prove that an operator-configured allow posture becomes deny for every
unsupported mode. The guarded homelab proof runs the same amd64 image and Aya
exec source against the real homelab v2 mount and a legacy marker fixture. The
real arm initialized, decoded 3,135 exec samples, and reported no fail-closed
event. The legacy fixture arm initialized the source, selected control word 2,
reported one fail-closed event, decoded and sent zero samples, and accounted
3,012 suppressed kernel events. The fixture proves the detector and forced
kernel posture on the homelab, but it is not a claim of execution on a node
booted with cgroup v1.

Operators must treat a non-unified mode as a capture outage, not partial
coverage. The appropriate remediation is to run a unified cgroup v2 node or
disable the capture filter intentionally. E-Navigator will not silently fall
back to a v1 controller hierarchy.
