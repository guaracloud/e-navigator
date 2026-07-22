# ADR 0012: Reduced Privilege On Proven Modern Kernels

Status: accepted

Date: 2026-07-22

## Context

The compatibility chart profile grants a broad set of Linux capabilities,
including `SYS_ADMIN`. That profile was intentionally conservative while the
live Aya sources had not been exercised independently under narrower sets. It
also obscured which privileges belong to kernel program management, perf-event
attachment, and cross-process procfs inspection.

Linux split eBPF program and map operations out of `SYS_ADMIN` into `BPF` in
5.8, and split performance monitoring into `PERFMON` in the same release. The
kernel perf security guide recommends `PERFMON` instead of the broader
`SYS_ADMIN` capability. `SYS_PTRACE` governs cross-process inspection checks.
These upstream contracts are described in
[capabilities(7)](https://man7.org/linux/man-pages/man7/capabilities.7.html),
the [perf security guide](https://www.kernel.org/doc/html/v6.7/admin-guide/perf-security.html),
and the [BPF syscall documentation](https://www.kernel.org/doc/html/v6.1/userspace-api/ebpf/syscall.html).

Capabilities alone are not sufficient evidence. Kernel configuration, LSMs,
seccomp, procfs mount policy, and container runtime behavior can still reject a
program or target. The reduced set therefore needs a runtime proof on each
kernel family before it becomes an operator default.

## Decision

Add `charts/e-navigator/values-reduced-privilege.yaml` as an opt-in profile for
modern kernels. It drops every inherited capability, adds only `BPF`,
`PERFMON`, and `SYS_PTRACE`, keeps `privileged: false`, uses
`RuntimeDefault` seccomp, forbids privilege escalation, and keeps UID 0.

The compatibility profile in `values.yaml` remains unchanged for unproven
kernels. The reduced profile is runtime proven only on the two Linux 6.6.68
homelab nodes. It is not a blanket claim for every kernel newer than 5.8.

The source-specific minimums established by the proof are:

| Source or surface | Proven capability set | Reason and scope |
| --- | --- | --- |
| `source.aya_exec` | `BPF`, `PERFMON` | BPF object/map operations plus tracepoint perf-event attachment. |
| `source.aya_network` | `BPF`, `PERFMON` | BPF operations plus tracepoint and BTF fexit attachment. |
| `source.aya_dns` | `BPF`, `PERFMON` | BPF operations plus socket-path tracepoint attachment. |
| `source.aya_http` | `BPF`, `PERFMON` | BPF operations plus syscall tracepoint attachment. |
| `source.aya_protocol` | `BPF`, `PERFMON` | BPF operations plus connection and payload tracepoint attachment. |
| `source.aya_tls` | `BPF`, `PERFMON`, `SYS_PTRACE` | Adds bounded cross-process procfs discovery for uprobes. The reduced-profile runtime proof covers unstripped Go 1.26.4, not every OpenSSL or GnuTLS permission layout. |
| `source.aya_cpu_profile` | `BPF`, `PERFMON`, `SYS_PTRACE` | Adds cross-UID procfs maps, executable, symbol, and memory access for the complete symbolization path. |
| `source.host_resource` | none | Reads the already-mounted host procfs, sysfs, and cgroup views without Aya attachment. |
| Processors, generators, and sinks | none beyond their source | They consume userspace signals and do not independently load BPF or inspect another process. |

`SYS_ADMIN`, `NET_ADMIN`, `NET_RAW`, `SYS_RESOURCE`, `SYSLOG`,
`CHECKPOINT_RESTORE`, and `DAC_READ_SEARCH` are absent from every reduced proof
arm. The Linux 6.6.68 runtime loaded the bounded BPF maps without
`SYS_RESOURCE`; memory is charged through the modern BPF memory-accounting
path. The proof did not use `/proc/<pid>/map_files`, so it does not establish a
need for `CHECKPOINT_RESTORE`. It also does not establish that every
non-world-readable executable or library can be inspected without
`DAC_READ_SEARCH`; inaccessible optional TLS targets remain visible as bounded
coverage failures.

UID 0 remains part of this profile. Rootless eBPF and rootless host-filesystem
traversal are separate claims and are not promoted by this decision.

## Rejected Alternatives

Keeping `SYS_ADMIN` in the reduced profile is rejected on the proven kernel
because it defeats the purpose of the split `BPF` and `PERFMON` capability
model and grants unrelated administrative authority.

Using one capability set for every source is rejected for proof work because
it cannot show that host resources need no capabilities or that the core Aya
sources do not need `SYS_PTRACE`. The public chart profile includes
`SYS_PTRACE` so one installation can enable TLS and full cross-process CPU
symbolization, while the proof harness uses narrower overlays for each source.

Declaring the agent non-root is rejected until the full host mount, procfs,
debugfs, tracing, cgroup, optional target, and LSM matrix is independently
implemented and runtime proven.

## Evidence And Consequences

The guarded homelab campaign ran no-agent baselines and one source at a time on
two k3s v1.30.4 nodes running Linux 6.6.68. Every agent arm had two ready pods,
zero restarts, `NoNewPrivs: 1`, `Seccomp: 2`, and the exact expected effective
capability set. Workload-correlated signals were observed for exec, network,
DNS, cleartext HTTP, Redis, CPU profiling, host resources, and Go TLS. Every Aya
arm reported zero transport loss, ring-buffer reservation failure, and sink
send failure. The detailed counts and candidate image digest are in
`documentation/proof/reduced-privilege-20260722/`.

Operators may opt in with the reduced values file after proving their target
kernel and policy environment. Unsupported or inaccessible optional targets
must remain loud and fail closed. The compatibility profile remains available;
this ADR does not silently weaken it or claim production validation.
