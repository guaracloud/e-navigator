# Reduced Privilege Homelab Proof

Date: 2026-07-22

Result: PASS for the scoped Linux 6.6.68 homelab profile.

## Scope

The guarded campaign tested a candidate amd64 image on both homelab nodes,
never on production. The nodes ran k3s v1.30.4, containerd 1.7.20, and Linux
6.6.68. The candidate digest was
`sha256:c43f285a9229c154eabc7753c1ccb760bb52fc7697e4ccf2a913c59c543cea9c`.

The standing Argo-managed E-Navigator DaemonSet was temporarily suspended to
avoid duplicate collection. Each positive arm installed one isolated
two-pod DaemonSet, ran the same non-root workload, captured pod and process
state, scraped native metrics, uninstalled the release, and removed the
workload. The harness restored the standing application before returning.

## Command

```bash
E_NAVIGATOR_HOMELAB_CONFIRM=1 \
E_NAVIGATOR_REDUCED_PRIVILEGE_RESULTS_DIR=benchmarks/results/reduced-privilege-proof \
E_NAVIGATOR_HOMELAB_IMAGE_REPOSITORY=docker.io/library/e-navigator \
E_NAVIGATOR_HOMELAB_IMAGE_TAG=gap7-reduced-amd64 \
E_NAVIGATOR_REDUCED_PRIVILEGE_DURATION_SECONDS=30 \
benchmarks/runner/homelab-reduced-privilege.sh
```

Interrupted proof arms can be continued with
`E_NAVIGATOR_REDUCED_PRIVILEGE_RESUME=1`. Completed arms are revalidated from
their artifacts. An incomplete arm is replaced before collection so stale pod
snapshots cannot satisfy a new run.

## Correctness Gates

The analyzer required exactly two ready agent pods with zero restarts, exact
effective capability sets, `NoNewPrivs: 1`, and `Seccomp: 2`. Every Aya source
also had to initialize on both nodes and report zero kernel transport loss,
ring-buffer reservation failure, and userspace send failure.

Signals were tied to the proof workload rather than accepted by kind alone:
`/bin/true` execs from UID 65532, TCP ports 16379 or 18080, unique
`reduced-*.invalid.e-navigator.local` DNS names, HTTP `/proof` on 18080, Redis
`PING`, a non-root Python process with resolved Python frames, and Go TLS
`/proof` on 8443. The host-resource arm required node CPU, node memory, and
process observations. The general workload ran as UID 65532 and completed all
five operation families in every arm. The Go client completed 4,000 of 4,000
requests in both the no-agent and TLS arms.

| Arm | Effective capabilities | Workload-correlated signals |
| --- | --- | ---: |
| Exec | `BPF`, `PERFMON` | 776 |
| Network | `BPF`, `PERFMON` | 500 |
| DNS | `BPF`, `PERFMON` | 6,058 |
| HTTP | `BPF`, `PERFMON` | 1,502 |
| Redis protocol | `BPF`, `PERFMON` | 1,544 |
| CPU profile | `BPF`, `PERFMON`, `SYS_PTRACE` | 1 |
| Host resource | none | 7,788 |
| Go TLS | `BPF`, `PERFMON`, `SYS_PTRACE` | 7,988 |

The single CPU count is intentionally narrow: it is the sample that satisfied
all cross-UID Python and symbol predicates, not the total source volume. Native
metrics recorded 14,567 decoded and sent CPU samples in that arm.

## Native Loss Accounting

| Aya arm | Decoded | Sent | Transport loss | Ring reservations | Send failures |
| --- | ---: | ---: | ---: | ---: | ---: |
| Exec | 7,435 | 7,435 | 0 | 0 | 0 |
| Network | 75,647 | 75,647 | 0 | 0 | 0 |
| DNS | 16,472 | 16,472 | 0 | 0 | 0 |
| HTTP | 3,647 | 3,647 | 0 | 0 | 0 |
| Redis protocol | 3,088 | 1,544 | 0 | 0 | 0 |
| CPU profile | 14,567 | 14,567 | 0 | 0 | 0 |
| Go TLS | 16,072 | 8,027 | 0 | 0 | 0 |

Decoded and sent totals need not match for stateful protocol pairing. The
correctness gate is explicit workload output plus positive semantic signals
and zero transport, reservation, and send loss.

## Cleanup And Claim Boundary

After the final arm, the benchmark Helm release was absent, the benchmark
namespace contained no workloads, the standing Argo application was
`Synced/Healthy`, and its DaemonSet was ready on both nodes.

This proves the listed source slices under the exact capability sets on the
homelab Linux 6.6.68 kernel. It does not prove rootless operation, every LSM or
seccomp policy, older kernels, production safety, every OpenSSL/GnuTLS target
permission layout, or lower overhead. The short no-agent arms are correctness
controls and must not be used as a performance comparison.
