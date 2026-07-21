# BTF fexit network-hook proof, 2026-07-21

## Decision

E-Navigator adopts BTF-backed fexit hooks for the network source's `read(2)`
and `write(2)` byte accounting on kernels that positively pass the capability
and target preflight. The established syscall tracepoints remain the automatic
compatibility fallback and a forced diagnostic mode.

The homelab result crossed the predeclared adoption threshold. Across three
counterbalanced 90-second runs per arm, fexit produced 7.971% more operations
per second and 7.710% lower mean latency than tracepoints. Every enabled run
reported exact workload byte counts in its matching close signal and zero
transport loss.

## Implementation proved

The source resolves its hook before loading the eBPF object. `auto` and forced
`fexit` require kernel tracing-program support, readable valid kernel BTF, and
`FUNC` targets for `ksys_read` and `ksys_write`. Positively unsupported
capabilities select tracepoints only in `auto`; indeterminate probe, BTF,
verifier, load, or attach errors fail source startup. Forced `tracepoint` skips
the fexit probe.

The fexit programs use the target argument and return context to update the
existing bounded active-connection map directly. They remove the network
source's enter/exit pending-map correlation for scalar read/write calls. The
event shape, reader, decoder, saturating counters, other syscall hooks, and
transport-loss surfaces are unchanged.

No CO-RE structure relocation was added because the programs do not read
kernel structure fields. Kernel BTF is used for function discovery and typed
attachment. Fentry was not selected because it would retain both an exit hook
and pending per-thread correlation.

## Environment and method

- Context: `homelab`, exclusively.
- Cluster: k3s `v1.30.4+k3s1`, two amd64 NixOS 24.05 nodes, Linux 6.6.68,
  containerd `1.7.20-k3s1`.
- Both nodes exposed `/sys/kernel/btf/vmlinux` and BTF function records for
  `ksys_read` and `ksys_write`.
- Image: `docker.io/library/e-navigator:gap2-20260721`, OCI manifest
  `sha256:5e45d737caad848c06b77acd94ab0465b738369cebd7ddb505f0786653e03c18`.
  It was loaded directly into both homelab containerd stores and never pushed.
- Final-code conformance image:
  `docker.io/library/e-navigator:gap2-final-20260721`, OCI manifest
  `sha256:6567f508245eb3fe97bf5670ca80e05a76077041f8ab4c7b5b5f80ba9b587679`.
  Its OCI archive SHA-256 was
  `374e38395932835728bf94fdab0eada5c991bb2aca9fd49375acd52025a3bb68`.
- Arms: no benchmark E-Navigator release, forced tracepoints, and forced
  fexit. RingBuf transport was held constant.
- Order: `none/tracepoint/fexit`, `fexit/none/tracepoint`, then
  `tracepoint/fexit/none`.
- Workload: one Python 3.12 process pinned to `homelab-01`, with a bounded echo
  thread and one client TCP connection. Each measured operation issued one
  256-byte `os.write` and one exact-length `os.read`.
- Repetitions: three per arm, 90 measured seconds each after a five-second
  cgroup-discovery wait.
- Sampling: 20 pod and node resource captures per run at five-second spacing.
  Metrics Server cadence makes adjacent samples correlated.
- The benchmark agent enabled only `source.aya_network`, container attribution,
  network metrics, JSON stdout, and Prometheus HTTP. Capture was restricted to
  `e-navigator-bench` after the cgroup map converged.

The complete normalized numeric record is in [runs.json](runs.json), with a
readable copy under `benchmarks/results/sample-kernel-hook-20260721.md`.

## Runtime results

| Arm | Operations/s mean +/- sd | Mean latency us +/- sd | Agent CPU m +/- sd | Agent RSS MiB +/- sd |
| --- | ---: | ---: | ---: | ---: |
| no benchmark agent | 39,452.230 +/- 230.731 | 23.467 +/- 0.133 | n/a | n/a |
| tracepoint | 33,965.449 +/- 1,344.217 | 27.378 +/- 1.053 | 13.965 +/- 1.827 | 20.611 +/- 1.058 |
| fexit | 36,672.691 +/- 148.847 | 25.267 +/- 0.080 | 13.984 +/- 2.770 | 34.000 +/- 1.000 |

Fexit versus tracepoint measured +7.971% operations/s, -7.710% mean latency,
+0.137% two-pod agent CPU, and +64.960% two-pod RSS. Fexit versus the no-agent
baseline measured -7.045% operations/s. The 50-microsecond p95 histogram upper
bound was identical in all runs except tracepoint repetition 2, which recorded
a 100-microsecond p99 upper bound.

Every forced fexit run logged fexit selection from both nodes. Each forced
tracepoint config passed strict config validation and produced the expected
tracepoint-accounted close signal. All six agent runs emitted exactly one
matching Python close event whose sent and received byte totals equaled
`operations * 256`. All six Prometheus snapshots reported zero aggregate
transport loss, zero perf loss, and zero RingBuf reservation failures for the
network source.

After the A/B implementation was frozen, the final-code image was exercised in
two additional five-second conformance smokes. `auto` selected fexit on both
nodes and captured 46,932,480 bytes in each direction. Forced `tracepoint`
selected tracepoints on both nodes and captured 44,971,520 bytes in each
direction. Both close events exactly matched their workload result, and both
smokes reported zero aggregate transport loss, zero perf loss, and zero RingBuf
reservation failures. These smokes validate the final selection and accounting
paths; they do not replace the predeclared 9-arm performance comparison.

## Boundaries

- The measured result covers scalar `read(2)` and `write(2)` on tracked TCP
  sockets. It does not cover `readv`, `writev`, `send*`, `recv*`, other sources,
  a mixed production workload, or a production cluster.
- The fexit arm used about 13.4 MiB more summed RSS across two agent pods. This
  is not a lower-memory result.
- Both nodes used the same Linux 6.6.68 kernel with BTF. Automatic tracepoint
  fallback on a kernel without fexit or BTF remains unit-tested, not runtime
  proven.
- The shared homelab had unrelated background activity. Counterbalancing and
  the low fexit run variance support this narrow decision, not a universal
  overhead percentage.
- No CO-RE kernel-structure compatibility claim is made because this path has
  no kernel-structure field relocations.

## Cleanup and restore

The disposable workload and Helm release were removed after every arm and
conformance smoke. Both imported Gap 2 image tags were removed from both node
containerd stores, both local OCI archives were deleted, and the disposable
`e-navigator-bench` namespace was removed. The standing Argo CD application was
restored to automated prune and self-heal, reported `Synced` and `Healthy`, and
its original digest-pinned DaemonSet was 2/2 Ready at image digest
`sha256:62402d21b9cb02d59d63365c7e3716ffa0980bfea42d070b43fed618703a7df9`.
The benchmark touched no production context.
