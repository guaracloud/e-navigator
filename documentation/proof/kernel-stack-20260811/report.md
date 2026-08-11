# Kernel-stack local proof

Date: 2026-08-11

Status: passed, scoped local smoke

## Environment

- Docker backend: OrbStack, `overlayfs`
- Kernel: `7.0.11-orbstack-00360-gc9bc4d96ac70`
- Architecture: `aarch64`
- Local image id:
  `sha256:ce8321b6964f18c2f0c84ffb9af9d75b259159aafb34e6a9022d9ec845812639`
- Pinned builder: `rust:1.96-bookworm` with
  `nightly-2026-07-01` for eBPF and `bpf-linker 0.10.3`

## Commands

```bash
docker build -f Containerfile -t e-navigator:local .
tests/smoke_aya_kernel_profile_linux.sh e-navigator:local
```

The container build compiled the release CLI and both embedded eBPF objects,
one for RingBuf and one for perf-buffer delivery. The smoke started a disposable
busy-loop workload and a privileged host-pid profiler using
`tests/fixtures/kernel-profile-smoke.toml`. Cleanup removed both containers.

## Acceptance

The smoke passed all of these checks:

- the actual eBPF profiler verifier-loaded and attached on the reported kernel;
- at least one periodic CPU sample retained both `user` and `kernel` frame
  domains;
- the sample reported a positive `profiling.stack.kernel_frames` count; and
- no exported kernel frame used the raw userspace fallback form `ip:<address>`.

The pinned Pyroscope `1.20.3` OTLP ingest/query smoke also passed after the
frame-domain dictionary change, returning 40,000,000 ticks for the synthetic
profile query.

## Boundary

This proves one local aarch64 OrbStack kernel, one periodic on-CPU path, short
duration, privileged execution, and functional export semantics. It does not
prove scheduler off-CPU or futex-wait kernel-frame meaning, other kernels or
architectures, Kubernetes capability profiles, `SYSLOG`-backed kernel names,
transport behavior under loss, sustained load, CPU/RSS overhead, or production
readiness.
