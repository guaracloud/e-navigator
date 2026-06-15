# E-Navigator

E-Navigator is a Rust and eBPF observability, security, profiling, and diagnostics platform for Linux and Kubernetes workloads.

Phase 6 builds a distributed tracing foundation on the bounded runtime, network, DNS, dependency, security, resource, and OTEL-compatible export foundations:

- A layered Rust workspace.
- A statically registered signal pipeline.
- A local Linux runner.
- Kubernetes DaemonSet packaging.
- An Aya process exec and process exit source.
- An Aya TCP-oriented network connect/failure and fd-close duration source.
- Bounded, configurable argv capture.
- Best-effort container and Kubernetes attribution.
- Bounded network metric generation for connection counts, failures, durations, active connection gauges, traffic destinations, and protocol distribution.
- DNS query/response schemas, synthetic DNS fixtures, and bounded DNS metric/dependency generation from DNS signals.
- Versioned resource observation schemas for node CPU/load/memory/filesystem/disk, process resources, and cgroup/container CPU, memory, process/thread, fd, and socket counts where available.
- A non-privileged bounded host resource source for procfs, sysfs, and cgroup v2 files with configurable roots and sampling limits.
- A bounded resource metric generator for low-cardinality node, process, and cgroup/container metrics.
- A dependency graph generator for observed network edges.
- Versioned trace-foundation schemas for trace span observations, service interaction span observations, service path observations, and trace correlation warnings.
- A bounded trace correlation generator for network-inferred service interactions, direct/upstream dependency-edge service paths, DNS-derived service paths, duplicate suppression, and missing-attribution warnings.
- A narrow runtime security generator for process and network findings.
- An internal OTEL-compatible metric formatter boundary for future exporters.
- An internal OTEL-compatible trace formatter boundary for future exporters.
- JSON stdout output.

Phase 6 is a tracing foundation, not a full distributed tracing backend or Tempo replacement. Runtime HTTP/gRPC parsing, request IDs, routes, methods, status codes, retries, full OTLP trace export, production trace storage, UI, critical path analysis, profiling correlation, cost attribution, capacity planning, continuous profiling, and runtime DNS packet capture are not implemented. The Aya network source remains TCP-oriented. Host resource accuracy depends on running on Linux with the configured host procfs/sysfs/cgroup mounts.

## Development

Run non-privileged checks:

```bash
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets --exclude e-navigator-ebpf-programs -- -D warnings
cargo test --locked --workspace --exclude e-navigator-ebpf-programs
cargo build --locked --workspace --exclude e-navigator-ebpf-programs
cargo run --locked -p e-navigator-cli -- --source synthetic
docker build -f Containerfile -t e-navigator:local .
docker run --rm e-navigator:local --source synthetic
tests/smoke_docker.sh e-navigator:local
git diff --check
```

Aya/eBPF development also requires the nightly Rust toolchain with `rust-src`, `bpf-linker`, and `bpftool`.

See:

- `docs/development/local-linux.md`
- `docs/development/kubernetes.md`

## Verification

Non-privileged checks:

```bash
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets --exclude e-navigator-ebpf-programs -- -D warnings
cargo test --locked --workspace --exclude e-navigator-ebpf-programs
cargo build --locked --workspace --exclude e-navigator-ebpf-programs
cargo run --locked -p e-navigator-cli -- --source synthetic
docker build -f Containerfile -t e-navigator:local .
docker run --rm e-navigator:local --source synthetic
tests/smoke_docker.sh e-navigator:local
git diff --check
```

Kubernetes manifest dry-run validation is also non-privileged:

```bash
kubectl apply --dry-run=client -f deploy/kubernetes/namespace.yaml
kubectl apply --dry-run=client -f deploy/kubernetes/rbac.yaml
kubectl apply --dry-run=client -f deploy/kubernetes/configmap.yaml
kubectl apply --dry-run=client -f deploy/kubernetes/daemonset.yaml
```

Privileged eBPF smoke test on Linux:

```bash
sudo -E cargo run -p e-navigator-cli --release -- --source aya-exec
```

The `aya-exec` source mode registers the statically compiled Aya exec and network sources when both modules are enabled. Do not treat privileged Aya, DNS runtime visibility, or Kubernetes runtime tests as passed unless they run on a real Linux host or Kubernetes cluster with tracefs/eBPF support and the documented privileges.
