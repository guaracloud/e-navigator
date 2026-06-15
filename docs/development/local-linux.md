# Local Linux Development

## Non-Privileged Checks

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

## Aya Prerequisites

Install the Rust nightly toolchain with `rust-src`, `bpf-linker`, and `bpftool`:

```bash
rustup toolchain install nightly --component rust-src
cargo install bpf-linker --version 0.10.3 --locked
```

Install `bpftool` from the Linux distribution package manager.

## Synthetic Runner

```bash
cargo run --locked -p e-navigator-cli -- --source synthetic
```

Expected result: newline-delimited JSON is printed to stdout, including attributed synthetic exec, process exit, network connection, failed network interaction, DNS, resource observation, dependency edge, network metric, DNS metric, resource metric, trace span observation, protocol request observation, request span observation, request correlation warning, profile sample observation, profiling session observation, profiling warning observation, network-inferred service interaction span, DNS-derived service path observation, and runtime security finding fixtures.

## Docker Smoke Tests

```bash
docker build -f Containerfile -t e-navigator:local .
docker run --rm e-navigator:local --source synthetic
tests/smoke_docker.sh e-navigator:local
```

These checks are non-privileged and do not prove real eBPF attach behavior.

## Argv Capture

Exec argv capture is bounded and configurable:

- `enabled`: defaults to `true`.
- `max_args`: defaults to `8`.
- `max_bytes`: defaults to `512`.

Arguments can contain sensitive data. Disable argv capture or lower limits when running in environments where command-line arguments may include secrets.

## Privileged Aya Exec And Network Smoke Test

```bash
sudo -E cargo run -p e-navigator-cli --release -- --source aya-exec
```

In another shell:

```bash
/bin/true
```

Expected result: the runner prints JSON exec signals from `source.aya_exec`.
To exercise network visibility, open a TCP connection from the same host while the runner is active.
Expected network result: the runner prints JSON network connection signals from `source.aya_network`.

## Privileged Aya CPU Profile Smoke Test

Create a local config that enables only the CPU profile source module and source config, then run:

```bash
sudo -E cargo run --locked -p e-navigator-cli --release -- --source aya-cpu-profile --config /path/to/e-navigator-cpu-profile.toml
```

Expected result: newline-delimited JSON `profile_sample_observation` records from `source.aya_cpu_profile` appear with `profiling_kind = "cpu"` and `correlation_kind = "observed_profile_sample"`. The source currently emits only observed process/thread/sample metadata and bounded stack frames when present; it does not symbolize stacks, export pprof, export OTLP profiles, store profiles, render flamegraphs, profile allocations, profile locks, correlate traces with profiles, or identify workload bottlenecks.

Do not claim live CPU profiling unless this command ran on a privileged Linux host with eBPF/perf-event support and observed at least one real sample.

Phase 5 resource metrics are available through synthetic fixtures and the non-privileged `source.host_resource` path when run on Linux with readable procfs, sysfs, and cgroup v2 files. Do not claim host resource accuracy from synthetic output.

DNS query and response schemas are available through synthetic fixtures and generator tests. Runtime Aya DNS packet capture is intentionally deferred; do not claim real DNS runtime visibility from the synthetic source or from the TCP-oriented `source.aya_network` source.

Phase 7 request-level tracing foundation signals are available through synthetic fixtures, fixture-backed protocol parsing tests, `generator.trace_correlation`, and `generator.request_correlation`. Synthetic output proves schema, runner, generator, and formatter behavior only. Do not claim live HTTP or gRPC parsing, request-level tracing from real traffic, real trace-context extraction from runtime payloads, production OTLP trace export, critical path analysis, or Kubernetes runtime tracing from synthetic output.

Phase 9 CPU profiling source foundation signals are available through synthetic profile fixtures, Aya CPU profile decode fixtures, `e-navigator-profiling` model tests, `source.aya_cpu_profile`, `generator.profiling`, and the internal profile formatter boundary. Synthetic output proves schema, bounded normalization, generator, attribution, and formatter behavior only. Aya CPU profile decode fixtures prove event decoding only. Do not claim live CPU profiling, memory allocation profiling, lock contention profiling, host runtime profiling accuracy, pprof export, OTLP profile export, profile storage, flamegraph UI, trace/profile correlation, Pyroscope replacement behavior, or workload bottleneck analysis from synthetic output or decode fixtures.

The smoke test must run as root or with the Linux capabilities and rlimits required to load and attach eBPF programs.
Do not claim this test passed unless it ran on a Linux host with tracefs/eBPF support.
