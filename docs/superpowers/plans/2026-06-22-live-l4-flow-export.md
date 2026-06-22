# Live L4 Flow Export Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Produce live `network_flow_summary` records from attributed TCP close events with bounded byte counters, then let `generator.guara_compat` export `beyla_network_flow_bytes_total`.

**Architecture:** Keep the static `Source -> Processor -> Generator -> Sink` pipeline. The Aya network source records byte counters on connected TCP file descriptors and includes them on close events; `generator.network_metrics` derives `network_flow_summary` after container/Kubernetes attribution; downstream `generator.guara_compat` projects the summary to the Beyla-compatible Prometheus metric.

**Tech Stack:** Rust 2024, Aya eBPF tracepoints, existing signal envelopes, existing generator fan-out, Prometheus HTTP sink, Helm homelab deployment.

---

## Files

- Modify: `crates/e-navigator-signals/src/network.rs` to add optional byte counters to `NetworkConnectionCloseEvent`.
- Modify: `crates/e-navigator-sources-ebpf-aya/src/network.rs` to decode byte counters from raw close events.
- Modify: `crates/e-navigator-ebpf-programs/src/main.rs` to count connected TCP read/write bytes before close.
- Modify: `crates/e-navigator-generators/src/network_metrics.rs` to emit `network_flow_summary` for close events with nonzero byte evidence.
- Modify docs and curated sample files after live proof.

## Proof Criteria

- Local positive evidence:
  - `cargo test --locked -p e-navigator-sources-ebpf-aya network -- --nocapture` shows raw close decode preserves `bytes_sent` and `bytes_received`.
  - `cargo test --locked -p e-navigator-generators network_flow -- --nocapture` shows `generator.network_metrics` emits a `network_flow_summary` with attributed endpoints and nonzero bytes.
  - `cargo test --locked -p e-navigator-runner generated -- --nocapture` continues to prove downstream generator fan-out.
- Live positive evidence:
  - `kubectl config current-context` is exactly `staging`.
  - Every `kubectl`/`helm` command uses namespace `e-navigator-bench`.
  - Pushed GHCR image is deployed by Helm and both DaemonSet pods are Ready with zero restarts.
  - E-Navigator logs contain live `network_flow_summary` records for controlled workload traffic.
  - Direct `/metrics` contains nonzero `beyla_network_flow_bytes_total` lines.
  - Homelab Prometheus returns nonzero `beyla_network_flow_bytes_total` results.
- Negative evidence:
  - No `network_flow_summary` lines in logs.
  - `beyla_network_flow_bytes_total` absent or only zero.
  - Controlled workload not represented in emitted summaries or Prometheus results.
  - DaemonSet restart/crash, sink failure flood, or context/namespace mismatch.

## Tasks

### Task 1: Tests For Byte Counters And Flow Summary

- [ ] Add a source decode test in `crates/e-navigator-sources-ebpf-aya/src/network.rs`:

```rust
#[test]
fn decodes_raw_close_byte_counters() {
    let raw = close_event_with_bytes(512, 1024);
    let signal = raw_network_to_signal_with_clock(raw_as_bytes(&raw), Some("node-a".to_string()), 3_000)
        .expect("raw event decodes");
    let SignalPayload::NetworkConnectionClose(event) = signal.payload else {
        panic!("expected network close payload");
    };
    assert_eq!(event.bytes_sent, Some(512));
    assert_eq!(event.bytes_received, Some(1024));
}
```

- [ ] Run:

```bash
cargo test --locked -p e-navigator-sources-ebpf-aya decodes_raw_close_byte_counters -- --nocapture
```

Expected: FAIL because close events do not expose byte counters yet.

- [ ] Add a generator test in `crates/e-navigator-generators/src/network_metrics.rs`:

```rust
#[tokio::test]
async fn emits_network_flow_summary_from_close_byte_counters() {
    let generator = NetworkMetricsGenerator::default();
    let signal = close_signal_with_bytes(100, 900, 512, 1024);

    let outputs = observe(&generator, &signal).await;
    let flow = network_flow_summary(&outputs);

    assert_eq!(flow.bytes, 1536);
    assert_eq!(flow.source.kubernetes, Some(kubernetes_context()));
    assert_eq!(flow.destination.address.as_deref(), Some("10.0.0.20"));
    assert_eq!(flow.first_seen_unix_nanos, 100);
    assert_eq!(flow.last_seen_unix_nanos, 900);
}
```

- [ ] Run:

```bash
cargo test --locked -p e-navigator-generators emits_network_flow_summary_from_close_byte_counters -- --nocapture
```

Expected: FAIL because `generator.network_metrics` does not emit `network_flow_summary` from close records yet.

### Task 2: Minimal Implementation

- [ ] Add optional `bytes_sent` and `bytes_received` fields to `NetworkConnectionCloseEvent` with serde defaults and skip-when-none serialization.
- [ ] Extend raw network event ABI in source and eBPF structs with `bytes_sent` and `bytes_received`; update the ABI layout-size test.
- [ ] In the eBPF program, add pending IO maps for connected TCP read/write-style syscalls and update the matching active connection byte counters only when syscall return values are positive.
- [ ] Attach the needed syscall tracepoints in `AyaNetworkSource`.
- [ ] Emit `network_flow_summary` from `NetworkMetricsGenerator::observe_close` when the close event has nonzero byte counters and Kubernetes attribution exists on the source side.

### Task 3: Local Verification

- [ ] Run targeted tests:

```bash
cargo test --locked -p e-navigator-sources-ebpf-aya network -- --nocapture
cargo test --locked -p e-navigator-generators network_flow -- --nocapture
```

- [ ] Run broader gates:

```bash
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets --exclude e-navigator-ebpf-programs -- -D warnings
cargo test --locked --workspace --exclude e-navigator-ebpf-programs
cargo run --locked -p e-navigator-cli -- --source synthetic
helm lint charts/e-navigator
helm template e-navigator charts/e-navigator
git diff --check
```

### Task 4: Publish And Homelab Proof

- [ ] Commit with `feat: emit live network flow summaries`.
- [ ] Push `main`, wait for CI and image publication, and record workflow run IDs.
- [ ] Deploy only `ghcr.io/guaracloud/e-navigator:sha-<commit>` to `staging/e-navigator-bench`.
- [ ] Record context, namespace, commit SHA, image digest, Helm revision, rendered values/manifests, rollout state, pod placement, pod restarts, workload manifest/logs, E-Navigator logs, `/healthz`, `/readyz`, `/metrics`, Prometheus queries, CPU/RSS samples, and cleanup/restore commands under `benchmarks/results/<timestamp>-guara-flow-live/`.
- [ ] Update `documentation/claims-matrix.md`, `documentation/benchmark.md` if methodology changes, `documentation/guara-compatibility.md`, and a curated `benchmarks/results/sample-<timestamp>-guara-flow-live.md`.
