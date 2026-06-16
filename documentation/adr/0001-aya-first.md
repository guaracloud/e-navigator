# ADR 0001: Use Aya As The First eBPF Stack

## Status

Accepted

## Context

E-Navigator is a Rust-first observability and diagnostics platform. The first phase needs a process exec eBPF source while preserving a long-term path for many probes.

## Decision

Use Aya as the first eBPF stack for userspace loading and kernel-side Rust eBPF programs.

## Consequences

- The project stays Rust-native across userspace and eBPF code.
- eBPF implementation details stay behind source boundaries.
- A future `libbpf-rs` backend remains possible if a specific probe or kernel compatibility requirement justifies it.
