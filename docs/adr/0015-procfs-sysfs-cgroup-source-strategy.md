# ADR 0015: Procfs Sysfs Cgroup Source Strategy

Date: 2026-06-15
Status: Accepted

## Context

Phase 5 resource metrics should work without eBPF privileges and without coupling procfs/sysfs/cgroup parsing to Aya source crates.

## Decision

E-Navigator adds `source.host_resource` in a non-Aya source crate. It reads bounded data from configurable procfs, sysfs, and cgroup v2 roots. Process and cgroup scans are capped by configuration, file reads are bounded, and missing or partial files produce structured warnings instead of failing the whole source.

The Kubernetes DaemonSet mounts only the host paths needed for this strategy: `/proc` and `/sys` under read-only `/host` paths, while existing tracefs/debugfs mounts remain for privileged Aya smoke tests.

## Consequences

The local CLI and Kubernetes DaemonSet use the same runner path. Non-privileged synthetic and parser tests can validate Phase 5 behavior without claiming real host accuracy. Real host resource accuracy still requires running on Linux with the configured host filesystems mounted.
