#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

program="crates/e-navigator-ebpf-programs/src/main.rs"
build_script="crates/e-navigator-sources-ebpf-aya/build.rs"
transport="crates/e-navigator-sources-ebpf-aya/src/event_transport.rs"
telemetry="crates/e-navigator-cli/src/registry.rs"

for expected in \
  'default = ["perf-buffer"]' \
  'perf-buffer = []' \
  'ring-buffer = []'; do
  if ! rg -Fq -- "$expected" crates/e-navigator-ebpf-programs/Cargo.toml; then
    printf 'eBPF package is missing transport feature: %s\n' "$expected" >&2
    exit 1
  fi
done

for expected in \
  'build_variant(&bpf_toolchain, "ring-buffer", "ring")' \
  'build_variant(&bpf_toolchain, "perf-buffer", "perf")' \
  'e-navigator-ebpf-programs-ring' \
  'e-navigator-ebpf-programs-perf'; do
  if ! rg -Fq -- "$expected" "$build_script"; then
    printf 'dual eBPF artifact build is missing: %s\n' "$expected" >&2
    exit 1
  fi
done

for expected in \
  'is_map_supported(MapType::RingBuf)' \
  'BPF ring-buffer capability probe failed' \
  'the kernel does not support BPF ring-buffer maps' \
  'EVENT_TRANSPORT_LOSSES' \
  'record_ring_buffer_reservation_failures'; do
  if ! rg -Fq -- "$expected" "$transport" "$program"; then
    printf 'runtime transport selection or loss accounting is missing: %s\n' "$expected" >&2
    exit 1
  fi
done

for map in \
  EXEC_EVENTS EXIT_EVENTS NETWORK_EVENTS TCP_STAT_EVENTS CPU_PROFILE_EVENTS \
  DNS_EVENTS HTTP_REQUEST_EVENTS PROTOCOL_DATA_EVENTS TLS_DATA_EVENTS; do
  if ! rg -q "output_event!\\($map," "$program"; then
    printf 'event map is not routed through transport accounting: %s\n' "$map" >&2
    exit 1
  fi
done

if rg -n '[A-Z_]+_EVENTS\.output\(' "$program"; then
  printf 'direct event output bypasses transport loss accounting\n' >&2
  exit 1
fi

for metric in \
  e_navigator_ebpf_source_event_transport \
  e_navigator_ebpf_source_lost_transport_events_total \
  e_navigator_ebpf_source_ring_buffer_reservation_failures_total \
  e_navigator_ebpf_source_lost_perf_events_total; do
  if ! rg -Fq -- "$metric" "$telemetry"; then
    printf 'native transport telemetry is missing: %s\n' "$metric" >&2
    exit 1
  fi
done
