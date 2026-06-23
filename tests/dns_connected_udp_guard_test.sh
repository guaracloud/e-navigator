#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

program="crates/e-navigator-ebpf-programs/src/main.rs"
source_file="crates/e-navigator-sources-ebpf-aya/src/dns.rs"

for expected in \
  "try_tracepoint_dns_connect_enter" \
  "try_tracepoint_dns_connect_exit" \
  "try_tracepoint_dns_close_enter" \
  "try_tracepoint_dns_write_enter" \
  "try_tracepoint_dns_read_enter" \
  "connected_dns_recv_peer" \
  "connected_dns_peer" \
  "DNS_DIAGNOSTIC_EVENTS" \
  "DNS_DIAGNOSTIC_CONNECTED_SEND_MISSING_PEER" \
  "DNS_DIAGNOSTIC_CONNECTED_RECV_MISSING_PEER" \
  "emit_dns_diagnostic_event" \
  "emit_dns_connected_send_event"; do
  if ! grep -Fq "$expected" "$program"; then
    printf 'expected %s to support connected UDP DNS path: missing %s\n' "$program" "$expected" >&2
    exit 1
  fi
done

for expected in \
  "tracepoint_dns_connect_enter" \
  "sys_enter_connect" \
  "tracepoint_dns_connect_exit" \
  "sys_exit_connect" \
  "tracepoint_dns_close_enter" \
  "sys_enter_close" \
  "tracepoint_write_enter" \
  "sys_enter_write" \
  "tracepoint_write_exit" \
  "sys_exit_write" \
  "tracepoint_read_enter" \
  "sys_enter_read" \
  "tracepoint_read_exit" \
  "sys_exit_read" \
  "configure_dns_diagnostics" \
  "DNS_DIAGNOSTIC_EVENTS" \
  "log_dns_drop_diagnostic"; do
  if ! grep -Fq "$expected" "$source_file"; then
    printf 'expected %s to attach connected UDP DNS tracepoint: missing %s\n' "$source_file" "$expected" >&2
    exit 1
  fi
done
