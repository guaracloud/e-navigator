#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

program="crates/e-navigator-ebpf-programs/src/main.rs"
source_file="crates/e-navigator-sources-ebpf-aya/src/network.rs"

for expected in \
  "try_tracepoint_dns_sendto_enter" \
  "try_tracepoint_sendto_exit" \
  "try_tracepoint_dns_sendmsg_enter" \
  "try_tracepoint_sendmsg_exit" \
  "try_tracepoint_dns_recvfrom_enter" \
  "try_tracepoint_dns_recvfrom_exit" \
  "try_tracepoint_dns_recvmsg_enter" \
  "try_tracepoint_dns_recvmsg_exit"; do
  if ! grep -Fq "$expected" "$program"; then
    printf 'expected %s to account stream socket I/O path: missing %s\n' "$program" "$expected" >&2
    exit 1
  fi
done

for expected in \
  "try_tracepoint_network_io_enter(&ctx, NETWORK_IO_WRITE)" \
  "try_tracepoint_network_io_enter(&ctx, NETWORK_IO_READ)" \
  "try_tracepoint_network_io_exit(&ctx)"; do
  if ! grep -Fq "$expected" "$program"; then
    printf 'expected %s to use shared network I/O accounting: missing %s\n' "$program" "$expected" >&2
    exit 1
  fi
done

for expected in \
  "tracepoint_sendto_enter" \
  "sys_enter_sendto" \
  "tracepoint_sendto_exit" \
  "sys_exit_sendto" \
  "tracepoint_sendmsg_enter" \
  "sys_enter_sendmsg" \
  "tracepoint_sendmsg_exit" \
  "sys_exit_sendmsg" \
  "tracepoint_recvfrom_enter" \
  "sys_enter_recvfrom" \
  "tracepoint_recvfrom_exit" \
  "sys_exit_recvfrom" \
  "tracepoint_recvmsg_enter" \
  "sys_enter_recvmsg" \
  "tracepoint_recvmsg_exit" \
  "sys_exit_recvmsg"; do
  if ! grep -Fq "$expected" "$source_file"; then
    printf 'expected %s to attach stream socket I/O tracepoint: missing %s\n' "$source_file" "$expected" >&2
    exit 1
  fi
done
