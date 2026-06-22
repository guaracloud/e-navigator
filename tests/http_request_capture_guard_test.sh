#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

program="crates/e-navigator-ebpf-programs/src/main.rs"
source_file="crates/e-navigator-sources-ebpf-aya/src/http.rs"

for expected in \
  "RawHttpRequestEvent" \
  "HTTP_REQUEST_EVENTS" \
  "tracepoint_http_connect_enter" \
  "tracepoint_http_connect_exit" \
  "tracepoint_http_close_enter" \
  "tracepoint_http_write_enter" \
  "tracepoint_http_sendto_enter" \
  "tracepoint_http_sendmsg_enter" \
  "emit_http_request_event" \
  "copy_http_request"; do
  if ! grep -Fq "$expected" "$program"; then
    printf 'expected %s to support HTTP request capture: missing %s\n' "$program" "$expected" >&2
    exit 1
  fi
done

for expected in \
  "HTTP_REQUEST_EVENTS" \
  "tracepoint_http_connect_enter" \
  "sys_enter_connect" \
  "tracepoint_http_connect_exit" \
  "sys_exit_connect" \
  "tracepoint_http_close_enter" \
  "sys_enter_close" \
  "tracepoint_http_write_enter" \
  "sys_enter_write" \
  "tracepoint_http_sendto_enter" \
  "sys_enter_sendto" \
  "tracepoint_http_sendmsg_enter" \
  "sys_enter_sendmsg"; do
  if ! grep -Fq "$expected" "$source_file"; then
    printf 'expected %s to attach HTTP request capture path: missing %s\n' "$source_file" "$expected" >&2
    exit 1
  fi
done
