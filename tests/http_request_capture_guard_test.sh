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
  "tracepoint_http_writev_enter" \
  "tracepoint_http_sendto_enter" \
  "tracepoint_http_sendmsg_enter" \
  "HTTP_MAX_IOVECS" \
  "HTTP_IOVEC_CHUNK_BYTES" \
  "copy_http_request_iovecs" \
  "copy_http_request_iovec_chunk" \
  "request_iovec_lens" \
  "emit_http_request_iovecs_event" \
  "emit_http_request_event" \
  "copy_http_request"; do
  if ! grep -Fq "$expected" "$program"; then
    printf 'expected %s to support HTTP request capture: missing %s\n' "$program" "$expected" >&2
    exit 1
  fi
done

if ! grep -Fq "copy_http_request_iovecs(iov, iov_len, event)" "$program"; then
  printf 'expected %s to assemble split HTTP writev requests across bounded iovecs\n' "$program" >&2
  exit 1
fi

if ! grep -Fq "HTTP_MAX_IOVECS: usize = 2" "$program"; then
  printf 'expected %s to keep split HTTP iovec verifier complexity bounded to two iovecs\n' "$program" >&2
  exit 1
fi

if ! grep -Fq "HTTP_IOVEC_CHUNK_BYTES: usize = HTTP_REQUEST_BYTES / HTTP_MAX_IOVECS" "$program"; then
  printf 'expected %s to keep split HTTP iovec copies in fixed verifier-bounded slots\n' "$program" >&2
  exit 1
fi

if ! grep -Fq "bpf_probe_read_user_buf(" "$program"; then
  printf 'expected %s to keep contiguous HTTP request copies on the bounded bulk helper\n' "$program" >&2
  exit 1
fi

if ! grep -Fq "compact_raw_http_request" "$source_file"; then
  printf 'expected %s to compact fixed-slot split HTTP iovecs before parsing\n' "$source_file" >&2
  exit 1
fi

if ! grep -Fq "fn try_tracepoint_http_sendmsg_enter(ctx: TracePointContext) -> Result<u32, i64>" "$program"; then
  printf 'expected %s to keep the HTTP sendmsg tracepoint attached as a no-op verifier boundary\n' "$program" >&2
  exit 1
fi

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
  "tracepoint_http_writev_enter" \
  "sys_enter_writev" \
  "tracepoint_http_sendto_enter" \
  "sys_enter_sendto" \
  "tracepoint_http_sendmsg_enter" \
  "sys_enter_sendmsg"; do
  if ! grep -Fq "$expected" "$source_file"; then
    printf 'expected %s to attach HTTP request capture path: missing %s\n' "$source_file" "$expected" >&2
    exit 1
  fi
done
