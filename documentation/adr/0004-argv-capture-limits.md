# ADR 0004: Bounded Argv Capture And Sensitive Data Handling

Date: 2026-06-14
Status: Accepted

## Context

Process exec arguments are useful for runtime visibility and security signals, but argv often contains tokens, URLs, credentials, or customer data. eBPF programs must also avoid unbounded memory reads and verifier-unsafe stack usage.

## Decision

E-Navigator captures exec argv only through fixed limits:

- Maximum argument count: 8.
- Maximum captured argument bytes: 512.
- Kernel argument slot size: 64 bytes.
- Capture is configurable through `[argv_capture]` and is disabled by default.
- Kernel-side buffers live in per-CPU scratch maps rather than stack allocations.
- The Aya source writes a control map so disabled argv capture avoids kernel argv reads.
- JSON stdout redacts obvious secret-like argv values, including token, password,
  API key, credential, Authorization, and Bearer-shaped arguments, when capture is
  explicitly enabled.
- The Aya exec source normalizes syscall-entry and `sched_process_exec` samples
  into one downstream exec signal. Syscall-entry samples only populate a bounded
  pending-argv map keyed by PID; `sched_process_exec` is the success signal that
  emits downstream. Stale pending entries are age-limited and capacity-limited so
  failed exec attempts do not become successful exec events.

Required Aya load, map configuration, and tracepoint attach failures remain startup failures when the Aya source is enabled.

## Consequences

Argv capture is useful but intentionally incomplete. Truncated, disabled, or redacted argv should be treated as an expected privacy and safety tradeoff, not as data loss in the pipeline. Operators that need argv must opt in and can lower limits in the ConfigMap.
