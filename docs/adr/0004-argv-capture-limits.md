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
- Capture is configurable through `[argv_capture]`.
- Kernel-side buffers live in per-CPU scratch maps rather than stack allocations.
- The Aya source writes a control map so disabled argv capture avoids kernel argv reads.

Required Aya load, map configuration, and tracepoint attach failures remain startup failures when the Aya source is enabled.

## Consequences

Argv capture is useful but intentionally incomplete. Truncated or disabled argv should be treated as an expected privacy and safety tradeoff, not as data loss in the pipeline. Operators that handle sensitive environments should disable argv capture or lower limits in the ConfigMap.
