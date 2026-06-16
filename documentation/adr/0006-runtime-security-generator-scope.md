# ADR 0006: First Runtime Security Generator Scope

Date: 2026-06-14
Status: Accepted

## Context

E-Navigator needs derived runtime security signals, but broad process rules are noisy and hard to trust. Phase 2 should prove the generator path with a small high-confidence rule set.

## Decision

The first runtime security generator is statically registered as `generator.runtime_security`. It observes process exec signals and emits versioned `runtime_security_finding` signals for exact basename matches only:

- `runtime.shell_in_container`: `sh`, `bash`, `dash`, `ash`, `zsh`, or `ksh` when container context is present.
- `runtime.network_tool_exec`: `curl`, `wget`, `nc`, `ncat`, `netcat`, or `socat`.

Findings include rule ID, severity, matched process details, and available attribution context. The generator deliberately avoids substring matching and broad suspicious-binary lists.

Service-account token path access is future work because Phase 2 does not implement file-open visibility.

## Consequences

The initial generator is narrow, deterministic, and low-noise. It proves the derived-signal path without pretending to be a complete runtime security product.
