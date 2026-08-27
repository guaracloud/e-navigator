# Guara Workload Qualification Ledger

This document records the blockers for replacing Guara's Beyla and Alloy
profiles with the standalone E-Navigator application. It is not yet a finite
support matrix because Guara has not declared exact workload cells. It
deliberately separates a parser recognizing a wire form from a
client/server/runtime cell being qualified in production-like execution.

## Gate Status

**Not replacement-ready.** Guara's current Beyla configuration selects HTTP,
gRPC, PostgreSQL, MySQL, Redis, MongoDB, and Kafka protocol families, but it
does not declare the client libraries, server releases, TLS implementations,
architectures, or I/O paths that form the required support matrix. Those cells
must not be inferred from traffic or from a wire-version field.

A cell can be promoted only when all of the following are recorded together:

1. exact client, server, runtime/TLS build, architecture, and transport;
2. client and server capture roles, cleartext/encrypted mode, and reconnect,
   retry, pooling, pipelining or out-of-order behavior that the cell uses;
3. fixture expectations for operation, status, `error.type`, latency,
   correlation, parent identity, and privacy;
4. restart, pre-attachment, concurrency, sustained-load, and loss-counter
   results from a capable Linux/Kubernetes environment; and
5. exact OTLP/Tempo and, where applicable, Pyroscope evidence.

An unspecified or partially evidenced cell fails the promotion gate. Unit,
property, fuzz-build, and optimized eBPF-build results are necessary evidence,
but they are not substitutes for the live cell.

## Current Executable Protocol Boundaries

| Family | Executable boundary | What is not established by that boundary |
| --- | --- | --- |
| HTTP | Bounded HTTP/1 client/server capture; h2c stream parsing; disabled-by-default plaintext HTTP/1 propagation for the exact ADR 0015 envelope | Framework/runtime versions, TLS propagation, Node async-task parentage, segmented headers across syscalls, multiple requests in one write, retries/reuse under concurrency, and pre-attachment client sockets |
| gRPC | HTTP/2/gRPC metadata and trailer status on the bounded protocol/TLS plaintext capture paths | W3C injection for HTTP/2, protobuf semantics, and Guara client/server/runtime cells |
| PostgreSQL | Protocol 3.0 startup/frontend/backend frames, startup/auth ownership, typed terminals, extended-query recovery, and COPY-in ownership | Protocol 3.0 does not identify a PostgreSQL server release; no Guara driver/server/version cell is declared or qualified |
| MySQL | Protocol-v10 greeting plus protocol-4.1 client response, command/result lifecycles, `LOCAL INFILE`, 16 MiB logical continuations, and mutually advertised zlib after authentication OK | Client-only compression evidence is rejected and counted; zstd, optional-resultset/EOF capability variants, client/server versions, reconnect, and pre-attachment state remain unqualified |
| Redis | RESP2/RESP3 commands and replies; RESP3 push/attribute frames; only valid request-matched explicit Pub/Sub confirmations establish RESP mode; null names and impossible zero-count subscribe acknowledgements are rejected; a request-matched successful `RESET` confirmation exits subscriber mode while errors preserve it; identical array shapes from ordinary commands remain replies | Zero-argument unsubscribe forms make correlation opaque for that connection because their terminal confirmation is unknowable when other subscription kinds remain; the transition emits low-confidence unmatched work and increments `protocol_redis_ambiguous_state_transitions`. Redis/client versions, arbitrary live Pub/Sub interleaving, pre-attachment state, current live reconnect proof, streamed RESP3 aggregates, and sustained load remain unqualified |
| MongoDB | Bounded `OP_MSG`, command `OP_QUERY`, `OP_REPLY`, `responseTo`, no-response, write outcome, and `moreToCome`/exhaust lifecycles | Driver/server versions, unsupported commands/opcodes, reconnect/pre-attachment state, and current live out-of-order/exhaust proof |
| Kafka | Bounded request API key/version parsing, per-API response dispatch, and correlation-id matching that is non-destructive on ambiguity | A Kafka API version is not a broker/client product version; the Guara client/broker matrix, broad live response semantics, retries/rebalances, reconnect, and sustained load remain unqualified |

NATS L7 semantics are not a Guara replacement requirement while Guara's
contract uses NATS only as TCP topology. E-Navigator's bounded NATS parser does
not broaden that Guara requirement.

## Current TLS Adapter Cells

| Adapter cell | Static compatibility boundary | Current qualification boundary |
| --- | --- | --- |
| Dynamic OpenSSL | OpenSSL 1.1.1 and 3 with the required classic and `_ex` read/write plus fd-association exports | Local/live fixtures exist for selected builds; every Guara build/restart/load cell is not yet recorded |
| Dynamic GnuTLS | ABI 30 with the standard integer socket transport | Selected live fixture evidence exists; custom transports and the Guara build matrix remain unqualified |
| Static Go `crypto/tls` | Unstripped Linux/amd64 Go 1.24 through 1.26 with exact build info, required symbols, decoded return sites, and audited fd layout | Go 1.26.4 has selected live evidence; Go 1.24/1.25 and every Guara executable are not yet live-qualified |
| Bundled Node.js TLS | Unsupported | Requires a build-identified plaintext runtime/TLS seam, transactional attach, socket association, restart rescan, fail-closed counters, and live Guara proof |
| JVM JSSE | Unsupported | Required only if Guara declares a JVM/JSSE cell; it needs the same build-specific attachment and proof contract |
| BoringSSL, rustls, custom transports, stripped Go, non-amd64 Go | Unsupported | Required only for cells explicitly declared by Guara |

## TCP Execution-Path Gate

The native TCP contract covers the documented syscall/fexit paths, periodic
active snapshots, final-close remainder, Kubernetes ownership attribution, and
bounded overflow. General `io_uring` is an explicit non-claim. Guara must either
exclude `io_uring` from its tenant TCP contract or add a cell that can be
promoted only after a canonical socket-level seam and the required byte oracle
prove no gaps or double counting. Observation of connections established
before attachment remains unqualified from the attachment point forward.

## Promotion Record

For each declared Guara cell, record the workload image digests, exact command,
kernel/node identity, E-Navigator commit and image digest, fixture seed, native
coverage/failure/loss counters, OTLP assertions, Tempo trace identifiers, and
Pyroscope query evidence. A replacement decision is valid only when every
declared cell is promoted and every explicit exclusion is reflected in
Guara's public workload contract.
