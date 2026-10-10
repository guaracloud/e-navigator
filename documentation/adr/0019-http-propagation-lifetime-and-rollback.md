# ADR 0019: HTTP propagation lifetime and rollback

- Status: accepted
- Date: 2026-10-10
- Scope: [issue #51](https://github.com/guaracloud/e-navigator/issues/51)

## Decision

Retain ADR 0015's disabled-by-default plaintext HTTP/1 mutation envelope.
Use the existing syscall planner, socket-message comparison, context queue,
bounded maps and same-thread ownership. Do not add a generic runtime adapter
that cannot identify a logical task or safely update transport framing.

A captured server read destroys the prior synchronous thread context before
checking the read result, framing, or incoming context. A rejected request,
failed read, continuation body read, or missing context therefore cannot borrow
the previous request's parent. This deliberately sacrifices continuation on
ambiguous reads. Only a newly validated complete inbound request can establish
the next owner. The existing bounded framing state machine now validates inbound
ownership as well as outbound mutation. Inbound bodies must be complete,
framing must be unambiguous, and no trailing request or upgrade is allowed.
Existing W3C headers are permitted for this validation and separately parsed.
Server response writes continue to end ownership.

Attach thread exit and process exec cleanup probes whenever mutation is enabled.
They remove thread context, pending mutation and pending read state inside the
kernel, independently of event delivery. Threads destroyed by exec run exit
cleanup; the exec probe clears both the surviving thread's current key and its
pre-exec TID from `sched_process_exec.old_pid`. A nonleader exec changes TID,
so clearing only the current key would retain stale ownership. This fences PID/TID reuse
without retaining historical application state. Logical async task reuse is
outside this same-thread contract.

Both thread continuation and pending mutation require a nonzero monotonic
timestamp no later than now and strictly less than the configured TTL old.
The TTL boundary expires state. Expired pending mutations bypass without
changing application bytes or claiming an injected span.

After a successful `bpf_msg_push_data`, every failure attempts
`bpf_msg_pop_data` on precisely the inserted range. Successful rollback passes
the original message and clears generated span ownership; failed rollback
drops the message to avoid sending partially written or uninitialized bytes.
The existing post-push failure counter remains a promotion blocker even when
rollback succeeds. Append `rolled_back`, `rollback_failed` and `context_expired`
diagnostics without changing native signal schema version 1.

## Qualification

The [Tempo tree validator](../../scripts/qualify_propagation_tempo.py) belongs
to the consumer/backend boundary. It checks an independent expected set of
trace IDs, span IDs, parent IDs, names, kinds and service owners. Missing,
extra, duplicate, cyclic and cross-request spans fail. Saved JSON mode is
fixture/replay evidence, never proof that Tempo stored fresh telemetry.
Read-only Tempo query mode saves verified expected trees and response checksums;
arbitrary backend attributes are never persisted. Its result proves
only the queried trees, not wire behavior, runtime support, safety or overhead.

Reference execution cells for repository tests are synchronous plaintext
HTTP/1 scalar writes and bounded `sendmsg` writes through the existing Python
fixture. These are development choices, not declared Guara deployment cells.
Existing application context remains application-owned, including applications
whose SDK propagates over TLS/HTTP2/gRPC or across async handoffs. Coexistence
continues to use ADR 0017's explicit ownership or positive detection evidence.

TLS/HTTP2/gRPC mutation, segmented headers, pipelining and unknown async
handoffs bypass the existing mutation boundary. Observation alone cannot
establish a safe injection seam. Their required Guara cells still need exact
runtime/build identities and independent implementation slices. This ADR does
not declare them implemented or exclude them from Guara's eventual contract.

## Consequences

No dependency, runtime plugin, deployment or startup-setting change is added.
The new rollback helper and lifecycle probes need fresh privileged verifier,
wire, restart/reuse, concurrency and overhead evidence before promotion.
Local builds and deterministic tests cannot close issue #51's live criteria.
