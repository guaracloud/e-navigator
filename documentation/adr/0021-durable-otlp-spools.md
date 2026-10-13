# ADR 0021: Opt-in independent durable OTLP spools

- Status: accepted
- Date: 2026-10-13
- Scope: [issue #56](https://github.com/guaracloud/e-navigator/issues/56)

## Decision and required families

Add `otlp_http.durable` to the existing static sink, with an empty `families`
list by default. Operators select only enabled OTLP families whose declared
contract requires durability: `metrics`, `traces`, `profiles`, `logs`. Each owns
an independent bounded admission channel, spool directory, filesystem lock and
HTTP delivery loop. Volatile families retain ADR 0004 behavior. No producer,
consumer query or native signal schema changes are required.

IN-05/IN-06 still lack production durability and outage requirements. The defaults
are implementation limits, not approved production thresholds. Select budgets
from the approved per-family arrival rate, outage horizon and recovery deadline.
Local fault fixtures validate collector behavior; they do not qualify GW-LOG or
prove deployed backend retention. Issue #55's live query criterion remains open.

## Acceptance and delivery contract

| Family | Acceptance with durability selected | Delivery and bounds |
| --- | --- | --- |
| Metrics | A mapped, timestamp-coalesced OTLP request synced into the metric spool | Coalescer and admission before append remain volatile; its suppression/ordering counters still apply |
| Traces | A validated mapped OTLP request synced into the trace spool | Pre-append channel admission is volatile; invalid identity remains rejected |
| Profiles | A mapped OTLP request synced into the profile spool | Pre-append channel admission is volatile; unresolved frames retain existing outcomes |
| Logs | A privacy-processed and mapped OTLP request synced into the log spool | CRI checkpoints wait for every log receipt in the poll batch; failed/missing receipt fails that source without committing its new offsets |

Queue admission is nonblocking and sheds newest work when full or closed, with
existing native counters. Disk work runs on Tokio's blocking pool, concurrently
with HTTP within that family. A slow log disk can pause that source while it
waits for acceptance, but neither disk nor destination I/O runs on the shared
signal path. The source waits at most 30 seconds per outstanding receipt; an
uncertain late append can duplicate a record after source restart. Restart the
failed source/agent only after correcting capacity, configuration or storage.
The existing source supervisor policy remains authoritative: `fail_fast` stops
the runtime on source failure, while `isolate` continues healthy sources.

Once durably accepted, oldest requests replay after restart and retry through
transport failure, timeout, retryable HTTP status, invalid response and compression
failure until terminal acknowledgement or age expiry. Existing bounded HTTP
retries, response limits and optional gzip are reused. A failed retry cycle pauses
for `circuit_breaker_cooldown_millis`, leaving disk admission independent. Durable
mode does not shed already accepted work when its circuit opens. Its retry-cycle
pause applies immediately, independently of the volatile circuit threshold.
Shutdown drains admitted work, but keeps transiently failed requests for restart;
the existing shutdown deadline bounds waiting.

A valid HTTP 200, including partial success, is terminal. Partial rejection is
counted and never retried. Permanent HTTP rejection removes the request and counts
loss. HTTP acknowledgement does not prove retention/queryability. Delivery is
at least once for durably accepted requests within storage/age limits, subject to
explicit permanent/partial rejection and storage failure. There is no exactly-once
guarantee. A crash between backend acceptance and local deletion may duplicate a
request. CRI replay before source checkpoint fsync may duplicate even after local
spool acknowledgement. Ordering is only append order within each spool during
normal replay; source replay, metrics coalescing, separate families and backend
behavior may reorder observations.

## Format, crash consistency and recovery

Use one uncompressed OTLP protobuf request per immutable `.spool` segment. This
reuses the installed protobuf encoder and flate2 CRC32 implementation. No new
serialization or database dependency is introduced. A 36-byte little-endian
header contains the eight-byte magic/version `ENSP0001`, creation time in Unix
milliseconds, input record count, body length and CRC32 over the preceding header
bytes plus body. Filenames are monotonic 16-digit hexadecimal sequence numbers.
CRC32 detects accidental corruption, not malicious tampering.

Append writes a private `pending.tmp`, syncs its data, renames it into sequence,
then syncs the directory before completing a durable receipt. Acknowledgement
unlinks the segment and syncs the directory. An orphan temp is unaccepted and
removed during recovery. A segment present after an uncertain append may replay;
an uncertain delete may also replay after a crash. No accepted segments are
silently overwritten. Recovery validates every segment and configured bounds,
including checksums and version, before starting delivery. Corrupt, truncated,
unknown-version, unsafe or over-budget spools fail startup visibly and preserve
segments for operator recovery. Runtime read or acknowledgement storage errors stop delivery and reject new
admission for that family, preserving remaining data. No body is written to a dead letter
or error log.

Spools require Unix filesystem support with reliable file/directory fsync,
atomic rename, unlink and advisory locks. Every path component and opened file
uses descriptor-relative no-follow access; nonregular files and hard links are
rejected. Newly created directories are 0700, files 0600. Existing final family
directories/files must deny group/other access and be controlled by the agent's
operator. One writer holds each family's lock for its lifetime. Node loss or loss
of the mounted storage is outside this guarantee.

## Limits, privacy and observable outcomes

Each selected family defaults to 64 MiB, 4,096 segments and one hour maximum age.
Validation allows 1 byte through 1 GiB, 1 through 65,536 segments and 1 millisecond
through seven days. Each segment, including its header, is at most 4 MiB. Stored
requests and an in-progress append together respect the configured byte budget.
Recovery retains bounded metadata; delivery reads only one bounded request. Memory
also includes the existing per-family admission queue, original mapped record,
encoding/copy and compression buffers. Logs retain the existing 128 MiB queue/body
budget. Four selected families have four separate disk budgets.

Storage saturation or ENOSPC rejects new appends; accepted requests remain. Oldest
expired requests are removed with an expiry counter before the next delivery
attempt, including after restart. Cleanup can be delayed by a bounded HTTP retry
cycle/cooldown. Age uses wall time: clock rollback delays expiry; forward jumps
can expire requests. Disk bounds still apply. One request per segment deliberately
trades batching throughput for the smallest crash-consistent implementation;
measure before introducing multi-record journal compaction.

Raw log bodies never enter the spool. Mapping requires the existing processing
metadata and privacy budgets; omission/redaction runs earlier in the pipeline.
The internal receipt is absent from native JSON/schema and Debug output. Stdout
continues to omit application bodies and processing metadata. Recovered bytes
retain the original applied policy; changing redaction policy does not reprocess
already stored requests. Spools must therefore remain protected data.

Native Prometheus metrics retain `signal_family` and existing request, retry,
rejection and queue counters. Additional `e_navigator_export_spool_*` metrics
expose accepted/recovered/rejected/expired records, storage errors, bytes and
entries. Startup failures expose a fixed module error without contents or paths.
See [durable export operations](../durable-export.md) for recovery and deletion.

## Validation

Fault fixtures cover append/write/rename/ack boundaries, ENOSPC, unaccepted temp
cleanup, restart replay, corrupted/truncated/unknown-version segments, bounds,
expiry, locking and filesystem privacy. Loopback tests cover backend recovery,
permanent and partial rejection, protected on-disk logs, saturation receipts and
independent metrics/trace/profile delivery during slow log HTTP. CRI fixtures
verify that checkpoints wait for receipts and rejected acceptance replays retained
records. Config goldens and Helm/static mount rendering cover opt-in packaging.
None of these tests is privileged Linux, Kubernetes or deployed backend proof.
