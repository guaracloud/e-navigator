# ADR 0018: Bounded CRI application log collection and read checkpoints

- Status: accepted
- Date: 2026-10-10
- Scope: [issue #54](https://github.com/guaracloud/e-navigator/issues/54)

## Decision

Add the statically registered `source.cri_logs` host source. It is disabled by
both module and source configuration by default. It reads regular files in
`/var/log/pods/<namespace>_<pod>_<pod-uid>/<container>/<restart-count>.log`
and uncompressed `.log.<rotation>` files. Discovery does not consult live pods
or PIDs, so retained files from exited containers remain eligible. The instance
identity is pod UID, container name and restart count; filesystem device/inode
identity distinguishes rotation and replacement within an instance. Pod names
alone never identify an instance. Runtime container IDs and Kubernetes API
metadata enrichment belong to #55.

The initial policy is `beginning`: drain retained files from offset zero unless
a valid checkpoint exists. `end` skips preexisting bytes during the first full
discovery traversal only. Files discovered in subsequent traversals start at
zero, including crash-final records from new container instances. A valid
checkpoint overrides either policy. Deployments needing historical retention
must retain their uncompressed files for the declared recovery horizon.

The source parses UTC RFC3339 CRI timestamps through nine fractional digits,
`stdout`/`stderr`, and `P`/`F` tags. Event time preserves original precision;
observed time records collection time. Partial fragments are assembled separately
per file and stream. UTF-8 decoding follows assembly, permitting split codepoints.
Invalid UTF-8 is replaced and flagged. Invalid calendars, non-UTC timestamps,
Docker JSON, unknown stream/tag and compressed archives are unsupported; parsing
failures emit a fixed native warning without content or path disclosure.

Default limits are 128 files/checkpoint entries, 4096 discovery entries per poll,
16 KiB per physical record and assembled body, 64 KiB read per file per poll,
a one-second poll, a five-second assembly timeout, and five-minute absent-file
retention. Config validates nonzero limits, their relationships and upper bounds;
`max_files * max_record_bytes` cannot exceed 8 MiB. Each tracked file holds one
physical-line buffer and at most two partial bodies. The read buffer is transient
per file. A poll admits at most about 1024 ordinary records/warnings plus bounded
discovery and expired-file outcomes, then rotates file scheduling to prevent one busy file starving others.
Discovery resumes a depth-first traversal with at most three open directory
iterators, so reaching the work budget cannot permanently hide later entries.

A physical record exceeding its budget is discarded through LF with a
`record_too_large` warning. Assembly overflow preserves a bounded prefix and sets
`truncated`; timeout, malformed gaps and retained-file expiry set `incomplete`.
An exit-final physical line lacking LF is emitted as incomplete after timeout.
File/discovery saturation and unsafe paths are explicit warnings. Retention
expiry releases absent files and checkpoints, with an explicit warning. State
capacity can delay new files until absent instances expire; operators must size
file and retention budgets for churn. No silently unbounded cache is introduced.

## Privacy boundary

This adds additive schema-v1 `application_log_observation` and
`log_collection_warning` families. `body` is nullable. `include_body = false`
omits payloads by default while preserving byte counts, stream, identity,
timestamps and loss flags. Explicit `include_body = true` permits bounded raw
payloads only on the internal native pipeline for subsequent processing.
Signal debug formatting omits bodies, checkpoints contain no bodies, warnings
contain fixed reasons, and the JSON stdout sink always omits application bodies.
Existing OTLP encoders do not export this new family. This scoped extension to
ADR 0001 permits collection, not unrestricted external payload export.

Redaction, structured/multiline processing, Kubernetes enrichment and an
independent external log worker remain #55. Sensitive unredacted bodies must not
enter the durable spool in #56. Those issues must retain the safe stdout behavior
and introduce explicit redaction/export acceptance fixtures before export.

## Checkpoint and crash boundary

One writer holds an advisory filesystem lock in the checkpoint directory.
Directory traversal and file opening use descriptor-relative, no-follow opens,
including every absolute path component. Roots cannot overlap or contain
traversal. Files must be regular, and FIFO opening is nonblocking. Newly created
checkpoint directories are mode 0700; files are mode 0600. Existing directories
must be operator-controlled. Logs are mounted read-only; only the dedicated
checkpoint directory is writable. No new capture privilege or API permission is
required.

A checkpoint advances only after every observation/warning in the poll batch
has been admitted to the bounded source channel. Its offset stays at the earliest
unfinished physical line or partial assembly, so restart can reconstruct pending
content from the original file without writing payloads to disk. Completed
records from the other stream after that offset may be replayed. A crash before
commit also replays already admitted records. Delivery is therefore potentially
duplicated and reordered across files. No exactly-once guarantee is made.

The versioned snapshot records instance/device/inode keys, offsets, last-seen
times and bounded prefix/tail hashes. Write a temporary snapshot, sync its data,
atomically rename it over the old snapshot, then sync the directory. Orphan temp
files are ignored during recovery. Checkpoint corruption or version/bounds
mismatch is visible and forces beginning recovery. Snapshot size/entry count are
bounded; unseen saved entries retain their startup recovery eligibility throughout the
initial traversal, then undergo absent-file retention cleanup. Unsupported storage sync/rename behavior or persistence failure fails
the source visibly instead of claiming a saved offset.

Open handles survive rename and unlink until the absence horizon; newly rotated
files are discovered separately. Shorter files or changed consumed-prefix/tail
anchors trigger beginning replay and `file_reset`. Anchors also detect typical
copy-truncate followed by regrowth and inode reuse. They are not cryptographic
integrity or a guarantee against truncation/regrowth that reproduces identical
anchor bytes. A record deleted before discovery or beyond the retention horizon
cannot be recovered. Cross-file order and concatenation across different rotated
files are not promised; incomplete fragments remain explicit.

**Read checkpointing is not durable delivery.** The channel and existing workers
are volatile. A crash after source commit can lose admitted records downstream.
#55/#56 must coordinate a redacted spool acceptance/acknowledgement boundary if
durable delivery is required; this source's admission checkpoint cannot be reused
as backend acknowledgement without changing its lifecycle and tests.

## Deployment and validation

See [CRI collection operations](../cri-logs.md). Fixture-backed tests exercise
parsing, bounds, malformed gaps, UTF-8, offsets, retained exit-final files,
rotation/replacement, replay, corrupted snapshots, temp snapshots, lock/symlink
rejection and churn. Golden native schema and configuration tests preserve the
additive contract. Helm checks render both disabled and mount-enabled variants.
These are repository execution evidence; they do not qualify an exact Guara
workload cell or establish Kubernetes/backend live proof. The missing-input
register in the replacement contract continues to govern production qualification.
