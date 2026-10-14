# Durable OTLP export operations

[ADR 0021](adr/0021-durable-otlp-spools.md) defines opt-in restart buffering for
metrics, traces, profiles and processed application logs. All defaults remain
volatile. The production family selection, outage horizon, privacy policy,
retention and recovery thresholds still require IN-05/IN-06 approval from the
[replacement contract](replacement-acceptance.md).

## Configure and mount

Keep the existing `sink.otlp_http` module and family configuration enabled. Select
only families requiring persistent buffering:

```toml
[otlp_http.durable]
families = ["logs"]
directory = "/var/lib/e-navigator/spool"
max_bytes = 67108864
max_entries = 4096
max_age_millis = 3600000
```

Logs also require the [CRI source](cri-logs.md) and [privacy processing](log-export.md).
The packaged `[otlp_http.durable]` table selects no families by default. Validate
configuration with `--validate-config` before an authorized deployment. Limits are
per selected family. The defaults are not production outage guarantees. Capacity
in records is bounded by both segment count and encoded bytes; estimate the outage
budget from the measured arrival rate and mean encoded size, then verify recovery
throughput exceeds sustained arrivals. Each segment holds one request/record;
durable mode prioritizes a simple recovery contract over batch throughput.

For Helm, set `durableSpool.mountsEnabled=true` along with the TOML settings. The
chart renders a writable node hostPath at `/var/lib/e-navigator/spool`. The optional
static strategic merge patch is
[durable-spool-mount.yaml](../deploy/kubernetes/optional/durable-spool-mount.yaml).
Apply it only as part of an authorized deployment. It adds storage, no privileges,
RBAC or source log write permissions. CRI checkpoint storage must also persist.
For a custom directory, provide a matching mount explicitly.

Pre-create the host spool parent with mode 0700 and ownership matching the agent
UID. Family subdirectories and private files are created by the agent. Existing
family directories/files must deny group/other access. Use a local filesystem
with supported fsync/rename/locking and reserve capacity for all selected families.
A node hostPath survives container restart on that node; it does not survive node
storage loss or follow workloads between nodes. Do not use ephemeral `emptyDir`
for a restart guarantee. Never run two writers on the same family directory.

## Check delivery and storage health

Scrape native Prometheus metrics without relying on the OTLP destination:

- `e_navigator_export_spool_bytes` and `_entries` show occupied capacity.
- `e_navigator_export_spool_accepted_total` counts successful synced appends.
- `e_navigator_export_spool_recovered_total` counts segments loaded at startup.
- `e_navigator_export_spool_rejected_total` counts failed new admissions, including
  capacity, encode and storage failures; `_errors_total` counts storage errors.
- `e_navigator_export_spool_expired_total` counts age eviction.
- Existing request/retry/partial/rejected/permanent/drop counters expose backend
  and pre-append channel losses. `sent_total` means HTTP acknowledgement, not
  retained/queryable data.

All use the bounded `signal_family` label. On ENOSPC or saturation, accepted data
remains and new appends fail. Durable CRI receipt failure preserves the previous
checkpoint and fails the log source visibly. Correct the cause, retain source
files, and restart the source/agent through the normal authorized operation.
Previously accepted logs may replay and duplicate. Source failures still follow
`source_supervisor.failure_policy`: the default `fail_fast` stops the runtime;
select `isolate` when healthy sources must continue after a log-source failure. A quiet/full spool with storage
errors requires operator attention; a runtime read or acknowledgement I/O error stops
that family's delivery and rejects new admission. Other families remain independent.

## Upgrade and recover

1. Stop the agent and ensure the writer lock has been released. Never edit or
   delete a live spool. Preserve both log source files and CRI checkpoints.
2. Back up the complete private spool directories with permissions intact.
   Do not put spool bytes in public tickets or logs. They contain protected data.
3. Keep the same endpoints, privacy policy, selected families and sufficient byte,
   count and age budgets during restart. Changing a destination sends retained
   requests to the new endpoint. Changing privacy rules does not redact retained
   requests again. Disabling a family leaves its spool untouched until re-enabled;
   its records can expire on later recovery.
4. Run the new binary against the existing version-1 format. Unsupported versions,
   checksum/truncation failures and smaller-than-existing limits fail closed.
   Restore the compatible binary/budgets or an intact backup. Do not reinterpret
   an unknown version or truncate a corrupt accepted segment to force recovery.
5. Verify recovery/occupancy/error metrics and backend queries separately. HTTP
   delivery success alone is insufficient to establish retention or replacement
   qualification. Observe duplicate/reordering expectations in the declared cell.

Only unaccepted `pending.tmp` is automatically removed at startup. Accepted
corruption requires deliberate operator recovery. CRC32 is accidental-corruption
detection, not authentication. Preserve source logs within their recovery horizon.
Spool restoration from backup can replay requests already acknowledged elsewhere.

## Deliberate spool deletion

Deletion loses any accepted request still pending. Stop the agent, record the
family and loss decision, and preserve a protected backup if recovery is wanted.
Delete that family's `.spool` segments or entire family directory only while the
writer is stopped. Restart with the intended configuration and verify empty
occupancy plus native health. Do not delete CRI checkpoints to clear exporter
storage: their lifecycle is separate. Retaining checkpoints after deleting a log
spool means those records will not be recovered from already committed source
offsets. Resetting checkpoints deliberately can replay retained raw source files
through the current privacy policy and duplicate prior deliveries. Both actions
require an explicit operator loss/replay decision.
