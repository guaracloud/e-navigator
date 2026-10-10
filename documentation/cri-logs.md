# CRI application log collection

The opt-in `source.cri_logs` source collects retained Kubernetes CRI files using
the [ADR 0018 contract](adr/0018-cri-log-collection.md). It requires a Unix host
and a CRI log directory with the standard Kubernetes pod directory layout.
Default paths target Linux nodes. Paths must be absolute and contain no symlink
components; on macOS fixtures use canonical `/private/...` paths.

## Enable repository deployment assets

In the chart's `config.toml` or static ConfigMap, set `[cri_logs] enabled = true`
and enable the existing `[[modules]] name = "source.cri_logs"` row. Keep
`include_body = false` for metadata-only collection. Set it to true only when
internal bounded payload capture is needed; JSON stdout still omits bodies.
Redacted backend export is a separate implementation in #55.

For Helm, also set `criLogs.mountsEnabled = true`. This adds exactly two mounts:
read-only `/var/log/pods` and writable node-local `/var/lib/e-navigator/cri-logs`.
For static manifests, the optional strategic merge patch is
[cri-logs-mounts.yaml](../deploy/kubernetes/optional/cri-logs-mounts.yaml). Apply
it to the DaemonSet as part of an authorized deployment after updating the
ConfigMap. The patch is not a standalone Kubernetes resource.

The default chart adds neither mount. Mounts and config are separate to preserve
custom `config.toml` ownership. Custom roots require corresponding deployment
mount edits. Do not mount all of `/var/log` or `/var/lib`. Existing checkpoint
storage must be writable by the agent and inaccessible to untrusted users.
No Kubernetes RBAC or workload startup changes are needed for file collection.

## Tune retention and budgets

```toml
[cri_logs]
enabled = true
include_body = false
root = "/var/log/pods"
checkpoint_dir = "/var/lib/e-navigator/cri-logs"
initial_read = "beginning"
poll_interval_millis = 1000
assembly_timeout_millis = 5000
retained_file_millis = 300000
max_files = 128
max_discovery_entries = 4096
max_record_bytes = 16384
max_read_bytes_per_file = 65536
```

Choose `beginning` to recover retained pre-start and exit-final records. `end`
skips preexisting bytes during the initial discovery traversal; subsequent new
instances start from the beginning. Valid saved offsets always take precedence.
Retain uncompressed files long enough for the poll/discovery, backlog and restart
horizons. A slow consumer delays polling and source commit; it cannot create
unbounded source state. File/discovery limit warnings require budget adjustments
or a smaller selected log directory. This first source has no live-pod filter.

Native observations expose `truncated`, `incomplete`, `invalid_utf8`, and
`body_bytes`, even when bodies are omitted. Native collection warnings expose
unsupported input, oversized records, reset/replay, state limits, unsafe paths,
retention expiry and rejected checkpoints. Source read/persistence failures are
also reported by existing source supervision. Warnings do not contain payloads.

## Recovery

Keep `checkpoints.json` and its directory on node-local persistent storage across
agent restarts. Do not share the directory between writers. The source holds
`lock`, and recovers only the bounded version-1 snapshot. Orphan
`checkpoints.tmp` files are ignored and replaced on the next commit. A malformed
snapshot produces `checkpoint_rejected` and beginning replay. Future unsupported
snapshot versions also cause visible beginning replay; preserve the old snapshot
before upgrades if replay is unacceptable.

To intentionally reset collection, stop the agent, preserve a copy if needed,
and remove only `checkpoints.json` and `checkpoints.tmp` from its dedicated
directory. Restart under the chosen initial policy. Never delete a live writer's
lock file. Deleting source files before collection or expiry of absent-file
retention can cause unrecoverable loss. Copy-truncate with identical consumed
anchor bytes is inherently undetectable by this bounded identity check.

Checkpoints prove source-channel admission, not backend storage. They offer
source-position crash recovery, with replay duplicates around incomplete
assemblies and commits. Durable redacted spool acceptance and backend delivery
remain #55/#56. Do not use this source's read checkpoint to claim durable delivery
or completed Guara replacement qualification.
