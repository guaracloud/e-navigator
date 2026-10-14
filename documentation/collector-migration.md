# Collector qualification and migration runbook

Scope: [issue #57](https://github.com/guaracloud/e-navigator/issues/57), replacing
the declared Beyla, Alloy CPU profiling and application log collection workflows.
Loki storage and query replacement remains RFC #58. This runbook changes no
deployment and grants no live-run authorization.

## Current decision

**Do not cut over. No production cells are qualified.** IN-01 through IN-07 in
the [acceptance contract](guara-replacement-acceptance.md) remain unresolved.
The [workload ledger](guara-workload-matrix.md) owns exact supported cells and
exclusions. Closed implementation issues and fixture PASS do not promote cells.
Issue #49 lacks required protocol qualification; issue #55 lacks deployed log
query proof. The historical full-stack benchmark is invalidated by missing Redis
coverage, as recorded in [ADR 0014](adr/0014-controlled-head-to-head-benchmark.md).

## Prepare the approved change record

Before live execution, the replacement decision owner must approve a versioned
record containing all of the following. Missing entries stop the campaign.

- Resolved IN-01 through IN-07, named owners, exact cell IDs, required families,
  approved exclusions and public workload contract revision.
- Authorized target, node/namespace allowlist, kernel/BTF/cgroup/security cells,
  execution window, mutation permissions and cleanup authority.
- Immutable workload, reference collector and candidate digests; complete
  configurations, source revision, sample rates, placement and backend identities.
- Independent workload oracles, load seeds/windows and approved numerical
  thresholds for coverage, stacks, loss, attribution freshness, CPU/RSS,
  throughput, latency, retention, outage and recovery.
- GQ consumer query records with original and native expressions, units, labels,
  windows, expected answers and owner approval. Keep translation in the backend
  or consumer, per [ADR 0001](adr/0001-standalone-native-contracts.md).
- Exact restoration artifacts for the previous collectors: image digests,
  manifests/chart versions, values, discovery filters, sampling, endpoints,
  checkpoint/storage locations and reconciliation policies. Store secrets in
  the existing protected system; reference them without copying secret values.
- Per-family delivery guarantees, duplicate/order bounds, source-file retention,
  spool capacity/age, outage horizon and a measured recovery deadline. Record
  who can stop the rollout and who restores the previous deployment.

Configuration examples are implementation defaults, never acceptance thresholds.
Validate candidate TOML using the pinned CLI's `--validate-config --config` and
render the chosen chart before deployment. Follow [Helm configuration](helm.md),
[log processing](log-export.md) and [durable export](durable-export.md).

## Qualify before comparing performance

1. Run `scripts/quality.sh` at the candidate revision. Record output and exact
   reasons for constrained skips. Local checks do not qualify a live cell.
2. Use the existing authorized [benchmark harnesses](benchmark.md) and the
   [replacement suite](issue-48-replacement-qualification.md). Run no-agent,
   deployed Beyla plus Alloy plus the declared log collector, and E-Navigator
   arms with identical workloads, placement, offered load, sample rates,
   required signal coverage and backend settings. Record intentional differences.
3. Check each required family's independent counts, outcomes, parentage, log
   processing, attribution freshness and profile stack/weight quality first.
   Missing Redis or any other required family invalidates the comparison even
   when aggregate telemetry is present. Retain failed trials and diagnostics.
4. Run normal, concurrent, pooling, retry/reconnect, process restart, agent
   restart, late attachment, privacy and unsupported-version cases. Add the
   approved sustained-load, churn, saturation and outage/recovery trials for
   every required kernel/capability cell. Attachment-forward observations must
   not fabricate history; retained CRI replay has its own source horizon.
5. Query stored data in the real backends. Verify exact identities, outcomes,
   parentage, profile weights and processed log contents. Verify retention,
   expiry and required Grafana navigation with the
   [backend qualification workflow](issue-53-backend-qualification.md).
   HTTP acceptance is insufficient. Required exact trace-to-profile execution
   ownership is unsupported unless separately established for the declared cell.
6. Only after equal per-family coverage passes, compare agent and total-node
   CPU/RSS, throughput and latency against approved thresholds. Name the measured
   resource scope; container sums are not total host utilization. Use matched
   repeated windows and report variability, sample count and uncertainty.
7. Reject any required skip, unsupported cell, threshold failure or missing
   consumer assertion. Publish exclusions only with owner approval and the
   matching public workload contract. Never drop a failed cell to obtain PASS.

The existing runners evaluate evidence without deploying workloads:

```sh
python3 scripts/qualify_replacement.py \
  --manifest /path/to/approved-manifest.json \
  --capture /path/to/recorded-capture.json \
  --endpoints /path/to/backend-endpoints.json \
  --authorization /path/to/target-authorization.json \
  --output /path/to/replacement-result.json
python3 scripts/qualify_backends.py \
  --manifest /path/to/backend-manifest.json \
  --evidence /path/to/backend-evidence.json \
  --endpoints /path/to/backend-endpoints.json \
  --authorization /path/to/target-authorization.json \
  --output /path/to/backend-result.json
```

Runner PASS deliberately leaves `replacement_qualified: false`. The decision
owner must review original execution artifacts and the additional production
trials. Archive sanitized commands, times, image/config/build digests, kernel
identity, workload oracles, raw measurements, counters, stored query responses,
UI recordings and results in immutable storage with SHA-256 checksums. Keep
protected spool contents and credentials out of the published bundle.

Before reviewing the replacement decision, run the
[issue-46 campaign gate](issue-46-replacement-campaign.md) against that archive.
It replays the capability assertions from preserved responses, checks matched
per-cell production measurements against approved thresholds, and requires
consumer results and delivery-accounted rollback records. Campaign PASS still
requires review of original execution recordings; it does not authorize cutover.

## Coexistence and staged cutover

1. Restore-test the previous collector artifacts on the authorized target before
   removing them. Check their queries and loss/health counters against an
   independent workload oracle. Record restoration time and delivery gaps.
2. Assign one authoritative writer per signal/workload and one propagation
   mutator. During shadow measurement, isolate candidate ingestion/query selectors
   from reference dashboards and alerts so duplicate telemetry cannot inflate
   results. Do not run two processes against the same spool or CRI checkpoint.
3. Keep `[http_source.context_propagation] enabled = false` during shadow capture.
   Enable mutation only for an explicitly approved and qualified cell after the
   previous mutator is disabled. Preserve application context and use the
   documented [SDK coexistence](adr/0017-otel-zero-code-coexistence.md) ownership
   policy; suppression requires its documented positive evidence or explicit
   ownership configuration, never a generic environment-variable guess.
4. Start with the approved canary nodes and workload cells. Keep previous
   collectors available throughout the approved observation window. Check
   per-family coverage, queries, attribution, stacks, native loss and spool
   health before each expansion. The decision owner signs each stage's results.
5. Switch one declared consumer mapping at a time. Verify the GQ expected answer
   and alert behavior before changing the next mapping. Record the switch time
   and retain the original dashboard/query revisions for restoration.
6. Expand only when all required canary checks pass. Stop the previous writers
   only after the candidate owns the selected workflows, delivery continuity
   has been demonstrated and rollback remains within the approved horizon.
   Approve and record changes to GitOps reconciliation separately.

Use sustained per-family arrivals and encoded request sizes to size durable
buffers. Recovery throughput must exceed arrivals. Keep CRI files and checkpoint
storage persistent over the rollback horizon. A node hostPath cannot guarantee
delivery after node-storage loss; exclude that guarantee explicitly or provide
and qualify appropriate storage before cutover.

## Stop conditions and rollback

Stop expansion immediately on a failed required query/family, privacy violation,
wrong parentage/ownership, unapproved attribution or stack degradation, exceeded
loss/overhead/latency thresholds, spool storage errors, or insufficient remaining
source/spool retention for recovery. Notify the named change owner through the
approved operational process. Record counters and sanitized evidence first.

1. Restore original consumer queries and alert revisions. Disable candidate
   context mutation before restoring the previous propagation mutator.
2. Restore the pinned previous collectors and reconciliation policy from the
   change record. Verify discovery, sampling, source ownership, backend queries
   and health using the independent oracle. Explicitly measure any capture gap.
3. Preserve pending candidate delivery. For durable families, keep the compatible
   E-Navigator binary delivering to the original destination until accepted
   requests drain, with capture ownership isolated from the restored collectors.
   If a validated drain configuration is unavailable, stop and preserve the
   complete spool/checkpoint directories and recover with the same compatible
   configuration on the authorized node. Never share a spool writer lock.
4. Keep endpoints, applied privacy policy and sufficient spool age/byte/count
   limits during recovery. Do not delete spools, reset CRI checkpoints, change
   destinations or reinterpret incompatible segments to force a clean status.
   Previously processed spool contents are not redacted again by a new policy.
5. Query stored data across the cutover and recovery windows. Reconcile accepted,
   acknowledged, rejected, expired and replayed records against the oracle.
   Verify recovery finishes inside the approved retention/recovery deadlines.
   Preserve protected backups until pending accepted work has been accounted for.

Restoring Beyla/Alloy does not transfer E-Navigator's pending OTLP spool to them.
Durable delivery is at least once within the documented bounds, with possible
duplicates after uncertain acknowledgement or CRI replay. Permanent/partial
rejection, expiry and storage loss remain explicit loss outcomes. Volatile
pre-append admission is outside the durable acceptance guarantee. A rollback
that exceeds these limits fails qualification; report the gap rather than
claiming lossless restoration. See [ADR 0021](adr/0021-durable-otlp-spools.md).

## Publish the decision

Publish the exact passing cells and exclusions in the ledger and update
[capabilities](capabilities.md) only to the evidence tier actually demonstrated.
Include immutable artifact references, commands, uncertainty, consumer migration
results and the executed restoration drill. Mark #57 complete only after every
required cell, production trial, stored query and delivery-preserving rollback
passes. Until then, this document supplies the procedure, not production proof.
