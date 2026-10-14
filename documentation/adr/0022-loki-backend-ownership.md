# ADR 0022: Loki backend ownership and replacement requirements

- Status: proposed RFC; backend selection and cutover blocked
- Date: 2026-10-13
- Scope: [issue #58](https://github.com/guaracloud/e-navigator/issues/58)
- Prerequisite: [#47](https://github.com/guaracloud/e-navigator/issues/47), completed inventory contract with named missing inputs
- Owning source rechecked: E-Navigator `6a00abd`, [architecture](../architecture.md), [boundaries](../boundaries.md), [ADR 0001](0001-standalone-native-contracts.md), [ADR 0020](0020-processed-otlp-logs.md), and [ADR 0021](0021-durable-otlp-spools.md)

## Recommendation and boundary

Retain Loki until a separately operated backend passes the requirements below.
E-Navigator owns collection, bounded privacy processing, workload enrichment,
and independent OTLP export. Historical storage, indexing, LogQL, alert
execution, tenant authentication and Grafana query APIs belong outside the
privileged agent. Preserve the static Source -> Processor -> Generator -> Sink
pipeline, bounded state, versioned native schemas and explicit loss/confidence
outcomes. Vendor translation belongs in consumers or backends under ADR 0001.

This RFC completes a planning artifact, not a Loki replacement. Collector
replacement under [#46](https://github.com/guaracloud/e-navigator/issues/46)
and [its contract](../guara-replacement-acceptance.md) remains independent.
No backend implementation, deployment, infrastructure change or production
acceptance is authorized or implied.

## Required inventory and missing inputs

No authorized deployed Loki inventory was supplied. Repository manifests and
historical benchmarks cannot establish current consumers or SLOs. Every row
below is missing, not an assertion about production. Roles require accountable
people assigned by the Guara decision owner. Supply sanitized artifact paths,
immutable revisions, observation dates, approving people and explicit
required/optional/excluded classification. Reuse collector inputs IN-04 through
IN-06 where they overlap. Never store credentials or raw sensitive logs here.

| ID | Required input | Responsible owner role |
| --- | --- | --- |
| LB-01 | Loki digest/version, topology, storage/index schema, enabled APIs, ingress paths, Grafana/data-source/plugin versions | Platform deployment owner |
| LB-02 | Every dashboard panel, recording rule, alert, API client, saved search, Explore link and automation; exact LogQL, variables, windows, units, expected results and alert transitions | Observability consumer owner |
| LB-03 | Tail consumers, filters, ordering, reconnect/resume, cancellation, concurrency and acceptable gaps | Observability consumer owner |
| LB-04 | Per-tenant sustained/peak bytes and records per second, record sizes, stream/label cardinality and churn, query ranges/concurrency and growth horizon | Backend capacity owner |
| LB-05 | Per-tenant retention, deletion deadlines, legal holds, backup expiry and redaction policy, including indexes/caches and audit evidence | Data governance owner |
| LB-06 | Tenant identity authority, authenticated ingress/query mapping, RBAC, credential lifecycle, network boundaries, encryption/key custody and audit access | Security owner |
| LB-07 | Ingest acknowledgement, loss/duplicate/order semantics, late data, availability window, ingest-to-query/query/tail latency, outage duration, RPO and RTO | Backend SLO owner |
| LB-08 | Authorized isolated qualification target, fixtures, numeric thresholds, measurement windows, resource/cost ceilings and rollback window | Guara replacement decision owner |

Each consumer needs a stable ID, a bounded sanitized fixture, expected record
identities/timestamps/aggregates, and a backend mapping or approved migration.
Inventory completion requires zero unclassified consumers. Missing inputs block
selection and cutover, but do not block RFC review. Production values must be
approved rather than invented.

## Alternatives and evidence

| Alternative | Benefit | Tradeoff and unverified capabilities | Disposition |
| --- | --- | --- | --- |
| Retain Loki | Preserves existing consumer contracts and avoids immediate migration | Current capacity, configuration, durability, isolation and recovery still need inventory and execution evidence | Recommended baseline while inputs are missing |
| Separately owned backend, including Positron if selected | May reuse an existing log database while keeping database ownership outside the agent | Must prove ingest, query/aggregation, tail, quotas, isolation, deletion, recovery and Grafana; no assumed LogQL parity | Candidate only, no repository assignment |
| New backend in a separate repository | Can target exactly the declared requirements | Adds database, index/query, security, operational and consumer migration maintenance | Reject until verified candidates fail required gates |

Read-only inspection of Positron's local README on this date found a description
of an observability database for native Logs and Traces. Its product sources
are [in Positron](https://github.com/guaracloud/positron). That description is
not evidence of deployed OTLP, LogQL, Grafana, tail or SLO readiness. No
candidate was executed or qualified for this RFC. Future comparison must pin
source commits, image digests, configuration and recorded test results.
Feature names or repository tests cannot establish backend readiness.

## Backend architecture and ownership

Use the existing processed OTLP log boundary. A separately operated service
owns authenticated ingress, derives tenant identity from trusted credentials,
applies per-tenant admission quotas, and durably commits accepted records
before acknowledgement. Reject client-controlled tenant impersonation. Any
adapter must declare mapping, rejection, retry and buffering semantics without
changing the native signal contract.

The backend owns durable storage/recovery, bounded indexing, historical query,
tail, per-tenant query budgets, retention/deletion workers, backups, encryption
and audit trails. Enforce authorization on reads and writes. Consumer owners
own Grafana data sources, query mapping and alerts. The platform owner owns
deployment and recovery execution. The Guara decision owner approves selection
and Loki removal. These roles are proposed responsibilities, not assignments.

Collector spool acceptance and HTTP success do not prove backend durability or
queryability. ADR 0021 permits at-least-once replay, explicit expiry and terminal
partial/permanent rejection. Declare duplicate identity/accounting, timestamp
ordering, late-data policy and partial-rejection semantics. Never promise
exactly-once delivery or silently discard privacy, truncation, attribution or
loss metadata. Bodies omitted by policy cannot be recovered by translation.

## Measurable acceptance gates

These proposed requirements govern future selection. Numeric deployment limits
come from LB-04 through LB-08 and require owner approval before execution.
Unset thresholds, missing required consumers or missing evidence fail a gate.
Reports need pinned identities, sanitized fixtures, offered load, duration,
observed values, approved limits and per-gate verdicts.

| Gate | Measurement and pass condition |
| --- | --- |
| BG-01 Durable ingest | Reconcile fixture IDs across acknowledgements, stored records and explicit rejects. Zero unexplained missing acknowledged records after crash/restart within the approved RPO/failure model. Report duplicates; test retries, timeouts and partial rejection. |
| BG-02 Query and alerts | 100% of required LB-02 consumers have approved mappings. Exact record sets, aggregates and alert transitions match fixtures, including empty results, malformed input, late data, Unicode and time boundaries. Query p95/p99 meet approved limits at declared ranges/concurrency. |
| BG-03 Tail | Every required workflow passes slow-client, reconnect/resume, order, gap-accounting and cancellation fixtures with bounded resources. Latency and concurrency meet approved limits. |
| BG-04 Capacity and quotas | Measure ingest-to-query p95/p99, query latency, CPU, memory, disk and cost at approved sustained/peak ingest and cardinality. All meet approved ceilings. Over-quota tenants receive explicit outcomes without starving others. |
| BG-05 Isolation and security | Zero unauthorized cross-tenant reads/writes across ingress, query, tail, caches, indexes, administration and recovery. Test spoofed identity, expired/revoked credentials, key rotation and noisy neighbors. Audit evidence contains no secrets. |
| BG-06 Retention/deletion | Fixtures remain queryable for required retention and become inaccessible by approved deletion deadlines in live storage, indexes, caches and backups, subject to holds. Restore cannot resurrect deleted data; verify deletion/tombstone and backup expiry policies. |
| BG-07 Availability/recovery | Measure availability over the approved window, outage backlog drain, acknowledged-record loss, RPO and timed RTO for approved process/node/storage failures. Test independent backup restoration and state out-of-model failures. |
| BG-08 Grafana/rollback | Every required dashboard, alert, Explore and navigation workflow passes on pinned Grafana/backend versions. Recorded cutover/rollback rehearsal meets the approved recovery window and reconciles data without unexplained gaps. |

## Query migration, cutover and rollback

Default to explicit consumer migration. Do not promise full LogQL compatibility.
If compatibility is required, freeze the exact query/API subset, errors and
semantics from LB-02/LB-03. Translation belongs in the backend; test every
required consumer. Unsupported expressions block removal until migrated or
explicitly excluded by the decision owner.

After separate execution authorization, establish a pinned Loki baseline and
replay the same fixtures into candidates on an isolated target. Any approved
dual-ingest trial needs bounded fan-out outside the agent, independent retries,
privacy policy and duplicate reconciliation. Existing sinks do not imply
dual-destination support. Pass BG-01 through BG-08 before staging cutover by
tenant/cohort. Record approvers, data-source/rule revisions and observations.

Keep Loki ingestion, consumer configurations and historical data available
through the approved rollback window. A failed gate or SLO breach triggers
restoration of pinned consumers and ingress routing. Reconcile backlog,
duplicates and historical coverage. The node spool cannot replay already
acknowledged history. Remove Loki only after evidence approval, completion of
the rollback window and governance approval of retained-data disposal. This
RFC does not authorize those actions.

## Follow-up ownership and authorization

The authorized plan remains [in #58](https://github.com/guaracloud/e-navigator/issues/58)
and this RFC. No external backend repository is selected and no cross-repository
work is created. If an external backend is selected later, obtain explicit
authorization and link its accepted follow-up plan here before implementation.
RFC completion does not satisfy that conditional gate for a later selection.

| Planned child work | Responsible role | Exit condition |
| --- | --- | --- |
| Supply inventory and thresholds | Decision owner coordinating input owners | Signed LB-01 through LB-08, no unknown required consumers |
| Compare candidates and select owning repository | Backend and security owners | Pinned BG-01 through BG-07 evidence or explicit gaps, cost comparison, accepted ownership and authorized linked backend plan |
| Implement selected gaps outside E-Navigator | Selected backend maintainer | Authorized child issues for failed gates, reviewed implementation and rerun evidence |
| Migrate queries and validate Grafana | Consumer owner | BG-02, BG-03 and BG-08 for every required consumer |
| Rehearse recovery, cutover and rollback | Platform and decision owners | Recorded BG-07/BG-08 on authorized targets and approved removal decision |

These are planning responsibilities, not created issues or assigned people.
Selection, live qualification and Loki removal remain blocked by LB-01 through
LB-08. Local documentation checks verify links and repository contracts only.
They provide no backend or production proof.
