# Collector replacement acceptance contract

Revision 1, 2026-10-14. This is an operator-owned qualification template for
E-Navigator as a standalone collector. It does not select a customer, cluster,
reference collector, workload label, or required deployment.

Use this profile when evaluating replacement of an existing collector stack.
Installing or releasing E-Navigator does not require replacing another collector.
Product capabilities and unsupported cases remain in [capabilities](capabilities.md)
and [boundaries](boundaries.md). Backend storage, query engines, dashboards,
and consumer query migration remain external responsibilities.

## Deployment inputs

Each qualification campaign supplies these inputs with immutable artifact
references, responsible owners, and approvals. A missing input blocks that
campaign, not other deployments or standalone software publication. No template,
fixture, or historical proof grants cluster mutation or cutover authorization.

| Input ID | Exact requested input | Responsible owner role |
| --- | --- | --- |
| IN-01 | Selected reference collector image digests and releases, chart versions, complete enabled discovery/protocol/profile/log settings, sampling and filtering, collector resources and startup/security posture | platform deployment owner |
| IN-02 | Complete selected workload list with immutable image/build identities; runtime/compiler flags, client/server libraries and releases, framework, TLS implementation/linkage/symbol availability, architecture and ABI; capture roles, socket I/O paths, pooling/retry/reconnect/concurrency patterns | application/runtime owners |
| IN-03 | Cluster/context and namespace/node allowlist, kernel releases/features/BTF, cgroup mode, container runtime, security/capability posture, target mutation permissions, qualification window and cleanup/rollback authority | platform/security owner |
| IN-04 | Metric/trace/profile/log backend releases and digests, ingest protocols/settings, retention, query interfaces and sanitized destination references | telemetry backend owner |
| IN-05 | Dashboard/alert/API query inventory with exact expressions, filters, units, windows, aggregation, expected fixtures and results; required trace-to-profile navigation and log sources/processing/durability semantics | observability consumer owner |
| IN-06 | Approved numerical thresholds below, measurement windows/load shapes, rationale and approving person for each required cell | replacement decision owner with application SLO and backend owners |
| IN-07 | Required/optional/excluded classification of every exact cell, exclusion rationale and corresponding public workload contract revision | replacement decision owner |

## Inventory profile

The complete replacement checker classifies every bucket below as required,
optional, or excluded. Exclusions require a rationale and approval. An unsupported
required cell remains a blocker. Do not remove buckets to hide missing capture.
This profile is the checker's bounded scope, not an assertion that every operator
runs every protocol. NATS L7 is outside this checker profile; TCP observations
can qualify NATS transport without qualifying its application semantics.

| Inventory ID | Workflow to inventory | Blocking inputs |
| --- | --- | --- |
| WC-HTTP | HTTP request metrics, spans and distributed parentage | IN-01, IN-02, IN-03, IN-04, IN-05, IN-06, IN-07 |
| WC-GRPC | gRPC request metrics, trailer status, spans and parentage | IN-01, IN-02, IN-03, IN-04, IN-05, IN-06, IN-07 |
| WC-POSTGRESQL | PostgreSQL operations and correlated outcomes | IN-01, IN-02, IN-03, IN-04, IN-05, IN-06, IN-07 |
| WC-MYSQL | MySQL operations, negotiated capabilities and outcomes | IN-01, IN-02, IN-03, IN-04, IN-05, IN-06, IN-07 |
| WC-REDIS | Redis operations, RESP mode and Pub/Sub where deployed | IN-01, IN-02, IN-03, IN-04, IN-05, IN-06, IN-07 |
| WC-MONGODB | MongoDB operations and out-of-order/exhaust where deployed | IN-01, IN-02, IN-03, IN-04, IN-05, IN-06, IN-07 |
| WC-KAFKA | Kafka operations, correlation and retry/rebalance behavior | IN-01, IN-02, IN-03, IN-04, IN-05, IN-06, IN-07 |
| WC-TCP | Topology, directional application bytes and ownership, including NATS as TCP only | IN-01, IN-02, IN-03, IN-04, IN-05, IN-06, IN-07 |
| WC-CPU | CPU profiling comparison for each selected runtime/build | IN-01, IN-02, IN-03, IN-04, IN-05, IN-06, IN-07 |
| WC-LOG | Application log collection, processing, enrichment and delivery | IN-01, IN-02, IN-03, IN-04, IN-05, IN-06, IN-07 |

Cell IDs use `<namespace>-<family>-<four digits>`. The operator owns the namespace,
which starts with an uppercase letter and contains at most 16 uppercase letters,
digits, or underscores. Families use the table above. Maintained examples use
`WC`, but no specific namespace is required. Existing valid IDs remain stable;
never rename historical IDs or regenerate their evidence hashes for branding.

Each exact cell records client/server/runtime/TLS builds, architecture and ABI,
image/configuration digests, capture roles, I/O paths, and required scenarios.
Requiredness and implementation support are separate decisions. Numeric wire
versions cannot substitute for deployment identities. See the
[workload qualification ledger](workload-qualification.md) and executable
[replacement manifest contract](issue-48-replacement-qualification.md).

## Threshold ownership

Operators approve numeric thresholds, units, comparison direction, observation
windows, and rationale before executing a campaign. The template provides no
production defaults or implied acceptance values.

| Threshold ID | Required specification | Responsible owner role |
| --- | --- | --- |
| TH-COVERAGE | Per-family observed/expected successful and failed operation coverage, overcount and unmatched fractions; minimum sample count and duration | Application SLO owner |
| TH-STACK | Unknown stack weight / total sample weight, named-frame coverage and weight error, separately per runtime and profile mode | Profiling consumer owner |
| TH-OVERHEAD | Collector CPU cores, RSS bytes and allocation rate; workload throughput impact against matched no-agent and selected reference collector arms at fixed offered load | Platform capacity owner |
| TH-LATENCY | Application p50/p95/p99 delta and allowed request-span latency error with units and fixed comparison windows | Application SLO owner |
| TH-OUTAGE | Backend outage duration, buffer capacity, restart count, drain/recovery deadline and tolerated duplicate/reorder bounds per signal | Platform and backend owners |
| TH-RETENTION | Collector replay horizon and backend retention duration per signal, measured query age and expiration boundary | Backend owner |
| TH-LOSS | Capture, parsing, correlation, queue/export/checkpoint loss and rejection limits with denominators, including saturation and recovery | Replacement decision owner |

## Evidence and promotion

Run the [qualification suite](issue-48-replacement-qualification.md), applicable
[protocol checks](issue-49-protocol-qualification.md),
[CPU checks](issue-52-cpu-qualification.md), and
[backend checks](issue-53-backend-qualification.md) against exact authorized cells.
The [campaign gate](issue-46-replacement-campaign.md) verifies preserved evidence,
matched trials, consumer mappings, and rollback. Reference collectors are an
operator-named map of pinned digests plus a pinned `config` snapshot; the checker
does not mandate a particular collector product.

Keep native evidence, backend queries, ownership, privacy assertions, loss and
coverage counters, retention/expiry checks, authorization, and numerical results.
Synthetic fixtures and local tests never promote live deployment qualification.
Any approved cutover follows the [migration runbook](collector-migration.md).
The [historical customer profile](guara-replacement-acceptance.md) records its own
inputs and decisions and does not define standalone application behavior.
