# Guara collector replacement acceptance contract

Contract revision: 1, 2026-10-09. Scope: [issue #47](https://github.com/guaracloud/e-navigator/issues/47)
under [tracking issue #46](https://github.com/guaracloud/e-navigator/issues/46).
Source baseline rechecked: stable 0.5.0, `8b93a5cf8b25c75cc604c16a78a94c4ef1dc05c5`.

**Qualification blocked. No exact deployment cells are declared or promoted.**
The [qualification ledger](guara-workload-matrix.md) owns executable capability
limits; this contract owns inventory, expected results, and input blockers.
Completing this inventory with named missing inputs satisfies the unavailable-input
path of #47. It does not satisfy the collector replacement gate in #46.

## Scope and evidence ownership

Replace required Beyla request observation, Alloy CPU profiling, and application
log collection with the standalone node collector. Tempo, Prometheus-compatible
storage, Pyroscope, and Loki storage/query remain backend responsibilities.
Loki backend replacement belongs to [RFC #58](https://github.com/guaracloud/e-navigator/issues/58).
Vendor query migration belongs to consumers/backends under
[ADR 0001](adr/0001-standalone-native-contracts.md), never vendor aliases in native signals.

No current Guara deployment artifact location was supplied for this issue.
Repository chart/manifests describe E-Navigator, not the deployed reference stack.
[ADR 0014](adr/0014-controlled-head-to-head-benchmark.md) records benchmark Beyla
3.28.0/chart 1.16.10 and Alloy 1.18.0, not current Guara identities. Its invalidated
33-run comparisons are not replacement evidence. [ADR 0003](adr/0003-direct-otlp-profiles.md)
records Pyroscope 1.20.3 compatibility, not a fresh deployment inventory.
[Capabilities](capabilities.md), [boundaries](boundaries.md), and
[benchmark methodology](benchmark.md) remain authoritative for their scoped claims.

Owners below are responsible roles, not an assertion that a person accepted
assignment. The Guara replacement decision owner must name accountable people
and approve requirements before live qualification. Repository work authorizes
no cluster access, deployment, or workload startup/security changes.

## Missing input register

Each input is unavailable as of this revision. Supply a sanitized artifact path,
revision/digest, observation date, and accountable person's approval. Do not put
credentials, unrestricted URLs, request bodies, or raw database values here.

| Input ID | Exact requested input | Responsible owner role |
| --- | --- | --- |
| IN-01 | Deployed Beyla/Alloy image digests and releases, chart versions, complete enabled discovery/protocol/profile/log settings, sampling and filtering, collector resources and startup/security posture | Guara platform deployment owner |
| IN-02 | Complete selected workload list with immutable image/build identities; runtime/compiler flags, client/server libraries and releases, framework, TLS implementation/linkage/symbol availability, architecture and ABI; capture roles, socket I/O paths, pooling/retry/reconnect/concurrency patterns | Guara application/runtime owners |
| IN-03 | Cluster/context and namespace/node allowlist, kernel releases/features/BTF, cgroup mode, container runtime, security/capability posture, target mutation permissions, qualification window and cleanup/rollback authority | Guara platform/security owner |
| IN-04 | Metric/trace/profile/log backend releases and digests, ingest protocols/settings, retention, query interfaces and sanitized destination references | Guara telemetry backend owner |
| IN-05 | Dashboard/alert/API query inventory with exact expressions, filters, units, windows, aggregation, expected fixtures and results; required trace-to-profile navigation and log sources/processing/durability semantics | Guara observability consumer owner |
| IN-06 | Approved numerical thresholds below, measurement windows/load shapes, rationale and approving person for each required cell | Guara replacement decision owner with application SLO and backend owners |
| IN-07 | Required/optional/excluded classification of every exact cell, exclusion rationale and corresponding public workload contract revision | Guara replacement decision owner |

Authorized live qualification environment: **none designated for this issue**,
blocked by IN-03. Historical `homelab` runs do not confer new authorization.

## Stable inventory IDs

These rows are required inventory buckets from the existing ledger and #46,
not exact workload cells or a claim that every runtime is required. Each bucket
must be expanded into all exact deployment cells or receive an owner-approved
exclusion. Unknown cardinality remains blocked by IN-02 and IN-07.

| Inventory ID | Required workflow to inventory | Blocking inputs |
| --- | --- | --- |
| GW-HTTP | HTTP request metrics, spans and distributed parentage | IN-01, IN-02, IN-03, IN-04, IN-05, IN-06, IN-07 |
| GW-GRPC | gRPC request metrics, trailer status, spans and parentage | IN-01, IN-02, IN-03, IN-04, IN-05, IN-06, IN-07 |
| GW-POSTGRESQL | PostgreSQL operations and correlated outcomes | IN-01, IN-02, IN-03, IN-04, IN-05, IN-06, IN-07 |
| GW-MYSQL | MySQL operations, negotiated capabilities and outcomes | IN-01, IN-02, IN-03, IN-04, IN-05, IN-06, IN-07 |
| GW-REDIS | Redis operations, RESP mode and Pub/Sub where deployed | IN-01, IN-02, IN-03, IN-04, IN-05, IN-06, IN-07 |
| GW-MONGODB | MongoDB operations and out-of-order/exhaust where deployed | IN-01, IN-02, IN-03, IN-04, IN-05, IN-06, IN-07 |
| GW-KAFKA | Kafka operations, correlation and retry/rebalance behavior | IN-01, IN-02, IN-03, IN-04, IN-05, IN-06, IN-07 |
| GW-TCP | Topology, directional application bytes and ownership, including NATS as TCP only | IN-01, IN-02, IN-03, IN-04, IN-05, IN-06, IN-07 |
| GW-CPU | Alloy CPU profiling replacement for each selected runtime/build | IN-01, IN-02, IN-03, IN-04, IN-05, IN-06, IN-07 |
| GW-LOG | Application log collection, processing, enrichment and delivery | IN-01, IN-02, IN-03, IN-04, IN-05, IN-06, IN-07 |

Allocate exact cell IDs as `<inventory-id>-0001`, incrementing per bucket. Never
reuse an ID; identity changes create a new cell and retire the old one with a
link. Share deployment records by reference, but a protocol wire version is
never a server release or driver identity.

Requiredness and implementation support are separate fields. Allowed requiredness
is `required`, `optional`, or `excluded`; support is `implemented`, `unsupported`,
or `unknown`. An unsupported required cell remains a blocker. Optional cells
cannot block replacement unless the owner revises the contract. Excluded cells
need rationale and public contract evidence. No optional exact cells are yet
declared. Existing unsupported TLS/runtime cells in the ledger remain unsupported;
JVM/JSSE, Node bundled TLS, rustls, BoringSSL and io_uring requirements must be
explicitly decided, never inferred. NATS L7 is excluded from the current Guara
requirement; TCP topology remains in GW-TCP.

## Exact cell record schema

Use one record per exact client/server/runtime/TLS/architecture/I/O combination.
A missing field must reference an IN input and owner, not a wildcard or guessed
value. This documentation schema does not change native signal schema version 1.

| Field group | Required contents |
| --- | --- |
| Identity and ownership | Cell ID, inventory ID, requiredness, support, responsible person, contract revision; workload and collector image digests, commands/config revision, runtime/compiler/build IDs and flags; client/server/library/framework releases; TLS build/linkage, architecture/ABI |
| Capture and environment | Client/server roles, cleartext/encrypted, transports and syscall/socket paths, kernel/BTF/cgroup/container runtime/security posture; namespace/labels and paid-tier/catalog exclusion rules; pre-attachment and restart behavior |
| Oracle and load | Fixture revision/hash/seed, expected operations and statuses, concurrency/rate/duration, warmup, pooling/pipelining/out-of-order/retry/reconnect behavior, independent operation and byte oracle |
| Metrics and spans | Required metric names, units/dimensions and count/latency expectations; operation/status/error.type/privacy assertions; exact trace tree, root/remote parent/client/server relationships, span kind and duplicate-ID expectations; explicit confidence/bypass/loss outcomes |
| Profiles | Required modes, sample period/weights, expected named frames and stack quality, user/kernel distinction and unknown-weight threshold; no implicit off-CPU, lock or allocation requirement from CPU replacement |
| Logs | Exact stdout/stderr/CRI/file sources and formats, rotation/multiline/timestamp/filter/redaction rules, workload attribution; checkpoint/restart/replay/duplicate/loss/order expectations and durability requirement |
| Consumers and backends | Query IDs and expected answers, backend identities and ingest/query versions, trace-to-profile requirement and join expectations, log durability requirement, retention/outage/recovery thresholds |
| Acceptance and evidence | Approved threshold IDs, exclusions, authorized target reference, exact execution commands/times, collector commit/digest, counters and backend query artifacts/checksums, verdict and reviewer |

Log durability and trace-to-profile correlation are **undecided**, blocked by
IN-05 and IN-06. Application log collection itself is required by #46. Neither
undecided workflow may be silently treated as optional or as already supported.

## Numerical acceptance register

Every required cell references owner-approved values with units, comparator,
measurement window, oracle, rationale and approving person. All values below
are **blocked by IN-06**; no production thresholds are invented. The designated
owner supplies the value and rationale, including any justified zero-loss rule.

| Threshold ID | Measurement and required numeric specification | Responsible owner role |
| --- | --- | --- |
| TH-COVERAGE | Per-family observed/expected successful and failed operation coverage, overcount and unmatched fractions; minimum sample count and duration | Application SLO owner |
| TH-STACK | Unknown stack weight / total sample weight, named-frame coverage and weight error, separately per runtime and profile mode | Profiling consumer owner |
| TH-OVERHEAD | Collector CPU cores, RSS bytes and allocation rate; workload throughput impact against matched no-agent and Beyla/Alloy arms at fixed offered load | Platform capacity owner |
| TH-LATENCY | Application p50/p95/p99 delta and allowed request-span latency error with units and fixed comparison windows | Application SLO owner |
| TH-OUTAGE | Backend outage duration, buffer capacity, restart count, drain/recovery deadline and tolerated duplicate/reorder bounds per signal | Platform and backend owners |
| TH-RETENTION | Collector replay horizon and backend retention duration per signal, measured query age and expiration boundary | Backend owner |
| TH-LOSS | Capture, parsing, correlation, queue/export/checkpoint loss and rejection limits with denominators, including saturation and recovery | Replacement decision owner |

Thresholds are per cell/family, not an aggregate that can hide a missing Redis
or other family. Correctness also requires exact expected trace parentage,
privacy, no duplicate span identity, correct exclusion/attribution and byte
accounting without double counting. Benchmark integrity gates and historical
sampling rates do not constitute Guara production acceptance values.

## Consumer migration inventory

Exact deployed queries and expected answers are missing under IN-05. These
boundary mappings identify owning source, not completed query translations.
For each actual consumer allocate `GQ-0001` onward and record original expression,
backend/version, units/window/labels, native expression, cell IDs, fixture answer,
tolerance and consumer-owner approval. Empty mappings block qualification.

| Workflow | Native contract and consumer boundary | Missing mapping |
| --- | --- | --- |
| Request rates/errors/latency | Protocol request observations and RequestSpan through OTLP trace export; inspect [request correlation](../crates/e-navigator-generators/src/request_correlation.rs) and [OTLP sink](../crates/e-navigator-sinks/src/otlp_http.rs); declare any required metrics lacking a native producer as gaps | Beyla dashboards/alerts and native backend queries, IN-05 |
| TCP topology/bytes | Network observations and [peer-flow metrics](../crates/e-navigator-generators/src/peer_flow_metrics.rs), normalized native namespaces at Prometheus/OTLP boundary | Existing topology queries and exact directional/ownership results, IN-05 |
| CPU profiles | Profile samples and standard pprof/OTLP Profiles per ADR 0003; Pyroscope query normalization belongs to backend | Alloy profile queries, named frames and required correlation, IN-05 |
| Application logs | Required collector contract to be implemented in #54/#55, with restart-safe buffering requirements in #56; no log compatibility claim here | Existing Loki queries, processing and durability expectations, IN-05 |

## Promotion and completion gate

A cell progresses from `blocked-input` to `declared` only when all required
fields, queries, thresholds and authorization are approved. `declared` is not
support proof. `qualified` requires recorded execution on the exact authorized
Linux/Kubernetes target, independent workload oracles, native counters and real
backend query assertions for normal, restart/pre-attachment, concurrency,
sustained-load, saturation, and outage/recovery cases. Record failure as `failed`
with artifacts; retain retired cells and negative results.

The ledger and this contract must reference the same cell IDs and verdicts.
No required cell can be promoted by parser recognition, unit tests, issue closure,
a past image, an unrelated backend smoke or an aggregate metric. Collector
replacement is accepted only when every required cell and consumer query passes,
all exclusions are approved and public, and the evidence/runbook in #57 records
rollout and rollback. Backend replacement remains a separate decision.

For #47 review, verify the inventory covers every required workflow, each unknown
has an IN reference and owner, all numerical categories have threshold records,
and neither document claims a designated target or qualified cells without
inputs. Request IN-01 through IN-07 from their owners before #48 or capability
qualification fills exact cells. No implementation prerequisite is claimed for
this documentation issue; missing inputs block live qualification.
