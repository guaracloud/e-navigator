# Workload qualification ledger

This is a deployment-neutral template. Each operator creates a finite inventory
of exact workload cells under the [acceptance contract](replacement-acceptance.md).
It contains no selected production environment and makes no global readiness
claim. A customer's missing inventory does not restrict another deployment.

## Inventory buckets

Expand every bucket into exact cells or record an approved exclusion. The
complete replacement checker requires the inventory to remain explicit even
when some protocols are not deployed.

| Bucket | Exact deployment cells | Requiredness and evidence |
| --- | --- | --- |
| WC-HTTP | Supplied by the operator | Required, optional, or excluded with evidence |
| WC-GRPC | Supplied by the operator | Required, optional, or excluded with evidence |
| WC-POSTGRESQL | Supplied by the operator | Required, optional, or excluded with evidence |
| WC-MYSQL | Supplied by the operator | Required, optional, or excluded with evidence |
| WC-REDIS | Supplied by the operator | Required, optional, or excluded with evidence |
| WC-MONGODB | Supplied by the operator | Required, optional, or excluded with evidence |
| WC-KAFKA | Supplied by the operator | Required, optional, or excluded with evidence |
| WC-TCP | Supplied by the operator | Required, optional, or excluded with evidence |
| WC-CPU | Supplied by the operator | Required, optional, or excluded with evidence |
| WC-LOG | Supplied by the operator | Required, optional, or excluded with evidence |

## Record each exact cell

Record immutable workload and collector images, collector commit/configuration,
client/server/runtime/TLS builds, architecture/ABI, kernel and cgroup mode,
capture roles, syscall paths, pooling/reconnect/retry/concurrency behavior,
fixture seed, query windows, and approved thresholds. Unsupported requirements
remain explicit; never infer a client or server release from a wire version.

Required scenarios include restart, late attachment, privacy, unsupported-version
controls, sustained load, and losses where the corresponding checker requires
them. Protocol controls, CPU caller-chain quality, stored telemetry, retention,
and consumer workflows retain their independent evidence requirements.

Implemented boundaries live in [capabilities](capabilities.md) and
[boundaries](boundaries.md). The owning profiles define executable contracts:
[protocol](issue-49-protocol-qualification.md), [TLS](issue-50-tls-qualification.md),
[CPU](issue-52-cpu-qualification.md), and [backends](issue-53-backend-qualification.md).
No namespace, account tier, catalog, or organization label is mandatory.

## Promotion

A promotion record includes native assertions, coverage/failure/loss counters,
independent backend responses, exact trace/profile/log identities, and approvals.
Missing or partially evidenced required cells block that campaign. Unit tests,
fuzz checks, Docker smoke, synthetic fixtures, and historical runs do not replace
live evidence for a new target. Use the [campaign gate](issue-46-replacement-campaign.md)
and [migration runbook](collector-migration.md) for review and authorized cutover.

The [historical customer ledger](guara-workload-matrix.md) remains an evidence
record for that deployment and is not the standalone product's support matrix.
