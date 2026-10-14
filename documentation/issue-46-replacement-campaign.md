# Replacement campaign gate for issue 46

[Issue #46](https://github.com/guaracloud/e-navigator/issues/46) requires one
replacement decision across request observation, CPU profiling and application
logs. `scripts/qualify_campaign.py` checks the combined evidence using Python's
standard library and the existing replacement, protocol and backend validators.
It does not execute imported commands, access backends, change deployments or
close issues. Native collector contracts and the static pipeline are unchanged.

Campaign PASS means the submitted archive passes the automated checks. Every
result retains `replacement_qualified: false` and `review_required: true`.
Hashes establish artifact integrity, not authenticity or execution. The decision
owner must review original capture, ingest, benchmark, Grafana and restoration
recordings before accepting any deployed cell. Fixture mode cannot satisfy a
recorded-evidence campaign.

## Run the deterministic example

The generator writes a complete synthetic archive, including original query
responses, capability manifests/captures/results, matched trial measurements,
consumer answers and publication snapshots. These are checker examples, not
Guara deployment identities, production thresholds or executed workloads.

```sh
PYTHONDONTWRITEBYTECODE=1 python3 tests/campaign_fixture.py /tmp/campaign-fixture
PYTHONDONTWRITEBYTECODE=1 python3 scripts/qualify_campaign.py \
  --plan /tmp/campaign-fixture/plan.json \
  --evidence /tmp/campaign-fixture/evidence.json \
  --artifacts /tmp/campaign-fixture \
  --output /tmp/campaign-fixture/result.json
PYTHONDONTWRITEBYTECODE=1 python3 tests/campaign_qualification_test.py
```

Expected output is `replacement campaign passed; replacement_qualified=false;
review required`. Removing a required family, scenario, recording, threshold or
consumer result fails the campaign even when individual suite summaries say PASS.
The CLI exits zero only on campaign PASS and writes a failed result for invalid
JSON, missing artifacts and failed assertions.

## Prepare a recorded campaign

Resolve IN-01 through IN-07 in the
[acceptance contract](guara-replacement-acceptance.md). Record exact cells and
requirements before execution. Use the
[migration runbook](collector-migration.md) to obtain authorization, generate
independent oracles, run matched trials and preserve original evidence. The
checker grants no execution authorization. Current Guara inputs and live proof
remain missing; this implementation does not declare or promote deployment cells.

Use the generated archive as the executable schema example. Replace all
synthetic records, set `fixture: false`, and supply these plan fields:

| Plan field | Required contents |
| --- | --- |
| `schema_version`, `fixture`, `contract_revision` | Version 1, explicit mode, approved contract revision |
| `environment` | The exact replacement manifest environment: target, kernel, architecture, cgroup, collector commit and four backend image digests |
| `inputs` | Exactly IN-01 through IN-07, each with `owner`, `reference`, `rationale`, and an original `artifact` reference |
| `authorization` | In recorded mode, an artifact containing `approved: true`, matching `target`, named `owner` and approval `reference`; all three capability suites use this same authorization |
| `reference` | Immutable SHA-256 pins for deployed `beyla`, `alloy`, application `logs` collector and complete `config` |
| `cells` | Stable exact IDs across all ten inventory families, requiredness and owner approval; required cells also contain native suite `identity`, matched `settings`, `thresholds` and `scenarios` |
| `consumers` | GQ IDs, original and native expressions, referenced cells, independently specified `expected` answer and owner approval |
| `publication` | Original `runbook` artifact plus normalized `ledger` and `public_contract` snapshots containing identical `contract_revision` and cell-to-requiredness mappings |

Requiredness remains separate from support. Optional cells are reported as
`optional-not-evaluated` and do not block acceptance. Excluded cells require an
explicit `exclusion` and owner approval, and must appear in both published
snapshots. Every family must have a declared classification and at least one
cell must be required. Required unknown/unsupported implementations fail
recorded mode. Required exact trace/profile execution correlation remains
unsupported by the backend validator; do not relabel it optional to obtain PASS.

The existing backend validator still requires trace and profile backends plus
their Grafana navigation workflows. This campaign gate preserves that scope;
it cannot currently evaluate a traces-free or profiles-free campaign. Fully
optional/excluded log and TCP families need no corresponding backend.

Each required cell's `settings` contains exact `placement`, positive
`offered_rate`, positive `sample_period_nanos`, and immutable `load_digest`.
Each scenario specifies positive `min_duration_seconds` and `repetitions`.
Normal and sustained-load trials require at least three independent seeds;
other trials require at least one. Owners can increase counts and windows.

## Supply original evidence

Every artifact reference has a relative `path` and SHA-256 of the exact file
bytes. Absolute paths, parent traversal, symlinks escaping the archive, missing
files, changed hashes, duplicate JSON keys and non-finite numbers fail. Files
are capped at 16 MiB, total bytes read at 128 MiB, cells at 64, repetitions at
32 per scenario, archived response records at 4,096, and consumer mappings at
4,096. Copy approved sanitized artifacts into a dedicated archive. Keep
credentials, raw sensitive payloads and protected spool contents outside it.

The evidence document contains these records:

| Evidence field | Required contents |
| --- | --- |
| `suites` | `replacement`, `protocol`, `backends`, each with original `manifest`, `evidence`, `result` artifact references and, in recorded mode, `authorization`; backends include all required signal kinds, while wholly optional/excluded log or TCP families need no backend |
| `records` | Digest-to-artifact map for original query responses, prior stored-query checkpoints, ingest recordings and required Grafana recordings referenced by the suite results |
| `quality` | Artifact with candidate `collector_commit`, `command: ["scripts/quality.sh"]`, integer `exit_code: 0`, original `log` artifact, and `skips` mapping permitted skip environment variables to exact constrained-environment reasons |
| `trials` | Required cell-to-artifact map; each document contains normal, sustained-load, churn, saturation, outage-recovery and rollback trials |
| `consumers` | One artifact per planned query containing executed status, exact environment, native expression and stored `response` |

Response and prior-checkpoint map keys use the existing suite's canonical JSON
digest, `qualify_replacement.digest(value)`. Ingest and Grafana recordings use
the original byte digest. Each reference still carries the byte hash of its
file. Canonical JSON digests and byte hashes are different conventions.

The gate verifies report-to-manifest/capture/authorization hashes, exact planned
identities and requiredness, complete scenario inventories and per-scenario
evidence digests. It reconstructs captures using the archived queried responses
and reruns the existing assertions offline. Changing a summary verdict cannot
override loss, privacy, parentage, metric, profile, log or retention failures.
Recorded campaigns require original `live-query` suite results from nonfixture
manifests with resolved inputs. Required backend cells need stored and expiry
queries; required Grafana workflows need preserved original recordings.

Archive responses at execution time. A digest alone is insufficient, and
querying a later mutable backend response does not reconstruct the original.

## Record matched production measurements

Every scenario is a list of trials, each with `no-agent`, `reference` and
`candidate` arms. Arms contain executed status, exact `environment`, `cell`,
`identity`, `settings`, shared independent `seed`, sanitized argument-vector
`commands`, nanosecond start/end and measured `metrics`. Candidate identity
matches the cell; reference identity matches the pinned previous collectors;
no-agent identity is empty and collector CPU/RSS are zero.

All arms use identical workload, placement, offered load, sample period, seed,
measurement duration and independent expected count. Comparison windows cannot
overlap. Repetitions cannot reuse a seed. Unsupported/skipped, shortened or
unmatched runs fail. The checker reads these records; original recording review
must establish that the measurements came from the declared execution.

Raw metrics contain integer `expected`, `observed`, `lost`, `duplicates`,
`unknown_weight`, `total_weight`; collector and total-node CPU cores/RSS bytes;
`throughput_per_second`; `p50_ms`, `p95_ms`, `p99_ms`; `recovery_seconds`,
`retention_seconds` and `attribution_age_seconds`. Values must be finite and
nonnegative, expected count must be positive, and latency quantiles ordered.
CPU cells require positive total sample weight and bounded unknown weight.

Each threshold has its fixed category/unit/comparator below, numeric `value`,
named `owner`, approval `reference`, and `rationale`. Values in fixtures are
synthetic. No production values default automatically.

Cells can declare additional numeric thresholds under those same categories,
with explicit unit, comparator, owner, approval and rationale. Every candidate
trial must supply and pass each additional measurement. Use this for approved
allocation rate, request-span error, outage duration, capacity, restart, reorder,
replay-horizon or stage-specific loss requirements beyond the core metrics.
The checker requires the measured value; original oracle and denominator review
must establish its semantics. A cell is limited to 64 total thresholds.

| Metric | Category and unit | Direction and calculation |
| --- | --- | --- |
| `coverage_ratio`, `overcount_ratio` | TH-COVERAGE, ratio | Minimum observed/expected; maximum excess/expected |
| `loss_ratio`, `duplicate_ratio` | TH-LOSS, ratio | Maximum lost/expected and duplicates/expected |
| `unknown_stack_ratio` | TH-STACK, ratio, CPU cells only | Maximum unknown/total sample weight |
| `collector_cpu_cores`, `collector_rss_bytes` | TH-OVERHEAD, cores/bytes | Maximum measured candidate resources |
| `node_cpu_delta_cores`, `node_rss_delta_bytes` | TH-OVERHEAD, cores/bytes | Maximum candidate minus matched no-agent total-node resources |
| `throughput_ratio` | TH-OVERHEAD, ratio | Minimum candidate/no-agent throughput |
| `p50_delta_ms`, `p95_delta_ms`, `p99_delta_ms` | TH-LATENCY, ms | Maximum candidate minus no-agent latency |
| `recovery_seconds` | TH-OUTAGE, seconds | Maximum measured recovery deadline |
| `retention_seconds` | TH-RETENTION, seconds | Minimum measured retention horizon |
| `attribution_age_seconds` | TH-COVERAGE, seconds | Maximum measured attribution age |

Reference and candidate per-family coverage, overcount, loss and duplicates
must pass before performance measurements enter the result. Every candidate
repetition must meet every approved threshold; averaging cannot hide failures.
Passing scenario results publish sample count, minimum, median, maximum and
sample standard deviation. Original reference measurements remain in the archive.
No lower-overhead claim follows automatically from campaign PASS.

Rollback also requires `restored` to match all previous collector/config pins
and an integer `delivery` record. Pending-before must equal delivered plus lost,
pending-after must be zero, and lost must agree with measured loss under the
approved threshold. Preserve original restoration and drain recordings. This
accounting does not establish exactly-once delivery or recover expired records.

Every required cell needs a migrated consumer query. Exact native expressions
and stored answers must match the planned records. Native schemas gain no vendor
aliases; translation stays with consumers/backends under ADR 0001.

## Review the replacement decision

Run the same CLI against the approved plan, evidence and original archive.
Review all failed cells and exact constrained quality skips before accepting
the candidate. A passing archive is ready for review, not automatic cutover.
Issue #46 remains open until recorded live execution establishes every required
cell, threshold, consumer result and delivery-preserving rollback, and the
decision owner accepts the published evidence under the migration runbook.
