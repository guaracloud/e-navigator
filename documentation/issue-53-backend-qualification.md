# Backend compatibility and Grafana workflow qualification

[Issue #53](https://github.com/guaracloud/e-navigator/issues/53) adds
[qualify_backends.py](../scripts/qualify_backends.py), a standard-library checker
over the existing [replacement suite](issue-48-replacement-qualification.md).
It reuses exact Tempo trees, native CPU period/weight and stored caller-chain
checks, and native consumer-side PromQL/LogQL assertions. No vendor aliases,
signal schema changes, dependencies or collector pipeline changes are needed.

This delivers repository tooling, not completion of the live acceptance gate.
The [replacement contract](replacement-acceptance.md) still owns IN-01
through IN-07. Backend identities, retention and query approvals come from
IN-04/IN-05/IN-06; exact required workload cells come from IN-02/IN-07; live
authorization comes from IN-03. Never derive production requirements from the
synthetic example. The checker always records `live_qualified: false` and
`replacement_qualified: false`, because artifact review is still required.

## Runnable local example

```sh
python3 tests/backend_fixture.py /tmp/backend-fixture
python3 scripts/qualify_backends.py \
  --manifest /tmp/backend-fixture/manifest.json \
  --evidence /tmp/backend-fixture/evidence.json \
  --output /tmp/backend-fixture/result.json
PYTHONDONTWRITEBYTECODE=1 python3 tests/backend_qualification_test.py
```

The example is deterministic and needs no backend, containers or privileges.
The regression tests also bind a loopback HTTP server to verify real request
transport, query-time clocks, negative 404 responses and that live query mode
ignores saved responses. This emulator is not Tempo/Pyroscope/Grafana proof.

## Manifest and preserved evidence

The generated example is the JSON schema example. Inputs use the replacement
suite's 16 MiB cap and reject duplicate keys and non-finite numbers. There are
at most four signal backends, 64 cells and 64 queries per backend, 64 workflows,
and 64 trace IDs per query, with at most 2,048 requests per run. Backend requests inherit bounded responses,
30-second timeouts and redirect rejection from the replacement suite.

| Manifest field | Requirement |
| --- | --- |
| `schema_version`, `fixture`, `target`, `blocked_inputs` | Version 1, explicit fixture mode, sanitized target reference and named missing inputs |
| `backends` | Required traces and profiles; metrics/logs may also be declared |
| Backend `identity` | Exact release, immutable image and configuration SHA-256 digests, wire contract revision |
| Backend `retention_ms`, `expiry_grace_ms`, `approval`, `cells` | Positive approved retention, nonnegative expiry grace, sanitized owner approval reference, stable selected cells |
| Backend `queries` | Every cell has stored and expired phases, backend oracle, cell ID, data-window end in epoch milliseconds, positive minimum query age; expired phases also declare a nonempty `prior_oracle` for the same cohort |
| `grafana` | Exact release and immutable image digest |
| `workflows` | Required trace and application-frame navigation, pinned dashboard/panel/datasource IDs, selected cell and stored query ID; extra workflows may be optional |
| `correlation` | `optional` or owner-approved `excluded`; required exact correlation fails because current profile signals do not prove span execution ownership |

Every evidence backend must match its declared identity. Its ingest record has
positive `accepted`, zero `rejected` and an `artifact_sha256` pointing to original
sanitized exporter output/counters. Query evidence has native samples, backend
response and `observed_at_ms`. Fixture mode checks saved responses and times;
live mode queries real backends and uses the current clock. Stored queries must
reach the minimum age and remain inside retention. Expired queries must be older
than retention plus grace and return no matching stored data. Each expired
query also needs `prior_stored` evidence containing a nonempty response, native
capture and an observation time inside retention for the exact same IDs or
query window. An arbitrary never-ingested ID cannot pass on 404. HTTP ingest
success alone cannot pass either phase.

Keep workload windows isolated. For live mode, use a recent cohort for stored
queries and an older independently recorded cohort for expired queries. For
saved fixture mode, the same cohort can demonstrate checks at two recorded
times. Profile windows must end at `data_end_ms`; do not substitute a current
query window for an old cohort. Trace cohort endpoints must match the latest
native span end rounded up to milliseconds; LogQL end is epoch nanoseconds
and PromQL time is epoch seconds, both bound to `data_end_ms`. Each trace oracle includes independently
allocated IDs, expected service/span/parent identities and outcomes. Profile
oracles include process/build identity, service selector, named caller chain,
sample periods and approved weight/unknown-stack thresholds. Declare CPU and
propagation dependencies by their exact cell IDs, not by runtime family alone.

Grafana evidence records `status: executed`, the exact manifest workflow
`definition`, and an `artifact_sha256` for a sanitized execution recording or
screenshot bundle. That bundle must show the selected datasource, query/window,
expected trace tree or application caller chain and successful navigation.
Definition mismatches or skipped required workflows fail. Optional skipped
workflows appear as `optional-incomplete`. Backend assertions must pass before
a corresponding UI recording can pass. The checker validates evidence links;
it does not automate a browser or treat an operator assertion as independent
UI execution proof. Review the referenced original artifact before promotion.

Retain original sanitized ingest/UI recordings, manifest and evidence, and
live query responses beside the result. Results preserve input, authorization,
query response and workflow-definition SHA-256 digests, exact backend identities,
query ages and assertion summaries. They omit raw backend attributes and endpoint
URLs. No access credentials belong in these artifacts. A manifest pins expected
deployment identity; its matching evidence still needs an authorized deployment
inventory artifact to establish the actual release/digest/configuration.

## Authorized live queries

Use existing captures and the authorized environment rules from issue #48.
Set `fixture: false`, resolve `blocked_inputs`, and supply an authorization JSON
with `approved: true`, matching `target`, and nonempty `owner` and `reference`.
Endpoint JSON maps exactly the declared signal backends to authorized HTTP(S)
base URLs without credentials, queries or fragments. This command performs
read-only backend queries and creates a local result; it provisions nothing.

```sh
python3 scripts/qualify_backends.py \
  --manifest /path/to/approved-backends.json \
  --evidence /path/to/recorded-evidence.json \
  --endpoints /path/to/authorized-endpoints.json \
  --authorization /path/to/target-authorization.json \
  --output /path/to/backend-result.json
```

Retryable/permanent responses, malformed responses and partial-success rejection
accounting remain in the existing OTLP sink tests and native
`e_navigator_export_*` counters under [ADR 0004](adr/0004-independent-export-pipelines.md).
Run `scripts/quality.sh` and preserve its output alongside live negative controls
on the approved backend versions. Healthy ingest evidence must not hide partial
success. Fault injection against production is not authorized by this tooling.

## Recorded local compatibility execution

On 2026-10-11 at 22:15:13 UTC the existing isolated Docker smoke ran with
Pyroscope `1.20.3`, digest
`sha256:47fc578b2227e9c0c5c5efda34966c1566b0d0a0802cb2adc2e1e9f7ae16a7aa`.
The synthetic collector exported directly through the ADR 0003 development
wire contract. The stored query returned 40,000,000 ticks with
`synthetic_api::checkout_handler` and `synthetic_api::deep_frame_0`.
The script's rejection-log assertion passed.

Preserved [execution and artifact checksums](evidence/issue-53/pyroscope-1.20.3/execution.json),
[collector output](evidence/issue-53/pyroscope-1.20.3/e-navigator.log),
[backend output](evidence/issue-53/pyroscope-1.20.3/pyroscope.log),
[query](evidence/issue-53/pyroscope-1.20.3/query.json),
[response](evidence/issue-53/pyroscope-1.20.3/render.json),
[image digests](evidence/issue-53/pyroscope-1.20.3/image-digests.json),
[collector commit](evidence/issue-53/pyroscope-1.20.3/collector-commit.txt) and
[execution time](evidence/issue-53/pyroscope-1.20.3/executed-at.txt) establish
this local smoke's scope. The run used the existing synthetic collector code,
not a production workload or the new backend retention runner.

To retain evidence from another local smoke, use a new, nonexistent directory:

```sh
E_NAVIGATOR_PYROSCOPE_EVIDENCE_DIR=/tmp/pyroscope-new-run \
  tests/smoke_pyroscope_otlp.sh
```

This opt-in preserves the query, response, image digests, execution time,
collector commit and local synthetic collector/backend logs. Existing evidence
directories are never overwritten. This smoke proves scoped direct ingest and
stored frames, not production retention, Grafana navigation, exact span/profile
ownership or a required Guara cell. Issue #53 must remain open until every
declared backend, retention assertion and required Grafana workflow has recorded
authorized execution and reviewed original artifacts.
