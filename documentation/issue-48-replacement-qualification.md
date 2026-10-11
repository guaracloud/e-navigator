# Replacement qualification suite for issue 48

[Issue 48](https://github.com/guaracloud/e-navigator/issues/48) adds a bounded,
standard-library evidence runner. It checks every cell and scenario independently,
reuses the Tempo tree and CPU quality checkers, and queries stored logs and
metrics at the consumer/backend boundary. The static collector pipeline and
native schema version 1 are unchanged.

Existing authorized workload harnesses produce captures; this runner never
executes commands imported from JSON. Suite PASS checks submitted evidence and
always records `replacement_qualified: false`. Guara replacement still requires
the complete contract, sustained-load/overhead/outage evidence and review under
issues 46 and 57. Operator attestations are not independent execution proof.

## Local fixture mode

Run from the repository root with Python 3, without capture privileges,
containers, cluster, backend or third-party Python packages:

```sh
python3 tests/replacement_fixture.py /tmp/replacement-fixture
python3 scripts/qualify_replacement.py \
  --manifest /tmp/replacement-fixture/manifest.json \
  --capture /tmp/replacement-fixture/capture.json \
  --output /tmp/replacement-fixture/result.json
PYTHONDONTWRITEBYTECODE=1 python3 tests/replacement_qualification_test.py
```

Seed 48 generates ten synthetic `GW-<family>-9001` cells covering HTTP, gRPC,
PostgreSQL, MySQL, Redis, MongoDB, Kafka, TCP, CPU and application logs. These IDs,
digests, acceptance values and environment are checker examples, not allocated
Guara cells or runnable image pins. The generator reuses native golden envelopes
and CPU fixtures and creates separate mutable oracle and observation records.
It does not execute the collector, workloads, eBPF or real backends.

Each cell has nine scenarios: normal, concurrent, pooling, retry/reconnect,
process restart, agent restart, late attachment, privacy and unsupported version.
Action records test overlapping intervals, connection reuse, retries, changed
process/agent generations and pre/post-attachment work. PASS requires all 90
synthetic assertions. IN-01 through IN-07 remain deployment blockers.

Regression tests remove each required family while others pass, shrink both
inventory and capture, and inject skips, loss, privacy leaks, bad identities,
wrong parentage/outcomes, duplicate spans, incorrect CPU weights, wrong stored
log content and foreign metric labels. A loopback HTTP emulator verifies API
transport, not backend qualification. Tests run in `scripts/quality.sh`.

## Manifest and capture schema

Generated JSON files are executable schema examples. Real runs use exact cells
from the [replacement contract](guara-replacement-acceptance.md). Oracles must
come from independent workload generation, never from observed telemetry.

| Record | Contents |
| --- | --- |
| Manifest | `schema_version: 1`, explicit `fixture` boolean, environment, `blocked_inputs`, cells keyed by stable ID |
| Environment | Target reference, kernel, architecture, cgroup mode, full collector commit, backend image digests by `traces`, `profiles`, `metrics`, `logs` |
| Cell | Requiredness, implementation support, approval reference, workload/collector/config SHA-256 identities, runtime/version/build/client/server/TLS/architecture/I/O identities, seed, scenarios |
| Scenario | Variant identity, independent workload actions, native envelope oracle, backend oracle, counter minimums/limits, forbidden privacy canaries, history policy |
| Capture | Matching environment and cell/scenario records with executed/skipped status, variant identity, seed, sanitized command argument vectors, execution interval, workload actions, native envelopes, counters |

Every inventory family needs a classification. Included cells have all nine
scenarios. Exclusions need rationale and approval. Required skipped/missing/failed
scenarios fail; optional incomplete scenarios stay explicit. Unknown/unsupported
required implementations fail live mode. Deployment identities and approvals
must be attested from authorized artifacts, not inferred from fixture PASS.

Workload actions contain numeric operation/connection IDs, process/agent
generations, attempt, nanosecond start/end and success/failure/unsupported outcome.
Captured actions must match the independent oracle and execution window. The
checker requires overlap for concurrency, connection reuse for pooling, repeated
operations across connections with failure/success for retries, and changed
generations for restart scenarios. Unsupported controls require only native
warnings, positive `unsupported_versions` counters and no matching stored data.

Native assertions compare oracle fields and exact ordered list contents. Extra
object fields permit additive schema-v1 compatibility; all native/backend data
is scanned for declared privacy canaries. Supply raw and encoded canary forms
that the workload could expose. Each protocol cell requires its own protocol
tagged spans. A HTTP span cannot satisfy Redis. All example zero-loss limits are
synthetic checks, not production thresholds.

| Backend oracle | Stored assertions |
| --- | --- |
| `traces` | Allocated trace IDs, exact trees and per-span status/error.type; native/stored trace, span, service, name and parent identities agree; cycles and duplicate IDs fail |
| `profiles` | Existing issue-52 CPU descriptor, selector/window, caller chain and approved quality limits; native and stored weights pass the existing checker |
| `logs` | Workload-scoped LogQL query/window/limit and exact label/timestamp/redacted-body records; duplicates, omissions and unexpected records fail |
| `metrics` | Workload-scoped PromQL query/time and exact label/value vector; missing series, foreign identities, duplicate labels and non-finite values fail |

Isolate each query's workload and execution window, including negative controls.
Allocate trace IDs before execution. Logs/metrics need dedicated scenario labels
or isolated workload instances so previous successful scenarios cannot pollute
negative controls. Match query limits to the independent operation oracle. HTTP
ingest acceptance never substitutes for stored-data assertions.

## Late attachment

Each scenario has an attachment timestamp and a history policy:

- `partial` allows attachment-forward events only. Historical protocol, topology
  and CPU observations fail even if the oracle changes to match. Pre-attachment
  workload actions do not require fabricated historical spans or samples.
- `retained` applies only to application logs. Historical event timestamps must
  fall within the retained-file horizon; observed timestamps must follow
  attachment. Historical record counts must match the independent oracle.
  This does not imply export durability or exactly-once delivery. See
  [ADR 0018](adr/0018-cri-log-collection.md).

Late-attachment actions must contain work on both sides of attachment. Results
record `attachment-forward-only` or `retained-file-replay` separately from verdicts.
This prevents the aggregate Redis omission described in
[ADR 0014](adr/0014-controlled-head-to-head-benchmark.md).

## Authorized live query mode

Resolve IN-01 through IN-07 with exact approved deployment records. On an
authorized capable Linux/Kubernetes target, use the existing relevant
[benchmark harnesses](benchmark.md),
[propagation workflow](issue-51-propagation-qualification.md) and
[CPU workflow](issue-52-cpu-qualification.md). Preserve commands/output, independent
workload logs, build/image/config attestations, kernel/attachment records, native
captures and counter scrapes. Normalize them into the capture schema without
deriving expectations from collector output. The suite does not provision a
target or extend historical execution authorization.

Set `fixture: false`, resolve `blocked_inputs` to an empty list, replace synthetic
identities and provide implementation approvals. Recorded capture/environment
must agree. Authorization JSON requires `approved: true`, the same `target`, and
nonempty `owner` and `reference` identifying existing approval. Repository work
does not authorize target deployment or startup/security changes.

Endpoint JSON maps `traces`, `profiles`, `logs`, `metrics` to accessible HTTP(S)
base URLs without credentials, queries or fragments. Redirects fail. Use an
already-authorized tunnel/gateway when authentication is needed. The suite does
not configure access or persist endpoint URLs.

```sh
python3 scripts/qualify_replacement.py \
  --manifest /path/to/approved-manifest.json \
  --capture /path/to/recorded-capture.json \
  --endpoints /path/to/backend-endpoints.json \
  --authorization /path/to/target-authorization.json \
  --output /path/to/replacement-result.json
```

Live mode ignores capture's saved backend responses and queries real services
using the documented [Tempo trace API](https://grafana.com/docs/tempo/latest/api_docs/),
[Pyroscope API](https://grafana.com/docs/pyroscope/latest/reference-server-api/),
[Loki query_range API](https://grafana.com/docs/loki/latest/reference/loki-http-api/)
and [Prometheus instant query API](https://prometheus.io/docs/prometheus/latest/querying/api/).
Translation remains outside native contracts per
[ADR 0001](adr/0001-standalone-native-contracts.md).

Inputs/responses are capped at 16 MiB, cells at 64, native/action/log records at
4,096 per scenario and backend requests at 2,048 per run, with 30-second request
timeouts. Existing Tempo/CPU budgets also apply. Duplicate JSON keys, non-finite
numbers, malformed/missing evidence and unmet assertions fail. CLI writes a
failed result on invalid input and exits zero only for suite PASS.

## Evidence and acceptance status

Retain original sanitized inputs and query responses beside the result. The
compact result contains manifest/capture/authorization and per-scenario response
SHA-256 digests, image/config identities, kernel provenance, seed, sanitized
argument-vector commands, intervals, counters, backend assertion summaries,
history classification and every skipped/failed scenario. Skip reasons are
hashed. Commands with URLs or common access-bearing argument names are rejected
before persistence. Backend exception text and arbitrary attributes are omitted.
Never import credentials, private raw values or unsanitized commands.

| Issue-48 criterion | Runnable verification |
| --- | --- |
| Missing family fails despite other telemetry | Every family is removed independently; reducing the manifest also fails |
| Partial observation and recoverable history stay distinct | Both policies pass; invented historical protocol data and logs observed before attachment fail |
| Nonprivileged fixture mode, explicit live requirements, no skipped promotion | Documented 90-scenario fixture run; unauthorized live paths query nothing; required skips fail in live-query tests |

All three suite criteria have repository checks. No live Guara qualification is
claimed. Actual deployment inputs, targets and thresholds remain IN-01 through
IN-07. Log export and restart-safe buffering remain issues 55/56; this checker
does not implement those capabilities or make them pass by inference.
