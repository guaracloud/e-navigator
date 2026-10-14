# Request metrics and span qualification for issue 49

[Issue #49](https://github.com/guaracloud/e-navigator/issues/49) uses the existing
[replacement suite](issue-48-replacement-qualification.md) with an opt-in
`protocol_qualification: true` manifest profile. It adds no collector modules,
dependencies, native metric aliases or schema changes. Source review found
existing bounded parsing, request matching, role and outcome tests; no production
parser defect is inferred from synthetic evidence.

## Local verification

```sh
PYTHONDONTWRITEBYTECODE=1 python3 tests/protocol_qualification_test.py
python3 tests/protocol_qualification_test.py /tmp/protocol-fixture
python3 scripts/qualify_replacement.py \
  --manifest /tmp/protocol-fixture/manifest.json \
  --capture /tmp/protocol-fixture/capture.json \
  --output /tmp/protocol-fixture/result.json
scripts/quality.sh
```

The deterministic example has seven synthetic protocol cells and 105 scenarios.
It checks the evidence evaluator, not packet capture or real server versions.
CPU, logs and TCP are explicitly excluded from this issue's example. NATS L7
remains outside Guara's request contract. Synthetic metric names and values are
checker examples, not new native producers or production requirements.

## Protocol evidence profile

Keep the suite's identity, authorization, privacy, command, bounded-input,
per-family and backend rules. Every included cell must be HTTP, gRPC, PostgreSQL,
MySQL, Redis, MongoDB or Kafka. All inventory families still need explicit
classification. Add these six scenarios to the existing nine:

| Scenario | Independent oracle requirement |
| --- | --- |
| pipelining | Overlapping operations with connection reuse |
| out-of-order | Connection reuse, overlapping operations and reversed completion order |
| compression | Exact supported negotiation/build and observed operations, or explicit unsupported diagnostics |
| malformed | Exact expected safe observations, or rejected traffic with warnings and positive counters |
| truncated | Exact expected safe observations, or rejected traffic with warnings and positive counters |
| ambiguous | Exact expected safe observations, or rejected correlation with warnings and positive counters |

Each scenario also contains `metrics`, using the existing metrics backend oracle
schema: `type: metrics`, `empty`, PromQL `query`/`time` and exact `series` with
`labels` and numeric `value`. Metric series names use `e_navigator_`; labels,
series cardinality and values must match exactly. Declare every required count,
outcome and latency series in this oracle, scoped to the cell, role and scenario.
Missing a native producer required by an approved consumer query is an unsupported
cell, not permission to invent a compatibility metric. Translation stays at the
consumer/backend boundary under [ADR 0001](adr/0001-standalone-native-contracts.md).

Positive native spans require internally consistent start/end/duration and one
`e.navigator.protocol.capture.role` attribute. Stored spans must have the exact
oracle timestamps and matching client/server kind. Existing tree and outcome
checks assert exact IDs, parentage, names, services, statuses and `error.type`.
Native attributes match the independent oracle exactly; stored `http.route` or
`db.collection.name` cannot appear unless declared as observed oracle attributes.
Do not put inferred framework routes or collection names in the oracle.

An unsupported or rejected scenario sets both trace and metric `empty: true`,
uses workload outcome `unsupported`, supplies only warning envelopes and has a
positive diagnostic counter minimum. Its `diagnostic` has `layer` equal to
`capture`, `parser` or `correlation`, and a bounded `reason`. Retain the original
sanitized reason with evidence; the result records its hash, layer and
`unsupported-or-rejected` observation. Empty results without diagnostics fail.
This verifies safe rejection, not support for that scenario. Compression support
needs original negotiation and wire artifacts; workload action assertions alone
cannot establish it. Keep per-protocol malformed/ambiguity counter names and
configured state bounds from the actual collector, rather than the synthetic
`unsupported_versions` example.

The profile reuses live read-only Tempo and Prometheus queries. Live mode ignores
saved metric responses as well as saved traces, requires resolved deployment
inputs and existing target authorization, and retains response hashes. A passed
checker result always has `protocol_qualified: false` and
`replacement_qualified: false`. Review original workload, wire, capture, counter
and query artifacts before a cell promotion. The evaluator does not run workloads
or prove that supplied commands, identities and counters came from execution.

## Acceptance evidence and blockers

| Issue criterion | Repository evidence | Remaining qualification requirement |
| --- | --- | --- |
| Per-cell backend and metric assertions, or explicit unsupported diagnostics | All seven synthetic families; independent trace and metric checks; negative controls with hashed diagnostics | Exact approved cells and real backend execution |
| Safe malformed/truncated/ambiguous behavior, bounded state and counters | Negative evidence controls plus existing parser/registry tests in the full Rust gate | Protocol-specific original traffic, native counter scrapes and configured bounds on the declared target |
| Privacy/cardinality and exact counts/outcomes | Canary scanning across native/traces/metrics, exact series and span lists, role/time/tree/outcome regression tests | Independent approved workload oracles and consumer query inventory |

Dependencies #47 and #48 delivered the contract schema and runnable suite. The
[acceptance contract](guara-replacement-acceptance.md) still has no exact cells:
IN-01 collector configuration, IN-02 client/server/runtime/build/I/O identities,
IN-03 authorized target, IN-04 backend identities, IN-05 consumer metric/query
requirements, IN-06 approved coverage/latency/loss thresholds and IN-07 required
cell classifications remain missing, with responsible owner roles recorded there.
Repository work can prepare these checks but cannot supply those deployment facts.
Issue #49 remains open until required cell evidence is supplied and reviewed.
Encrypted capture and propagation remain owned by #50 and #51. No infrastructure
or workload startup/security changes are authorized by this profile.
