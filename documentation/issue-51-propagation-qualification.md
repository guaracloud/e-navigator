# Issue 51 propagation qualification

This repository slice implements synchronous HTTP/1 lifetime fencing,
transactional rollback and exact backend tree assertions under
[ADR 0019](adr/0019-http-propagation-lifetime-and-rollback.md).
Issue #51 remains open until its required runtime/transport cells and live
acceptance evidence are complete. Mutation remains opt-in.

## Local checks

```sh
cargo test --locked -p e-navigator-context-propagation -p e-navigator-sources-ebpf-aya
PYTHONDONTWRITEBYTECODE=1 python3 tests/propagation_tempo_test.py
scripts/quality.sh
```

The tree tests contain eight independent concurrent-request expectations and
negative controls for cross-request parent contamination, absent traces/spans,
extra/duplicate spans, wrong ownership/kind, foreign trace IDs and cycles.
They validate the oracle, not actual concurrent traffic or backend storage.
The existing HTTP/1 planner tests cover application context, malformed framing,
upgrades, segmentation, pipelining, bounded capture and privacy boundaries.
The shared lifetime test covers expiry, zero/future timestamps and overflow.

## Exact Tempo tree oracle

Create an independent expected JSON object keyed by lowercase trace ID. Each
value is the complete list of expected spans, with no wildcard identities:

```json
{
  "4bf92f3577b34da6a3ce929d0e0e4736": [
    {
      "span_id": "0000000000000001",
      "parent_span_id": "00f067aa0ba902b7",
      "service": "proxy",
      "name": "/proxy",
      "kind": "SPAN_KIND_SERVER"
    },
    {
      "span_id": "0000000000000002",
      "parent_span_id": "0000000000000001",
      "service": "proxy",
      "name": "/sink",
      "kind": "SPAN_KIND_CLIENT"
    },
    {
      "span_id": "0000000000000003",
      "parent_span_id": "0000000000000002",
      "service": "sink",
      "name": "/sink",
      "kind": "SPAN_KIND_SERVER"
    }
  ]
}
```

The remote upstream parent may be outside the queried collector tree. Include
it if the backend is expected to store it. Record generated IDs from an
independent workload/wire oracle; do not copy the backend result into the
expectation. Include separate traces for overlapping requests and retries.
Record the concurrency schedule and expected complete tree for every request.

For saved responses, use a JSON object keyed by trace ID whose values are
Tempo JSON responses. Both `batches` and OTLP `resourceSpans` are accepted,
with hex or protobuf-JSON base64 IDs. The validator bounds input size, traces
and spans and rejects empty expectations:

```sh
python3 scripts/qualify_propagation_tempo.py \
  --expected expected.json --traces tempo-responses.json --output replay-result.json
```

On a separately authorized backend, query each expected trace directly:

```sh
python3 scripts/qualify_propagation_tempo.py \
  --expected expected.json --tempo-url http://127.0.0.1:3200 --output tempo-result.json
```

The command writes a versioned pass/fail bundle, verified expected trees and
canonical SHA-256 checksums of the expectations and returned JSON. It exits
nonzero on missing data or mismatches. Backend URLs, transport exception details
and arbitrary response attributes are omitted from evidence. Keep the expected
oracle sanitized under the existing privacy rules. A query result is not a
wire-safety or overhead verdict.

## Remaining live gate

Record exact workload/image/runtime/library/TLS/kernel/config identities,
collector commit and digest, commands, timings and backend versions. Then run
the existing privileged HTTP propagation smoke only on an authorized target.
Extend the live campaign to concurrent requests, retries, request rejection,
expiry, thread exit/exec/reuse, application-owned headers, proxies and TLS
termination, and fault-induced comparison/push/pull/pop failures. Require
original application bytes after successful rollback, a drop after failed
rollback, visible unsupported bypass, bounded state and no stale parent reuse.
Any post-push failure blocks promotion even after a successful rollback.

The exact required HTTPS/HTTP2/gRPC and async runtime builds, approved overhead
thresholds and authorized target remain inputs from the replacement contract.
No live campaign or deployment is recorded by this document. Fixture results
must not promote those cells or satisfy issue #51's Tempo/concurrency criterion.
