# ADR 0020: Privacy processing and independent OTLP Logs export

- Status: accepted
- Date: 2026-10-11
- Scope: [issue #55](https://github.com/guaracloud/e-navigator/issues/55)

## Decision

Use standard OTLP/HTTP protobuf Logs as the single initial log transport. The
existing OpenTelemetry protobuf dependency supplies its wire messages. The
operator supplies an ingestion endpoint that accepts this protocol. Support by
the deployed Guara backend remains unverified under IN-04. No Loki private wire
format, vendor query translation, new runtime plugins or production changes are
introduced.

Register opt-in `processor.log_processing` before container attribution in the
existing Source → Processor → Generator → Sink pipeline. It adds optional
`processing` metadata to schema-v1 `application_log_observation`. Missing metadata
remains accepted and omitted when serializing older native fixtures. Raw CRI
observations without processing metadata never enter the log worker.

The processor preserves the CRI event timestamp, observed timestamp, stream,
namespace, pod name, pod UID, container name, restart count and collection loss
flags. It processes one bounded assembled body. Existing CRI P/F reconstruction
owns partial-record assembly and its timeout/restart behavior. Embedded multiline
text and JSON messages preserve their line breaks. Separate complete CRI records
are separate events; no heuristic joins unrelated complete records or container
instances. This avoids delayed final-event delivery or new buffering state.

JSON objects/arrays have recursive omission of built-in sensitive keys and
operator-configured case-insensitive keys. Literal redaction applies to strings,
numbers and booleans; keys containing configured literal secrets are omitted.
Only explicitly selected top-level scalar fields become record attributes.
Malformed JSON-looking input has an explicit outcome and omits its body by
default. Operators can choose `keep_redacted` for malformed input, which applies
literal redaction only. Plain text also uses literal redaction. Operators must
supply literals for secrets in free text; this is not an arbitrary secret detector.

The built-in key denylist matches password, passwd, secret, token, authorization,
credential, cookie, api_key, api-key, apikey, private_key and jwt,
case-insensitively, through the shared native sensitive-key predicate. Omission
removes whole nested values before field selection. No unrestricted labels or
application fields become service/resource identity. Debug formatting hides body,
processing values and literal redaction configuration. JSON stdout omits bodies
and processing metadata. There is no dead-letter output. Backend partial-success
text is reduced to a warning bit and never logged by the log worker; failure logs
use a fixed message rather than response/error text.

## Bounds and identity

The default body budget is 16 KiB and 256 lines. Maximums are 32 KiB and 1,024
lines. Up to 64 omission keys and 64 literal redactions, each at most 256 bytes,
are permitted. Up to 32 selected field keys of at most 64 ASCII letters, digits,
underscores or dots have values bounded to 256 bytes. Serde's recursion limit
remains enabled. Input, line, serialized-output and redaction-expansion budgets
reject content with `budget_rejected`, preserving metadata without a partial
secret-bearing prefix. Configuration errors do not reproduce rule values.

The shared Kubernetes cache may supply a workload owner only for exact namespace
and pod UID. Missing or replaced pod UIDs remain unattributed. Owner name/kind
are additive resource attributes. Service name uses the existing native qualified
workload name when available, otherwise the CRI container name, with service
namespace from CRI. Resource identity includes pod UID, container name and restart
count. It does not claim a runtime container ID: the shared metadata cache lacks
restart-count evidence and cannot safely map retained files to current runtime
container IDs. Application `service.name` never replaces this attribution.

The sink maps UTC CRI time to integer OTLP nanoseconds without floating point or
local timezone. Invalid, pre-epoch or u64-unrepresentable times are rejected.
Severity comes from redacted `severity` or `level`; unknown severity keeps its
text and OTLP's unspecified number. Explicit nonzero hexadecimal `trace_id` and
`span_id` are validated; a span ID requires a valid trace ID. No context is inferred
from message content. Record fields use `e.navigator.log.field.*`, independently
of resource attributes. Stream, original byte count and collection/processing
outcomes remain explicit record attributes.

## Worker and acknowledgement boundary

Logs own a fourth bounded worker using ADR 0004's existing nonblocking admission,
batching, timeout, gzip, retries, partial-success decoding, circuit breaking,
shutdown deadline and native `signal_family="logs"` telemetry. Queue-full sheds
new records. Malformed responses and permanent rejection are counted. Partial
success is not retried; rejected records and warning responses have their own
counters. Processing rejection has a separate native counter. The log worker
never performs network I/O on capture or the shared signal path.

With logs enabled, queue capacity plus batch size times a conservative 64 KiB
per-record body/attribute allocation budget may not exceed 128 MiB. This bounds
the retained log worker payload independently of other families. Encoding and
compression have bounded transient batch allocations in addition to this budget.

Read checkpoint advancement remains source-channel admission under ADR 0018.
Processing and worker enqueue are volatile and are not durable acceptance. HTTP
200 accounts sent input records, with backend partial rejection counted separately;
it does not prove backend retention, exactly-once delivery or completed queries.
A crash after a read checkpoint may lose downstream records, and source recovery
may duplicate/reorder records around earlier commits. Issue #56 must change the
checkpoint lifecycle to acknowledge redacted durable spool acceptance before any
restart-safe delivery claim. Unredacted bodies must never enter that spool.

## Validation and qualification

Schema/config goldens, processing privacy and budget fixtures, exact UID cache
fixtures, timestamp/mapping checks and loopback worker tests verify repository
behavior. The loopback collector exercises structured, multiline, malformed and
crash-final content, response handling, queue loss and isolation from metric,
trace and profile workers. It is not a deployed Guara backend.

Acceptance criterion one remains pending recorded backend queries on an authorized
target using IN-03/IN-04/IN-05 and approved cells/budgets under IN-06/IN-07. Do not
close #55 or promote GW-LOG using the local fixtures. No deployment is authorized
by this ADR. See [log processing operations](../log-export.md).
