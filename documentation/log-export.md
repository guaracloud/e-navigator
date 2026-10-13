# Application log processing and OTLP export

The collector supports one initial external log transport, standard OTLP/HTTP
protobuf Logs, under [ADR 0020](adr/0020-processed-otlp-logs.md). It extends
[CRI collection](cri-logs.md) and the existing independent exporters. Defaults
leave collection, payload capture, processing and external log export disabled.

## Configure

Enable the existing `source.cri_logs` and `sink.otlp_http` module rows, and the
packaged `processor.log_processing` row. Keep
`processor.container_attribution` enabled to enrich exact pod UIDs from the shared
Kubernetes controller. Enable the CRI mounts as documented for collection. No
additional mounts or RBAC are needed for export.

```toml
[cri_logs]
enabled = true
include_body = true

[log_processing]
enabled = true
max_body_bytes = 16384
max_lines = 256
omit_keys = ["customer_email"]
redact_values = ["replace-with-approved-literal-secret"]
attribute_keys = ["request_id"]
parse_failure = "omit_body"

[otlp_http]
enabled = true
logs_enabled = true
logs_endpoint = "http://otel-collector:4318/v1/logs"
metrics_enabled = false
traces_enabled = false
profiles_enabled = false
queue_capacity = 1024
batch_size = 64
```

This snippet changes settings, not the module rows. Set each required row's
`enabled = true` too. A complete validated repository example is
[log_export.toml](../crates/e-navigator-core/src/config/golden/log_export.toml).
Endpoints are full request URLs. `logs_endpoint` falls back to `endpoint`; the
sink does not append `/v1/logs`. Keep the existing metrics/traces/profiles enabled
with their own endpoints when those families are required. Validate before any
authorized deployment:

```sh
cargo run --locked -p e-navigator-cli -- --validate-config --config /path/to/config.toml
```

Literal secrets in configuration must be protected as configuration data. The
native configuration Debug formatter and validation errors hide their values.
The sample redaction literal is a placeholder, not production privacy policy.
Bodies default to omitted at collection. Explicit payload capture/export requires
an approved policy for the selected workloads. JSON omission rules remove nested
subtrees; plain text and malformed `keep_redacted` bodies require matching literal
rules. `omit_body` is the safe malformed-JSON default. JSON scalar fields are
exported only through `attribute_keys`; they never become resource dimensions.

## Outcomes and budgets

Processing records `json`, `plain_text`, `malformed_json`, `body_omitted` or
`budget_rejected`. An oversized input, too many lines or an expanding redaction
omits the whole body. Stream, event/observed time, CRI instance identity and
truncated/incomplete/invalid-UTF-8 flags remain available. Complete CRI events
remain separate; explicit multiline bodies and bounded CRI partial assembly are
preserved without heuristic joins. Crash-final records are exported immediately
once the source emits them, including its incomplete flag.

Kubernetes enrichment joins exact namespace/pod UID to a cached workload owner.
`e.navigator.log.workload_attributed=false` exposes missing metadata, including
retained files for an exited or replaced pod. No current container ID is attached
to historical restart records by inference. Resource attributes carry identity;
selected record fields carry the `e.navigator.log.field.*` prefix. JSON stdout
always omits application bodies and processing fields.

Inspect native Prometheus telemetry independently of backend health:

- `e_navigator_log_processing_rejected_total` counts malformed/budget outcomes
  and log records rejected before worker admission, including unprocessed inputs
  and invalid/unrepresentable timestamps.
- Existing `e_navigator_export_*` metrics with `signal_family="logs"` expose
  queue capacity/depth, accepted/sent records, queue-full/closed/circuit/failure
  losses, request timing, retries and backend rejection/partial-success outcomes.

Malformed JSON with `keep_redacted` is still counted as a parse failure even when
its redacted body is exported. Omitted collection bodies are valid metadata-only
records and are not counted as processing rejection. Configure source and
processing body limits together to avoid retaining content that processing will
reject. The source defaults to 16 KiB; processing permits 32 KiB at most.

Worker delivery is volatile unless [durable export](durable-export.md) is selected.
Source read checkpoints, worker admission and
HTTP acknowledgement are different boundaries. HTTP acknowledgement alone does
not establish retained/queryable data. See ADR 0021 before claiming
restart-safe export or deleting any retained source/checkpoint files.

## Acceptance status

Local fixtures verify mapping and exporter isolation. Issue #55 remains open
until recorded queries from the deployed backend prove expected structured,
multiline, malformed and crash-final content with correct instance identity.
The replacement contract still needs backend identity/settings and query/privacy
expectations under IN-04/IN-05, authorization under IN-03 and exact approved
cells/thresholds under IN-06/IN-07. The OTLP choice is an implementation decision,
not a claim that the deployed ingestion path has been verified. No production or
infrastructure changes are part of this implementation.
