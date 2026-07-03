# Proof Report

This report is the curated public evidence summary for E-Navigator. It replaces
the previous chronological sample ledger with a capability-oriented view.

Status vocabulary:

- **Proven:** the stated behavior has direct recorded evidence.
- **Partial:** a useful slice is proven, but nearby production behavior remains
  outside the claim.
- **Not proven:** implementation may exist, but required evidence is missing.
- **Blocked:** the run identified an environmental or version boundary that
  prevents the proof from being completed as attempted.

## Proven Locally

These areas are proven by local tests, fixtures, synthetic runs, Docker smoke,
or chart rendering:

- static module registration and runner fan-out;
- versioned JSON signal envelopes with bounded source and host metadata;
- JSON stdout newline-delimited serialization and sink-side redaction, including
  exec strings, argument count, and nested context strings/labels, exec and
  runtime-security matched-process argv redaction, bounded runtime-security
  finding strings and matched-process argument count, protocol request
  observations without retained raw trace headers and with bounded sanitized trace
  attributes, identifier/scalar strings, and process/context/peer strings and
  labels, trace signal families with bounded identifier/scalar, process,
  endpoint, and context strings and labels, network connection signals with
  bounded process/address/context strings, deterministic attribution cache
  eviction, and safe Kubernetes labels, network flow warning signals with
  bounded process/address/source/message/context strings, network flow summary
  endpoint strings and dependency endpoint
  address/domain/context strings and labels, DNS signal families with bounded
  DNS, process, and context strings
  and labels, network metric signal families with bounded metric, process,
  context strings and labels,
  node/process/cgroup resource observation signals with bounded strings,
  resource metric signals with bounded scalar/context strings including nested
  container/Kubernetes contexts and bounded sensitive-key-filtered dynamic
  attributes, and profiling signal families with bounded sensitive/reserved
  profiling attribute filtering, stack frames, scalar strings, process/context
  strings, and labels;
- synthetic source pipeline, including sanitized HTTP, gRPC, Kafka, MongoDB,
  MySQL, NATS, PostgreSQL, and Redis protocol request/error-span fixtures and
  flow-attribution warnings;
- strict config validation with unknown-field rejection, packaged config guards,
  runtime log-level, queue/derivation, and runtime-security endpoint bounds,
  Prometheus and OTLP HTTP sink runtime-bound validation, Prometheus bind-address
  host/port-shape validation, OTLP HTTP endpoint host/shape/length validation,
  shared HTTP exporter endpoint shape/length validation plus header count/size
  validation and upper-bound validation for batch, queue, timeout, and retry
  settings, local Kubernetes attribution selector filtering and
  selector-shape/whitespace/duplicate bounds plus response/cache/label/path
  bounds, runtime `NODE_NAME` field-selector shape validation, including
  combined container-ID and pod-IP cache-entry bounds, cgroup-ID attribution
  scan/cache bounds, and host resource source scan/path/cgroup-traversal/fd
  scan plus metric-generator cardinality bounds;
- procfs, sysfs, cgroup, loadavg, meminfo, diskstats, and process-stat
  parsing, including cgroup container-ID extraction that requires
  container/Kubernetes cgroup markers rather than unrelated 64-hex substrings;
- raw userspace decode paths for selected Aya exec/network/DNS/HTTP/profile
  events, including profile fixture normalization with sensitive/reserved
  attribute filtering, owned stack-truncation markers, raw DNS label-shape
  validation, and build-checked DNS and HTTP raw decode fuzz targets plus HTTP
  iovec length validation;
- bounded DNS request parsing with configurable packet and diagnostic preview
  limits plus validated preview/packet relationships, bounded DNS-derived
  domain label-shape validation, bounded HTTP request parsing with configurable
  HTTP parser limits and validated header/sub-limit relationships plus
  HTTP/1.x version-token validation and CONNECT authority-form extraction,
  HTTP response-status fixture parsing with version-token validation and a
  build-checked parser fuzz target, strict W3C traceparent parsing,
  decoded gRPC-over-HTTP/2 metadata and trailer-status parsing with bounded
  content-type suffix validation, POST pseudo-header validation,
  authority-port/userinfo validation, and a build-checked parser fuzz target,
  Kafka request-header plus bounded ApiVersions, non-flexible FindCoordinator,
  Heartbeat, ListOffsets, and Metadata request bodies, ApiVersions response,
  bounded Produce request/response, and bounded non-flexible Fetch,
  FindCoordinator, Heartbeat, ListOffsets, and Metadata request/response-error
  parsing,
  MongoDB
  wire-message and response-error parsing with OP_MSG section and checksum
  validation, bounded OP_REPLY response parsing, and non-negative response-code validation,
  MySQL command packet parsing for quit/init-db/query/ping/prepare/execute/
  send-long-data/close/reset/fetch/reset-connection plus OK/EOF/ERR response
  parsing with canonical SQLSTATE validation and build-checked parser fuzz coverage, NATS text command
  parsing with canonical command-token and exact non-payload frame validation
  plus OK/error response parsing,
  PostgreSQL Query/Parse/Bind/Describe/Close/Execute/FunctionCall/CopyData/
  CopyDone/CopyFail/Password/Flush/Sync/Terminate wire-message and
  Authentication/BackendKeyData/ParseComplete/BindComplete/CloseComplete/
  ParameterDescription/RowDescription/DataRow/FunctionCallResponse/backend
  CopyData/CopyDone/CopyInResponse/CopyOutResponse/CopyBothResponse/
  EmptyQueryResponse/NoData/PortalSuspended/CommandComplete/
  NegotiateProtocolVersion/NotificationResponse/NoticeResponse/ParameterStatus/
  ReadyForQuery/ErrorResponse parsing with canonical SQLSTATE validation and
  build-checked parser fuzz
  coverage, and Redis RESP command plus
  simple/integer/bulk/RESP3-scalar/RESP3-blob-error/verbatim/flat-array/
  nested-array/RESP3-map/RESP3-set/RESP3-push/error response parsing with
  declared frame-length bounds,
  bounded response-status token validation, and build-checked parser fuzz
  coverage;
- network, DNS, resource, dependency, request, trace, profiling, and runtime
  security generator behavior, including synthetic protocol request/error-span
  flow, deterministic service path keys, precise duplicate flow suppression with
  deterministic bounded dedupe eviction, bounded flow-byte aggregation across
  remote destinations, flow-attribution warnings, bounded DNS-derived
  service-path domains with deterministic bounded dedupe eviction, generated
  flow-summary destination pod-IP attribution before sinks, deterministic
  resource metric dedupe eviction, deterministic trace-correlation interaction
  and warning dedupe eviction,
  deterministic profile sample and warning dedupe eviction, deterministic
  profile session IDs with sampling-period separation, generated profile session
  bounded and non-empty sensitive/reserved-attribute filtering, bounded safe-attribute
  merging across samples, bounded profile stack-ID state,
  bounded request-span scalar fields and attributes with sensitive trace
  attribute filtering, deterministic request-correlation request and warning
  dedupe eviction, and dropped-profile-sample warnings;
- Prometheus HTTP formatting, profile session aggregate rendering, profiling
  warning-count rendering, metric/profile family toggles, health/readiness
  endpoints, constructor-validated latest-metric storage bounds, bounded
  latest-metric storage, bounded metric attribute counts, bounded label
  names/values, and secret-like label filtering;
- OTLP protobuf request encoding plus per-family endpoint routing and family
  toggle suppression for metrics with bounded scalar/resource/attribute keys
  and values, native `network.flow.bytes` fake-collector export, traces with
  HTTP, gRPC, `error.type`, and protocol response-status request/error status
  mapping, server span kind and Kubernetes resource
  attributes with bounded trace resource/context/scalar values
  including Kafka, MongoDB, MySQL, NATS, PostgreSQL, and Redis request spans,
  local warning trace-record formatting for trace, request, network-flow, and
  profiling warnings, explicit no-ID network-flow and profiling-warning trace
  export suppression, bounded profiling-warning trace attributes,
  hex-shape and nonzero trace/span ID filtering,
  bounded non-empty final OTLP attribute key and string value conversion, and
  development-status profile sample records with
  deterministic, workload-aware IDs, bounded session IDs, bounded resource
  attributes, bounded stack frames, final canonical-plus-user attribute caps,
  bounded/sensitive attribute filtering, and session dropped-sample records in
  fake-collector tests;
- native profile record formatting with bounded identifiers, bounded resource
  attributes, and non-empty sensitive attribute filtering;
- pprof-compatible profile sample protobuf rendering with bounded stack
  locations, sample-period scaling, bounded frame strings and workload labels,
  canonical label overwrite protection, and sensitive/canonical metadata
  attribute filtering;
- local Criterion hot-path benchmark harness compile coverage for host parsers,
  raw Aya decode harnesses, traceparent, HTTP, gRPC, Kafka, MongoDB, MySQL,
  NATS, PostgreSQL, and Redis protocol parsers, Kubernetes metadata cache
  construction, generators, and sink formatters;
- dedicated fuzz-target build checking through `scripts/fuzz_check.sh`, now
  wired into the local quality gate;
- Helm rendering, schema checks, and release verification workflow structure.

## Runtime-Proven Slices

Guarded Linux/Kubernetes runs have recorded these slices:

- E-Navigator DaemonSet readiness on the homelab benchmark namespace for
  selected images and configurations.
- Live `source.aya_exec` and `source.aya_network` records from Kubernetes nodes.
- Kubernetes/container attribution on selected exec, network, metric,
  dependency, trace-derived, DNS, HTTP, and profile records.
- Host resource source and resource metric output under selected seccomp
  settings.
- Runtime security findings from observed process and network activity.
- DNS source/generator output for selected UDP DNS paths, including a proven
  `homelab-02` connected-UDP Python client path under RuntimeDefault seccomp.
- Cleartext HTTP request/span capture for selected `homelab-02` client paths
  using bounded `writev`/iovec shapes, including one RuntimeDefault seccomp run.
- CPU profile source/generator output and selected controlled workload
  attribution, including live profile records exported through OTLP profile
  protobuf to a namespace-local OpenTelemetry Collector.
- Prometheus HTTP endpoint reachability and selected live scrape/query evidence
  for E-Navigator metric series.
- Namespace-local OpenTelemetry Collector acceptance for OTLP metric, trace, and
  development-status profile protobuf slices.
- Workload scheduling, workload cleanup, and collector wait behavior for the
  guarded homelab harness.

## Partial Or Not Yet Proven

These areas remain explicitly partial:

- **Native flow byte metric export:** code emits native `network.flow.bytes`,
  Prometheus renders it as `network_flow_bytes`, OTLP HTTP fake-collector export
  is locally proven, and byte-counted closes without complete source attribution
  emit warnings locally, but positive live native export and warning proof must
  be rerun after the native metric migration.
- **HTTP/gRPC capture:** selected `homelab-02` outbound cleartext HTTP/1 paths
  work and bounded HTTP/1 response-status plus CONNECT authority parsing and
  decoded gRPC-over-HTTP/2 metadata/trailer-status parsing are locally tested,
  including explicit gRPC POST pseudo-header validation, but symmetric node
  coverage, inbound parsing, TLS, runtime HTTP/2 frame/HPACK capture, live HTTP
  or gRPC status matching, route templates, retries, app errors, and broader
  iovec shapes are not proven.
- **Trace readiness:** OTLP trace protobuf export includes request span kind,
  resource attributes, and local status mapping for HTTP status errors, gRPC
  status errors, selected `error.type` protocol request errors,
  response-status attribute errors, and network interaction errors, but broad
  backend service-graph compatibility and live collector proof for the status
  mappings are not yet proven.
- **Kafka protocol observability:** bounded request-header parsing for common
  API keys, bounded ApiVersions request-body validation, bounded non-flexible
  Produce, Fetch, FindCoordinator, Heartbeat, ListOffsets, and Metadata
  request-body validation, and ApiVersions, Produce, and non-flexible Fetch,
  FindCoordinator, Heartbeat, ListOffsets, and Metadata response-error parsing
  is locally tested without exporting client IDs, coordinator keys, consumer
  group/member identifiers, software names, topics, record payloads, broker
  hosts, cluster IDs, or response body values, but runtime capture,
  request/response matching, broad response coverage, flexible-version body
  semantics beyond ApiVersions, and live Kafka proof are not implemented or
  proven.
- **MongoDB protocol observability:** bounded `OP_MSG` including
  checksum-present messages, command `OP_QUERY`, OP_MSG response-error parsing,
  and OP_REPLY response parsing is locally tested without exporting raw BSON
  values, namespaces, checksums, or raw error messages, including bounded
  OP_REPLY document counts and non-negative response-code validation, but runtime
  capture, request/response matching, broad response coverage, and live MongoDB
  proof are not implemented or proven.
- **NATS protocol observability:** bounded text command parsing for common
  publish, subscribe, message, and control lines plus OK/error response parsing
  is locally tested with canonical command-token validation and without
  exporting raw subjects, payloads, or raw error messages, including exact
  frame-end validation for non-payload commands and responses, but runtime
  capture, request/response matching, broad response coverage, and live NATS
  proof are not implemented or proven.
- **MySQL protocol observability:** bounded `COM_QUERY`,
  `COM_QUIT`, `COM_INIT_DB`, `COM_PING`, `COM_STMT_PREPARE`,
  `COM_STMT_EXECUTE`, `COM_STMT_SEND_LONG_DATA`, `COM_STMT_CLOSE`,
  `COM_STMT_RESET`, `COM_STMT_FETCH`, `COM_RESET_CONNECTION`, and OK/EOF/ERR
  response parsing is locally tested without exporting raw SQL text, schema names,
  statement IDs, parameter values, long parameter data, or raw error messages,
  including canonical SQLSTATE validation for error responses, but runtime
  capture, request/response matching, broad
  response coverage, and live MySQL proof are not implemented or proven.
- **PostgreSQL protocol observability:** bounded simple Query, Parse, Bind,
  Describe, Close, Execute, FunctionCall, CopyData, CopyDone, CopyFail,
  PasswordMessage, Flush, Sync, Terminate, Authentication, BackendKeyData,
  ParseComplete, BindComplete, CloseComplete, ParameterDescription,
  RowDescription, DataRow, FunctionCallResponse, backend CopyData, backend
  CopyDone, CopyInResponse, CopyOutResponse, CopyBothResponse,
  EmptyQueryResponse, NoData, PortalSuspended, CommandComplete,
  NegotiateProtocolVersion, NotificationResponse, NoticeResponse,
  ParameterStatus, ReadyForQuery, and ErrorResponse parsing is locally tested
  without exporting raw SQL text, function OIDs, function return values,
  argument values, parameter type OIDs, row values, authentication salts or SASL
  data, backend cancellation keys, copy payloads, copy format metadata, copy
  failure text, negotiated protocol versions or option names, notification
  channel or payload values, password values, row field names, notice text,
  parameter status values, or raw error messages, including
  canonical SQLSTATE validation for notice and error responses, but runtime
  capture,
  request/response matching, broad
  response coverage, and live PostgreSQL proof are not implemented or proven.
- **Redis protocol observability:** bounded RESP command and
  simple/integer/bulk/RESP3-scalar/RESP3-blob-error/verbatim/flat-array/
  nested-array/RESP3-map/RESP3-set/RESP3-push/error response parsing is locally
  tested without exporting raw key/value payloads or raw error messages,
  including declared frame-length bounds and bounded response-status token
  validation, but runtime capture, request/response matching, broad response
  coverage, and live Redis proof are not implemented or proven.
- **DNS capture:** selected UDP paths work, but symmetric all-node capture and
  lossless DNS coverage are not proven.
- **CPU profiling:** selected samples and sessions plus local pprof protobuf
  rendering are proven, but deterministic capture for every workload shape,
  symbolization, runtime pprof upload, storage, and flamegraph rendering are not
  proven.
- **Exporter infrastructure:** local and namespace-local proof exists, but broad
  production backend/collector compatibility and longer live soaks are not
  proven.
- **Resource and privilege posture:** selected resource samples and seccomp
  slices are proven, but reduced overhead, reduced capabilities, and non-root
  eBPF operation are not proven.

## Blocked Or Version-Boundary Findings

Some proof attempts established useful boundaries rather than positive claims:

- Older benchmark images rejected newer modules such as `source.aya_dns`,
  `sink.prometheus_http`, and `sink.otlp_http`; those are image-vintage
  boundaries, not current-head feature failures.
- The 20260624 OTLP per-family endpoint homelab proof was blocked because the
  checked DaemonSet image was not proven to include the local change and the
  local Docker daemon did not respond for building a current image; local
  fake-collector routing tests remain the evidence for that change.
- Some BPF diagnostic experiments were verifier-hostile on the tested homelab
  kernel and were reverted.
- Some controlled workloads completed successfully but produced no matching
  protocol/profile/DNS records; those remain negative runtime evidence, not
  product claims.

## Publication Rule

Future proof updates should edit this report only after the raw run records
enough evidence to support the exact statement. Nearby capabilities must remain
listed as partial, not proven, or blocked unless they were directly observed.
