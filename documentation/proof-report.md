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
- Kubernetes-aware capture filter (`[capture_filter]`): the pure policy
  evaluator (glob namespace matching, exact label include/exclude, fixed
  exclude-wins precedence, `default_posture`/`unknown_cgroup` postures), the raw
  node-pod-list parser and resolver, the desired-map builder and
  `FilterMapMirror` diff (upsert/removal/verdict-flip convergence), and the
  systemd/cgroupfs/guaranteed-QoS cgroup-path pod-UID and container-id parsers,
  all unit-tested with malformed/arbitrary-byte coverage; `deny_unknown_fields`
  config validation and posture parsing; a privacy invariant test asserting only
  cgroup ids and 0/1 verdict bytes reach the kernel-bound map (no namespace or
  label strings); `capture_filter_glob` and `capture_filter_cgroup_path` fuzz
  targets; and Criterion rule-eval (~9-12ns), whole-node desired-build (~11.8us
  for 300 cgroups), and map-diff (~3.4us steady, ~555ns churn) benchmarks;
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
  Kafka request-header plus bounded ApiVersions, flexible AddRaftVoter, UpdateRaftVoter, InitializeShareGroupState, ReadShareGroupState, WriteShareGroupState, DeleteShareGroupState, ReadShareGroupStateSummary, DeleteShareGroupOffsets, DescribeShareGroupOffsets, RemoveRaftVoter, AlterPartitionReassignments, AlterUserScramCredentials, ConsumerGroupDescribe, ControllerRegistration, ConsumerGroupHeartbeat, ShareGroupHeartbeat, DescribeCluster, DescribeProducers, BrokerHeartbeat, DescribeQuorum, DescribeTopicPartitions, DescribeTransactions, DescribeUserScramCredentials, GetTelemetrySubscriptions, ListConfigResources, ListPartitionReassignments, ListTransactions, AllocateProducerIds, PushTelemetry, UnregisterBroker, UpdateFeatures, and WriteTxnMarkers, flexible/non-flexible AlterClientQuotas, DescribeClientQuotas, and IncrementalAlterConfigs, non-flexible AlterConfigs, AlterReplicaLogDirs, CreateDelegationToken, DescribeDelegationToken, DescribeLogDirs, ElectLeaders, ExpireDelegationToken, RenewDelegationToken, AddOffsetsToTxn, AddPartitionsToTxn,
  CreateAcls, CreatePartitions, CreateTopics, DeleteAcls, DeleteRecords, DeleteTopics, DescribeAcls, DescribeConfigs, DescribeGroups, DeleteGroups, EndTxn, FindCoordinator, Heartbeat,
  InitProducerId, JoinGroup, LeaveGroup, ListGroups, ListOffsets, Metadata, OffsetCommit,
  TxnOffsetCommit, SaslAuthenticate, SaslHandshake, OffsetDelete, OffsetForLeaderEpoch, OffsetFetch, and SyncGroup request bodies,
  ApiVersions response, bounded Produce request/response, and bounded
  flexible AddRaftVoter, UpdateRaftVoter, InitializeShareGroupState, ReadShareGroupState, WriteShareGroupState, DeleteShareGroupState, ReadShareGroupStateSummary, DeleteShareGroupOffsets, DescribeShareGroupOffsets, RemoveRaftVoter, AlterPartitionReassignments, AlterUserScramCredentials, ConsumerGroupDescribe, ControllerRegistration, ConsumerGroupHeartbeat, ShareGroupHeartbeat, DescribeCluster, DescribeProducers, BrokerHeartbeat, DescribeQuorum, DescribeTopicPartitions, DescribeTransactions, DescribeUserScramCredentials, GetTelemetrySubscriptions, ListConfigResources, ListPartitionReassignments, ListTransactions, AllocateProducerIds, PushTelemetry, UnregisterBroker, UpdateFeatures, and WriteTxnMarkers, flexible/non-flexible AlterClientQuotas, DescribeClientQuotas, and IncrementalAlterConfigs, and non-flexible AddOffsetsToTxn, AddPartitionsToTxn, AlterConfigs, AlterReplicaLogDirs, CreateDelegationToken, DescribeDelegationToken, DescribeLogDirs, ElectLeaders, ExpireDelegationToken, RenewDelegationToken, CreateAcls, CreatePartitions, CreateTopics, DeleteAcls, DeleteRecords, DeleteTopics, DeleteGroups, DescribeAcls, DescribeConfigs, DescribeGroups,
  EndTxn, Fetch, FindCoordinator, Heartbeat, InitProducerId, JoinGroup, LeaveGroup, ListGroups,
  WriteTxnMarkers, SaslAuthenticate, SaslHandshake, ListOffsets, Metadata, OffsetCommit, TxnOffsetCommit,
  OffsetDelete, OffsetForLeaderEpoch, OffsetFetch, and SyncGroup
  request/response-error parsing,
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
  names/values, secret-like label filtering, and deterministic fingerprints
  that keep bounded redacted metric identities distinct without exporting raw
  workload, process, endpoint, or DNS dimensions;
- OTLP protobuf request encoding plus per-family endpoint routing and family
  toggle suppression for metrics with bounded scalar/resource/attribute keys
  and values, bounded latest-value coalescing for same-receiver-millisecond
  cumulative updates across batches, idle-window and shutdown flushing, native
  `network.flow.bytes` fake-collector export, traces with
  HTTP, gRPC, `error.type`, and protocol response-status request/error status
  mapping, server span kind and Kubernetes resource
  attributes with bounded trace resource/context/scalar values
  including Kafka, MongoDB, MySQL, NATS, PostgreSQL, and Redis request spans,
  local warning trace-record formatting for trace, request, network-flow, and
  profiling warnings, explicit no-ID network-flow and profiling-warning trace
  export suppression, bounded profiling-warning trace attributes,
  hex-shape and nonzero trace/span ID filtering,
  bounded non-empty final OTLP attribute key and string value conversion, and
  development-status OTLP Profiles `v1development` `v0.3.0` sample records
  with deterministic workload-aware IDs, bounded resource attributes and stack
  frames, canonical-plus-user attribute caps, bounded/sensitive filtering, and
  explicit cumulative-session export suppression. The pinned real Pyroscope
  `1.20.3` local smoke accepted the request and its Guara-shaped backend query
  returned `synthetic_api::checkout_handler` and deep representative frames;
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

- Dual BPF event transport proof (2026-07-21, homelab k3s v1.30, kernel 6.6,
  amd64, two NixOS nodes). A locally built, never-pushed image was loaded into
  the homelab only. Three counterbalanced 180-second runs each compared no
  benchmark E-Navigator release, forced perf buffers, and forced RingBuf with
  the exec and network Aya sources under identical connection, DNS, and process
  churn. Both forced modes loaded on both nodes and all captured source
  summaries reported zero transport loss, perf loss, RingBuf reservation
  failures, invalid samples, and send failures. RingBuf versus perf measured
  -0.56% requests/s, +1.46% mean latency, +11.40% summed agent CPU, and -4.45%
  summed agent RSS. These short shared-cluster results prove transport operation
  and accounting, not a RingBuf overhead win. The older-kernel automatic
  fallback remains unit-tested but not runtime-proven because both nodes run
  Linux 6.6. The numeric artifact and exact non-claims are in
  `documentation/proof/event-transport-20260721/`. Disposable resources were
  removed and the standing Argo CD application returned Synced/Healthy with its
  original digest-pinned DaemonSet 2/2 Ready.

- BTF fexit network byte-accounting proof (2026-07-21, homelab k3s v1.30,
  kernel 6.6.68, amd64, two NixOS nodes). Three counterbalanced 90-second runs
  each compared no benchmark agent, forced syscall tracepoints, and forced
  `ksys_read`/`ksys_write` fexit while holding RingBuf and the one-source agent
  profile constant. A pinned Python workload issued exact 256-byte
  `os.write`/`os.read` round trips over one tracked TCP connection. Every
  enabled run emitted exactly one matching close event whose sent and received
  totals equaled the workload total, and all six reported zero transport loss.
  Fexit versus tracepoints measured +7.971% operations/s and -7.710% mean
  latency, passing the predeclared +5% throughput and at-most +2% latency gates.
  Fexit remained -7.045% operations/s versus no agent, kept two-pod agent CPU
  effectively unchanged, and increased summed RSS from 20.611 to 34.000 MiB.
  This proves and motivates the narrow scalar read/write hook selection; it is
  not a mixed-workload, lower-memory, old-kernel-fallback, production, or
  universal overhead claim. The numeric artifact and exact boundaries are in
  `documentation/proof/kernel-hook-20260721/`. The local image was loaded
  directly into homelab containerd and never pushed. Disposable resources were
  removed, and the standing Argo CD application returned Synced/Healthy with
  its original digest-pinned DaemonSet 2/2 Ready.

- Go `crypto/tls` userspace-boundary proof (2026-07-21 local date, homelab k3s
  v1.30, kernel 6.6.68, amd64, two NixOS nodes). Three counterbalanced pairs
  compared a clean no-agent arm with an agent enabling only the TLS source and
  RingBuf transport. A pinned Go 1.26.4 image ran two normal HTTPS replicas and
  one `-s -w` rejection control. All six clients completed 4,000 of 4,000
  requests. Every TLS run logged the exact unstripped binary as capture-ready,
  rejected the stripped binary for its absent static symbol, emitted
  workload-scoped `/proof` HTTP 200 observations through `source.aya_tls`, and
  exposed positive Go entry/exit/fd/output counters with zero state-update
  failures, zero transport loss, and zero RingBuf reservation failures. Every
  no-agent inventory contained zero benchmark agent pods. This proves the Go
  1.26.4 Linux/amd64 HTTP/1 slice, not Go 1.24/1.25 runtime compatibility,
  other architectures/protocols, production, or overhead. The request bursts
  lasted only 0.105 to 0.265 seconds, so their throughput and resource numbers
  are recorded but support no performance claim. Curated evidence is in
  `documentation/proof/go-crypto-tls-20260721/`. Both local-only images,
  workloads, the benchmark release, loader, and namespace were removed. The
  standing Argo CD application returned Synced/Healthy with automated
  prune/self-heal and its original digest-pinned DaemonSet 2/2 Ready.

- Capture-filter verifier-load and OrbStack live scoping proof (2026-07-07,
  OrbStack Docker plus its in-VM Kubernetes v1.34, arm64). The cgroup capture
  filter's in-kernel fast-path check verifier-loaded on every modified program:
  the exec/network/dns/http/protocol sources emitted events with TLS uprobes
  attached, and the `cpu_profile` DWARF/CPython tail-call chain sampled, all with
  the check inlined and no verifier rejection. A privileged hostPID DaemonSet was
  then deployed on OrbStack Kubernetes with an allowlist policy
  (`default_posture`/`unknown_cgroup = "deny"`, `namespace_include =
  ["proj-included"]`) and identical Redis workloads in `proj-included` and
  `proj-excluded`. Recorded, then cleaned up:
  - The controller logged `capture filter active control_word=2` with no
    API-unavailable warning, confirming the raw attribution-unscoped node
    pod-list fetch worked in-cluster.
  - `proj-included` was captured with full attribution (exec/network/protocol
    records carrying container id and pod context, including namespace, pod name/uid,
    container name, node, labels).
  - `proj-excluded` produced zero filterable signals (0 exec, 0
    network-connection open/close, 0 protocol) over the whole run; its only
    signals were softirq `network_tcp_stat_observation` events, which the filter
    deliberately does not cgroup-scope, and which appeared at effectively equal
    counts in both namespaces (~4260), corroborating that they are node-scoped.
    No bootstrap leak occurred under the allowlist posture.
  - Drop accounting was emitted per source and climbed with excluded traffic
    (network `dropped_total` 7404 -> 60519 over ~3 minutes; `denied=15` cgroups,
    `live_entries=21`).
  - Overhead A/B, identical `redis-benchmark -n 50000 -c 20`: the filtered-out
    (excluded) workload ran at ~+42% throughput (SET 134,048 -> 190,114 rps; GET
    148,809 -> 210,970 rps) and ~-20% p50 latency (0.079 -> 0.063 ms) versus the
    captured workload, because its connections are filtered at `connect()` and
    never tracked so the per-syscall read/write path early-exits. Recorded as a
    local OrbStack smoke figure on a shared node, not a production number.
  Cleaned up fully (test namespaces, ClusterRole/binding, and the built image).
- Capture-filter homelab live scoping proof (2026-07-07, homelab k3s v1.30,
  kernel 6.6, x86_64, containerd runtime, workloads pinned to `homelab-02`).
  The x86_64 CLI cross-built from the committed code was staged into the node's
  containerd and rolled out as a privileged hostPID DaemonSet with the same
  allowlist policy (`namespace_include = ["proj-included"]`) against identical
  low-rate Redis workloads in throwaway `proj-included` and `proj-excluded`
  namespaces. Recorded, then cleaned up:
  - Included pods were captured with full attribution resolved from the
    **systemd `kubepods.slice` cgroup driver** (`runtime=containerd`, pod UID
    read from the `...-pod<uid>.slice` path), which is the cgroup-driver path the
    OrbStack docker runtime does not exercise. The controller applied
    `allowed=3, denied=50` cgroups, confirming the in-cluster raw pod-list
    fetch.
  - `proj-excluded` produced zero filterable signals over the whole run; its
    only signals were node-scoped softirq `network_tcp_stat_observation` events
    at effectively equal count to the included namespace (2388 vs 2400). No
    bootstrap leak under the allowlist posture.
  - Per-source drop accounting climbed (exec 3649 -> 9297, network 13702,
    protocol 5380). Both nodes stayed Ready throughout (no control-plane
    flapping). The overhead A/B was deliberately skipped on the homelab to keep
    load gentle; the quantified figure remains the OrbStack local smoke A/B
    above, with the drop counter confirming the excluded path is the cheap one.
  Recorded as homelab live proof, not production proof. Cleanup independently
  verified: no throwaway namespaces, ClusterRole/binding, or imported images
  remained, and the user's namespaces were untouched.

- Homelab Kubernetes live proof (2026-07-06, homelab k3s v1.30, kernel 6.6,
  x86_64, single `e-navigator` namespace on the `homelab-02` node). A
  privileged hostPID DaemonSet built from the current binary was rolled out
  alongside resource-limited Redis, PostgreSQL, MongoDB, NATS, Kafka
  (KRaft), gRPC (grpcbin), and TLS-nginx workloads with per-protocol client
  loops, and separately a CPython 3.12 and a frame-pointer-omitted C
  workload for profiling. Recorded, then cleaned up:
  - `source.aya_protocol` captured Redis, PostgreSQL, MongoDB, NATS, gRPC,
    and Kafka requests with request/response matching and semantic
    attributes (`db.operation=SET`, `db.system=postgresql`, `rpc.system=grpc`,
    `messaging.system=kafka` with error code, etc.); no raw payloads.
  - `source.aya_tls` captured HTTPS requests through libssl uprobes across
    the pod's mount namespace (the cross-namespace library-resolution fix)
    with matched 200 responses.
  - `source.aya_cpu_profile` native DWARF/CFI unwinding verifier-loaded and
    ran on the 6.6 kernel, producing symbolized stacks for node processes;
    CPython 3.12 interpreter unwinding produced complete
    function/file/line stacks for the containerized python workload
    (`leaf_busy` -> `level_c` -> `level_b` -> `level_a` -> `main` ->
    `<module>`) via the pid-namespace thread-translation fix.
  - Container and Kubernetes attribution attached to captured records
    (container id plus pod context with the DaemonSet's `NODE_NAME` and a
    pod-read ClusterRole), and the Prometheus sink served attributed
    `network_*` metric families in-cluster.
  Recorded honestly as homelab live proof, not production proof. Not cleanly
  verified on the homelab this session: native DWARF unwinding of pod
  process stacks specifically, because the in-kernel unwind-table row pool is
  capacity-bounded on a node running several hundred processes with large
  system libraries, and while demand-driven prioritization and per-refresh
  pool re-allocation are implemented and DWARF-proven on OrbStack, full pod
  native-DWARF coverage under that load was not confirmed. TCP retransmit
  induction and live Prometheus scrape wiring beyond the served endpoint
  also remain out of this run.
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
- Live `source.aya_protocol` Redis request capture on a local OrbStack Docker
  VM (2026-07-04): with only `source.aya_protocol` enabled, a privileged run
  captured pipelined RESP traffic from a Python client to a throwaway Redis
  container and emitted one `protocol_request_observation` per command (10
  observations for 5 connections sending pipelined GET+PING), with correct
  process identity, peer address/port, `db.operation`, high confidence, and
  `db.redis.key_present=true` while the key bytes were absent from every
  exported record. This is local smoke proof only, not production or
  Kubernetes proof; Kafka, PostgreSQL, MySQL, MongoDB, and NATS live capture
  paths are implemented but not yet runtime-proven.
- Live TCP stack accounting on the local OrbStack Docker VM (2026-07-04,
  host PID namespace): the aya-network source emitted 30
  `network_tcp_stat_observation` reset signals (send direction, correct
  loopback tuple and python3 process attribution) from abortive SO_LINGER
  closes, plus 182 state-transition observations across established, close,
  syn_sent, syn_recv, and listen. Retransmit capture attaches its
  tracepoint but was not induced (loopback has no loss); the retransmit
  decode and generator aggregation are unit-tested. Counter aggregation
  (network.tcp.retransmits/resets/transitions) is unit-tested; this run
  exercised the source observation path only. Local smoke proof only.
- Live CPU profile symbolization and pprof serving on the local OrbStack
  Docker VM (2026-07-04, host PID namespace): the aya-cpu-profile source
  captured ~32k samples under a busy workload and resolved frame-pointer
  frames to real modules and module-relative offsets (for example
  `/opt/orb/scon-agent+0x3f643c` with `module_offset` set), and the
  Prometheus sink `/debug/pprof/profile` endpoint served a ~30 KB pprof
  protobuf carrying module mappings and location addresses. Frames requiring
  DWARF unwinding (interpreted/JIT stacks) and idle `swapper` samples
  correctly fall back to raw `ip:` addresses. Local smoke proof only;
  DWARF unwinding and Kubernetes-node symbolization remain unproven (the
  32-frame kernel cap this run operated under was lifted to a configurable
  depth on 2026-07-05; see the configurable-depth entry below).
- Live inbound (server-side) HTTP capture on the local OrbStack Docker VM
  (2026-07-04): with `http_source.inbound_enabled`, five curl requests
  against a local Python HTTP server produced exactly five
  `protocol_request_observation` records with `role=server`, correct
  method/path attributes, and client peer attribution, alongside the
  existing client-role capture. Local smoke proof only; inbound capture on
  Kubernetes nodes and non-loopback traffic is not yet runtime-proven.
- Live HTTP/2 capture with HPACK decoding on the local OrbStack Docker VM
  (2026-07-04): with `protocol_source.http2_ports = [8080]`, five nghttp
  h2c requests against a local nghttpd produced five observations with
  Huffman-decoded method/path (`GET /index.html`), stream-id-matched
  responses carrying `http.response.status_code=200`, and real durations,
  through the writev capture path. Local smoke proof only; TLS, gRPC live
  traffic, CONTINUATION reassembly, and HEADERS frames larger than the
  capture window remain unproven or out of scope (this run predates the
  configurable multi-segment window and ran under the then-fixed 256-byte
  bound).
- Live `source.aya_protocol` request/response matching on the same local
  OrbStack Docker setup (2026-07-04): with read-direction capture and the
  in-flight matcher enabled, all 10 captured Redis observations carried
  `end_unix_nanos`, real `duration_nanos` (4-28 us round trips), and
  `db.response.status_code` values (`OK`/`PONG`) matched from live response
  bytes. Local smoke proof only; latency/error matching for Kafka,
  PostgreSQL, MySQL, and MongoDB is implemented and unit-tested but not yet
  runtime-proven.
- Live TLS plaintext capture via OpenSSL uprobes on the local OrbStack Docker
  VM (2026-07-05): with `source.aya_tls` and `tls_source.redis_ports = [6390]`,
  a privileged agent attached five OpenSSL uprobes (`SSL_set_fd`, `SSL_read`,
  `SSL_write`) to `libssl.so.3` discovered from process maps, and a `redis-cli
  --tls` (RESP3) client against a TLS-only `redis-server` (`--tls-port 6390`,
  self-signed cert) produced eight `protocol_request_observation` records
  (SET x2, GET, PING, HELLO x4) with matched responses (`OK`/`PONG`), real
  durations, and `redis-cli` client attribution. A 600-byte value was
  reassembled across capture segments, and neither the key bytes nor the
  600-byte value appeared in any exported signal. All ten `source.aya_tls`
  uprobe programs verifier-loaded on the OrbStack kernel. This is
  library-boundary interception, not on-the-wire decryption, and local smoke
  proof only; GnuTLS probes are implemented and verifier-loaded but were not
  exercised by a GnuTLS workload, and HTTP/1-over-TLS framing is not yet
  implemented.
- Live HTTP/1-over-TLS capture on the local OrbStack Docker VM (2026-07-05):
  with `source.aya_tls` and `tls_source.http1_ports = [443]`, the agent
  attached nine OpenSSL uprobes (classic `SSL_read`/`SSL_write` plus the
  OpenSSL 3 `SSL_read_ex`/`SSL_write_ex` variants) to `libssl.so.3`, and a
  Python HTTPS client (whose `ssl` module uses OpenSSL) issued three GET
  requests to an nginx TLS server. Each produced one HTTP
  `protocol_request_observation` with `http.request.method=GET`, the request
  `url.path`, and a matched `http.response.status_code=200`, with real
  durations and `python3` client attribution; the `hello-from-nginx` response
  body did not appear in any exported signal. All fourteen `source.aya_tls`
  uprobe programs verifier-loaded, and the classic `SSL_read`/`SSL_write`
  Redis-over-TLS path still captured SET/GET/PING on the same binary. This is
  library-boundary interception, not on-the-wire decryption, and local smoke
  proof only.
- Live GnuTLS-over-TLS capture and dynamic library rescan on the local
  OrbStack Docker VM (2026-07-05): with `source.aya_tls` and
  `tls_source.http1_ports = [443]`, a `gnutls-cli` client (linked against
  `libgnutls`, using `gnutls_transport_set_int2` for its socket fd and
  `gnutls_record_send`/`gnutls_record_recv` for I/O) issued three HTTPS GET
  requests to an nginx TLS server; each produced one HTTP observation with
  `http.request.method=GET`, `url.path`, and matched
  `http.response.status_code=200`, attributed to the `gnutls-cli` process
  (six GnuTLS uprobes attached). Separately, an agent started with no TLS
  library mapped attached nine OpenSSL uprobes on its next 15s rescan after
  nginx started, then captured a subsequently launched Python HTTPS client's
  requests, confirming libraries mapped after startup are not missed. Local
  smoke proof only, library-boundary interception, not decryption.
- Live multi-segment protocol payload capture on the local OrbStack Docker
  VM (2026-07-05): with the default 1 KiB `capture_bytes_per_syscall`
  window, a privileged run against a throwaway Redis container captured a
  600-byte `SET` as three spliced 256-byte segments and emitted one
  complete high-confidence observation (`db.operation=SET`,
  `db.redis.argument.count=2`, matched `OK` response), while a 3000-byte
  `SET` exceeding the window degraded to an accounted truncated-frame
  observation (low confidence, still response-matched) instead of being
  silently mis-parsed; `GET` and `PING` on the same connection stayed
  high-confidence, and no payload value bytes appeared in any exported
  signal. All eBPF programs verifier-loaded on the OrbStack kernel after
  the segment-loop change. Local smoke proof only.
- Live configurable-depth CPU profile capture on the local OrbStack Docker
  VM (2026-07-05): with `max_frames_per_sample = 100`, a privileged run
  sampling an 80-deep recursive C spinner (built `-O0
  -fno-omit-frame-pointer`) captured 1176 samples all exceeding the old
  32-frame cap, the deepest at 85 fully symbolized frames (`spin_leaf`,
  80x `deep_recurse`, `__libc_start_main`, `_start`); rerun with
  `max_frames_per_sample = 16`, every spinner sample was capped at exactly
  16 frames, carried the `profiling.stack.capture_truncated` attribute,
  and a `stack_depth_capped` warning reported the truncated count and
  frame limit. The same run proved in-kernel pid-namespace translation:
  sampled pids matched the procfs pids of the agent's namespace (they had
  not, pre-fix, under OrbStack's nested pid namespaces), and samples from
  the VM's parent namespace were refused symbolization with
  `profiling.stack.pid_ns=unverified` plus a `pid_unverified_samples`
  warning instead of being mis-attributed to same-numbered processes. The
  perf-event program verifier-loaded on the OrbStack kernel after both
  changes. Local smoke proof only.

- Live in-kernel DWARF/CFI stack unwinding on the local OrbStack Docker VM
  (2026-07-06): with `.eh_frame` unwind tables built and registered for
  running processes, a `-fomit-frame-pointer` deep-recursion binary whose
  frame-pointer stacks capped at 3 frames produced 2925 of 2925
  DWARF-unwound samples with the exact expected 64-frame chain
  (`spin_leaf`, 61x `deep_recurse`, `main`, libc start), each carrying
  `profiling.stack.unwind=dwarf` and an explicit stop reason; startup
  samples before the first table refresh fell back to frame-pointer
  unwinding with accounting. The chunked tail-called unwinder and both
  CPython programs verifier-loaded on the OrbStack kernel. Local smoke
  proof only.
- Live CPython 3.12 interpreter unwinding on the local OrbStack Docker VM
  (2026-07-06): against `python:3.12-bookworm` running a five-level nested
  busy loop, 3916 of 3941 interpreter samples carried the complete logical
  stack (`leaf_busy`, `level_c`, `level_b`, `level_a`, `main`,
  `<module>`) resolved to real function names, the real script path, and
  correct first-line numbers via bounded `/proc/<pid>/mem` reads, with
  `profiling.stack.py_stop=complete` and native frames following; the
  remainder predate the first registration pass. No interpreter memory
  beyond code-object name/filename/line fields was read or exported.
  Local smoke proof only.

- Local OrbStack Kubernetes DaemonSet smoke (2026-07-06): a privileged
  hostPID DaemonSet built from the current binary rolled out on the local
  OrbStack k3s cluster in a throwaway namespace alongside a resource-limited
  CPython 3.12 busy pod. All CPU-profile eBPF programs (sampler, chunked
  DWARF unwinder, CPython find/walk) verifier-loaded in-cluster and ~5,000
  profile samples exported. Pod processes were captured with honest
  accounting - `profiling.stack.unwind=fp` plus
  `profiling.stack.pid_ns=unverified` - because OrbStack nests the
  Kubernetes node's pid namespace under a hidden VM namespace the agent
  cannot resolve; same-namespace processes DWARF-unwound. Namespace,
  workload, DaemonSet, and image were removed afterward. This is a rollout
  and accounting smoke only; symbolized pod stacks require a standard
  (non-nested) node namespace layout and remain unproven on Kubernetes.

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
  API keys, bounded ApiVersions request-body validation, bounded flexible AddRaftVoter, UpdateRaftVoter, InitializeShareGroupState, ReadShareGroupState, WriteShareGroupState, DeleteShareGroupState, ReadShareGroupStateSummary, DeleteShareGroupOffsets, DescribeShareGroupOffsets, RemoveRaftVoter, AlterPartitionReassignments, AlterUserScramCredentials, ConsumerGroupDescribe, ControllerRegistration, ConsumerGroupHeartbeat, ShareGroupHeartbeat, DescribeCluster, DescribeProducers, BrokerHeartbeat, DescribeQuorum, DescribeTopicPartitions, DescribeTransactions, DescribeUserScramCredentials, GetTelemetrySubscriptions, ListConfigResources, ListPartitionReassignments, ListTransactions, AllocateProducerIds, PushTelemetry, UnregisterBroker, UpdateFeatures, and WriteTxnMarkers, flexible/non-flexible
  AlterClientQuotas, DescribeClientQuotas, and IncrementalAlterConfigs, and non-flexible Produce, Fetch, AddOffsetsToTxn, AddPartitionsToTxn, AlterConfigs, AlterReplicaLogDirs, CreateDelegationToken, DescribeDelegationToken, DescribeLogDirs, ElectLeaders, ExpireDelegationToken, RenewDelegationToken, CreateAcls, CreatePartitions, CreateTopics, DeleteAcls, DeleteRecords, DeleteTopics, DeleteGroups, DescribeAcls, DescribeConfigs, DescribeGroups, EndTxn,
  FindCoordinator, Heartbeat, InitProducerId, JoinGroup, LeaveGroup, ListGroups,
  ListOffsets, Metadata, OffsetCommit, OffsetDelete, OffsetForLeaderEpoch, OffsetFetch, TxnOffsetCommit,
  SaslAuthenticate, SaslHandshake, and SyncGroup request-body
  validation, and ApiVersions, Produce, flexible AddRaftVoter, UpdateRaftVoter, InitializeShareGroupState, ReadShareGroupState, WriteShareGroupState, DeleteShareGroupState, ReadShareGroupStateSummary, DeleteShareGroupOffsets, DescribeShareGroupOffsets, RemoveRaftVoter, AlterPartitionReassignments, AlterUserScramCredentials, ConsumerGroupDescribe, ControllerRegistration, ConsumerGroupHeartbeat, ShareGroupHeartbeat, DescribeCluster, DescribeProducers, BrokerHeartbeat, DescribeQuorum, DescribeTopicPartitions, DescribeTransactions, DescribeUserScramCredentials, GetTelemetrySubscriptions, ListConfigResources, ListPartitionReassignments, ListTransactions, AllocateProducerIds, PushTelemetry, UnregisterBroker, UpdateFeatures, and WriteTxnMarkers, flexible/non-flexible AlterClientQuotas, DescribeClientQuotas, and IncrementalAlterConfigs, and non-flexible AddOffsetsToTxn,
  AddPartitionsToTxn, AlterConfigs, AlterReplicaLogDirs, CreateDelegationToken, DescribeDelegationToken, DescribeLogDirs, ElectLeaders, ExpireDelegationToken, RenewDelegationToken, CreateAcls, CreatePartitions, CreateTopics, DeleteAcls, DeleteRecords, DeleteTopics, DeleteGroups, DescribeAcls, DescribeConfigs, DescribeGroups, EndTxn, Fetch, FindCoordinator, Heartbeat,
  InitProducerId, JoinGroup, LeaveGroup, ListGroups, ListOffsets, Metadata, OffsetCommit,
  WriteTxnMarkers, TxnOffsetCommit, SaslAuthenticate, SaslHandshake, OffsetDelete, OffsetForLeaderEpoch, OffsetFetch, and SyncGroup
  response-error parsing is locally tested without exporting client IDs,
  coordinator keys, consumer group/member identifiers, assignment payloads,
  offset metadata, protocol metadata, software names, topics, record payloads,
  broker hosts, cluster IDs, or response body values,
  but runtime capture, request/response matching, broad response coverage,
  flexible-version body semantics beyond ApiVersions, and live Kafka proof are
  not implemented or proven.
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
  validation. Runtime capture and request/response matching have local
  OrbStack proof for plain TCP and OpenSSL Redis, including pipelining and
  multi-segment payloads, but broad production/Kubernetes coverage and longer
  live soaks are not proven.
- **DNS capture:** selected UDP paths work, but symmetric all-node capture and
  lossless DNS coverage are not proven.
- **CPU profiling:** selected samples and sessions, local pprof rendering, and
  direct OTLP Profiles ingest/query against a disposable Pyroscope `1.20.3`
  container are proven. Deterministic eBPF capture and backend queryability for
  every workload/runtime shape, production storage/retention, and homelab
  direct-Pyroscope delivery are not proven.
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
