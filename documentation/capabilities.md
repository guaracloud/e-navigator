# Capabilities

This document is the current public capability map for E-Navigator. It is
intentionally shorter than the internal proof trail and should be updated only
when implementation and evidence change together.

## Capability Inventory

E-Navigator is a node-local Rust/eBPF signal plane with a statically registered
`Source -> Processor -> Generator -> Sink` runtime. The CLI can run a real Aya
exec/network/resource bundle, an opt-in Aya CPU profiling source, or a synthetic
fixture source. Runtime config validates known module names, duplicate modules,
bounded queues, derived-signal fan-out, source limits, generator limits, and
sink settings before the runner starts.

### Source Capabilities

| Source | Default | Capability |
| --- | --- | --- |
| `source.aya_exec` | Enabled in `aya-exec` mode | Captures Linux exec success and process exit events from Aya/eBPF, with bounded optional argv capture, uid, pid, cgroup id, executable/command, exit timestamp, and best-effort container context from procfs. |
| `source.aya_network` | Enabled in `aya-exec` mode | Captures TCP IPv4/IPv6 connection open, close, and failure observations, including pid/uid/command, fd, local/remote address and port, duration, errno, and optional sent/received byte counters. |
| `source.aya_dns` | Opt-in | Captures bounded DNS query/response packets over UDP or TCP, parses A, AAAA, CNAME, and other query types, response code, server address/port, latency when present, and process/container context. |
| `source.aya_http` | Opt-in | Captures bounded cleartext outbound HTTP request bytes from write-style syscall paths and, when inbound capture is enabled, server-side HTTP request bytes from accept-tracked connections and read-style syscall paths. Parses request method/target metadata and W3C trace context when present and emits protocol request observations tagged with the client or server capture role. |
| `source.aya_protocol` | Opt-in | Captures bounded socket payload prefixes in both directions for outbound TCP connections to configured HTTP/2 (h2c/gRPC), Kafka, MongoDB, MySQL, NATS, PostgreSQL, and Redis ports, reassembles per-connection streams with explicit truncation/desync accounting, matches responses to a bounded in-flight request queue (stream-id keyed for HTTP/2) for real latency and response-status semantics, and emits protocol request observations through the existing bounded parsers, including HPACK-decoded HTTP/2 and gRPC request semantics. |
| `source.aya_cpu_profile` | Opt-in source mode and config | Samples CPU profiles through Aya perf events across online CPUs (up to 32 stack frames), resolves frame-pointer instruction pointers to module and module-relative offset from procfs maps with best-effort local ELF symbol names, accounts for kernel and backpressure sample drops and capped coverage, and emits profile sample observations with stack ids and symbolized frames. |
| `source.host_resource` | Enabled in `aya-exec` mode | Samples procfs, sysfs, and cgroup files for node CPU/load/memory/filesystem/disk I/O, process resource usage, cgroup CPU/memory/pids/file-descriptor observations, and bounded warning aggregation. |
| `source.synthetic_exec` | Enabled only in synthetic mode | Emits synthetic exec, network, DNS, HTTP/request, trace, profile, and resource fixtures for non-privileged local exercise. |

### Processing And Attribution Capabilities

| Processor | Default | Capability |
| --- | --- | --- |
| `processor.container_attribution` | Enabled | Enriches exec, process exit, network, DNS, request, trace, profile, dependency, flow, process-resource, and cgroup-resource signals with container and Kubernetes context when evidence exists. Attribution can use pid, cgroup id/path, container id, Kubernetes pod metadata, selected labels, node name, pod IP cache, and generic namespace/node/pod-label selectors. Missing context remains missing rather than guessed. |

### Generator Capabilities

| Generator | Default | Capability |
| --- | --- | --- |
| `generator.dependency_graph` | Enabled | Converts observed network open/close events into bounded dependency edges from workload/container context to remote address/port. |
| `generator.network_metrics` | Enabled | Derives bounded network counters, duration summaries, active connection gauges, native flow summaries, and `network.flow.bytes` from connection observations. |
| `generator.resource_metrics` | Enabled | Derives bounded resource gauges and counters for system CPU/load/memory/filesystem/disk, process CPU/memory/fd/thread counts, and cgroup/container CPU, memory, pids, and fd/socket counts. |
| `generator.dns_metrics` | Enabled | Derives bounded DNS query counters, response-code counters, lookup duration summaries, and DNS dependency edges with normalized domain labels. |
| `generator.trace_correlation` | Enabled | Derives service interaction spans from network close/failure events, service paths from dependency and DNS edges, and trace correlation warnings for missing attribution. |
| `generator.request_correlation` | Enabled | Derives request span observations from protocol request observations, promotes valid trace context to high-confidence request spans, and emits bounded warnings for missing or malformed trace context and missing attribution. |
| `generator.profiling` | Enabled | Aggregates profile samples into bounded profile session windows, tracks observed/dropped/distinct stack counts, and emits profiling warnings for missing attribution. |
| `generator.runtime_security` | Enabled | Emits first-scope runtime findings for shell execution in containers, network-tool execution, workload connections to configured/discovered Kubernetes API endpoints, and containerized external network connections. |

### Sink And Export Capabilities

| Sink | Default | Capability |
| --- | --- | --- |
| `sink.json_stdout` | Enabled | Emits every signal envelope as newline-delimited JSON schema version 1 and redacts secret-like argv values before stdout export. |
| `sink.prometheus_http` | Opt-in | Maintains bounded latest metric lines and exposes `/metrics`, `/healthz`, and `/readyz` over HTTP. It renders network, DNS, resource, profile session aggregate, and profiling warning-count signals as Prometheus text with metric/profile family toggles. |
| `sink.otlp_http` | Opt-in | Exports OTLP HTTP protobuf for metrics, traces with valid trace/span ids, and development-status profiles. Supports per-family endpoints, fallback endpoint, family toggles, queue capacity, batch size, timeout, retries, and optional insecure TLS verification. |

### Packaging, Operations, And Verification Capabilities

| Area | Capability |
| --- | --- |
| CLI | Supports `--source aya-exec`, `--source aya-cpu-profile`, `--source synthetic`, `--config`, `E_NAVIGATOR_CONFIG`, and `--validate-config`. |
| Kubernetes | Provides raw manifests and a Helm chart for a Linux DaemonSet with ConfigMap-driven TOML, ServiceAccount/RBAC, host path mounts for tracing/debugfs/proc/cgroup, node-name injection, optional Prometheus Service, and optional ServiceMonitor. |
| Container image | Builds the Rust CLI with the eBPF program artifact through `Containerfile` and runs `/usr/local/bin/e-navigator` as the entrypoint. |
| Supply chain and quality gate | `scripts/quality.sh` runs formatting, clippy, tests, workspace build, synthetic CLI, guard scripts, optional supply-chain checks, optional Docker smoke, optional Helm/Kubernetes schema checks, website link checks, and whitespace checks. |
| Fuzzing and fixtures | Raw decode/protocol boundaries have fixture and fuzz-facing helpers for exec, network, DNS, HTTP, protocol stream reassembly, protocol data events, Redis RESP command parsing, and CPU profile event decoding. |
| Benchmarks | Local Criterion hot-path benchmarks and homelab benchmark guard scripts exist, with benchmark claims bounded in `benchmark.md`. |

## Public Capability Map

| Area | Current state | Evidence level | Still missing |
| --- | --- | --- | --- |
| Static pipeline runtime | Implemented `Source -> Processor -> Generator -> Sink` runtime with registered modules and strict runtime config schema validation | Cargo tests, synthetic CLI, Docker smoke, and unknown-field config tests | runtime plugin loading is not planned |
| JSON signal envelopes | Implemented versioned newline-delimited JSON output | Cargo tests, golden signal coverage, Docker smoke | storage and UI |
| Process exec source | Implemented Aya exec/exit source | raw decode tests and guarded homelab observations | reduced-capability/non-root eBPF proof |
| TCP network source | Implemented TCP-oriented network observations | raw decode tests and guarded homelab observations | full TCP state, retransmit/reset accounting |
| Host resource source | Implemented procfs/sysfs/cgroup observation | parser tests, Docker fixtures, guarded homelab observations | independent host-accuracy baseline and warning-free/lossless enumeration proof |
| Kubernetes attribution | Implemented best-effort container/Kubernetes context enrichment with namespace, node-name, and pod-label include/exclude selectors | unit tests and guarded homelab attribution for selected signals | live selector proof and complete attribution for every host process or packet |
| DNS runtime capture | Partial opt-in source with configurable bounded packet and diagnostic preview limits plus generator | parser/raw decode/configured-limit tests, build-checked raw decode fuzz target, and selected homelab DNS proof | symmetric all-node capture and lossless DNS proof |
| HTTP/request foundation | Partial opt-in cleartext HTTP/1 client capture plus opt-in inbound server-side HTTP/1 request capture with configurable bounded parser limits plus bounded HTTP/1 response-status and decoded gRPC-over-HTTP/2 metadata/trailer-status parser foundations | fixture tests, HTTP response-status parser-limit tests, build-checked raw request-event, HTTP response-status, and gRPC headers fuzz targets, HTTP response-status parser tests, gRPC metadata/status parser tests, synthetic request/span coverage, and selected homelab `writev`/bounded-iovec proof | TLS, gRPC live-traffic proof, HTTP/2 CONTINUATION reassembly, inbound response/status matching, route templates, broad multi-iovec support |
| Kafka parser foundation | Parser-only request-header plus ApiVersions response-error extraction for bounded API-key/status semantics without client id, topic, payload, or response body value export | parser fixture, malformed-input, property, fuzz-target, synthetic request/error-span coverage, local ApiVersions error-status parser tests, and local error-status trace export tests | request/response matching, broad response coverage, flexible-version body semantics beyond ApiVersions response headers, truncated-frame prefix semantics, live Kafka capture proof |
| MongoDB parser foundation | Parser-only `OP_MSG`, command `OP_QUERY`, and OP_MSG response-error extraction for bounded operation/status semantics without raw BSON value, namespace, or raw error-message export | parser fixture, malformed-input, property, fuzz-target, synthetic request/error-span coverage, local error-status parser tests, and local error-status trace formatter tests | request/response matching, broad response coverage, truncated-frame prefix semantics, live MongoDB capture proof |
| MySQL parser foundation | Parser-only `COM_QUERY`, `COM_STMT_PREPARE`, and ERR response extraction for bounded operation/status semantics without raw SQL or raw error-message export | parser fixture, malformed-input, property, command/error fuzz-target, synthetic request/error-span coverage, and local error-status trace export path | request/response matching, broad response coverage, truncated-frame prefix semantics, live MySQL capture proof |
| NATS parser foundation | Parser-only text command plus OK/error response extraction for bounded operation/status semantics without raw subject, payload, or raw error-message export | parser fixture, malformed-input, property, fuzz-target, synthetic request/error-span coverage, and local error-status trace export tests | request/response matching, broad response coverage, truncated-frame prefix semantics, live NATS capture proof |
| PostgreSQL parser foundation | Parser-only simple Query, Parse, and ErrorResponse extraction for bounded operation/status semantics without raw SQL or raw error-message export | parser fixture, malformed-input, property, message/error fuzz-target, synthetic request/error-span coverage, and local error-status trace export path | request/response matching, broad response coverage, truncated-frame prefix semantics, live PostgreSQL capture proof |
| Redis parser foundation | Parser-only RESP command and error-response extraction for bounded command/status semantics without raw key/value or raw error-message export | parser fixture, malformed-input, property, command/response fuzz-target, synthetic request/error-span coverage, and local error-status trace export tests | request/response matching, broad response coverage, truncated-frame prefix semantics |
| Dependency graph | Implemented generator for observed network relationships | generator tests, deterministic service path key tests, and selected live output | persisted service map and complete topology |
| Protocol runtime capture | Implemented opt-in `source.aya_protocol` socket payload capture for outbound client connections to configured protocol ports, with bounded per-connection stream reassembly in both directions, pipelined-frame extraction, bounded FIFO request/response matching with per-protocol response policies (MySQL sequence-1 packets, PostgreSQL ErrorResponse/ReadyForQuery batch semantics, Kafka per-API-key response dispatch), and drop/desync/truncation/orphan accounting | stream decoder, matcher, and registry tests, raw-event and stream fuzz targets, Criterion reassembly and matched-pair benchmarks, and local OrbStack Docker live Redis runs (capture plus matched latency/status on all 10 observations) | server-side/inbound capture, truncated-frame prefix parsing for oversized frames, TLS, Kafka correlation-id verification, live proof for Kafka/PostgreSQL/MySQL/MongoDB/NATS, production overhead baselines |
| Resource metrics | Implemented bounded resource metric generation | parser/generator tests and selected live output | production overhead baselines |
| Runtime security findings | Implemented first generator scope | generator tests, golden coverage, selected live findings | broad policy engine and production alert routing |
| CPU profiling | Implemented Aya perf-event CPU sampling with 32-frame stacks, procfs-maps + bounded ELF symbolization (module, module-relative offset, best-effort local function names), source-layer drop and coverage-cap accounting, session aggregation, pprof rendering with real addresses/mappings, a `/debug/pprof/profile` serving endpoint, and OTLP profile export | source/generator/symbolizer/sink tests, raw-event and symbolize fuzz targets, and a local OrbStack live run resolving real modules and serving pprof | DWARF stack unwinding for interpreted/JIT frames, live Kubernetes-node symbolization, production overhead baselines |
| Native flow byte metrics | Implemented native `network.flow.bytes` signal with bounded workload/protocol/address-family aggregation, Prometheus rendering, precise duplicate flow suppression, per-flow summary endpoint detail, and flow-attribution warnings | generator/sink tests, cross-destination aggregation tests, duplicate-flow fingerprint tests, and golden schema coverage | positive live native metric export and warning proof after migration |
| Prometheus HTTP sink | Implemented opt-in HTTP surface with network, DNS, resource, profile session aggregate rendering, profiling warning-count rendering, and metric/profile family toggles | local `/metrics`, `/healthz`, `/readyz`, profile session aggregate rendering, profiling warning-count rendering, family-toggle, and config validation tests plus selected live scrape proof | longer soak, cardinality baseline, production-load correctness |
| OTLP HTTP sink | Partial metric, trace, development-status profile protobuf support, HTTP/gRPC/`error.type` request error status mapping, warning trace-record formatting, and per-family endpoint routing | fake-collector and formatter tests, including deterministic profile sample workload IDs, profile session dropped-sample export, and selected Kafka/MongoDB/MySQL/NATS/PostgreSQL/Redis error-type status paths, plus selected namespace-local Collector proof | broad production collector/backend compatibility and live status-mapping proof |
| Kubernetes packaging | Implemented Helm chart and raw manifests | Helm lint/template, schema checks, guarded homelab rollouts | production rollout proof across environments |
| Supply chain | Implemented release signing/SBOM workflow and local checks | release workflow, `cargo deny`, `cargo audit`, `cargo machete`, secret-pattern guard | container vulnerability policy gates |

## Reading The Evidence Level

- **Implemented:** code path exists and is registered/configurable.
- **Local proven:** tests, fixtures, synthetic CLI, Docker smoke, or render checks
  prove the userspace behavior.
- **Runtime proven:** a guarded Linux/Kubernetes run recorded the claimed output.
- **Partial:** a useful slice is proven, but nearby production behavior remains
  outside the claim.

Detailed evidence lives in [proof-report.md](proof-report.md). Non-claims live
in [boundaries.md](boundaries.md).
