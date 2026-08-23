# Remaining capability gaps: feasibility and delivery boundaries

Status: research and implementation boundary

Date: 2026-08-23

Repository baseline: `07b3269` (`v0.5.0-rc.3`)

Local implementation series: `ebfcd18`, `1982ed3`, `89c75f1`, `9377f1e`,
and `93a6919` (not pushed)

## Scope and method

This note evaluates the remaining managed-runtime profiling, TLS/HTTPS,
context propagation, protocol, OpenTelemetry coexistence, L4 accounting, and
native-unwinding gaps. It uses only first-party project documentation, source,
and specifications. OpenTelemetry semantic-convention claims are pinned to
release `v1.44.0` where a release link is available.

E-Navigator remains standalone. Upstream profilers and auto-instrumentation
projects are evidence and design precedents, not dependencies or compatibility
contracts to copy.

## Decision matrix

| Gap | Verdict | Honest deliverable | Irreducible boundary |
| --- | --- | --- | --- |
| Managed-runtime profiling | **GO, one runtime adapter at a time** | Versioned descriptor, BPF unwinder, userspace symbolizer, replay corpus, and live runtime/build/architecture matrix | Perf maps add names but do not unwind opaque JIT/interpreter frames |
| Broad TLS/HTTPS | **GO, one plaintext adapter at a time** | Named library/runtime/build matrices with transactional attach and fail-closed discovery | No universal plaintext ABI; static linking, providers, inlining, and stripped binaries move or remove probe seams |
| Production propagation | **GO as separate wire and runtime programs** | Complete bounded HTTP framing first; add logical task propagation and HTTPS injection through versioned runtime/library adapters | Kernel thread/socket identity is not logical async-task identity |
| Dynamic protocol discovery | **GO for bounded cleartext candidates** | Userspace classification from bounded bidirectional prefixes, cached per connection with confidence and ambiguity | TLS, late attachment, truncation, and overlapping prefixes cannot always be classified |
| Protocol-span semantics | **GO protocol by protocol** | Protocol-defined matching, outcome parsing, status, and semconv attributes | Wire bytes cannot reveal a framework route template |
| OTel coexistence | **NO-GO as universal automatic detection** | Explicit ownership plus conservative runtime-specific positive evidence | Programmatic/custom SDK configuration makes static-marker completeness impossible |
| Universal L4 accounting | **NO-GO under one byte semantic** | Define supported TCP application bytes; add message-batch and `io_uring` paths without double counting; specify UDP/packet metrics separately | Syscall, application, TLS-plaintext, and packet bytes are different measurements |
| Universal native unwinding | **NO-GO as a universal claim; GO for broader CFI** | Normalize more CFI expressions in userspace and preserve explicit bounded fallbacks | Valid DWARF expressions and finite BPF/map/cache budgets prevent an unbounded guarantee |

## 2026-08-23 execution outcome

The request contains several compatibility programs, not single features. This
execution implements only slices whose semantics and local evidence can be
bounded honestly. A row marked deferred is an explicit quality decision, not
an assertion that the gap is solved elsewhere.

| Requested gap | Outcome in this series | Evidence and remaining boundary |
| --- | --- | --- |
| Broad managed-runtime profiling | **Deferred; per-runtime GO, universal claim NO-GO.** | Existing exact CPython 3.11/3.12 walking and conditional perf-map names do not establish Node/V8, HotSpot, .NET, Ruby, PHP, Perl, or other Python support. Each runtime/version/build/architecture needs a descriptor, dedicated BPF walker, userspace symbolizer, negative detection, coredump replay, verifier proof, and live backend query. |
| Broad TLS/HTTPS tracing | **Deferred; per-adapter GO, universal claim NO-GO.** | Existing OpenSSL 1.1.1/3, GnuTLS ABI 30, and version-gated unstripped Linux/amd64 Go adapters remain the only claimed plaintext seams. Bundled Node/JVM TLS, BoringSSL, rustls, custom transports, stripped Go, and non-amd64 Go require independent identity/ABI/return-site/socket-association matrices. |
| HTTPS context propagation | **Deferred; cannot be implemented at ciphertext.** | TLS 1.3 authenticates encrypted records, so injection must happen at a validated library/runtime plaintext header seam before encryption. No such universal seam exists; each future adapter needs transactional attachment, compare-before-mutate behavior, rollback, and live peer-tree proof. |
| Complete HTTP/1 context propagation | **Deferred beyond the existing bounded subset.** | The current disabled-by-default path retains its documented small-iovec, bounded `Content-Length`, configured-port, post-attachment envelope. Segmented headers, pipelining, chunked bodies, larger vectors, pre-existing sockets, and logical async continuation require separate stream and runtime state machines plus verifier/live-wire matrices. |
| Complete MySQL correlation | **Material bounded implementation: `ebfcd18`, hardened by `14eca57`.** | Sequence-checked command state now covers immediate responses, text/binary rows, structurally validated protocol 4.1 OK and column metadata, short EOF and modern OK terminators, multi-results, parameter-only and column-bearing prepares, cursor execution/fetch terminals, no-response commands, malformed/truncated packets, and sequence gaps. `LOCAL INFILE`, compression, capability-negotiated optional resultset metadata/EOF, 16 MiB logical-packet continuation, handshake/authentication, live server/version proof, and production soak remain open. |
| Complete database and messaging response semantics | **Material protocol slices, not a blanket completion claim.** | MySQL uses the lifecycle above; PostgreSQL simple queries (`9377f1e`) and typed extended pipelines (`93a6919`) use protocol terminals and skip-to-Sync recovery; Redis (`1982ed3`, `14eca57`) keeps ordinary RESP3 push/attribute frames out of FIFO matching and correlates the bounded acknowledgement count for explicit RESP2/RESP3 subscription commands. Kafka broad per-API bodies, MongoDB broad outcomes, arbitrary RESP2 Pub/Sub delivery interleaving, streamed RESP3 values, NATS request/reply and JetStream semantics, PostgreSQL startup/COPY-in control state, live matrices, and retry semantics remain open. |
| Database collection naming beyond MongoDB | **Deliberately not implemented from query text or Redis keys.** | OpenTelemetry says `db.collection.name` should not be extracted from `db.query.text`; a Redis key is not a collection. E-Navigator keeps MongoDB's explicit command collection field and omits guessed SQL table/key names. A future driver/runtime adapter may emit a table only when it receives an already-parsed, single-collection value without raw query export. |
| HTTP route-template discovery | **Not implemented from wire paths.** | A concrete URL cannot reliably reveal whether `/users/42` maps to `/users/:id`, `/users/{userId}`, or a literal route. E-Navigator therefore omits `http.route` unless a future framework adapter supplies the framework-owned template; heuristic path generalization would violate cardinality and semantic accuracy. |
| Automatic detection of all application-owned OTel spans | **Universal claim NO-GO.** | Manual/custom SDKs can configure exporters and samplers programmatically with no stable static marker. Existing conservative zero-code markers plus explicit exact Kubernetes ownership labels remain the contract; unknown evidence fails open and suppresses no request spans. Exporter-activity probes can add runtime-specific positive evidence but cannot prove all SDK ownership. |
| General `io_uring` network accounting | **Deferred.** | General send/receive paths can run outside the submitting task and use registered, provided, bundled, multishot, vectored, or zero-copy buffers. One canonical socket-generation seam plus an origin/deduplication contract is required before adding it; combining syscall and deeper hooks without that contract can double count. |
| Complete message-batch accounting | **Native LP64 ceiling implemented: `89c75f1`.** | A verifier-bounded `bpf_loop` reads every kernel-written `mmsghdr.msg_len` through Linux's 1,024-entry `UIO_MAXIOV` limit, fails closed on invalid counts or unreadable memory, and passed exact 32- and 1,024-entry arm64 OrbStack smokes. Compatibility ABIs remain unsupported and explicitly counted. |
| UDP flow observability | **Deferred as a separate signal domain.** | Current peer-flow state is TCP connection-generation state. UDP needs datagram/socket identity, role and peer rules for connected and unconnected sockets, batch accounting, expiry/cardinality policy, and distinct metrics; adding UDP bytes to TCP flow series would change their meaning. |
| Packet-level byte accounting | **Deferred as a separate packet metric.** | Application syscall bytes intentionally exclude headers, retransmissions, segmentation, and encrypted packet sizes. Packet truth requires a TC/cgroup-SKB or equivalent host-network seam, direction/namespace attribution, offload-aware tests, and deduplication from syscall metrics; it must not redefine `network.flow.bytes`. |
| Pre-attachment flow history | **Historical reconstruction is impossible.** | Existing listener discovery and later payload observation can establish state going forward, but no observer can recover bytes, headers, latency, retransmissions, or context that occurred before attachment. Future existing-socket discovery may emit explicitly partial observations from the attach timestamp; it cannot claim flow-from-beginning history. |
| Universal native stack unwinding | **Universal claim NO-GO; broader bounded CFI remains GO.** | Existing direct register-plus-offset CFA folding is a bounded subset. Dynamic/dereferencing expressions, multi-operation CFA, broader register recovery, signal trampolines, and row/map budget exhaustion require typed fallback and differential compiler corpora; finite verifier, tail-call, stack, and map budgets prevent universal coverage. |

## Primary findings

### Managed runtimes require a profiling subsystem

Grafana Alloy's
[`pyroscope.ebpf`](https://grafana.com/docs/alloy/latest/reference/components/pyroscope/pyroscope.ebpf/)
embeds Grafana's fork of the OpenTelemetry eBPF profiler and documents native
code plus HotSpot, Python, Ruby, PHP, Node/V8, and Perl. The upstream
[OpenTelemetry profiler](https://github.com/open-telemetry/opentelemetry-ebpf-profiler)
also lists Erlang and .NET. [Parca Agent](https://github.com/parca-dev/parca-agent)
independently lists broad language support.

That breadth is not perf-map lookup. The OpenTelemetry profiler's
[internals](https://github.com/open-telemetry/opentelemetry-ebpf-profiler/blob/main/doc/internals.md)
describe this architecture:

```text
process identity and mappings
  -> runtime/version/layout detector
  -> immutable validated descriptor
  -> bounded BPF metadata
  -> runtime-specific unwinder selected by tail call
  -> userspace runtime symbolizer
  -> profile observation
```

Each E-Navigator adapter must fail closed on an unknown version, architecture,
pointer mode, symbol, layout, or process identity. HotSpot, Node/V8, .NET,
Ruby, PHP, Perl, and BEAM are separate support matrices, not one feature flag.
The upstream testing strategy also proves ordinary unit tests are insufficient:
it uses userspace tests, coredump replay of BPF unwinders, and privileged
verifier/integration tests across kernels.

The upstream repository licenses userspace under Apache-2.0 and its BPF source
under GPL-2.0. It is architectural evidence; reuse requires an explicit
licensing decision.

### TLS plaintext has library- and runtime-specific seams

OpenSSL exposes documented plaintext APIs such as `SSL_read_ex` and
`SSL_write_ex` in its [official API index](https://docs.openssl.org/3.5/man3/),
which supports named ABI adapters. This does not generalize:

- Node dependencies, including OpenSSL, are
  [bundled by default](https://github.com/nodejs/node/blob/main/doc/contributing/maintaining/maintaining-dependencies.md),
  though distributions may externalize them.
- BoringSSL provides
  [no API or ABI stability guarantee](https://boringssl.googlesource.com/boringssl/)
  and expects applications to ship their own copy.
- rustls separates encrypted `read_tls`/`write_tls` from plaintext
  [`Reader`/`Writer`](https://docs.rs/rustls/latest/rustls/enum.Connection.html),
  often through monomorphized or async-wrapper code rather than a stable C ABI.
- Java's provider-based `SSLSocket` and transport-independent
  [`SSLEngine`](https://docs.oracle.com/en/java/javase/17/security/java-secure-socket-extension-jsse-reference-guide.html)
  do not pass through a universal native TLS library.
- Go source functions use unstable, version-specific
  [`ABIInternal`](https://go.dev/src/cmd/compile/abi-internal).

Every TLS adapter therefore needs exact binary/runtime identity, plaintext and
socket-association seams, architecture and ABI validation, complete return-site
resolution where applicable, transactional attachment, and bounded coverage
diagnostics. HTTPS W3C injection must happen at a validated plaintext header
construction seam before encryption. Mutating authenticated TLS records would
fail under [TLS 1.3](https://www.rfc-editor.org/rfc/rfc8446.html).

### Wire propagation and async continuation are different problems

[W3C Trace Context](https://www.w3.org/TR/trace-context/) defines header
validation and forwarding. The OpenTelemetry
[Context](https://opentelemetry.io/docs/specs/otel/context/) and
[Propagators](https://opentelemetry.io/docs/specs/otel/context/api-propagators/)
specifications separately cover execution-scoped state and carrier injection,
normally through library-specific interceptors.

The wire program must independently support bounded segmented headers,
multiple header fields, pipelining, fixed/chunked bodies, larger vectored I/O,
pre-attachment loss accounting, exact compare-before-mutate, and fail-closed
rollback. Linux verifier/state limits documented in the
[BPF design Q&A](https://docs.kernel.org/bpf/bpf_design_QA.html) still require
bounded logic even when using
[SOCKMAP/SOCKHASH](https://docs.kernel.org/bpf/map_sockmap.html).

Async continuation needs runtime adapters. OpenTelemetry eBPF Instrumentation
documents separate handlers for Go goroutines/channels, Node Async Hooks, Java
thread pools/virtual threads, Ruby Puma, and Python uvloop in its
[feature matrix](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/main/devdocs/features.md).
E-Navigator should similarly model create, transfer, resume, suspend, and
destroy events with PID/task-reuse fencing and bounded expiry. An unknown
handoff must break correlation visibly rather than select a wrong parent.

### Dynamic discovery is a bounded classifier, not universal recognition

The 64-port, one-protocol-per-port rule is an E-Navigator design constraint,
not a Linux/eBPF limit. A safe replacement is:

1. capture a small bounded prefix for candidate TCP connections within an
   explicitly selected workload scope;
2. reassemble bounded prefixes per connection generation and direction;
3. run statically registered Rust detectors returning `need_more`, `match`,
   `ambiguous`, or `reject`;
4. require protocol-specific confidence, preferably bidirectional for binary
   protocols;
5. cache the promoted protocol in a bounded kernel map; and
6. expire undecided state with truncation, ambiguity, and budget counters.

Explicit port configuration must take precedence. Full protocol parsers belong
in Rust userspace because verifier branch/state limits make a large in-kernel
registry fragile. OBI's broad
[protocol support](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/main/SUPPORT_MATRIX.md)
still coexists with process/path/port selection in its
[official configuration](https://opentelemetry.io/docs/zero-code/obi/configure/options/);
it does not establish infallible arbitrary-port discovery.

### Protocol semantics require system-specific correlation

OpenTelemetry `v1.44.0` imposes these constraints:

- HTTP instrumentation must not substitute a raw path for `http.route`; use
  framework routing data or omit it. See
  [HTTP spans](https://github.com/open-telemetry/semantic-conventions/blob/v1.44.0/docs/http/http-spans.md).
- `db.collection.name` is emitted only when a single collection is readily
  available and must not generally be guessed from arbitrary query text. See
  [database spans](https://opentelemetry.io/docs/specs/semconv/db/database-spans/).
- `db.response.status_code` uses the protocol/system code; `error.type` is
  present if and only if the operation failed. See
  [SQL](https://opentelemetry.io/docs/specs/semconv/db/sql/),
  [messaging spans](https://github.com/open-telemetry/semantic-conventions/blob/v1.44.0/docs/messaging/messaging-spans.md),
  and [recording errors](https://opentelemetry.io/docs/specs/semconv/general/recording-errors/).

| Protocol | Correlation/outcome source | Required boundary |
| --- | --- | --- |
| MongoDB | [`responseTo`](https://www.mongodb.com/docs/manual/reference/mongodb-wire-protocol/) plus command/error fields | Match request id; emit collection only when supplied unambiguously; all MongoDB error codes follow its [system convention](https://opentelemetry.io/docs/specs/semconv/db/mongodb/) |
| Kafka | Echoed correlation id in the [protocol](https://kafka.apache.org/22/design/protocol/) | Match out of order and dispatch response layout/error fields by API key and version |
| Redis | Ordered replies under [pipelining](https://redis.io/docs/latest/develop/using-commands/pipelining/) | FIFO per connection generation, with RESP nesting, pushes, transactions, and reconnects handled explicitly |
| PostgreSQL | Multi-message [protocol flow](https://www.postgresql.org/docs/current/protocol-flow.html), SQLSTATE, and terminal readiness | Maintain bounded state through completion/error; do not finish on the first backend message |
| MySQL | Sequence ids reset per command and results span packets/result sets in the [packet protocol](https://dev.mysql.com/doc/dev/mysql-server/8.0.46/page_protocol_basic_packets.html) | A command lifecycle state machine is required; pairing the next packet is insufficient |
| NATS | Reply subjects/subscriptions and asynchronous `-ERR` in the [client protocol](https://docs.nats.io/reference/protocols/client) | Separate publish, request/reply, delivery, JetStream acknowledgement, and connection errors; socket FIFO is not a universal correlation rule |

At the repository baseline, PostgreSQL, MySQL, MongoDB, and Redis already have
`db.response.status_code`/`error.type` paths, Kafka and NATS have error paths,
and MySQL response parsing exists. The remaining work is a request-kind and
terminal-outcome audit, not one blanket response patch.

Implementation update (2026-08-23): PostgreSQL simple Query correlation retains
intermediate responses and the first SQLSTATE error through terminal
`ReadyForQuery`, preserving the terminal transaction state. A separate typed
state machine now matches Parse, Bind, both Describe variants, Close, Execute,
Password, Sync, and legacy FunctionCall to their protocol-defined terminal
messages. Extended-query errors mark dependent operations skipped until the
next captured Sync without fabricating response latency, while commands after
that Sync remain eligible for matching. COPY data/control and no-response
messages do not displace the initiating query. Startup correlation, the
COPY-in rule that ignores already-sent Sync/Flush messages, truncated-prefix
semantics, and live extended/COPY proof remain open and are not claimed.

The same audit hardened MySQL terminal recognition and Redis push handling.
MySQL now validates complete supported prepare headers, protocol 4.1 OK packets,
and ColumnDefinition41 metadata before advancing; parameter-only prepares and
cursor execution metadata terminals have dedicated completion tests. Redis
ordinary pushes and attributes stay out of FIFO matching, while explicit
subscription commands retain exactly their request-bounded acknowledgement
count across RESP2 arrays or RESP3 pushes. A zero-argument unsubscribe has no
request-bounded count, so it is deliberately emitted without correlated
response latency. Arbitrary RESP2 Pub/Sub delivery interleaving and live
subscription matrices remain open.

### Universal OTel coexistence detection is impossible from static markers

OpenTelemetry requires a
[programmatic SDK configuration interface](https://opentelemetry.io/docs/specs/otel/configuration/),
while environment-variable configuration is optional. Variables such as
`OTEL_SDK_DISABLED`, `OTEL_TRACES_EXPORTER=none`, and `always_off` are useful
negative evidence, but absence or presence of generic configuration cannot
prove active span export. See the
[environment-variable specification](https://opentelemetry.io/docs/specs/otel/configuration/sdk-environment-variables/).

The honest product is explicit per-workload ownership plus conservative,
runtime-specific positive detectors. Unknown/manual/custom configurations
remain `unknown`; only request spans are suppressible; detector source and
decision are observable without exporting process secrets. Default enablement
requires false-suppression testing across manual SDKs, agents, framework
starters, disabled SDKs, samplers, and exporter failures.

### L4 byte domains and syscall paths cannot be conflated

`sendmmsg` returns a message count and writes each byte result to
`mmsghdr.msg_len`; its [manual](https://man7.org/linux/man-pages/man2/sendmmsg.2.html)
also permits vectors up to `UIO_MAXIOV`. Exact accounting needs bounded
exit-time traversal and explicit partial/overflow telemetry.

`io_uring` bypasses ordinary send/receive syscall tracepoints and supports
registered buffers, multishot receive, bundles, vectorized and zero-copy sends
in its [UAPI](https://github.com/torvalds/linux/blob/master/include/uapi/linux/io_uring.h).
The current [network path](https://github.com/torvalds/linux/blob/master/io_uring/net.c)
reaches socket-layer calls but may execute outside the submitting task context.
A deeper canonical hook can improve coverage while losing fd/user-buffer/task
identity; using both layers risks double counting.

Add `sendmmsg`/`recvmmsg` with bounded per-message results first. Add
`io_uring` through one canonical accounting seam keyed by socket identity and
connection generation, with an observation origin that prevents duplicate
syscall accounting. Define UDP/datagram and packet-byte metrics separately.
OBI itself documents a different host-perspective
[packet-aware byte semantic](https://opentelemetry.io/docs/zero-code/obi/network/)
that includes network-stack overhead.

Implementation update (2026-08-23): native LP64 `sendmmsg`/`recvmmsg`
traversal now covers Linux's full 1,024-entry `UIO_MAXIOV` ceiling through a
bounded `bpf_loop`, with exact 32-entry and maximum-vector local arm64 smokes.
Compatibility ABIs remain unsupported and explicitly counted.

### Native unwinding remains bounded even with full names

Demangling cannot recover a missing frame. DWARF 5 call-frame information can
contain full expressions in `DW_CFA_def_cfa_expression`, `DW_CFA_expression`,
and `DW_CFA_val_expression`; see
[DWARF 5 section 6.4.2](https://dwarfstd.org/doc/DWARF5.pdf).

Broaden coverage by inventorying unsupported rules, adding a deterministic
bounded userspace expression evaluator, constant-folding expressions into a
compact BPF rule format, and retaining reason-specific fallback/truncation.
Compiler, optimization, architecture, signal-trampoline, shared-library,
stripped-binary, and mixed Go/native corpora must be differential-tested.
Finite stack, tail-call, map, row-pool, and cache budgets remain public limits.

## Staged implementation and risk matrix

| Stage | Work package | Required evidence before a claim | Residual risk |
| --- | --- | --- | --- |
| 1 | Re-audit and close concrete protocol operation/outcome gaps | Golden request/response fixtures, malformed/property/fuzz tests, matcher replay, OTLP assertions, live protocol fixtures | Unseen operations/server versions |
| 2 | `sendmmsg`/`recvmmsg` TCP application bytes | ABI and compat fixtures, partial/error/limit cases, mixed-hook no-double-count tests, privileged exact totals | Unusual kernel/compat paths |
| 3 | Cleartext protocol discovery, disabled by default | Cross-protocol negative corpus, ambiguity/late/truncation/budget tests, arbitrary-port live fixtures, overhead A/B | TLS and weak early signatures |
| 4 | HTTP/1 wire-framing completion | Model/property/differential tests, verifier matrix, segmented/pipelined/chunked live-wire tests, mutation failure injection | Kernel/proxy diversity and mutation blast radius |
| 5 | One demanded TLS and async-runtime family | Exact binary/runtime preflight, attach rollback, logical handoff replay, task reuse/expiry, amd64/arm64 live HTTPS | Release/build shapes outside matrix |
| 6 | One demanded managed-runtime profiler | Negative detection, coredump replay, mixed stacks, verifier/kernel CI, amd64/arm64 runtime/build matrix, backend query | Runtime/JIT modes outside matrix |
| 7 | `io_uring` TCP accounting and broader native CFI | Registered/provided/vector/bundle tests, no-double-count exact totals; DWARF differential corpus, fuzzing and map budgets | Kernel-version path changes and costly valid CFI |
| 8 | Additional runtimes/libraries/frameworks | Repeat the same independent matrix per adapter | Compatibility program never becomes universal |

Universal OTel coexistence, universal TLS, universal async propagation,
universal L4 accounting, and universal unwinding remain explicit non-claims.

## Cross-cutting release gate

Every slice requires bounded configuration/state; typed unsupported,
ambiguous, truncated, budget, attach, and verifier outcomes; deterministic
unit/property/golden tests; fuzzing for untrusted parsers and executable/DWARF
decoders; repository-pinned amd64 and arm64 BPF builds; privileged verifier,
attach, and live semantic proof for every claimed kernel/runtime/build row;
loss/fallback/expiry diagnostics; and overhead/cardinality budgets.

Docker on macOS can prove reproducible Linux builds, fixtures, userspace
integration, and selected OrbStack behavior. It cannot prove every target
kernel, distribution BTF, runtime build, architecture, or production overhead.
