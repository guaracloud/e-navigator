# Boundaries

This document is the public source of truth for what E-Navigator does not claim.
It should be read before deploying the project or citing its benchmark/proof
results.

E-Navigator is a pre-release runtime signal plane. It is designed to collect,
attribute, derive, and export bounded runtime signals. It is not yet a complete
observability product.

## In Scope

E-Navigator is designed to provide:

- node-local Linux and Kubernetes runtime observations;
- versioned signal envelopes;
- bounded attribution to host, process, container, and Kubernetes context;
- optional operator-controlled capture filtering that scopes which workloads
  are probed by namespace and label rules, enforced in-kernel per cgroup id;
- low-cardinality metrics, dependency edges, request spans, profiling windows,
  and runtime security findings;
- JSON stdout by default;
- opt-in Prometheus HTTP and OTLP HTTP export surfaces;
- explicit evidence boundaries for synthetic, local, Docker, render, and
  privileged runtime proof.

## Explicit Non-Claims

E-Navigator does not currently claim:

- production observability backend behavior;
- trace storage, profile storage, flamegraph UI, dashboards, or query UI;
- production profile-delivery behavior or homelab stored-profile query proof
  (the generic OTLP Profiles HTTP sink is locally ingest/query proven against
  Pyroscope `1.20.3`, and the 2026-07-22 final-stack homelab arm recorded 567
  profiles accepted by the standing Pyroscope endpoint with zero worker loss
  or rejection. That arm did not query storage or validate retention);
- complete production HTTP/gRPC/browser protocol coverage (bounded HTTP/1,
  HTTP/2/HPACK, gRPC, extension-free WebSocket metadata, and gRPC-Web metadata
  capture are implemented. WebSocket and gRPC-Web have focused homelab proof,
  but the full protocol matrix, TLS combinations, sustained load, and
  production traffic remain outside the claim);
- HTTP/3 or generic QUIC semantic capture. The current payload source observes
  configured TCP connections, while HTTP/3 runs over QUIC/UDP and protects its
  HEADERS and DATA semantics. A real aioquic exchange in the homelab proof is a
  negative control and correctly produces no HTTP/3 or QUIC semantic signal;
- WebSocket extensions, compressed frames, reconstruction of fragmented
  application messages, or payload export. The parser validates only
  extension-free RFC 6455 framing, emits frame opcode/direction/length/control
  metadata, and rejects invalid transitions or RSV use with native accounting;
- gRPC-Web protobuf decoding, browser CORS behavior, or full duplex streaming.
  The parser accepts bounded binary and base64-text HTTP/1 envelopes, records
  RPC method/message counts and trailer status, and exports no application
  bytes;
- live Kafka protocol capture proof (capture, reassembly, and request/response
  matching are implemented and unit-tested; only Redis and HTTP/2 are live
  proven);
- live NATS, MongoDB, MySQL, or PostgreSQL protocol capture proof (implemented
  and unit-tested, not yet runtime-proven);
- on-the-wire TLS decryption (the claimed `source.aya_tls` surface is
  userspace library-boundary plaintext interception for dynamically linked
  OpenSSL 1.1.1/3 with the complete required read/write/fd-association export
  set, GnuTLS ABI 30 using the standard integer socket transport, and
  unstripped Linux/amd64 Go 1.24 through 1.26 ELF executables with exact static
  `crypto/tls` and `netFD` symbols; candidates are bounded, version-gated,
  architecture-checked, preflighted, and transactionally attached, with
  15-second rescans and native coverage counters; stripped Go binaries,
  non-amd64 Go ABIs, unknown versions, BoringSSL, rustls, custom BIO/custom
  transport, and statically bundled Node/JVM TLS fail closed and are not
  claimed; only Go 1.26.4 has current homelab runtime proof);
- full per-connection TCP state-machine tracking or packet accounting (TCP
  retransmit, reset, and state-transition observation and counting are
  implemented, with resets and state transitions locally proven);
- universal stack unwinding (CPU profiles unwind natively via in-kernel
  DWARF/CFI rules parsed from `.eh_frame` for registered processes, with
  frame-pointer unwinding as the fallback, up to 128 configurable frames and
  the kernel `kernel.perf_event_max_stack` sysctl bound of 127 for the
  frame-pointer path; DWARF-expression CFI rules are not evaluated, so they
  stop the unwind with accounting. Coverage is bounded by row/module/process
  budgets with counters, terminal frames in modules that do not CFI-mark
  their outermost function classify conservatively as `no_mapping`, and
  stacks that fill the configured budget are flagged and counted, never
  silently truncated);
- interpreter unwinding beyond exact CPython 3.11 and 3.12 layouts (other
  versions are counted as unsupported; Node/V8 and JVM generated-code names resolve only
  when the target runtime or its tooling publishes a bounded
  `/tmp/perf-<pid>.map` in the target mount namespace, and that symbol map does
  not itself make every opaque JIT frame unwindable. E-Navigator does not add
  Node/V8 perf flags, attach a JVM agent, or generate jitdump output. Thread matching uses
  `native_thread_id` and therefore degrades with accounting when the
  interpreter runs in a pid namespace whose CPython thread ids the agent
  cannot translate, and only co_qualname/co_name, co_filename, and
  co_firstlineno are ever read from interpreter memory; the interpreter's
  own pid namespace is translated when the kernel allows, which is the
  containerized-workload case proven on the homelab);
- complete off-CPU, synchronization, or allocation profiling (the opt-in
  event-driven surface covers scheduler deschedule duration and
  `FUTEX_WAIT`/`FUTEX_WAIT_BITSET` duration with bounded state, thresholds,
  rate caps, and counters. It does not identify wakeup cause, lock owner,
  spin locks, uncontended locks, non-futex primitives, or allocations);
- native DWARF coverage of every process on a heavily loaded node (the
  in-kernel unwind-table row pool is finite; the agent prioritizes
  processes it observes on-CPU and re-allocates the pool each refresh, but
  on nodes running many processes with large system libraries some
  modules are skipped with row-budget accounting and fall back to
  frame-pointer unwinding);
- cross-pid-namespace symbolization beyond verified pids (pids are translated
  in-kernel into the symbolization procfs namespace where the kernel allows;
  untranslatable pids are symbolized only after a thread-comm identity check
  and otherwise carry raw addresses with accounting. An unrelated process
  sharing pid, tid, and thread comm would evade this check);
- cgroup v1 or hybrid capture filtering (the in-kernel
  `bpf_get_current_cgroup_id()` key belongs to the task's default hierarchy,
  while cgroup v1 can expose multiple controller hierarchies with unrelated
  inode ids. E-Navigator accepts only a directly mounted unified cgroup v2
  root. Legacy, hybrid, unreadable, and unrecognized roots are diagnosed with
  native metrics and force every unknown cgroup to deny before any Aya program
  attaches. This is a deliberate architecture boundary, not best-effort v1
  support; see ADR 0011);
- instant capture-scope changes for newly started workloads (the optional
  `[capture_filter]` cgroup-id capture filter cannot decide a pod that
  userspace has not yet discovered; a new pod's cgroup id is absent from the
  eBPF membership map until controller discovery and source map application
  finish. The default event-driven mode uses a bounded recursive inotify watch
  tree plus Kubernetes watch notifications and immediate source wakeups. A
  2-second scan remains the loss-recovery boundary, and diagnostic `polling`
  mode preserves the old behavior. Both modes keep the configured
  `unknown_cgroup` posture: under an allowlist it creates a temporary coverage
  gap, and under a denylist it creates a temporary capture leak. Five
  counterbalanced Linux 6.6.68 homelab runs measured a 0.463 ms median and
  0.487 ms p95 event-driven first-signal window, versus 1,148.131 ms and
  1,216.842 ms for polling. That scoped result is not an instant-update,
  production, sustained-churn, or every-runtime claim);
- cgroup-based capture filtering of softirq TCP-stat observations (the
  `tcp_set_state`, `tcp_retransmit_skb`, and `tcp_send_reset`/`receive_reset`
  tracepoints run in softirq/interrupt context where `bpf_get_current_cgroup_id`
  reflects whatever task is on-CPU rather than the connection's workload; these
  observations are therefore treated as node-scoped and are always emitted, never
  cgroup-filtered);
- namespace or label capture filtering without the Kubernetes API (a namespace
  and labels are not present in the cgroup path. Only the pod UID and container
  id are present, so namespace/label rules hard-depend on the node pod list; when the
  API is unavailable the filter degrades loudly and applies the configured
  `unknown_cgroup` posture to every workload);
- glob or regular-expression label values (capture-filter namespace and
  process/container patterns support `*` and `?`; label rules support exact
  equality/inequality, existence/non-existence, set membership, and bounded OR
  groups);
- cgroup v1 capture filtering (the capture filter's join key is the cgroup v2
  container cgroup inode; it assumes the unified cgroup v2 hierarchy used by
  modern Kubernetes nodes, and host/non-pod processes, which have a cgroup but
  no namespace, always fall to the `unknown_cgroup` posture);
- capture filtering of a connection's network open/close lifecycle events after
  a mid-connection verdict flip (the capture decision for connection-lifecycle
  events is taken at connect/accept establishment; a workload whose verdict
  changes while a connection is open still emits that connection's open/close
  events, though its L7/payload events re-check the live per-cgroup verdict);
- lossless DNS or HTTP capture across every node and workload shape;
- live native `network.flow.bytes` export from traffic after the native metric
  migration, including flow-attribution warning proof;
- production collector/backend compatibility beyond recorded local or
  namespace-local Collector proof;
- a RingBuf performance win over the perf-event transport (the 2026-07-21
  homelab A/B proved both transports for the enabled exec/network slice with
  zero observed transport loss, but RingBuf measured 0.56% lower application
  throughput, 1.46% higher mean latency, 11.40% higher two-pod agent CPU, and
  4.45% lower two-pod RSS in three short runs; the application movements were
  within noisy run variance and do not support a win claim);
- runtime proof of the automatic perf fallback on an old kernel (the selection
  matrix is unit-tested, but both homelab nodes support RingBuf on Linux 6.6);
- runtime proof of the automatic network-hook fallback on a kernel without
  tracing programs, kernel BTF, or the required `ksys_read`/`ksys_write`
  targets (the selection matrix is unit-tested, but both homelab nodes used
  Linux 6.6.68 with the complete BTF surface);
- a universal lower-overhead or lower-memory fexit claim (the 2026-07-21
  homelab A/B covered one scalar `os.read`/`os.write` TCP loop: fexit measured
  7.971% more operations/s and 7.710% lower mean latency than tracepoints, but
  still 7.045% lower throughput than no agent and used about 13.4 MiB more
  summed two-pod RSS. Vectored I/O, `send*`/`recv*`, other sources, mixed
  workloads, and production were not measured);
- a Go `crypto/tls` overhead claim (the correctness campaign used 0.105 to
  0.265 second fixed request bursts on a shared homelab; Go 1.24/1.25,
  Linux/arm64, gRPC, WebSocket, production traffic, and sustained load were not
  runtime-proven);
- a general profiling overhead claim (the 2026-07-22 homelab campaign covered
  one pinned CPython 3.11.15 workload for three 60-second pairs. The profiling
  arm measured 2.049% lower busy-loop throughput than no agent with all three
  modes enabled, but it did not cover mixed services, higher rates, backend
  delivery, JVM/V8, production, or a dedicated node);
- lower overhead or lower memory versus another observability stack (the
  2026-07-22 33-run homelab comparison measured E-Navigator at 43.601071% more
  agent CPU and 31.903883% more agent RSS than pinned Beyla plus Alloy in the
  final cumulative HTTP, gRPC, Redis, PostgreSQL, and 10 Hz CPU-profile arm);
- universal application-latency or node-resource conclusions from that
  head-to-head result. The driver used fixed offered rates rather than a
  saturation search, only three shared-cluster repetitions were run, and the
  node series are summed container CPU and working-set memory rather than
  total host utilization;
- rootless eBPF operation, or a universal reduced-capability claim across
  kernels and security policies (the opt-in reduced profile is runtime proven
  only on the Linux 6.6.68 homelab. Core Aya sources used `BPF` and `PERFMON`,
  Go TLS and cross-UID CPU symbolization added `SYS_PTRACE`, and host resources
  used no capabilities. Other kernels, LSMs, seccomp profiles, and optional TLS
  target permissions require their own proof);
- complete attribution for every host process, packet, profile sample, or
  runtime security finding.

## Evidence Rules

Do not treat these as interchangeable:

- synthetic CLI output;
- Cargo/unit/golden tests;
- Docker smoke tests;
- Helm rendering or Kubernetes schema checks;
- guarded Linux/Kubernetes runtime proof.

A claim is runtime proven only when a capable Linux host or Kubernetes cluster
recorded the relevant E-Navigator output, pod state, workload output, and
cleanup/restore evidence.

## Security And Data Handling Boundaries

E-Navigator favors bounded data structures and explicit attribution warnings.
Sensitive values must not be added as high-cardinality labels or exported as
raw secrets. Signal schemas and exporters must keep secret-like label filtering
and bounded cardinality intact. Prometheus preserves the identity of bounded
metric series whose raw workload, process, endpoint, or DNS dimensions are
redacted by exporting deterministic fingerprints instead of the raw values.

## Operational Boundaries

The compatibility chart profile retains broad capabilities for unproven
kernels. The opt-in reduced profile removes `SYS_ADMIN` and is proven only on
the Linux 6.6.68 homelab with UID 0, `RuntimeDefault` seccomp, and no privilege
escalation. Do not present it as rootless, universally portable, production
proven, or sufficient for every cross-UID OpenSSL/GnuTLS filesystem layout.
Treat optional-target permission failures as coverage loss, not partial
success.

## Benchmark Boundaries

Local Criterion benchmarks are hot-path hygiene and regression tools. They are
not live overhead proof. Runtime overhead claims require a controlled baseline,
resource samples, comparable workload shape, and recorded runtime evidence.
The 2026-07-22 head-to-head campaign provides that evidence only for its pinned
two-node homelab, workload, versions, rates, cumulative stages, and short
windows. Its PASS verdict means the evidence matrix passed integrity gates. It
does not mean E-Navigator outperformed the comparison stack.
